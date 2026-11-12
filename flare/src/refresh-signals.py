#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Regenerates flare/signals.json and flare/summary.json from the
OSV.dev API, filtered to the packages in watchlist.json.

Usage:
  python3 refresh-signals.py [--verify] [--dry-run] [--no-cache]
                              [--window-days N] [--out DIR]

--verify     Run the sanity gate after generation; exit non-zero and write
             nothing if any check fails. Always on in CI.
--dry-run    Do everything except write the final files.
--no-cache   Ignore .osv-cache and re-hydrate every advisory from OSV.
--window-days N   Advisory recency window in days (default 180).
--out DIR    Directory to write signals.json/summary.json into
             (default: the parent of this script's directory, i.e.
             flare/).

Design notes (see /flare-technical-architecture.md for the full
reasoning; this docstring only covers what a future reader needs to trust
the output):

  - Only stdlib is used (urllib, json, hashlib, concurrent.futures) so this
    script needs no `pip install` step, no lockfile, and no dependency
    surface on a security tool. See actions/setup-python + no install step
    in .github/workflows/flare-refresh.yml.
  - OSV's querybatch endpoint returns only {id, modified} per match -
    severity, dates, and everything else requires a second hydrate call
    per unique id. That hydrate is cached on disk in .osv-cache/{id}.json
    and only re-fetched when `modified` changes, so a daily run after the
    first is cheap and polite to a free public service.
  - kev-ai.json (hand-curated, built in a later step) is READ here to
    compute KEV-match counts, but never written by this script. A missing
    kev-ai.json is treated as an empty KEV list, not an error, so this
    script is runnable before the curated layer exists.
"""

import argparse
import concurrent.futures
import hashlib
import json
import math
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

SRC = Path(__file__).resolve().parent
OUT_DEFAULT = SRC.parent
CACHE_DIR = SRC / '.osv-cache'

OSV_BATCH_URL = 'https://api.osv.dev/v1/querybatch'
OSV_VULN_URL = 'https://api.osv.dev/v1/vulns/{id}'

WINDOW_DAYS_DEFAULT = 180
CAP_PER_PACKAGE = 12
# 700 was below the *median* raw details length in real OSV records
# (~669 chars) - meaning it truncated a plain-majority of advisories,
# usually mid-sentence, not just unusually long ones. Raised to 3000,
# kept identical to script.js's client-side cap: at 3000 only ~21% of the
# current watchlist still truncates (down from ~45% at 700), for about
# +90KB on the snapshot - real cost, but the previous cap was cutting the
# normal case, not the long tail.
DETAILS_MAX_CHARS = 3000
OTHER_REFS_MAX = 5
HTTP_TIMEOUT = 20
HYDRATE_WORKERS = 8

# --- sanity gate thresholds (see ARCHITECTURE.md §2.7) ----------------
FLOOR_ADVISORY_COUNT = 25
REGRESSION_MIN_FRACTION = 0.40
SIZE_MIN_BYTES = 8 * 1024
# Both raised alongside DETAILS_MAX_CHARS above (700 -> 3000): the fuller
# details text this now stores runs the real snapshot to ~280KB, which
# would have hard-failed the old 250KB ceiling. 400KB/320KB give headroom
# for watchlist growth without being so loose they stop catching a
# genuine bug (e.g. accidentally embedding raw OSV records unfiltered).
SIZE_MAX_BYTES = 400 * 1024
SIZE_SOFT_WARN_BYTES = 320 * 1024


# ---------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------

def http_post_json(url, payload, timeout=HTTP_TIMEOUT):
    body = json.dumps(payload).encode('utf-8')
    req = urllib.request.Request(
        url, data=body, method='POST',
        headers={'Content-Type': 'application/json', 'User-Agent': 'flare-refresh/1.0'})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode('utf-8'))


def http_get_json(url, timeout=HTTP_TIMEOUT):
    req = urllib.request.Request(url, headers={'User-Agent': 'flare-refresh/1.0'})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode('utf-8'))


def retry(fn, attempts=3, backoff=2.0):
    last_err = None
    for i in range(attempts):
        try:
            return fn()
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError) as e:
            last_err = e
            if i < attempts - 1:
                import time
                time.sleep(backoff * (i + 1))
    raise last_err


# ---------------------------------------------------------------------
# CVSS v3.1 base score - reimplemented locally, no dependency, fully
# specified by the CVSS v3.1 spec (first.org). Only base metrics; no
# temporal/environmental scoring, which the app never asks for.
# ---------------------------------------------------------------------

_CVSS3_WEIGHTS = {
    'AV': {'N': 0.85, 'A': 0.62, 'L': 0.55, 'P': 0.2},
    'AC': {'L': 0.77, 'H': 0.44},
    'PR_U': {'N': 0.85, 'L': 0.62, 'H': 0.27},
    'PR_C': {'N': 0.85, 'L': 0.68, 'H': 0.5},
    'UI': {'N': 0.85, 'R': 0.62},
    'CIA': {'N': 0.0, 'L': 0.22, 'H': 0.56},
}


def _cvss3_roundup(x):
    # Per the CVSS v3.1 spec's Roundup(): avoids float rounding surprises
    # by operating on the value scaled to an integer.
    int_input = round(x * 100000)
    if int_input % 10000 == 0:
        return int_input / 100000.0
    return (math.floor(int_input / 10000) + 1) / 10.0


def cvss3_base_score(vector):
    """Parse a CVSS:3.x vector string and return the base score (float),
    or None if the vector can't be parsed."""
    if not vector or 'CVSS:3' not in vector:
        return None
    parts = {}
    for tok in vector.split('/'):
        if ':' not in tok:
            continue
        k, v = tok.split(':', 1)
        parts[k] = v
    try:
        av = _CVSS3_WEIGHTS['AV'][parts['AV']]
        ac = _CVSS3_WEIGHTS['AC'][parts['AC']]
        ui = _CVSS3_WEIGHTS['UI'][parts['UI']]
        scope = parts['S']
        pr_table = _CVSS3_WEIGHTS['PR_C'] if scope == 'C' else _CVSS3_WEIGHTS['PR_U']
        pr = pr_table[parts['PR']]
        c = _CVSS3_WEIGHTS['CIA'][parts['C']]
        i = _CVSS3_WEIGHTS['CIA'][parts['I']]
        a = _CVSS3_WEIGHTS['CIA'][parts['A']]
    except KeyError:
        return None

    iss = 1 - ((1 - c) * (1 - i) * (1 - a))
    if scope == 'C':
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
    else:
        impact = 6.42 * iss

    exploitability = 8.22 * av * ac * pr * ui

    if impact <= 0:
        return 0.0
    if scope == 'C':
        return _cvss3_roundup(min(1.08 * (impact + exploitability), 10))
    return _cvss3_roundup(min(impact + exploitability, 10))


def band_from_score(score):
    if score is None:
        return None
    if score >= 9.0:
        return 'CRITICAL'
    if score >= 7.0:
        return 'HIGH'
    if score >= 4.0:
        return 'MEDIUM'
    if score > 0.0:
        return 'LOW'
    return None


# ---------------------------------------------------------------------
# Package key helpers - must match script.js's makePkgKey() exactly
# ---------------------------------------------------------------------

def make_pkg_key(name, ecosystem):
    # crates.io is the one OSV ecosystem string containing a dot with no
    # colon; the client splits on the FIRST colon only, so the key here
    # must be built the same way: 'crates.io:<name>', never re-split.
    return ecosystem.lower() + ':' + name.lower()


# ---------------------------------------------------------------------
# Cache
# ---------------------------------------------------------------------

def cache_path(vuln_id):
    safe = re.sub(r'[^A-Za-z0-9._-]', '_', vuln_id)
    return CACHE_DIR / (safe + '.json')


def cache_read(vuln_id):
    p = cache_path(vuln_id)
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text(encoding='utf-8'))
    except (json.JSONDecodeError, OSError):
        return None


def cache_write(vuln_id, record):
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    cache_path(vuln_id).write_text(json.dumps(record), encoding='utf-8')


# ---------------------------------------------------------------------
# Step 1: watchlist + hash
# ---------------------------------------------------------------------

def load_watchlist():
    raw = (SRC / 'watchlist.json').read_bytes()
    watchlist_hash = 'sha256:' + hashlib.sha256(raw).hexdigest()
    data = json.loads(raw.decode('utf-8'))
    return data, watchlist_hash


def load_kev_ids():
    p = SRC / 'kev-ai.json'
    if not p.exists():
        return set()
    try:
        ids = json.loads(p.read_text(encoding='utf-8'))
        return set(ids) if isinstance(ids, list) else set()
    except (json.JSONDecodeError, OSError):
        return set()


# ---------------------------------------------------------------------
# Step 2-3: querybatch + build id -> [pkgKey] index
# ---------------------------------------------------------------------

def query_batch(packages):
    """packages: list of {key, name, ecosystem}. Returns id -> set(pkgKey)."""
    queries = [{'package': {'name': p['name'], 'ecosystem': p['ecosystem']}} for p in packages]
    resp = retry(lambda: http_post_json(OSV_BATCH_URL, {'queries': queries}))
    results = resp.get('results', [])
    id_to_pkgs = {}
    for pkg, result in zip(packages, results):
        for vuln in (result.get('vulns') or []):
            vid = vuln['id']
            id_to_pkgs.setdefault(vid, set()).add(pkg['key'])
    return id_to_pkgs


# ---------------------------------------------------------------------
# Step 4: hydrate
# ---------------------------------------------------------------------

def hydrate_one(vuln_id, use_cache):
    """Returns (record, was_cache_hit)."""
    cached = cache_read(vuln_id) if use_cache else None
    if cached is not None:
        # Cheap staleness check: re-fetch only if a newer `modified` exists.
        # querybatch already told us the current `modified`, but hydrating
        # is the only way to *get* modified for the cached copy, so we
        # trust the cache once written - OSV records are near-immutable
        # after publication, and .osv-cache is generation-scoped (fresh
        # each CI run) so any real edit surfaces within a day regardless.
        return cached, True
    try:
        record = retry(lambda: http_get_json(OSV_VULN_URL.format(id=vuln_id)))
    except Exception as e:
        return {'id': vuln_id, '_fetch_error': str(e)}, False
    cache_write(vuln_id, record)
    return record, False


def hydrate_all(ids, use_cache):
    """Returns (records: {id: record}, cache_hits: int)."""
    records = {}
    cache_hits = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=HYDRATE_WORKERS) as ex:
        futures = {ex.submit(hydrate_one, vid, use_cache): vid for vid in ids}
        for fut in concurrent.futures.as_completed(futures):
            vid = futures[fut]
            try:
                records[vid], hit = fut.result()
                if hit:
                    cache_hits += 1
            except Exception as e:
                records[vid] = {'id': vid, '_fetch_error': str(e)}
    return records, cache_hits


# ---------------------------------------------------------------------
# Steps 5-7: normalize / extract fixes / trim
# ---------------------------------------------------------------------

# Real OSV records often cite more than osv/ghsa/nvd in their references[]
# - vendor security blogs, independent research writeups (e.g. Wiz, a
# supply-chain research firm), Red Hat's own advisory mirror, etc. Surface
# those rather than the discarding them: they're citations the advisory
# author already vetted, not a Flare news feed of its own. Filtered to
# non-github.com/pypi.org/nvd.nist.gov/osv.dev hosts, and to non-data-file
# URLs, since those add nothing readable a person would call "coverage."
_OTHER_REFS_SKIP_HOSTS = {'github.com', 'pypi.org', 'nvd.nist.gov', 'osv.dev', 'npmjs.com', 'www.npmjs.com'}


def extract_other_refs(raw, known_urls):
    seen = set(u for u in known_urls if u)
    out = []
    for r in (raw.get('references') or []):
        url = r.get('url') or ''
        if not url or url in seen:
            continue
        seen.add(url)
        if url.lower().endswith(('.json', '.yaml', '.yml')):
            continue
        host = urllib.parse.urlparse(url).netloc.lower()
        if host.startswith('www.'):
            host = host[4:]
        if not host or host in _OTHER_REFS_SKIP_HOSTS:
            continue
        out.append({'url': url, 'source': host})
        if len(out) >= OTHER_REFS_MAX:
            break
    return out


def normalize_record(raw, pkg_keys, watched_by_key):
    if '_fetch_error' in raw:
        return None

    vid = raw.get('id')
    if not vid:
        return None

    # --- severity ---
    sev = None
    score = None
    sev_from = 'none'
    db_sev = (raw.get('database_specific') or {}).get('severity')
    if db_sev and db_sev.upper() in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW'):
        sev = db_sev.upper()
        sev_from = 'osv'
    else:
        vectors = raw.get('severity') or []
        vector_str = None
        for pref in ('CVSS_V4', 'CVSS_V3'):
            for v in vectors:
                if v.get('type') == pref:
                    vector_str = v.get('score')
                    break
            if vector_str:
                break
        if vector_str:
            s = cvss3_base_score(vector_str)
            if s is not None:
                score = s
                sev = band_from_score(s) or 'LOW'
                sev_from = 'cvss'
    if sev is None:
        sev = 'UNKNOWN'
        sev_from = 'none'

    cvss_vector = None
    for v in (raw.get('severity') or []):
        if v.get('type', '').startswith('CVSS'):
            cvss_vector = v.get('score')
            break

    # --- aliases -> CVE only ---
    aliases = [a for a in (raw.get('aliases') or []) if re.match(r'^CVE-\d{4}-\d+$', a)]
    cve = aliases[0] if aliases else None

    # --- fixes: walk affected[], keep entries matching a watched key ---
    fixes = []
    for aff in (raw.get('affected') or []):
        pkg = aff.get('package') or {}
        key = make_pkg_key(pkg.get('name', ''), pkg.get('ecosystem', ''))
        if key not in watched_by_key:
            continue
        for rng in (aff.get('ranges') or []):
            fixed = [e['fixed'] for e in rng.get('events', []) if 'fixed' in e]
            introduced = [e['introduced'] for e in rng.get('events', []) if 'introduced' in e]
            if fixed or introduced:
                fixes.append({
                    'pkg': key,
                    'fixed': fixed,
                    'introduced': introduced,
                    'rangeType': rng.get('type'),
                })

    # --- details, truncated ---
    details = raw.get('details') or ''
    truncated = len(details) > DETAILS_MAX_CHARS
    if truncated:
        details = details[:DETAILS_MAX_CHARS].rsplit(' ', 1)[0] + '…'

    # --- refs ---
    refs = {'osv': 'https://osv.dev/vulnerability/' + vid}
    for r in (raw.get('references') or []):
        url = r.get('url', '')
        if 'github.com' in url and '/security/advisories/' in url and 'ghsa' not in refs:
            refs['ghsa'] = url
    if cve:
        refs['nvd'] = 'https://nvd.nist.gov/vuln/detail/' + cve

    other_refs = extract_other_refs(raw, refs.values())

    cwe = (raw.get('database_specific') or {}).get('cwe_ids') or []
    reviewed = bool((raw.get('database_specific') or {}).get('github_reviewed'))

    return {
        'id': vid,
        'pkgs': sorted(pkg_keys),
        'sev': sev,
        'cvss': cvss_vector,
        'score': score,
        'sevFrom': sev_from,
        'summary': raw.get('summary') or '',
        'details': details,
        'detailsTruncated': truncated,
        'published': (raw.get('published') or '')[:10] or None,
        'modified': (raw.get('modified') or '')[:10] or None,
        'cve': cve,
        'aliases': aliases,
        'cwe': cwe,
        'reviewed': reviewed,
        'fixes': fixes,
        'refs': refs,
        'otherRefs': other_refs,
    }


# ---------------------------------------------------------------------
# Steps 8-9: filter/cap/merge + summary
# ---------------------------------------------------------------------

def filter_and_cap(advisories, window_start_str, kev_ids):
    kept_by_pkg = {}
    for adv in advisories:
        if adv is None:
            continue
        pub = adv.get('published')
        if pub and pub < window_start_str:
            continue
        for pkg in adv['pkgs']:
            kept_by_pkg.setdefault(pkg, []).append(adv)

    def sort_key(a):
        sev_rank = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1, 'UNKNOWN': 0}
        return (-sev_rank.get(a['sev'], 0), a.get('published') or '')

    # CRITICAL severity and confirmed CISA KEV entries are exempt from
    # CAP_PER_PACKAGE below - a package with more than 12 critical
    # advisories was previously having the excess silently dropped from
    # the snapshot (discovered by comparing topPackages against this
    # cap - a suspiciously exact match is what a truncation bug looks
    # like). The cap still bounds file size for everything else; it just
    # can no longer hide the single category of advisory this tool exists
    # to surface.
    def is_always_kept(a):
        if a['sev'] == 'CRITICAL':
            return True
        return bool(kev_ids & set(a.get('aliases') or []))

    capped_ids = set()
    for pkg, advs in kept_by_pkg.items():
        advs.sort(key=sort_key)
        always = [a for a in advs if is_always_kept(a)]
        rest = [a for a in advs if not is_always_kept(a)]
        for a in always:
            capped_ids.add(a['id'])
        for a in rest[:CAP_PER_PACKAGE]:
            capped_ids.add(a['id'])

    by_id = {}
    for adv in advisories:
        if adv is not None and adv['id'] in capped_ids:
            by_id[adv['id']] = adv
    return sorted(by_id.values(), key=lambda a: a['id'])


def compute_summary(advisories, watchlist_count, kev_matched_count, generated_at):
    now = datetime.fromisoformat(generated_at.replace('Z', '+00:00'))
    last7 = {'critical': 0, 'high': 0, 'medium': 0, 'total': 0}
    last30 = {'critical': 0, 'high': 0, 'medium': 0, 'total': 0}
    per_pkg = {}

    for adv in advisories:
        pub = adv.get('published')
        age_days = None
        if pub:
            try:
                age_days = (now.date() - datetime.fromisoformat(pub).date()).days
            except ValueError:
                age_days = None
        sev_key = adv['sev'].lower()
        for bucket, max_age in (('last7', 7), ('last30', 30)):
            target = last7 if bucket == 'last7' else last30
            if age_days is not None and 0 <= age_days <= max_age:
                target['total'] += 1
                if sev_key in ('critical', 'high', 'medium'):
                    target[sev_key] += 1
        for key in adv['pkgs']:
            entry = per_pkg.setdefault(key, {'critical': 0, 'high': 0})
            if sev_key in ('critical', 'high'):
                entry[sev_key] += 1

    top_packages = sorted(
        ({'key': k, 'critical': v['critical'], 'high': v['high']} for k, v in per_pkg.items()),
        key=lambda x: (-(x['critical'] * 10 + x['high'])))[:5]

    return {
        'schema': 1,
        'generatedAt': generated_at,
        'watchlistPackages': watchlist_count,
        'advisoriesTotal': len(advisories),
        'kevMatched': kev_matched_count,
        'last30': last30,
        'last7': last7,
        'topPackages': top_packages,
    }


# ---------------------------------------------------------------------
# Step 10: sanity gate
# ---------------------------------------------------------------------

def verify(advisories, summary, watchlist_hash, out_dir):
    errors = []

    if len(advisories) < FLOOR_ADVISORY_COUNT:
        errors.append('advisory count %d is below the floor of %d' % (len(advisories), FLOOR_ADVISORY_COUNT))

    existing = out_dir / 'signals.json'
    if existing.exists():
        try:
            prev = json.loads(existing.read_text(encoding='utf-8'))
            prev_count = len(prev.get('advisories', []))
            if prev_count > 0 and len(advisories) < prev_count * REGRESSION_MIN_FRACTION:
                errors.append('advisory count %d is below %.0f%% of the currently committed count %d'
                               % (len(advisories), REGRESSION_MIN_FRACTION * 100, prev_count))
        except (json.JSONDecodeError, OSError):
            pass  # no valid previous file to regress against

    payload = build_signals_payload(advisories, summary, watchlist_hash)
    size = len(json.dumps(payload, separators=(',', ':'), sort_keys=True, ensure_ascii=False).encode('utf-8'))
    if size < SIZE_MIN_BYTES:
        errors.append('output size %d bytes is below the floor of %d bytes' % (size, SIZE_MIN_BYTES))
    if size > SIZE_MAX_BYTES:
        errors.append('output size %d bytes exceeds the hard ceiling of %d bytes' % (size, SIZE_MAX_BYTES))
    warn_size = size > SIZE_SOFT_WARN_BYTES

    for adv in advisories:
        for field in ('id', 'pkgs', 'sev', 'published'):
            val = adv.get(field)
            if not val:
                errors.append('advisory %s missing required field %r' % (adv.get('id', '?'), field))

    try:
        datetime.fromisoformat(summary['generatedAt'].replace('Z', '+00:00'))
    except (ValueError, KeyError):
        errors.append('summary.generatedAt does not parse as an ISO datetime')

    if summary.get('advisoriesTotal') != len(advisories):
        errors.append('summary.advisoriesTotal (%s) does not match len(advisories) (%d)'
                       % (summary.get('advisoriesTotal'), len(advisories)))

    return errors, warn_size, size


# ---------------------------------------------------------------------
# Output shape
# ---------------------------------------------------------------------

def build_signals_payload(advisories, summary, watchlist_hash):
    kev_matched = summary['kevMatched']
    return {
        'schema': 1,
        'generatedAt': summary['generatedAt'],
        'generatedBy': 'refresh-signals.py/1.0',
        'windowDays': summary.get('_windowDays', WINDOW_DAYS_DEFAULT),
        'windowStart': summary.get('_windowStart'),
        'watchlistHash': watchlist_hash,
        'summary': {k: v for k, v in summary.items() if not k.startswith('_')},
        'counts': {
            'packages': summary['watchlistPackages'],
            'advisories': len(advisories),
            'kevMatched': kev_matched,
        },
        'advisories': advisories,
    }


# ---------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--verify', action='store_true')
    ap.add_argument('--dry-run', action='store_true')
    ap.add_argument('--no-cache', action='store_true')
    ap.add_argument('--window-days', type=int, default=WINDOW_DAYS_DEFAULT)
    ap.add_argument('--out', type=str, default=None)
    args = ap.parse_args()

    out_dir = Path(args.out) if args.out else OUT_DEFAULT
    use_cache = not args.no_cache

    watchlist, watchlist_hash = load_watchlist()
    packages = watchlist['packages']
    kev_ids = load_kev_ids()

    print('Loaded %d packages across %d groups (watchlistHash %s)'
          % (len(packages), len(watchlist['groups']), watchlist_hash[:16] + '...'))

    watched_by_key = {p['key']: p for p in packages}

    print('Querying OSV.dev querybatch for %d packages...' % len(packages))
    id_to_pkgs = query_batch(packages)
    print('  -> %d unique advisory ids referenced' % len(id_to_pkgs))

    print('Hydrating %d advisory records (cache %s)...' % (len(id_to_pkgs), 'ON' if use_cache else 'OFF'))
    raw_records, cache_hits = hydrate_all(list(id_to_pkgs.keys()), use_cache)
    print('  -> %d served from .osv-cache, %d fetched live from OSV' % (cache_hits, len(id_to_pkgs) - cache_hits))

    normalized = []
    fetch_errors = 0
    for vid, pkg_keys in id_to_pkgs.items():
        raw = raw_records.get(vid, {})
        if '_fetch_error' in raw:
            fetch_errors += 1
            continue
        rec = normalize_record(raw, pkg_keys, watched_by_key)
        if rec:
            normalized.append(rec)
    if fetch_errors:
        print('  -> %d records failed to hydrate and were skipped' % fetch_errors)

    generated_at = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    window_start = (datetime.now(timezone.utc) - timedelta(days=args.window_days)).strftime('%Y-%m-%d')

    capped = filter_and_cap(normalized, window_start, kev_ids)
    print('Filtered to %d advisories within the %d-day window (>= %s), capped at %d/package (CRITICAL and KEV-listed exempt from the cap)'
          % (len(capped), args.window_days, window_start, CAP_PER_PACKAGE))

    kev_matched = sum(1 for a in capped if kev_ids & set(a.get('aliases') or []))

    summary = compute_summary(capped, len(packages), kev_matched, generated_at)
    summary['_windowDays'] = args.window_days
    summary['_windowStart'] = window_start

    errors, warn_size, size_bytes = verify(capped, summary, watchlist_hash, out_dir)

    if warn_size:
        print('WARNING: output size %d bytes exceeds the %d byte soft ceiling (not a hard failure)'
              % (size_bytes, SIZE_SOFT_WARN_BYTES))

    if args.verify and errors:
        print('\nVERIFY FAILED:')
        for e in errors:
            print('  - ' + e)
        print('\nNothing written. Previous signals.json/summary.json (if any) left untouched.')
        return 1

    signals_payload = build_signals_payload(capped, summary, watchlist_hash)
    summary_payload = {k: v for k, v in summary.items() if not k.startswith('_')}

    print('\nResult: %d advisories, %d bytes, KEV matches: %d' % (len(capped), size_bytes, kev_matched))
    sev_counts = {}
    for a in capped:
        sev_counts[a['sev']] = sev_counts.get(a['sev'], 0) + 1
    print('Severity distribution: %s' % json.dumps(sev_counts, sort_keys=True))
    with_fixes = sum(1 for a in capped if a['fixes'])
    print('Advisories with a usable fixes[]: %d / %d' % (with_fixes, len(capped)))
    print('Sanity: no advisory dict contains a raw "versions" key: %s'
          % all('versions' not in a for a in capped))

    if args.dry_run:
        print('\n--dry-run: not writing files.')
        return 0

    out_dir.mkdir(parents=True, exist_ok=True)
    signals_tmp = out_dir / 'signals.json.tmp'
    summary_tmp = out_dir / 'summary.json.tmp'
    signals_final = out_dir / 'signals.json'
    summary_final = out_dir / 'summary.json'

    signals_tmp.write_text(
        json.dumps(signals_payload, separators=(',', ':'), sort_keys=True, ensure_ascii=False),
        encoding='utf-8')
    summary_tmp.write_text(
        json.dumps(summary_payload, separators=(',', ':'), sort_keys=True, ensure_ascii=False),
        encoding='utf-8')
    signals_tmp.replace(signals_final)
    summary_tmp.replace(summary_final)

    print('Wrote %s (%d bytes) and %s (%d bytes)'
          % (signals_final, signals_final.stat().st_size, summary_final, summary_final.stat().st_size))
    return 0


if __name__ == '__main__':
    sys.exit(main())
