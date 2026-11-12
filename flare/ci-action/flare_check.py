#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Flare CI check - fails a build when a scanned dependency manifest has a
critical-severity or actively-exploited (CISA KEV) advisory, straight
from OSV.dev. Standalone companion to lab.krismccabe.com/flare/, not a
copy of it: same data source and severity math (CVSS v3.1 base score,
ported from flare/src/refresh-signals.py so the numbers never disagree
with the dashboard), but scans whatever manifest you point it at
instead of a curated watchlist.

Usage:
  python3 flare_check.py [--file PATH ...] [--severity-threshold LEVEL]
                          [--no-fail-on-kev] [--sarif PATH] [--json PATH]
                          [--quiet]

  --file PATH             Manifest to scan (requirements.txt, pyproject.toml,
                           package.json, package-lock.json). Repeatable.
                           Auto-detects these filenames in the current
                           directory if omitted entirely.
  --severity-threshold    Fail if any match is at or above this severity:
                           LOW | MEDIUM | HIGH | CRITICAL (default CRITICAL).
  --no-fail-on-kev        By default, any CISA KEV match fails the build
                           regardless of --severity-threshold (an actively
                           exploited advisory is worth stopping on even at
                           low CVSS). This turns that off.
  --sarif PATH            Write a SARIF 2.1.0 file for GitHub code scanning
                           (or any SARIF-reading tool) - same schema Flare's
                           own web export uses.
  --json PATH             Write the raw match list as JSON, for scripting.
  --quiet                 Suppress the human-readable table; exit code and
                           any --sarif/--json files still get written.

Only the Python standard library is used - no pip install step, no
lockfile, no dependency surface on a security tool. Network calls: OSV.dev
(api.osv.dev, always) and CISA's KEV catalog GitHub mirror
(raw.githubusercontent.com, only unless --no-fail-on-kev is NOT the only
reason you'd want it - it's fetched either way to annotate matches, but
only affects the exit code when fail-on-kev is active).
"""

import argparse
import json
import math
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

OSV_BATCH_URL = 'https://api.osv.dev/v1/querybatch'
OSV_VULN_URL = 'https://api.osv.dev/v1/vulns/{id}'
KEV_URL = 'https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json'
HTTP_TIMEOUT = 20

SEV_RANK = {'LOW': 1, 'MEDIUM': 2, 'HIGH': 3, 'CRITICAL': 4}


# ---------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------

def http_post_json(url, payload, timeout=HTTP_TIMEOUT):
    body = json.dumps(payload).encode('utf-8')
    req = urllib.request.Request(
        url, data=body, method='POST',
        headers={'Content-Type': 'application/json', 'User-Agent': 'flare-ci-check/1.0'})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode('utf-8'))


def http_get_json(url, timeout=HTTP_TIMEOUT):
    req = urllib.request.Request(url, headers={'User-Agent': 'flare-ci-check/1.0'})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode('utf-8'))


# ---------------------------------------------------------------------
# CVSS v3.1 base score - ported verbatim from flare/src/refresh-signals.py
# (cvss3_base_score/band_from_score) so this tool's severity numbers can
# never quietly drift from what the web dashboard shows for the same CVE.
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
    int_input = round(x * 100000)
    if int_input % 10000 == 0:
        return int_input / 100000.0
    return (math.floor(int_input / 10000) + 1) / 10.0


def cvss3_base_score(vector):
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


def severity_of(raw):
    """Mirrors normalize_record()'s severity fallback chain in
    refresh-signals.py: OSV's own database_specific.severity first, then
    a CVSS v3/v4 vector, then UNKNOWN."""
    db_sev = (raw.get('database_specific') or {}).get('severity')
    if db_sev and db_sev.upper() in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW'):
        return db_sev.upper(), None
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
        score = cvss3_base_score(vector_str)
        if score is not None:
            return (band_from_score(score) or 'LOW'), score
    return 'UNKNOWN', None


# ---------------------------------------------------------------------
# Manifest parsing - deliberately simple, stdlib-only. Mirrors the
# format-sniffing approach of Flare's own browser-side SBOM import
# (script.js: detectAndParseImport), reimplemented here for a real
# filesystem instead of an uploaded file.
# ---------------------------------------------------------------------

AUTO_DETECT_FILES = ['requirements.txt', 'package-lock.json', 'package.json', 'pyproject.toml']


def parse_requirements_txt(text):
    out = []
    for line in text.splitlines():
        line = line.split('#', 1)[0].strip()
        if not line or line.startswith('-'):
            continue
        m = re.match(r'^([A-Za-z0-9][A-Za-z0-9._-]*)', line)
        if m:
            out.append(('PyPI', m.group(1)))
    return out


def parse_package_json(text):
    try:
        data = json.loads(text)
    except ValueError:
        return []
    names = set()
    for key in ('dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies'):
        names.update((data.get(key) or {}).keys())
    return [('npm', n) for n in sorted(names)]


def parse_package_lock_json(text):
    try:
        data = json.loads(text)
    except ValueError:
        return []
    names = set()
    packages = data.get('packages')
    if isinstance(packages, dict):
        for path in packages.keys():
            if not path or 'node_modules/' not in path and not path.startswith('node_modules/'):
                continue
            name = path.rsplit('node_modules/', 1)[-1]
            if name:
                names.add(name)
    deps = data.get('dependencies')
    if isinstance(deps, dict):
        names.update(deps.keys())
    return [('npm', n) for n in sorted(names)]


_PEP508_NAME = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._-]*')


def parse_pyproject_toml(text):
    names = set()
    # Deliberately not a real TOML parser (stdlib-only, no tomllib on
    # Python <3.11) - just enough regex to pull dependency-looking
    # quoted strings out of [project.dependencies] / poetry sections,
    # matching script.js's parsePyprojectToml() same trade-off.
    for m in re.finditer(r'["\']([A-Za-z0-9][A-Za-z0-9._-]*)\s*[><=!~^]', text):
        names.add(m.group(1))
    for line in text.splitlines():
        line = line.strip()
        m = re.match(r'^([A-Za-z0-9][A-Za-z0-9._-]*)\s*=\s*["\']', line)
        if m and m.group(1).lower() not in ('python', 'name', 'version'):
            names.add(m.group(1))
    return [('PyPI', n) for n in sorted(names)]


def parse_manifest(path):
    text = path.read_text(encoding='utf-8', errors='replace')
    name = path.name.lower()
    if name == 'requirements.txt' or name.endswith('.txt'):
        return parse_requirements_txt(text)
    if name == 'package-lock.json':
        return parse_package_lock_json(text)
    if name == 'package.json':
        return parse_package_json(text)
    if name == 'pyproject.toml':
        return parse_pyproject_toml(text)
    return []


def normalize_pkg_name(name, ecosystem):
    if ecosystem == 'PyPI':
        return re.sub(r'[-_.]+', '-', name.lower())
    if ecosystem == 'npm':
        return name.lower()
    return name


# ---------------------------------------------------------------------
# SARIF - same shape as script.js's buildSarif(), ported to Python.
# ---------------------------------------------------------------------

def sev_security_score(sev, score):
    if score is not None:
        return round(score, 1)
    return {'CRITICAL': 9.5, 'HIGH': 7.5, 'MEDIUM': 5.0, 'LOW': 2.0}.get(sev, 0.0)


def sarif_level_for(sev):
    if sev in ('CRITICAL', 'HIGH'):
        return 'error'
    if sev == 'MEDIUM':
        return 'warning'
    return 'note'


def build_sarif(matches):
    rules = {}
    results = []
    for m in matches:
        if m['id'] not in rules:
            tags = ['security']
            if m['kev']:
                tags.append('kev')
            rules[m['id']] = {
                'id': m['id'],
                'shortDescription': {'text': m['summary'] or m['id']},
                'fullDescription': {'text': m['summary'] or m['id']},
                'helpUri': m.get('url') or ('https://osv.dev/vulnerability/' + m['id']),
                'properties': {'tags': tags, 'security-severity': str(sev_security_score(m['sev'], m['score'])), 'severity': m['sev']},
            }
        results.append({
            'ruleId': m['id'],
            'level': sarif_level_for(m['sev']),
            'message': {'text': m['sev'] + ' in ' + m['package'] + ': ' + (m['summary'] or m['id'])},
            'locations': [{
                'physicalLocation': {'artifactLocation': {'uri': 'dependencies/' + m['ecosystem'].lower() + '/' + m['package'], 'uriBaseId': 'FLARE_CI'}},
                'logicalLocations': [{'name': m['package'], 'kind': 'package'}],
            }],
            'properties': {'package': m['package'], 'ecosystem': m['ecosystem'], 'kev': m['kev']},
        })
    return {
        '$schema': 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
        'version': '2.1.0',
        'runs': [{
            'tool': {'driver': {
                'name': 'Flare CI Check', 'informationUri': 'https://lab.krismccabe.com/flare/', 'version': '1.0.0',
                'shortDescription': {'text': 'OSV.dev/CISA-KEV vulnerability check for AI-stack dependencies.'},
                'rules': list(rules.values()),
            }},
            'originalUriBaseIds': {'FLARE_CI': {'uri': 'https://lab.krismccabe.com/flare/', 'description': {'text': 'Synthetic base - locations group findings by ecosystem/package, not a real repo file.'}}},
            'results': results,
        }],
    }


# ---------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------

def discover_packages(files):
    seen = {}
    for f in files:
        p = Path(f)
        if not p.is_file():
            print('warning: --file %s not found, skipping' % f, file=sys.stderr)
            continue
        for eco, name in parse_manifest(p):
            key = eco + ':' + normalize_pkg_name(name, eco)
            if key not in seen:
                seen[key] = {'ecosystem': eco, 'name': normalize_pkg_name(name, eco)}
    return seen


def fetch_kev_cves():
    try:
        data = http_get_json(KEV_URL)
        return {v['cveID'] for v in data.get('vulnerabilities', []) if v.get('cveID')}
    except Exception as e:
        print('warning: could not fetch CISA KEV catalog (%s) - KEV matching skipped this run' % e, file=sys.stderr)
        return set()


def run_check(packages, kev_cves):
    if not packages:
        return []
    pkg_list = []
    for key, p in packages.items():
        entry = dict(p)
        entry['_key'] = key
        pkg_list.append(entry)
    queries = [{'package': {'name': p['name'], 'ecosystem': p['ecosystem']}} for p in pkg_list]
    resp = http_post_json(OSV_BATCH_URL, {'queries': queries})
    results = resp.get('results', [])

    vuln_to_pkgs = {}
    for p, result in zip(pkg_list, results):
        for v in (result.get('vulns') or []):
            vuln_to_pkgs.setdefault(v['id'], set()).add(p['_key'])

    matches = []
    for vid, pkg_keys in vuln_to_pkgs.items():
        try:
            raw = http_get_json(OSV_VULN_URL.format(id=vid))
        except Exception as e:
            print('warning: could not hydrate %s (%s)' % (vid, e), file=sys.stderr)
            continue
        sev, score = severity_of(raw)
        aliases = [a for a in (raw.get('aliases') or []) if re.match(r'^CVE-\d{4}-\d+$', a)]
        cve = aliases[0] if aliases else None
        kev = bool(cve and cve in kev_cves)
        summary = raw.get('summary') or (raw.get('details') or '')[:200]
        url = None
        for ref in (raw.get('references') or []):
            if ref.get('type') == 'ADVISORY' or 'osv.dev' in (ref.get('url') or ''):
                url = ref.get('url')
                break
        for key in pkg_keys:
            pkg = packages[key]
            matches.append({
                'id': vid, 'cve': cve, 'package': pkg['name'], 'ecosystem': pkg['ecosystem'],
                'sev': sev, 'score': score, 'kev': kev, 'summary': summary, 'url': url,
            })
    return matches


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--file', action='append', default=[], help='Manifest path (repeatable)')
    ap.add_argument('--severity-threshold', default='CRITICAL', choices=list(SEV_RANK.keys()))
    ap.add_argument('--no-fail-on-kev', action='store_true')
    ap.add_argument('--sarif', default=None)
    ap.add_argument('--json', dest='json_out', default=None)
    ap.add_argument('--quiet', action='store_true')
    args = ap.parse_args()

    files = args.file or [f for f in AUTO_DETECT_FILES if Path(f).is_file()]
    if not files:
        print('No manifest found (looked for: %s). Pass --file explicitly.' % ', '.join(AUTO_DETECT_FILES), file=sys.stderr)
        return 2

    # An explicitly-named --file that doesn't exist is a config error, not
    # "nothing to scan" - failing loud here matters because the opposite
    # (silently exiting 0) would let a typo'd path quietly turn this into
    # a no-op security gate that always passes.
    if args.file:
        missing = [f for f in args.file if not Path(f).is_file()]
        if missing:
            print('error: --file path(s) not found: %s' % ', '.join(missing), file=sys.stderr)
            return 2

    packages = discover_packages(files)
    if not packages:
        print('No packages found in: %s' % ', '.join(files), file=sys.stderr)
        return 0
    if not args.quiet:
        print('Scanning %d package(s) from: %s' % (len(packages), ', '.join(files)))

    kev_cves = fetch_kev_cves()

    try:
        matches = run_check(packages, kev_cves)
    except (urllib.error.URLError, TimeoutError) as e:
        print('error: could not reach OSV.dev (%s)' % e, file=sys.stderr)
        return 2

    matches.sort(key=lambda m: (-SEV_RANK.get(m['sev'], 0), not m['kev'], m['package']))

    if not args.quiet:
        if not matches:
            print('No advisories found for the scanned packages.')
        else:
            for m in matches:
                kev_tag = ' [ACTIVELY EXPLOITED]' if m['kev'] else ''
                print('%-9s %-28s %-20s%s  %s' % (m['sev'], m['package'], m['id'], kev_tag, m['summary'][:80]))

    if args.sarif:
        Path(args.sarif).write_text(json.dumps(build_sarif(matches), indent=2), encoding='utf-8')
        if not args.quiet:
            print('Wrote SARIF: %s' % args.sarif)
    if args.json_out:
        Path(args.json_out).write_text(json.dumps(matches, indent=2), encoding='utf-8')
        if not args.quiet:
            print('Wrote JSON: %s' % args.json_out)

    threshold_rank = SEV_RANK[args.severity_threshold]
    over_threshold = [m for m in matches if SEV_RANK.get(m['sev'], 0) >= threshold_rank]
    kev_matches = [m for m in matches if m['kev']]
    fail = bool(over_threshold) or (kev_matches and not args.no_fail_on_kev)

    if not args.quiet:
        print('')
        print('%d total advisor%s, %d at/above %s, %d actively exploited (KEV).' % (
            len(matches), 'y' if len(matches) == 1 else 'ies', len(over_threshold), args.severity_threshold, len(kev_matches)))
        print('RESULT: %s' % ('FAIL' if fail else 'PASS'))

    return 1 if fail else 0


if __name__ == '__main__':
    sys.exit(main())
