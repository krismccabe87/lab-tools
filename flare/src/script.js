(function () {
  // ---------------------------------------------------------------
  // DATA  (build-time constants - curated layers, never fetched)
  // ---------------------------------------------------------------
  const WATCHLIST = __WATCHLIST_JSON__;   // {groups:[...], packages:[...]}
  const OWASP     = __OWASP_JSON__;       // {schema, framework, items:[...]}
  const KEV       = __KEV_JSON__;         // ["CVE-...", ...] - hand-maintained fallback baseline
  const KEV_SET   = new Set(KEV);
  // The set isKev() actually checks against. Starts as the hand-maintained
  // baseline and is only ever REPLACED with a strict superset of it (see
  // checkKevLive) - a failed or disabled live fetch never shrinks this back
  // below the baseline, so the "Actively exploited" badge can't go dark.
  let kevEffectiveSet = KEV_SET;

  function escapeHtml(str) {
    return String(str == null ? '' : str).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  }

  // Real OSV `details` text is GitHub-flavored markdown (### headings,
  // **bold**, `code`, - lists) - rendering it as escaped plain text left
  // the literal ### and ** characters visible. This is a small, safe
  // line-based renderer: HTML-escape first (still the only defense
  // against injection), then only ever ADD the handful of tags below via
  // our own regex, never interpret anything from the source as markup.
  function mdLiteInline(escapedText) {
    return escapedText
      .replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>')
      .replace(/\*\*/g, '')  // unpaired ** left over (usually truncation cutting before the close) - drop, don't show
      .replace(/`([^`]+)`/g, '<code>$1</code>')
      // [text](url) - patch/reference links are common in real advisory
      // prose (see GHSA-r75f-5x8p-qvmc). escapedText already went through
      // escapeHtml, so any & in the URL is already &amp; - valid, and
      // browsers decode it fine as an href.
      .replace(/\[([^\]]+)\]\((https?:\/\/[^\s)]+)\)/g, '<a href="$2" target="_blank" rel="noopener">$1</a>');
  }
  function mdLite(raw, truncated) {
    const text = escapeHtml(raw || '');
    const lines = text.split('\n');
    const blocks = [];
    let para = [];
    let list = null;
    let codeLines = null; // non-null while inside a fenced code block

    function flushPara() {
      if (para.length) { blocks.push('<p>' + mdLiteInline(para.join(' ')) + '</p>'); para = []; }
    }
    function flushList() {
      if (list) {
        blocks.push('<' + list.type + '>' + list.items.map(i => '<li>' + mdLiteInline(i) + '</li>').join('') + '</' + list.type + '>');
        list = null;
      }
    }

    lines.forEach(line => {
      // Fenced code blocks (```lang ... ```) - real advisory text often
      // includes exploit snippets this way. Content inside is shown
      // verbatim (already HTML-escaped above), no inline markdown applied.
      if (codeLines !== null) {
        if (/^`{2,}\s*$/.test(line.trim())) {
          blocks.push('<pre><code>' + codeLines.join('\n') + '</code></pre>');
          codeLines = null;
        } else {
          codeLines.push(line);
        }
        return;
      }
      const trimmed = line.trim();
      if (/^`{2,}\w*\s*$/.test(trimmed)) { flushPara(); flushList(); codeLines = []; return; }
      if (!trimmed) { flushPara(); flushList(); return; }
      const heading = trimmed.match(/^#{1,6}\s+(.*)$/);
      if (heading) {
        flushPara(); flushList();
        // Same MAL-record convention: "## Source: <name> (<64-char content
        // hash>)" - the hash identifies the source feed entry, it's not
        // meaningful to a reader. Keep the source name, drop the hash.
        const headingText = heading[1].replace(/^(Source:\s*\S+)\s*\([0-9a-f]{16,64}\)\s*$/i, '$1');
        blocks.push('<p class="md-heading">' + mdLiteInline(headingText) + '</p>');
        return;
      }
      // A bare "###" with no following text - typically the 700-char
      // truncation cutting a record off right after a heading marker.
      // Drop it rather than show the literal hashes.
      if (/^#{1,6}/.test(trimmed)) { flushPara(); flushList(); return; }
      if (/^(-{3,}|\*{3,}|_{3,})$/.test(trimmed)) { flushPara(); flushList(); return; }
      // OSV's malicious-package (MAL-*) records always open their details
      // with this exact editorial marker before the per-source breakdown -
      // confirmed verbatim against live records (MAL-2026-3432/3608).
      // It's an authoring instruction, not advisory content - drop it.
      if (/^_-=.*=-_$/.test(trimmed)) { flushPara(); flushList(); return; }
      if (/^\|[-\s|:]+\|$/.test(trimmed)) { return; }
      const ul = trimmed.match(/^[-*]\s+(.*)$/);
      if (ul) {
        flushPara();
        if (!list || list.type !== 'ul') { flushList(); list = { type: 'ul', items: [] }; }
        list.items.push(ul[1]);
        return;
      }
      const ol = trimmed.match(/^\d+\.\s+(.*)$/);
      if (ol) {
        flushPara();
        if (!list || list.type !== 'ol') { flushList(); list = { type: 'ol', items: [] }; }
        list.items.push(ol[1]);
        return;
      }
      flushList();
      para.push(trimmed);
    });
    // Truncation can cut a record off mid-code-block - show what was
    // captured rather than dropping it silently.
    if (codeLines !== null && codeLines.length) blocks.push('<pre><code>' + codeLines.join('\n') + '</code></pre>');
    flushPara();
    flushList();

    if (truncated && blocks.length) {
      const last = blocks[blocks.length - 1];
      const closeTag = last.match(/<\/(\w+)>$/);
      blocks[blocks.length - 1] = closeTag
        ? last.slice(0, -closeTag[0].length) + '&hellip;' + closeTag[0]
        : last;
      if (!closeTag) blocks.push('<p>&hellip;</p>');
    }

    return blocks.join('') || '<p></p>';
  }

  function fmtDate(iso) {
    if (!iso) return '';
    try { return new Date(iso).toLocaleDateString('en-GB', { day: 'numeric', month: 'long', year: 'numeric' }); } catch (e) { return iso; }
  }
  function fmtRelativeTime(iso) {
    if (!iso) return '';
    const ms = Date.now() - new Date(iso).getTime();
    if (!(ms >= 0)) return 'just now';
    const mins = Math.floor(ms / 60000);
    if (mins < 1) return 'just now';
    if (mins < 60) return mins + 'm ago';
    const hours = Math.floor(mins / 60);
    if (hours < 24) return hours + 'h ago';
    const days = Math.floor(hours / 24);
    return days + 'd ago';
  }

  function downloadBlob(content, filename, type) {
    const blob = new Blob([content], { type: type });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = filename; a.click();
    URL.revokeObjectURL(url);
  }

  const SEV_RANK = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, UNKNOWN: 0 };
  const SEV_LABEL = { CRITICAL: 'Critical', HIGH: 'High', MEDIUM: 'Medium', LOW: 'Low', UNKNOWN: 'Severity unknown' };
  const INITIAL_CARDS = 25;

  function allPackages() {
    return WATCHLIST.packages.concat(state.custom);
  }
  function pkgByKey(key) {
    return allPackages().find(p => p.key === key);
  }
  function selectedPackages() {
    const set = new Set(state.selected);
    return allPackages().filter(p => set.has(p.key));
  }
  function pkgLabel(key) {
    const p = pkgByKey(key);
    return p ? (p.label || p.name) : key;
  }
  function isKev(adv) {
    if (adv.cve && kevEffectiveSet.has(adv.cve)) return true;
    return (adv.aliases || []).some(a => kevEffectiveSet.has(a));
  }
  function compareAdvisories(a, b) {
    const ak = isKev(a) ? 1 : 0, bk = isKev(b) ? 1 : 0;
    if (ak !== bk) return bk - ak;
    const as = SEV_RANK[a.sev] || 0, bs = SEV_RANK[b.sev] || 0;
    if (as !== bs) return bs - as;
    const asc = a.score || 0, bsc = b.score || 0;
    if (asc !== bsc) return bsc - asc;
    // Last tiebreak: most recently updated first (OSV revises records
    // after initial publish - a fresh revision is more worth a second
    // look than one that's sat unchanged), falling back to published
    // for the rare record with no modified date.
    const am = a.modified || a.published || '', bm = b.modified || b.published || '';
    return bm.localeCompare(am);
  }

  // ---------------------------------------------------------------
  // STATE: the curated stack selector
  // ---------------------------------------------------------------
  const KNOWN_KEYS = new Set(WATCHLIST.packages.map(p => p.key));
  const STACK_KEY = 'flare-stack-v1';
  const REMEMBER_KEY = 'flare-remember-v1';
  const CACHE_KEY = 'flare-cache-v1';
  const HISTORY_KEY = 'flare-history-v1';
  const CACHE_TTL_MS = 24 * 60 * 60 * 1000;
  const ECOSYSTEMS = ['PyPI', 'npm', 'Go', 'Maven', 'crates.io', 'RubyGems', 'NuGet', 'Packagist'];
  const MAX_CUSTOM = 15;
  const MAX_FEEDS = 10;
  const MAX_FEED_ITEMS = 15;
  const MAX_WATCHED = 50;
  const MAX_VERSION_LEN = 40;

  // PyPI is case-insensitive with -/_/. all equivalent (PEP 503); npm is
  // lowercase but keeps scoped @scope/name; every other ecosystem here is
  // case-sensitive. Getting this wrong produces silent duplicate chips and
  // phantom "no advisories" results for packages that plainly exist - so
  // this is also what makePkgKey() routes through, not just the add form.
  function normalizePkgName(name, ecosystem) {
    const n = String(name || '').trim();
    if (ecosystem === 'PyPI') return n.toLowerCase().replace(/[-_.]+/g, '-');
    if (ecosystem === 'npm') return n.toLowerCase();
    return n;
  }
  function makePkgKey(name, ecosystem) {
    return String(ecosystem || '').toLowerCase() + ':' + normalizePkgName(name, ecosystem);
  }

  function freshState() {
    return {
      selected: WATCHLIST.packages.filter(p => p.default).map(p => p.key), custom: [], ghsaEnabled: false, feeds: [],
      watched: [],
      // Live-fetched by default: this is what keeps the "Actively exploited"
      // badge (shown unconditionally, not opt-in) accurate, unlike GHSA
      // which is purely additive/optional. See checkKevLive().
      kevLiveEnabled: true,
      // Also on by default - assurestart.co's feed is scoped to exactly
      // the watchlist's own vendor names (see ASSURESTART_URL), so unlike
      // a generic user-added feed it's curated specifically for this page.
      assurestartEnabled: true,
      // Off by default, same reasoning as ghsaEnabled - unlike the
      // batched OSV/KEV checks, this fires one request per selected
      // package to two more third-party registries (npm, PyPI), a
      // bigger footprint worth an explicit opt-in.
      packageHealthEnabled: false,
      // Off by default, same footprint reasoning as packageHealthEnabled -
      // one more third-party batched request beyond OSV/KEV/GHSA.
      epssEnabled: false,
      // Slack/Teams webhook alerts - off by default (no URL configured).
      webhookUrl: '', webhookPlatform: 'slack', webhookAutoNotify: false,
      // Exact installed version per package key, captured only from an
      // SBOM/lockfile entry that pins one (never from a manual pick or a
      // version *range*) - see the VERSION-AWARE MATCHING section below.
      // Absent for any key means "name only", the original behaviour.
      versions: {},
    };
  }

  // Repairs whatever was in localStorage rather than trusting it: a bare
  // array (the pre-custom-packages v0 shape), duplicate or mis-cased keys,
  // watchlist packages that have since been retired, and stale custom-pkg
  // status all get cleaned up here rather than left to break rendering
  // downstream. A persisted 'ok' status is never trusted across a reload -
  // it resets to 'stale' so a three-week-old result can't present as fresh.
  function normalizeStack(saved) {
    const fresh = freshState();
    if (!saved) return fresh;
    if (Array.isArray(saved)) saved = { selected: saved, custom: [] };
    if (typeof saved !== 'object') return fresh;

    const custom = (Array.isArray(saved.custom) ? saved.custom : [])
      .filter(c => c && typeof c.name === 'string' && typeof c.ecosystem === 'string' && ECOSYSTEMS.indexOf(c.ecosystem) !== -1)
      .map(c => ({
        key: makePkgKey(c.name, c.ecosystem),
        name: String(c.name).trim(),
        ecosystem: c.ecosystem,
        label: typeof c.label === 'string' && c.label ? c.label : String(c.name).trim(),
        addedAt: typeof c.addedAt === 'string' ? c.addedAt : new Date().toISOString(),
        status: 'stale',
        checkedAt: typeof c.checkedAt === 'string' ? c.checkedAt : null,
        count: typeof c.count === 'number' ? c.count : 0,
      }))
      .slice(0, MAX_CUSTOM);
    const customKeys = new Set(custom.map(c => c.key));

    let selected = Array.isArray(saved.selected) ? saved.selected : [];
    selected = selected
      .filter(k => typeof k === 'string')
      .map(k => k.toLowerCase())
      .filter((k, i, arr) => arr.indexOf(k) === i)
      .filter(k => KNOWN_KEYS.has(k) || customKeys.has(k));

    // Only ever kept for a key that's still actually selected - a version
    // pinned for a package you've since removed is dead weight, not a fact
    // worth carrying forward to a future re-add.
    const versions = {};
    if (saved.versions && typeof saved.versions === 'object') {
      Object.keys(saved.versions).forEach(k => {
        const v = saved.versions[k];
        if (selected.indexOf(k) !== -1 && typeof v === 'string' && v && v.length <= MAX_VERSION_LEN) {
          versions[k] = v;
        }
      });
    }

    // Same "never trust a persisted 'ok' as still fresh" rule as custom
    // packages - a feed's status resets to 'stale' on load rather than
    // silently claiming last session's result is still current.
    const feeds = (Array.isArray(saved.feeds) ? saved.feeds : [])
      .filter(f => f && typeof f.url === 'string' && typeof f.id === 'string')
      .map(f => ({
        id: f.id, url: f.url,
        name: typeof f.name === 'string' ? f.name : '',
        addedAt: typeof f.addedAt === 'string' ? f.addedAt : new Date().toISOString(),
        status: 'stale', checkedAt: null, items: [], error: null,
      }))
      .filter((f, i, arr) => arr.findIndex(x => x.url === f.url) === i)
      .slice(0, MAX_FEEDS);

    const ghsaEnabled = saved.ghsaEnabled === true;
    // Defaults to true (unlike ghsaEnabled, which defaults false) so a
    // saved state from before this feature existed - where the key is
    // simply absent - still opts into the live KEV fetch rather than
    // silently staying on the hand-maintained-only baseline forever.
    const kevLiveEnabled = saved.kevLiveEnabled !== false;
    // Same defaults-to-true reasoning as kevLiveEnabled above.
    const assurestartEnabled = saved.assurestartEnabled !== false;
    // Same defaults-to-false reasoning as ghsaEnabled above.
    const packageHealthEnabled = saved.packageHealthEnabled === true;
    const epssEnabled = saved.epssEnabled === true;

    const webhookUrl = typeof saved.webhookUrl === 'string' ? saved.webhookUrl.trim().slice(0, 500) : '';
    const webhookPlatform = saved.webhookPlatform === 'teams' ? 'teams' : 'slack';
    const webhookAutoNotify = saved.webhookAutoNotify === true;

    // Same "don't trust it, sanitize it" treatment as everything else here -
    // filter to strings, dedupe, cap at a reasonable max. Watched IDs that
    // no longer resolve to a known advisory are left as-is (harmless dead
    // weight) rather than cross-checked here; renderExposureList()'s watch
    // filter already handles an ID matching nothing without crashing.
    const watched = (Array.isArray(saved.watched) ? saved.watched : [])
      .filter(id => typeof id === 'string' && id)
      .filter((id, i, arr) => arr.indexOf(id) === i)
      .slice(0, MAX_WATCHED);

    const webhookFields = { webhookUrl, webhookPlatform, webhookAutoNotify };
    if (selected.length === 0 && custom.length === 0) return Object.assign(fresh, { ghsaEnabled, feeds, watched, kevLiveEnabled, assurestartEnabled, packageHealthEnabled, epssEnabled }, webhookFields);
    return Object.assign({ selected, custom, versions, ghsaEnabled, feeds, watched, kevLiveEnabled, assurestartEnabled, packageHealthEnabled, epssEnabled }, webhookFields);
  }

  let state = freshState();
  let rememberEnabled = true;
  let snapshot = null;          // signals.json, once loaded; each advisory tagged src:'snapshot'
  let live = null;              // { fetchedAt, advisories: {id: record} } - session or 24h cache, tagged src:'live'
  let lastCheckedAt = null;     // ISO of the most recent successful check, whether or not it found anything new
  let checkInFlight = false;
  let shownCount = INITIAL_CARDS;
  let printPrevShownCount = null;  // shownCount to restore after printing - see beforeprint/afterprint below
  let openModalId = null;  // which advisory's pop-out modal is open, if any - transient
  let modalTriggerEl = null;  // the .signal-head that opened it, refocused on close
  let expandedDescriptions = new Set();  // which long Descriptions the user chose to unclamp - transient
  let external = null;           // { fetchedAt, advisories: {id: record} } - GHSA-sourced, additive only, never persisted
  let ghsaCheckState = 'idle';   // 'idle' | 'checking' | 'ok' | 'error' - transient, resets every load
  let stackSearchQuery = '';     // transient drawer search - not persisted
  let sourcesSearchQuery = '';   // transient drawer search - not persisted

  function matchesSearch(text, query) {
    if (!query) return true;
    return String(text || '').toLowerCase().indexOf(query.trim().toLowerCase()) !== -1;
  }

  function persistStack() {
    try { localStorage.setItem(STACK_KEY, JSON.stringify(state)); } catch (e) {}
  }
  function persistIfEnabled() {
    // Skipped entirely while viewing a team's shared stack (see TEAM
    // DASHBOARD below) - team mode is a temporary lens over someone else's
    // shared list, not something that should silently overwrite whatever
    // you'd saved locally before opening the link. Leaving team view
    // restores your own saved stack untouched.
    if (rememberEnabled && !teamModeActive) persistStack();
  }
  function loadPersisted() {
    try {
      rememberEnabled = localStorage.getItem(REMEMBER_KEY) !== '0';
      const toggle = document.getElementById('remember-toggle');
      if (toggle) toggle.checked = rememberEnabled;
      const raw = localStorage.getItem(STACK_KEY);
      if (raw) state = normalizeStack(JSON.parse(raw));
    } catch (e) {}
  }

  document.getElementById('remember-toggle').addEventListener('change', e => {
    rememberEnabled = e.target.checked;
    try { localStorage.setItem(REMEMBER_KEY, rememberEnabled ? '1' : '0'); } catch (e) {}
    if (rememberEnabled) { persistStack(); persistCache(); }
    else { try { localStorage.removeItem(STACK_KEY); localStorage.removeItem(CACHE_KEY); localStorage.removeItem(HISTORY_KEY); } catch (e) {} }
  });

  // ---------------------------------------------------------------
  // AI-SHIELD BRIDGE (one-directional, read-only): both tools live under
  // lab.krismccabe.com, so localStorage is already shared across
  // /ai-shield/ and /flare/ - no URL params or new storage contract
  // needed. AI-SHIELD's deployment-pattern question ("how do you build")
  // is the closest thing it has to "which kind of AI packages you use";
  // it doesn't know exact package names, only architecture patterns, so
  // this maps each pattern to Flare's package GROUPS, not specific
  // packages, and only ever pre-selects each group's own defaults -
  // never invents a package selection more specific than what AI-SHIELD
  // actually told us.
  const SHIELD_ACTIVE_KEY = 'shield-active-v2';
  const SHIELD_SUGGESTION_APPLIED_KEY = 'flare-shield-suggestion-applied-v1';
  const DEPLOY_PATTERN_TO_GROUPS = {
    api: ['providers'],
    rag: ['providers', 'vector'],
    finetune: ['providers', 'mlops'],
    selfhost: ['serving', 'mlops'],
    agents: ['orchestration', 'app'],
  };

  // Applies at most once, ever (tracked by its own flag). Eligibility is
  // "has this visitor ever saved a stack", not "is state.selected empty
  // right now" - Flare ships with defaults already checked, so
  // state.selected is never actually empty on a first-ever visit, and
  // checking it would mean this could never fire at all.
  function maybeSuggestStackFromShield() {
    try {
      if (localStorage.getItem(SHIELD_SUGGESTION_APPLIED_KEY)) return false;
      if (localStorage.getItem(STACK_KEY) !== null) return false;
    } catch (e) { return false; }
    let raw;
    try { raw = localStorage.getItem(SHIELD_ACTIVE_KEY); } catch (e) { return false; }
    if (!raw) return false;
    let parsed;
    try { parsed = JSON.parse(raw); } catch (e) { return false; }
    const deployments = (parsed && parsed.meta && Array.isArray(parsed.meta.deployments)) ? parsed.meta.deployments : [];
    if (!deployments.length) return false;
    const groupIds = new Set();
    deployments.forEach(d => (DEPLOY_PATTERN_TO_GROUPS[d] || []).forEach(g => groupIds.add(g)));
    if (!groupIds.size) return false;
    const suggested = WATCHLIST.packages.filter(p => groupIds.has(p.group) && p.default).map(p => p.key);
    if (!suggested.length) return false;
    state.selected = suggested;
    try { localStorage.setItem(SHIELD_SUGGESTION_APPLIED_KEY, '1'); } catch (e) {}
    return true;
  }

  function renderShieldSuggestionNote(show) {
    const el = document.getElementById('shield-suggestion-note');
    if (el) el.hidden = !show;
  }

  // ---------------------------------------------------------------
  // RENDER: the stack selector grid
  // ---------------------------------------------------------------
  function groupOptions(groupId) {
    return WATCHLIST.packages.filter(p => p.group === groupId);
  }

  function fmtTime(iso) {
    if (!iso) return '';
    try { return new Date(iso).toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' }); } catch (e) { return ''; }
  }

  function customStatusHtml(p) {
    if (p.status === 'pending') return '<span class="custom-status">Checking&hellip;</span>';
    if (p.status === 'ok') {
      return '<span class="custom-status">' + p.count + ' advisor' + (p.count === 1 ? 'y' : 'ies') +
        ' &mdash; checked ' + fmtTime(p.checkedAt) + '</span>';
    }
    if (p.status === 'none') {
      return '<span class="custom-status custom-status-ok">No advisories found &mdash; checked ' + fmtTime(p.checkedAt) + '</span>';
    }
    if (p.status === 'error') {
      return '<span class="custom-status custom-status-error">Couldn&rsquo;t look this up ' +
        '<button type="button" class="custom-retry" data-retry-key="' + escapeHtml(p.key) + '">Retry</button></span>';
    }
    return '<span class="custom-status">Not checked this session ' +
      '<button type="button" class="custom-retry" data-retry-key="' + escapeHtml(p.key) + '">Check now</button></span>';
  }

  // Only ever shown once checkPackageHealth() has actually run for this
  // key (packageHealth[key].checked) - a package that's simply never
  // been checked (toggle off, or an ecosystem this feature doesn't cover)
  // shows nothing, not a false "healthy" implication.
  function packageHealthBadgeHtml(pkg) {
    const h = packageHealth[pkg.key];
    if (!h || !h.checked || h.error) return '';
    if (h.deprecated) {
      return '<span class="pkg-health pkg-health-deprecated" title="' + escapeHtml(h.deprecated) + '">Deprecated by maintainer</span>';
    }
    if (h.stale) {
      const age = daysSince(h.lastRelease);
      const years = age != null ? (age / 365).toFixed(1) : null;
      return '<span class="pkg-health pkg-health-stale" title="Last release ' + escapeHtml(fmtDate(h.lastRelease)) + '">' +
        'No release in ' + (years || '18+ months') + (years ? ' years' : '') + '</span>';
    }
    return '';
  }

  // Only shown for a key with a known exact version (see VERSION-AWARE
  // MATCHING) - absence means nothing more than "no version on file",
  // never "not vulnerable".
  function versionBadgeHtml(pkg) {
    const v = state.versions[pkg.key];
    if (!v) return '';
    return '<span class="pkg-version" title="Live checks for this package are scoped to exactly this version, not just the name">v' + escapeHtml(v) + '</span>';
  }

  function stackOptionHtml(pkg, isCustom) {
    const selected = state.selected.indexOf(pkg.key) !== -1;
    return '<div class="stack-option' + (isCustom ? ' is-custom' : '') + (selected ? ' selected' : '') +
      '" data-key="' + escapeHtml(pkg.key) + '" role="button" tabindex="0" aria-pressed="' + selected + '">' +
      (isCustom ? '<button type="button" class="custom-remove" data-remove-key="' + escapeHtml(pkg.key) +
        '" aria-label="Remove ' + escapeHtml(pkg.label || pkg.name) + '">&times;</button>' : '') +
      '<span class="s-name">' + escapeHtml(pkg.label || pkg.name) + (isCustom ? ' <span class="custom-tag">custom</span>' : '') + '</span>' +
      '<span class="s-eco">' + escapeHtml(pkg.ecosystem) + '</span>' +
      versionBadgeHtml(pkg) +
      packageHealthBadgeHtml(pkg) +
      (isCustom ? customStatusHtml(pkg) : '') +
    '</div>';
  }

  function toggleKey(key) {
    const idx = state.selected.indexOf(key);
    // Deselecting drops any known version too - a stale version from a
    // previous import shouldn't silently reattach itself if the package is
    // picked again later without re-importing.
    if (idx === -1) state.selected.push(key); else { state.selected.splice(idx, 1); delete state.versions[key]; }
    shownCount = INITIAL_CARDS;
    persistIfEnabled();
    queueTeamUpdate();
    renderStackSelector();
    renderExposureList();
  }

  function renderStackSelector() {
    const grid = document.getElementById('stack-grid');
    const count = document.getElementById('stack-selected-count');
    const summaryCount = document.getElementById('stack-summary-count');
    if (summaryCount) {
      summaryCount.textContent = state.selected.length === 0
        ? 'No packages selected yet.'
        : state.selected.length + ' package' + (state.selected.length === 1 ? '' : 's') + ' in your stack.';
    }
    if (!grid) return;

    if (count) {
      count.textContent = state.selected.length === 0
        ? 'No packages selected yet.'
        : state.selected.length + ' package' + (state.selected.length === 1 ? '' : 's') + ' selected.';
    }

    // "Select all" scopes to whatever's currently visible under the search,
    // not the group's full membership - matches what the button looks like
    // it's about to act on.
    const groupsHtml = WATCHLIST.groups.map(g => {
      const opts = groupOptions(g.id).filter(p => matchesSearch(p.label || p.name, stackSearchQuery));
      if (!opts.length) return '';
      const keys = opts.map(p => p.key);
      const allSelected = keys.every(k => state.selected.indexOf(k) !== -1);
      return '<div class="stack-group">' +
        '<div class="stack-group-head">' +
          '<div><h3>' + escapeHtml(g.name) + '</h3>' +
            (g.blurb ? '<p class="sg-blurb">' + escapeHtml(g.blurb) + '</p>' : '') +
          '</div>' +
          '<div class="stack-group-actions"><button type="button" data-select-all="' + escapeHtml(g.id) + '">' +
            (allSelected ? 'Clear' : 'Select all') + '</button></div>' +
        '</div>' +
        '<div class="stack-grid-inner">' + opts.map(p => stackOptionHtml(p, false)).join('') + '</div>' +
      '</div>';
    }).join('');

    const filteredCustom = state.custom.filter(p => matchesSearch(p.label || p.name, stackSearchQuery));
    const customHtml = filteredCustom.length
      ? '<div class="stack-group"><div class="stack-group-head"><div><h3>Custom packages</h3></div></div>' +
        '<div class="stack-grid-inner">' + filteredCustom.map(p => stackOptionHtml(p, true)).join('') + '</div></div>'
      : '';

    grid.innerHTML = (groupsHtml || customHtml)
      ? groupsHtml + customHtml
      : '<p class="drawer-search-empty">No packages match &ldquo;' + escapeHtml(stackSearchQuery) + '&rdquo;.</p>';

    grid.querySelectorAll('.stack-option').forEach(el => {
      el.addEventListener('click', () => toggleKey(el.dataset.key));
      el.addEventListener('keydown', e => {
        if (e.target !== el) return; // let nested custom-remove/retry buttons handle their own activation
        if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); toggleKey(el.dataset.key); }
      });
    });

    grid.querySelectorAll('.custom-remove').forEach(btn => {
      btn.addEventListener('click', e => { e.stopPropagation(); removeCustomPackage(btn.dataset.removeKey); });
    });
    grid.querySelectorAll('.custom-retry').forEach(btn => {
      btn.addEventListener('click', e => { e.stopPropagation(); checkCustomPackage(btn.dataset.retryKey); });
    });

    grid.querySelectorAll('[data-select-all]').forEach(btn => {
      btn.addEventListener('click', () => {
        const keys = groupOptions(btn.dataset.selectAll)
          .filter(p => matchesSearch(p.label || p.name, stackSearchQuery))
          .map(p => p.key);
        const allSelected = keys.every(k => state.selected.indexOf(k) !== -1);
        if (allSelected) state.selected = state.selected.filter(k => keys.indexOf(k) === -1);
        else keys.forEach(k => { if (state.selected.indexOf(k) === -1) state.selected.push(k); });
        shownCount = INITIAL_CARDS;
        persistIfEnabled();
        renderStackSelector();
        renderExposureList();
      });
    });
  }

  // ---------------------------------------------------------------
  // CUSTOM PACKAGES (decision 4) - free-form additions beyond the
  // curated ~25, resolved live since they're unknown at snapshot-build
  // time. Validation runs entirely before any network call.
  // ---------------------------------------------------------------
  function validateCustomName(name, ecosystem) {
    const trimmed = String(name || '').trim();
    if (!trimmed) return 'Enter a package name.';
    if (trimmed.length > 120) return 'That name is too long.';
    if (!/^[@a-z0-9._/-]+$/i.test(trimmed)) return 'Only letters, numbers, and . _ - / @ are allowed.';
    if (trimmed.indexOf('..') !== -1) return 'Package names can’t contain "..".';
    if (ECOSYSTEMS.indexOf(ecosystem) === -1) return 'Choose a valid ecosystem.';
    const key = makePkgKey(trimmed, ecosystem);
    if (KNOWN_KEYS.has(key)) return 'Already in the curated list above.';
    if (state.custom.some(p => p.key === key)) return 'Already added.';
    if (state.custom.length >= MAX_CUSTOM) return 'You can add up to ' + MAX_CUSTOM + ' custom packages.';
    return '';
  }

  function addCustomPackage(name, ecosystem) {
    const error = validateCustomName(name, ecosystem);
    if (error) return { error };
    const trimmed = String(name).trim();
    const key = makePkgKey(trimmed, ecosystem);
    const entry = { key, name: trimmed, ecosystem, label: trimmed, addedAt: new Date().toISOString(), status: 'pending', checkedAt: null, count: 0 };
    state.custom.push(entry);
    if (state.selected.indexOf(key) === -1) state.selected.push(key);
    shownCount = INITIAL_CARDS;
    persistIfEnabled();
    renderStackSelector();
    renderExposureList();
    checkCustomPackage(key);
    return { error: null };
  }

  function removeCustomPackage(key) {
    state.custom = state.custom.filter(p => p.key !== key);
    state.selected = state.selected.filter(k => k !== key);
    delete state.versions[key];
    shownCount = INITIAL_CARDS;
    if (relatedFilterKey === key) relatedFilterKey = null;
    persistIfEnabled();
    renderStackSelector();
    renderExposureList();
  }

  // The one path that resolves a single package immediately (on add, or on
  // retry/"check now") rather than diffing against known IDs like
  // checkForNewAdvisories() does - a brand-new custom package has no prior
  // state to diff against, so everything returned is new.
  async function checkCustomPackage(key) {
    const pkg = state.custom.find(p => p.key === key);
    if (!pkg) return;
    pkg.status = 'pending';
    renderStackSelector();

    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), FETCH_TIMEOUT);
    try {
      const idToPkgs = await osvQueryBatch([{ ...pkg, version: state.versions[pkg.key] }], ctrl.signal);
      const ids = Object.keys(idToPkgs);
      if (!ids.length) {
        pkg.status = 'none';
        pkg.count = 0;
      } else {
        const { records } = await osvHydrate(ids, ctrl.signal);
        const normalized = {};
        Object.keys(records).forEach(id => {
          const rec = normalizeRecord(records[id], idToPkgs[id]);
          if (rec) normalized[id] = rec;
        });
        mergeLive(normalized);
        persistCache();
        pkg.status = 'ok';
        pkg.count = Object.keys(normalized).length;
      }
      pkg.checkedAt = new Date().toISOString();
      lastCheckedAt = pkg.checkedAt;
    } catch (err) {
      pkg.status = 'error';
    } finally {
      clearTimeout(timer);
      persistIfEnabled();
      renderStackSelector();
      withReorderAnimation(renderExposureList);
      renderProvenance();
    }
  }

  // ---------------------------------------------------------------
  // SBOM / LOCKFILE IMPORT - "here's what we actually run" instead of
  // clicking through the grid by hand. Everything here runs on the text
  // already in the browser; nothing is fetched or sent anywhere to do the
  // parsing itself. Deliberately matches against WATCHLIST only (not a
  // general SCA tool) - Flare tracks AI-stack libraries specifically, so
  // silently bulk-importing an entire transitive dependency tree as
  // "custom" packages would blow past MAX_CUSTOM, send a pile of unrelated
  // package names to OSV.dev, and dilute the one thing this tool is for.
  // ---------------------------------------------------------------

  // Only an exact "==" pin counts as a known version - >=, ~=, a bare
  // range, or no specifier at all tells us nothing about what's actually
  // installed, so those are left undefined rather than guessed at.
  function parseRequirementsTxt(text) {
    const out = [];
    text.split('\n').forEach(rawLine => {
      let line = rawLine.split('#')[0].trim();
      if (!line) return;
      if (/^-/.test(line)) return; // -e, -r other.txt, --index-url, etc.
      if (/^(git\+|https?:\/\/|\.\/|\.\.\/|\/)/.test(line)) return; // VCS/URL/path installs - no clean name
      line = line.split(';')[0].trim(); // strip environment markers
      const m = line.match(/^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(==\s*([A-Za-z0-9.!+_-]+))?/);
      if (m) out.push({ name: m[1], ecosystem: 'PyPI', version: m[3] || undefined });
    });
    return out;
  }

  function parseNpmLockfile(json) {
    const out = [];
    const seen = new Set();
    function addName(name, version) {
      if (!name || seen.has(name)) return;
      seen.add(name);
      out.push({ name, ecosystem: 'npm', version: version || undefined });
    }
    if (json.packages && typeof json.packages === 'object') {
      // lockfileVersion 2/3 - keys are paths like "node_modules/foo" or
      // "node_modules/@scope/bar/node_modules/nested-dep"; the package name
      // is everything after the LAST node_modules/ segment. Each entry
      // carries the exact resolved "version" straight from the lockfile.
      Object.keys(json.packages).forEach(p => {
        if (!p) return; // "" is the root project itself
        const idx = p.lastIndexOf('node_modules/');
        if (idx === -1) return;
        const entry = json.packages[p];
        addName(p.slice(idx + 'node_modules/'.length), entry && entry.version);
      });
    } else if (json.dependencies && typeof json.dependencies === 'object') {
      // lockfileVersion 1 - nested "dependencies" objects keyed by name,
      // each with its own resolved "version".
      (function walk(deps) {
        Object.keys(deps).forEach(name => {
          addName(name, deps[name] && deps[name].version);
          if (deps[name] && deps[name].dependencies) walk(deps[name].dependencies);
        });
      })(json.dependencies);
    }
    return out;
  }

  function extractPep508Names(str, out) {
    const items = str.match(/"([^"]+)"|'([^']+)'/g) || [];
    items.forEach(raw => {
      const s = raw.slice(1, -1);
      const m = s.match(/^([A-Za-z0-9][A-Za-z0-9._-]*)/);
      if (m) out.push({ name: m[1], ecosystem: 'PyPI' });
    });
  }

  // Deliberately not a general TOML parser - just enough structure
  // (section headers, poetry's "name = ..." dependency lines, PEP 621's
  // dependencies = [ "..." ] array) to pull package names out of the two
  // real-world pyproject.toml shapes, nothing else in the file matters here.
  function parsePyprojectToml(text) {
    const out = [];
    let section = null;
    let inDepsArray = false;
    let arrayBuf = '';
    text.split('\n').forEach(rawLine => {
      const line = rawLine.trim();
      const sectionMatch = line.match(/^\[([^\]]+)\]$/);
      if (sectionMatch) { section = sectionMatch[1]; inDepsArray = false; return; }
      if (!section) return;
      if (/^tool\.poetry(\.group\.[^.]+)?\.dependencies$/.test(section)) {
        const m = line.match(/^([A-Za-z0-9][A-Za-z0-9._-]*)\s*=/);
        if (m && m[1].toLowerCase() !== 'python') out.push({ name: m[1], ecosystem: 'PyPI' });
        return;
      }
      if (section === 'project') {
        if (/^dependencies\s*=\s*\[/.test(line)) {
          const closesHere = /\]\s*$/.test(line);
          arrayBuf = line.replace(/^dependencies\s*=\s*\[/, '').replace(/\]\s*$/, '');
          inDepsArray = !closesHere;
          if (closesHere) { extractPep508Names(arrayBuf, out); arrayBuf = ''; }
          return;
        }
        if (inDepsArray) {
          if (/\]\s*$/.test(line)) {
            arrayBuf += ' ' + line.replace(/\]\s*$/, '');
            extractPep508Names(arrayBuf, out);
            arrayBuf = '';
            inDepsArray = false;
          } else {
            arrayBuf += ' ' + line;
          }
        }
      }
    });
    return out;
  }

  const PURL_TYPE_TO_ECOSYSTEM = {
    pypi: 'PyPI', npm: 'npm', golang: 'Go', maven: 'Maven',
    cargo: 'crates.io', gem: 'RubyGems', nuget: 'NuGet', composer: 'Packagist',
  };
  function parsePurl(purl) {
    // pkg:type/namespace/name@version or pkg:type/name@version
    const m = String(purl || '').match(/^pkg:([a-zA-Z0-9.+-]+)\/(.+?)(?:@([^?#]+))?(?:[?#]|$)/);
    if (!m) return null;
    const ecosystem = PURL_TYPE_TO_ECOSYSTEM[m[1].toLowerCase()];
    if (!ecosystem) return null;
    let path;
    try { path = decodeURIComponent(m[2]); } catch (e) { path = m[2]; }
    let version;
    if (m[3]) { try { version = decodeURIComponent(m[3]); } catch (e) { version = m[3]; } }
    return { name: path.split('?')[0].split('#')[0], ecosystem, version };
  }
  function parseCycloneDx(json) {
    const out = [];
    (json.components || []).forEach(c => {
      if (c.purl) { const p = parsePurl(c.purl); if (p) out.push(p); }
    });
    return out;
  }
  function parseSpdx(json) {
    const out = [];
    (json.packages || []).forEach(p => {
      const purlRef = (p.externalRefs || []).find(r => r.referenceType === 'purl');
      if (purlRef) { const parsed = parsePurl(purlRef.referenceLocator); if (parsed) out.push(parsed); }
    });
    return out;
  }

  function detectAndParseImport(filename, text) {
    const lowerName = String(filename || '').toLowerCase();
    let json = null;
    try { json = JSON.parse(text); } catch (e) { json = null; }
    if (json && typeof json === 'object') {
      if (json.bomFormat === 'CycloneDX' || (Array.isArray(json.components) && json.specVersion)) {
        return { format: 'CycloneDX SBOM', items: parseCycloneDx(json) };
      }
      if (json.spdxVersion || (Array.isArray(json.packages) && json.packages.some(p => p && p.SPDXID))) {
        return { format: 'SPDX SBOM', items: parseSpdx(json) };
      }
      if (json.lockfileVersion || json.packages || json.dependencies) {
        return { format: 'npm lockfile', items: parseNpmLockfile(json) };
      }
      return { format: 'unrecognized JSON', items: [] };
    }
    if (lowerName.endsWith('.toml') || /^\s*\[tool\.poetry/m.test(text) || /^\s*\[project\]/m.test(text)) {
      return { format: 'pyproject.toml', items: parsePyprojectToml(text) };
    }
    return { format: 'requirements.txt', items: parseRequirementsTxt(text) };
  }

  // Only ever SELECTS existing watchlist entries - never creates custom
  // packages (see the header comment above for why). Duplicate names
  // across ecosystems in the same file (a JS + Python monorepo's combined
  // SBOM, say) are each considered independently since they're genuinely
  // different packages to OSV.
  function applyImportedPackages(items) {
    let matched = 0, alreadySelected = 0, notTracked = 0, versioned = 0;
    const seenKeys = new Set();
    items.forEach(({ name, ecosystem, version }) => {
      if (!ecosystem) { notTracked++; return; }
      const key = makePkgKey(name, ecosystem);
      if (seenKeys.has(key)) return;
      seenKeys.add(key);
      if (!KNOWN_KEYS.has(key)) { notTracked++; return; }
      const wasSelected = state.selected.indexOf(key) !== -1;
      if (!wasSelected) { state.selected.push(key); matched++; }
      else alreadySelected++;
      // Re-importing an already-selected package still refreshes its
      // version - the file you just uploaded is the freshest truth about
      // what's actually installed, whether or not the key was new.
      if (version && String(version).length <= MAX_VERSION_LEN) {
        state.versions[key] = String(version);
        versioned++;
      }
    });
    if (matched || versioned) {
      shownCount = INITIAL_CARDS;
      persistIfEnabled();
      renderStackSelector();
      withReorderAnimation(renderExposureList);
    }
    return { matched, alreadySelected, notTracked, versioned, total: items.length };
  }

  function importResultMessage(format, result) {
    if (!result.total) {
      return 'Couldn&rsquo;t find any package entries in that file (parsed as ' + escapeHtml(format) + ').';
    }
    const parts = [];
    if (result.matched) parts.push(result.matched + ' package' + (result.matched === 1 ? '' : 's') + ' selected');
    if (result.alreadySelected) parts.push(result.alreadySelected + ' already selected');
    const matchedPart = parts.length ? parts.join(', ') : 'No matches in Flare&rsquo;s curated list';
    const untrackedPart = result.notTracked
      ? ' <span class="sbom-warn">' + result.notTracked + ' other package' + (result.notTracked === 1 ? " isn't" : "s aren't") + " part of Flare's AI-stack list, so " + (result.notTracked === 1 ? "it wasn't" : "they weren't") + ' added.</span>'
      : '';
    // Exact pinned versions sharpen the live advisory check for those
    // packages (see VERSION-AWARE MATCHING) - worth surfacing since it's
    // not obvious from the selection count alone.
    const versionedPart = result.versioned
      ? ' ' + result.versioned + ' package' + (result.versioned === 1 ? ' has' : 's have') + ' an exact version on file, so live checks for ' + (result.versioned === 1 ? 'it' : 'them') + ' are version-scoped, not just name-scoped.'
      : '';
    return 'Parsed as ' + escapeHtml(format) + ' &mdash; ' + matchedPart + '.' + untrackedPart + versionedPart;
  }

  function runSbomImport(filename, text) {
    const resultEl = document.getElementById('sbom-import-result');
    const { format, items } = detectAndParseImport(filename, text);
    const result = applyImportedPackages(items);
    if (resultEl) resultEl.innerHTML = importResultMessage(format, result);
  }

  // ---------------------------------------------------------------
  // SNAPSHOT: signals.json, fetched once at load (live refresh is a
  // later build step - everything here is snapshot-only for now)
  // ---------------------------------------------------------------
  function loadSnapshot() {
    const today = new Date().toISOString().slice(0, 10);
    return fetch('signals.json?d=' + today)
      .then(r => { if (!r.ok) throw new Error('bad status ' + r.status); return r.json(); })
      .then(data => {
        (data.advisories || []).forEach(a => { a.src = 'snapshot'; });
        snapshot = data;
        readCache();
      })
      .catch(() => { snapshot = null; renderRefreshStatus('snapshot-unavailable'); })
      .then(() => {
        renderProvenance();
        computeChangeHistory();
        maybeAutoNotifyWebhook();
        renderExposureList();
        renderHeatmap();
        // Fetch the latest from OSV automatically on every load - see the
        // disclaimer for what that sends and to whom. Only when there's
        // something selected to check; the button stays for a manual re-run.
        if (snapshot && state.selected.length > 0) checkForNewAdvisories();
      });
  }

  function renderProvenance() {
    const el = document.getElementById('console-sync-text');
    const dot = document.getElementById('status-dot');
    if (!el) return;
    if (!snapshot) {
      el.textContent = 'Advisory data unavailable.';
      if (dot) dot.className = 'status-dot warn';
      return;
    }
    const syncedIso = lastCheckedAt || (live ? live.fetchedAt : snapshot.generatedAt);
    el.textContent = 'Advisory data as of ' + fmtDate(snapshot.generatedAt) + '. Last synced ' + fmtRelativeTime(syncedIso) + '.';
    if (dot) dot.className = 'status-dot ok';
  }

  // Briefly swaps the sync line for a result message (e.g. "2 new
  // advisories found"), then reverts to the normal "Last synced" text -
  // a console shows live state, not a stacking toast log.
  let flashSyncTimer = null;
  function flashSyncMessage(msg) {
    const el = document.getElementById('console-sync-text');
    if (!el) return;
    el.textContent = msg;
    clearTimeout(flashSyncTimer);
    flashSyncTimer = setTimeout(renderProvenance, 4000);
  }

  function showDiagnostics(msg) {
    const banner = document.getElementById('diagnostics-banner');
    const text = document.getElementById('diagnostics-text');
    if (!banner || !text) return;
    text.textContent = msg;
    banner.hidden = false;
  }
  function hideDiagnostics() {
    const banner = document.getElementById('diagnostics-banner');
    if (banner) banner.hidden = true;
  }

  // ---------------------------------------------------------------
  // LIVE REFRESH (fetches automatically on load and after adding/checking
  // a custom package; the button below stays for a manual re-run)
  // ---------------------------------------------------------------
  const HYDRATE_CAP = 40;
  const HYDRATE_POOL = 6;
  const FETCH_TIMEOUT = 10000;
  // 700 was below the *median* raw details length in real OSV records
  // (~669 chars) - meaning it truncated a plain-majority of advisories,
  // usually mid-sentence, not just unusually long ones. Raised to 3000,
  // kept identical to refresh-signals.py's cap: at 3000 only ~21% of the
  // current watchlist still truncates (down from ~45% at 700), for about
  // +90KB on the snapshot - real cost, but the previous cap was cutting
  // the normal case, not the long tail.
  const DETAILS_MAX_CHARS = 3000;
  const OTHER_REFS_MAX = 5;
  const OTHER_REFS_SKIP_HOSTS = new Set(['github.com', 'pypi.org', 'nvd.nist.gov', 'osv.dev', 'npmjs.com', 'www.npmjs.com']);

  // Client mirror of refresh-signals.py's extract_other_refs() - surfaces
  // third-party citations (vendor blogs, independent research writeups)
  // already present in the advisory's own references[], filtered to
  // non-redundant, non-data-file, non-hosting-platform URLs.
  function extractOtherRefs(raw, knownUrls) {
    const seen = new Set((knownUrls || []).filter(Boolean));
    const out = [];
    (raw.references || []).forEach(r => {
      if (out.length >= OTHER_REFS_MAX) return;
      const url = r.url || '';
      if (!url || seen.has(url)) return;
      seen.add(url);
      if (/\.(json|yaml|yml)$/i.test(url)) return;
      let host = '';
      try { host = new URL(url).hostname.toLowerCase(); } catch (e) { return; }
      if (host.indexOf('www.') === 0) host = host.slice(4);
      if (!host || OTHER_REFS_SKIP_HOSTS.has(host)) return;
      out.push({ url, source: host });
    });
    return out;
  }

  // CVSS v3.1 base score - client mirror of refresh-signals.py's
  // cvss3_base_score(), kept in lockstep because custom packages (a later
  // step) are hydrated only in the browser and must be scored the same way.
  const CVSS3_WEIGHTS = {
    AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 },
    AC: { L: 0.77, H: 0.44 },
    PR_U: { N: 0.85, L: 0.62, H: 0.27 },
    PR_C: { N: 0.85, L: 0.68, H: 0.5 },
    UI: { N: 0.85, R: 0.62 },
    CIA: { N: 0.0, L: 0.22, H: 0.56 },
  };
  function cvss3Roundup(x) {
    const intInput = Math.round(x * 100000);
    if (intInput % 10000 === 0) return intInput / 100000;
    return (Math.floor(intInput / 10000) + 1) / 10;
  }
  function cvss3BaseScore(vector) {
    if (!vector || vector.indexOf('CVSS:3') === -1) return null;
    const parts = {};
    vector.split('/').forEach(tok => {
      const idx = tok.indexOf(':');
      if (idx === -1) return;
      parts[tok.slice(0, idx)] = tok.slice(idx + 1);
    });
    const scope = parts.S;
    const prTable = scope === 'C' ? CVSS3_WEIGHTS.PR_C : CVSS3_WEIGHTS.PR_U;
    const av = CVSS3_WEIGHTS.AV[parts.AV], ac = CVSS3_WEIGHTS.AC[parts.AC], ui = CVSS3_WEIGHTS.UI[parts.UI],
      pr = prTable[parts.PR], c = CVSS3_WEIGHTS.CIA[parts.C], i = CVSS3_WEIGHTS.CIA[parts.I], a = CVSS3_WEIGHTS.CIA[parts.A];
    if ([av, ac, ui, pr, c, i, a].some(v => v === undefined)) return null;

    const iss = 1 - ((1 - c) * (1 - i) * (1 - a));
    const impact = scope === 'C' ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15) : 6.42 * iss;
    const exploitability = 8.22 * av * ac * pr * ui;
    if (impact <= 0) return 0.0;
    return scope === 'C'
      ? cvss3Roundup(Math.min(1.08 * (impact + exploitability), 10))
      : cvss3Roundup(Math.min(impact + exploitability, 10));
  }
  function bandFromScore(score) {
    if (score === null || score === undefined) return null;
    if (score >= 9.0) return 'CRITICAL';
    if (score >= 7.0) return 'HIGH';
    if (score >= 4.0) return 'MEDIUM';
    if (score > 0.0) return 'LOW';
    return null;
  }

  // Client mirror of refresh-signals.py's normalize_record() - same field
  // shape, same severity/fix-extraction rules, so a live-merged card is
  // indistinguishable from a snapshot one except for its src tag.
  function normalizeRecord(raw, pkgKeys) {
    if (!raw || !raw.id) return null;
    const vid = raw.id;

    let sev = null, score = null, sevFrom = 'none';
    const dbSev = raw.database_specific && raw.database_specific.severity;
    if (dbSev && ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].indexOf(String(dbSev).toUpperCase()) !== -1) {
      sev = String(dbSev).toUpperCase();
      sevFrom = 'osv';
    } else {
      const vectors = raw.severity || [];
      let vectorStr = null;
      ['CVSS_V4', 'CVSS_V3'].some(pref => {
        const found = vectors.find(v => v.type === pref);
        if (found) { vectorStr = found.score; return true; }
        return false;
      });
      if (vectorStr) {
        const s = cvss3BaseScore(vectorStr);
        if (s !== null) { score = s; sev = bandFromScore(s) || 'LOW'; sevFrom = 'cvss'; }
      }
    }
    if (sev === null) { sev = 'UNKNOWN'; sevFrom = 'none'; }

    let cvssVector = null;
    (raw.severity || []).some(v => {
      if (v.type && v.type.indexOf('CVSS') === 0) { cvssVector = v.score; return true; }
      return false;
    });

    const aliases = (raw.aliases || []).filter(a => /^CVE-\d{4}-\d+$/.test(a));
    const cve = aliases.length ? aliases[0] : null;

    const watchedKeys = new Set(allPackages().map(p => p.key));
    const fixes = [];
    (raw.affected || []).forEach(aff => {
      const pkg = aff.package || {};
      const key = makePkgKey(pkg.name || '', pkg.ecosystem || '');
      if (!watchedKeys.has(key)) return;
      (aff.ranges || []).forEach(rng => {
        const events = rng.events || [];
        const fixed = events.filter(e => 'fixed' in e).map(e => e.fixed);
        const introduced = events.filter(e => 'introduced' in e).map(e => e.introduced);
        if (fixed.length || introduced.length) fixes.push({ pkg: key, fixed, introduced, rangeType: rng.type });
      });
    });

    let details = raw.details || '';
    const truncated = details.length > DETAILS_MAX_CHARS;
    if (truncated) {
      const cut = details.slice(0, DETAILS_MAX_CHARS);
      const lastSpace = cut.lastIndexOf(' ');
      details = (lastSpace > -1 ? cut.slice(0, lastSpace) : cut) + '…';
    }

    const refs = { osv: 'https://osv.dev/vulnerability/' + vid };
    (raw.references || []).forEach(r => {
      const url = r.url || '';
      if (url.indexOf('github.com') !== -1 && url.indexOf('/security/advisories/') !== -1 && !refs.ghsa) refs.ghsa = url;
    });
    if (cve) refs.nvd = 'https://nvd.nist.gov/vuln/detail/' + cve;

    const otherRefs = extractOtherRefs(raw, Object.keys(refs).map(k => refs[k]));

    return {
      id: vid,
      pkgs: Array.from(pkgKeys).sort(),
      sev, cvss: cvssVector, score, sevFrom,
      summary: raw.summary || '',
      details, detailsTruncated: truncated,
      published: (raw.published || '').slice(0, 10) || null,
      modified: (raw.modified || '').slice(0, 10) || null,
      cve, aliases,
      cwe: (raw.database_specific && raw.database_specific.cwe_ids) || [],
      reviewed: !!(raw.database_specific && raw.database_specific.github_reviewed),
      fixes, refs, otherRefs,
      src: 'live',
    };
  }

  // When a query carries a version, OSV.dev filters server-side to only
  // the vulnerabilities that actually affect that version (it evaluates
  // the affected-range data itself) - Flare never computes semver ranges
  // locally, across 8 different ecosystems' version schemes that would be
  // its own source of bugs. Only ever narrows results for the packages
  // that have a known version; every other package queries exactly as
  // before (name+ecosystem only).
  async function osvQueryBatch(pkgs, signal) {
    const queries = pkgs.map(p => {
      const q = { package: { name: p.name, ecosystem: p.ecosystem } };
      if (p.version) q.version = p.version;
      return q;
    });
    const resp = await fetch('https://api.osv.dev/v1/querybatch', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ queries }),
      signal,
    });
    if (!resp.ok) throw new Error('querybatch failed: ' + resp.status);
    const data = await resp.json();
    const results = data.results || [];
    const idToPkgs = {};
    pkgs.forEach((p, i) => {
      const vulns = (results[i] && results[i].vulns) || [];
      vulns.forEach(v => {
        if (!idToPkgs[v.id]) idToPkgs[v.id] = new Set();
        idToPkgs[v.id].add(p.key);
      });
    });
    return idToPkgs;
  }

  async function osvHydrate(ids, signal) {
    const capped = ids.slice(0, HYDRATE_CAP);
    const records = {};
    let idx = 0;
    async function worker() {
      while (idx < capped.length) {
        const id = capped[idx++];
        try {
          const resp = await fetch('https://api.osv.dev/v1/vulns/' + encodeURIComponent(id), { signal });
          if (resp.ok) records[id] = await resp.json();
        } catch (e) { /* leave missing - caller treats absence as a failed hydrate */ }
      }
    }
    const workers = [];
    for (let w = 0; w < HYDRATE_POOL; w++) workers.push(worker());
    await Promise.allSettled(workers);
    return { records, truncated: ids.length > capped.length };
  }

  // ---------------------------------------------------------------
  // GITHUB SECURITY ADVISORIES (optional built-in source, opt-in) -
  // queried directly from the browser like OSV.dev already is, same
  // no-backend/nothing-leaves-this-page model. Ecosystem+package
  // filtering (not keyword search), so results are as precise as OSV's -
  // that precision is what makes the additive, no-duplicates merge in
  // mergedAdvisoriesMap() safe to promise in the Sources tab copy.
  // ---------------------------------------------------------------
  const GH_ECOSYSTEM_FROM_FLARE = {
    PyPI: 'pip', npm: 'npm', Go: 'go', Maven: 'maven',
    'crates.io': 'rust', RubyGems: 'rubygems', NuGet: 'nuget', Packagist: 'composer',
  };
  const GH_ECOSYSTEM_TO_FLARE = {
    pip: 'PyPI', npm: 'npm', go: 'Go', maven: 'Maven',
    rust: 'crates.io', rubygems: 'RubyGems', nuget: 'NuGet', composer: 'Packagist',
  };
  const GH_SEV_MAP = { critical: 'CRITICAL', high: 'HIGH', medium: 'MEDIUM', low: 'LOW' };

  async function ghsaFetchForEcosystem(ghEco, names, signal) {
    const affects = names.slice(0, 20).map(encodeURIComponent).join(',');
    const url = 'https://api.github.com/advisories?ecosystem=' + encodeURIComponent(ghEco) +
      '&affects=' + affects + '&per_page=100';
    const resp = await fetch(url, { signal, headers: { Accept: 'application/vnd.github+json' } });
    if (!resp.ok) throw new Error('GHSA fetch failed: ' + resp.status);
    return resp.json();
  }

  function normalizeGhsaRecord(raw, pkgKeys) {
    if (!raw || !raw.ghsa_id) return null;
    const sev = GH_SEV_MAP[String(raw.severity || '').toLowerCase()] || 'UNKNOWN';
    const cvssVector = (raw.cvss && raw.cvss.vector_string) || null;
    const score = raw.cvss && typeof raw.cvss.score === 'number' ? raw.cvss.score : null;

    const watchedKeys = new Set(allPackages().map(p => p.key));
    const fixes = [];
    (raw.vulnerabilities || []).forEach(v => {
      const pkg = v.package || {};
      const eco = GH_ECOSYSTEM_TO_FLARE[pkg.ecosystem] || pkg.ecosystem;
      const key = makePkgKey(pkg.name || '', eco || '');
      if (!watchedKeys.has(key)) return;
      const fixed = v.first_patched_version && v.first_patched_version.identifier ? [v.first_patched_version.identifier] : [];
      if (fixed.length) fixes.push({ pkg: key, fixed, introduced: [], rangeType: 'ECOSYSTEM' });
    });

    let details = raw.description || raw.summary || '';
    const truncated = details.length > DETAILS_MAX_CHARS;
    if (truncated) {
      const cut = details.slice(0, DETAILS_MAX_CHARS);
      const lastSpace = cut.lastIndexOf(' ');
      details = (lastSpace > -1 ? cut.slice(0, lastSpace) : cut) + '…';
    }

    const refs = { ghsa: raw.html_url || ('https://github.com/advisories/' + raw.ghsa_id) };
    if (raw.cve_id) refs.nvd = 'https://nvd.nist.gov/vuln/detail/' + raw.cve_id;
    const otherRefs = extractOtherRefs({ references: raw.references }, Object.keys(refs).map(k => refs[k]));

    return {
      id: raw.ghsa_id,
      pkgs: Array.from(pkgKeys).sort(),
      sev, cvss: cvssVector, score, sevFrom: cvssVector ? 'cvss' : 'none',
      summary: raw.summary || '',
      details, detailsTruncated: truncated,
      published: (raw.published_at || '').slice(0, 10) || null,
      modified: (raw.updated_at || '').slice(0, 10) || null,
      cve: raw.cve_id || null,
      aliases: raw.cve_id ? [raw.cve_id] : [],
      cwe: (raw.cwes || []).map(c => c.cwe_id).filter(Boolean),
      reviewed: true,
      fixes, refs, otherRefs,
      src: 'github-advisories',
    };
  }

  async function checkGhsaSources() {
    if (!state.ghsaEnabled) return;
    const pkgs = selectedPackages();
    if (!pkgs.length) { ghsaCheckState = 'idle'; renderSourcesTab(); return; }

    ghsaCheckState = 'checking';
    renderSourcesTab();

    const byEco = {};
    pkgs.forEach(p => {
      const ghEco = GH_ECOSYSTEM_FROM_FLARE[p.ecosystem];
      if (!ghEco) return;
      (byEco[ghEco] = byEco[ghEco] || []).push(p);
    });

    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), FETCH_TIMEOUT);
    let hadError = false;
    try {
      for (const ghEco of Object.keys(byEco)) {
        try {
          const names = byEco[ghEco].map(p => p.name);
          const raws = await ghsaFetchForEcosystem(ghEco, names, ctrl.signal);
          const keyByName = {};
          byEco[ghEco].forEach(p => { keyByName[p.name.toLowerCase()] = p.key; });
          raws.forEach(raw => {
            const matchedKeys = new Set();
            (raw.vulnerabilities || []).forEach(v => {
              const name = ((v.package && v.package.name) || '').toLowerCase();
              if (keyByName[name]) matchedKeys.add(keyByName[name]);
            });
            if (!matchedKeys.size) return;
            const rec = normalizeGhsaRecord(raw, matchedKeys);
            if (!rec) return;
            if (!external) external = { fetchedAt: new Date().toISOString(), advisories: {} };
            external.advisories[rec.id] = rec;
          });
        } catch (e) { hadError = true; }
      }
    } finally {
      clearTimeout(timer);
    }
    ghsaCheckState = hadError ? 'error' : 'ok';
    renderSourcesTab();
    shownCount = INITIAL_CARDS;
    withReorderAnimation(renderExposureList);
    renderHeatmap();
  }

  // ---------------------------------------------------------------
  // PACKAGE MAINTENANCE STATUS (opt-in, off by default) - a package with
  // zero open CVEs can still be a real supply-chain risk if nobody's
  // maintaining it any more; the next vulnerability in an abandoned
  // dependency has no one left to patch it. Checks only your SELECTED
  // packages (not the full watchlist), and only PyPI/npm - the two
  // ecosystems every watchlist package uses today; other ecosystems are
  // silently skipped rather than guessed at. Two data points, both from
  // the registries themselves, not inferred: how long since the last
  // release, and (npm only - PyPI's registry has no equivalent field) an
  // explicit maintainer deprecation notice, a much stronger signal than
  // staleness alone, always shown regardless of date.
  //   PyPI JSON API:      https://pypi.org/pypi/<name>/json
  //     -> confirmed CORS (access-control-allow-origin: *); releases[<latest
  //        version>][].upload_time_iso_8601 gives the last publish date.
  //   npm registry API:   https://registry.npmjs.org/<name>
  //     -> confirmed CORS; time.modified gives the last publish date,
  //        versions[<latest>].deprecated carries the maintainer's own
  //        deprecation message when set (verified against the real
  //        "request" package, long-deprecated in favour of fetch/axios).
  // ---------------------------------------------------------------
  const STALE_DAYS = 545; // ~18 months with no release
  let packageHealth = {}; // key -> { checked, lastRelease, deprecated, stale, error }
  let packageHealthCheckState = 'idle'; // 'idle' | 'checking' | 'ok' | 'error'

  async function fetchPypiHealth(name) {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), FETCH_TIMEOUT);
    try {
      const r = await fetch('https://pypi.org/pypi/' + encodeURIComponent(name) + '/json', { signal: ctrl.signal });
      if (!r.ok) throw new Error('bad status ' + r.status);
      const data = await r.json();
      const latestVer = data.info && data.info.version;
      const files = latestVer && data.releases ? (data.releases[latestVer] || []) : [];
      const dates = files.map(f => f.upload_time_iso_8601).filter(Boolean).sort();
      return { lastRelease: dates.length ? dates[dates.length - 1] : null, deprecated: null };
    } finally {
      clearTimeout(timer);
    }
  }
  async function fetchNpmHealth(name) {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), FETCH_TIMEOUT);
    try {
      const r = await fetch('https://registry.npmjs.org/' + encodeURIComponent(name), { signal: ctrl.signal });
      if (!r.ok) throw new Error('bad status ' + r.status);
      const data = await r.json();
      const latestVer = data['dist-tags'] && data['dist-tags'].latest;
      const lastRelease = (data.time && data.time.modified) || null;
      const deprecated = (latestVer && data.versions && data.versions[latestVer] && data.versions[latestVer].deprecated) || null;
      return { lastRelease, deprecated };
    } finally {
      clearTimeout(timer);
    }
  }
  function daysSince(iso) {
    if (!iso) return null;
    const ms = Date.now() - new Date(iso).getTime();
    return Number.isFinite(ms) && ms >= 0 ? Math.floor(ms / 86400000) : null;
  }
  async function checkPackageHealth() {
    if (!state.packageHealthEnabled) return;
    const pkgs = selectedPackages().filter(p => p.ecosystem === 'PyPI' || p.ecosystem === 'npm');
    if (!pkgs.length) { packageHealthCheckState = 'idle'; renderSourcesTab(); return; }

    packageHealthCheckState = 'checking';
    renderSourcesTab();

    const results = await Promise.allSettled(pkgs.map(p =>
      (p.ecosystem === 'PyPI' ? fetchPypiHealth(p.name) : fetchNpmHealth(p.name)).then(r => Object.assign({ key: p.key }, r))
    ));
    let hadError = false;
    results.forEach((res, i) => {
      const key = pkgs[i].key;
      if (res.status === 'fulfilled') {
        const age = daysSince(res.value.lastRelease);
        packageHealth[key] = {
          checked: true, lastRelease: res.value.lastRelease, deprecated: res.value.deprecated || null,
          stale: age != null && age > STALE_DAYS, error: false,
        };
      } else {
        hadError = true;
        packageHealth[key] = { checked: true, error: true };
      }
    });
    packageHealthCheckState = hadError ? 'error' : 'ok';
    renderSourcesTab();
    renderStackSelector();
  }

  // ---------------------------------------------------------------
  // EPSS (Exploit Prediction Scoring System, FIRST.org) - opt-in, same
  // footprint reasoning as package health above. EPSS is a continuous
  // 0-1 probability of exploitation in the next 30 days, a different
  // signal from CISA KEV's binary "already confirmed exploited" - two
  // CRITICAL advisories with the same severity and neither one KEV-listed
  // can still have wildly different real-world exploitation likelihood,
  // which severity/KEV alone can't distinguish. Confirmed CORS-friendly:
  //   curl -I -H "Origin: https://lab.krismccabe.com" \
  //     "https://api.first.org/data/v1/epss?cve=CVE-2024-3094"
  //   -> HTTP/2 200, access-control-allow-origin: *
  // Only ever covers advisories with a CVE (EPSS's own scope); anything
  // GHSA/PYSEC-only with no CVE alias simply has no score, same "additive,
  // never a false negative" pattern as isKev()/kevDueDateFor() above - a
  // missing score contributes nothing to priorityScore(), it doesn't
  // penalize the advisory.
  // ---------------------------------------------------------------
  const EPSS_URL = 'https://api.first.org/data/v1/epss';
  const EPSS_BATCH_SIZE = 100; // the API's own per-request result limit
  let epssScores = {};   // cve -> { epss: 0..1, percentile: 0..1 } - transient, never persisted
  let epssCheckState = 'idle'; // 'idle' | 'checking' | 'ok' | 'error'
  let epssCheckedAt = null;

  async function fetchEpssBatch(cves, signal) {
    const url = EPSS_URL + '?cve=' + cves.map(encodeURIComponent).join(',') + '&limit=' + cves.length;
    const resp = await fetch(url, { signal });
    if (!resp.ok) throw new Error('EPSS fetch failed: ' + resp.status);
    const data = await resp.json();
    return Array.isArray(data.data) ? data.data : [];
  }
  async function checkEpss() {
    if (!state.epssEnabled) return;
    const cves = Array.from(new Set(baseAdvisories().map(a => a.cve).filter(Boolean)));
    if (!cves.length) { epssCheckState = 'idle'; renderSourcesTab(); return; }

    epssCheckState = 'checking';
    renderSourcesTab();
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), FETCH_TIMEOUT);
    try {
      const chunks = [];
      for (let i = 0; i < cves.length; i += EPSS_BATCH_SIZE) chunks.push(cves.slice(i, i + EPSS_BATCH_SIZE));
      const results = await Promise.all(chunks.map(c => fetchEpssBatch(c, ctrl.signal)));
      const fresh = {};
      results.flat().forEach(row => {
        const epss = Number(row.epss);
        const percentile = Number(row.percentile);
        if (row.cve && Number.isFinite(epss)) fresh[row.cve] = { epss, percentile: Number.isFinite(percentile) ? percentile : null };
      });
      // Merge, don't replace - a CVE outside this check's scope (a stack
      // change since the last run) keeps whatever score it already had
      // rather than losing it for no reason.
      epssScores = Object.assign({}, epssScores, fresh);
      epssCheckedAt = new Date().toISOString();
      epssCheckState = 'ok';
    } catch (err) {
      epssCheckState = 'error';
      // epssScores left exactly as it was, same never-regress rule as KEV.
    } finally {
      clearTimeout(timer);
      renderSourcesTab();
      shownCount = INITIAL_CARDS;
      withReorderAnimation(renderExposureList);
    }
  }
  function epssFor(adv) {
    return adv.cve && epssScores[adv.cve] ? epssScores[adv.cve] : null;
  }
  // Shown in the modal's Quick facts strip alongside the SLA field above -
  // absent unless EPSS is enabled AND this advisory has a CVE AND FIRST.org
  // actually returned a score for it, same "only show what we actually
  // know" rule as slaFieldHtml.
  function epssFieldHtml(adv) {
    const e = epssFor(adv);
    if (!e) return '';
    const pct = (e.epss * 100).toFixed(1);
    const pctLabel = e.percentile != null ? ' (' + (e.percentile * 100).toFixed(0) + 'th percentile)' : '';
    return '<div class="signal-field">' +
      '<h4 class="signal-field-label">EPSS exploit probability</h4>' +
      '<p class="signal-field-body">' + pct + '%' + escapeHtml(pctLabel) +
        ' estimated chance of exploitation in the next 30 days (FIRST.org).</p>' +
    '</div>';
  }

  // ---------------------------------------------------------------
  // CISA KEV CATALOG (live, on by default) - CISA's own domain doesn't
  // send CORS headers (verified: no access-control-allow-origin on
  // cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json),
  // so it can't be fetched from a browser at all. Its official GitHub-org
  // mirror does, verified the same way GHSA is verified below:
  //   curl -I -H "Origin: https://lab.krismccabe.com" \
  //     https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json
  //   -> HTTP/2 200, access-control-allow-origin: *
  // Body shape confirmed by fetching it directly (not guessed): a JSON
  // object with a `vulnerabilities` array, each entry carrying `cveID`.
  // Unlike GHSA (purely additive, opt-in, off by default), this backs a
  // badge already shown unconditionally on every card - so it defaults ON,
  // and a failed/disabled fetch falls back to the baked-in KEV_SET rather
  // than ever narrowing or emptying it (see kevEffectiveSet above).
  // ---------------------------------------------------------------
  const KEV_LIVE_URL = 'https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json';
  let kevCheckState = 'idle';   // 'idle' | 'checking' | 'ok' | 'error'
  let kevLiveFetchedAt = null;
  let kevLiveCount = 0;
  // CVE -> CISA's federal remediation deadline (YYYY-MM-DD), only ever
  // populated by a successful live fetch - the hand-maintained fallback
  // list (KEV, just an array of IDs) carries no due dates at all, and a
  // failed fetch leaves this exactly as it was rather than clearing it,
  // same "never regress" rule as kevEffectiveSet below.
  let kevDueDates = {};

  function kevDueDateFor(adv) {
    if (adv.cve && kevDueDates[adv.cve]) return kevDueDates[adv.cve];
    const alias = (adv.aliases || []).find(a => kevDueDates[a]);
    return alias ? kevDueDates[alias] : null;
  }
  function isPastDue(dueDateStr) {
    if (!dueDateStr) return false;
    const due = new Date(dueDateStr + 'T23:59:59');
    return !isNaN(due.getTime()) && due.getTime() < Date.now();
  }

  // ---------------------------------------------------------------
  // REMEDIATION SLA TRACKING - a CISA-set KEV deadline (above) is one
  // fixed external clock; most teams also run their own internal
  // remediation policy across everything else, typically tighter windows
  // for higher severity. Targets are user-editable (Filters drawer) and
  // persisted independently of the stack/watch state, so re-picking your
  // packages never resets a policy you've tuned. A target of 0 means
  // "not tracked" for that severity, not "breached on day zero".
  // ---------------------------------------------------------------
  const SLA_TARGETS_KEY = 'flare-sla-targets-v1';
  const DEFAULT_SLA_TARGETS = { CRITICAL: 15, HIGH: 30, MEDIUM: 60, LOW: 90 };
  let slaTargets = Object.assign({}, DEFAULT_SLA_TARGETS);
  (function loadSlaTargets() {
    try {
      const raw = localStorage.getItem(SLA_TARGETS_KEY);
      if (!raw) return;
      const parsed = JSON.parse(raw);
      Object.keys(DEFAULT_SLA_TARGETS).forEach(sev => {
        const v = Number(parsed[sev]);
        if (Number.isFinite(v) && v >= 0) slaTargets[sev] = v;
      });
    } catch (e) {}
  })();
  function saveSlaTargets() {
    try { localStorage.setItem(SLA_TARGETS_KEY, JSON.stringify(slaTargets)); } catch (e) {}
  }
  function slaTargetFor(sev) {
    return Object.prototype.hasOwnProperty.call(slaTargets, sev) ? slaTargets[sev] : null;
  }
  function daysOpen(adv) {
    if (!adv.published) return null;
    const ms = Date.now() - new Date(adv.published).getTime();
    if (!Number.isFinite(ms) || ms < 0) return null;
    return Math.floor(ms / 86400000);
  }
  function isSlaBreached(adv) {
    const target = slaTargetFor(adv.sev);
    if (!target) return false;
    const open = daysOpen(adv);
    return open != null && open > target;
  }
  // "Overdue" (badge-overdue, above) is CISA's own deadline on a KEV
  // entry; this is your own policy's deadline on anything with a
  // tracked severity - a distinct fact, so it gets its own color rather
  // than reusing that badge.
  function slaBadgeHtml(adv) {
    if (!isSlaBreached(adv)) return '';
    const target = slaTargetFor(adv.sev);
    const open = daysOpen(adv);
    return '<span class="badge badge-sla-breach" title="Open ' + open + ' day' + (open === 1 ? '' : 's') +
      ' &mdash; past this severity&#8217;s ' + target + '-day remediation target.">' +
      badgeIconHtml('sla') + 'SLA breached</span>';
  }
  // Shown in the modal's Quick facts strip whenever a target is set for
  // this severity, breached or not - "open 8 of 30 days" is useful
  // context on its own, not just the alarm state.
  function slaFieldHtml(adv) {
    const target = slaTargetFor(adv.sev);
    if (!target) return '';
    const open = daysOpen(adv);
    if (open == null) return '';
    const breached = open > target;
    return '<div class="signal-field">' +
      '<h4 class="signal-field-label">Remediation SLA</h4>' +
      '<p class="signal-field-body sla-field-body' + (breached ? ' sla-field-breached' : '') + '">' +
        'Open <b>' + open + '</b> day' + (open === 1 ? '' : 's') + ' of a <b>' + target + '</b>-day target for ' +
        escapeHtml(SEV_LABEL[adv.sev] || 'this') + ' severity.' +
        (breached ? ' <b>Past target.</b>' : '') +
      '</p>' +
    '</div>';
  }

  async function checkKevLive() {
    if (!state.kevLiveEnabled) return;
    kevCheckState = 'checking';
    renderSourcesTab();

    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), FETCH_TIMEOUT);
    try {
      const resp = await fetch(KEV_LIVE_URL, { signal: ctrl.signal });
      if (!resp.ok) throw new Error('KEV fetch failed: ' + resp.status);
      const data = await resp.json();
      const vulns = (data.vulnerabilities || [])
        .filter(v => v && typeof v.cveID === 'string' && /^CVE-\d{4}-\d+$/.test(v.cveID));
      if (!vulns.length) throw new Error('empty or unrecognized KEV payload');
      const ids = vulns.map(v => v.cveID);
      // Union with the hand-maintained baseline, never a bare replacement -
      // a partial/odd response still can't regress below KEV_SET.
      kevEffectiveSet = new Set(KEV.concat(ids));
      // Due dates DO get replaced wholesale on a successful fetch (not
      // merged) - this is always CISA's complete current catalog, not an
      // incremental update, so last-fetched is authoritative.
      const dueDates = {};
      vulns.forEach(v => {
        if (typeof v.dueDate === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(v.dueDate)) dueDates[v.cveID] = v.dueDate;
      });
      kevDueDates = dueDates;
      kevLiveCount = ids.length;
      kevLiveFetchedAt = new Date().toISOString();
      kevCheckState = 'ok';
    } catch (err) {
      kevCheckState = 'error';
      // kevEffectiveSet is left exactly as it was - already either KEV_SET
      // (never fetched / this is the first attempt) or a previously
      // successful superset of it. Either way, never emptied or replaced
      // with something worse on a failed fetch.
    } finally {
      clearTimeout(timer);
      renderSourcesTab();
      shownCount = INITIAL_CARDS;
      withReorderAnimation(renderExposureList);
      renderHeatmap();
    }
  }

  // ---------------------------------------------------------------
  // CUSTOM RSS/ATOM FEEDS - best-effort direct fetch. Most third-party
  // feeds don't set the CORS headers a browser fetch from another origin
  // needs, and the Fetch API can't distinguish a CORS block from a plain
  // network error (both surface as the same generic failure), so the
  // error message is honest about that ambiguity rather than pretending
  // to diagnose it. Items carry no severity/CVSS, so they're rendered
  // separately from the ranked exposure list, never mixed into it.
  // ---------------------------------------------------------------
  function makeFeedId(url) {
    let h = 0;
    for (let i = 0; i < url.length; i++) h = (h * 31 + url.charCodeAt(i)) | 0;
    return 'feed-' + Math.abs(h).toString(36);
  }

  function validateFeedUrl(url) {
    const trimmed = String(url || '').trim();
    if (!trimmed) return { error: 'Enter a feed URL.' };
    let parsed;
    try { parsed = new URL(trimmed); } catch (e) { return { error: 'That doesn’t look like a valid URL.' }; }
    if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') return { error: 'Feed URL must start with http:// or https://.' };
    if (state.feeds.some(f => f.url === trimmed)) return { error: 'Already added.' };
    if (state.feeds.length >= MAX_FEEDS) return { error: 'You can add up to ' + MAX_FEEDS + ' feeds.' };
    return { url: trimmed };
  }

  function addFeed(name, url) {
    const result = validateFeedUrl(url);
    if (result.error) return { error: result.error };
    const feed = {
      id: makeFeedId(result.url), name: String(name || '').trim(), url: result.url,
      addedAt: new Date().toISOString(), status: 'pending', checkedAt: null, items: [], error: null,
    };
    state.feeds.push(feed);
    persistIfEnabled();
    renderSourcesTab();
    fetchFeed(feed.id);
    return { error: null };
  }

  function removeFeed(id) {
    state.feeds = state.feeds.filter(f => f.id !== id);
    persistIfEnabled();
    renderSourcesTab();
  }

  function parseFeedXml(text) {
    const doc = new DOMParser().parseFromString(text, 'application/xml');
    if (doc.querySelector('parsererror')) throw new Error('Not valid XML.');
    const items = [];
    const rssItems = doc.querySelectorAll('item');
    if (rssItems.length) {
      rssItems.forEach(item => {
        if (items.length >= MAX_FEED_ITEMS) return;
        items.push({
          title: (item.querySelector('title') || {}).textContent || '',
          link: (item.querySelector('link') || {}).textContent || '',
          pubDate: (item.querySelector('pubDate') || {}).textContent || '',
        });
      });
      return items;
    }
    const entries = doc.querySelectorAll('entry');
    if (!entries.length) throw new Error('Not a recognized RSS or Atom feed.');
    entries.forEach(entry => {
      if (items.length >= MAX_FEED_ITEMS) return;
      const linkEl = entry.querySelector('link[href]');
      items.push({
        title: (entry.querySelector('title') || {}).textContent || '',
        link: linkEl ? linkEl.getAttribute('href') : ((entry.querySelector('link') || {}).textContent || ''),
        pubDate: ((entry.querySelector('updated') || entry.querySelector('published')) || {}).textContent || '',
      });
    });
    return items;
  }

  async function fetchFeed(id) {
    const feed = state.feeds.find(f => f.id === id);
    if (!feed) return;
    feed.status = 'pending';
    renderSourcesTab();
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), FETCH_TIMEOUT);
    // A request that never gets a response at all (CORS rejection, DNS
    // failure, offline) throws inside fetch() itself - that really is
    // "likely blocked by CORS." A request that succeeds but then fails to
    // parse (0 entries, malformed XML) got a real response, so it can't be
    // a CORS problem; conflating the two under one CORS-blaming message is
    // what made a feed that's just temporarily empty look permanently
    // broken. gotResponse tracks which side of that line the failure is on.
    let gotResponse = false;
    try {
      const resp = await fetch(feed.url, { signal: ctrl.signal });
      if (!resp.ok) throw new Error('HTTP ' + resp.status);
      const text = await resp.text();
      gotResponse = true;
      feed.items = parseFeedXml(text);
      feed.status = 'ok';
      feed.error = null;
    } catch (e) {
      feed.status = 'error';
      feed.items = [];
      feed.error = (e && e.name === 'AbortError')
        ? 'Timed out waiting for this feed.'
        : gotResponse
          ? 'This URL loaded, but doesn’t currently look like a working feed — it may have no entries right now (between posts), or the URL may not point at an RSS/Atom feed at all.'
          : 'Couldn’t load this feed — likely blocked by the source’s CORS policy (most feeds don’t allow this from other websites), though it could also be an invalid URL or a temporary outage.';
    } finally {
      clearTimeout(timer);
      feed.checkedAt = new Date().toISOString();
      persistIfEnabled();
      renderSourcesTab();
    }
  }

  function dedupeRefsByUrl(refs) {
    const seen = new Set();
    return refs.filter(r => {
      if (!r || !r.url || seen.has(r.url)) return false;
      seen.add(r.url);
      return true;
    });
  }

  // OSV genuinely indexes the same CVE more than once for a lot of
  // packages - independently ingested from more than one upstream database
  // (GitHub's own GHSA-xxxx entry AND a separate PyPI-ecosystem PYSEC-xxxx
  // entry for the exact same vulnerability, most commonly), each with its
  // own distinct top-level `id`. Deduping only by exact id (the old
  // behavior) missed this entirely, so the same vulnerability could show
  // up as two separate cards and count twice in every stat - confirmed
  // against live data: ~28% of torch's 43 OSV entries were exactly this,
  // 12 CVEs each indexed twice. This collapses every group that shares a
  // CVE alias into one card, keeping the fuller/more complete record as
  // canonical (GHSA-sourced preferred - same content in practice as the
  // source advisory, and already what "Coverage elsewhere" treats as
  // primary) and folding in whatever the others had that it didn't, rather
  // than silently dropping their data.
  function dedupeAdvisoriesByAlias(list) {
    const byCve = new Map();
    const passthrough = [];
    list.forEach(a => {
      if (!a.cve) { passthrough.push(a); return; }
      if (!byCve.has(a.cve)) byCve.set(a.cve, []);
      byCve.get(a.cve).push(a);
    });
    const merged = [];
    byCve.forEach(group => {
      if (group.length === 1) { merged.push(group[0]); return; }
      const sorted = group.slice().sort((a, b) => {
        const aGhsa = /^GHSA-/.test(a.id) ? 0 : 1;
        const bGhsa = /^GHSA-/.test(b.id) ? 0 : 1;
        if (aGhsa !== bGhsa) return aGhsa - bGhsa;
        return (b.details || '').length - (a.details || '').length; // fuller writeup wins ties
      });
      const canonical = sorted[0];
      const others = sorted.slice(1);
      const pkgSet = new Set(canonical.pkgs);
      others.forEach(o => (o.pkgs || []).forEach(k => pkgSet.add(k)));
      const fixes = (canonical.fixes && canonical.fixes.length) ? canonical.fixes
        : ((others.find(o => o.fixes && o.fixes.length) || {}).fixes || []);
      // Each folded-in duplicate's own OSV page is still real, citable
      // data - kept reachable as a coverage link instead of discarded, so
      // "merged" doesn't mean "silently threw away a source."
      const extraRefs = others.map(o => ({ url: 'https://osv.dev/vulnerability/' + o.id, source: 'osv.dev (' + o.id + ')' }));
      const otherRefs = dedupeRefsByUrl(
        (canonical.otherRefs || []).concat(extraRefs, others.flatMap(o => o.otherRefs || []))
      );
      merged.push(Object.assign({}, canonical, {
        pkgs: Array.from(pkgSet).sort(),
        fixes, otherRefs,
        mergedFrom: others.map(o => o.id),
      }));
    });
    return merged.concat(passthrough);
  }

  // external (GHSA) only ever fills a gap, never overwrites - most GHSA
  // records already reach Flare via OSV.dev under this exact same ID, so
  // this is what actually keeps the "won't create duplicates" promise
  // in the Sources tab true, not just a claim. The alias-dedup pass below
  // catches the rest (same CVE, different OSV-native id) regardless of
  // which of snapshot/live/external it came in through.
  function mergedAdvisoriesMap() {
    const map = {};
    if (snapshot) snapshot.advisories.forEach(a => { map[a.id] = a; });
    if (live) Object.keys(live.advisories).forEach(id => { map[id] = live.advisories[id]; });
    if (external) Object.keys(external.advisories).forEach(id => { if (!map[id]) map[id] = external.advisories[id]; });
    const deduped = dedupeAdvisoriesByAlias(Object.keys(map).map(id => map[id]));
    const out = {};
    deduped.forEach(a => { out[a.id] = a; });
    return out;
  }

  function mergeLive(records) {
    if (!live) live = { fetchedAt: new Date().toISOString(), advisories: {} };
    live.fetchedAt = new Date().toISOString();
    Object.keys(records).forEach(id => { live.advisories[id] = records[id]; });
  }

  function readCache() {
    try {
      const raw = localStorage.getItem(CACHE_KEY);
      if (!raw) return;
      const parsed = JSON.parse(raw);
      if (!parsed || typeof parsed !== 'object') return;
      if (!snapshot || parsed.watchlistHash !== snapshot.watchlistHash) return; // stale association - discard
      const age = Date.now() - new Date(parsed.fetchedAt).getTime();
      if (!(age >= 0) || age > CACHE_TTL_MS) return; // expired or malformed
      live = { fetchedAt: parsed.fetchedAt, advisories: parsed.advisories || {} };
    } catch (e) {}
  }

  function persistCache() {
    if (!live || !rememberEnabled) return;
    try {
      localStorage.setItem(CACHE_KEY, JSON.stringify({
        schema: 1,
        fetchedAt: live.fetchedAt,
        watchlistHash: snapshot ? snapshot.watchlistHash : null,
        advisories: live.advisories,
      }));
    } catch (e) {}
  }

  function renderRefreshStatus(kind, detail) {
    const dot = document.getElementById('status-dot');
    if (kind === 'checking') {
      if (dot) dot.className = 'status-dot checking';
      return;
    }
    const asOf = snapshot ? fmtDate(snapshot.generatedAt) : '';
    const warnMessages = {
      network: "Couldn't reach the OSV advisory database. Showing the built-in snapshot from " + asOf + " — still accurate for anything disclosed before then.",
      timeout: 'The advisory service is slow right now. Showing the snapshot; try again in a few minutes.',
      'snapshot-unavailable': "Couldn't load the advisory snapshot. The risk categories below are unaffected — they're built into this page.",
    };
    if (warnMessages[kind]) {
      if (dot) dot.className = 'status-dot warn';
      showDiagnostics(warnMessages[kind]);
      return;
    }
    hideDiagnostics();
    if (kind === 'checked' && detail && detail.count) {
      flashSyncMessage(detail.count + ' new advisor' + (detail.count === 1 ? 'y' : 'ies') + ' found and merged in.');
    }
  }

  function updateRefreshButton() {
    const btn = document.getElementById('refresh-btn');
    if (!btn) return;
    btn.disabled = checkInFlight || !snapshot || state.selected.length === 0;
    btn.textContent = checkInFlight ? 'Checking…' : 'Check for newer advisories';
  }

  async function checkForNewAdvisories() {
    if (checkInFlight || !snapshot) return;
    const pkgs = selectedPackages();
    if (!pkgs.length) return;

    checkInFlight = true;
    updateRefreshButton();
    renderRefreshStatus('checking');

    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), FETCH_TIMEOUT);

    try {
      // Map to plain wrapper objects rather than attaching .version onto
      // the shared watchlist/custom package objects directly - those are
      // reused across every render, so mutating them in place would leave
      // a stale version field lingering after a deselect elsewhere.
      const queryPkgs = pkgs.map(p => ({ key: p.key, name: p.name, ecosystem: p.ecosystem, version: state.versions[p.key] }));
      const idToPkgs = await osvQueryBatch(queryPkgs, ctrl.signal);
      const knownIds = new Set(Object.keys(mergedAdvisoriesMap()));
      const newIds = Object.keys(idToPkgs).filter(id => !knownIds.has(id));

      if (!newIds.length) {
        lastCheckedAt = new Date().toISOString();
        renderRefreshStatus('none-new');
        renderProvenance();
        return;
      }

      const { records } = await osvHydrate(newIds, ctrl.signal);
      const normalized = {};
      Object.keys(records).forEach(id => {
        const rec = normalizeRecord(records[id], idToPkgs[id]);
        if (rec) normalized[id] = rec;
      });

      // Report the actual change in what the list you're looking at shows
      // (baseAdvisories - your current stack selection, post-dedup), not
      // the raw hydrated-record count and not a global across-every-package
      // count either - either of those can disagree with what you can see
      // change on screen, which is its own way of looking untrustworthy. A
      // "new" id can still turn out to be the same CVE already shown under
      // a different OSV-native id (dedupeAdvisoriesByAlias folds it into
      // that existing card on the next render); counting it as "Added"
      // anyway is what made this number look like it was climbing on every
      // single check.
      const beforeCount = baseAdvisories().length;
      mergeLive(normalized);
      const afterCount = baseAdvisories().length;
      persistCache();
      lastCheckedAt = new Date().toISOString();
      shownCount = INITIAL_CARDS;
      withReorderAnimation(renderExposureList);
      renderHeatmap();
      renderProvenance();
      renderRefreshStatus('checked', { count: Math.max(0, afterCount - beforeCount) });
    } catch (err) {
      renderRefreshStatus(err && err.name === 'AbortError' ? 'timeout' : 'network');
    } finally {
      clearTimeout(timer);
      checkInFlight = false;
      updateRefreshButton();
    }
  }

  // ---------------------------------------------------------------
  // RENDER: the ranked exposure list + signal cards
  // ---------------------------------------------------------------
  let relatedFilterKey = null; // transient "show everything related to this package" view - not persisted
  let filterHasFix = false;       // transient view filters - not persisted
  let filterNoFix = false;
  let filterHasWorkaround = false;
  let filterNoWorkaround = false;
  let filterWatchedOnly = false;
  let filterSlaBreachOnly = false; // set by clicking the SLA breached "At a glance" tile, or the Filters drawer chip
  let filterSeverity = null;      // null | 'CRITICAL' - set by clicking the Critical "At a glance" tile
  let filterKevOnly = false;      // set by clicking the Actively exploited "At a glance" tile
  let filterDateRange = 'all';    // 'all' | '7' | '30' | '90' - days since filterDateBasis
  let filterDateBasis = 'published'; // 'published' | 'modified' - which date field the range above measures from
  let alertsSearchQuery = ''; // transient keyword search over the alerts list - not persisted

  // ---------------------------------------------------------------
  // WATCH LIST - state.watched is a plain array of advisory IDs, persisted
  // the same way as feeds/custom (persistIfEnabled -> STACK_KEY). Toggling
  // never touches selection/scope, so a watched advisory that later falls
  // out of mergedAdvisoriesMap() (package deselected, snapshot rotated)
  // just stops matching the filter below - nothing here looks it up by ID
  // in a way that can throw on a miss.
  // ---------------------------------------------------------------
  function isWatched(id) {
    return state.watched.indexOf(id) !== -1;
  }
  function toggleWatch(id) {
    const idx = state.watched.indexOf(id);
    if (idx === -1) {
      if (state.watched.length >= MAX_WATCHED) return;
      state.watched.push(id);
    } else {
      state.watched.splice(idx, 1);
    }
    persistIfEnabled();
    renderExposureList();
  }

  // The selection/related-package scope, before the view-only fix/workaround
  // filters - shared by the ranked list and the stats panel so "At a
  // glance" always describes the same scope the list is drawn from,
  // independent of which view filters happen to be checked right now.
  function baseAdvisories() {
    const map = mergedAdvisoriesMap();
    const all = Object.keys(map).map(id => map[id]);
    if (relatedFilterKey) return all.filter(a => a.pkgs.indexOf(relatedFilterKey) !== -1);
    const selectedKeys = new Set(state.selected);
    return all.filter(a => a.pkgs.some(k => selectedKeys.has(k)));
  }

  // The date range narrows the scope itself (a different time window,
  // not just a same-scope toggle like fix/workaround), so it's applied
  // here rather than only in visibleAdvisories() - the stats panel needs
  // it too, or "At a glance" silently describes a wider window than the
  // list actually shows.
  function dateScopedAdvisories() {
    let filtered = baseAdvisories();
    if (filterDateRange !== 'all') {
      const cutoff = Date.now() - Number(filterDateRange) * 86400000;
      const field = filterDateBasis === 'modified' ? 'modified' : 'published';
      filtered = filtered.filter(a => a[field] && new Date(a[field]).getTime() >= cutoff);
    }
    return filtered;
  }

  // Package names, summary, CVE, and the advisory's own id (GHSA-.../
  // PYSEC-...) all count as reasonable "keyword" matches - a search for
  // "sandbox escape" or "CVE-2026-5674" or "litellm" should each find
  // something a plain package-name filter wouldn't.
  function advisoryMatchesSearch(adv, query) {
    if (!query) return true;
    const q = query.trim().toLowerCase();
    if (!q) return true;
    const haystacks = [adv.id, adv.cve, adv.summary].concat((adv.pkgs || []).map(pkgLabel));
    return haystacks.some(h => h && String(h).toLowerCase().indexOf(q) !== -1);
  }

  function visibleAdvisories() {
    let filtered = dateScopedAdvisories();
    if (filterSeverity) filtered = filtered.filter(a => a.sev === filterSeverity);
    if (filterKevOnly) filtered = filtered.filter(isKev);
    if (filterHasFix) filtered = filtered.filter(hasFix);
    if (filterNoFix) filtered = filtered.filter(a => !hasFix(a));
    if (filterHasWorkaround) filtered = filtered.filter(hasWorkaround);
    if (filterNoWorkaround) filtered = filtered.filter(a => !hasWorkaround(a));
    if (filterWatchedOnly) filtered = filtered.filter(a => isWatched(a.id));
    if (filterSlaBreachOnly) filtered = filtered.filter(isSlaBreached);
    if (alertsSearchQuery) filtered = filtered.filter(a => advisoryMatchesSearch(a, alertsSearchQuery));
    return filtered.sort(compareAdvisories);
  }

  function showRelated(key) {
    relatedFilterKey = key;
    shownCount = INITIAL_CARDS;
    renderExposureList();
  }
  function clearRelatedFilter() {
    relatedFilterKey = null;
    shownCount = INITIAL_CARDS;
    renderExposureList();
  }
  // From the Threat map tab, a related-package click must land on the
  // (invisible, other-tab) exposure list, so switch first.
  function goToRelated(key) {
    switchTab('alerts');
    showRelated(key);
  }

  function sevBadgeHtml(sev) {
    const key = SEV_LABEL[sev] ? sev : 'UNKNOWN';
    const lower = key.toLowerCase();
    return '<span class="badge badge-' + lower + '">' + badgeIconHtml(lower) + escapeHtml(SEV_LABEL[key]) + '</span>';
  }

  // "Known exploited in the wild" is CISA's own KEV-catalog phrasing, but
  // it reads as jargon out of context and its length was the reason this
  // badge was so much wider than the others next to it. "Actively
  // exploited" is the shorter, plainer phrase security tools commonly use
  // for the same fact; the title attribute and the Threat level field
  // below (kevExplanationHtml) carry the full explanation for anyone who
  // wants it, rather than cramming it into the badge itself.
  function kevBadgeHtml(adv) {
    const due = kevDueDateFor(adv);
    const overdue = due && isPastDue(due);
    const dueNote = due ? (overdue
      ? ' CISA&#8217;s federal remediation deadline (' + fmtDate(due) + ') has passed.'
      : ' CISA&#8217;s federal remediation deadline is ' + fmtDate(due) + '.') : '';
    const kevPill = '<span class="badge badge-kev" title="Confirmed by CISA&#8217;s Known Exploited Vulnerabilities (KEV) catalog: attackers are already using this against real systems, not a theoretical risk.' + dueNote + '">' +
      badgeIconHtml('kev') + 'Actively exploited</span>';
    // Only the overdue state gets its own badge - "not yet due" isn't
    // actionable enough to earn a second pill on every KEV card, but
    // "CISA's own deadline already passed" is exactly the kind of thing
    // that should be impossible to miss while scanning the list.
    const overduePill = overdue
      ? '<span class="badge badge-overdue" title="Past CISA&#8217;s federal remediation due date of ' + escapeHtml(fmtDate(due)) + '.">' + badgeIconHtml('kev') + 'Overdue</span>'
      : '';
    return kevPill + overduePill;
  }
  function kevExplanationHtml(adv) {
    const due = kevDueDateFor(adv);
    const overdue = due && isPastDue(due);
    const dueLine = due
      ? (overdue
        ? ' CISA set a federal remediation deadline of <b>' + escapeHtml(fmtDate(due)) + '</b> for this one &mdash; that date has passed.'
        : ' CISA set a federal remediation deadline of <b>' + escapeHtml(fmtDate(due)) + '</b> for this one.')
      : '';
    return '<p class="signal-field-body kev-explanation">' +
      'This is in CISA&rsquo;s <a href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog" target="_blank" rel="noopener">Known Exploited Vulnerabilities catalog</a> &mdash; ' +
      'confirmed real-world attacks, not a theoretical risk. Patch this first.' + dueLine +
    '</p>';
  }

  function usableFixes(adv) {
    // Real OSV records sometimes carry a fixes[] entry with an empty
    // fixed[] array (a known affected range with no upper bound published
    // yet) - treat that the same as "no fix" rather than printing a
    // hollow "unspecified" version number.
    return (adv.fixes || []).filter(f => f.fixed && f.fixed.length);
  }
  function hasFix(adv) {
    return usableFixes(adv).length > 0;
  }

  function fixedInHtml(adv) {
    const usable = usableFixes(adv);
    if (!usable.length) {
      return '<h4 class="signal-field-label">Known fixes</h4>' +
        '<p class="signal-field-empty">No fixed version published yet.</p>';
    }
    const chips = usable.map(f =>
      '<span class="fixed-in-version">' + escapeHtml(pkgLabel(f.pkg)) + ' &ge; ' + escapeHtml(f.fixed.join(', ')) + '</span>'
    ).join('');
    return '<h4 class="signal-field-label">Known fixes</h4>' +
      '<div class="fixed-in-chips">' + chips + '</div>';
  }

  function fixBadgeHtml() {
    return '<span class="badge badge-fix">' + badgeIconHtml('fix') + 'Fix available</span>';
  }

  // OSV's `details` markdown sometimes carries its own named sub-sections
  // (### Impact, ### Workarounds, ### Mitigation) written by the advisory
  // author. Generic scan for one, shared by every named-section extractor
  // below rather than duplicated per section.
  function extractNamedSection(details, headingPattern) {
    if (!details) return null;
    const lines = details.split('\n');
    let start = -1;
    for (let i = 0; i < lines.length; i++) {
      if (headingPattern.test(lines[i].trim())) { start = i + 1; break; }
    }
    if (start === -1) return null;
    const collected = [];
    let reachedEnd = true;
    for (let i = start; i < lines.length; i++) {
      if (/^#{1,6}\s+\S/.test(lines[i].trim())) { reachedEnd = false; break; }
      collected.push(lines[i]);
    }
    const text = collected.join('\n').trim();
    if (!text) return null;
    return { text, possiblyTruncated: reachedEnd };
  }

  // A named section found this way can itself already end in the
  // generator's own truncation ellipsis if the raw text ran right up to
  // the length cutoff - don't double it.
  function namedSectionHtml(details, wasTruncated, headingPattern, emptyText) {
    const found = extractNamedSection(details, headingPattern);
    if (!found) return '<p class="signal-field-empty">' + escapeHtml(emptyText) + '</p>';
    const alreadyMarked = /…\s*$/.test(found.text);
    const truncated = found.possiblyTruncated && !!wasTruncated && !alreadyMarked;
    return '<div class="signal-field-body md-body">' + mdLite(found.text, truncated) + '</div>';
  }

  const WORKAROUND_HEADING = /^#{1,6}\s*(workarounds?|mitigations?)\s*$/i;
  const IMPACT_HEADING = /^#{1,6}\s*impact\s*$/i;
  // Section names pulled into their own dedicated card fields, so they're
  // stripped from the generic Description below rather than shown twice -
  // once as a labeled field, once again as an unlabeled paragraph inside
  // Description. Only ~28% of advisories carry an explicit Impact heading
  // at all, and only ~6% a Workarounds/Mitigation one; the rest render
  // nothing there, which is exactly the "sometimes it's there, sometimes
  // it's not" inconsistency this fixes - Description now always means the
  // same thing (everything not already broken out into its own field).
  const STRIPPED_SECTION_NAMES = /^(impact|workarounds?|mitigations?)$/i;

  function hasWorkaround(adv) {
    return !!extractNamedSection(adv.details, WORKAROUND_HEADING);
  }
  function workaroundHtml(adv) {
    return namedSectionHtml(adv.details, adv.detailsTruncated, WORKAROUND_HEADING, 'Unknown');
  }
  function impactHtml(adv) {
    return namedSectionHtml(adv.details, adv.detailsTruncated, IMPACT_HEADING, 'Not stated separately by the advisory.');
  }

  // Same double-ellipsis guard as namedSectionHtml: the raw `details` text
  // can already end in the generator's own truncation ellipsis, and
  // detailsForDescription's section-stripping doesn't remove it - without
  // this check mdLite's own truncation marker doubles up behind it.
  function descriptionHtml(adv) {
    if (!adv.details) return mdLite(adv.summary, false);
    const text = detailsForDescription(adv.details);
    const alreadyMarked = /…\s*$/.test(text);
    return mdLite(text, adv.detailsTruncated && !alreadyMarked);
  }

  // Some advisories' Description is a full technical writeup - multiple
  // headings, byte tables, exploit-chain code - hundreds of lines longer
  // than what "should I patch this" needs. The plain-English summary and
  // Impact/Vectors/Fixes fields already cover that question; a long
  // Description collapses by default so it doesn't drown the card.
  const DESCRIPTION_CLAMP_THRESHOLD = 500;
  function descriptionIsLong(adv) {
    if (!adv.details) return false;
    return detailsForDescription(adv.details).length > DESCRIPTION_CLAMP_THRESHOLD;
  }

  function detailsForDescription(details) {
    if (!details) return details;
    const lines = details.split('\n');
    const out = [];
    let skipping = false;
    for (const line of lines) {
      const heading = line.trim().match(/^#{1,6}\s+(.*)$/);
      if (heading) {
        skipping = STRIPPED_SECTION_NAMES.test(heading[1].trim());
        if (skipping) continue;
      }
      if (!skipping) out.push(line);
    }
    return out.join('\n');
  }

  // Human-readable "vectors of attack" derived from the CVSS base vector -
  // real, parsed data (not fabricated commentary). OSV records carry no
  // separate workaround field at all, so that section stays honest about
  // the gap rather than inventing advice.
  const CVSS_AV_LABEL = { N: 'the network', A: 'an adjacent network', L: 'local access', P: 'physical access' };
  const CVSS_AC_LABEL = { L: 'low', H: 'high' };
  const CVSS_UI_LABEL = { N: 'no user interaction', R: 'user interaction' };
  const CVSS_PR_LABEL = { N: 'no privileges', L: 'low privileges', H: 'high privileges' };

  function parseCvssVector(vector) {
    if (!vector) return null;
    const parts = {};
    vector.split('/').forEach(tok => {
      const idx = tok.indexOf(':');
      if (idx !== -1) parts[tok.slice(0, idx)] = tok.slice(idx + 1);
    });
    return parts;
  }

  function vectorsOfAttackHtml(adv) {
    const parts = parseCvssVector(adv.cvss);
    const av = parts && CVSS_AV_LABEL[parts.AV];
    if (!av) return '<p class="signal-field-empty">Unknown</p>';
    const bits = ['Exploitable over ' + av];
    if (CVSS_AC_LABEL[parts.AC]) bits.push(CVSS_AC_LABEL[parts.AC] + ' attack complexity');
    if (CVSS_PR_LABEL[parts.PR]) bits.push('requires ' + CVSS_PR_LABEL[parts.PR]);
    if (CVSS_UI_LABEL[parts.UI]) bits.push(CVSS_UI_LABEL[parts.UI]);
    return '<p class="signal-field-body">' + escapeHtml(bits.join(', ') + '.') + '</p>';
  }

  // A one-line, plain-English TL;DR built entirely from data Flare already
  // has - severity, the parsed CVSS vector, KEV status, fix/workaround
  // availability - never a rewrite of the advisory's own prose. Purely
  // rule-based and client-side: no network call, nothing leaves the page,
  // same guarantee the rest of the site already makes.
  function plainEnglishSentence(adv) {
    const sevWord = (SEV_LABEL[adv.sev] || 'Unknown-severity').toLowerCase();
    const pkgNames = adv.pkgs.map(pkgLabel).join(', ');
    const parts = parseCvssVector(adv.cvss);
    const av = parts && CVSS_AV_LABEL[parts.AV];
    let exploitBit = '';
    if (av) {
      exploitBit = ' — exploitable over ' + av;
      if (parts.PR === 'N') exploitBit += ' without authentication';
      else if (CVSS_PR_LABEL[parts.PR]) exploitBit += ' with ' + CVSS_PR_LABEL[parts.PR];
      if (parts.UI === 'R') exploitBit += ', but only if someone can be tricked into interacting with something';
    }
    const kevBit = isKev(adv) ? ', and it is already being exploited in the wild' : '';
    let actionBit;
    if (hasFix(adv)) actionBit = 'A fix is available — update to close this.';
    else if (hasWorkaround(adv)) actionBit = 'No fixed version yet, but a workaround is documented below.';
    else actionBit = 'No fixed version or workaround has been published yet — worth tracking.';
    return 'A ' + sevWord + '-severity issue in ' + pkgNames + exploitBit + kevBit + '. ' + actionBit;
  }

  function plainEnglishHtml(adv) {
    return '<p class="signal-plain-english">' + escapeHtml(plainEnglishSentence(adv)) + '</p>';
  }

  function signalLinksHtml(adv) {
    const refs = adv.refs || {};
    const links = [];
    if (refs.osv) links.push('<a href="' + escapeHtml(refs.osv) + '" target="_blank" rel="noopener">OSV record</a>');
    if (refs.nvd) links.push('<a href="' + escapeHtml(refs.nvd) + '" target="_blank" rel="noopener">NVD</a>');
    if (refs.ghsa) links.push('<a href="' + escapeHtml(refs.ghsa) + '" target="_blank" rel="noopener">GitHub Advisory</a>');
    return links.length ? '<div class="signal-links">' + links.join('') + '</div>' : '';
  }

  // Third-party links the advisory itself already cites (vendor blogs,
  // independent research writeups) - not a Flare-vetted "this is
  // legitimate news" claim, just an honest surfacing of what OSV recorded.
  // Rendered as a chip row right under the plain-English summary (not
  // buried after every technical field) - it's real, already-fetched data
  // that was previously easy to miss at the bottom of a long card.
  // CVE ID is the query whenever one exists - it's the one identifier news
  // coverage of a vulnerability actually uses, so it's a far more precise
  // search than a package name would be. Falls back to "<package>
  // vulnerability" for the advisories (mostly GHSA-only records) that never
  // got a CVE assigned - still specific enough to be useful, just less so.
  // The advisory's own summary (e.g. "LiteLLM: Authentication Bypass via
  // Host Header Injection") is what a real news headline about this
  // actually reads like - a bare CVE ID is precise but matches nothing in
  // a news search unless the outlet happened to quote it verbatim, which
  // most coverage doesn't. Falls back to CVE, then package name, only for
  // the rare advisory with no summary text at all.
  function newsSearchQuery(adv) {
    if (adv.summary) return adv.summary;
    if (adv.cve) return adv.cve;
    const primaryKey = adv.pkgs && adv.pkgs.length ? adv.pkgs[0] : null;
    const pkgName = primaryKey ? pkgLabel(primaryKey) : null;
    return pkgName ? pkgName + ' vulnerability' : adv.id;
  }
  // A link to a plain Google web search, News tab (tbm=nws) - not the
  // separate news.google.com app/service, and not a fetched/curated list
  // either. Flare has no backend to hold a news-API key server-side (the
  // honest alternative costs real money - see mediastack.com etc.), and no
  // keyless client-side fetch path exists either (verified: no CORS header
  // from news.google.com's own search feed, or from any general
  // news-search API without a paid key). This is the free, zero-backend
  // middle ground - it opens the visitor's own search rather than
  // pretending to show results Flare never actually fetched or vetted.
  function newsSearchUrl(adv) {
    const q = newsSearchQuery(adv);
    return 'https://www.google.com/search?q=' + encodeURIComponent(q) + '&tbm=nws';
  }
  const NEWS_ICON = '<svg viewBox="0 0 24 24" width="12" height="12" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="11" cy="11" r="7"/><path d="M21 21l-4.35-4.35"/></svg>';

  function otherRefsHtml(adv) {
    const other = adv.otherRefs || [];
    const links = other.map(r =>
      '<a class="coverage-chip" href="' + escapeHtml(r.url) + '" target="_blank" rel="noopener">' + escapeHtml(r.source) + '</a>'
    ).join('');
    const newsChip = '<a class="coverage-chip coverage-chip-news" href="' + escapeHtml(newsSearchUrl(adv)) + '" target="_blank" rel="noopener">' +
      NEWS_ICON + ' News coverage</a>';
    return '<div class="signal-coverage">' +
      '<span class="signal-coverage-label">Coverage elsewhere</span>' +
      '<div class="coverage-links">' + links + newsChip + '</div>' +
    '</div>';
  }

  // The severity+KEV badges already sit in the always-visible header
  // directly above this field (the header stays on screen when a card is
  // expanded - it's not replaced), so re-rendering them here was a literal
  // on-screen duplicate, not just a stylistic echo. This field now only
  // ever adds information the badges don't already carry: the raw CVSS
  // score/vector for anyone who wants it, and the KEV explanation
  // paragraph. If a card has neither (no CVSS vector published, not a KEV
  // entry), the field is skipped entirely rather than rendered empty.
  function threatLevelFieldHtml(adv) {
    const kev = isKev(adv);
    const hasCvss = adv.score != null || !!adv.cvss;
    if (!hasCvss && !kev) return '';
    const bits = [];
    if (adv.score != null) bits.push('<span class="qf-score">' + escapeHtml(String(adv.score)) + '<span class="qf-score-max">/10</span></span>');
    if (adv.cvss) bits.push('<code class="qf-vector">' + escapeHtml(adv.cvss) + '</code>');
    const body = bits.length ? '<p class="signal-field-body qf-cvss-row">' + bits.join(' ') + '</p>' : '';
    return '<div class="signal-field">' +
      '<h4 class="signal-field-label">CVSS</h4>' +
      body +
      (kev ? kevExplanationHtml(adv) : '') +
    '</div>';
  }

  function watchToggleHtml(adv) {
    const watched = isWatched(adv.id);
    return '<button type="button" class="watch-toggle' + (watched ? ' is-watched' : '') + '" data-watch="' + escapeHtml(adv.id) + '" ' +
      'aria-pressed="' + watched + '" aria-label="' + (watched ? 'Remove from watch list' : 'Add to watch list') + '" ' +
      'title="' + (watched ? 'Remove from watch list' : 'Add to watch list') + '">' +
      (watched ? '★' : '☆') +
    '</button>';
  }

  function signalCardHtml(adv) {
    const matched = adv.pkgs.filter(k => state.selected.indexOf(k) !== -1);
    const pkgNames = (matched.length ? matched : adv.pkgs).map(pkgLabel).join(', ');
    const kev = isKev(adv);
    const sevClass = 'sev-' + (SEV_LABEL[adv.sev] ? adv.sev : 'UNKNOWN').toLowerCase();

    return '<div class="signal-card ' + sevClass + (kev ? ' is-kev' : '') + (isWatched(adv.id) ? ' is-watched' : '') + '" data-id="' + escapeHtml(adv.id) + '">' +
      watchToggleHtml(adv) +
      '<button type="button" class="signal-head" aria-haspopup="dialog" data-open-modal="' + escapeHtml(adv.id) + '">' +
        '<div class="signal-title-row">' +
          '<span class="signal-pkg">' + escapeHtml(pkgNames) + '</span>' +
          '<div class="signal-badges">' +
            (kev ? kevBadgeHtml(adv) : '') + sevBadgeHtml(adv.sev) +
            (hasFix(adv) ? fixBadgeHtml() : '') +
            slaBadgeHtml(adv) +
            (adv.src === 'live' ? '<span class="src-live" title="Found by checking OSV.dev just now - not yet in today\'s published snapshot.">New since last snapshot</span>' : '') +
            (adv.src === 'github-advisories' ? '<span class="src-live" title="Found via GitHub Security Advisories - not in OSV.dev under this ID.">GitHub Advisories</span>' : '') +
          '</div>' +
        '</div>' +
        '<p class="signal-summary">' + escapeHtml(adv.summary) + '</p>' +
        '<div class="signal-meta-row">' +
          '<span class="signal-id">' + escapeHtml(adv.id) + '</span>' +
          '<span>Published ' + fmtDate(adv.published) + '</span>' +
          (adv.modified && adv.modified !== adv.published ? '<span>Updated ' + fmtDate(adv.modified) + '</span>' : '') +
        '</div>' +
      '</button>' +
    '</div>';
  }

  // The full write-up, shown only in the pop-out modal now - a card in the
  // list is just the head above (package, badges, summary, dates); clicking
  // it opens this rather than expanding in place, so the feed never grows
  // and shrinks around whatever you last clicked (the "cluttered feed"
  // complaint this replaced).
  function signalBodyHtml(adv) {
    const matched = adv.pkgs.filter(k => state.selected.indexOf(k) !== -1);
    const relatedKey = matched.length ? matched[0] : adv.pkgs[0];

    // "Quick facts" - the dense, glanceable, technical block: CVSS, attack
    // vector, known fixes. Grouped and visually set apart from the prose
    // fields below (Description/Impact/Workaround) so the card reads as
    // two tiers - scan this strip first, read the writeup only if needed -
    // rather than one flat stack of equally-weighted labeled fields.
    const quickFacts = [
      threatLevelFieldHtml(adv),
      '<div class="signal-field"><h4 class="signal-field-label">Vectors of attack</h4>' + vectorsOfAttackHtml(adv) + '</div>',
      '<div class="signal-field">' + fixedInHtml(adv) + '</div>',
      slaFieldHtml(adv),
      epssFieldHtml(adv),
    ].filter(Boolean).join('');

    return '<div class="signal-body">' +
        plainEnglishHtml(adv) +
        otherRefsHtml(adv) +
        (quickFacts ? '<div class="signal-quickfacts">' + quickFacts + '</div>' : '') +
        '<div class="signal-divider"><span>Full advisory</span></div>' +
        '<div class="signal-field">' +
          '<h4 class="signal-field-label">Description</h4>' +
          '<div class="signal-field-body md-body' + (descriptionIsLong(adv) && !expandedDescriptions.has(adv.id) ? ' md-body-clamped' : '') + '">' +
            descriptionHtml(adv) +
          '</div>' +
          (descriptionIsLong(adv) ? '<button type="button" class="btn small desc-toggle-btn" data-desc-toggle="' + escapeHtml(adv.id) + '">' +
            (expandedDescriptions.has(adv.id) ? 'Show less' : 'Show full description') + '</button>' : '') +
        '</div>' +
        '<div class="signal-field">' +
          '<h4 class="signal-field-label">Impact</h4>' +
          impactHtml(adv) +
        '</div>' +
        '<div class="signal-field">' +
          '<h4 class="signal-field-label">Known workaround</h4>' +
          workaroundHtml(adv) +
        '</div>' +
        signalLinksHtml(adv) +
        '<button type="button" class="btn small related-btn" data-related-key="' + escapeHtml(relatedKey) + '">Show other advisories for ' + escapeHtml(pkgLabel(relatedKey)) + '</button>' +
      '</div>';
  }

  // Same head content as the card, but as static markup (not a button -
  // the modal is already the "opened" state, nothing left to click to open
  // further) so the modal reads as one continuous advisory writeup, headed
  // by the same title/badges/summary/dates you clicked from.
  function signalModalContentHtml(adv) {
    const matched = adv.pkgs.filter(k => state.selected.indexOf(k) !== -1);
    const pkgNames = (matched.length ? matched : adv.pkgs).map(pkgLabel).join(', ');
    const kev = isKev(adv);
    return '<div class="signal-modal-head">' +
        '<div class="signal-title-row">' +
          '<span class="signal-pkg">' + escapeHtml(pkgNames) + '</span>' +
          '<div class="signal-badges">' +
            (kev ? kevBadgeHtml(adv) : '') + sevBadgeHtml(adv.sev) +
            (hasFix(adv) ? fixBadgeHtml() : '') +
            slaBadgeHtml(adv) +
            (adv.src === 'live' ? '<span class="src-live" title="Found by checking OSV.dev just now - not yet in today\'s published snapshot.">New since last snapshot</span>' : '') +
            (adv.src === 'github-advisories' ? '<span class="src-live" title="Found via GitHub Security Advisories - not in OSV.dev under this ID.">GitHub Advisories</span>' : '') +
          '</div>' +
        '</div>' +
        '<p class="signal-summary">' + escapeHtml(adv.summary) + '</p>' +
        '<div class="signal-meta-row">' +
          '<span class="signal-id">' + escapeHtml(adv.id) + '</span>' +
          '<span>Published ' + fmtDate(adv.published) + '</span>' +
          (adv.modified && adv.modified !== adv.published ? '<span>Updated ' + fmtDate(adv.modified) + '</span>' : '') +
        '</div>' +
      '</div>' +
      signalBodyHtml(adv);
  }

  function wireSignalBodyControls(container) {
    container.querySelectorAll('[data-desc-toggle]').forEach(btn => {
      btn.addEventListener('click', e => {
        e.stopPropagation();
        const id = btn.dataset.descToggle;
        if (expandedDescriptions.has(id)) expandedDescriptions.delete(id); else expandedDescriptions.add(id);
        renderCardModal();
      });
    });
    wireRelatedControls(container);
    // "Show other advisories for X" filters the list behind the modal -
    // close it so that list is actually visible instead of hidden behind
    // the write-up you just clicked away from.
    container.querySelectorAll('[data-related-key]').forEach(btn => {
      btn.addEventListener('click', () => closeCardModal());
    });
  }

  function renderCardModal() {
    const overlay = document.getElementById('card-modal-overlay');
    const modal = document.getElementById('card-modal');
    const bodyEl = document.getElementById('card-modal-body');
    if (!overlay || !modal || !bodyEl) return;
    if (!openModalId) {
      overlay.classList.remove('open');
      modal.classList.remove('open');
      modal.setAttribute('aria-hidden', 'true');
      modal.inert = true;
      bodyEl.innerHTML = '';
      return;
    }
    const adv = mergedAdvisoriesMap()[openModalId];
    if (!adv) { closeCardModal(); return; }
    bodyEl.innerHTML = signalModalContentHtml(adv);
    wireSignalBodyControls(bodyEl);
    overlay.classList.add('open');
    modal.classList.add('open');
    modal.setAttribute('aria-hidden', 'false');
    modal.inert = false;
  }

  function openCardModal(id, triggerEl) {
    openModalId = id;
    modalTriggerEl = triggerEl || null;
    renderCardModal();
    overlayOpened();
    // Deferred a tick: a real mouse click's native "focus the clicked
    // element" behavior runs AFTER bubbling listeners finish, not before -
    // calling closeBtn.focus() synchronously here just gets overwritten
    // the instant that native behavior fires (and since triggerEl is now
    // inert, it can't even land there, so it falls back to <body>
    // instead). Running on the next tick puts this after that native
    // focus attempt rather than before it.
    setTimeout(() => {
      const closeBtn = document.getElementById('card-modal-close');
      if (closeBtn) closeBtn.focus();
    }, 0);
  }

  function closeCardModal() {
    if (!openModalId) return;
    openModalId = null;
    renderCardModal();
    overlayClosed();
    if (modalTriggerEl && document.contains(modalTriggerEl)) modalTriggerEl.focus();
    modalTriggerEl = null;
  }

  // Only rendered when more than one source is actually contributing to
  // the visible list - the common case (nothing custom, nothing newer
  // than the snapshot, GHSA off) gets the plain count line instead.
  // Ranking stays one list; this is the honest annotation that replaces
  // splitting into two. Every advisory's src is exactly one of these
  // three (dedupeAdvisoriesByAlias picks a single canonical record when
  // merging), so the three counts always sum to list.length - a two-way
  // breakdown that silently dropped the GHSA count used to make the
  // sentence not add up to the total whenever GHSA was enabled.
  function sourceCountLabel(list) {
    const snapshotCount = list.filter(a => a.src === 'snapshot').length;
    const liveCount = list.filter(a => a.src === 'live').length;
    const ghsaCount = list.filter(a => a.src === 'github-advisories').length;
    const sourcesUsed = [snapshotCount, liveCount, ghsaCount].filter(Boolean).length;
    if (sourcesUsed < 2) return null;
    const parts = [];
    if (snapshotCount) parts.push(snapshotCount + ' from the built-in snapshot (' + escapeHtml(fmtDate(snapshot.generatedAt)) + ')');
    if (liveCount) parts.push(liveCount + ' fetched live');
    if (ghsaCount) parts.push(ghsaCount + ' from GitHub Security Advisories');
    const customCount = state.custom.length;
    return 'Showing ' + list.length + ' advisories &mdash; ' + parts.join(', ') +
      (customCount ? ' for your ' + customCount + ' custom package' + (customCount === 1 ? '' : 's') : '') + '.';
  }

  // Same outline-SVG style as the header logo / theme toggle (viewBox 0 0 24
  // 24, stroke currentColor, stroke-width ~1.7) so the stat row reads as part
  // of the same icon language rather than a bolted-on set.
  const STAT_ICONS = {
    total: '<path d="M4 6h16M4 12h16M4 18h10"/>',
    critical: '<path d="M12 3.3 2.5 20h19L12 3.3Z" stroke-linejoin="round"/><path d="M12 9.3v4.7M12 17v.01"/>',
    // Same warning-triangle shape as critical for every severity level -
    // severity is already color-coded (and labeled in text right next to
    // it); a different glyph per level would just be visual noise at
    // 12px, not an extra signal. "Unknown" gets a distinct question-mark
    // glyph since it's a different kind of fact (no data, not a level).
    high: '<path d="M12 3.3 2.5 20h19L12 3.3Z" stroke-linejoin="round"/><path d="M12 9.3v4.7M12 17v.01"/>',
    medium: '<path d="M12 3.3 2.5 20h19L12 3.3Z" stroke-linejoin="round"/><path d="M12 9.3v4.7M12 17v.01"/>',
    low: '<path d="M12 3.3 2.5 20h19L12 3.3Z" stroke-linejoin="round"/><path d="M12 9.3v4.7M12 17v.01"/>',
    unknown: '<circle cx="12" cy="12" r="9"/><path d="M9.4 9.3a2.6 2.6 0 1 1 3.8 2.3c-.8.4-1.2 1-1.2 1.9"/><path d="M12 17.2v.01"/>',
    kev: '<path d="M13 2 4.5 14h5.8l-1 8L18 10h-5.8l0.8-8Z" stroke-linejoin="round"/>',
    fix: '<circle cx="12" cy="12" r="9"/><path d="M7.8 12.3 10.3 15 16.2 9"/>',
    workaround: '<path d="M14.7 6.3a4 4 0 0 0-5.5 5.4L4.3 16.6l3 3 4.9-4.9a4 4 0 0 0 5.5-5.4l-2.8 2.8-2-2 2.8-2.8Z" stroke-linejoin="round"/>',
    watched: '<path d="M12 3.5 14.6 8.8 20.4 9.6 16.2 13.7 17.2 19.5 12 16.7 6.8 19.5 7.8 13.7 3.6 9.6 9.4 8.8 12 3.5Z" stroke-linejoin="round"/>',
    sla: '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3.3 2"/>',
  };
  // Badges already carry white text on a solid, contrast-checked
  // background (see the hex comments below), so stroke="currentColor"
  // makes the icon white too, for free - no separate contrast case to
  // solve like the stat-tile icons had against --surface-3.
  function badgeIconHtml(key) {
    const path = STAT_ICONS[key];
    if (!path) return '';
    return '<svg class="badge-icon" viewBox="0 0 24 24" width="11" height="11" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" aria-hidden="true">' + path + '</svg>';
  }
  function statIconHtml(key) {
    const path = STAT_ICONS[key];
    if (!path) return '';
    return '<svg class="stat-icon" viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" aria-hidden="true">' + path + '</svg>';
  }
  // Clickable when filterKey is given - each "At a glance" tile doubles as
  // a shortcut for the filter it summarizes, so seeing "38 Critical" and
  // acting on it is one click instead of a trip to the Filters drawer.
  // Rendered as a <button> in that case so it's keyboard-reachable; plain
  // <div> otherwise (nothing to click, nothing to reset styling on).
  function statTileHtml(label, value, extraClass, iconKey, filterKey, isActive) {
    const tag = filterKey ? 'button' : 'div';
    const typeAttr = filterKey ? ' type="button"' : '';
    const dataAttr = filterKey ? ' data-stat-filter="' + filterKey + '"' : '';
    // "total" is a reset action, not a toggle - aria-pressed doesn't apply
    // to it the way it does to the other tiles, which really do reflect a
    // filter's current on/off state (same pattern as .watch-toggle).
    const pressedAttr = filterKey && filterKey !== 'total' ? ' aria-pressed="' + !!isActive + '"' : '';
    const cls = 'stat-tile' + (extraClass ? ' ' + extraClass : '') + (isActive ? ' is-active' : '');
    return '<' + tag + typeAttr + ' class="' + cls + '"' + dataAttr + pressedAttr + '>' +
      '<div class="stat-value">' + statIconHtml(iconKey) + value + '</div>' +
      '<div class="stat-label">' + escapeHtml(label) + '</div>' +
    '</' + tag + '>';
  }

  // Mirrors the same scope as the ranked list (dateScopedAdvisories - the
  // date range applied, but not the click-to-filter quick filters below),
  // so a tile's count never collapses just because a different one is
  // active - you can always see "38 Critical" while "Fix available" is
  // engaged, then pivot straight to it.
  function renderExposureStats() {
    const el = document.getElementById('exposure-stats');
    if (!el) return;
    if (!snapshot || (!relatedFilterKey && state.selected.length === 0)) { el.innerHTML = ''; return; }
    const list = dateScopedAdvisories();
    const critical = list.filter(a => a.sev === 'CRITICAL').length;
    const kevCount = list.filter(isKev).length;
    const fixCount = list.filter(hasFix).length;
    const workaroundCount = list.filter(hasWorkaround).length;
    const watchedCount = list.filter(a => isWatched(a.id)).length;
    const slaBreachCount = list.filter(isSlaBreached).length;
    const dateNote = filterDateRange !== 'all' ? ' <span class="exposure-stats-scope">(last ' + filterDateRange + ' days)</span>' : '';
    el.innerHTML =
      '<h3 class="exposure-stats-heading">At a glance' + dateNote + '</h3>' +
      '<p class="exposure-stats-hint">Click a metric to filter the list.</p>' +
      statTileHtml('Total advisories', list.length, '', 'total', 'total', false) +
      statTileHtml('Critical', critical, critical ? 'stat-critical' : '', 'critical', 'critical', filterSeverity === 'CRITICAL') +
      statTileHtml('Actively exploited', kevCount, kevCount ? 'stat-kev' : '', 'kev', 'kev', filterKevOnly) +
      statTileHtml('SLA breached', slaBreachCount, slaBreachCount ? 'stat-sla-breach' : '', 'sla', 'sla', filterSlaBreachOnly) +
      statTileHtml('Fix available', fixCount, fixCount ? 'stat-fix' : '', 'fix', 'fix', filterHasFix) +
      statTileHtml('Workaround documented', workaroundCount, workaroundCount ? 'stat-workaround' : '', 'workaround', 'workaround', filterHasWorkaround) +
      (state.watched.length ? statTileHtml('Watched', watchedCount, watchedCount ? 'stat-watched' : '', 'watched', 'watched', filterWatchedOnly) : '') +
      '<div class="cross-link-card">' +
        '<p>Package CVEs are one slice of AI risk. <a href="/ai-shield/" target="_blank" rel="noopener">AI-SHIELD</a> assesses the rest &mdash; governance, access, data handling.</p>' +
      '</div>';
  }

  // ---------------------------------------------------------------
  // WHAT CHANGED - a "since your last visit" diff, not another feed to
  // re-scan for what's already been seen. Compares a snapshot of
  // {severity, KEV, fix} per advisory saved at the end of the previous
  // visit against the current merged data, computed once per page load
  // (right after loadSnapshot() resolves, see below) then immediately
  // overwritten with the current state - so a second reload seconds
  // later correctly shows "nothing changed" rather than repeating itself.
  // Tied to the "remember" toggle exactly like the stack/cache: with it
  // off there's no cross-visit identity to diff against, so history is
  // neither computed nor written, same privacy posture as everywhere
  // else persistence is optional here.
  // ---------------------------------------------------------------
  function loadHistorySnapshot() {
    try {
      const raw = localStorage.getItem(HISTORY_KEY);
      if (!raw) return null;
      const parsed = JSON.parse(raw);
      if (!parsed || typeof parsed !== 'object' || !parsed.records) return null;
      return parsed;
    } catch (e) { return null; }
  }
  function saveHistorySnapshot(records) {
    try { localStorage.setItem(HISTORY_KEY, JSON.stringify({ savedAt: new Date().toISOString(), records })); } catch (e) {}
  }
  function currentHistoryRecords() {
    const map = mergedAdvisoriesMap();
    const records = {};
    Object.keys(map).forEach(id => {
      const a = map[id];
      records[id] = { sev: a.sev, kev: isKev(a), fix: hasFix(a) };
    });
    return records;
  }
  // null = nothing to compare yet (first-ever visit, or "remember" is off).
  // Otherwise { since: ISO, items: [{ id, adv, kinds: [...] }] } - built
  // from the FULL merged data, not pre-filtered to the current stack, so
  // re-selecting packages later re-scopes the same underlying diff
  // instead of needing a recompute (see renderChangeHistory below).
  let changeHistoryDiff = null;
  function computeChangeHistory() {
    if (!rememberEnabled) { changeHistoryDiff = null; renderChangeHistory(); return; }
    const prev = loadHistorySnapshot();
    const current = currentHistoryRecords();
    if (prev) {
      const map = mergedAdvisoriesMap();
      const items = [];
      Object.keys(current).forEach(id => {
        const adv = map[id];
        if (!adv) return;
        const before = prev.records[id];
        const now = current[id];
        const kinds = [];
        if (!before) {
          kinds.push({ kind: 'new' });
        } else {
          if ((SEV_RANK[now.sev] || 0) > (SEV_RANK[before.sev] || 0)) kinds.push({ kind: 'severity-up', from: before.sev, to: now.sev });
          if (now.kev && !before.kev) kinds.push({ kind: 'kev' });
          if (now.fix && !before.fix) kinds.push({ kind: 'fix' });
        }
        if (kinds.length) items.push({ id, adv, kinds });
      });
      items.sort((a, b) => compareAdvisories(a.adv, b.adv));
      changeHistoryDiff = { since: prev.savedAt, items };
    } else {
      changeHistoryDiff = null;
    }
    saveHistorySnapshot(current);
    renderChangeHistory();
  }
  function changeTagHtml(k, adv) {
    if (k.kind === 'new') return '<span class="src-live">New</span>';
    if (k.kind === 'severity-up') return '<span class="src-live">' + escapeHtml(SEV_LABEL[k.from] || 'Unknown') + ' → ' + escapeHtml(SEV_LABEL[k.to] || 'Unknown') + '</span>';
    if (k.kind === 'kev') return kevBadgeHtml(adv);
    if (k.kind === 'fix') return fixBadgeHtml();
    return '';
  }
  function changeHistoryRowHtml(item) {
    const adv = item.adv;
    const matched = adv.pkgs.filter(k => state.selected.indexOf(k) !== -1);
    const pkgNames = (matched.length ? matched : adv.pkgs).map(pkgLabel).join(', ');
    return '<button type="button" class="priority-row" data-open-modal="' + escapeHtml(adv.id) + '">' +
      '<span class="priority-body">' +
        '<span class="priority-pkg">' + escapeHtml(pkgNames) + '</span>' +
        '<span class="priority-summary">' + escapeHtml(adv.summary) + '</span>' +
      '</span>' +
      '<span class="priority-badges">' + item.kinds.map(k => changeTagHtml(k, adv)).join('') + sevBadgeHtml(adv.sev) + '</span>' +
    '</button>';
  }
  // Re-scopes changeHistoryDiff to whatever's currently selected (or the
  // active related-package view) every time it's called - same
  // baseAdvisories() scoping the rest of the ranked list/stats use - so
  // toggling a package after load updates this without recomputing the
  // underlying diff.
  function renderChangeHistory() {
    const el = document.getElementById('change-history');
    if (!el) return;
    if (!rememberEnabled || !snapshot || (!relatedFilterKey && state.selected.length === 0)) { el.innerHTML = ''; return; }
    if (!changeHistoryDiff) { el.innerHTML = ''; return; }
    const selectedKeys = new Set(state.selected);
    const items = changeHistoryDiff.items.filter(it =>
      relatedFilterKey ? it.adv.pkgs.indexOf(relatedFilterKey) !== -1 : it.adv.pkgs.some(k => selectedKeys.has(k))
    );
    const sinceLabel = fmtRelativeTime(changeHistoryDiff.since);
    if (!items.length) {
      el.innerHTML =
        '<div class="change-history-head"><h3>What changed</h3>' +
        '<p class="sub">Nothing new for your selected stack since your last visit (' + escapeHtml(sinceLabel) + ').</p></div>';
      return;
    }
    const shown = items.slice(0, 6);
    const remaining = items.length - shown.length;
    el.innerHTML =
      '<div class="change-history-head">' +
        '<h3>What changed since your last visit</h3>' +
        '<p class="sub">' + items.length + ' update' + (items.length === 1 ? '' : 's') + ' for your selected stack since ' + escapeHtml(sinceLabel) + '.</p>' +
      '</div>' +
      '<div class="priority-list">' + shown.map(changeHistoryRowHtml).join('') + '</div>' +
      (remaining > 0 ? '<p class="change-history-more">+' + remaining + ' more change' + (remaining === 1 ? '' : 's') + '.</p>' : '');
    el.querySelectorAll('[data-open-modal]').forEach(btn => {
      btn.addEventListener('click', () => openCardModal(btn.dataset.openModal, btn));
    });
  }

  // ---------------------------------------------------------------
  // TOP PRIORITIES - "where do I spend one engineer-day this week", not
  // another 116-row list. A composite score, not just severity: known
  // active exploitation (and CISA's own deadline having passed) matters
  // more than the CVSS number alone, a published fix makes something
  // actionable RIGHT NOW rather than blocked waiting on upstream, and a
  // CVE hitting three of your selected packages is a bigger blast radius
  // than one hitting a single package at the same severity.
  // ---------------------------------------------------------------
  const RISK_SEV_WEIGHT = { CRITICAL: 40, HIGH: 25, MEDIUM: 12, LOW: 5, UNKNOWN: 8 };
  function priorityScore(adv) {
    let score = RISK_SEV_WEIGHT[adv.sev] || RISK_SEV_WEIGHT.UNKNOWN;
    if (isKev(adv)) {
      score += 35;
      const due = kevDueDateFor(adv);
      if (due && isPastDue(due)) score += 15;
    }
    if (hasFix(adv)) score += 8; // actionable now, not blocked on upstream
    if (isSlaBreached(adv)) score += 20; // already past your own team's deadline for it
    // Continuous, not binary like KEV above - two advisories at the same
    // severity with neither one KEV-listed can still differ hugely in
    // real-world exploitation likelihood; only ever adds (opt-in, and a
    // CVE with no score contributes nothing rather than being penalized).
    const epss = epssFor(adv);
    if (epss) score += Math.round(epss.epss * 15);
    const matchedCount = adv.pkgs.filter(k => state.selected.indexOf(k) !== -1).length;
    score += Math.min(12, Math.max(0, matchedCount - 1) * 3); // blast radius across your stack
    if (adv.published) {
      const ageDays = (Date.now() - new Date(adv.published).getTime()) / 86400000;
      if (ageDays > 180) score += 8;
      else if (ageDays > 90) score += 4;
    }
    return score;
  }

  function topPriorityRowHtml(adv, rank) {
    const matched = adv.pkgs.filter(k => state.selected.indexOf(k) !== -1);
    const pkgNames = (matched.length ? matched : adv.pkgs).map(pkgLabel).join(', ');
    const kev = isKev(adv);
    return '<button type="button" class="priority-row" data-open-modal="' + escapeHtml(adv.id) + '">' +
      '<span class="priority-rank">' + rank + '</span>' +
      '<span class="priority-body">' +
        '<span class="priority-pkg">' + escapeHtml(pkgNames) + '</span>' +
        '<span class="priority-summary">' + escapeHtml(adv.summary) + '</span>' +
      '</span>' +
      '<span class="priority-badges">' + (kev ? kevBadgeHtml(adv) : '') + sevBadgeHtml(adv.sev) + slaBadgeHtml(adv) + '</span>' +
    '</button>';
  }

  // Same scope as the At a Glance stats (date range applied, quick
  // filters ignored) and a floor of 4 advisories before it bothers
  // ranking anything - a "top 5" of a 3-item list isn't a priority call,
  // it's just the list again.
  function renderTopPriorities() {
    const el = document.getElementById('top-priorities');
    if (!el) return;
    if (!snapshot || (!relatedFilterKey && state.selected.length === 0)) { el.innerHTML = ''; return; }
    const list = dateScopedAdvisories();
    if (list.length < 4) { el.innerHTML = ''; return; }
    const top = list.slice().sort((a, b) => priorityScore(b) - priorityScore(a)).slice(0, 5);
    el.innerHTML =
      '<div class="priority-head">' +
        '<h3>Top priorities</h3>' +
        '<p class="sub">Ranked by severity, active exploitation, fixability, and how much of your stack it touches &mdash; where to spend limited time first.</p>' +
      '</div>' +
      '<div class="priority-list">' + top.map((adv, i) => topPriorityRowHtml(adv, i + 1)).join('') + '</div>';
    el.querySelectorAll('[data-open-modal]').forEach(btn => {
      btn.addEventListener('click', () => openCardModal(btn.dataset.openModal, btn));
    });
  }

  // Keeps the Filters-drawer checkboxes in sync whenever a quick filter is
  // toggled from a stat tile instead - so the drawer never shows "off"
  // while the list is actually filtered by that same control.
  function syncFilterCheckboxes() {
    const map = {
      'filter-has-fix': filterHasFix,
      'filter-no-fix': filterNoFix,
      'filter-has-workaround': filterHasWorkaround,
      'filter-no-workaround': filterNoWorkaround,
      'filter-watched-only': filterWatchedOnly,
      'filter-sla-breach': filterSlaBreachOnly,
    };
    Object.keys(map).forEach(id => {
      const box = document.getElementById(id);
      if (box) box.checked = map[id];
    });
  }

  // One tile, one filter - clicking again turns it back off. "Total
  // advisories" isn't a filter itself; it's the reset action, clearing
  // every quick filter below it (date range and search stay put, since
  // those are more deliberate choices than a one-click pivot).
  function toggleStatFilter(key) {
    if (key === 'total') {
      filterSeverity = null;
      filterKevOnly = false;
      filterHasFix = false;
      filterNoFix = false;
      filterHasWorkaround = false;
      filterNoWorkaround = false;
      filterWatchedOnly = false;
      filterSlaBreachOnly = false;
    } else if (key === 'critical') {
      filterSeverity = filterSeverity === 'CRITICAL' ? null : 'CRITICAL';
    } else if (key === 'kev') {
      filterKevOnly = !filterKevOnly;
    } else if (key === 'sla') {
      filterSlaBreachOnly = !filterSlaBreachOnly;
    } else if (key === 'fix') {
      filterHasFix = !filterHasFix;
      if (filterHasFix) filterNoFix = false;
    } else if (key === 'workaround') {
      filterHasWorkaround = !filterHasWorkaround;
      if (filterHasWorkaround) filterNoWorkaround = false;
    } else if (key === 'watched') {
      filterWatchedOnly = !filterWatchedOnly;
    } else {
      return;
    }
    shownCount = INITIAL_CARDS;
    syncFilterCheckboxes();
    renderExposureList();
  }

  // Wraps a renderExposureList() call so live data arriving mid-session
  // (a new advisory, or an existing one whose fresh CVSS/KEV/modified-date
  // moves it up the ranking) is visibly seen re-sorting rather than
  // silently swapped in via the instant innerHTML replace every render
  // already does. Cards are matched before/after by their stable data-id;
  // one that existed in both spots gets a FLIP transform from its old
  // position to its new one, one that's brand new gets a brief highlight
  // instead of a position to animate from. Only wraps the handful of call
  // sites where new data can actually arrive (live OSV/GHSA/KEV checks, a
  // custom package's own check) - routine filter/search/sort-order-only
  // interactions still update instantly, nothing to call out there.
  function withReorderAnimation(renderFn) {
    const container = document.getElementById('exposure-list');
    const before = new Map();
    if (container) {
      container.querySelectorAll('.signal-card[data-id]').forEach(el => {
        before.set(el.dataset.id, el.getBoundingClientRect());
      });
    }
    renderFn();
    if (!container) return;
    const reduceMotion = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    if (reduceMotion) return;
    container.querySelectorAll('.signal-card[data-id]').forEach(el => {
      const prev = before.get(el.dataset.id);
      if (!prev) {
        el.classList.add('card-just-updated');
        setTimeout(() => el.classList.remove('card-just-updated'), 1600);
        return;
      }
      const now = el.getBoundingClientRect();
      const dx = prev.left - now.left, dy = prev.top - now.top;
      if (Math.abs(dx) < 1 && Math.abs(dy) < 1) return;
      el.style.transition = 'none';
      el.style.transform = 'translate(' + dx + 'px,' + dy + 'px)';
      requestAnimationFrame(() => {
        el.style.transition = 'transform 0.4s ease';
        el.style.transform = '';
      });
    });
  }

  function updateFiltersBadge() {
    const badge = document.getElementById('filters-badge');
    if (!badge) return;
    const count = (filterSeverity ? 1 : 0) + (filterKevOnly ? 1 : 0) + (filterHasFix ? 1 : 0) + (filterNoFix ? 1 : 0) + (filterHasWorkaround ? 1 : 0) + (filterNoWorkaround ? 1 : 0) + (filterWatchedOnly ? 1 : 0) + (filterSlaBreachOnly ? 1 : 0) + (filterDateRange !== 'all' ? 1 : 0);
    badge.textContent = String(count);
    badge.hidden = count === 0;
  }

  function renderExposureList() {
    const el = document.getElementById('exposure-list');
    updateRefreshButton();
    updateDigestButton();
    updateSarifButton();
    updateCsvButton();
    updateExecOnePagerButton();
    updateWebhookButtons();
    updateBenchmarkButton();
    renderExposureStats();
    renderChangeHistory();
    renderTopPriorities();
    updateFiltersBadge();
    if (!el) return;

    // The text and the button need to be exactly two flex items, not four
    // - flexbox wraps each run of loose text/inline content between
    // elements in its own anonymous flex item, so raw text + <b> + text +
    // <button> as direct children of a space-between flex container tears
    // the sentence apart across the row. Wrapping the sentence in one <p>
    // makes it a single item again.
    const bannerHtml = relatedFilterKey
      ? '<div class="related-banner"><p>Showing all advisories related to <b>' + escapeHtml(pkgLabel(relatedFilterKey)) +
        '</b>, regardless of your selected stack above.</p><button type="button" id="clear-related-btn" class="btn small">Clear filter</button></div>'
      : '';

    if (!relatedFilterKey && state.selected.length === 0) {
      el.innerHTML = '<div class="empty-state"><p>Pick at least one package above to see its live advisories.</p></div>';
      return;
    }
    if (!snapshot) {
      el.innerHTML = '<div class="empty-state"><p>The advisory snapshot couldn&rsquo;t be loaded. Try reloading the page &mdash; the risk categories tab is unaffected either way.</p></div>';
      return;
    }

    const activeFilterLabels = [];
    if (filterSeverity) activeFilterLabels.push(SEV_LABEL[filterSeverity] ? SEV_LABEL[filterSeverity].toLowerCase() + ' severity' : 'that severity');
    if (filterKevOnly) activeFilterLabels.push('active exploitation confirmed');
    if (filterHasFix) activeFilterLabels.push('a known fix');
    if (filterNoFix) activeFilterLabels.push('no fix available yet');
    if (filterHasWorkaround) activeFilterLabels.push('a known workaround');
    if (filterNoWorkaround) activeFilterLabels.push('no known workaround');
    if (filterWatchedOnly) activeFilterLabels.push('a watch-list match');
    if (filterSlaBreachOnly) activeFilterLabels.push('a breached remediation SLA');
    if (alertsSearchQuery) activeFilterLabels.push('&ldquo;' + escapeHtml(alertsSearchQuery.trim()) + '&rdquo; in it');
    const dateLabel = filterDateRange !== 'all'
      ? (filterDateBasis === 'modified' ? 'updated' : 'published') + ' in the last ' + filterDateRange + ' days'
      : '';
    const withSuffix = activeFilterLabels.length ? ' with ' + activeFilterLabels.join(' and ') : '';
    const dateSuffix = dateLabel ? (withSuffix ? ', ' : ' ') + dateLabel : '';
    const filterSuffix = withSuffix + dateSuffix;
    activeFilterLabels.push(...(dateLabel ? [dateLabel] : []));

    const all = visibleAdvisories();
    if (all.length === 0) {
      const emptyMsg = activeFilterLabels.length
        ? 'No advisories' + filterSuffix + ' in the current view. Try clearing a filter in the Filters drawer.'
        : (relatedFilterKey
          ? 'No advisories found for ' + escapeHtml(pkgLabel(relatedFilterKey)) + '.'
          : 'No advisories in the current snapshot for your selected stack. That&rsquo;s a genuinely good sign, not a loading gap.');
      el.innerHTML = bannerHtml + '<div class="empty-state"><p>' + emptyMsg + '</p></div>';
      wireRelatedControls(el);
      return;
    }

    const shown = all.slice(0, shownCount);
    const remaining = all.length - shown.length;
    const moreHtml = remaining > 0
      ? '<button type="button" class="btn" id="show-more-btn">Show ' + Math.min(INITIAL_CARDS, remaining) + ' more (' + remaining + ' remaining)</button>'
      : '';
    const countLabel = (relatedFilterKey
      ? ' related to ' + escapeHtml(pkgLabel(relatedFilterKey))
      : ' for your selected stack') + filterSuffix + '.';
    const sourceLabel = relatedFilterKey ? null : sourceCountLabel(all);
    const countHtml = sourceLabel
      ? '<div class="signal-count source-note">' + sourceLabel + '</div>'
      : '<div class="signal-count">' + all.length + ' advisor' + (all.length === 1 ? 'y' : 'ies') + countLabel + '</div>';

    el.innerHTML = bannerHtml + countHtml +
      '<div class="signal-list">' + shown.map(signalCardHtml).join('') + '</div>' +
      moreHtml;

    el.querySelectorAll('[data-open-modal]').forEach(btn => {
      btn.addEventListener('click', () => openCardModal(btn.dataset.openModal, btn));
    });
    // Sibling of .signal-head, not nested inside it (a <button> can't
    // nest another <button>) - it's positioned on top via CSS instead. Not
    // a descendant of the modal-open button, so no propagation to stop, but
    // a click on it must not also open the modal; it's kept as its own
    // listener rather than delegated through signal-head.
    el.querySelectorAll('[data-watch]').forEach(btn => {
      btn.addEventListener('click', () => toggleWatch(btn.dataset.watch));
    });
    const moreBtn = document.getElementById('show-more-btn');
    if (moreBtn) moreBtn.addEventListener('click', () => { shownCount += INITIAL_CARDS; renderExposureList(); });
    wireRelatedControls(el);
  }

  function wireRelatedControls(el) {
    el.querySelectorAll('[data-related-key]').forEach(btn => {
      btn.addEventListener('click', e => { e.stopPropagation(); showRelated(btn.dataset.relatedKey); });
    });
    const clearBtn = document.getElementById('clear-related-btn');
    if (clearBtn) clearBtn.addEventListener('click', clearRelatedFilter);
  }

  // ---------------------------------------------------------------
  // DIGEST (P0-7): a plain-text Markdown export of whatever's currently
  // visible - "Copy this list" is the tool's only distribution mechanism
  // (paste into Slack, a ticket) so it must match the screen exactly,
  // fixed-in versions included, and never leave freshness ambiguous.
  // ---------------------------------------------------------------
  function buildDigest() {
    const list = visibleAdvisories();
    const lines = [];
    lines.push('Flare exposure digest');
    const snapshotPart = 'Snapshot: ' + (snapshot ? fmtDate(snapshot.generatedAt) : 'unavailable');
    const livePart = live ? ' · Live-checked: ' + fmtDate(live.fetchedAt) + ' ' + fmtTime(live.fetchedAt) : ' · No live check performed this session';
    lines.push(snapshotPart + livePart);
    lines.push('');
    const scopeLabel = relatedFilterKey ? 'related to ' + pkgLabel(relatedFilterKey) : 'for your selected stack';
    lines.push(list.length + ' advisor' + (list.length === 1 ? 'y' : 'ies') + ' ' + scopeLabel + ':');
    lines.push('');

    list.forEach(adv => {
      const pkgNames = adv.pkgs.map(pkgLabel).join(', ');
      const usable = (adv.fixes || []).filter(f => f.fixed && f.fixed.length);
      const fixedLine = usable.length
        ? usable.map(f => pkgLabel(f.pkg) + ' >= ' + f.fixed.join(', ')).join('; ')
        : 'no fixed version yet';
      const tags = [];
      if (isKev(adv)) tags.push('KEV');
      if (adv.src === 'live') tags.push('LIVE');
      if (adv.src === 'github-advisories') tags.push('GHSA');
      const tagStr = tags.length ? ' [' + tags.join(', ') + ']' : '';
      const sev = SEV_LABEL[adv.sev] || 'Severity unknown';
      const link = (adv.refs && adv.refs.osv) || '';
      lines.push('- [' + sev.toUpperCase() + ']' + tagStr + ' ' + pkgNames + ' — ' + adv.summary +
        ' (' + adv.id + ') — Fixed in: ' + fixedLine + (link ? ' — ' + link : ''));
    });

    return lines.join('\n');
  }

  function updateDigestButton() {
    const btn = document.getElementById('digest-btn');
    if (!btn) return;
    btn.disabled = !snapshot || visibleAdvisories().length === 0;
  }

  function copyDigestText(text) {
    const note = document.getElementById('digest-copy-note');
    const ok = () => { if (note) note.textContent = 'Copied to clipboard.'; };
    const manual = () => { if (note) note.textContent = 'Couldn’t copy automatically — the text above is selected, press Ctrl/Cmd+C.'; };
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(ok).catch(manual);
    } else {
      try { document.execCommand('copy'); ok(); } catch (e) { manual(); }
    }
  }

  function openDigest() {
    const panel = document.getElementById('digest-panel');
    const box = document.getElementById('digest-box');
    if (!panel || !box) return;
    const text = buildDigest();
    box.value = text;
    panel.hidden = false;
    box.focus();
    box.select();
    copyDigestText(text);
  }

  // ---------------------------------------------------------------
  // SARIF EXPORT - SARIF 2.1.0, the static-analysis interchange format
  // GitHub code scanning, Azure DevOps, and most SCA/SAST dashboards
  // ingest natively, so a security team can pull Flare's findings into
  // whatever tracker they already run instead of re-keying them by hand.
  // Same scope as the digest above (visibleAdvisories - respects
  // whatever filters are active). One result per (advisory, matched
  // package) pair - a CVE hitting three of your packages produces three
  // findings, each pointing at that package, mirroring how OSV-Scanner's
  // own SARIF output structures multi-package advisories. Locations are
  // synthetic (Flare runs client-side and has no knowledge of your real
  // lockfile path) - documented in the run's own originalUriBaseIds
  // description rather than left silently unexplained.
  // ---------------------------------------------------------------
  const ECOSYSTEM_TO_PURL_TYPE = {
    PyPI: 'pypi', npm: 'npm', Go: 'golang', Maven: 'maven',
    'crates.io': 'cargo', RubyGems: 'gem', NuGet: 'nuget', Packagist: 'composer',
  };
  function sarifLevelFor(sev) {
    if (sev === 'CRITICAL' || sev === 'HIGH') return 'error';
    if (sev === 'MEDIUM') return 'warning';
    return 'note';
  }
  // GitHub code scanning colors/sorts alerts by this 0-10 property when
  // present, falling back to a representative score per band for the
  // (common) case where OSV didn't publish a CVSS number for this
  // particular advisory.
  const SEV_SECURITY_SCORE = { CRITICAL: 9.5, HIGH: 7.5, MEDIUM: 5.0, LOW: 2.0, UNKNOWN: 0.0 };
  function sarifSecuritySeverity(adv) {
    if (typeof adv.score === 'number') return adv.score.toFixed(1);
    const band = SEV_SECURITY_SCORE[adv.sev];
    return (band != null ? band : 0).toFixed(1);
  }
  function buildSarif() {
    const list = visibleAdvisories();
    const rulesById = new Map();
    const results = [];
    list.forEach(adv => {
      if (!rulesById.has(adv.id)) {
        const tags = ['security'];
        if (isKev(adv)) tags.push('kev');
        if (isSlaBreached(adv)) tags.push('sla-breached');
        rulesById.set(adv.id, {
          id: adv.id,
          shortDescription: { text: adv.summary || adv.id },
          fullDescription: { text: (adv.summary || adv.id) + (adv.cve && adv.cve !== adv.id ? ' (' + adv.cve + ')' : '') },
          helpUri: (adv.refs && adv.refs.osv) || newsSearchUrl(adv),
          properties: {
            tags,
            'security-severity': sarifSecuritySeverity(adv),
            severity: SEV_LABEL[adv.sev] || 'Unknown',
          },
        });
      }
      const matchKeys = adv.pkgs.length ? adv.pkgs : [null];
      matchKeys.forEach(key => {
        const pkg = key ? pkgByKey(key) : null;
        const pkgName = pkg ? (pkg.name || pkg.label || key) : (key || 'unknown package');
        const purlType = pkg && ECOSYSTEM_TO_PURL_TYPE[pkg.ecosystem] ? ECOSYSTEM_TO_PURL_TYPE[pkg.ecosystem] : 'generic';
        const fixNote = usableFixes(adv).length ? ' A fix is available.' : ' No fixed version has been published yet.';
        results.push({
          ruleId: adv.id,
          level: sarifLevelFor(adv.sev),
          message: { text: (SEV_LABEL[adv.sev] || 'Unknown severity') + ' in ' + pkgName + ': ' + (adv.summary || adv.id) + fixNote },
          locations: [{
            physicalLocation: {
              artifactLocation: { uri: 'dependencies/' + purlType + '/' + pkgName, uriBaseId: 'FLARE_STACK' },
            },
            logicalLocations: [{ name: pkgName, kind: 'package' }],
          }],
          properties: {
            package: pkgName,
            ecosystem: pkg ? pkg.ecosystem : null,
            kev: isKev(adv),
            slaBreached: isSlaBreached(adv),
            published: adv.published || null,
          },
        });
      });
    });
    return {
      '$schema': 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
      version: '2.1.0',
      runs: [{
        tool: {
          driver: {
            name: 'Flare',
            informationUri: 'https://lab.krismccabe.com/flare/',
            version: '1.0.0',
            organization: 'Kris McCabe',
            shortDescription: { text: 'Live AI-stack dependency vulnerability advisories from OSV.dev, CISA KEV, and GitHub Security Advisories.' },
            rules: Array.from(rulesById.values()),
          },
        },
        originalUriBaseIds: {
          FLARE_STACK: {
            uri: 'https://lab.krismccabe.com/flare/',
            description: { text: 'Synthetic base - Flare runs entirely client-side and has no knowledge of your real lockfile path. Locations group findings by ecosystem and package name, not a literal file in your repo.' },
          },
        },
        results,
      }],
    };
  }
  // ---------------------------------------------------------------
  // SHAREABLE VIEW LINKS - encodes the current stack selection + active
  // filters into a URL, so "here's what I'm looking at" is a paste
  // instead of a screen-share. applySharedViewFromUrl() runs once on
  // load (right after loadPersisted(), before the first real render):
  // if the link points at a package the recipient doesn't track (one of
  // the sender's own custom packages), that entry is silently dropped
  // rather than auto-adding an unrecognized package - Flare never
  // bulk-adds tracked packages without an explicit user action
  // elsewhere in the app, and a shared link shouldn't be the exception.
  // Applying a link never calls persistIfEnabled() - it's a one-time
  // view, not a silent overwrite of whatever stack you'd already saved;
  // touching any control afterward resumes normal persistence.
  // ---------------------------------------------------------------
  function buildShareUrl() {
    const params = new URLSearchParams();
    if (relatedFilterKey) params.set('related', relatedFilterKey);
    else if (state.selected.length) params.set('pkgs', state.selected.join(','));
    if (filterSeverity) params.set('sev', filterSeverity);
    if (filterKevOnly) params.set('kev', '1');
    if (filterSlaBreachOnly) params.set('sla', '1');
    if (filterHasFix) params.set('fix', '1');
    if (filterNoFix) params.set('nofix', '1');
    if (filterHasWorkaround) params.set('wa', '1');
    if (filterNoWorkaround) params.set('nowa', '1');
    if (filterWatchedOnly) params.set('watched', '1');
    if (filterDateRange !== 'all') params.set('range', filterDateRange);
    if (filterDateBasis !== 'published') params.set('basis', filterDateBasis);
    if (alertsSearchQuery) params.set('q', alertsSearchQuery);
    params.set('tab', 'alerts');
    const qs = params.toString();
    return location.origin + location.pathname + (qs ? '?' + qs : '');
  }
  function copyShareLink() {
    const url = buildShareUrl();
    const note = document.getElementById('share-view-note');
    const ok = () => { if (note) note.textContent = 'Link copied — it reproduces this exact view.'; };
    const manual = () => { if (note) note.textContent = url; };
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(url).then(ok).catch(manual);
    } else {
      try {
        const ta = document.createElement('textarea');
        ta.value = url; ta.style.position = 'fixed'; ta.style.opacity = '0';
        document.body.appendChild(ta); ta.focus(); ta.select();
        document.execCommand('copy'); document.body.removeChild(ta);
        ok();
      } catch (e) { manual(); }
    }
  }
  const SEV_URL_VALUES = new Set(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']);
  const RANGE_URL_VALUES = new Set(['7', '30', '90']);
  // Returns true if a package selection (or related-package view) came
  // from the URL, so the caller can skip the AI-SHIELD stack suggestion
  // below - that suggestion only guards against overwriting a *saved*
  // stack (localStorage), so without this a first-time visitor opening a
  // shared link would have it silently clobbered right after being applied.
  function applySharedViewFromUrl() {
    let params;
    try { params = new URLSearchParams(location.search); } catch (e) { return false; }
    if (![...params.keys()].length) return false;

    const relatedKey = params.get('related');
    const pkgsParam = params.get('pkgs');
    let appliedSelection = false;
    if (relatedKey && pkgByKey(relatedKey)) {
      relatedFilterKey = relatedKey;
      appliedSelection = true;
    } else if (pkgsParam) {
      const keys = pkgsParam.split(',').map(s => s.trim()).filter(Boolean).filter(k => pkgByKey(k));
      if (keys.length) { state.selected = keys; appliedSelection = true; }
    }

    const sev = params.get('sev');
    if (sev && SEV_URL_VALUES.has(sev)) filterSeverity = sev;
    if (params.get('kev') === '1') filterKevOnly = true;
    if (params.get('sla') === '1') filterSlaBreachOnly = true;
    if (params.get('fix') === '1') filterHasFix = true;
    if (params.get('nofix') === '1') filterNoFix = true;
    if (params.get('wa') === '1') filterHasWorkaround = true;
    if (params.get('nowa') === '1') filterNoWorkaround = true;
    if (params.get('watched') === '1') filterWatchedOnly = true;
    const range = params.get('range');
    if (range && RANGE_URL_VALUES.has(range)) filterDateRange = range;
    if (params.get('basis') === 'modified') filterDateBasis = 'modified';
    const q = params.get('q');
    if (q) alertsSearchQuery = q.slice(0, 200);

    // Reflect the parsed state into the actual form controls - they're
    // already in the DOM at this point (static body.html), and a user
    // who opens the Filters drawer afterward should see checkboxes/
    // selects that already agree with what's on screen, not defaults
    // that silently don't match.
    syncFilterCheckboxes();
    const dateRangeEl = document.getElementById('filter-date-range');
    if (dateRangeEl) dateRangeEl.value = filterDateRange;
    const dateBasisEl = document.getElementById('filter-date-basis');
    if (dateBasisEl) dateBasisEl.value = filterDateBasis;
    const searchEl = document.getElementById('alerts-search-input');
    if (searchEl) searchEl.value = alertsSearchQuery;

    if (params.get('tab') === 'alerts' || relatedFilterKey || pkgsParam) switchTab('alerts');
    return appliedSelection;
  }

  // ---------------------------------------------------------------
  // TEAM DASHBOARD - link-based shared stack ("Option A" of the
  // multi-team dashboard idea): no accounts, no passwords, no email.
  // Creating a team mints an unguessable token server-side
  // (api/flare-team.php); anyone holding the ?team=<token> link can view
  // and edit that team's package list, the same trust model as an
  // unlisted document link - possessing the link IS the access control.
  // Distinct from the one-time SHAREABLE VIEW LINKS above: this is
  // persistent and bidirectional (short polling both picks up teammates'
  // edits and pushes your own), not a single "here's what I was looking
  // at" snapshot. Only the base watchlist's package keys reliably round-
  // trip - a teammate's own custom (non-watchlist) packages aren't synced
  // as full definitions, so a key your browser doesn't already recognize
  // is silently dropped, same as applySharedViewFromUrl() does for the
  // same reason. Applying a team's list never calls persistIfEnabled() -
  // see the comment on that function.
  // ---------------------------------------------------------------
  const TEAM_ENDPOINT = 'https://krismccabe.com/api/flare-team.php';
  const TEAM_TOKEN_RE = /^[a-f0-9]{32}$/;
  const TEAM_POLL_MS = 20000;
  let teamToken = null;
  let teamName = '';
  let teamModeActive = false;
  let teamPollTimer = null;
  let teamUpdateTimer = null;
  let teamPendingLocalEdit = false; // true between a local toggle and its debounced POST landing - polling skips applying incoming state so it can't clobber an unsent edit
  let teamLinkDead = false; // true once the server says this token no longer resolves (expired, or regenerated from elsewhere) - stops polling/sending but keeps the last-known view on screen rather than yanking it away

  function teamUrlFor(token) {
    return location.origin + location.pathname + '?team=' + token;
  }
  function setTeamUrlParam(token) {
    const params = new URLSearchParams(location.search);
    if (token) params.set('team', token); else params.delete('team');
    const qs = params.toString();
    history.replaceState(null, '', location.pathname + (qs ? '?' + qs : ''));
  }
  function renderTeamBanner() {
    const banner = document.getElementById('team-banner');
    const text = document.getElementById('team-banner-text');
    if (!banner || !text) return;
    banner.hidden = !teamModeActive;
    banner.classList.toggle('team-banner-dead', teamLinkDead);
    if (!teamModeActive) return;
    text.innerHTML = teamLinkDead
      ? 'This team link no longer works <strong>&mdash; it may have expired or been regenerated elsewhere.</strong> What’s on screen is the last synced view; it will not update further.'
      : 'Viewing team: <strong>' + escapeHtml(teamName || 'Untitled team') + '</strong> &mdash; changes here sync for everyone with this link.';
  }
  // Marks the current token as dead (expired, or replaced by a
  // regenerate elsewhere) - stops polling/sending but deliberately leaves
  // state.selected exactly as it last was, rather than clearing the
  // screen out from under whoever's looking at it.
  function markTeamLinkDead() {
    if (teamLinkDead) return;
    teamLinkDead = true;
    stopTeamPolling();
    renderTeamBanner();
    renderTeamPanel("This link no longer works — it may have expired or been regenerated. Ask whoever shared it for a fresh one.", true);
  }
  function renderTeamPanel(statusMsg, isError) {
    const createRow = document.getElementById('team-create-row');
    const linkRow = document.getElementById('team-link-row');
    const linkInput = document.getElementById('team-link-input');
    const status = document.getElementById('team-dashboard-status');
    const toggleBtn = document.getElementById('team-dashboard-toggle-btn');
    const regenBtn = document.getElementById('team-regenerate-btn');
    if (createRow) createRow.hidden = teamModeActive;
    if (linkRow) linkRow.hidden = !teamModeActive;
    if (linkInput && teamModeActive) linkInput.value = teamUrlFor(teamToken);
    if (toggleBtn) toggleBtn.textContent = teamModeActive ? 'Team dashboard (active)' : 'Team dashboard';
    // A dead token can't regenerate itself (there's nothing left server-side
    // to rotate) - the only way forward is a fresh Create.
    if (regenBtn) regenBtn.disabled = teamLinkDead;
    if (status && statusMsg !== undefined) {
      status.textContent = statusMsg;
      status.classList.toggle('team-status-error', !!isError);
    }
  }
  function stopTeamPolling() {
    if (teamPollTimer) { clearInterval(teamPollTimer); teamPollTimer = null; }
  }
  function startTeamPolling() {
    stopTeamPolling();
    teamPollTimer = setInterval(() => {
      if (document.visibilityState === 'visible' && teamModeActive && !teamPendingLocalEdit) pollTeam();
    }, TEAM_POLL_MS);
  }
  async function pollTeam() {
    if (!teamToken || teamPendingLocalEdit) return;
    try {
      const resp = await fetch(TEAM_ENDPOINT + '?action=get&token=' + encodeURIComponent(teamToken));
      const data = await resp.json();
      if (!data || !data.ok) {
        if (resp.status === 404) markTeamLinkDead();
        return;
      }
      teamName = data.name || '';
      state.selected = Array.isArray(data.selected) ? data.selected.filter(k => pkgByKey(k)) : [];
      shownCount = INITIAL_CARDS;
      renderTeamBanner();
      renderStackSelector();
      renderExposureList();
    } catch (e) { /* transient network hiccup - the next poll retries; not worth surfacing an error for */ }
  }
  function enterTeamMode(token, name, selected) {
    teamToken = token;
    teamName = name || '';
    teamModeActive = true;
    teamLinkDead = false;
    state.selected = Array.isArray(selected) ? selected.filter(k => pkgByKey(k)) : [];
    shownCount = INITIAL_CARDS;
    setTeamUrlParam(token);
    renderTeamBanner();
    renderTeamPanel('Live — syncing with everyone who has this link.', false);
    renderStackSelector();
    renderExposureList();
    startTeamPolling();
  }
  function leaveTeamMode() {
    stopTeamPolling();
    teamToken = null; teamName = ''; teamModeActive = false; teamPendingLocalEdit = false; teamLinkDead = false;
    if (teamUpdateTimer) { clearTimeout(teamUpdateTimer); teamUpdateTimer = null; }
    setTeamUrlParam(null);
    loadPersisted();
    shownCount = INITIAL_CARDS;
    renderTeamBanner();
    renderTeamPanel('', false);
    renderStackSelector();
    renderExposureList();
  }
  async function joinTeamFromUrl(token) {
    renderTeamPanel('Loading team…', false);
    try {
      const resp = await fetch(TEAM_ENDPOINT + '?action=get&token=' + encodeURIComponent(token));
      const data = await resp.json();
      if (data && data.ok) {
        enterTeamMode(token, data.name, data.selected);
      } else {
        renderTeamPanel("That team link doesn't work anymore — it may be mistyped, or the team no longer exists.", true);
      }
    } catch (e) {
      renderTeamPanel("Couldn't reach the team dashboard right now — try reloading.", true);
    }
  }
  async function createTeam() {
    const btn = document.getElementById('team-create-btn');
    const nameInput = document.getElementById('team-create-name-input');
    if (!btn) return;
    btn.disabled = true;
    btn.textContent = 'Creating…';
    try {
      const resp = await fetch(TEAM_ENDPOINT + '?action=create', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: nameInput ? nameInput.value : '', selected: state.selected }),
      });
      const data = await resp.json();
      if (data && data.ok && data.token) {
        enterTeamMode(data.token, data.name, data.selected);
      } else {
        renderTeamPanel("Couldn't create a team link right now — try again in a moment.", true);
      }
    } catch (e) {
      renderTeamPanel("Couldn't create a team link right now — try again in a moment.", true);
    } finally {
      btn.disabled = false;
      btn.textContent = 'Create a shareable team link';
    }
  }
  // Mints a fresh token for the current team and retires the old one -
  // the "kill switch" if a link leaked (posted somewhere public, sent to
  // the wrong person) or just needs rotating. Same shared list, new link;
  // anyone still holding the old one stops resolving immediately.
  async function regenerateTeamLink() {
    const btn = document.getElementById('team-regenerate-btn');
    if (!btn || !teamToken || teamLinkDead) return;
    btn.disabled = true;
    const prevLabel = btn.textContent;
    btn.textContent = 'Regenerating…';
    try {
      const resp = await fetch(TEAM_ENDPOINT + '?action=regenerate', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token: teamToken }),
      });
      const data = await resp.json();
      if (data && data.ok && data.token) {
        teamToken = data.token;
        setTeamUrlParam(teamToken);
        renderTeamPanel('New link generated — the old one no longer works. Live — syncing with everyone who has this link.', false);
      } else {
        renderTeamPanel("Couldn't regenerate the link right now — try again in a moment.", true);
      }
    } catch (e) {
      renderTeamPanel("Couldn't regenerate the link right now — try again in a moment.", true);
    } finally {
      btn.disabled = teamLinkDead;
      btn.textContent = prevLabel;
    }
  }
  function queueTeamUpdate() {
    if (!teamModeActive || !teamToken) return;
    teamPendingLocalEdit = true;
    if (teamUpdateTimer) clearTimeout(teamUpdateTimer);
    teamUpdateTimer = setTimeout(async () => {
      const selectedAtSend = state.selected.slice();
      try {
        const resp = await fetch(TEAM_ENDPOINT + '?action=update', {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ token: teamToken, selected: selectedAtSend }),
        });
        const data = await resp.json();
        if (data && data.ok) {
          renderTeamPanel('Live — syncing with everyone who has this link.', false);
        } else if (resp.status === 404) {
          markTeamLinkDead();
        } else {
          renderTeamPanel("Couldn't save your last change — it may not have reached the team.", true);
        }
      } catch (e) {
        renderTeamPanel("Couldn't save your last change — it may not have reached the team.", true);
      } finally {
        teamPendingLocalEdit = false;
      }
    }, 800);
  }
  function copyTeamLink() {
    const input = document.getElementById('team-link-input');
    if (!input) return;
    const url = input.value;
    const ok = () => renderTeamPanel('Link copied.', false);
    const manual = () => renderTeamPanel(url, false);
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(url).then(ok).catch(manual);
    } else {
      try { input.focus(); input.select(); document.execCommand('copy'); ok(); } catch (e) { manual(); }
    }
  }
  // Checked once at boot (see init below), same "sync, cheap, decides
  // whether the shield suggestion should run" role sharedViewApplied
  // plays for the URL-encoded view links - a malformed token just means
  // "not a team link", no error shown.
  function teamTokenFromUrl() {
    let params;
    try { params = new URLSearchParams(location.search); } catch (e) { return null; }
    const token = params.get('team');
    return token && TEAM_TOKEN_RE.test(token) ? token : null;
  }

  function updateSarifButton() {
    const btn = document.getElementById('sarif-btn');
    if (!btn) return;
    btn.disabled = !snapshot || visibleAdvisories().length === 0;
  }
  function exportSarif() {
    downloadBlob(JSON.stringify(buildSarif(), null, 2), 'flare-advisories.sarif', 'application/sarif+json');
  }

  // ---------------------------------------------------------------
  // CSV VULNERABILITY REGISTER - the flat, audit-friendly counterpart to
  // the SARIF export above: one row per (advisory, matched package),
  // every column a register/spreadsheet-literate reviewer expects,
  // openable directly in Excel/Sheets with no tool support needed. Same
  // scope as SARIF and the digest (visibleAdvisories - respects
  // whatever filters are currently active).
  // ---------------------------------------------------------------
  function toCSVRow(cells) {
    return cells.map(c => {
      const s = String(c == null ? '' : c);
      return /[",\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
    }).join(',');
  }
  function buildCsvRegister() {
    const list = visibleAdvisories();
    const rows = [[
      'Advisory ID', 'CVE', 'Package', 'Ecosystem', 'Severity', 'CVSS Score',
      'Actively Exploited (KEV)', 'KEV Due Date', 'EPSS Score (%)', 'Published', 'Last Updated',
      'Days Open', 'SLA Target (days)', 'SLA Breached', 'Fix Available',
      'Fixed Version(s)', 'Workaround Available', 'Source', 'Summary', 'Reference URL',
    ]];
    list.forEach(adv => {
      const usable = usableFixes(adv);
      const fixedLine = usable.length ? usable.map(f => pkgLabel(f.pkg) + ' >= ' + f.fixed.join(', ')).join('; ') : '';
      const kev = isKev(adv);
      const due = kevDueDateFor(adv);
      const epss = epssFor(adv);
      const open = daysOpen(adv);
      const target = slaTargetFor(adv.sev);
      const breached = isSlaBreached(adv);
      const link = (adv.refs && adv.refs.osv) || '';
      const sourceLabel = adv.src === 'live' ? 'OSV.dev (live check)' : (adv.src === 'github-advisories' ? 'GitHub Security Advisories' : 'OSV.dev (daily snapshot)');
      const matchKeys = adv.pkgs.length ? adv.pkgs : [null];
      matchKeys.forEach(key => {
        const pkg = key ? pkgByKey(key) : null;
        rows.push([
          adv.id,
          adv.cve || '',
          pkg ? (pkg.name || pkg.label || key) : (key || ''),
          pkg ? pkg.ecosystem : '',
          SEV_LABEL[adv.sev] || 'Unknown',
          adv.score != null ? adv.score : '',
          kev ? 'Yes' : 'No',
          due || '',
          epss ? (epss.epss * 100).toFixed(1) : '',
          adv.published || '',
          adv.modified || '',
          open != null ? open : '',
          target || '',
          breached ? 'Yes' : 'No',
          hasFix(adv) ? 'Yes' : 'No',
          fixedLine,
          hasWorkaround(adv) ? 'Yes' : 'No',
          sourceLabel,
          adv.summary || '',
          link,
        ]);
      });
    });
    return rows.map(toCSVRow).join('\r\n');
  }
  function updateCsvButton() {
    const btn = document.getElementById('csv-btn');
    if (!btn) return;
    btn.disabled = !snapshot || visibleAdvisories().length === 0;
  }
  function exportCsvRegister() {
    downloadBlob(buildCsvRegister(), 'flare-vulnerability-register.csv', 'text/csv');
  }

  // ---------------------------------------------------------------
  // EXECUTIVE ONE-PAGER (print/PDF) - a purpose-built single-page report
  // for a CISO or leadership audience, not "whatever the card list looks
  // like right now". Populates a dedicated #print-root container (hidden
  // on screen; everything else hidden via body.printing-onepager during
  // print, see CSS) rather than reusing the existing .no-print
  // convention - that convention already covers "print the current
  // filtered card list" via plain Ctrl+P, which stays exactly as it was;
  // this is a deliberately different, opt-in report triggered by its own
  // button. Same scope as the At a Glance stats and Top priorities
  // (dateScopedAdvisories - date range applied, quick filters ignored),
  // for the same reason: an executive summary shouldn't silently
  // describe a narrower window than the dashboard itself does.
  // ---------------------------------------------------------------
  function execOnePagerIdentityLine() {
    const pkgs = selectedPackages().map(p => p.label || p.name);
    if (!pkgs.length) return 'No packages selected.';
    if (pkgs.length <= 8) return pkgs.join(', ');
    return pkgs.slice(0, 8).join(', ') + ', and ' + (pkgs.length - 8) + ' more';
  }
  function buildExecOnePagerHtml() {
    const today = new Date().toLocaleDateString('en-GB', { day: 'numeric', month: 'long', year: 'numeric' });
    const list = dateScopedAdvisories();
    const critical = list.filter(a => a.sev === 'CRITICAL').length;
    const kevCount = list.filter(isKev).length;
    const slaBreachCount = list.filter(isSlaBreached).length;
    const fixCount = list.filter(hasFix).length;

    let out = '<div class="print-page onepager">';
    out += '<p class="p-eyebrow">Flare &mdash; Executive Summary</p>';
    out += '<h1>AI Stack Exposure Summary</h1>';
    out += '<p class="p-identity">' + escapeHtml(execOnePagerIdentityLine()) + '</p>';
    out += '<p><strong>Generated:</strong> ' + today + (snapshot ? ' &middot; <strong>Advisory data as of:</strong> ' + fmtDate(snapshot.generatedAt) : '') + '</p>';

    out += '<div class="p-score-box"><span class="p-score-num" style="color:' + (critical || kevCount ? '#DC2626' : '#15803D') + ';">' + list.length + '</span>' +
      '<span class="p-score-denom">advisor' + (list.length === 1 ? 'y' : 'ies') + ' currently tracked</span></div>';

    const sentenceParts = [];
    if (kevCount) sentenceParts.push(kevCount + ' actively exploited in the wild (CISA KEV)');
    if (critical) sentenceParts.push(critical + ' critical severity');
    if (slaBreachCount) sentenceParts.push(slaBreachCount + ' past your team’s own remediation SLA');
    const lead = list.length === 0
      ? 'No advisories are currently tracked for this stack &mdash; a genuinely good sign, not a loading gap.'
      : (sentenceParts.length
        ? 'Of ' + list.length + ' tracked advisories, ' + sentenceParts.join('; ') + '. ' + fixCount + ' already have a published fix available.'
        : list.length + ' advisories are tracked, none critical or actively exploited right now. ' + fixCount + ' have a published fix available.');
    out += '<p class="p-lead">' + lead + '</p>';

    if (changeHistoryDiff) {
      const selectedKeys = new Set(state.selected);
      const changeItems = changeHistoryDiff.items.filter(it =>
        relatedFilterKey ? it.adv.pkgs.indexOf(relatedFilterKey) !== -1 : it.adv.pkgs.some(k => selectedKeys.has(k))
      );
      out += '<h2>Since your last visit</h2>';
      out += changeItems.length
        ? '<p>' + changeItems.length + ' update' + (changeItems.length === 1 ? '' : 's') + ' since ' + escapeHtml(fmtRelativeTime(changeHistoryDiff.since)) + '.</p>'
        : '<p>Nothing new since ' + escapeHtml(fmtRelativeTime(changeHistoryDiff.since)) + '.</p>';
    }

    const top = list.slice().sort((a, b) => priorityScore(b) - priorityScore(a)).slice(0, 5);
    out += '<h2>Top priorities</h2>';
    if (top.length) {
      top.forEach((adv, i) => {
        const matched = adv.pkgs.filter(k => state.selected.indexOf(k) !== -1);
        const pkgNames = (matched.length ? matched : adv.pkgs).map(pkgLabel).join(', ');
        const tags = [];
        if (isKev(adv)) tags.push('Actively exploited');
        tags.push(SEV_LABEL[adv.sev] || 'Unknown severity');
        if (isSlaBreached(adv)) tags.push('Past SLA');
        const usable = usableFixes(adv);
        const fixLine = usable.length ? 'Upgrade ' + usable.map(f => pkgLabel(f.pkg) + ' to ' + f.fixed.join(' or ')).join('; ') + '.' : 'No fixed version published yet.';
        out += '<div class="p-gap' + (adv.sev === 'CRITICAL' || isKev(adv) ? ' p-gap-critical' : '') + '">' +
          '<strong>' + (i + 1) + '. ' + escapeHtml(pkgNames) + ' — ' + escapeHtml(tags.join(', ')) + '</strong><br>' +
          escapeHtml(adv.summary) + '<br>' +
          '<span class="p-next"><b>Action:</b> ' + escapeHtml(fixLine) + '</span>' +
        '</div>';
      });
    } else {
      out += '<p>No outstanding priorities — nothing tracked meets the bar for this list.</p>';
    }

    out += '<p class="p-footer">Generated by Flare &mdash; a free tool by Kris McCabe. lab.krismccabe.com/flare/. Advisory data from OSV.dev' +
      (kevCount ? ', cross-checked against CISA’s Known Exploited Vulnerabilities catalog' : '') + '. Not a certified audit or penetration test.</p>';
    out += '</div>';
    return out;
  }
  function updateExecOnePagerButton() {
    const btn = document.getElementById('exec-onepager-btn');
    if (!btn) return;
    btn.disabled = !snapshot || (!relatedFilterKey && state.selected.length === 0);
  }
  function printExecOnePager() {
    const root = document.getElementById('print-root');
    if (!root) return;
    root.innerHTML = buildExecOnePagerHtml();
    document.body.classList.add('printing-onepager');
    window.print();
  }
  window.addEventListener('afterprint', () => {
    document.body.classList.remove('printing-onepager');
  });

  // ---------------------------------------------------------------
  // SLACK / TEAMS WEBHOOK ALERTS - sent directly from the browser to the
  // webhook URL you paste in, no server of ours involved. Verified live
  // (not guessed) that Slack's incoming-webhook endpoint sends
  // access-control-allow-origin: * on its responses but does NOT answer
  // a real CORS preflight (no Access-Control-Allow-Methods/-Headers on
  // an OPTIONS request) - so a plain application/json POST would be
  // blocked by the browser before it ever left. The fix is the standard
  // client-side-webhook workaround: POST with Content-Type: text/plain
  // (one of the fetch spec's CORS-"simple" content types, so no
  // preflight is triggered at all) - both Slack and Teams parse the
  // body as JSON regardless of the declared content-type. mode:'no-cors'
  // on top of that means the request still goes out even against a
  // receiver whose CORS story is worse than Slack's, at the cost of an
  // opaque response - fetch can't report whether the webhook actually
  // accepted the payload, only that the browser sent it, so every
  // status message here says "sent", never "delivered" or "succeeded".
  //
  // Auto-notify only fires while this tab is open - Flare has no
  // backend, so there is no way to alert while the page isn't loaded.
  // That limitation is stated up front in the Sources drawer copy, not
  // left for the user to discover the hard way.
  // ---------------------------------------------------------------
  function webhookConfigured() {
    return !!(state.webhookUrl && /^https:\/\//i.test(state.webhookUrl));
  }
  function updateWebhookButtons() {
    const testBtn = document.getElementById('webhook-test-btn');
    const postBtn = document.getElementById('webhook-post-now-btn');
    const ok = webhookConfigured();
    if (testBtn) testBtn.disabled = !ok;
    if (postBtn) postBtn.disabled = !ok || !snapshot || (!relatedFilterKey && state.selected.length === 0);
  }
  function slackPayload(text) {
    return { text: text };
  }
  function teamsPayload(title, text, color) {
    return {
      '@type': 'MessageCard', '@context': 'http://schema.org/extensions',
      summary: title, themeColor: color || '2563EB',
      sections: [{ activityTitle: title, text: text }],
    };
  }
  async function postToWebhook(title, text, color) {
    const payload = state.webhookPlatform === 'teams' ? teamsPayload(title, text, color) : slackPayload(text);
    await fetch(state.webhookUrl, {
      method: 'POST', mode: 'no-cors', headers: { 'Content-Type': 'text/plain' },
      body: JSON.stringify(payload),
    });
  }
  function setWebhookStatus(text) {
    const el = document.getElementById('webhook-status');
    if (el) el.textContent = text;
  }
  async function sendWebhookTest() {
    if (!webhookConfigured()) return;
    setWebhookStatus('Sending…');
    try {
      await postToWebhook('Flare test alert',
        'This is a test alert from Flare (lab.krismccabe.com/flare/). If you can see this, the webhook is wired up correctly.', '2563EB');
      setWebhookStatus('Test alert sent — check your channel to confirm it arrived (the browser can’t confirm delivery for you).');
    } catch (e) {
      setWebhookStatus('Couldn’t send — the request itself failed, check the URL.');
    }
  }
  function webhookSummaryText() {
    const list = dateScopedAdvisories();
    const critical = list.filter(a => a.sev === 'CRITICAL').length;
    const kevCount = list.filter(isKev).length;
    const slaBreachCount = list.filter(isSlaBreached).length;
    const top = list.slice().sort((a, b) => priorityScore(b) - priorityScore(a)).slice(0, 3);
    const flags = [critical ? critical + ' critical' : '', kevCount ? kevCount + ' actively exploited' : '', slaBreachCount ? slaBreachCount + ' past SLA' : ''].filter(Boolean);
    const lines = ['Flare exposure summary — ' + list.length + ' advisor' + (list.length === 1 ? 'y' : 'ies') + ' tracked' + (flags.length ? ' (' + flags.join(', ') + ')' : '') + '.'];
    if (top.length) {
      lines.push('');
      lines.push('Top priorities:');
      top.forEach((adv, i) => {
        const pkgNames = adv.pkgs.map(pkgLabel).join(', ');
        lines.push((i + 1) + '. ' + pkgNames + ' — ' + adv.summary + ' (' + (SEV_LABEL[adv.sev] || 'Unknown') + (isKev(adv) ? ', actively exploited' : '') + ')');
      });
    }
    lines.push('');
    lines.push('View full details: https://lab.krismccabe.com/flare/');
    return lines.join('\n');
  }
  async function sendWebhookSummaryNow() {
    if (!webhookConfigured()) return;
    setWebhookStatus('Sending…');
    try {
      await postToWebhook('Flare exposure summary', webhookSummaryText(), '2563EB');
      setWebhookStatus('Summary sent — check your channel to confirm it arrived.');
    } catch (e) {
      setWebhookStatus('Couldn’t send — the request itself failed, check the URL.');
    }
  }
  // Runs once per page load, right after computeChangeHistory() - only
  // ever looks at what THIS load's diff found, so the same advisory
  // never triggers a repeat notification on a later reload (the history
  // snapshot it's diffed against is overwritten at the end of every load).
  async function maybeAutoNotifyWebhook() {
    if (!state.webhookAutoNotify || !webhookConfigured() || !changeHistoryDiff) return;
    const selectedKeys = new Set(state.selected);
    const urgent = changeHistoryDiff.items.filter(it => {
      const inScope = relatedFilterKey ? it.adv.pkgs.indexOf(relatedFilterKey) !== -1 : it.adv.pkgs.some(k => selectedKeys.has(k));
      if (!inScope) return false;
      return it.kinds.some(k => (k.kind === 'new' && it.adv.sev === 'CRITICAL') || k.kind === 'kev');
    });
    if (!urgent.length) return;
    const lines = ['Flare alert — ' + urgent.length + ' new critical/actively-exploited advisor' + (urgent.length === 1 ? 'y' : 'ies') + ' for your stack:'];
    urgent.slice(0, 5).forEach(it => {
      const pkgNames = it.adv.pkgs.map(pkgLabel).join(', ');
      lines.push('- ' + pkgNames + ' — ' + it.adv.summary);
    });
    lines.push('');
    lines.push('View in Flare: https://lab.krismccabe.com/flare/');
    try { await postToWebhook('Flare alert', lines.join('\n'), 'DC2626'); } catch (e) {}
  }

  // ---------------------------------------------------------------
  // ANONYMOUS PEER BENCHMARKING (opt-in) - same shape and same server as
  // AI-SHIELD's existing "compare anonymously" feature (krismccabe.com/
  // api/, honeypot + timing guard + per-IP rate limit + a minimum-
  // cohort-size gate before reporting a percentile), a separate endpoint
  // and a separate data file. Only ever sends aggregate counts (how many
  // advisories, what share are critical, stack size, which watchlist
  // groups are represented) - never package names, CVE/advisory IDs, or
  // anything else that could identify a specific stack. Computed fresh
  // at click time from dateScopedAdvisories() (same scope the At a
  // Glance stats and executive one-pager use), not from anything
  // pre-rendered - this panel lives in the Sources drawer specifically
  // because that's rebuilt far less often than the exposure list, so a
  // shown result doesn't vanish the next time a filter is clicked.
  // ---------------------------------------------------------------
  const BENCHMARK_ENDPOINT = 'https://krismccabe.com/api/flare-benchmark.php';
  function updateBenchmarkButton() {
    const btn = document.getElementById('benchmark-submit-btn');
    if (!btn) return;
    btn.disabled = !snapshot || (!relatedFilterKey && state.selected.length === 0);
  }
  async function submitBenchmark() {
    const btn = document.getElementById('benchmark-submit-btn');
    const resultEl = document.getElementById('benchmark-result');
    const websiteEl = document.getElementById('benchmark-website');
    if (!btn || !resultEl) return;
    const loadedAt = Date.now();
    const list = dateScopedAdvisories();
    const groupIds = Array.from(new Set(
      selectedPackages().map(p => p.group).filter(Boolean)
    ));
    const payload = {
      loadedAt: loadedAt,
      website: websiteEl ? websiteEl.value : '',
      stackSize: state.selected.length,
      totalAdvisories: list.length,
      criticalCount: list.filter(a => a.sev === 'CRITICAL').length,
      kevCount: list.filter(isKev).length,
      fixAvailableCount: list.filter(hasFix).length,
      slaBreachCount: list.filter(isSlaBreached).length,
      groupIds: groupIds,
    };
    btn.disabled = true;
    btn.textContent = 'Comparing…';
    resultEl.textContent = '';
    try {
      const resp = await fetch(BENCHMARK_ENDPOINT, {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload),
      });
      const data = await resp.json();
      if (data && data.ok && data.percentile !== null && data.percentile !== undefined) {
        resultEl.textContent = 'Your critical-severity share (' + data.criticalSharePct + '%) is lower than ' + data.percentile + '% of ' + data.scope + ' (n=' + data.count + ').';
      } else if (data && data.ok) {
        resultEl.textContent = 'Thanks — recorded. Not enough submissions yet for a meaningful comparison (' + data.count + ' so far). Check back later.';
      } else {
        resultEl.textContent = "Couldn't reach the comparison service right now. Your data is unaffected — try again later.";
      }
    } catch (e) {
      resultEl.textContent = "Couldn't reach the comparison service right now. Your data is unaffected — try again later.";
    } finally {
      btn.disabled = false;
      btn.textContent = 'Compare my stack anonymously';
      updateBenchmarkButton();
    }
  }

  // ---------------------------------------------------------------
  // RENDER: Threat map tab - the FULL watchlist, not the user's
  // selection. "Global" is the point: it's the one view that doesn't
  // change based on what you picked above.
  // ---------------------------------------------------------------
  const SEV_HEX = { CRITICAL: '#DC2626', HIGH: '#B45309', MEDIUM: '#A16207', LOW: '#0F766E', UNKNOWN: '#64748B' };

  function heatmapCounts() {
    const map = mergedAdvisoriesMap();
    const counts = {};
    WATCHLIST.packages.forEach(p => { counts[p.key] = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, UNKNOWN: 0, kev: false }; });
    Object.keys(map).forEach(id => {
      const adv = map[id];
      const kev = isKev(adv);
      adv.pkgs.forEach(k => {
        const c = counts[k];
        if (!c) return; // custom packages (a later feature) aren't part of the global grid
        c[adv.sev] = (c[adv.sev] || 0) + 1;
        if (kev) c.kev = true;
      });
    });
    return counts;
  }

  function riskScore(c) {
    return c.CRITICAL * 8 + c.HIGH * 4 + c.MEDIUM * 2 + c.LOW * 1 + (c.kev ? 100 : 0);
  }

  function heatCellHtml(count, sev) {
    if (!count) return '<td class="heat-cell-empty">&ndash;</td>';
    return '<td class="heat-cell" style="background:' + SEV_HEX[sev] + ';">' + count + '</td>';
  }

  function heatmapRowHtml(pkg, counts) {
    return '<tr class="heatmap-pkg-row" data-related-key="' + escapeHtml(pkg.key) + '" tabindex="0" role="button" aria-label="Show advisories for ' + escapeHtml(pkg.label || pkg.name) + '">' +
      '<td class="heatmap-pkg-name">' + escapeHtml(pkg.label || pkg.name) +
        (counts.kev ? ' <span class="kev-dot" title="Actively exploited - confirmed by CISA\'s Known Exploited Vulnerabilities catalog">&#9679;</span>' : '') +
      '</td>' +
      SEV_ORDER.map(sev => heatCellHtml(counts[sev], sev)).join('') +
    '</tr>';
  }

  // Low-to-Critical left to right - reads as an increasing-danger gradient,
  // not a "most urgent first" ranking (that's SEV_RANK above, used for
  // sorting the exposure list itself, which stays highest-severity-first).
  const SEV_ORDER = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL', 'UNKNOWN'];

  function topOffendersHtml() {
    const top = snapshot && snapshot.summary && snapshot.summary.topPackages ? snapshot.summary.topPackages : [];
    const withCounts = top.filter(t => t.critical || t.high);
    if (!withCounts.length) return '';
    const items = withCounts.map(t =>
      '<button type="button" class="btn small top-offender-btn" data-related-key="' + escapeHtml(t.key) + '">' +
        escapeHtml(pkgLabel(t.key)) + ' &mdash; ' +
        (t.critical ? t.critical + ' critical' : '') + (t.critical && t.high ? ', ' : '') + (t.high ? t.high + ' high' : '') +
      '</button>'
    ).join('');
    return '<div class="top-offenders"><span class="top-offenders-label">Most affected right now:</span> ' + items + '</div>';
  }

  function renderHeatmap() {
    const topEl = document.getElementById('heatmap-top');
    const wrapEl = document.getElementById('heatmap-wrap');
    if (!wrapEl) return;

    if (!snapshot) {
      if (topEl) topEl.innerHTML = '';
      wrapEl.innerHTML = '<div class="empty-state"><p>The advisory snapshot couldn&rsquo;t be loaded.</p></div>';
      return;
    }

    if (topEl) {
      topEl.innerHTML = topOffendersHtml();
      topEl.querySelectorAll('[data-related-key]').forEach(btn => {
        btn.addEventListener('click', () => goToRelated(btn.dataset.relatedKey));
      });
    }

    const counts = heatmapCounts();
    const groupsHtml = WATCHLIST.groups.map(g => {
      const pkgs = WATCHLIST.packages.filter(p => p.group === g.id).slice()
        .sort((a, b) => riskScore(counts[b.key]) - riskScore(counts[a.key]));
      if (!pkgs.length) return '';
      return '<tr class="heatmap-group-row"><td colspan="6">' + escapeHtml(g.name) + '</td></tr>' +
        pkgs.map(p => heatmapRowHtml(p, counts[p.key])).join('');
    }).join('');

    wrapEl.innerHTML =
      '<div class="heatmap-scroll"><table class="heatmap">' +
        '<thead><tr><th>Package</th><th>Low</th><th>Medium</th><th>High</th><th>Critical</th><th>Unknown</th></tr></thead>' +
        '<tbody>' + groupsHtml + '</tbody>' +
      '</table></div>';

    wrapEl.querySelectorAll('.heatmap-pkg-row').forEach(row => {
      const activate = () => goToRelated(row.dataset.relatedKey);
      row.addEventListener('click', activate);
      row.addEventListener('keydown', e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); activate(); } });
    });
  }

  // ---------------------------------------------------------------
  // RENDER: Risk categories tab (Layer A - curated, complete, permanent)
  // ---------------------------------------------------------------
  function shapeTagHtml(shape) {
    if (shape === 'cve') return '<span class="shape-tag cve">Usually a CVE &mdash; patchable</span>';
    return '<span class="shape-tag technique">Usually a design choice &mdash; no patch fixes this</span>';
  }

  // Only ever shown when this specific item has a confident crosswalk (see
  // owasp.json's atlasNote) - most items are deliberately left without one
  // rather than forcing a loose match, so absence here is the honest
  // default, not a gap to fix.
  function atlasBadgeHtml(item) {
    if (!item.atlas || !item.atlas.id) return '';
    return '<a class="atlas-badge" href="' + escapeHtml(item.atlas.url) + '" target="_blank" rel="noopener" ' +
      'title="MITRE ATLAS - Adversarial Threat Landscape for AI Systems">' +
      'ATLAS ' + escapeHtml(item.atlas.id) + '</a>';
  }

  function owaspEntryHtml(item) {
    return '<div class="owasp-entry">' +
      '<div class="oe-head">' +
        '<div><div class="oe-id">' + escapeHtml(item.id) + '</div><h3>' + escapeHtml(item.name) + '</h3></div>' +
        shapeTagHtml(item.shape) +
      '</div>' +
      '<p class="oe-summary">' + escapeHtml(item.summary) + '</p>' +
      '<p class="oe-looks-like"><b>What it looks like:</b> ' + escapeHtml(item.looksLike) + '</p>' +
      '<ul class="oe-mitigations">' +
        item.mitigations.map(m => '<li>' + escapeHtml(m) + '</li>').join('') +
      '</ul>' +
      atlasBadgeHtml(item) +
    '</div>';
  }

  function renderOwaspLayer() {
    const el = document.getElementById('owasp-list');
    if (!el) return;
    el.innerHTML = OWASP.items.map(owaspEntryHtml).join('');
  }

  // ---------------------------------------------------------------
  // RENDER: Sources tab - built-in source toggles + custom feeds
  // ---------------------------------------------------------------
  function fmtFeedDate(raw) {
    if (!raw) return '';
    try {
      const d = new Date(raw);
      if (isNaN(d.getTime())) return raw;
      return d.toLocaleDateString('en-GB', { day: 'numeric', month: 'long', year: 'numeric' });
    } catch (e) { return raw; }
  }

  function renderGhsaStatusText() {
    const el = document.getElementById('ghsa-status');
    if (!el) return;
    if (!state.ghsaEnabled) { el.innerHTML = ''; return; }
    if (ghsaCheckState === 'checking') { el.innerHTML = 'Checking&hellip;'; return; }
    if (ghsaCheckState === 'error') {
      el.innerHTML = 'Some ecosystems couldn&rsquo;t be checked &mdash; GitHub&rsquo;s API may be rate-limited or unreachable right now. ' +
        '<button type="button" class="custom-retry" id="ghsa-retry-btn">Retry</button>';
      return;
    }
    if (ghsaCheckState === 'ok') {
      const count = external ? Object.keys(external.advisories).length : 0;
      el.textContent = count
        ? ('Added ' + count + ' advisor' + (count === 1 ? 'y' : 'ies') + ' not already covered by OSV.dev.')
        : 'Checked — nothing found beyond what OSV.dev already covers.';
      return;
    }
    el.innerHTML = 'Not checked this session. <button type="button" class="custom-retry" id="ghsa-retry-btn">Check now</button>';
  }

  function renderPackageHealthStatusText() {
    const el = document.getElementById('package-health-status');
    if (!el) return;
    if (!state.packageHealthEnabled) { el.innerHTML = ''; return; }
    if (packageHealthCheckState === 'checking') { el.innerHTML = 'Checking&hellip;'; return; }
    if (packageHealthCheckState === 'error') {
      el.innerHTML = 'Some packages couldn&rsquo;t be checked &mdash; the registry may be rate-limited or unreachable right now. ' +
        '<button type="button" class="custom-retry" id="package-health-retry-btn">Retry</button>';
      return;
    }
    if (packageHealthCheckState === 'ok') {
      const checked = Object.keys(packageHealth).filter(k => packageHealth[k].checked && !packageHealth[k].error);
      const flagged = checked.filter(k => packageHealth[k].deprecated || packageHealth[k].stale);
      el.textContent = flagged.length
        ? ('Checked ' + checked.length + ' package' + (checked.length === 1 ? '' : 's') + ' — ' + flagged.length + ' flagged. See the stack picker above.')
        : ('Checked ' + checked.length + ' package' + (checked.length === 1 ? '' : 's') + ' — all actively maintained.');
      return;
    }
    el.innerHTML = 'Not checked this session. <button type="button" class="custom-retry" id="package-health-retry-btn">Check now</button>';
  }

  function renderEpssStatusText() {
    const el = document.getElementById('epss-status');
    if (!el) return;
    if (!state.epssEnabled) { el.innerHTML = ''; return; }
    if (epssCheckState === 'checking') { el.innerHTML = 'Checking&hellip;'; return; }
    if (epssCheckState === 'error') {
      el.innerHTML = 'Couldn&rsquo;t reach FIRST.org just now. ' +
        '<button type="button" class="custom-retry" id="epss-retry-btn">Retry</button>';
      return;
    }
    if (epssCheckState === 'ok') {
      const count = Object.keys(epssScores).length;
      el.textContent = 'Scored ' + count + ' CVE' + (count === 1 ? '' : 's') + ' — checked ' + fmtTime(epssCheckedAt) + '.';
      return;
    }
    el.innerHTML = 'Not checked this session. <button type="button" class="custom-retry" id="epss-retry-btn">Check now</button>';
  }

  function renderKevStatusText() {
    const el = document.getElementById('kev-status');
    if (!el) return;
    if (!state.kevLiveEnabled) {
      el.textContent = 'Off — using the hand-maintained fallback list only (' + KEV.length + ' entries).';
      return;
    }
    if (kevCheckState === 'checking') { el.innerHTML = 'Checking&hellip;'; return; }
    if (kevCheckState === 'error') {
      el.innerHTML = 'Couldn&rsquo;t reach the live catalog just now &mdash; falling back to the hand-maintained list (' + KEV.length + ' entries), nothing missing, nothing broken. ' +
        '<button type="button" class="custom-retry" id="kev-retry-btn">Retry</button>';
      return;
    }
    if (kevCheckState === 'ok') {
      el.innerHTML = 'Live &mdash; ' + kevLiveCount + ' entries fetched from CISA&rsquo;s catalog ' + fmtRelativeTime(kevLiveFetchedAt) + '.';
      return;
    }
    el.innerHTML = 'Not checked this session. <button type="button" class="custom-retry" id="kev-retry-btn">Check now</button>';
  }

  // A composable CVE feed API, scoped with term= to exactly the
  // vendor/product names Flare's own watchlist.json tracks (max 10 terms
  // per their API), cvss_min=7 to match "high-severity" like the rest of
  // the site. Merges NVD, MITRE's CVE List, CISA KEV, and CISA Vulnrichment
  // - verified live, real, current CVEs against these exact packages
  // (mlflow, vllm, huggingface, litellm, etc.), not a generic firehose.
  // Built-in and on by default (unlike a user-added feed) because it's
  // curated specifically for this page, not a general source someone opts
  // into - same rationale as KEV and GHSA above.
  const ASSURESTART_URL = 'https://cve.assurestart.co/api/feed.xml?term=openai,anthropic,langchain,litellm,huggingface,pytorch,mlflow,chromadb,vllm,ollama&cvss_min=7';
  let assurestartCheckState = 'idle'; // 'idle' | 'checking' | 'ok' | 'error' - transient, resets every load
  let assurestartItems = [];
  let assurestartFetchedAt = null;

  async function checkAssurestartFeed() {
    if (!state.assurestartEnabled) return;
    assurestartCheckState = 'checking';
    renderSourcesTab();
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), FETCH_TIMEOUT);
    try {
      const resp = await fetch(ASSURESTART_URL, { signal: ctrl.signal });
      if (!resp.ok) throw new Error('HTTP ' + resp.status);
      const text = await resp.text();
      assurestartItems = parseFeedXml(text);
      assurestartCheckState = 'ok';
      assurestartFetchedAt = new Date().toISOString();
    } catch (e) {
      assurestartCheckState = 'error';
    } finally {
      clearTimeout(timer);
      renderSourcesTab();
    }
  }

  function renderAssurestartStatusText() {
    const el = document.getElementById('assurestart-status');
    if (!el) return;
    if (!state.assurestartEnabled) { el.textContent = 'Off.'; return; }
    if (assurestartCheckState === 'checking') { el.innerHTML = 'Checking&hellip;'; return; }
    if (assurestartCheckState === 'error') {
      el.innerHTML = 'Couldn&rsquo;t reach this feed just now. ' +
        '<button type="button" class="custom-retry" id="assurestart-retry-btn">Retry</button>';
      return;
    }
    if (assurestartCheckState === 'ok') {
      el.innerHTML = 'Live &mdash; ' + assurestartItems.length + ' item' + (assurestartItems.length === 1 ? '' : 's') +
        ' fetched ' + fmtRelativeTime(assurestartFetchedAt) + '.';
      return;
    }
    el.innerHTML = 'Not checked this session. <button type="button" class="custom-retry" id="assurestart-retry-btn">Check now</button>';
  }

  // Every entry here was independently verified before being listed - real
  // HTTP fetch, real content, and a real CORS check (curl -I -H "Origin:
  // https://lab.krismccabe.com", looking for access-control-allow-origin)
  // confirming it'll actually load for most visitors, not just look
  // plausible. Dropped after trying (real source, but no CORS header of its
  // own, so it never loaded and just sat there broken): OWASP Gen AI
  // Security Project, GitHub Security Lab (its own feed intermittently
  // returns zero entries, unrelated to CORS, but removed per a request
  // rather than kept around while empty), CIRCL Vulnerability-Lookup,
  // NCSC UK, cvefeed.io (real and CORS-fine, but a firehose of every CVE
  // for every vendor with no way to scope it to AI - same problem as the
  // per-ecosystem GHSA mirrors evaluated earlier), OpenAI's blog, arXiv,
  // MarkTechPost (blocked by a bot-check), ai-techpark.com (same), and the
  // 432-feed "all infosec news" OPML (too broad and unfiltered to suggest
  // as a unit - the opposite problem from cvefeed.io, same conclusion).
  const SUGGESTED_FEEDS = [
    { name: 'Embrace The Red', url: 'https://embracethered.com/blog/index.xml' },
    // These two are general AI industry/research news, not security-specific
    // - a different category from the rest of this list, included because
    // they were explicitly requested and both check out (real, current,
    // genuinely CORS-enabled, unlike OpenAI's own blog or arXiv).
    { name: 'Google AI Blog', url: 'https://blog.google/innovation-and-ai/technology/ai/rss/' },
    { name: 'NVIDIA Blog', url: 'https://blogs.nvidia.com/feed/' },
  ];
  function suggestedFeedRowHtml() {
    return SUGGESTED_FEEDS
      .filter(f => !state.feeds.some(sf => sf.url === f.url))
      .map(f => '<button type="button" class="suggested-feed-chip" data-suggested-feed="' + escapeHtml(f.url) + '">' +
        '+ Suggested: ' + escapeHtml(f.name) +
      '</button>')
      .join('');
  }

  function feedStatusHtml(f) {
    if (f.status === 'pending') return '<span class="custom-status">Checking&hellip;</span>';
    if (f.status === 'error') {
      return '<span class="custom-status custom-status-error">' + escapeHtml(f.error || 'Couldn&rsquo;t load this feed.') +
        ' <button type="button" class="custom-retry" data-feed-retry="' + escapeHtml(f.id) + '">Retry</button>' +
        ' <button type="button" class="custom-retry" data-feed-remove="' + escapeHtml(f.id) + '">Remove</button></span>';
    }
    if (f.status === 'ok') {
      return '<span class="custom-status custom-status-ok">' + f.items.length + ' item' + (f.items.length === 1 ? '' : 's') +
        ' &mdash; checked ' + fmtTime(f.checkedAt) + '</span>';
    }
    return '<span class="custom-status">Not checked this session ' +
      '<button type="button" class="custom-retry" data-feed-retry="' + escapeHtml(f.id) + '">Check now</button></span>';
  }

  function feedRowHtml(f) {
    return '<div class="feed-row">' +
      '<div class="feed-row-main">' +
        '<span class="feed-row-name">' + escapeHtml(f.name || f.url) + '</span>' +
        (f.name ? '<span class="feed-row-url">' + escapeHtml(f.url) + '</span>' : '') +
        feedStatusHtml(f) +
      '</div>' +
      '<button type="button" class="custom-remove" data-feed-remove="' + escapeHtml(f.id) + '" aria-label="Remove ' + escapeHtml(f.name || f.url) + '">&times;</button>' +
    '</div>';
  }

  // Feed items carry no severity/CVSS - a malicious or careless feed is
  // just untrusted third-party text, so titles are escaped and a link is
  // only ever rendered as a clickable <a> when it's actually http(s).
  function feedItemHtml(feedLabel, item) {
    const title = escapeHtml(item.title || '(untitled)');
    const linkOk = /^https?:\/\//i.test(String(item.link || ''));
    const titleHtml = linkOk
      ? '<a href="' + escapeHtml(item.link) + '" target="_blank" rel="noopener">' + title + '</a>'
      : '<span>' + title + '</span>';
    const dateStr = fmtFeedDate(item.pubDate);
    return '<div class="feed-item">' + titleHtml +
      '<div class="feed-item-meta">' + escapeHtml(feedLabel) + (dateStr ? ' &middot; ' + escapeHtml(dateStr) : '') + '</div>' +
    '</div>';
  }

  function renderFeedItemsWrap(feeds) {
    const okFeeds = feeds.filter(f => f.status === 'ok' && f.items.length);
    if (!okFeeds.length) return '';
    const rows = [];
    okFeeds.forEach(f => f.items.forEach(item => rows.push(feedItemHtml(f.name || f.url, item))));
    return '<h3 class="sources-section-heading">From your feeds</h3><div class="feed-items-grid">' + rows.join('') + '</div>';
  }

  function renderSourcesTab() {
    const kevToggle = document.getElementById('kev-toggle');
    if (kevToggle) kevToggle.checked = state.kevLiveEnabled;
    renderKevStatusText();
    const kevRetryBtn = document.getElementById('kev-retry-btn');
    if (kevRetryBtn) kevRetryBtn.addEventListener('click', checkKevLive);

    const ghsaToggle = document.getElementById('ghsa-toggle');
    if (ghsaToggle) ghsaToggle.checked = state.ghsaEnabled;
    renderGhsaStatusText();
    const ghsaRetryBtn = document.getElementById('ghsa-retry-btn');
    if (ghsaRetryBtn) ghsaRetryBtn.addEventListener('click', checkGhsaSources);

    const assurestartToggle = document.getElementById('assurestart-toggle');
    if (assurestartToggle) assurestartToggle.checked = state.assurestartEnabled;
    renderAssurestartStatusText();
    const assurestartRetryBtn = document.getElementById('assurestart-retry-btn');
    if (assurestartRetryBtn) assurestartRetryBtn.addEventListener('click', checkAssurestartFeed);

    const packageHealthToggle = document.getElementById('package-health-toggle');
    if (packageHealthToggle) packageHealthToggle.checked = state.packageHealthEnabled;
    renderPackageHealthStatusText();
    const packageHealthRetryBtn = document.getElementById('package-health-retry-btn');
    if (packageHealthRetryBtn) packageHealthRetryBtn.addEventListener('click', checkPackageHealth);

    const epssToggle = document.getElementById('epss-toggle');
    if (epssToggle) epssToggle.checked = state.epssEnabled;
    renderEpssStatusText();
    const epssRetryBtn = document.getElementById('epss-retry-btn');
    if (epssRetryBtn) epssRetryBtn.addEventListener('click', checkEpss);

    const webhookPlatformEl = document.getElementById('webhook-platform');
    if (webhookPlatformEl) webhookPlatformEl.value = state.webhookPlatform;
    const webhookUrlEl = document.getElementById('webhook-url-input');
    if (webhookUrlEl && document.activeElement !== webhookUrlEl) webhookUrlEl.value = state.webhookUrl;
    const webhookAutoEl = document.getElementById('webhook-auto-toggle');
    if (webhookAutoEl) webhookAutoEl.checked = state.webhookAutoNotify;
    updateWebhookButtons();
    updateBenchmarkButton();

    // Built-in source rows are static HTML, not templated - toggle
    // [hidden] directly rather than re-rendering them.
    document.querySelectorAll('#sources-drawer .source-row').forEach(row => {
      const name = row.querySelector('.source-row-name')?.textContent || '';
      row.hidden = !matchesSearch(name, sourcesSearchQuery);
    });

    const suggestedEl = document.getElementById('suggested-feed-wrap');
    if (suggestedEl) {
      suggestedEl.innerHTML = suggestedFeedRowHtml();
      suggestedEl.querySelectorAll('[data-suggested-feed]').forEach(btn => {
        btn.addEventListener('click', () => addSuggestedFeed(btn.dataset.suggestedFeed));
      });
    }

    const filteredFeeds = state.feeds.filter(f => matchesSearch(f.name || f.url, sourcesSearchQuery));
    const listEl = document.getElementById('feed-list');
    if (listEl) {
      listEl.innerHTML = filteredFeeds.length
        ? filteredFeeds.map(feedRowHtml).join('')
        : (state.feeds.length && sourcesSearchQuery ? '<p class="drawer-search-empty">No feeds match &ldquo;' + escapeHtml(sourcesSearchQuery) + '&rdquo;.</p>' : '');
      listEl.querySelectorAll('[data-feed-remove]').forEach(btn => {
        btn.addEventListener('click', () => removeFeed(btn.dataset.feedRemove));
      });
      listEl.querySelectorAll('[data-feed-retry]').forEach(btn => {
        btn.addEventListener('click', () => fetchFeed(btn.dataset.feedRetry));
      });
    }
    const itemsEl = document.getElementById('feed-items-wrap');
    if (itemsEl) {
      // Built-in feed's items join the same "From your feeds" grid as any
      // user-added one - it's still just a feed (title/link/date), not a
      // ranked advisory card, so it belongs in that list either way.
      const builtinAsFeed = state.assurestartEnabled && assurestartCheckState === 'ok' && assurestartItems.length
        ? [{ name: 'AI Stack CVEs (assurestart.co)', status: 'ok', items: assurestartItems }]
        : [];
      itemsEl.innerHTML = renderFeedItemsWrap(builtinAsFeed.concat(filteredFeeds));
    }
  }

  // Pre-fills the add-feed form then submits it through the exact same
  // addFeed() path as typing the URL in by hand - no separate add mechanism
  // to keep in sync with validation/dedup/cap rules.
  function addSuggestedFeed(url) {
    const feed = SUGGESTED_FEEDS.find(f => f.url === url);
    if (!feed) return;
    const nameInput = document.getElementById('feed-name-input');
    const urlInput = document.getElementById('feed-url-input');
    const errorEl = document.getElementById('feed-add-error');
    const result = addFeed(feed.name, feed.url);
    if (errorEl) errorEl.textContent = result.error || '';
    if (!result.error) { if (nameInput) nameInput.value = ''; if (urlInput) urlInput.value = ''; }
  }

  // ---------------------------------------------------------------
  // TABS
  // ---------------------------------------------------------------
  function switchTab(name) {
    const btn = document.querySelector('.tab-btn[data-tab="' + name + '"]');
    if (btn) btn.click();
  }

  // Only real tabs (with a data-tab target) toggle .tab-panel visibility -
  // the Sources button looks like a tab but opens a drawer instead, wired
  // separately below.
  document.querySelectorAll('.tab-btn[data-tab]').forEach(btn => {
    btn.addEventListener('click', () => {
      if (btn.disabled) return;
      document.querySelectorAll('.tab-btn[data-tab]').forEach(b => b.classList.remove('active'));
      document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
      btn.classList.add('active');
      document.getElementById('tab-' + btn.dataset.tab).classList.add('active');
      window.scrollTo({ top: document.querySelector('.tabs').offsetTop - 20, behavior: 'smooth' });
    });
  });

  // Inline cross-tab links (e.g. "see what's wrong with them under Alerts
  // Live Stream" on the exposure summary) reuse the same tab-switch path.
  document.querySelectorAll('[data-goto-tab]').forEach(btn => {
    btn.addEventListener('click', () => switchTab(btn.dataset.gotoTab));
  });

  // ---------------------------------------------------------------
  // DRAWERS - the package picker and Sources both slide in over the page
  // instead of sitting inline, so editing either is a deliberate action
  // rather than something that eats screen space on every visit. Returns
  // open/close functions bound to one drawer/overlay/trigger triple, so
  // both instances share the same logic instead of being copy-pasted.
  // ---------------------------------------------------------------
  // A dialog (drawer or the card modal) being open must make everything
  // else on the page - including a DIFFERENT, closed drawer's own
  // controls, which stay in the DOM and were still Tab-reachable despite
  // aria-hidden - unreachable by keyboard, not just visually covered by
  // the overlay. inert covers both: drops the subtree out of the tab
  // order and hides it from assistive tech in one step. Reference-counted
  // rather than a plain boolean so the background only comes back once
  // every open dialog has actually closed.
  let openOverlayCount = 0;
  function setBackgroundInert(inertState) {
    ['.skip-link', '.lab-header', '.hero', '.console-chrome', '.wrap', 'footer'].forEach(sel => {
      const el = document.querySelector(sel);
      if (el) el.inert = inertState;
    });
  }
  function overlayOpened() {
    openOverlayCount++;
    document.body.classList.add('drawer-open');
    setBackgroundInert(true);
  }
  function overlayClosed() {
    openOverlayCount = Math.max(0, openOverlayCount - 1);
    if (openOverlayCount === 0) {
      document.body.classList.remove('drawer-open');
      setBackgroundInert(false);
    }
  }

  function initDrawer(drawerId, overlayId, openBtnId, closeBtnId) {
    const drawer = document.getElementById(drawerId);
    const overlay = document.getElementById(overlayId);
    const openBtn = document.getElementById(openBtnId);
    const closeBtn = document.getElementById(closeBtnId);

    function open() {
      if (!drawer) return;
      drawer.classList.add('open');
      if (overlay) overlay.classList.add('open');
      drawer.setAttribute('aria-hidden', 'false');
      drawer.inert = false;
      overlayOpened();
      // Deferred a tick - see openCardModal for why a synchronous
      // .focus() here loses to the click's own native post-listener
      // focus behavior targeting openBtn (now inert).
      setTimeout(() => { if (closeBtn) closeBtn.focus(); }, 0);
    }
    function close() {
      if (!drawer || !drawer.classList.contains('open')) return;
      drawer.classList.remove('open');
      if (overlay) overlay.classList.remove('open');
      drawer.setAttribute('aria-hidden', 'true');
      drawer.inert = true;
      overlayClosed();
      if (openBtn) openBtn.focus();
    }
    if (openBtn) openBtn.addEventListener('click', open);
    if (closeBtn) closeBtn.addEventListener('click', close);
    if (overlay) overlay.addEventListener('click', close);
    return { drawer, open, close };
  }

  const sourcesDrawerCtl = initDrawer('sources-drawer', 'sources-drawer-overlay', 'open-sources-drawer-btn', 'sources-drawer-close');
  const filtersDrawerCtl = initDrawer('filters-drawer', 'filters-drawer-overlay', 'open-filters-drawer-btn', 'filters-drawer-close');

  function currentDialogEl() {
    if (sourcesDrawerCtl.drawer && sourcesDrawerCtl.drawer.classList.contains('open')) return sourcesDrawerCtl.drawer;
    if (filtersDrawerCtl.drawer && filtersDrawerCtl.drawer.classList.contains('open')) return filtersDrawerCtl.drawer;
    if (openModalId) return document.getElementById('card-modal');
    return null;
  }

  document.addEventListener('keydown', e => {
    if (e.key === 'Escape') {
      if (sourcesDrawerCtl.drawer && sourcesDrawerCtl.drawer.classList.contains('open')) sourcesDrawerCtl.close();
      if (filtersDrawerCtl.drawer && filtersDrawerCtl.drawer.classList.contains('open')) filtersDrawerCtl.close();
      if (openModalId) closeCardModal();
      return;
    }
    // Focus trap: inert already keeps everything outside the open dialog
    // unreachable, but the browser's native Tab order still has no
    // concept of "wrap at the dialog's edges" - past the last focusable
    // element it falls through to <body> and dead-ends there instead of
    // cycling back to the first. This is that wraparound.
    if (e.key !== 'Tab') return;
    const dialog = currentDialogEl();
    if (!dialog) return;
    const focusable = Array.from(dialog.querySelectorAll(
      'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])'
    )).filter(el => el.offsetParent !== null);
    if (!focusable.length) return;
    const first = focusable[0];
    const last = focusable[focusable.length - 1];
    if (e.shiftKey && document.activeElement === first) {
      e.preventDefault();
      last.focus();
    } else if (!e.shiftKey && (document.activeElement === last || !dialog.contains(document.activeElement))) {
      e.preventDefault();
      first.focus();
    }
  });

  // ---------------------------------------------------------------
  // INIT
  // ---------------------------------------------------------------
  const refreshBtn = document.getElementById('refresh-btn');
  if (refreshBtn) refreshBtn.addEventListener('click', () => { checkForNewAdvisories(); });

  const digestBtn = document.getElementById('digest-btn');
  if (digestBtn) digestBtn.addEventListener('click', openDigest);
  const sarifBtn = document.getElementById('sarif-btn');
  if (sarifBtn) sarifBtn.addEventListener('click', exportSarif);
  const csvBtn = document.getElementById('csv-btn');
  if (csvBtn) csvBtn.addEventListener('click', exportCsvRegister);
  const execOnePagerBtn = document.getElementById('exec-onepager-btn');
  if (execOnePagerBtn) execOnePagerBtn.addEventListener('click', printExecOnePager);
  const shareViewBtn = document.getElementById('share-view-btn');
  if (shareViewBtn) shareViewBtn.addEventListener('click', copyShareLink);

  const teamDashboardToggleBtn = document.getElementById('team-dashboard-toggle-btn');
  const teamDashboardPanel = document.getElementById('team-dashboard-panel');
  if (teamDashboardToggleBtn && teamDashboardPanel) teamDashboardToggleBtn.addEventListener('click', () => {
    const opening = teamDashboardPanel.hidden;
    teamDashboardPanel.hidden = !opening;
    teamDashboardToggleBtn.setAttribute('aria-expanded', opening ? 'true' : 'false');
  });
  const teamDashboardCloseBtn = document.getElementById('team-dashboard-close-btn');
  if (teamDashboardCloseBtn && teamDashboardPanel) teamDashboardCloseBtn.addEventListener('click', () => {
    teamDashboardPanel.hidden = true;
    if (teamDashboardToggleBtn) teamDashboardToggleBtn.setAttribute('aria-expanded', 'false');
  });
  const teamCreateBtn = document.getElementById('team-create-btn');
  if (teamCreateBtn) teamCreateBtn.addEventListener('click', createTeam);
  const teamLinkCopyBtn = document.getElementById('team-link-copy-btn');
  if (teamLinkCopyBtn) teamLinkCopyBtn.addEventListener('click', copyTeamLink);
  const teamRegenerateBtn = document.getElementById('team-regenerate-btn');
  if (teamRegenerateBtn) teamRegenerateBtn.addEventListener('click', regenerateTeamLink);
  const teamLeaveBtn = document.getElementById('team-leave-btn');
  if (teamLeaveBtn) teamLeaveBtn.addEventListener('click', leaveTeamMode);
  const closeDigestBtn = document.getElementById('close-digest-btn');
  if (closeDigestBtn) closeDigestBtn.addEventListener('click', () => {
    const panel = document.getElementById('digest-panel');
    if (panel) panel.hidden = true;
  });

  const diagnosticsDismissBtn = document.getElementById('diagnostics-dismiss');
  if (diagnosticsDismissBtn) diagnosticsDismissBtn.addEventListener('click', hideDiagnostics);

  const shieldSuggestionDismissBtn = document.getElementById('shield-suggestion-dismiss');
  if (shieldSuggestionDismissBtn) shieldSuggestionDismissBtn.addEventListener('click', () => renderShieldSuggestionNote(false));

  // "Fix available" and "No fix available" (likewise for workaround) are
  // opposite states - checking one clears the other rather than letting
  // both apply at once and silently zero out the list.
  const filterFixEl = document.getElementById('filter-has-fix');
  const filterNoFixEl = document.getElementById('filter-no-fix');
  if (filterFixEl) filterFixEl.addEventListener('change', e => {
    filterHasFix = e.target.checked;
    if (filterHasFix && filterNoFixEl) { filterNoFixEl.checked = false; filterNoFix = false; }
    shownCount = INITIAL_CARDS;
    renderExposureList();
  });
  if (filterNoFixEl) filterNoFixEl.addEventListener('change', e => {
    filterNoFix = e.target.checked;
    if (filterNoFix && filterFixEl) { filterFixEl.checked = false; filterHasFix = false; }
    shownCount = INITIAL_CARDS;
    renderExposureList();
  });
  const filterDateEl = document.getElementById('filter-date-range');
  if (filterDateEl) filterDateEl.addEventListener('change', e => {
    filterDateRange = e.target.value;
    shownCount = INITIAL_CARDS;
    renderExposureList();
  });
  const filterDateBasisEl = document.getElementById('filter-date-basis');
  if (filterDateBasisEl) filterDateBasisEl.addEventListener('change', e => {
    filterDateBasis = e.target.value;
    shownCount = INITIAL_CARDS;
    renderExposureList();
  });
  const alertsSearchInput = document.getElementById('alerts-search-input');
  if (alertsSearchInput) alertsSearchInput.addEventListener('input', e => {
    alertsSearchQuery = e.target.value;
    shownCount = INITIAL_CARDS;
    renderExposureList();
  });
  // Delegated on the container (not the tiles - those are rebuilt on
  // every renderExposureStats() call) so it keeps working across re-renders
  // without needing to be rewired each time.
  const exposureStatsEl = document.getElementById('exposure-stats');
  if (exposureStatsEl) exposureStatsEl.addEventListener('click', e => {
    const btn = e.target.closest('[data-stat-filter]');
    if (btn) toggleStatFilter(btn.dataset.statFilter);
  });
  const cardModalOverlay = document.getElementById('card-modal-overlay');
  if (cardModalOverlay) cardModalOverlay.addEventListener('click', closeCardModal);
  const cardModalCloseBtn = document.getElementById('card-modal-close');
  if (cardModalCloseBtn) cardModalCloseBtn.addEventListener('click', closeCardModal);
  const filterWorkaroundEl = document.getElementById('filter-has-workaround');
  const filterNoWorkaroundEl = document.getElementById('filter-no-workaround');
  if (filterWorkaroundEl) filterWorkaroundEl.addEventListener('change', e => {
    filterHasWorkaround = e.target.checked;
    if (filterHasWorkaround && filterNoWorkaroundEl) { filterNoWorkaroundEl.checked = false; filterNoWorkaround = false; }
    shownCount = INITIAL_CARDS;
    renderExposureList();
  });
  if (filterNoWorkaroundEl) filterNoWorkaroundEl.addEventListener('change', e => {
    filterNoWorkaround = e.target.checked;
    if (filterNoWorkaround && filterWorkaroundEl) { filterWorkaroundEl.checked = false; filterHasWorkaround = false; }
    shownCount = INITIAL_CARDS;
    renderExposureList();
  });
  const filterWatchedEl = document.getElementById('filter-watched-only');
  if (filterWatchedEl) filterWatchedEl.addEventListener('change', e => {
    filterWatchedOnly = e.target.checked;
    shownCount = INITIAL_CARDS;
    renderExposureList();
  });
  const filterSlaBreachEl = document.getElementById('filter-sla-breach');
  if (filterSlaBreachEl) filterSlaBreachEl.addEventListener('change', e => {
    filterSlaBreachOnly = e.target.checked;
    shownCount = INITIAL_CARDS;
    renderExposureList();
  });

  // SLA target inputs - populate from the loaded/default values, then
  // persist + re-render (badges, stat tile, Top priorities ranking all
  // depend on these) on every change. Values are clamped rather than
  // rejected outright so a stray keystroke can't leave the field in a
  // state that silently breaks scoring (e.g. a negative or NaN target).
  Object.keys(DEFAULT_SLA_TARGETS).forEach(sev => {
    const input = document.getElementById('sla-target-' + sev.toLowerCase());
    if (!input) return;
    input.value = String(slaTargets[sev]);
    input.addEventListener('change', e => {
      let v = Math.round(Number(e.target.value));
      if (!Number.isFinite(v) || v < 0) v = 0;
      if (v > 365) v = 365;
      slaTargets[sev] = v;
      e.target.value = String(v);
      saveSlaTargets();
      renderExposureList();
    });
  });
  const slaResetBtn = document.getElementById('sla-target-reset');
  if (slaResetBtn) slaResetBtn.addEventListener('click', () => {
    slaTargets = Object.assign({}, DEFAULT_SLA_TARGETS);
    saveSlaTargets();
    Object.keys(DEFAULT_SLA_TARGETS).forEach(sev => {
      const input = document.getElementById('sla-target-' + sev.toLowerCase());
      if (input) input.value = String(slaTargets[sev]);
    });
    renderExposureList();
  });

  const customForm = document.getElementById('custom-add-form');
  if (customForm) {
    customForm.addEventListener('submit', e => {
      e.preventDefault();
      const nameInput = document.getElementById('custom-name-input');
      const ecoSelect = document.getElementById('custom-eco-select');
      const errorEl = document.getElementById('custom-add-error');
      const result = addCustomPackage(nameInput.value, ecoSelect.value);
      errorEl.textContent = result.error || '';
      if (!result.error) nameInput.value = '';
    });
  }

  const sbomFileInput = document.getElementById('sbom-file-input');
  if (sbomFileInput) sbomFileInput.addEventListener('change', () => {
    const file = sbomFileInput.files && sbomFileInput.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => { runSbomImport(file.name, String(reader.result || '')); sbomFileInput.value = ''; };
    reader.onerror = () => {
      const resultEl = document.getElementById('sbom-import-result');
      if (resultEl) resultEl.textContent = "Couldn't read that file.";
      sbomFileInput.value = '';
    };
    reader.readAsText(file);
  });
  const sbomPasteToggle = document.getElementById('sbom-paste-toggle');
  const sbomPasteArea = document.getElementById('sbom-paste-area');
  if (sbomPasteToggle && sbomPasteArea) sbomPasteToggle.addEventListener('click', () => {
    const opening = sbomPasteArea.hidden;
    sbomPasteArea.hidden = !opening;
    sbomPasteToggle.setAttribute('aria-expanded', String(opening));
    if (opening) document.getElementById('sbom-paste-input').focus();
  });
  const sbomPasteSubmit = document.getElementById('sbom-paste-submit');
  if (sbomPasteSubmit) sbomPasteSubmit.addEventListener('click', () => {
    const textarea = document.getElementById('sbom-paste-input');
    if (!textarea || !textarea.value.trim()) return;
    runSbomImport('pasted.txt', textarea.value);
    textarea.value = '';
  });

  const kevToggleEl = document.getElementById('kev-toggle');
  if (kevToggleEl) kevToggleEl.addEventListener('change', e => {
    state.kevLiveEnabled = e.target.checked;
    persistIfEnabled();
    if (state.kevLiveEnabled) {
      checkKevLive();
    } else {
      kevCheckState = 'idle';
      kevEffectiveSet = KEV_SET; // falls back to the hand-maintained baseline, not an empty set
      renderSourcesTab();
      shownCount = INITIAL_CARDS;
      renderExposureList();
      renderHeatmap();
    }
  });

  const ghsaToggleEl = document.getElementById('ghsa-toggle');
  if (ghsaToggleEl) ghsaToggleEl.addEventListener('change', e => {
    state.ghsaEnabled = e.target.checked;
    persistIfEnabled();
    if (state.ghsaEnabled) {
      checkGhsaSources();
    } else {
      external = null;
      ghsaCheckState = 'idle';
      renderSourcesTab();
      shownCount = INITIAL_CARDS;
      renderExposureList();
      renderHeatmap();
    }
  });

  const assurestartToggleEl = document.getElementById('assurestart-toggle');
  if (assurestartToggleEl) assurestartToggleEl.addEventListener('change', e => {
    state.assurestartEnabled = e.target.checked;
    persistIfEnabled();
    if (state.assurestartEnabled) {
      checkAssurestartFeed();
    } else {
      assurestartCheckState = 'idle';
      assurestartItems = [];
      renderSourcesTab();
    }
  });

  const packageHealthToggleEl = document.getElementById('package-health-toggle');
  if (packageHealthToggleEl) packageHealthToggleEl.addEventListener('change', e => {
    state.packageHealthEnabled = e.target.checked;
    persistIfEnabled();
    if (state.packageHealthEnabled) {
      checkPackageHealth();
    } else {
      packageHealth = {};
      packageHealthCheckState = 'idle';
      renderSourcesTab();
      renderStackSelector();
    }
  });

  const epssToggleEl = document.getElementById('epss-toggle');
  if (epssToggleEl) epssToggleEl.addEventListener('change', e => {
    state.epssEnabled = e.target.checked;
    persistIfEnabled();
    if (state.epssEnabled) {
      checkEpss();
    } else {
      epssScores = {};
      epssCheckState = 'idle';
      renderSourcesTab();
      shownCount = INITIAL_CARDS;
      renderExposureList();
    }
  });

  const webhookPlatformEl = document.getElementById('webhook-platform');
  if (webhookPlatformEl) webhookPlatformEl.addEventListener('change', e => {
    state.webhookPlatform = e.target.value === 'teams' ? 'teams' : 'slack';
    persistIfEnabled();
  });
  const webhookUrlInputEl = document.getElementById('webhook-url-input');
  if (webhookUrlInputEl) webhookUrlInputEl.addEventListener('input', e => {
    state.webhookUrl = e.target.value.trim().slice(0, 500);
    persistIfEnabled();
    updateWebhookButtons();
    setWebhookStatus('');
  });
  const webhookAutoToggleEl = document.getElementById('webhook-auto-toggle');
  if (webhookAutoToggleEl) webhookAutoToggleEl.addEventListener('change', e => {
    state.webhookAutoNotify = e.target.checked;
    persistIfEnabled();
  });
  const webhookTestBtn = document.getElementById('webhook-test-btn');
  if (webhookTestBtn) webhookTestBtn.addEventListener('click', sendWebhookTest);
  const webhookPostNowBtn = document.getElementById('webhook-post-now-btn');
  if (webhookPostNowBtn) webhookPostNowBtn.addEventListener('click', sendWebhookSummaryNow);
  const benchmarkSubmitBtn = document.getElementById('benchmark-submit-btn');
  if (benchmarkSubmitBtn) benchmarkSubmitBtn.addEventListener('click', submitBenchmark);

  const feedAddForm = document.getElementById('feed-add-form');
  if (feedAddForm) {
    feedAddForm.addEventListener('submit', e => {
      e.preventDefault();
      const nameInput = document.getElementById('feed-name-input');
      const urlInput = document.getElementById('feed-url-input');
      const errorEl = document.getElementById('feed-add-error');
      const result = addFeed(nameInput.value, urlInput.value);
      if (errorEl) errorEl.textContent = result.error || '';
      if (!result.error) { nameInput.value = ''; urlInput.value = ''; }
    });
  }

  const stackSearchInput = document.getElementById('stack-search-input');
  if (stackSearchInput) stackSearchInput.addEventListener('input', e => {
    stackSearchQuery = e.target.value;
    renderStackSelector();
  });
  const sourcesSearchInput = document.getElementById('sources-search-input');
  if (sourcesSearchInput) sourcesSearchInput.addEventListener('input', e => {
    sourcesSearchQuery = e.target.value;
    renderSourcesTab();
  });

  loadPersisted();
  const teamTokenFromLink = teamTokenFromUrl();
  const sharedViewApplied = teamTokenFromLink ? false : applySharedViewFromUrl();
  // A team link takes priority over both the personal saved stack and the
  // AI-SHIELD suggestion - joinTeamFromUrl() is async, so its own success
  // handler (enterTeamMode) does the actual state.selected overwrite and
  // re-render once the fetch resolves; treating the mere presence of a
  // well-formed token as "applied" here just prevents the shield
  // suggestion from racing it and clobbering the team's list first.
  if (teamTokenFromLink) joinTeamFromUrl(teamTokenFromLink);
  const shieldSuggestionApplied = (sharedViewApplied || teamTokenFromLink) ? false : maybeSuggestStackFromShield();
  if (shieldSuggestionApplied) persistIfEnabled();
  renderShieldSuggestionNote(shieldSuggestionApplied);
  // No drawer to open anymore - the stack picker (and this note) lives
  // directly on "Your exposure", already the default active tab.
  renderStackSelector();
  renderExposureList();
  renderOwaspLayer();
  renderSourcesTab();
  // EPSS scoring needs baseAdvisories() to have real data to score against
  // (it reads from `snapshot`), so it's chained onto loadSnapshot()
  // resolving rather than fired alongside the other opt-in checks below.
  loadSnapshot().then(() => { if (state.epssEnabled) checkEpss(); });
  if (state.kevLiveEnabled) checkKevLive();
  // GHSA had no equivalent of this line - if it was left enabled from a
  // previous session, reloading the page left the toggle checked but
  // fetched nothing until you manually retoggled it or hit "Check now".
  // Every built-in source now checks itself automatically on load, same as
  // OSV.dev (via loadSnapshot -> checkForNewAdvisories) and KEV already did.
  if (state.ghsaEnabled) checkGhsaSources();
  if (state.assurestartEnabled) checkAssurestartFeed();
  if (state.packageHealthEnabled) checkPackageHealth();
  // Same gap, same fix, for custom feeds: normalizeStack() resets every
  // persisted feed to status:'stale', items:[] on load (so a stale result
  // never presents as fresh) but nothing then re-fetched them - a feed
  // added last session just sat there unchecked until you manually hit
  // Retry. Every feed you've added now checks itself on load too.
  state.feeds.forEach(f => fetchFeed(f.id));

  // Keep "Last synced Xm ago" honest without another network call.
  setInterval(() => { if (snapshot) renderProvenance(); }, 30000);

  // Same check the "Check for newer advisories" button makes, just timed -
  // checkForNewAdvisories() already no-ops if one's in flight or nothing's
  // selected, so this only ever adds a request when there's actually
  // something to look for. Paused while the tab isn't visible so a
  // backgrounded tab doesn't keep polling OSV.dev for nothing.
  setInterval(() => {
    if (document.visibilityState === 'visible' && snapshot && state.selected.length > 0) checkForNewAdvisories();
  }, 5 * 60 * 1000);

  // The on-screen list is paginated (Show more) for browsing, but a
  // printed/PDF'd copy is a one-shot report - silently cutting it off at
  // whatever page you happened to be on would drop real advisories from
  // it. Expand to the full filtered list for the print itself, then put
  // pagination back the way it was once the print dialog closes (fires
  // whether the user actually printed or cancelled, so this never gets
  // stuck expanded).
  window.addEventListener('beforeprint', () => {
    printPrevShownCount = shownCount;
    shownCount = Infinity;
    renderExposureList();
  });
  window.addEventListener('afterprint', () => {
    if (printPrevShownCount === null) return;
    shownCount = printPrevShownCount;
    printPrevShownCount = null;
    renderExposureList();
  });

  // ---------------------------------------------------------------
  // HERO BACKGROUND: a dot-matrix world map with occasional "advisory
  // detected" pulses drifting across it - decoration themed around what
  // the tool actually does, not generic hero motion.
  // ---------------------------------------------------------------
  function initHeroMap() {
  const canvas = document.getElementById('hero-map');
  if (!canvas || !canvas.getContext) return;
  if (window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches) return;

  // A deliberately coarse land/ocean grid (60 cols x 24 rows,
  // equirectangular) - hand-drawn to read as "world map" at a glance from
  // a normal viewing distance, not a surveyed one. Each row lists
  // [startCol, endCol) land bands; anything not listed is ocean.
  const COLS = 60, ROWS = 24;
  const LAND_BANDS = [
    [],
    [[34, 38]],
    [[33, 39], [10, 20], [46, 58]],
    [[2, 8], [6, 24], [32, 40], [38, 44], [44, 59]],
    [[4, 26], [34, 40], [36, 46], [46, 59]],
    [[4, 28], [34, 48], [48, 59]],
    [[6, 28], [32, 48], [48, 59]],
    [[6, 28], [30, 46], [46, 54], [54, 59]],
    [[8, 26], [28, 46], [46, 52], [52, 59]],
    [[10, 22], [26, 48], [46, 52], [52, 59]],
    [[14, 20], [26, 48], [46, 50], [50, 58]],
    [[16, 20], [28, 46], [50, 58], [56, 59]],
    [[18, 20], [26, 44], [44, 50], [50, 56], [56, 59]],
    [[18, 28], [32, 46], [54, 59]],
    [[18, 30], [32, 46], [54, 59]],
    [[18, 32], [32, 48], [54, 59]],
    [[18, 30], [34, 48], [52, 59]],
    [[18, 28], [34, 46], [50, 59]],
    [[18, 26], [34, 44], [48, 59]],
    [[18, 24], [34, 42], [48, 58]],
    [[18, 24], [48, 56]],
    [[18, 23], [58, 59]],
    [[18, 22]],
    [[18, 21]],
  ];
  const dots = [];
  LAND_BANDS.forEach((bands, row) => {
    bands.forEach(([from, to]) => {
      for (let col = from; col < to; col++) dots.push({ col, row });
    });
  });

  const ctx = canvas.getContext('2d');
  const hero = canvas.closest('.hero');
  const DPR = Math.min(window.devicePixelRatio || 1, 2);
  let width = 0, height = 0;
  let mapDots = [];

  // Margins keep the map inset from the hero's edges rather than
  // touching every side - reads as "a map placed on the background",
  // not a texture cut off by the container.
  function resize() {
    width = hero.offsetWidth;
    height = hero.offsetHeight;
    canvas.width = width * DPR;
    canvas.height = height * DPR;
    canvas.style.width = width + 'px';
    canvas.style.height = height + 'px';
    ctx.setTransform(DPR, 0, 0, DPR, 0, 0);
    const marginX = width * 0.06, marginY = height * 0.1;
    const spanX = width - marginX * 2, spanY = height - marginY * 2;
    mapDots = dots.map(d => ({
      x: marginX + (d.col / COLS) * spanX,
      y: marginY + (d.row / ROWS) * spanY,
    }));
  }

  // Randomly generated, decorative-only advisory-style codes - not real
  // CVEs/GHSAs, just the same visual pattern the rest of the app uses for
  // IDs, so a pulse reads as "something was found" at a glance.
  function randomCode() {
    const year = 2024 + Math.floor(Math.random() * 3);
    if (Math.random() < 0.5) {
      const num = 1000 + Math.floor(Math.random() * 89000);
      return 'CVE-' + year + '-' + num;
    }
    const hex = () => Math.floor(Math.random() * 0xffff).toString(16).padStart(4, '0');
    return 'GHSA-' + hex() + '-' + hex();
  }

  const MAX_PULSES = 3;
  const PULSE_LIFETIME = 2600;
  let pulses = [];
  let lastSpawn = 0;
  let nextSpawnDelay = 900;

  function maybeSpawn(now) {
    if (pulses.length >= MAX_PULSES || !mapDots.length) return;
    if (now - lastSpawn < nextSpawnDelay) return;
    const point = mapDots[Math.floor(Math.random() * mapDots.length)];
    pulses.push({ x: point.x, y: point.y, born: now, code: randomCode() });
    lastSpawn = now;
    nextSpawnDelay = 1400 + Math.random() * 1800;
  }

  function draw(now) {
    ctx.clearRect(0, 0, width, height);

    ctx.fillStyle = 'rgba(147, 197, 253, 0.22)';
    mapDots.forEach(d => {
      ctx.beginPath();
      ctx.arc(d.x, d.y, 1.1, 0, Math.PI * 2);
      ctx.fill();
    });

    maybeSpawn(now);
    pulses = pulses.filter(p => now - p.born < PULSE_LIFETIME);
    pulses.forEach(p => {
      const age = now - p.born;
      const ringT = Math.min(1, age / 1100);
      const ringR = 3 + ringT * 20;
      ctx.strokeStyle = 'rgba(96, 165, 250, ' + (0.55 * (1 - ringT)) + ')';
      ctx.lineWidth = 1.4;
      ctx.beginPath();
      ctx.arc(p.x, p.y, ringR, 0, Math.PI * 2);
      ctx.stroke();

      const dotOpacity = age < 900 ? 1 : Math.max(0, 1 - (age - 900) / 900);
      ctx.fillStyle = 'rgba(147, 197, 253, ' + dotOpacity + ')';
      ctx.beginPath();
      ctx.arc(p.x, p.y, 2.2, 0, Math.PI * 2);
      ctx.fill();

      // Label fades in, holds, then fades out - never static long enough
      // to read as a real alert, just a passing "something's out there".
      const fadeIn = Math.min(1, age / 300);
      const fadeOut = age > PULSE_LIFETIME - 700 ? Math.max(0, (PULSE_LIFETIME - age) / 700) : 1;
      const labelOpacity = Math.min(fadeIn, fadeOut) * 0.85;
      if (labelOpacity > 0.02) {
        ctx.font = '10px ui-monospace, SFMono-Regular, Menlo, Consolas, monospace';
        ctx.fillStyle = 'rgba(191, 219, 254, ' + labelOpacity + ')';
        const labelX = Math.min(width - 8, p.x + 8);
        const align = labelX + ctx.measureText(p.code).width > width - 4 ? 'right' : 'left';
        ctx.textAlign = align;
        ctx.fillText(p.code, align === 'right' ? p.x - 8 : labelX, p.y - 8);
      }
    });

    requestAnimationFrame(draw);
  }

  let resizeTimer;
  window.addEventListener('resize', () => {
    clearTimeout(resizeTimer);
    resizeTimer = setTimeout(resize, 150);
  }, { passive: true });

  resize();
  requestAnimationFrame(draw);
  }

  initHeroMap();
})();
