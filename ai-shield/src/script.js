  // ---------------------------------------------------------------
  // DATA
  // ---------------------------------------------------------------

  const PILLARS = __PILLARS_JSON__;

  const PILLAR_SCOPE = {
    s: "Who else's risk is now yours",
    h: 'Who owns this when it breaks',
    i: "What it's allowed to do alone",
    e: 'Whether it survives an attack',
    l: "Whether you'd notice",
    d: 'What it knows, and who it tells',
  };

  const DEPLOYMENT_PATTERNS = [
    { id: 'api', name: 'Vendor API / SaaS chatbot', desc: 'Consuming a hosted model or product as-is \u2014 ChatGPT, Claude, a vendor\u2019s built-in AI feature.' },
    { id: 'rag', name: 'RAG on a vendor model', desc: 'A vendor or foundation model plus your own retrieved data.' },
    { id: 'finetune', name: 'Fine-tuning', desc: 'Fine-tuning a vendor or open model on your own data.' },
    { id: 'selfhost', name: 'Self-hosting / training', desc: 'Self-hosting or training your own model.' },
    { id: 'agents', name: 'Autonomous agents', desc: 'Building agents with tool access and delegated authority.' },
  ];

  const BENCHMARK_ENDPOINT = 'https://krismccabe.com/api/shield-benchmark.php';
  const INDUSTRIES = [
    'Technology / SaaS', 'Financial Services', 'Healthcare', 'Retail / E-commerce',
    'Manufacturing', 'Government / Public Sector', 'Professional Services', 'Education', 'Other',
  ];
  const ORG_SIZE_BANDS = ['1-50', '51-200', '201-1000', '1000+'];

  const RATING_BANDS = [
    { min: 0.0, max: 0.8, name: 'Exposed', color: '#DC2626', desc: 'No meaningful AI-specific controls. Risk is unmanaged and, most likely, unmeasured.' },
    { min: 0.8, max: 1.6, name: 'Reactive', color: '#EA580C', desc: 'Controls exist because someone personally cared. Nothing survives that person leaving.' },
    { min: 1.6, max: 2.4, name: 'Defined', color: '#CA8A04', desc: 'Policies and controls are written down. Whether they\u2019re followed is a separate question.' },
    { min: 2.4, max: 3.2, name: 'Managed', color: '#0D9488', desc: 'Controls are owned, applied consistently, and someone is watching the results.' },
    { min: 3.2, max: 4.01, name: 'Resilient', color: '#16A34A', desc: 'Controls are continuously tested against real adversarial pressure, and the evidence is automatic.' },
  ];

  const ALL_QUESTIONS = [];
  PILLARS.forEach(p => {
    p.questions.forEach(q => {
      ALL_QUESTIONS.push(Object.assign({}, q, { pillarId: p.id, pillarLetter: p.letter, pillarName: p.name }));
    });
  });
  const TOTAL_QUESTIONS = ALL_QUESTIONS.length;
  const pillarById = id => PILLARS.find(p => p.id === id);
  const deployById = id => DEPLOYMENT_PATTERNS.find(d => d.id === id);
  // Migrates assessments saved before deployment pattern became multi-select
  // (meta.deployment as a single string) onto the current meta.deployments array shape.
  function normalizeMeta(meta) {
    if (!meta) return meta;
    if (!Array.isArray(meta.deployments)) {
      meta.deployments = meta.deployment ? [meta.deployment] : [];
    }
    delete meta.deployment;
    return meta;
  }

  function bandFor(score) {
    return RATING_BANDS.find(b => score >= b.min && score < b.max) || RATING_BANDS[RATING_BANDS.length - 1];
  }
  function scoreColor(score) { return bandFor(score).color; }

  function escapeHtml(str) {
    return String(str == null ? '' : str).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  }
  function stripTags(str) { return String(str || '').replace(/<[^>]+>/g, ''); }
  function deent(str) {
    return String(str || '').replace(/&middot;/g, '\u00B7').replace(/&amp;/g, '&').replace(/&ndash;/g, '\u2013').replace(/&mdash;/g, '\u2014').replace(/&rsquo;/g, '\u2019');
  }
  function slug(str) { return String(str || '').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/(^-|-$)/g, ''); }
  function fmtDate(iso) {
    if (!iso) return '';
    try { return new Date(iso).toLocaleDateString('en-GB', { day: 'numeric', month: 'long', year: 'numeric' }); } catch (e) { return iso; }
  }
  function downloadBlob(content, filename, type) {
    const blob = new Blob([content], { type: type });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = filename; a.click();
    URL.revokeObjectURL(url);
  }
  function uid() { return 'a' + Date.now().toString(36) + Math.random().toString(36).slice(2, 8); }

  // ---------------------------------------------------------------
  // STATE
  // ---------------------------------------------------------------

  function freshAssessment() {
    return {
      meta: {
        id: uid(), name: '', org: '', scope: '', assessor: '', assessorRole: '',
        deployments: [], createdAt: new Date().toISOString(), savedAt: '', previousId: ''
      },
      answers: {},
      currentQuestionIndex: 0,
      mergeConflicts: []
    };
  }
  let state = freshAssessment();
  let portfolio = [];
  let rememberEnabled = true;
  let screen = 'start'; // 'start' | 'questions' | 'review'
  let printMode = 'full';

  const PORTFOLIO_KEY = 'shield-portfolio-v2';
  const ACTIVE_KEY = 'shield-active-v2';
  const REMEMBER_KEY = 'shield-remember-v2';

  function isAnswered(a) { return !!a && (typeof a.level === 'number' || a.na || a.dontKnow); }
  function answeredCount(assessment) {
    assessment = assessment || state;
    return ALL_QUESTIONS.filter(q => isAnswered(assessment.answers[q.id])).length;
  }

  // ---------------------------------------------------------------
  // SCORING
  // ---------------------------------------------------------------

  function computeScores(assessment) {
    const pillarScores = {};
    PILLARS.forEach(p => {
      let sum = 0, count = 0;
      p.questions.forEach(q => {
        const a = assessment.answers[q.id];
        if (a && typeof a.level === 'number') { sum += a.level; count++; }
      });
      pillarScores[p.id] = count > 0 ? sum / count : null;
    });
    const applicable = PILLARS.filter(p => pillarScores[p.id] !== null);
    const avg = applicable.length ? applicable.reduce((s, p) => s + pillarScores[p.id], 0) / applicable.length : 0;
    const govScore = pillarScores['h'];
    const overall = (govScore !== null) ? Math.min(avg, govScore + 1) : avg;
    return { pillarScores, avg, overall, govScore };
  }

  function computeResults(assessment) {
    assessment = assessment || state;
    const { pillarScores, avg, overall, govScore } = computeScores(assessment);
    const band = bandFor(overall);
    const capped = govScore !== null && overall < avg - 0.0001;

    const criticalGaps = [], improvable = [], needsVerification = [];
    PILLARS.forEach(p => p.questions.forEach(q => {
      const a = assessment.answers[q.id];
      if (!a) return;
      if (a.dontKnow) { needsVerification.push({ pillar: p, question: q }); return; }
      if (typeof a.level !== 'number') return;
      if (a.level === 0) criticalGaps.push({ pillar: p, question: q, level: a.level, answer: a });
      else if (a.level < 4) improvable.push({ pillar: p, question: q, level: a.level, answer: a });
    }));

    function deltaIfFixed(qid, currentLevel) {
      const clone = { answers: Object.assign({}, assessment.answers) };
      clone.answers[qid] = Object.assign({}, clone.answers[qid], { level: currentLevel + 1, na: false, dontKnow: false });
      const alt = computeScores(clone);
      return +(alt.overall - overall).toFixed(2);
    }

    const actionable = criticalGaps.concat(improvable).map(g => Object.assign({}, g, { delta: deltaIfFixed(g.question.id, g.level) }));
    actionable.sort((x, y) => {
      const xLifts = capped && x.pillar.id === 'h';
      const yLifts = capped && y.pillar.id === 'h';
      if (xLifts !== yLifts) return xLifts ? -1 : 1;
      if (y.delta !== x.delta) return y.delta - x.delta;
      return x.level - y.level;
    });
    const govUnresolved = capped ? pillarById('h').questions.filter(q => {
      const a = assessment.answers[q.id];
      return a && typeof a.level === 'number' && a.level < 4;
    }) : [];

    return { pillarScores, avg, overall, govScore, band, capped, criticalGaps, improvable, needsVerification, actionable, govUnresolved };
  }

  // ---------------------------------------------------------------
  // RENDER: Framework tab (static reference content, built from PILLARS)
  // ---------------------------------------------------------------

  function renderPillarStrip() {
    const html = PILLARS.map(p =>
      '<a class="pillar-cell" href="#fw-pillar-' + p.id + '" data-tab="framework"><span class="letter">' + p.letter + '</span>' +
      '<span class="ptext"><span class="pname">' + p.name + '</span><span class="pscope">' + (PILLAR_SCOPE[p.id] || '') + '</span></span></a>'
    ).join('');
    document.getElementById('pillar-strip').innerHTML = html;
  }

  function renderBands() {
    document.getElementById('band-track').innerHTML = RATING_BANDS.map(b => '<div style="background:' + b.color + ';"></div>').join('');
    document.getElementById('band-grid').innerHTML = RATING_BANDS.map(b =>
      '<div class="band-card"><span class="range">' + b.min.toFixed(1) + '\u2013' + (b.max > 4 ? '4.0' : b.max.toFixed(1)) + '</span>' +
      '<div class="bname" style="color:' + b.color + ';">' + b.name + '</div><p>' + b.desc + '</p></div>'
    ).join('');
  }

  function renderFrameworkContent() {
    let html = '';
    PILLARS.forEach(p => {
      html += '<div class="fw-pillar-head" id="fw-pillar-' + p.id + '"><span class="big-letter">' + p.letter + '</span><h2>' + p.name + '</h2></div>';
      html += '<p class="fw-pillar-intro">' + p.intro + '</p>';
      html += '<p class="fw-maps-to"><b>Maps to</b>&nbsp; ' + p.maps + '</p>';
      p.questions.forEach(q => {
        html += '<div class="fw-question"><span class="qid">' + q.id + '</span><h3>' + q.q + '</h3><div class="fw-ladder">';
        q.levels.forEach((lvl, i) => {
          html += '<div class="fw-rung' + (i === 4 ? ' lvl-4' : '') + '"><div class="lvl">' + i + '</div><div class="rtext">' + lvl + '</div></div>';
        });
        html += '</div><p class="fw-crosswalk"><b>Relevant controls in other frameworks</b>&nbsp; ' + q.crosswalk + '</p>';
        html += '<p class="fw-why"><b>Why this matters</b>&nbsp; ' + q.rationale + '</p>';
        html += liveCheckHtml(q) + '</div>';
      });
    });
    document.getElementById('framework-content').innerHTML = html;
  }

  // ---------------------------------------------------------------
  // RENDER: Assessment tab \u2014 screens
  // ---------------------------------------------------------------

  function setScreen(next) {
    screen = next;
    ['start', 'questions', 'review'].forEach(s => {
      document.getElementById('screen-' + s).style.display = (s === screen) ? '' : 'none';
    });
    if (screen === 'start') renderStartScreen();
    if (screen === 'questions') renderCurrentQuestion();
    if (screen === 'review') renderReviewScreen();
  }

  function renderStartScreen() {
    const listEl = document.getElementById('portfolio-list');
    const wrapEl = document.getElementById('portfolio-wrap');
    if (!portfolio.length) {
      wrapEl.style.display = 'none';
      listEl.innerHTML = '';
    } else {
      wrapEl.style.display = '';
      listEl.innerHTML = portfolio.slice().sort((a, b) => (b.meta.savedAt || '').localeCompare(a.meta.savedAt || '')).map(a => {
        const r = computeResults(a);
        const complete = answeredCount(a) === TOTAL_QUESTIONS;
        return '<div class="portfolio-card">' +
          '<div class="pf-main"><div class="pf-name">' + escapeHtml(a.meta.name || 'Untitled assessment') + '</div>' +
          '<div class="pf-meta">' + (complete ? (r.overall.toFixed(1) + ' / 4.0 \u00B7 ' + r.band.name + ' \u00B7 ' + r.criticalGaps.length + ' critical gap' + (r.criticalGaps.length === 1 ? '' : 's')) : (answeredCount(a) + ' of ' + TOTAL_QUESTIONS + ' answered')) +
          (a.meta.savedAt ? ' \u00B7 saved ' + fmtDate(a.meta.savedAt) : '') + '</div></div>' +
          '<div class="pf-actions">' +
          '<button class="btn small" data-act="open" data-id="' + a.meta.id + '">' + (complete ? 'View' : 'Continue') + '</button>' +
          (complete ? '<button class="btn small" data-act="reassess" data-id="' + a.meta.id + '">Re-assess</button>' : '') +
          '<button class="btn small" data-act="delete" data-id="' + a.meta.id + '" aria-label="Delete">Delete</button>' +
          '</div></div>';
      }).join('');
    }
    document.getElementById('assessment-name-input').value = state.meta.name || '';
    renderDeployGrid();
  }

  document.getElementById('portfolio-list').addEventListener('click', e => {
    const btn = e.target.closest('button[data-act]');
    if (!btn) return;
    const id = btn.dataset.id;
    const found = portfolio.find(a => a.meta.id === id);
    if (!found) return;
    if (btn.dataset.act === 'delete') {
      if (!confirm('Delete "' + (found.meta.name || 'Untitled assessment') + '"? This cannot be undone.')) return;
      portfolio = portfolio.filter(a => a.meta.id !== id);
      persistPortfolio();
      renderStartScreen();
      return;
    }
    if (btn.dataset.act === 'reassess') {
      const clone = JSON.parse(JSON.stringify(found));
      clone.meta.id = uid();
      clone.meta.previousId = found.meta.id;
      clone.meta.createdAt = new Date().toISOString();
      clone.meta.savedAt = '';
      clone.currentQuestionIndex = 0;
      state = clone;
      persistActive();
      setScreen('questions');
      return;
    }
    // open / continue
    state = JSON.parse(JSON.stringify(found));
    persistActive();
    if (answeredCount(state) === TOTAL_QUESTIONS) {
      switchTab('results');
    } else {
      setScreen('questions');
    }
  });

  document.getElementById('assessment-name-input').addEventListener('input', e => {
    state.meta.name = e.target.value;
  });

  function renderDeployGrid() {
    const el = document.getElementById('deploy-grid');
    el.innerHTML = DEPLOYMENT_PATTERNS.map(d => {
      const checked = state.meta.deployments.includes(d.id);
      return '<div class="deploy-option' + (checked ? ' selected' : '') + '" data-id="' + d.id + '" role="checkbox" aria-checked="' + checked + '" tabindex="0">' +
        '<div class="d-name">' + d.name + '</div><div class="d-desc">' + d.desc + '</div></div>';
    }).join('');
    el.querySelectorAll('.deploy-option').forEach(opt => {
      const toggle = () => {
        const id = opt.dataset.id;
        const idx = state.meta.deployments.indexOf(id);
        if (idx >= 0) state.meta.deployments.splice(idx, 1); else state.meta.deployments.push(id);
        renderDeployGrid();
      };
      opt.addEventListener('click', toggle);
      opt.addEventListener('keydown', e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); toggle(); } });
    });
  }

  document.getElementById('begin-assessment-btn').addEventListener('click', () => {
    const nameInput = document.getElementById('assessment-name-input');
    if (!state.meta.name.trim()) {
      nameInput.focus();
      document.getElementById('name-required-note').style.display = '';
      return;
    }
    document.getElementById('name-required-note').style.display = 'none';
    setScreen('questions');
  });

  // ---------------------------------------------------------------
  // RENDER: Assessment tab \u2014 question flow
  // ---------------------------------------------------------------

  const questionsContainer = document.getElementById('questions-container');

  function renderCurrentQuestion() {
    const idx = state.currentQuestionIndex;
    const q = ALL_QUESTIONS[idx];
    const a = state.answers[q.id] || {};
    const selectedLevel = a.level;
    const pillarDeployNotes = pillarById(q.pillarId).deployNotes;
    const deployNotes = state.meta.deployments
      .map(id => deent(pillarDeployNotes[id]))
      .filter(Boolean);

    let html = '<div class="q-progress-track"><div class="q-progress-fill" style="width:' + (((idx + 1) / TOTAL_QUESTIONS) * 100) + '%;"></div></div>';
    html += '<div class="pillar-tag">' + q.pillarLetter + ' &middot; ' + q.pillarName + '</div>';
    if (deployNotes.length) html += '<ul class="deploy-note">' + deployNotes.map(n => '<li>' + escapeHtml(n) + '</li>').join('') + '</ul>';
    html += '<div class="question-card"><div class="q-num">Question ' + (idx + 1) + ' of ' + TOTAL_QUESTIONS + '</div><h3 tabindex="-1" id="current-q-heading">' + q.q + '</h3>';
    html += '<div class="level-options">';
    q.levels.forEach((desc, i) => {
      html += '<div class="level-option' + (selectedLevel === i ? ' selected' : '') + '" data-level="' + i + '" role="button" tabindex="0">' +
        '<span class="lvl-badge">' + i + '</span><span class="lvl-text">' + desc + '</span></div>';
    });
    html += '</div>';

    html += '<div class="alt-answers">';
    html += '<button type="button" class="alt-btn' + (a.na ? ' selected' : '') + '" data-alt="na">Not applicable to us</button>';
    html += '<button type="button" class="alt-btn' + (a.dontKnow ? ' selected' : '') + '" data-alt="dontKnow">I don\u2019t know &mdash; needs verification</button>';
    html += '</div>';

    html += '<details class="evidence-box"' + (a.evidence || a.evidenceUrl ? ' open' : '') + '><summary>+ Add evidence or a note (optional)</summary>' +
      '<textarea id="evidence-text" placeholder="e.g. name of the document, or what you checked">' + escapeHtml(a.evidence || '') + '</textarea>' +
      '<input type="url" id="evidence-url" placeholder="Optional link" value="' + escapeHtml(a.evidenceUrl || '') + '">' +
      '</details>';

    html += '<div class="q-nav">';
    html += '<button class="btn" id="q-back" ' + (idx === 0 ? 'disabled' : '') + '>&#8592; Back</button>';
    if (!isAnswered(a)) {
      html += '<span class="must-answer-note">Pick the closest description above to continue</span>';
    }
    html += '<button class="btn primary" id="q-next" ' + (!isAnswered(a) ? 'disabled' : '') + '>' +
      (idx === TOTAL_QUESTIONS - 1 ? 'See my results \u2192' : 'Next \u2192') + '</button>';
    html += '</div></div>';
    html += '<div class="review-link-row no-print"><button type="button" class="link-btn" id="review-link-btn">View / edit all answers</button></div>';

    questionsContainer.innerHTML = html;

    function ensureAnswer() {
      if (!state.answers[q.id]) state.answers[q.id] = {};
      return state.answers[q.id];
    }

    questionsContainer.querySelectorAll('.level-option').forEach(opt => {
      const select = () => {
        const ans = ensureAnswer();
        ans.level = parseInt(opt.dataset.level, 10);
        ans.na = false; ans.dontKnow = false;
        renderCurrentQuestion();
        refreshAll();
      };
      opt.addEventListener('click', select);
      opt.addEventListener('keydown', e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); select(); } });
    });
    questionsContainer.querySelectorAll('.alt-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        const ans = ensureAnswer();
        const key = btn.dataset.alt;
        const turningOn = !ans[key];
        ans.level = undefined; ans.na = false; ans.dontKnow = false;
        if (turningOn) ans[key] = true;
        renderCurrentQuestion();
        refreshAll();
      });
    });
    document.getElementById('evidence-text').addEventListener('change', e => { ensureAnswer().evidence = e.target.value; refreshAll(); });
    document.getElementById('evidence-url').addEventListener('change', e => { ensureAnswer().evidenceUrl = e.target.value; refreshAll(); });

    document.getElementById('q-back').addEventListener('click', () => {
      state.currentQuestionIndex = Math.max(0, state.currentQuestionIndex - 1);
      renderCurrentQuestion();
      questionsContainer.scrollIntoView({ behavior: 'smooth', block: 'start' });
    });
    document.getElementById('q-next').addEventListener('click', () => {
      if (!isAnswered(state.answers[q.id])) return;
      if (idx === TOTAL_QUESTIONS - 1) {
        switchTab('results');
      } else {
        state.currentQuestionIndex = Math.min(TOTAL_QUESTIONS - 1, state.currentQuestionIndex + 1);
        renderCurrentQuestion();
        questionsContainer.scrollIntoView({ behavior: 'smooth', block: 'start' });
      }
    });
    document.getElementById('review-link-btn').addEventListener('click', () => setScreen('review'));
  }

  // ---------------------------------------------------------------
  // RENDER: Assessment tab \u2014 review/edit screen
  // ---------------------------------------------------------------

  function renderReviewScreen() {
    let html = '<h2>Review your answers</h2><p class="sub">Click any question to jump back and change it.</p>';
    if (state.mergeConflicts && state.mergeConflicts.length) {
      html += '<div class="conflict-banner"><b>' + state.mergeConflicts.length + ' answer' + (state.mergeConflicts.length === 1 ? '' : 's') + ' changed meaningfully during an import.</b> ' +
        'Different respondents gave different answers to the same question (2 or more levels apart) \u2014 worth a quick conversation before you treat the result as final.<ul>' +
        state.mergeConflicts.map(c => '<li>' + c.qid + ': was ' + c.existingLevel + ', imported answer scored ' + c.incomingLevel + (c.source ? ' (from ' + escapeHtml(c.source) + ')' : '') + '</li>').join('') +
        '</ul></div>';
    }
    html += '<div class="review-list">';
    ALL_QUESTIONS.forEach((q, idx) => {
      const a = state.answers[q.id] || {};
      let statusText = 'Not yet answered';
      let statusClass = 'unanswered';
      if (typeof a.level === 'number') { statusText = 'Level ' + a.level + ' of 4'; statusClass = a.level === 0 ? 'critical' : (a.level < 4 ? 'partial' : 'good'); }
      else if (a.na) { statusText = 'Not applicable'; statusClass = 'neutral'; }
      else if (a.dontKnow) { statusText = 'Needs verification'; statusClass = 'unknown'; }
      html += '<button type="button" class="review-row" data-idx="' + idx + '">' +
        '<span class="rr-id">' + q.id + '</span><span class="rr-q">' + q.q + '</span>' +
        '<span class="rr-status ' + statusClass + '">' + statusText + '</span></button>';
    });
    html += '</div><div class="review-actions"><button class="btn" id="review-back-btn">&#8592; Back to questions</button></div>';
    document.getElementById('screen-review').innerHTML = html;
    document.querySelectorAll('.review-row').forEach(row => {
      row.addEventListener('click', () => {
        state.currentQuestionIndex = parseInt(row.dataset.idx, 10);
        setScreen('questions');
      });
    });
    document.getElementById('review-back-btn').addEventListener('click', () => setScreen('questions'));
  }

  // ---------------------------------------------------------------
  // RENDER: Results tab
  // ---------------------------------------------------------------

  function renderReportDetails() {
    const el = document.getElementById('report-details');
    el.innerHTML =
      '<div class="rd-grid">' +
      '<label>Organisation<input type="text" id="rd-org" value="' + escapeHtml(state.meta.org) + '" placeholder="Optional"></label>' +
      '<label>System / scope assessed<input type="text" id="rd-scope" value="' + escapeHtml(state.meta.scope) + '" placeholder="e.g. Customer support agent, production"></label>' +
      '<label>Assessor name<input type="text" id="rd-assessor" value="' + escapeHtml(state.meta.assessor) + '" placeholder="Optional"></label>' +
      '<label>Assessor role<input type="text" id="rd-assessor-role" value="' + escapeHtml(state.meta.assessorRole) + '" placeholder="Optional"></label>' +
      '</div><p class="rd-note">These appear on the exported PDF and register. Nothing here leaves your browser.</p>';
    ['org', 'scope', 'assessor', 'assessorRole'].forEach(key => {
      const id = 'rd-' + key.replace(/([A-Z])/g, '-$1').toLowerCase();
      const input = document.getElementById(id);
      if (input) input.addEventListener('change', e => { state.meta[key] = e.target.value; persistIfEnabled(); });
    });
  }

  function renderBenchmarkPanel(r) {
    const el = document.getElementById('benchmark-panel');
    if (!el) return;
    el.innerHTML =
      '<h3 class="section-h" style="margin-top:0;">See how you compare (optional)</h3>' +
      '<p class="sub" style="margin:-4px 0 14px;">Opt in to send only your overall score, band, per-pillar scores, and the two fields below to an anonymous aggregate on a server I control &mdash; never your answers, evidence, owner names, or organisation name. Nothing is sent unless you click the button below.</p>' +
      '<div class="benchmark-form">' +
      '<label>Industry<select id="bm-industry">' + INDUSTRIES.map(i => '<option value="' + escapeHtml(i) + '">' + escapeHtml(i) + '</option>').join('') + '</select></label>' +
      '<label>Organisation size<select id="bm-size"><option value="">Prefer not to say</option>' + ORG_SIZE_BANDS.map(s => '<option value="' + s + '">' + s + ' employees</option>').join('') + '</select></label>' +
      '<button class="btn primary" id="bm-submit">Compare anonymously</button>' +
      '<input type="text" id="bm-website" name="website" autocomplete="off" tabindex="-1" aria-hidden="true" style="position:absolute; left:-9999px; width:1px; height:1px;">' +
      '</div>' +
      '<div id="bm-result" class="bm-result" style="display:none;" aria-live="polite"></div>';

    const loadedAt = Date.now();
    document.getElementById('bm-submit').addEventListener('click', async () => {
      const btn = document.getElementById('bm-submit');
      const resultEl = document.getElementById('bm-result');
      btn.disabled = true;
      btn.textContent = 'Comparing\u2026';
      const payload = {
        loadedAt: loadedAt,
        website: document.getElementById('bm-website').value,
        score: r.overall,
        band: r.band.name,
        pillarScores: r.pillarScores,
        deploymentPattern: state.meta.deployments.length === 1 ? state.meta.deployments[0] : null,
        industry: document.getElementById('bm-industry').value,
        orgSizeBand: document.getElementById('bm-size').value,
      };
      resultEl.style.display = '';
      try {
        const resp = await fetch(BENCHMARK_ENDPOINT, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload),
        });
        const data = await resp.json();
        if (data && data.ok && data.percentile !== null && data.percentile !== undefined) {
          resultEl.innerHTML = '<p>You scored higher than <b>' + data.percentile + '%</b> of ' + escapeHtml(data.scope) + ' (n=' + data.count + ').</p>';
        } else if (data && data.ok) {
          resultEl.innerHTML = '<p>Thanks &mdash; recorded. Not enough submissions yet for a meaningful comparison (' + data.count + ' so far). Check back later.</p>';
        } else {
          resultEl.innerHTML = '<p>Couldn\u2019t reach the comparison service right now. Your assessment is unaffected &mdash; try again later.</p>';
        }
      } catch (e) {
        resultEl.innerHTML = '<p>Couldn\u2019t reach the comparison service right now. Your assessment is unaffected &mdash; try again later.</p>';
      } finally {
        btn.disabled = false;
        btn.textContent = 'Compare anonymously';
      }
    });
  }

  // Not every question has one - a small handful of questions (currently
  // just S1, vendor vetting) point at a companion tool that actually
  // answers part of the question live, rather than just citing a static
  // framework control. Same escaping discipline as the rest of this file
  // even though the source is our own curated JSON, not user input.
  function liveCheckHtml(q) {
    if (!q.liveCheck) return '';
    const lc = q.liveCheck;
    return '<p class="fw-live-check"><b>Check this live</b>&nbsp; ' + lc.note +
      ' <a href="' + lc.url + '" target="_blank" rel="noopener">' + lc.label + ' &rarr;</a></p>';
  }

  function actionCardHtml(g) {
    const isCritical = g.level === 0;
    const a = g.answer || {};
    return '<div class="gap-card ' + (isCritical ? 'severity-critical' : 'severity-improve') + '" data-qid="' + g.question.id + '">' +
      '<div class="gap-head"><p class="gap-title">' + g.question.id + ' &middot; ' + g.pillar.name + '</p>' +
      '<span class="gap-badge">' + (isCritical ? 'Critical gap' : 'Level ' + g.level + ' of 4') + '</span></div>' +
      '<p class="gap-desc">' + g.question.q + '</p>' +
      '<p class="gap-next"><b>Next step</b>&nbsp; ' + g.question.nextSteps[g.level] + '</p>' +
      '<p class="gap-why"><b>Why it matters</b>&nbsp; ' + g.question.rationale + '</p>' +
      (g.delta > 0 ? '<p class="gap-delta">Moving this to the next level would raise your overall score by roughly <b>+' + g.delta.toFixed(1) + '</b>.</p>' :
        '<p class="gap-delta gap-delta-flat">Fixing this alone would not move your overall score right now &mdash; see the governance cap note above.</p>') +
      '<div class="gap-assign">' +
      '<label>Owner <input type="text" class="gap-owner" value="' + escapeHtml(a.owner || '') + '" placeholder="' + escapeHtml(g.question.ownerRole) + ' (suggested)"></label>' +
      '<label>Target date <input type="date" class="gap-date" value="' + escapeHtml(a.targetDate || '') + '"></label>' +
      '</div>' +
      '<p class="gap-crosswalk"><b style="color:var(--text);">Relevant controls in other frameworks</b><br>' + g.question.crosswalk + '</p>' +
      liveCheckHtml(g.question) + '</div>';
  }

  function renderResults() {
    const panel = document.getElementById('results-panel-content');
    if (answeredCount() < TOTAL_QUESTIONS) {
      panel.innerHTML = '<div class="empty-state"><p>Answer all ' + TOTAL_QUESTIONS + ' questions to see your results.</p></div>';
      return;
    }
    const r = computeResults(state);
    const deploys = state.meta.deployments.map(deployById).filter(Boolean);
    const deployNames = deploys.map(d => d.name).join(', ');

    let html = '<div id="report-details" class="report-details no-print"></div>';

    // delta vs previous assessment
    let prev = null, prevResults = null;
    if (state.meta.previousId) {
      prev = portfolio.find(a => a.meta.id === state.meta.previousId);
      if (prev) prevResults = computeResults(prev);
    }
    if (prevResults) {
      const diff = +(r.overall - prevResults.overall).toFixed(1);
      html += '<div class="delta-banner"><h3>Progress since your last assessment (' + escapeHtml(prev.meta.name || 'Untitled') + ', ' + fmtDate(prev.meta.savedAt) + ')</h3>' +
        '<p>Overall score: ' + prevResults.overall.toFixed(1) + ' &rarr; <b>' + r.overall.toFixed(1) + '</b> (' + (diff >= 0 ? '+' : '') + diff.toFixed(1) + ')</p>';
      const closed = prevResults.criticalGaps.filter(pg => !r.criticalGaps.some(ng => ng.question.id === pg.question.id));
      const opened = r.criticalGaps.filter(ng => !prevResults.criticalGaps.some(pg => pg.question.id === ng.question.id));
      if (closed.length) html += '<p>Critical gaps closed: ' + closed.map(g => g.question.id).join(', ') + '</p>';
      if (opened.length) html += '<p>New critical gaps: ' + opened.map(g => g.question.id).join(', ') + '</p>';
      if (!closed.length && !opened.length) html += '<p>No critical gaps opened or closed since last time.</p>';
      html += '</div>';
    }

    html += '<div class="score-hero">';
    html += '<div class="score-circle" style="--band-color:' + r.band.color + ';"><span class="num">' + r.overall.toFixed(1) + '</span><span class="denom">out of 4.0</span></div>';
    html += '<div class="score-meta"><span class="band-pill" style="background:' + r.band.color + ';">' + r.band.name + '</span>';
    html += '<h3>' + r.band.name + ' &mdash; ' + r.overall.toFixed(1) + ' / 4.0</h3>';
    html += '<p>' + r.band.desc + '</p>';
    if (deployNames) html += '<p style="margin-top:8px; font-size:12px;">Deployment pattern' + (deploys.length > 1 ? 's' : '') + ': <b style="color:var(--text);">' + escapeHtml(deployNames) + '</b></p>';
    html += '</div></div>';

    if (r.capped) {
      html += '<div class="cap-banner"><b>Your overall score is capped at ' + r.overall.toFixed(1) + '</b> by your Governance &amp; Human Oversight score (' + r.govScore.toFixed(1) + '), even though your other pillars average ' + r.avg.toFixed(1) + '. ' +
        'While this cap applies, improving the other five pillars on their own will not raise your overall score. The only questions that can lift it right now: ' +
        r.govUnresolved.map(q => '<b>' + q.id + '</b>').join(', ') + '.</div>';
    }

    html += '<h3 class="section-h">By pillar</h3><div class="pillar-bars">';
    PILLARS.forEach(p => {
      const score = r.pillarScores[p.id];
      const color = score === null ? '#475569' : scoreColor(score);
      html += '<div class="pillar-bar-row"><span class="pb-label">' + p.letter + ' &middot; ' + p.name + '</span>' +
        '<div class="pillar-bar-track"><div class="pillar-bar-fill" style="width:' + (score === null ? 0 : (score / 4) * 100) + '%; background:' + color + ';"></div></div>' +
        '<span class="pb-score">' + (score === null ? 'N/A' : score.toFixed(1)) + '</span></div>';
    });
    html += '</div>';

    html += '<h3 class="section-h">What to fix, in order (' + r.actionable.length + ')</h3>';
    if (r.actionable.length) {
      html += '<p class="sub" style="margin:-4px 0 16px;">Ranked so the items that actually move your score \u2014 and any governance-cap questions, while the cap applies \u2014 come first.</p>';
      r.actionable.forEach(g => { html += actionCardHtml(g); });
    } else {
      html += '<div class="gap-card severity-good"><p class="gap-title">Nothing outstanding</p><p class="gap-desc">Every applicable question is already at the top level.</p></div>';
    }

    if (r.needsVerification.length) {
      html += '<h3 class="section-h">Needs verification (' + r.needsVerification.length + ')</h3>';
      html += '<p class="sub" style="margin:-4px 0 16px;">Marked \u201CI don\u2019t know\u201D \u2014 this is a discovery task (find out), not yet a remediation task (fix).</p>';
      r.needsVerification.forEach(g => {
        html += '<div class="gap-card severity-unknown"><p class="gap-title">' + g.question.id + ' &middot; ' + g.pillar.name + '</p><p class="gap-desc">' + g.question.q + '</p></div>';
      });
    }

    html += '<div class="method-item" style="margin-top:24px;"><div class="step">i</div><div><h3>How this was calculated</h3>' +
      '<p>Overall = min(average of applicable pillar scores, Governance score + 1). Your Governance &amp; Human Oversight score was <b>' + (r.govScore === null ? 'N/A' : r.govScore.toFixed(1)) + '</b>, ' +
      (r.capped ? 'which capped your raw average of <b>' + r.avg.toFixed(1) + '</b> down to <b>' + r.overall.toFixed(1) + '</b>.' : 'which did not cap your raw average of <b>' + r.avg.toFixed(1) + '</b>.') +
      '</p></div></div>';

    html += '<div id="benchmark-panel" class="benchmark-panel no-print"></div>';

    html += '<div class="export-row no-print">' +
      '<button class="btn primary" id="btn-pdf-full">&#128196; Export full PDF</button>' +
      '<button class="btn" id="btn-pdf-onepager">&#128203; Export board one-pager</button>' +
      '<button class="btn" id="btn-register-csv">&#128202; Export register (CSV)</button>' +
      '<button class="btn" id="btn-review-from-results">&#9998; Review / edit answers</button>' +
      '</div>';

    panel.innerHTML = html;
    renderReportDetails();
    renderBenchmarkPanel(r);
    document.getElementById('btn-review-from-results').addEventListener('click', () => { switchTab('assessment'); setScreen('review'); });

    panel.querySelectorAll('.gap-owner').forEach(inp => {
      inp.addEventListener('change', e => {
        const qid = e.target.closest('.gap-card').dataset.qid;
        if (!state.answers[qid]) state.answers[qid] = {};
        state.answers[qid].owner = e.target.value;
        persistIfEnabled();
      });
    });
    panel.querySelectorAll('.gap-date').forEach(inp => {
      inp.addEventListener('change', e => {
        const qid = e.target.closest('.gap-card').dataset.qid;
        if (!state.answers[qid]) state.answers[qid] = {};
        state.answers[qid].targetDate = e.target.value;
        persistIfEnabled();
      });
    });

    document.getElementById('btn-pdf-full').addEventListener('click', () => { printMode = 'full'; buildPrintRoot(r, deployNames); window.print(); });
    document.getElementById('btn-pdf-onepager').addEventListener('click', () => { printMode = 'onepager'; buildPrintRoot(r, deployNames); window.print(); });
    document.getElementById('btn-register-csv').addEventListener('click', () => exportRegisterCSV(r));

    buildPrintRoot(r, deployNames);
    persistToPortfolioIfComplete(r);
  }

  // ---------------------------------------------------------------
  // PDF EXPORT (two modes: full report, board one-pager)
  // ---------------------------------------------------------------

  function buildPrintRoot(r, deployNames) {
    if (printMode === 'onepager') buildPrintRootOnePager(r, deployNames);
    else buildPrintRootFull(r, deployNames);
  }

  function printIdentityLine() {
    const bits = [];
    if (state.meta.org) bits.push('Organisation: ' + escapeHtml(state.meta.org));
    if (state.meta.scope) bits.push('Scope: ' + escapeHtml(state.meta.scope));
    if (state.meta.assessor) bits.push('Assessor: ' + escapeHtml(state.meta.assessor) + (state.meta.assessorRole ? ' (' + escapeHtml(state.meta.assessorRole) + ')' : ''));
    return bits.length ? bits.join(' &middot; ') : '[organisation, scope, and assessor not specified]';
  }

  function buildPrintRootFull(r, deployNames) {
    const today = new Date().toLocaleDateString('en-GB', { day: 'numeric', month: 'long', year: 'numeric' });
    const assessmentName = escapeHtml(state.meta.name || 'Untitled assessment');

    let out = '<div class="print-page">';
    out += '<p class="p-eyebrow">AI-SHIELD &mdash; Executive Summary</p>';
    out += '<h1>' + assessmentName + '</h1>';
    out += '<p class="p-identity">' + printIdentityLine() + '</p>';
    out += '<p><strong>Generated:</strong> ' + today + (deployNames ? ' &middot; <strong>Deployment pattern' + (deployNames.includes(',') ? 's' : '') + ':</strong> ' + escapeHtml(deployNames) : '') + '</p>';
    out += '<div class="p-score-box"><span class="p-score-num" style="color:' + r.band.color + ';">' + r.overall.toFixed(1) + '</span><span class="p-score-denom">/ 4.0 \u2014 ' + r.band.name + '</span></div>';
    out += '<p>' + r.band.desc + '</p>';
    if (r.capped) {
      out += '<div class="p-cap-note"><strong>Score capped by governance:</strong> your Governance &amp; Human Oversight score (' + r.govScore.toFixed(1) + ') is holding the overall score below the raw average of ' + r.avg.toFixed(1) + '. ' +
        'Until ' + r.govUnresolved.map(q => q.id).join(', ') + ' improve, no other fix will raise this number.</div>';
    }
    out += '<h2>Top actions</h2>';
    r.actionable.slice(0, 3).forEach((g, i) => {
      out += '<p><strong>' + (i + 1) + '. ' + g.question.id + ' &middot; ' + g.pillar.name.replace(/&amp;/g, '&') + '</strong> (owner: ' + g.question.ownerRole + ')<br>' + g.question.nextSteps[g.level] + '</p>';
    });
    if (!r.actionable.length) out += '<p>No outstanding actions \u2014 every applicable question is at the top level.</p>';
    out += '</div>'; // end print-page (forces page break after)

    out += '<h2>By pillar</h2><div class="p-bars">';
    PILLARS.forEach(p => {
      const score = r.pillarScores[p.id];
      const pct = score === null ? 0 : (score / 4) * 100;
      out += '<div class="p-bar-row"><span class="p-bar-label">' + p.letter + ' \u00B7 ' + p.name.replace(/&amp;/g, '&') + '</span>' +
        '<div class="p-bar-track"><div class="p-bar-fill" style="width:' + pct + '%;"></div></div>' +
        '<span class="p-bar-score">' + (score === null ? 'N/A' : score.toFixed(1)) + '</span></div>';
    });
    out += '</div>';

    if (r.actionable.length) {
      out += '<h2>What to fix, in order (' + r.actionable.length + ')</h2>';
      r.actionable.forEach(g => {
        const a = g.answer || {};
        out += '<div class="p-gap' + (g.level === 0 ? ' p-gap-critical' : '') + '"><strong>' + g.question.id + ' \u00B7 ' + g.pillar.name.replace(/&amp;/g, '&') + (g.level === 0 ? ' \u2014 Critical gap' : ' \u2014 Level ' + g.level + ' of 4') + '</strong><br>' +
          g.question.q + '<br><span class="p-next"><b>Next step:</b> ' + g.question.nextSteps[g.level] + '</span><br>' +
          '<span class="p-owner"><b>Owner:</b> ' + escapeHtml(a.owner || g.question.ownerRole + ' (suggested)') + (a.targetDate ? ' &middot; <b>Target date:</b> ' + escapeHtml(a.targetDate) : '') + '</span><br>' +
          '<span class="p-crosswalk">' + deent(g.question.crosswalk) + '</span></div>';
      });
    }
    if (r.needsVerification.length) {
      out += '<h2>Needs verification (' + r.needsVerification.length + ')</h2>';
      r.needsVerification.forEach(g => { out += '<p><strong>' + g.question.id + '</strong> \u2014 ' + g.question.q + '</p>'; });
    }

    out += '<h2>Full answer log</h2>';
    PILLARS.forEach(p => {
      out += '<h3>' + p.letter + ' \u00B7 ' + p.name.replace(/&amp;/g, '&') + '</h3>';
      p.questions.forEach(q => {
        const a = state.answers[q.id] || {};
        let scored = a.na ? 'N/A' : (a.dontKnow ? 'unverified' : (typeof a.level === 'number' ? a.level + '/4' : '\u2014'));
        out += '<p><strong>' + q.id + '</strong> (scored ' + scored + '): ' + q.q + '<br>' +
          (typeof a.level === 'number' ? '<span class="p-crosswalk">' + stripTags(q.levels[a.level]) + '</span><br>' : '') +
          (a.evidence ? '<span class="p-crosswalk"><b>Evidence:</b> ' + escapeHtml(a.evidence) + (a.evidenceUrl ? ' (' + escapeHtml(a.evidenceUrl) + ')' : '') + '</span>' : '') + '</p>';
      });
    });

    out += '<h2>License &amp; disclaimer</h2>';
    out += '<p>AI-SHIELD is open source (MIT License), provided "as is" without warranty. This assessment is an indicative tool to aid your own thinking, not a certified audit or professional advice. Use at your own risk \u2014 to the fullest extent permitted by law, the author accepts no liability for any loss or damage arising from its use. Not affiliated with NIST, ISO, OWASP, MITRE, CSA, Gartner, or any named vendor.</p>';
    out += '<p class="p-footer">Generated by AI-SHIELD \u2014 lab.krismccabe.com/ai-shield/</p>';
    document.getElementById('print-root').innerHTML = out;
  }

  function buildPrintRootOnePager(r, deployNames) {
    const today = new Date().toLocaleDateString('en-GB', { day: 'numeric', month: 'long', year: 'numeric' });
    const assessmentName = escapeHtml(state.meta.name || 'Untitled assessment');
    let out = '<div class="print-page onepager">';
    out += '<p class="p-eyebrow">AI Security Snapshot</p>';
    out += '<h1>' + assessmentName + '</h1>';
    out += '<p class="p-identity">' + printIdentityLine() + ' &middot; ' + today + '</p>';
    out += '<div class="p-score-box"><span class="p-score-num" style="color:' + r.band.color + ';">' + r.overall.toFixed(1) + '</span><span class="p-score-denom">/ 4.0 \u2014 ' + r.band.name + '</span></div>';

    const overallSentence = r.capped
      ? 'Overall, this system is rated "' + r.band.name + '." Several technical controls are stronger than this number suggests, but the score is being held down by weak governance and human oversight \u2014 until that\u2019s addressed, technical fixes alone will not move the needle.'
      : 'Overall, this system is rated "' + r.band.name + '." ' + r.band.desc;
    out += '<p class="p-lead">' + overallSentence + '</p>';

    out += '<h2>What this actually means</h2>';
    const top = r.actionable.slice(0, 3);
    if (top.length) {
      top.forEach(g => {
        out += '<div class="p-narrative"><p>' + g.question.rationale + '</p><p><b>What to do:</b> ' + g.question.nextSteps[g.level] + ' <i>(suggested owner: ' + g.question.ownerRole + ')</i></p></div>';
      });
    } else {
      out += '<p>No outstanding gaps \u2014 every area assessed is at the top level.</p>';
    }

    out += '<h2>Recommended next steps</h2><ol class="p-actions">';
    top.forEach(g => { out += '<li>' + g.question.nextSteps[g.level] + '</li>'; });
    out += '</ol>';
    out += '<p class="p-footer">Generated by AI-SHIELD \u2014 an independent, evidence-based AI security self-assessment. lab.krismccabe.com/ai-shield/</p>';
    out += '</div>';
    document.getElementById('print-root').innerHTML = out;
  }

  // ---------------------------------------------------------------
  // REGISTER (CSV) EXPORT
  // ---------------------------------------------------------------

  function toCSVRow(cells) {
    return cells.map(c => {
      const s = String(c == null ? '' : c);
      return /[",\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
    }).join(',');
  }

  function exportRegisterCSV() {
    const rows = [['Assessment', 'Date', 'Question ID', 'Pillar', 'Question', 'Score', 'Level text', 'Critical Gap', 'Next Step', 'Owner', 'Target Date', 'Evidence', 'Crosswalk']];
    const dateStr = new Date().toISOString().slice(0, 10);
    PILLARS.forEach(p => p.questions.forEach(q => {
      const a = state.answers[q.id] || {};
      const scoreText = a.na ? 'N/A' : (a.dontKnow ? 'Unknown' : (typeof a.level === 'number' ? a.level : ''));
      const levelText = (typeof a.level === 'number') ? stripTags(q.levels[a.level]) : '';
      const isCritical = a.level === 0 ? 'Yes' : 'No';
      const nextStep = (typeof a.level === 'number' && a.level < 4) ? q.nextSteps[a.level] : '';
      rows.push([
        state.meta.name || 'Untitled assessment', dateStr, q.id, p.name.replace(/&amp;/g, '&'), q.q,
        scoreText, levelText, isCritical, nextStep, a.owner || '', a.targetDate || '', a.evidence || '',
        deent(q.crosswalk)
      ]);
    }));
    const csv = rows.map(toCSVRow).join('\r\n');
    downloadBlob(csv, (slug(state.meta.name) || 'ai-shield-assessment') + '-register.csv', 'text/csv');
  }

  // ---------------------------------------------------------------
  // TABS
  // ---------------------------------------------------------------

  function switchTab(name) {
    document.querySelector('.tab-btn[data-tab="' + name + '"]').click();
  }

  document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      if (btn.disabled) return;
      document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
      document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
      btn.classList.add('active');
      document.getElementById('tab-' + btn.dataset.tab).classList.add('active');
      window.scrollTo({ top: document.querySelector('.tabs').offsetTop - 20, behavior: 'smooth' });
      if (btn.dataset.tab === 'assessment') {
        const inProgress = state.meta.name && answeredCount() > 0 && answeredCount() < TOTAL_QUESTIONS;
        setScreen(inProgress ? 'questions' : 'start');
      }
      if (btn.dataset.tab === 'results') renderResults();
    });
  });
  document.getElementById('start-assessment-btn').addEventListener('click', () => switchTab('assessment'));
  document.getElementById('pillar-strip').addEventListener('click', e => {
    const cell = e.target.closest('.pillar-cell');
    if (!cell) return;
    e.preventDefault();
    switchTab('framework');
    setTimeout(() => { document.getElementById(cell.getAttribute('href').slice(1)).scrollIntoView({ behavior: 'smooth', block: 'start' }); }, 60);
  });

  // ---------------------------------------------------------------
  // SAVE / LOAD / IMPORT / PORTFOLIO / REMEMBER
  // ---------------------------------------------------------------

  function updateProgress() {
    document.getElementById('progress-text').textContent = answeredCount() + ' of ' + TOTAL_QUESTIONS + ' answered' + (state.meta.name ? ' \u00B7 ' + escapeHtml(state.meta.name) : '');
    const complete = answeredCount() === TOTAL_QUESTIONS;
    document.getElementById('tab-btn-results').disabled = !complete;
  }

  function refreshAll() {
    updateProgress();
    persistIfEnabled();
  }

  function persistIfEnabled() {
    if (rememberEnabled) { persistActive(); persistPortfolio(); }
  }

  function persistActive() {
    try { localStorage.setItem(ACTIVE_KEY, JSON.stringify(state)); } catch (e) {}
  }
  function persistPortfolio() {
    try { localStorage.setItem(PORTFOLIO_KEY, JSON.stringify(portfolio)); } catch (e) {}
  }
  function persistToPortfolioIfComplete(r) {
    if (answeredCount() !== TOTAL_QUESTIONS) return;
    state.meta.savedAt = new Date().toISOString();
    const idx = portfolio.findIndex(a => a.meta.id === state.meta.id);
    const snapshot = JSON.parse(JSON.stringify(state));
    if (idx >= 0) portfolio[idx] = snapshot; else portfolio.push(snapshot);
    persistIfEnabled();
  }

  document.getElementById('remember-toggle').addEventListener('change', e => {
    rememberEnabled = e.target.checked;
    try { localStorage.setItem(REMEMBER_KEY, rememberEnabled ? '1' : '0'); } catch (e) {}
    if (rememberEnabled) { persistActive(); persistPortfolio(); }
    else { try { localStorage.removeItem(ACTIVE_KEY); localStorage.removeItem(PORTFOLIO_KEY); } catch (e) {} }
  });

  window.addEventListener('beforeunload', e => {
    if (!rememberEnabled && answeredCount() > 0) {
      e.preventDefault();
      e.returnValue = '';
    }
  });

  document.getElementById('btn-save').addEventListener('click', () => {
    downloadBlob(JSON.stringify(state, null, 2), (slug(state.meta.name) || 'ai-shield-assessment') + '.json', 'application/json');
  });

  document.getElementById('btn-load').addEventListener('click', () => document.getElementById('file-input').click());
  document.getElementById('file-input').addEventListener('change', e => {
    const file = e.target.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => {
      try {
        const loaded = JSON.parse(reader.result);
        if (loaded && typeof loaded === 'object' && loaded.answers) {
          state = Object.assign(freshAssessment(), loaded);
          normalizeMeta(state.meta);
          state.mergeConflicts = [];
          setScreen(answeredCount() === TOTAL_QUESTIONS ? 'review' : 'start');
          refreshAll();
        }
      } catch (err) {}
    };
    reader.readAsText(file);
    e.target.value = '';
  });

  document.getElementById('btn-import').addEventListener('click', () => document.getElementById('import-file-input').click());
  document.getElementById('import-file-input').addEventListener('change', e => {
    const file = e.target.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => {
      try {
        const loaded = JSON.parse(reader.result);
        const incomingAnswers = (loaded && loaded.answers) ? loaded.answers : null;
        if (!incomingAnswers) return;
        const sourceName = (loaded.meta && (loaded.meta.assessor || loaded.meta.name)) || file.name;
        const conflicts = [];
        Object.keys(incomingAnswers).forEach(qid => {
          const incoming = incomingAnswers[qid];
          if (!incoming || typeof incoming.level !== 'number') return;
          const existing = state.answers[qid];
          if (existing && typeof existing.level === 'number' && Math.abs(existing.level - incoming.level) >= 2) {
            conflicts.push({ qid: qid, existingLevel: existing.level, incomingLevel: incoming.level, source: sourceName });
          }
          state.answers[qid] = Object.assign({}, existing, incoming);
        });
        state.mergeConflicts = (state.mergeConflicts || []).concat(conflicts);
        setScreen(answeredCount() === TOTAL_QUESTIONS ? 'review' : 'start');
        refreshAll();
      } catch (err) {}
    };
    reader.readAsText(file);
    e.target.value = '';
  });

  document.getElementById('new-assessment-btn').addEventListener('click', () => {
    if (answeredCount() > 0 && !state.meta.savedAt && !confirm('Discard the assessment you have in progress and start a new one?')) return;
    state = freshAssessment();
    persistIfEnabled();
    switchTab('assessment');
  });

  // ---------------------------------------------------------------
  // INIT
  // ---------------------------------------------------------------

  renderPillarStrip();
  renderBands();
  renderFrameworkContent();

  try {
    rememberEnabled = localStorage.getItem(REMEMBER_KEY) !== '0';
    document.getElementById('remember-toggle').checked = rememberEnabled;
    const rawPortfolio = localStorage.getItem(PORTFOLIO_KEY);
    if (rawPortfolio) { const p = JSON.parse(rawPortfolio); if (Array.isArray(p)) { p.forEach(a => normalizeMeta(a.meta)); portfolio = p; } }
    const rawActive = localStorage.getItem(ACTIVE_KEY);
    if (rawActive) {
      const loaded = JSON.parse(rawActive);
      if (loaded && typeof loaded === 'object') { state = Object.assign(freshAssessment(), loaded); normalizeMeta(state.meta); }
    }
  } catch (e) {}

  setScreen((state.meta.name && answeredCount() > 0 && answeredCount() < TOTAL_QUESTIONS) ? 'questions' : 'start');
  updateProgress();
