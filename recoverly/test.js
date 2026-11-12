// Recoverly scoring logic tests — run with: node test.js
//
// This deliberately mirrors the scoring algorithm from index.html rather than
// importing it, since the app is a single dependency-free HTML file with no
// module exports. If you change computeMaturityScore() in index.html, update
// the copy below to match, then re-run this to confirm the worked example in
// REQUIREMENTS.md §12 still holds.

const DIMENSION_IDS = [
  'ownership', 'policy', 'inventory', 'dependencies', 'backup', 'access',
  'monitoring', 'command', 'communication', 'procedures', 'testing', 'review'
];

// Must match INDUSTRY_WEIGHTS.financial in index.html exactly.
const FINANCIAL_WEIGHTS = {
  ownership: 1.5, policy: 2.0, inventory: 1.0, dependencies: 1.0, backup: 1.5,
  access: 1.5, monitoring: 1.0, command: 1.5, communication: 2.0,
  procedures: 1.0, testing: 1.5, review: 1.5
};

// Must match computeMaturityScore() in index.html exactly.
function computeMaturityScore(scores, weights) {
  let weightedSum = 0, weightSum = 0;
  const gaps = [];
  DIMENSION_IDS.forEach(id => {
    const score = scores[id];
    if (!score) return;
    const w = weights[id] || 1.0;
    weightedSum += score * w;
    weightSum += w;
    gaps.push({ id, gap: (5 - score) * w, score });
  });
  const weightedAverage = weightSum > 0 ? weightedSum / weightSum : 0;
  const roundedLevel = Math.min(5, Math.max(1, Math.round(weightedAverage)));
  gaps.sort((a, b) => b.gap - a.gap);
  const topGapValue = gaps.length ? (gaps[2] ? gaps[2].gap : gaps[gaps.length - 1].gap) : 0;
  const priorityGaps = gaps.filter((g, i) => i < 3 || g.gap === topGapValue).filter(g => g.gap > 0);
  return { weightedAverage, roundedLevel, priorityGaps };
}

// --- Tiny assertion helper, no framework needed ---
let passed = 0, failed = 0;
function assertEqual(actual, expected, label) {
  const ok = JSON.stringify(actual) === JSON.stringify(expected);
  if (ok) { passed++; console.log('  PASS  ' + label); }
  else {
    failed++;
    console.log('  FAIL  ' + label);
    console.log('        expected: ' + JSON.stringify(expected));
    console.log('        actual:   ' + JSON.stringify(actual));
  }
}
function assertClose(actual, expected, tolerance, label) {
  const ok = Math.abs(actual - expected) <= tolerance;
  if (ok) { passed++; console.log('  PASS  ' + label); }
  else {
    failed++;
    console.log('  FAIL  ' + label + ' (expected ~' + expected + ', got ' + actual + ')');
  }
}

console.log('Test 1: REQUIREMENTS.md §12 worked example (Financial Services)');
{
  const scores = {
    ownership: 3, policy: 3, inventory: 4, dependencies: 2, backup: 3, access: 3,
    monitoring: 2, command: 2, communication: 2, procedures: 3, testing: 2, review: 2
  };
  const result = computeMaturityScore(scores, FINANCIAL_WEIGHTS);
  assertClose(result.weightedAverage, 2.56, 0.01, 'weighted average is 2.56');
  assertEqual(result.roundedLevel, 3, 'rounds to Level 3 (Defined)');
  const gapIds = result.priorityGaps.map(g => g.id).sort();
  assertEqual(gapIds, ['command', 'communication', 'review', 'testing'].sort(),
    'priority gaps are communication (6.0) + the three-way tie at 4.5 (command, testing, review)');
}

console.log('');
console.log('Test 2: an org meeting every target perfectly scores 5.0, Level 5');
{
  const scores = {};
  DIMENSION_IDS.forEach(id => { scores[id] = 5; });
  const result = computeMaturityScore(scores, FINANCIAL_WEIGHTS);
  assertEqual(result.weightedAverage, 5, 'weighted average is exactly 5');
  assertEqual(result.roundedLevel, 5, 'rounds to Level 5 (Optimised)');
  assertEqual(result.priorityGaps.length, 0, 'no priority gaps when every dimension is perfect');
}

console.log('');
console.log('Test 3: an org at rock bottom scores 1.0, Level 1, gaps ranked by weight');
{
  const scores = {};
  DIMENSION_IDS.forEach(id => { scores[id] = 1; });
  const result = computeMaturityScore(scores, FINANCIAL_WEIGHTS);
  assertEqual(result.weightedAverage, 1, 'weighted average is exactly 1');
  assertEqual(result.roundedLevel, 1, 'rounds to Level 1 (Ad hoc)');
  // At uniform score=1, gap = 4 * weight, so the two highest-weighted
  // dimensions (policy and communication, both 2.0) should top the list.
  const topTwoIds = result.priorityGaps.slice(0, 2).map(g => g.id).sort();
  assertEqual(topTwoIds, ['communication', 'policy'].sort(),
    'the two highest-weighted dimensions (2.0 each) top the priority list');
}

console.log('');
console.log('Test 4: partial answers (not all 12 done) only average the answered ones');
{
  const result = computeMaturityScore({ ownership: 4, policy: 4 }, FINANCIAL_WEIGHTS);
  // (4*1.5 + 4*2.0) / (1.5+2.0) = 14/3.5 = 4.0
  assertClose(result.weightedAverage, 4.0, 0.01, 'only answered dimensions count toward the average');
}

console.log('');
console.log(passed + ' passed, ' + failed + ' failed');
if (failed > 0) process.exit(1);
