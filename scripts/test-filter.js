#!/usr/bin/env node
/*
 * scripts/test-filter.js
 *
 * Tests the quarantine filter (applyQuarantineFilter + its centroid blocklists
 * and helpers) that lives inside anyclip-proxy-worker.js.
 *
 * HOW IT WORKS
 * The filter is embedded in a 498KB Cloudflare Worker ES module that can't be
 * require()'d in a plain Node process (it has an `export default` handler, KV
 * bindings, etc.). So instead of testing a hand-maintained replica (which would
 * silently drift from the real code), this test EXTRACTS the actual filter
 * region from the worker source at runtime and evaluates it in isolation. That
 * means if anyone edits a centroid coordinate, flips a comparison, or changes
 * the epsilon, this test runs the changed code and catches it.
 *
 * Run:   node scripts/test-filter.js
 * Exit:  0 = all pass, 1 = any failure (CI-friendly)
 *
 * No dependencies — Node standard library only.
 */

'use strict';

const fs = require('fs');
const path = require('path');

const WORKER_PATH = path.join(__dirname, '..', 'anyclip-proxy-worker.js');

// ---------------------------------------------------------------------------
// Extract the filter region from the worker source.
// Region runs from the first centroid array declaration through the closing
// brace of applyQuarantineFilter, located by brace-counting.
// ---------------------------------------------------------------------------
function extractFilter(src) {
  const startIdx = src.indexOf('const CENTROID_BLOCKLIST_HIGH');
  if (startIdx < 0) throw new Error('Could not find CENTROID_BLOCKLIST_HIGH in worker source');

  const fnIdx = src.indexOf('function applyQuarantineFilter', startIdx);
  if (fnIdx < 0) throw new Error('Could not find applyQuarantineFilter in worker source');

  let i = src.indexOf('{', fnIdx);
  if (i < 0) throw new Error('Could not find opening brace of applyQuarantineFilter');
  let depth = 0, endIdx = -1;
  for (; i < src.length; i++) {
    if (src[i] === '{') depth++;
    else if (src[i] === '}') { depth--; if (depth === 0) { endIdx = i + 1; break; } }
  }
  if (endIdx < 0) throw new Error('Could not find matching closing brace of applyQuarantineFilter');

  const region = src.slice(startIdx, endIdx);

  // Evaluate the region and return the public symbols. Using new Function keeps
  // the eval scoped and avoids leaking into the module scope.
  // eslint-disable-next-line no-new-func
  const factory = new Function(
    region +
    '\n; return { applyQuarantineFilter, CENTROID_BLOCKLIST_HIGH, CENTROID_BLOCKLIST_MEDIUM, COORD_MATCH_EPSILON, CLUSTER_THRESHOLD };'
  );
  return factory();
}

// ---------------------------------------------------------------------------
// Tiny assertion harness
// ---------------------------------------------------------------------------
const results = [];
function assert(name, cond, detail) {
  results.push({ name, pass: !!cond, detail: cond ? undefined : detail });
}

// ---------------------------------------------------------------------------
// Load + extract
// ---------------------------------------------------------------------------
let api;
try {
  const src = fs.readFileSync(WORKER_PATH, 'utf8');
  api = extractFilter(src);
} catch (e) {
  console.error('FATAL: could not extract filter from worker source:');
  console.error('  ' + e.message);
  process.exit(1);
}

const applyQuarantineFilter = api.applyQuarantineFilter;
if (typeof applyQuarantineFilter !== 'function') {
  console.error('FATAL: applyQuarantineFilter is not a function after extraction');
  process.exit(1);
}

// ---------------------------------------------------------------------------
// Sanity: the extracted blocklists match expected shape/size. If someone adds
// or removes a centroid, update these numbers deliberately.
// ---------------------------------------------------------------------------
assert('HIGH blocklist has 4 entries', api.CENTROID_BLOCKLIST_HIGH.length === 4,
  'got ' + api.CENTROID_BLOCKLIST_HIGH.length);
assert('MEDIUM blocklist has 4 entries', api.CENTROID_BLOCKLIST_MEDIUM.length === 4,
  'got ' + api.CENTROID_BLOCKLIST_MEDIUM.length);
assert('epsilon is 0.001', api.COORD_MATCH_EPSILON === 0.001, 'got ' + api.COORD_MATCH_EPSILON);
assert('cluster threshold is 50', api.CLUSTER_THRESHOLD === 50, 'got ' + api.CLUSTER_THRESHOLD);

// ---------------------------------------------------------------------------
// Behavioural tests
// ---------------------------------------------------------------------------

// T1: US centroid (Pedro's case) -> quarantined_high, coords nulled
{
  const out = applyQuarantineFilter({ X: { hexId: 'h', coordinates: [37.7684, -97.5634], countryCode: 'US' } });
  assert('US centroid -> quarantined_centroid_high', out.filtered.X.geoQuality === 'quarantined_centroid_high', out.filtered.X.geoQuality);
  assert('US centroid -> coordinates nulled', out.filtered.X.coordinates === null, JSON.stringify(out.filtered.X.coordinates));
  assert('US centroid -> countryCode nulled', out.filtered.X.countryCode === null, JSON.stringify(out.filtered.X.countryCode));
}

// T2: each remaining HIGH centroid -> quarantined_high
[[46.9803, 9.5512, 'LI'], [42.5240, 1.6166, 'AD'], [44.0385, 12.2915, 'SM']].forEach(function (t) {
  const out = applyQuarantineFilter({ X: { hexId: 'h', coordinates: [t[0], t[1]], countryCode: t[2] } });
  assert(t[2] + ' centroid -> quarantined_centroid_high', out.filtered.X.geoQuality === 'quarantined_centroid_high', out.filtered.X.geoQuality);
});

// T3: a real relay with city + AS at normal coords -> trusted, coords preserved
{
  const out = applyQuarantineFilter({ X: { hexId: 'h', coordinates: [52.3702, 4.8952], countryCode: 'NL', cityName: 'Amsterdam', asNumber: 14061 } });
  assert('real relay -> trusted', out.filtered.X.geoQuality === 'trusted', out.filtered.X.geoQuality);
  assert('real relay -> coordinates preserved', Array.isArray(out.filtered.X.coordinates), JSON.stringify(out.filtered.X.coordinates));
}

// T4: a MEDIUM centroid with supplemental data and no cluster -> must NOT quarantine
//     (guards against over-quarantining legitimate relays that merely sit near a centroid)
{
  const out = applyQuarantineFilter({ X: { hexId: 'h', coordinates: [49.7700, 6.0547], countryCode: 'LU', cityName: 'Luxembourg City', asNumber: 1234 } });
  assert('LU centroid w/ city + no cluster -> trusted', out.filtered.X.geoQuality === 'trusted', out.filtered.X.geoQuality);
}

// T5: a MEDIUM centroid WITH a large no-supplemental cluster -> quarantined_medium
{
  const bulk = {};
  for (let n = 0; n < 60; n++) bulk['F' + n] = { hexId: 'h' + n, coordinates: [49.7700, 6.0547], countryCode: 'LU' };
  const out = applyQuarantineFilter(bulk);
  const anyMed = Object.keys(out.filtered).some(function (k) { return out.filtered[k].geoQuality === 'quarantined_centroid_medium'; });
  assert('LU cluster (60x, no supplemental) -> quarantined_centroid_medium', anyMed, 'stats=' + JSON.stringify(out.stats));
}

// T6: null coordinates -> trusted, no crash
{
  const out = applyQuarantineFilter({ X: { hexId: 'h', coordinates: null, countryCode: null } });
  assert('null coordinates -> trusted (no crash)', out.filtered.X.geoQuality === 'trusted', out.filtered.X.geoQuality);
}

// T7: garbage relay (null) -> preserved, no crash
{
  const out = applyQuarantineFilter({ X: null });
  assert('null relay value -> preserved (no crash)', out.filtered.X === null, JSON.stringify(out.filtered.X));
}

// T8: fail-open on bad top-level input
{
  let out = applyQuarantineFilter('not an object');
  assert('string input -> fail-open invalid_input', out.stats && out.stats.error === 'invalid_input', JSON.stringify(out.stats));
  out = applyQuarantineFilter(null);
  assert('null input -> fail-open invalid_input', out.stats && out.stats.error === 'invalid_input', JSON.stringify(out.stats));
  out = applyQuarantineFilter([1, 2, 3]);
  assert('array input -> fail-open invalid_input', out.stats && out.stats.error === 'invalid_input', JSON.stringify(out.stats));
}

// T9: a coordinate just outside the epsilon must NOT be quarantined (boundary test)
{
  const out = applyQuarantineFilter({ X: { hexId: 'h', coordinates: [37.7684 + 0.01, -97.5634], countryCode: 'US' } });
  assert('coord 0.01 off US centroid -> trusted (epsilon boundary)', out.filtered.X.geoQuality === 'trusted', out.filtered.X.geoQuality);
}

// T10: stats totals are internally consistent
{
  const out = applyQuarantineFilter({
    A: { hexId: 'h', coordinates: [37.7684, -97.5634] },                                  // high
    B: { hexId: 'h', coordinates: [52.3702, 4.8952], cityName: 'AMS', asNumber: 1 },      // trusted
    C: { hexId: 'h', coordinates: [46.9803, 9.5512] }                                     // high
  });
  const s = out.stats;
  const sum = s.trusted + s.quarantined_centroid_high + s.quarantined_centroid_medium + s.flagged_cluster_no_supplemental;
  assert('stats components sum to totalRelays', sum === s.totalRelays, 'sum=' + sum + ' total=' + s.totalRelays);
  assert('stats counts 2 high in mixed input', s.quarantined_centroid_high === 2, 'got ' + s.quarantined_centroid_high);
  assert('stats counts 1 trusted in mixed input', s.trusted === 1, 'got ' + s.trusted);
}

// T11: input object is not mutated (filter must return a copy, not edit in place)
{
  const input = { X: { hexId: 'h', coordinates: [37.7684, -97.5634], countryCode: 'US' } };
  applyQuarantineFilter(input);
  assert('input not mutated (coords intact on original)',
    Array.isArray(input.X.coordinates) && input.X.coordinates[0] === 37.7684,
    JSON.stringify(input.X.coordinates));
}

// ---------------------------------------------------------------------------
// Report
// ---------------------------------------------------------------------------
const passed = results.filter(function (r) { return r.pass; }).length;
const failed = results.length - passed;

console.log('');
console.log('quarantine filter tests (extracted from anyclip-proxy-worker.js)');
console.log('-----------------------------------------------------------------');
results.forEach(function (r) {
  const tag = r.pass ? 'PASS' : 'FAIL';
  console.log('  [' + tag + '] ' + r.name + (r.pass ? '' : '   -> got: ' + r.detail));
});
console.log('-----------------------------------------------------------------');
console.log('  ' + passed + '/' + results.length + ' passed' + (failed ? (', ' + failed + ' FAILED') : ''));
console.log('');

process.exit(failed ? 1 : 0);
