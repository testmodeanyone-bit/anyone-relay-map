#!/usr/bin/env node
/* ============================================================================
 * check-geo-schema-sync.js — CI guard for the geo:<fp> KV contract (seam S2)
 * ============================================================================
 *
 * Sibling of check-schema-sync.js. That guard covers exit-relays:latest
 * (kv-schema.js); THIS one covers the geo:<fp> records in the GEO_ENRICH
 * namespace (geo-schema.js), written by the enrichment worker and read by the
 * producer's enrichFromCache().
 *
 * Like its sibling, it loads canonical geo-schema.js, then for each worker
 * that INLINES a copy, slices out the inlined IIFE, executes it in isolation,
 * and deep-compares the two record-variant schemas (GEO_SUCCESS, GEO_TOMBSTONE)
 * field-by-field on `type` + `required`. Any drift is a hard failure.
 *
 * The inline marker differs from kv-schema's: the build inlines geo-schema as
 *   const _geoSchema = (function() { ... })();
 * Workers that do NOT inline geo-schema are skipped with a notice (not an
 * error) — only workers that actually carry a copy are checked, so this guard
 * can be added before every worker inlines it.
 *
 * EXIT CODES: 0 ok · 1 drift · 2 structural error (fails safe).
 *
 * USAGE:  node scripts/check-geo-schema-sync.js
 *   CANONICAL_GEO=path  WORKERS="a.js,b.js"  to override defaults.
 * ============================================================================
 */
'use strict';
const fs = require('fs');
const path = require('path');
const vm = require('vm');

function parseConfig(argv) {
  const cfg = {
    canonical: process.env.CANONICAL_GEO || 'geo-schema.js',
    workers: (process.env.WORKERS
      ? process.env.WORKERS.split(',').map((s) => s.trim()).filter(Boolean)
      : ['enrichment-worker_final.js', 'anyclip-proxy-worker.js']),
  };
  for (let i = 2; i < argv.length; i++) {
    if (argv[i] === '--canonical') cfg.canonical = argv[++i];
    else if (argv[i] === '--workers') {
      const list = [];
      while (i + 1 < argv.length && !argv[i + 1].startsWith('--')) list.push(argv[++i]);
      if (list.length) cfg.workers = list;
    }
  }
  return cfg;
}

const OPEN_MARKER = 'const _geoSchema = (function() {';
const CLOSE_MARKER = '})();';

/* Returns the inlined geo-schema export object, or null if this worker does
 * not inline geo-schema at all (which is allowed). */
function extractInlinedSchema(workerPath) {
  const src = fs.readFileSync(workerPath, 'utf8');
  const openIdx = src.indexOf(OPEN_MARKER);
  if (openIdx === -1) return null; /* worker doesn't inline geo-schema — skip */
  const afterOpen = openIdx + OPEN_MARKER.length;
  const lines = src.slice(afterOpen).split('\n');
  const bodyLines = [];
  let found = false;
  for (const line of lines) {
    if (line.trim() === CLOSE_MARKER) { found = true; break; }
    bodyLines.push(line);
  }
  if (!found) throw new Error('found geo-schema open marker but no matching close "' + CLOSE_MARKER + '"');
  const wrapped = '(function() {\n' + bodyLines.join('\n') + '\n})()';
  const sandbox = { module: undefined, Date };
  vm.createContext(sandbox);
  let result;
  try {
    result = vm.runInContext(wrapped, sandbox, { filename: workerPath, timeout: 2000 });
  } catch (e) {
    throw new Error('evaluating inlined geo-schema threw: ' + e.message);
  }
  if (!result || !result.GEO_SUCCESS || !result.GEO_TOMBSTONE) {
    throw new Error('inlined geo-schema did not produce GEO_SUCCESS / GEO_TOMBSTONE');
  }
  return result;
}

function loadCanonical(p) {
  const abs = path.resolve(p);
  delete require.cache[abs];
  const mod = require(abs);
  if (!mod || !mod.GEO_SUCCESS || !mod.GEO_TOMBSTONE) {
    throw new Error('canonical geo-schema.js did not export GEO_SUCCESS / GEO_TOMBSTONE');
  }
  return mod;
}

function diffFields(label, cFields, wFields) {
  const diffs = [];
  for (const name of Object.keys(cFields).sort()) {
    if (!(name in wFields)) { diffs.push(label + '.' + name + ': in canonical, MISSING in worker'); continue; }
    const c = cFields[name], w = wFields[name];
    if (c.type !== w.type) diffs.push(label + '.' + name + '.type: canonical \'' + c.type + '\' != worker \'' + w.type + '\'');
    if (!!c.required !== !!w.required) diffs.push(label + '.' + name + '.required: canonical ' + !!c.required + ' != worker ' + !!w.required);
  }
  for (const name of Object.keys(wFields)) {
    if (!(name in cFields)) diffs.push(label + '.' + name + ': in worker, NOT in canonical');
  }
  return diffs;
}

function diffSchema(canonical, worker) {
  let diffs = [];
  if (canonical.GEO_SCHEMA_VERSION !== worker.GEO_SCHEMA_VERSION) {
    diffs.push('GEO_SCHEMA_VERSION: canonical "' + canonical.GEO_SCHEMA_VERSION + '" != worker "' + worker.GEO_SCHEMA_VERSION + '" (stale build)');
  }
  diffs = diffs.concat(diffFields('GEO_SUCCESS', canonical.GEO_SUCCESS.fields, worker.GEO_SUCCESS.fields));
  diffs = diffs.concat(diffFields('GEO_TOMBSTONE', canonical.GEO_TOMBSTONE.fields, worker.GEO_TOMBSTONE.fields));
  return diffs;
}

function main() {
  const cfg = parseConfig(process.argv);
  let canonical;
  try { canonical = loadCanonical(cfg.canonical); }
  catch (e) { console.error('[check-geo-schema-sync] FATAL: cannot load canonical ' + cfg.canonical + ': ' + e.message); process.exit(2); }

  let anyDrift = false, anyError = false, anyChecked = false;
  for (const wp of cfg.workers) {
    if (!fs.existsSync(wp)) { console.error('[check-geo-schema-sync] ERROR: worker not found: ' + wp); anyError = true; continue; }
    let worker;
    try { worker = extractInlinedSchema(wp); }
    catch (e) { console.error('[check-geo-schema-sync] ERROR in ' + wp + ': ' + e.message); anyError = true; continue; }
    if (worker === null) { console.log('[check-geo-schema-sync] SKIP  ' + wp + ' — does not inline geo-schema'); continue; }
    anyChecked = true;
    const diffs = diffSchema(canonical, worker);
    if (diffs.length === 0) console.log('[check-geo-schema-sync] OK    ' + wp + ' — inlined geo-schema matches canonical');
    else { anyDrift = true; console.error('[check-geo-schema-sync] DRIFT ' + wp + ' — STALE, rebuild this worker:'); for (const d of diffs) console.error('    - ' + d); }
  }

  if (anyError) { console.error('[check-geo-schema-sync] FAILED: structural error(s) above.'); process.exit(2); }
  if (anyDrift) { console.error('[check-geo-schema-sync] FAILED: stale inlined geo-schema. Rebuild the drifted worker(s).'); process.exit(1); }
  if (!anyChecked) console.log('[check-geo-schema-sync] NOTE: no worker inlines geo-schema yet — nothing to check (passing).');
  console.log('[check-geo-schema-sync] PASS');
  process.exit(0);
}
main();
