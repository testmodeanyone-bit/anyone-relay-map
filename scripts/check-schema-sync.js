#!/usr/bin/env node
/* ============================================================================
 * check-schema-sync.js — CI guard for the cross-worker KV schema contract
 * ============================================================================
 *
 * THE BUG THIS PREVENTS (seam "S4"):
 *   kv-schema.js is the single source of truth for the exit-relays:latest KV
 *   contract. Both built workers INLINE a copy of it at build time (wrapped in
 *   `const _kvSchema = (function(){ ... })();`). There is no runtime import —
 *   each deployed worker carries its own frozen copy.
 *
 *   A copy can therefore go STALE: if canonical changes (e.g. the v54-fix that
 *   retyped zones/countries/isps from 'object' to 'number') and a worker is not
 *   rebuilt+redeployed, its inlined copy silently disagrees with canonical and
 *   with the other worker. That exact skew shipped to production: the producer
 *   said 'number', the deployed consumer still said 'object', and the consumer's
 *   permissive-read extract() discarded every real count as "wrong-typed",
 *   substituting null. No crash, just silently wrong data on the map.
 *
 *   The pre-existing guard (referenced in the producer header) apparently only
 *   covered the producer build, so a stale CONSUMER slipped through. This script
 *   closes that blind spot by checking EVERY built worker against canonical.
 *
 * HOW IT WORKS:
 *   1. Load canonical kv-schema.js via require() to get the real exported
 *      EXIT_RELAYS_LATEST object (types, required flags, key, version).
 *   2. For each built worker, slice out the inlined IIFE text between the
 *      `const _kvSchema = (function() {` open marker and its matching `})();`
 *      close, evaluate it in an isolated vm context, and read back the SAME
 *      exported object the running worker would use.
 *   3. Deep-compare: SNAPSHOT_KEY, SCHEMA_VERSION, the exact set of field names,
 *      and each field's `type` + `required`. Any mismatch is a hard failure.
 *
 *   We compare the EXECUTED schema objects, not the source text — so harmless
 *   formatting differences introduced by the build (whitespace, minification,
 *   reordering) never cause false failures. Only a real semantic drift fails.
 *
 * EXIT CODES:
 *   0  all built workers match canonical
 *   1  at least one worker drifted (prints a precise per-field diff)
 *   2  a structural/IO error (file missing, markers not found, eval threw) —
 *      treated as failure so CI never green-lights on a broken check.
 *
 * USAGE (run from repo root, in CI on every push/PR):
 *   node scripts/check-schema-sync.js
 *
 *   Defaults assume canonical at ./kv-schema.js and the two built workers at
 *   ./anyonemap-worker.js and ./anyclip-proxy-worker.js. Override via env or
 *   args if your layout differs:
 *     CANONICAL=path  WORKERS="a.js,b.js"  node scripts/check-schema-sync.js
 *     node scripts/check-schema-sync.js --canonical path --workers a.js b.js
 * ============================================================================
 */

'use strict';

const fs = require('fs');
const path = require('path');
const vm = require('vm');

/* ── config: where to find the files ─────────────────────────────────────── */

function parseConfig(argv) {
  const cfg = {
    canonical: process.env.CANONICAL || 'kv-schema.js',
    workers: (process.env.WORKERS
      ? process.env.WORKERS.split(',').map((s) => s.trim()).filter(Boolean)
      : ['anyonemap-worker.js', 'anyclip-proxy-worker.js']),
  };
  for (let i = 2; i < argv.length; i++) {
    if (argv[i] === '--canonical') { cfg.canonical = argv[++i]; }
    else if (argv[i] === '--workers') {
      const list = [];
      while (i + 1 < argv.length && !argv[i + 1].startsWith('--')) list.push(argv[++i]);
      if (list.length) cfg.workers = list;
    }
  }
  return cfg;
}

/* ── extract the inlined _kvSchema IIFE from a built worker and run it ────── */

const OPEN_MARKER = 'const _kvSchema = (function() {';
const CLOSE_MARKER = '})();';

/* Pull out the source of the IIFE body, evaluate it in isolation, and return
 * the object literal it produces (the same one the worker assigns to _kvSchema).
 * We reconstruct `(function(){ ... })()` from the inlined text so the result is
 * exactly what the running worker computes — no assumptions about field order
 * or formatting. */
function extractInlinedSchema(workerPath) {
  const src = fs.readFileSync(workerPath, 'utf8');
  const openIdx = src.indexOf(OPEN_MARKER);
  if (openIdx === -1) {
    throw new Error(`could not find inlined-schema open marker "${OPEN_MARKER}"`);
  }
  /* The IIFE opens with `(function() {` right after `const _kvSchema = `.
   * Find the matching close marker AFTER the open. The close marker `})();`
   * appears many times in a bundled worker, so we scan forward from the open
   * and take the FIRST one that sits at the start of a line (the canonical
   * file's IIFE is closed by a line that is exactly ` })();`). */
  const afterOpen = openIdx + OPEN_MARKER.length;
  const lines = src.slice(afterOpen).split('\n');
  let bodyLines = [];
  let found = false;
  for (const line of lines) {
    if (line.trim() === CLOSE_MARKER) { found = true; break; }
    bodyLines.push(line);
  }
  if (!found) {
    throw new Error(`could not find matching close marker "${CLOSE_MARKER}" after open`);
  }
  const iifeBody = bodyLines.join('\n');

  /* Run `(function(){ <body> })()` in a fresh sandbox. The canonical body ends
   * with `return { SCHEMA_VERSION, SNAPSHOT_KEY, EXIT_RELAYS_LATEST, validate,
   * extract };` so the IIFE evaluates to that object. Provide a minimal module
   * shim because the body's tail has an `if (typeof module !== 'undefined' ...)`
   * guard; in IIFE-return form that branch is harmless but module must exist
   * as undefined-or-object without throwing. */
  const wrapped = `(function() {\n${iifeBody}\n})()`;
  const sandbox = { module: undefined, Date };
  vm.createContext(sandbox);
  let result;
  try {
    result = vm.runInContext(wrapped, sandbox, { filename: workerPath, timeout: 2000 });
  } catch (e) {
    throw new Error(`evaluating inlined schema threw: ${e.message}`);
  }
  if (!result || typeof result !== 'object' || !result.EXIT_RELAYS_LATEST) {
    throw new Error('inlined schema did not produce an EXIT_RELAYS_LATEST export');
  }
  return result;
}

/* ── load canonical via require (it's a normal CommonJS module) ───────────── */

function loadCanonical(canonicalPath) {
  const abs = path.resolve(canonicalPath);
  delete require.cache[abs];
  const mod = require(abs);
  if (!mod || !mod.EXIT_RELAYS_LATEST) {
    throw new Error('canonical kv-schema.js did not export EXIT_RELAYS_LATEST');
  }
  return mod;
}

/* ── compare one worker's schema against canonical ───────────────────────── */

/* Returns an array of human-readable diff strings. Empty array == in sync.
 * We compare the things that change RUNTIME BEHAVIOUR: the key, the version,
 * the exact field set, and each field's type + required flag. We deliberately
 * do NOT compare `default` or `sanity` — those are functions/sentinels that the
 * permissive reader uses identically regardless of formatting, and comparing
 * function source would produce noisy false positives. `type` and `required`
 * are what caused S1 and are what the validator branches on. */
function diffSchema(canonical, worker) {
  const diffs = [];

  if (canonical.SNAPSHOT_KEY !== worker.SNAPSHOT_KEY) {
    diffs.push(`SNAPSHOT_KEY: canonical "${canonical.SNAPSHOT_KEY}" != worker "${worker.SNAPSHOT_KEY}"`);
  }
  if (canonical.SCHEMA_VERSION !== worker.SCHEMA_VERSION) {
    diffs.push(`SCHEMA_VERSION: canonical "${canonical.SCHEMA_VERSION}" != worker "${worker.SCHEMA_VERSION}" (non-fatal drift, but indicates a stale build)`);
  }

  const cFields = canonical.EXIT_RELAYS_LATEST.fields || {};
  const wFields = worker.EXIT_RELAYS_LATEST.fields || {};
  const cNames = Object.keys(cFields).sort();
  const wNames = Object.keys(wFields).sort();

  for (const name of cNames) {
    if (!(name in wFields)) { diffs.push(`field "${name}": present in canonical, MISSING in worker`); continue; }
    const c = cFields[name], w = wFields[name];
    if (c.type !== w.type) {
      diffs.push(`field "${name}".type: canonical '${c.type}' != worker '${w.type}'  <-- this is the S1-class bug`);
    }
    if (!!c.required !== !!w.required) {
      diffs.push(`field "${name}".required: canonical ${!!c.required} != worker ${!!w.required}`);
    }
  }
  for (const name of wNames) {
    if (!(name in cFields)) diffs.push(`field "${name}": present in worker, NOT in canonical (worker is ahead, or canonical lost a field)`);
  }

  return diffs;
}

/* ── main ────────────────────────────────────────────────────────────────── */

function main() {
  const cfg = parseConfig(process.argv);
  let canonical;
  try {
    canonical = loadCanonical(cfg.canonical);
  } catch (e) {
    console.error(`[check-schema-sync] FATAL: cannot load canonical ${cfg.canonical}: ${e.message}`);
    process.exit(2);
  }

  let anyDrift = false;
  let anyError = false;

  for (const workerPath of cfg.workers) {
    if (!fs.existsSync(workerPath)) {
      console.error(`[check-schema-sync] ERROR: built worker not found: ${workerPath}`);
      anyError = true;
      continue;
    }
    let worker;
    try {
      worker = extractInlinedSchema(workerPath);
    } catch (e) {
      console.error(`[check-schema-sync] ERROR in ${workerPath}: ${e.message}`);
      anyError = true;
      continue;
    }
    const diffs = diffSchema(canonical, worker);
    if (diffs.length === 0) {
      console.log(`[check-schema-sync] OK    ${workerPath} — inlined schema matches canonical`);
    } else {
      anyDrift = true;
      console.error(`[check-schema-sync] DRIFT ${workerPath} — inlined schema is STALE, rebuild this worker:`);
      for (const d of diffs) console.error(`    - ${d}`);
    }
  }

  if (anyError) {
    console.error('[check-schema-sync] FAILED: structural error(s) above — treating as failure so CI does not pass on a broken check.');
    process.exit(2);
  }
  if (anyDrift) {
    console.error('[check-schema-sync] FAILED: at least one worker carries a stale inlined schema.');
    console.error('    Fix: rebuild the drifted worker(s) from current sources, e.g.');
    console.error('      node scripts/build-worker.js worker-shell.js kv-schema.js index.html anyonemap-worker.js');
    console.error('    then commit the regenerated output.');
    process.exit(1);
  }
  console.log('[check-schema-sync] PASS: all built workers in sync with canonical kv-schema.js');
  process.exit(0);
}

main();
