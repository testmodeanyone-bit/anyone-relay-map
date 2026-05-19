#!/usr/bin/env node
/* check-schema-sync.js — CI guard for KV schema drift between producer and consumer
 *
 * Anyclip-proxy-worker.js contains an inlined copy of kv-schema.js between sentinel
 * markers (no build step for that file — direct paste-deploy). This guard verifies
 * the inlined copy matches the canonical scripts/kv-schema.js byte-for-byte. Drift
 * means producer and consumer have desynchronized schemas, which is the exact
 * failure mode this whole exercise was meant to prevent.
 *
 * (Consumer side — worker-shell.js → anyonemap-worker.js — is verified differently:
 *  the schema gets re-inlined by build-worker.js on every build, so the existing
 *  build-verify CI step already catches drift there. This script only guards the
 *  anyclip-proxy side, which has no build step.)
 *
 * Exit codes:
 *   0 — inline copy matches canonical
 *   1 — drift detected (prints location of first difference)
 *   2 — missing files or malformed markers (configuration error)
 *
 * Run via:
 *   node scripts/check-schema-sync.js
 * Wired into .github/workflows/check-dupes.yml as a required step.
 */

const fs = require('fs');
const path = require('path');

const SCHEMA_FILE = path.join(__dirname, '..', 'kv-schema.js');  /* kv-schema.js lives at repo root, not in scripts/ */
const TARGET = path.join(__dirname, '..', 'anyclip-proxy-worker.js');

const BEGIN_MARKER = '// === BEGIN KV_SCHEMA_INLINE (canonical: scripts/kv-schema.js — verified by scripts/check-schema-sync.js) ===';
const END_MARKER = '// === END KV_SCHEMA_INLINE ===';

/* Adapt the canonical schema source into the form it should take inside the inline
 * block: strip the module.exports postscript, wrap in an IIFE that returns the
 * public exports. This must produce the IDENTICAL block that's expected in the
 * target. If you change the wrapping format here, also change sync-schema.js (if
 * we add one later) and the existing inline blocks. */
function buildExpectedInline(schemaSrc) {
  const cutoff = schemaSrc.indexOf("if (typeof module !== 'undefined' && module.exports)");
  if (cutoff < 0) {
    throw new Error('canonical kv-schema.js missing module.exports marker');
  }
  const body = schemaSrc.slice(0, cutoff).trimEnd();
  const iife = [
    'const _kvSchema = (function() {',
    body,
    '  return { SCHEMA_VERSION, SNAPSHOT_KEY, EXIT_RELAYS_LATEST, validate, extract };',
    '})();'
  ].join('\n');
  /* The inline block in anyclip-proxy uses CRLF line endings to match the rest of
   * that file. Normalize before comparing — drift in line endings alone is not a
   * meaningful diff. */
  return iife;
}

/* Read content between sentinel markers from a file. Returns the raw bytes
 * (whatever line endings) so we can normalize for comparison. */
function extractInlineBlock(src) {
  const beginIdx = src.indexOf(BEGIN_MARKER);
  const endIdx = src.indexOf(END_MARKER);
  if (beginIdx < 0) return { ok: false, reason: 'missing BEGIN marker' };
  if (endIdx < 0) return { ok: false, reason: 'missing END marker' };
  if (endIdx < beginIdx) return { ok: false, reason: 'END marker before BEGIN' };
  /* Slice from after BEGIN line to start of END line. */
  const afterBegin = beginIdx + BEGIN_MARKER.length;
  const block = src.slice(afterBegin, endIdx).trim();
  return { ok: true, block: block };
}

function normalize(s) {
  return s.replace(/\r\n/g, '\n').trim();
}

function main() {
  if (!fs.existsSync(SCHEMA_FILE)) {
    console.error('ERROR: canonical schema file not found:', SCHEMA_FILE);
    process.exit(2);
  }
  if (!fs.existsSync(TARGET)) {
    console.error('ERROR: target not found:', TARGET);
    process.exit(2);
  }

  const schemaSrc = fs.readFileSync(SCHEMA_FILE, 'utf8');
  const expected = normalize(buildExpectedInline(schemaSrc));

  const targetSrc = fs.readFileSync(TARGET, 'utf8');
  const extraction = extractInlineBlock(targetSrc);
  if (!extraction.ok) {
    console.error('ERROR: ' + path.basename(TARGET) + ': ' + extraction.reason);
    process.exit(2);
  }
  const actual = normalize(extraction.block);

  if (actual === expected) {
    console.error('OK: anyclip-proxy-worker.js inline schema matches canonical (' + expected.length + ' bytes after normalize)');
    process.exit(0);
  }

  /* Drift. Report the first differing byte so the developer can find it fast. */
  let i = 0;
  while (i < Math.min(expected.length, actual.length) && expected[i] === actual[i]) i++;
  const exCtx = expected.slice(Math.max(0, i - 40), i + 40).replace(/\n/g, '\\n');
  const acCtx = actual.slice(Math.max(0, i - 40), i + 40).replace(/\n/g, '\\n');
  console.error('DRIFT: anyclip-proxy-worker.js inline schema differs from canonical');
  console.error('       expected length: ' + expected.length + ', actual: ' + actual.length);
  console.error('       first diff at byte ' + i + ':');
  console.error('         expected: ...' + exCtx + '...');
  console.error('         actual:   ...' + acCtx + '...');
  console.error('');
  console.error('Fix: re-inline the schema by editing scripts/kv-schema.js and pasting the');
  console.error('     updated content (wrapped in the IIFE) between the sentinel markers in');
  console.error('     anyclip-proxy-worker.js, then commit.');
  process.exit(1);
}

main();
