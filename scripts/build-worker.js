#!/usr/bin/env node
// build-worker.js — combine a shell .js, a kv-schema.js, and an index.html
// into a single deployable Cloudflare Worker file.
//
// Usage:  node build-worker.js <shell.js> <kv-schema.js> <index.html> <out.js> [--no-bump|--dry-run-bump]
//
// Required placeholders in the shell file:
//   1.  const html = "__INDEX_HTML_PLACEHOLDER__";
//       → replaced with JSON.stringify(html) so the SPA renders inline
//   2.  const _kvSchema = __KV_SCHEMA_PLACEHOLDER__;
//       → replaced with an IIFE wrapping kv-schema.js, exposing
//         _kvSchema.validate(...) and _kvSchema.extract(...) etc.
//
// Version handling:
//   By default, this script auto-increments the WORKER_VERSION constant in
//   the shell file before building (e.g. v410 → v411) and writes that back
//   to disk. The built worker reflects the bumped version.
//
//   Flags:
//     --no-bump      Don't bump the version. Use this for CI build-verify
//                    which compares committed output to fresh-built — bumping
//                    every CI run would break that comparison.
//     --dry-run-bump Print what the next version would be and exit without
//                    writing anything. Useful for "what's the next version?"
//
//   The version constant MUST match /const\s+WORKER_VERSION\s*=\s*['"]v(\d+)['"]/.
//   Suffixed versions like "v410-beta" fail loudly rather than mis-bumping.
//   Reason: WORKER_VERSION drives the Service Worker cache key. Forgetting to
//   bump means PWA users serve stale precached HTML for up to 30 days (the
//   SW only updates on install→activate, which only triggers on a cache name
//   change). v408→v409→v410 today were all manual bumps; this automates them.

const fs = require('fs');

// Argument parsing: positional first, then flags.
const args = process.argv.slice(2);
const flags = new Set(args.filter(a => a.startsWith('--')));
const positional = args.filter(a => !a.startsWith('--'));
const noBump = flags.has('--no-bump');
const dryRunBump = flags.has('--dry-run-bump');

if (positional.length < 4) {
  console.error('usage: node build-worker.js <shell.js> <kv-schema.js> <index.html> <out.js> [--no-bump|--dry-run-bump]');
  process.exit(2);
}
const [shellPath, schemaPath, htmlPath, outPath] = positional;

let shell = fs.readFileSync(shellPath, 'utf8');
const schemaSrc = fs.readFileSync(schemaPath, 'utf8');
const html = fs.readFileSync(htmlPath, 'utf8');

// === Version bump ===
// Parse the current version. The regex matches both single and double quotes,
// and tolerates the spacing variations a careful or hurried developer would
// write. Bare numeric versions only — suffixed versions (v410-beta, v410.1)
// are intentionally rejected to avoid wrong-bumping a deliberate annotation.
const versionRe = /(const\s+WORKER_VERSION\s*=\s*['"])v(\d+)(['"]\s*;)/;
const versionMatch = shell.match(versionRe);
if (!versionMatch) {
  console.error('shell file missing WORKER_VERSION constant in expected form:');
  console.error('  const WORKER_VERSION = \'vNNN\';');
  console.error('If your version has a suffix (e.g. v410-beta), please bump manually.');
  process.exit(1);
}
const currentVersion = parseInt(versionMatch[2], 10);
const nextVersion = currentVersion + 1;

if (dryRunBump) {
  console.error('Current WORKER_VERSION: v' + currentVersion);
  console.error('Next WORKER_VERSION:    v' + nextVersion);
  console.error('(Dry run — no files modified.)');
  process.exit(0);
}

if (!noBump) {
  // Write the bumped shell file back to disk FIRST, then read it back. This
  // means the bump is persisted even if the build later fails, which is the
  // right behavior — a partial build still represents "I tried to ship v411,
  // it didn't work, fix it and rebuild as v411 not v412."
  shell = shell.replace(versionRe, '$1v' + nextVersion + '$3');
  fs.writeFileSync(shellPath, shell, 'utf8');
  console.error('Bumped WORKER_VERSION: v' + currentVersion + ' → v' + nextVersion + ' (in ' + shellPath + ')');
} else {
  console.error('Skipping version bump (--no-bump): WORKER_VERSION stays at v' + currentVersion);
}

// === Placeholder substitution ===

// Placeholder 1: HTML
const htmlPlaceholder = 'const html = "__INDEX_HTML_PLACEHOLDER__";';
if (!shell.includes(htmlPlaceholder)) {
  console.error('shell file missing required HTML placeholder:\n  ' + htmlPlaceholder);
  process.exit(1);
}
const htmlReplacement = 'const html = ' + JSON.stringify(html) + ';';

// Placeholder 2: KV Schema
const schemaPlaceholder = 'const _kvSchema = __KV_SCHEMA_PLACEHOLDER__;';
if (!shell.includes(schemaPlaceholder)) {
  console.error('shell file missing required schema placeholder:\n  ' + schemaPlaceholder);
  process.exit(1);
}

// Strip the module.exports block from kv-schema.js so the body works as an IIFE.
const exportsMarker = '/* Module exports';
const exportsIdx = schemaSrc.indexOf(exportsMarker);
if (exportsIdx < 0) {
  console.error('kv-schema.js missing expected "Module exports" marker comment');
  process.exit(1);
}
const schemaBody = schemaSrc.slice(0, exportsIdx);

const schemaIIFE = [
  '(function() {',
  schemaBody,
  '  return { SCHEMA_VERSION, SNAPSHOT_KEY, EXIT_RELAYS_LATEST, validate, extract };',
  '})()'
].join('\n');

const schemaReplacement = 'const _kvSchema = ' + schemaIIFE + ';';

let body = shell.replace(htmlPlaceholder, htmlReplacement);
body = body.replace(schemaPlaceholder, schemaReplacement);

const generatedHeader = [
  '/* ============================================================================',
  ' * anyonemap-worker.js — AUTO-GENERATED. DO NOT EDIT BY HAND.',
  ' * ============================================================================',
  ' *',
  ' * This file is the deployable Cloudflare Worker. It is built from:',
  ' *   - worker-shell.js  (worker logic and request handlers)',
  ' *   - kv-schema.js     (shared cross-worker KV schema and validators)',
  ' *   - index.html       (the SPA — HTML+CSS+JS in one document)',
  ' *',
  ' * To make a change:',
  ' *   1. Edit worker-shell.js, kv-schema.js, OR index.html',
  ' *   2. Run: node scripts/build-worker.js worker-shell.js kv-schema.js index.html anyonemap-worker.js',
  ' *      (Auto-bumps WORKER_VERSION. Pass --no-bump for a build that keeps the',
  ' *      current version — required when verifying that the committed output',
  ' *      matches a fresh build of the sources.)',
  ' *   3. Commit the result of step 2 alongside the source change',
  ' *',
  ' * CI verifies that this file matches the build output of the sources on',
  ' * every push/PR. Direct edits will be rejected by CI.',
  ' *',
  ' * Deploy by pasting this entire file into the Cloudflare Workers dashboard.',
  ' * ============================================================================',
  ' */',
  '',
  ''
].join('\n');

const out = generatedHeader + body;
fs.writeFileSync(outPath, out, 'utf8');

console.error(
  'Built ' + outPath +
  ' (v' + (noBump ? currentVersion : nextVersion) + ')' +
  ': shell=' + shell.length.toLocaleString() +
  ' + schema=' + schemaSrc.length.toLocaleString() +
  ' + html=' + html.length.toLocaleString() +
  ' (+ header ' + generatedHeader.length + ')' +
  ' = ' + out.length.toLocaleString() + ' bytes'
);
