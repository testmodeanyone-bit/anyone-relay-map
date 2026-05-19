#!/usr/bin/env node
// build-worker.js — combine a shell .js, a kv-schema.js, and an index.html
// into a single deployable Cloudflare Worker file.
//
// Usage:  node build-worker.js <shell.js> <kv-schema.js> <index.html> <out.js>
//
// Required placeholders in the shell file:
//   1.  const html = "__INDEX_HTML_PLACEHOLDER__";
//       → replaced with JSON.stringify(html) so the SPA renders inline
//   2.  const _kvSchema = __KV_SCHEMA_PLACEHOLDER__;
//       → replaced with an IIFE wrapping kv-schema.js, exposing
//         _kvSchema.validate(...) and _kvSchema.extract(...) etc.

const fs = require('fs');

if (process.argv.length < 6) {
  console.error('usage: node build-worker.js <shell.js> <kv-schema.js> <index.html> <out.js>');
  process.exit(2);
}
const [shellPath, schemaPath, htmlPath, outPath] = process.argv.slice(2);

const shell = fs.readFileSync(shellPath, 'utf8');
const schemaSrc = fs.readFileSync(schemaPath, 'utf8');
const html = fs.readFileSync(htmlPath, 'utf8');

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
  ': shell=' + shell.length.toLocaleString() +
  ' + schema=' + schemaSrc.length.toLocaleString() +
  ' + html=' + html.length.toLocaleString() +
  ' (+ header ' + generatedHeader.length + ')' +
  ' = ' + out.length.toLocaleString() + ' bytes'
);
