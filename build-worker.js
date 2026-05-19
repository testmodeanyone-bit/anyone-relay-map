#!/usr/bin/env node
// build-worker.js — combine a shell .js (worker route handlers, the parts
// outside the embedded SPA) with a standalone index.html to produce the
// deployable worker source.
//
// Usage:  node build-worker.js <shell.js> <index.html> <out.js>
//
// The shell file MUST contain the literal placeholder:
//   const html = "__INDEX_HTML_PLACEHOLDER__";
// This placeholder gets replaced with the JSON.stringify-encoded contents of index.html.
//
// The built output is prepended with an AUTO-GENERATED warning so anyone
// who opens anyonemap-worker.js directly knows it should not be hand-edited.
//
// Pairs with extract-html.js which goes the other direction.

const fs = require('fs');

if (process.argv.length < 5) {
  console.error('usage: node build-worker.js <shell.js> <index.html> <out.js>');
  process.exit(2);
}
const [shellPath, htmlPath, outPath] = process.argv.slice(2);

const shell = fs.readFileSync(shellPath, 'utf8');
const html = fs.readFileSync(htmlPath, 'utf8');

const placeholder = 'const html = "__INDEX_HTML_PLACEHOLDER__";';
if (!shell.includes(placeholder)) {
  console.error('shell file missing required placeholder:\n  ' + placeholder);
  process.exit(1);
}

// JSON.stringify produces a valid JS string literal for any JS string,
// using \uNNNN for non-ASCII below BMP and \uD8XX\uDCXX surrogate pairs
// for codepoints above. This is exactly the format the worker source uses.
const replacement = 'const html = ' + JSON.stringify(html) + ';';

const body = shell.replace(placeholder, replacement);

// Prepend AUTO-GENERATED warning. Anyone reading the committed
// anyonemap-worker.js should immediately understand they shouldn't edit it
// directly — the source files are worker-shell.js + index.html.
const generatedHeader = [
  '/* ============================================================================',
  ' * anyonemap-worker.js — AUTO-GENERATED. DO NOT EDIT BY HAND.',
  ' * ============================================================================',
  ' *',
  ' * This file is the deployable Cloudflare Worker. It is built from:',
  ' *   - worker-shell.js  (worker logic and request handlers)',
  ' *   - index.html       (the SPA — HTML+CSS+JS in one document)',
  ' *',
  ' * To make a change:',
  ' *   1. Edit worker-shell.js OR index.html',
  ' *   2. Run: node scripts/build-worker.js worker-shell.js index.html anyonemap-worker.js',
  ' *   3. Commit the result of step 2 alongside the source change',
  ' *',
  ' * CI verifies that this file matches the build output of worker-shell.js +',
  ' * index.html on every push/PR. Direct edits will be rejected by CI.',
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
  ' + html=' + html.length.toLocaleString() +
  ' (+ header ' + generatedHeader.length + ')' +
  ' = ' + out.length.toLocaleString() + ' bytes'
);
