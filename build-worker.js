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

const out = shell.replace(placeholder, replacement);
fs.writeFileSync(outPath, out, 'utf8');

console.error(
  'Built ' + outPath +
  ': shell=' + shell.length.toLocaleString() +
  ' + html=' + html.length.toLocaleString() +
  ' = ' + out.length.toLocaleString() + ' bytes'
);
