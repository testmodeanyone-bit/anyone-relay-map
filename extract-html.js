#!/usr/bin/env node
// extract-html.js — given a worker source file, extract the `const html = "..."`
// embedded SPA into a standalone .html file.
//
// Usage:  node extract-html.js <worker.js> <out.html>
//
// Pairs with build-worker.js which goes the other direction.

const fs = require('fs');

if (process.argv.length < 4) {
  console.error('usage: node extract-html.js <worker.js> <out.html>');
  process.exit(2);
}
const [workerPath, outPath] = process.argv.slice(2);
const src = fs.readFileSync(workerPath, 'utf8');

// Find the `const html = "` declaration. The string is single-line and uses
// JS literal escapes (\", \\, \n, \u, etc.). We walk from the opening quote
// to the matching closing quote, respecting backslash escapes.
const startMarker = 'const html = "';
const startIdx = src.indexOf(startMarker);
if (startIdx === -1) {
  console.error('could not find `const html = "` in ' + workerPath);
  process.exit(1);
}
const litStart = startIdx + startMarker.length - 1;  // index of the opening "
let i = litStart + 1;
while (i < src.length) {
  if (src[i] === '\\') { i += 2; continue; }
  if (src[i] === '"') break;
  i++;
}
const litEnd = i;  // index of the closing "
const literal = src.slice(litStart, litEnd + 1);

// Parse the JS string literal via JSON.parse (works because JSON literals are
// a subset of JS string literals for our escape vocabulary).
let html;
try {
  html = JSON.parse(literal);
} catch (e) {
  // Some workers use \x escapes or other JS-only forms. Fall back to indirect eval.
  // Safe here because we're processing our own code.
  html = (0, eval)(literal);
}

fs.writeFileSync(outPath, html, 'utf8');
console.error('Extracted ' + html.length.toLocaleString() + ' chars to ' + outPath);
