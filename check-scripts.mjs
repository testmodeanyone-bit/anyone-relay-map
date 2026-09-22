#!/usr/bin/env node
/* check-scripts.mjs — SPA syntax gate for build-worker.js
 *
 * Compiles every inline <script> block in an HTML file with V8 (node:vm) and
 * fails the build on the first one that does not parse. No dependencies.
 *
 * Why it exists: `node --check` on the BUILT worker cannot see a syntax error
 * inside index.html, because the SPA is embedded as a string literal. A broken
 * block kills every function declared in it and the map ships with a blank
 * canvas. This gate runs on the source before embedding and again on the
 * minified output (build-worker.js calls it twice).
 *
 * Usage: node check-scripts.mjs <index.html>   (exit 0 = all blocks parse)
 */
import fs from 'node:fs';
import vm from 'node:vm';

const file = process.argv[2];
if (!file) { console.error('usage: node check-scripts.mjs <index.html>'); process.exit(2); }
const html = fs.readFileSync(file, 'utf8');

/* Inline blocks only: no src=, and no type unless it is a JavaScript type.
 * JSON / importmap / template blocks are not JavaScript and are skipped. */
const re = /<script\b([^>]*)>([\s\S]*?)<\/script>/gi;
let m, n = 0, bad = 0;
const lineOf = (idx) => html.slice(0, idx).split('\n').length;

while ((m = re.exec(html)) !== null) {
  const attrs = m[1] || '';
  if (/\bsrc\s*=/.test(attrs)) continue;
  const type = (/\btype\s*=\s*["']?([^"'\s>]+)/i.exec(attrs) || [])[1];
  if (type && !/^(text\/javascript|application\/javascript|module)$/i.test(type)) continue;
  const code = m[2];
  const startLine = lineOf(m.index + m[0].indexOf('>') + 1);
  n++;
  try {
    if (/^module$/i.test(type || '')) {
      /* A module can use import/export; compile as a function body after
       * neutralising top-level import/export syntax is not safe, so use the
       * module compiler when the flag is available, else a classic parse of
       * the body minus import/export lines as a best effort. */
      if (typeof vm.SourceTextModule === 'function') new vm.SourceTextModule(code, { identifier: file });
      else new vm.Script(code.replace(/^\s*(import|export)\b.*$/gm, ''), { filename: file });
    } else {
      new vm.Script(code, { filename: file });
    }
  } catch (e) {
    bad++;
    /* V8 reports the line inside the block; translate to the file line. */
    const rel = new RegExp(file.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + ':(\\d+)').exec((e.stack || '').split('\n')[0] || '');
    const fileLine = rel ? startLine + Number(rel[1]) - 1 : startLine;
    console.error(`\x1b[31m✗ script block #${n} (starts line ${startLine}) does not parse\x1b[0m`);
    console.error(`  ${file}:${fileLine}: ${e.name}: ${e.message}`);
    const ctx = (e.stack || '').split('\n').slice(1, 3).join('\n  ');
    if (ctx) console.error('  ' + ctx);
  }
}
if (n === 0) { console.error('check-scripts: no inline <script> blocks found in ' + file); process.exit(1); }
if (bad) { console.error(`check-scripts: ${bad} of ${n} inline script block(s) failed to parse`); process.exit(1); }
console.log(`check-scripts: ${n} inline script blocks parse OK (${file})`);
