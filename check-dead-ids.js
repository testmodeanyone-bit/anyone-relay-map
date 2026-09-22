#!/usr/bin/env node
/* check-dead-ids.js — dead-id gate for build-worker.js
 *
 * Every getElementById('literal') / querySelector('#literal') in the SPA must
 * point at an id that exists somewhere in the file: a static id="…" attribute,
 * an id created in JS (el.id = '…', id: '…', `id="…"` inside a template
 * string, createElement + setAttribute('id', …)). A lookup whose id appears
 * nowhere always returns null, and the `if(!el) return;` guard in front of it
 * turns a rename into a silently dead feature.
 *
 * Usage: node check-dead-ids.js [--allow-file dead-ids.allow] <index.html>
 * Allow file: one id per line, `#` comments; use it for ids that exist only at
 * runtime for a documented reason. Exit 1 on any unallowed dead id.
 */
const fs = require('fs');

const args = process.argv.slice(2);
let allowFile = null;
const ai = args.indexOf('--allow-file');
if (ai !== -1) { allowFile = args[ai + 1]; args.splice(ai, 2); }
const file = args[0];
if (!file) { console.error('usage: node check-dead-ids.js [--allow-file f] <index.html>'); process.exit(2); }
const src = fs.readFileSync(file, 'utf8');

const allow = new Set();
if (allowFile && fs.existsSync(allowFile)) {
  for (const line of fs.readFileSync(allowFile, 'utf8').split('\n')) {
    const t = line.replace(/#.*/, '').trim(); if (t) allow.add(t);
  }
}

/* 1. ids that exist (any way an id can come into being) */
const defined = new Set();
const defRes = [
  /\bid\s*=\s*["']([A-Za-z_][\w:.-]*)["']/g,          // id="x" in HTML or template strings
  /\bid\s*=\s*([A-Za-z_][\w:.-]*)[\s>\/]/g,           // unquoted id=x
  /\.id\s*=\s*["'`]([A-Za-z_][\w:.-]*)["'`]/g,        // el.id = 'x'
  /\bid\s*:\s*["'`]([A-Za-z_][\w:.-]*)["'`]/g,        // { id: 'x' }
  /setAttribute\(\s*["']id["']\s*,\s*["'`]([A-Za-z_][\w:.-]*)["'`]/g,
];
for (const re of defRes) { let m; while ((m = re.exec(src)) !== null) defined.add(m[1]); }
/* an id assigned through a variable (var BAND_ID = 'x'; el.id = BAND_ID) — accept
 * any string literal equal to the id that is NOT itself a lookup argument */
const literalRe = /["'`]([A-Za-z_][\w:.-]*)["'`]/g;
const literals = new Set();
{ let m; while ((m = literalRe.exec(src)) !== null) {
    const before = src.slice(Math.max(0, m.index - 24), m.index);
    if (/getElementById\(\s*$|querySelector(?:All)?\(\s*$/.test(before)) continue;
    literals.add(m[1]);
  } }
/* ids built with a prefix at runtime: id="rl-${…}" → remember the prefix */
const prefixes = new Set();
{ let m; const re = /\bid\s*=\s*["']([A-Za-z_][\w-]*[-_])\$\{/g; while ((m = re.exec(src)) !== null) prefixes.add(m[1]); }

/* 2. ids that are looked up */
const lookups = new Map(); // id -> [lines]
const lineOf = (i) => src.slice(0, i).split('\n').length;
const useRes = [
  /getElementById\(\s*["']([A-Za-z_][\w:.-]*)["']\s*\)/g,
  /querySelector(?:All)?\(\s*["']#([A-Za-z_][\w:.-]*)["']\s*\)/g,
];
for (const re of useRes) {
  let m;
  while ((m = re.exec(src)) !== null) {
    const id = m[1];
    if (!lookups.has(id)) lookups.set(id, []);
    lookups.get(id).push(lineOf(m.index));
  }
}

/* 3. report */
const dead = [];
for (const [id, lines] of lookups) {
  if (defined.has(id) || allow.has(id) || literals.has(id)) continue;
  if ([...prefixes].some((p) => id.startsWith(p))) continue;
  dead.push({ id, lines });
}
dead.sort((a, b) => a.id.localeCompare(b.id));
for (const d of dead) console.error(`\x1b[31m✗ dead id "${d.id}"\x1b[0m looked up at line(s) ${d.lines.slice(0, 5).join(', ')}${d.lines.length > 5 ? ', …' : ''} — no element or JS ever defines it`);
if (dead.length) {
  console.error(`check-dead-ids: ${dead.length} dead id(s) among ${lookups.size} looked up (${defined.size} defined). Fix the id, delete the code, or add it to dead-ids.allow with a reason.`);
  process.exit(1);
}
console.log(`check-dead-ids: ${lookups.size} ids looked up, all defined (${file})`);
