#!/usr/bin/env node
/* check-dead-fns.js — dead-function gate for build-worker.js
 *
 * A `function name(…)` declared in the SPA must be referenced somewhere else
 * in the file: a call, an onclick="name(…)" attribute, a window.name export,
 * an event listener, a string passed to a dispatcher. A function whose only
 * occurrence is its own declaration is dead code — usually the remnant of a
 * feature whose last caller was removed.
 *
 * Deliberately simple: whole-word occurrence counting over the file, which
 * catches every kind of reference the SPA uses (including inline handlers and
 * names in strings). It cannot see a call built by string concatenation; put
 * those in dead-fns.allow with the reason.
 *
 * Usage: node check-dead-fns.js <index.html> [--allow-file dead-fns.allow]
 */
const fs = require('fs');

const args = process.argv.slice(2);
let allowFile = null;
const ai = args.indexOf('--allow-file');
if (ai !== -1) { allowFile = args[ai + 1]; args.splice(ai, 2); }
const file = args[0];
if (!file) { console.error('usage: node check-dead-fns.js <index.html> [--allow-file f]'); process.exit(2); }
const src = fs.readFileSync(file, 'utf8');

const allow = new Set();
if (allowFile && fs.existsSync(allowFile)) {
  for (const line of fs.readFileSync(allowFile, 'utf8').split('\n')) {
    const t = line.replace(/#.*/, '').trim(); if (t) allow.add(t);
  }
}

/* Only inline <script> code is scanned for declarations; the whole file is
 * scanned for references (handlers live in the HTML). */
const scripts = [];
const re = /<script\b([^>]*)>([\s\S]*?)<\/script>/gi;
let m;
while ((m = re.exec(src)) !== null) {
  if (/\bsrc\s*=/.test(m[1] || '')) continue;
  /* declarations are scanned with comments blanked (same length, so line
   * numbers hold): a comment saying "removed function foo()" must not count */
  const blanked = m[2]
    .replace(/\/\*[\s\S]*?\*\//g, (c) => c.replace(/[^\n]/g, ' '))
    .replace(/^([ \t]*)\/\/.*$/gm, (c) => c.replace(/[^\n]/g, ' '));
  scripts.push({ code: blanked, offset: m.index + m[0].indexOf('>') + 1 });
}
const lineOf = (i) => src.slice(0, i).split('\n').length;

const decls = new Map(); // name -> first line
/* `(function name(){…})()` is a named IIFE, not a declaration — excluded via the leading char */
const declRe = /(?:^|[^.\w$(!])\s*(?:async\s+)?function\s*\*?\s*([A-Za-z_$][\w$]*)\s*\(/g;
for (const s of scripts) {
  let d;
  while ((d = declRe.exec(s.code)) !== null) {
    const name = d[1];
    if (!decls.has(name)) decls.set(name, lineOf(s.offset + d.index + d[0].indexOf('function')));
  }
}

/* whole-word occurrences across the entire file */
const dead = [];
for (const [name, line] of decls) {
  if (allow.has(name)) continue;
  const esc = name.replace(/\$/g, '\\$');
  const total  = (src.match(new RegExp('(?<![\\w$])' + esc + '(?![\\w$])', 'g')) || []).length;
  /* `obj.name` is a member access, not a reference to this function; `...name(`
   * (spread) is. Subtract single-dot member accesses only. */
  const member = (src.match(new RegExp('(?<![.\\s])\\.' + esc + '(?![\\w$])', 'g')) || []).length;
  if (total - member <= 1) dead.push({ name, line });
}
dead.sort((a, b) => a.line - b.line);
for (const d of dead) console.error(`\x1b[31m✗ dead function ${d.name}()\x1b[0m declared at line ${d.line} — never referenced anywhere else in the file`);
if (dead.length) {
  console.error(`check-dead-fns: ${dead.length} unreferenced function(s) of ${decls.size} declared. Delete it, wire it up, or add it to dead-fns.allow with a reason.`);
  process.exit(1);
}
console.log(`check-dead-fns: ${decls.size} functions declared, all referenced (${file})`);
