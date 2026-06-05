#!/usr/bin/env node
/* ===========================================================================
 * lint-xss.js — pre-deploy XSS-sink linter for the AnyoneMap front-end.
 *
 * WHY: relay nicknames, .anyone domain names, owners, and AS/ISP strings are
 * ATTACKER-CONTROLLED (anyone can run a relay or mint a domain with arbitrary
 * characters). When those flow into an HTML sink (innerHTML / outerHTML /
 * insertAdjacentHTML / document.write) without HTML-escaping, you get stored
 * XSS — exactly the Domains-panel bug fixed in v199. This tool stops that class
 * from regressing.
 *
 * WHAT IT DOES: for every HTML sink it captures the template literal, extracts
 * each ${...} interpolation (multi-line + nested aware), and classifies it:
 *   HIGH  — touches a known attacker-controlled field and is NOT wrapped in an
 *           approved escaper. Fails the build (exit 1).
 *   WARN  — an interpolation that isn't obviously safe (review by eye).
 *           Informational; only fails under --strict.
 *   safe  — wrapped in _aoEscHtml()/acSanitize()/esc()/encodeURIComponent(),
 *           or a number / i18n string / constant.
 *
 * USAGE:
 *   node lint-xss.js [file ...]            # defaults to index.html worker-shell.js
 *   node lint-xss.js --strict index.html   # WARN also fails the build
 *
 * It is a heuristic, not a JS parser — tuned for THIS codebase's conventions.
 * Add fields to SENSITIVE_FIELDS / escapers to ESCAPERS as the app grows.
 * =========================================================================== */
'use strict';
const fs = require('fs');

/* ----- configuration ----------------------------------------------------- */
const SINK_RE = /\.innerHTML|\.outerHTML|insertAdjacentHTML\s*\(|document\.write\s*\(/;

// Wrapping any interpolation in one of these neutralises HTML — treat as safe.
const ESCAPERS = ['_aoEscHtml(', 'acSanitize(', 'escapeHtml(', 'esc(',
                  'encodeURIComponent(', 'encodeURI('];

// Inherently-safe producers: developer-controlled i18n strings + numeric/format.
const SAFE_HELPERS = ['_i18t(', '.toLocaleString(', '.toFixed(', '.length',
                      'Number(', 'parseInt(', 'parseFloat(', 'Math.', '.size',
                      '.count', '? ' /* short ternaries of literals, low risk */];

// Attacker-controlled fields that MUST be escaped before hitting an HTML sink.
// (Keep this tight to stay low-noise — these are the real injection vectors.)
const SENSITIVE_FIELDS = [
  '.name', '.owner', '.nickname', '.asName', '.as_name', '.isp', '.contact',
  '.host', '.hostname', '.domain', '.platform', '.operator', 'topIsps',
  'namePart', 'shortOwner', 'rawName', '.message', '.body', '.text'
];
// Relay nickname is accessed as `.n` in the raw enriched data — match `.n`
// only when it is a complete property (followed by a non-word char).
const NICKNAME_RE = /\.n\b/;

/* ----- template-literal scanner ------------------------------------------ */
/* Given source `s` and the index of an opening backtick, return the end index
 * and every ${...} interpolation expression (recursing into nested templates). */
function scanTemplate(s, start) {
  const interps = [];
  let i = start + 1; // past opening `
  while (i < s.length) {
    const c = s[i];
    if (c === '\\') { i += 2; continue; }
    if (c === '`') return { end: i, interps };
    if (c === '$' && s[i + 1] === '{') {
      const r = scanInterp(s, i + 2);
      interps.push(r.expr.trim());
      for (const nested of r.nested) interps.push(nested);
      i = r.end + 1;
      continue;
    }
    i++;
  }
  return { end: s.length, interps };
}
/* Parse a ${ ... } body starting just after the `${`. Brace-balanced, skips
 * quoted strings, and recurses into nested template literals. */
function scanInterp(s, start) {
  let i = start, depth = 1;
  const nested = [];
  const from = start;
  while (i < s.length && depth > 0) {
    const c = s[i];
    if (c === '\\') { i += 2; continue; }
    if (c === '{') { depth++; i++; continue; }
    if (c === '}') { depth--; i++; continue; }
    if (c === '"' || c === "'") { i = skipString(s, i, c); continue; }
    if (c === '`') { const r = scanTemplate(s, i); nested.push(...r.interps); i = r.end + 1; continue; }
    i++;
  }
  return { expr: s.slice(from, i - 1), end: i - 1, nested };
}
function skipString(s, i, q) {
  i++;
  while (i < s.length) {
    if (s[i] === '\\') { i += 2; continue; }
    if (s[i] === q) return i + 1;
    i++;
  }
  return i;
}

/* ----- classification ---------------------------------------------------- */
function classify(expr) {
  const hasEscaper = ESCAPERS.some(e => expr.includes(e));
  /* Inline HTML-escape chain, e.g. .replace(/&/g,'&amp;').replace(/</g,'&lt;')…
   * — the chat path escapes this way rather than via a named helper. */
  const inlineEscaped = expr.includes('&amp;') && expr.includes('&lt;');
  if (hasEscaper || inlineEscaped) return 'safe';
  const sensitive = SENSITIVE_FIELDS.find(f => expr.includes(f)) ||
                    (NICKNAME_RE.test(expr) ? '.n' : null);
  if (sensitive) return { level: 'HIGH', field: sensitive };
  const looksSafe = SAFE_HELPERS.some(h => expr.includes(h)) ||
                    /^[A-Z0-9_]+$/.test(expr) ||           // CONSTANT
                    /^['"`].*['"`]$/.test(expr) ||         // string literal
                    /^[\d.\s+\-*/()]+$/.test(expr) ||      // arithmetic
                    expr === '' ;
  if (looksSafe) return 'safe';
  return { level: 'WARN', field: null };
}

/* ----- locate sinks & their template literals ---------------------------- */
function findInterpsForFile(src) {
  const findings = [];
  const lineStarts = [0];
  for (let i = 0; i < src.length; i++) if (src[i] === '\n') lineStarts.push(i + 1);
  const lineOf = idx => { // binary search
    let lo = 0, hi = lineStarts.length - 1;
    while (lo < hi) { const m = (lo + hi + 1) >> 1; if (lineStarts[m] <= idx) lo = m; else hi = m - 1; }
    return lo + 1;
  };

  const sinkTokenRe = /\.innerHTML|\.outerHTML|insertAdjacentHTML\s*\(|document\.write\s*\(/g;
  let m;
  while ((m = sinkTokenRe.exec(src)) !== null) {
    // From the sink, find the first backtick that starts the HTML template.
    // Bail if a ';' or newline-with-no-backtick suggests a non-template RHS.
    let j = m.index + m[0].length;
    let tick = -1;
    const limit = Math.min(src.length, j + 400);
    while (j < limit) {
      const c = src[j];
      if (c === '`') { tick = j; break; }
      if (c === ';') break;            // statement ended, no template
      j++;
    }
    if (tick === -1) continue;         // RHS isn't a template literal — skip
    const tpl = scanTemplate(src, tick);
    /* Auditable suppression: a sink whose template (or its line) carries an
     * `xss-ok` marker is skipped. Use ONLY for provably developer-controlled
     * data (e.g. a hardcoded constant array like AC_STICKERS). Greppable, so
     * suppressions can be reviewed: `grep -n xss-ok index.html`. */
    if (src.slice(m.index, tpl.end).includes('xss-ok')) continue;
    for (const expr of tpl.interps) {
      const verdict = classify(expr);
      if (verdict === 'safe') continue;
      findings.push({ line: lineOf(tick), expr: expr.slice(0, 80), ...verdict });
    }
  }
  return findings;
}

/* ----- runner ------------------------------------------------------------ */
function main() {
  const args = process.argv.slice(2);
  const strict = args.includes('--strict');
  let files = args.filter(a => !a.startsWith('--'));
  if (files.length === 0) files = ['index.html', 'worker-shell.js'];

  let high = 0, warn = 0;
  for (const file of files) {
    if (!fs.existsSync(file)) { console.error(`! skip (not found): ${file}`); continue; }
    const src = fs.readFileSync(file, 'utf8');
    const findings = findInterpsForFile(src);
    if (!findings.length) { console.log(`\x1b[32m✓\x1b[0m ${file}: no unescaped sensitive interpolations`); continue; }
    console.log(`\n\x1b[1m${file}\x1b[0m`);
    for (const f of findings) {
      if (f.level === 'HIGH') {
        high++;
        console.log(`  \x1b[31mHIGH\x1b[0m  L${f.line}  unescaped \x1b[33m${f.field}\x1b[0m → \${${f.expr}}`);
      } else {
        warn++;
        console.log(`  \x1b[90mwarn\x1b[0m  L${f.line}  review → \${${f.expr}}`);
      }
    }
  }

  console.log(`\n${high} HIGH, ${warn} WARN`);
  if (high > 0) {
    console.log('\x1b[31mFAIL\x1b[0m — wrap attacker-controlled fields in _aoEscHtml() before the HTML sink.');
    process.exit(1);
  }
  if (strict && warn > 0) {
    console.log('\x1b[31mFAIL (--strict)\x1b[0m — review the WARN interpolations.');
    process.exit(1);
  }
  console.log('\x1b[32mPASS\x1b[0m');
  process.exit(0);
}
main();
