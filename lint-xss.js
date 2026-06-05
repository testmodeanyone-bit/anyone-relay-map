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
// These are the raw DATA-FIELD accessors where untrusted input enters — NOT
// local variable names (a local that holds _aoEscHtml(...) is already safe; the
// escaper is recognised below). Keep this tight to stay low-noise.
const SENSITIVE_FIELDS = [
  '.name', '.owner', '.nickname', '.asName', '.as_name', '.isp', '.contact',
  '.host', '.hostname', '.domain', '.platform', '.operator', 'topIsps',
  '.message', '.body', '.text'
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

function escapeRe(s) { return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }

/* When a sink's RHS is a bare variable (el.innerHTML = html;) rather than a
 * template literal, pull out that variable name so we can resolve its assignment.
 * Returns null for function calls (renderCard(d)), property access (data.html),
 * and literals — those are out of this one-level scope. */
function extractRhsVar(rhs) {
  const cleaned = rhs.replace(/'[^']*'|"[^"]*"/g, "''"); // drop string args (e.g. insertAdjacentHTML position)
  const mm = cleaned.match(/(?:[=,(]|^)\s*([A-Za-z_$][\w$]*)\s*([);.,]|\+|$)/);
  if (!mm) return null;
  const name = mm[1], after = mm[2];
  if (after === '(' || after === '.') return null;           // call / property — out of scope
  if (['true', 'false', 'null', 'undefined', 'this'].includes(name)) return null;
  return name;
}

/* ----- locate sinks & their template literals ---------------------------- */
function findInterpsForFile(src) {
  const findings = [];
  const seen = new Set();              // dedupe (a var feeding several sinks)
  const lineStarts = [0];
  for (let i = 0; i < src.length; i++) if (src[i] === '\n') lineStarts.push(i + 1);
  const lineOf = idx => { // binary search
    let lo = 0, hi = lineStarts.length - 1;
    while (lo < hi) { const m = (lo + hi + 1) >> 1; if (lineStarts[m] <= idx) lo = m; else hi = m - 1; }
    return lo + 1;
  };
  const lineText = idx => {
    const s = src.lastIndexOf('\n', idx) + 1;
    const e = src.indexOf('\n', idx);
    return src.slice(s, e === -1 ? src.length : e);
  };
  const collect = (interps, line, via) => {
    for (const expr of interps) {
      const verdict = classify(expr);
      if (verdict === 'safe') continue;
      const key = line + '|' + expr;
      if (seen.has(key)) continue;
      seen.add(key);
      findings.push({ line, expr: expr.slice(0, 80), via, ...verdict });
    }
  };

  const sinkTokenRe = /\.innerHTML|\.outerHTML|insertAdjacentHTML\s*\(|document\.write\s*\(/g;
  let m;
  while ((m = sinkTokenRe.exec(src)) !== null) {
    // From the sink, find the first backtick that starts the HTML template.
    /* Walk the sink's RHS tracking bracket depth so we find template literals
     * even when the RHS is `arr.map(d => { const x = …; return `…` }).join('')`
     * — i.e. don't mistake a `;` *inside* the expression for the statement end.
     * Collect every template literal found; only treat the RHS as a bare
     * variable when NO template appears before the depth-0 statement terminator. */
    const rhsStart = m.index + m[0].length;
    const limit = Math.min(src.length, rhsStart + 20000);
    let j = rhsStart, depth = 0, foundTemplate = false, breakPos = limit;
    while (j < limit) {
      const c = src[j];
      if (c === '\\') { j += 2; continue; }
      if (c === '`') {
        foundTemplate = true;
        const tpl = scanTemplate(src, j);
        /* Auditable suppression: an `xss-ok` marker between the sink token and
         * the template's end skips it. Use ONLY for provably developer-
         * controlled data (e.g. a hardcoded constant array). Greppable. */
        if (!src.slice(m.index, tpl.end).includes('xss-ok')) collect(tpl.interps, lineOf(j), null);
        j = tpl.end + 1; continue;
      }
      if (c === '"' || c === "'") { j = skipString(src, j, c); continue; }
      if (c === '(' || c === '{' || c === '[') { depth++; j++; continue; }
      if (c === ')' || c === '}' || c === ']') { depth--; if (depth < 0) { breakPos = j; break; } j++; continue; }
      if (c === ';' && depth === 0) { breakPos = j; break; }   // real statement end
      j++;
    }
    if (foundTemplate) continue;       // template sink(s) handled above

    /* No template in the RHS — it may be a VARIABLE holding one (one-level
     * trace). Resolve the variable's `VAR = `…`` / `VAR += `…`` template
     * assignments, SCOPED to the window between the variable's nearest preceding
     * declaration (let/const/var VAR) and this sink. That keeps a common name
     * like `html` from pulling in unrelated same-named vars in other functions,
     * while still capturing a full `let html=''; html+=…; html+=…` accumulation
     * block. Reported at the ASSIGNMENT's line, annotated `via VAR`. */
    if (lineText(m.index).includes('xss-ok')) continue;
    const rhs = src.slice(rhsStart, breakPos);
    const varName = extractRhsVar(rhs);
    if (!varName) continue;            // call/property/literal — out of one-level scope
    let declIdx = 0, dm;
    const declRe = new RegExp('(?:let|const|var)\\s+' + escapeRe(varName) + '\\b', 'g');
    while ((dm = declRe.exec(src)) !== null) { if (dm.index < m.index) declIdx = dm.index; else break; }
    const asgRe = new RegExp('(?:^|[^\\w$.])' + escapeRe(varName) + '\\s*\\+?=\\s*`', 'g');
    asgRe.lastIndex = declIdx;
    let a;
    while ((a = asgRe.exec(src)) !== null) {
      if (a.index >= m.index) break;   // only assignments before this sink, in scope
      const tk = src.indexOf('`', a.index);
      if (tk === -1) continue;
      const tpl = scanTemplate(src, tk);
      if (src.slice(a.index, tpl.end).includes('xss-ok')) continue;
      collect(tpl.interps, lineOf(tk), varName);
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
      const via = f.via ? ` \x1b[36m(via ${f.via})\x1b[0m` : '';
      if (f.level === 'HIGH') {
        high++;
        console.log(`  \x1b[31mHIGH\x1b[0m  L${f.line}  unescaped \x1b[33m${f.field}\x1b[0m → \${${f.expr}}${via}`);
      } else {
        warn++;
        console.log(`  \x1b[90mwarn\x1b[0m  L${f.line}  review → \${${f.expr}}${via}`);
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
