#!/usr/bin/env node
/* Reproduces the AnyoneMap build contract:
 *   - __INDEX_HTML_PLACEHOLDER__ : SPA embedded as a double-quoted JS string.
 *       Source shell has:  const html = "__INDEX_HTML_PLACEHOLDER__";
 *       We replace the WHOLE quoted token  "__INDEX_HTML_PLACEHOLDER__"  with a
 *       single JSON.stringify(indexHtml) literal (its own quotes + escaping).
 *   - __KV_SCHEMA_PLACEHOLDER__   : kv-schema inlined as raw JS, wrapped in an
 *       IIFE that returns the export object (mirrors the documented mechanism).
 */
const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');

const rawArgs = process.argv.slice(2);
const noLint = rawArgs.includes('--no-lint');
const [shellPath, kvPath, indexPath, outPath] = rawArgs.filter(a => !a.startsWith('--'));
if (!shellPath || !kvPath || !indexPath || !outPath) {
  console.error('usage: node build-worker.js <shell> <kv-schema> <index.html> <out> [--no-lint]');
  process.exit(1);
}

/* ---- SECURITY GATE -------------------------------------------------------
 * Block the build on any HIGH XSS-sink finding so a deploy artifact is NEVER
 * produced with an attacker-controlled field reaching an HTML sink unescaped.
 * The linter (lint-xss.js, next to this script) is the single source of truth;
 * we gate on its exit code. Emergency override: --no-lint (loud, discouraged). */
if (noLint) {
  console.error('\x1b[33m⚠  XSS lint gate SKIPPED (--no-lint) — do NOT deploy this artifact without review.\x1b[0m');
} else {
  const linter = path.join(__dirname, 'lint-xss.js');
  if (!fs.existsSync(linter)) {
    /* A gate that silently skips when its script is missing is not a gate.
     * Every gate below fails the build if its file is absent; --no-lint is
     * the only way past the policy gates, and nothing gets past the syntax one. */
    console.error('\x1b[31mFATAL: lint-xss.js not found beside build-worker.js — XSS gate cannot run. Restore the file or use --no-lint (loud).\x1b[0m');
    process.exit(10);
  } else {
    try {
      execFileSync(process.execPath, [linter, indexPath, shellPath], { stdio: 'inherit' });
    } catch (_) {
      console.error('\x1b[31mFATAL: XSS lint gate failed — build aborted, no artifact written.\x1b[0m');
      console.error('Fix the HIGH finding(s) above, or (emergency only) re-run with --no-lint.');
      process.exit(5);
    }
  }
}

/* ---- SYNTAX GATE ---------------------------------------------------------
 * Block the build if any inline <script> in the SPA fails to parse.
 *
 * Added after a CSS insert landed inside a JS comment block: its closing
 * marker terminated the comment early, leaving a bare @media rule as
 * JavaScript. That produced "SyntaxError: Invalid or unexpected token", which
 * killed the whole script block and cascaded into "AC is not defined" and
 * "dismissOnboarding is not defined". The map shipped with a blank canvas,
 * every counter on em-dash, a stopped clock and a ticker stuck on LOADING.
 *
 * Neither existing gate could see it, and not by accident:
 *   - `node --check` on the BUILT worker passes, because the SPA is embedded as
 *     a string literal. A syntax error inside it is just an odd-looking string.
 *   - lint-xss.js looks for HTML sinks, not syntax.
 * Both were green on a build that could not run.
 *
 * Deliberately NOT skipped by --no-lint. That flag is an emergency override for
 * POLICY findings, where a human can weigh the risk. Shipping a file that does
 * not parse is never a judgement call, so this gate has no override. */
const syntaxGate = path.join(__dirname, 'check-scripts.mjs');
if (!fs.existsSync(syntaxGate)) {
  console.error('\x1b[31mFATAL: check-scripts.mjs not found beside build-worker.js — the syntax gate has no override and cannot be skipped by omission either.\x1b[0m');
  process.exit(11);
} else {
  try {
    execFileSync(process.execPath, [syntaxGate, indexPath], { stdio: 'inherit' });
  } catch (_) {
    console.error('\x1b[31mFATAL: SPA syntax gate failed — build aborted, no artifact written.\x1b[0m');
    console.error('An inline <script> in ' + indexPath + ' does not parse. Fix it; there is no override.');
    process.exit(6);
  }
}

/* ---- DEAD-ID GATE ---------------------------------------------------------
 * Block the build on any getElementById() pointing at an id that does not exist.
 *
 * `if (!el) return;` is a good defensive guard and a terrible diagnostic: it
 * treats "renamed" exactly like "nothing to do", so a feature dies silently at
 * the moment of a rename. Three real cases, all invisible to every other check:
 * updateExploreCard showed hardcoded "7,500+ relays / 61 countries" instead of
 * live values for months; the tappable ticker never attached a handler; the
 * AnyClip dimension animation counted up to fabricated fallbacks.
 *
 * Skipped by --no-lint, unlike the syntax gate: unlike a parse failure, a dead id
 * is a correctness problem rather than a "this file cannot run" problem, so an
 * emergency deploy may reasonably want past it. */
if (!noLint) {
  const deadIds = path.join(__dirname, 'check-dead-ids.js');
  const allowFile = path.join(__dirname, 'dead-ids.allow');
  if (!fs.existsSync(deadIds)) { console.error('\x1b[31mFATAL: check-dead-ids.js not found beside build-worker.js.\x1b[0m'); process.exit(12); }
  {
    try {
      const args = [deadIds];
      if (fs.existsSync(allowFile)) args.push('--allow-file', allowFile);
      args.push(indexPath);
      execFileSync(process.execPath, args, { stdio: 'inherit' });
    } catch (_) {
      console.error('\x1b[31mFATAL: dead-id gate failed — build aborted, no artifact written.\x1b[0m');
      console.error('A getElementById in ' + indexPath + ' always returns null. Fix the id,');
      console.error('delete the dead code, or add the id to dead-ids.allow with a reason.');
      process.exit(7);
    }
  }
}

/* ---- DEAD-FUNCTION GATE ---------------------------------------------------
 * The mirror of the dead-id gate: a function whose last caller was removed.
 * First run found the ground-contact ramp (liftAt / refreshObstacle /
 * feetBaseline) three versions after the character stopped touching the
 * ground, and three chat commands advertised to users with no dispatch branch.
 * Skipped by --no-lint, same reasoning as the dead-id gate. */
if (!noLint) {
  const deadFns = path.join(__dirname, 'check-dead-fns.js');
  const allowFile = path.join(__dirname, 'dead-fns.allow');
  if (!fs.existsSync(deadFns)) { console.error('\x1b[31mFATAL: check-dead-fns.js not found beside build-worker.js.\x1b[0m'); process.exit(13); }
  {
    try {
      const args = [deadFns, indexPath];
      if (fs.existsSync(allowFile)) args.push('--allow-file', allowFile);
      execFileSync(process.execPath, args, { stdio: 'inherit' });
    } catch (_) {
      console.error('\x1b[31mFATAL: dead-function gate failed — build aborted, no artifact written.\x1b[0m');
      console.error('A function in ' + indexPath + ' is defined but never referenced. Delete it,');
      console.error('wire it up, or add it to dead-fns.allow with a reason.');
      process.exit(8);
    }
  }
}

let shell = fs.readFileSync(shellPath, 'utf8');
const kv = fs.readFileSync(kvPath, 'utf8');
let index = fs.readFileSync(indexPath, 'utf8');

/* ---- MINIFY (comments only) ----------------------------------------------
 * The SPA ships 267KB of comments — 14% of the file, 30% of the Brotli payload
 * (measured: 434KB -> 302KB on the wire). They are valuable in the repo and
 * useless in the browser.
 *
 * Deliberately conservative: strip HTML/CSS/JS comments, nothing else. No JS
 * compression, no mangling, no whitespace collapse — every one of those can
 * change behaviour and none is needed for the win. A regex strip was rejected
 * because a `/*` inside a string or a `//` in a URL would break code; this
 * uses a real parser.
 *
 * Runs AFTER the four gates (which check the source, where the comments live
 * and where line numbers mean something) and BEFORE embedding. The syntax
 * gate is then re-run on the minified output, because the minifier is the one
 * new step that could produce something that does not parse.
 *
 * Skip with --no-minify (e.g. to bisect a bug against readable source). */
const noMinify = rawArgs.includes('--no-minify');
async function minifyIndex(html) {
  if (noMinify) { console.log('minify: skipped (--no-minify)'); return html; }
  let minify;
  try { ({ minify } = await import('html-minifier-terser')); }
  catch (_) { console.warn('\x1b[33mminify: html-minifier-terser not installed — shipping unminified. npm install html-minifier-terser\x1b[0m'); return html; }
  const out = await minify(html, {
    removeComments: true,
    collapseWhitespace: false,
    minifyJS: { compress: false, mangle: false, format: { comments: false } },
    minifyCSS: { level: { 1: { specialComments: 0 } } },
  });
  const tmp = path.join(require('os').tmpdir(), 'anyonemap-index.min.html');
  fs.writeFileSync(tmp, out);
  const syntaxGate = path.join(__dirname, 'check-scripts.mjs');
  if (fs.existsSync(syntaxGate)) {
    try { execFileSync(process.execPath, [syntaxGate, tmp], { stdio: 'inherit' }); }
    catch (_) {
      console.error('\x1b[31mFATAL: minified SPA does not parse — build aborted. Re-run with --no-minify to ship the readable source.\x1b[0m');
      process.exit(9);
    }
  }
  console.log(`minify: ${html.length.toLocaleString()} -> ${out.length.toLocaleString()} chars (-${(100 * (1 - out.length / html.length)).toFixed(0)}%)`);
  return out;
}

(async () => {
/* v5: split the I18N table. English stays inline; the other languages become
 * JSON packs served at /i18n/<lang>.json by the shell (see I18N_PACKS). The
 * table is parsed as JS (object literal with unquoted keys and single quotes)
 * in a bare vm context, per language block, and refused if any block does
 * not parse or if a language ends up with fewer keys than English. */
{
  const vm = require('vm');
  const start = index.indexOf('const I18N = {');
  const end = index.indexOf('\n};', start);
  if (start === -1 || end === -1) { console.error('\x1b[31mFATAL: I18N table not found in index.html\x1b[0m'); process.exit(18); }
  const seg = index.slice(start, end);
  const blocks = [...seg.matchAll(/\n  ([a-z]{2}):\{/g)];
  const packs = {}; let enBlock = null; let enKeys = 0;
  for (let i = 0; i < blocks.length; i++) {
    const lang = blocks[i][1]; const from = blocks[i].index; const to = i + 1 < blocks.length ? blocks[i + 1].index : seg.length;
    let body = seg.slice(from + blocks[i][0].length, to).replace(/\s*\},?\s*$/, '');
    let obj;
    try { obj = vm.runInNewContext('({' + body + '})'); } catch (e) { console.error('\x1b[31mFATAL: I18N block "' + lang + '" does not parse: ' + e.message + '\x1b[0m'); process.exit(18); }
    if (lang === 'en') { enBlock = seg.slice(from, to); enKeys = Object.keys(obj).length; continue; }
    const json = JSON.stringify(obj);
    packs[lang] = { body: json, etag: require('crypto').createHash('sha256').update(json).digest('hex').slice(0, 16), keys: Object.keys(obj).length };
  }
  if (!enBlock) { console.error('\x1b[31mFATAL: no en block in I18N\x1b[0m'); process.exit(18); }
  for (const [lang, p] of Object.entries(packs)) if (p.keys < enKeys * 0.9) { console.error('\x1b[31mFATAL: I18N pack ' + lang + ' has ' + p.keys + ' keys vs en ' + enKeys + '\x1b[0m'); process.exit(18); }
  index = index.slice(0, start) + 'const I18N = {' + enBlock.replace(/,?\s*$/, '') + index.slice(end);
  const tok = '__I18N_PACKS_PLACEHOLDER__';
  if (shell.indexOf(tok) === -1) { console.error('\x1b[31mFATAL: ' + tok + ' not found in shell\x1b[0m'); process.exit(18); }
  shell = shell.replace(tok, function(){ return JSON.stringify(packs); });
  const total = Object.values(packs).reduce((s, p) => s + p.body.length, 0);
  console.log(`i18n-split: ${Object.keys(packs).length} language packs (${Math.round(total / 1024)} KB) moved out of the page; en (${enKeys} keys) stays inline`);
}

index = await minifyIndex(index);

/* v3: CSP without 'unsafe-inline' for scripts. Inline handler attributes →
 * data-h-* + a generated handler table; then hash every inline <script>
 * body and put the hashes into the shell's script-src. See csp-inline.js. */
{
  const cspInline = require(path.join(__dirname, 'csp-inline.js'));
  let t;
  try { t = cspInline.transform(index); }
  catch (e) { console.error('\x1b[31mFATAL: ' + e.message + '\x1b[0m'); process.exit(14); }
  index = t.html;
  const tmp2 = path.join(require('os').tmpdir(), 'anyonemap-index.csp.html');
  fs.writeFileSync(tmp2, index);
  const syntaxGate2 = path.join(__dirname, 'check-scripts.mjs');
  if (fs.existsSync(syntaxGate2)) {
    try { execFileSync(process.execPath, [syntaxGate2, tmp2], { stdio: 'inherit' }); }
    catch (_) { console.error('\x1b[31mFATAL: generated handler table does not parse — build aborted.\x1b[0m'); process.exit(15); }
  }
  const hashes = cspInline.scriptHashes(index);
  /* Only the SPA's header — the one that lists the CDN hosts. /bitcoin has its
   * own two CSP headers (script-src 'self' 'unsafe-inline';) for its own
   * inline scripts; those are untouched. */
  const SPA_SCRIPT_SRC = "script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://cdn.jsdelivr.net;";
  const n = shell.split(SPA_SCRIPT_SRC).length - 1;
  if (n !== 1) { console.error('\x1b[31mFATAL: expected exactly one SPA script-src directive in the shell, found ' + n + ' — CSP step cannot apply\x1b[0m'); process.exit(16); }
  shell = shell.replace(SPA_SCRIPT_SRC, "script-src 'self' " + hashes.join(' ') + " https://cdnjs.cloudflare.com https://cdn.jsdelivr.net;");
  console.log(`csp-inline: ${t.count} handler attributes → ${t.unique} tabled bodies; ${hashes.length} script hashes into ${n} CSP header(s); 'unsafe-inline' removed from script-src`);

  /* v4: /bitcoin gets the same treatment. Its HTML is embedded in the shell as
   * `const bpHtml = "…"`; its inline <script> bodies are static (the live
   * placeholders sit in the HTML text, not in the scripts), so their hashes go
   * into the __BP_SCRIPT_HASHES__ token of the /bitcoin CSP. Any edit to those
   * scripts changes the hashes at the next build; a script that gets a
   * placeholder inside it would break the hash at request time, so refuse. */
  {
    const bpStart = shell.indexOf('const bpHtml = "');
    const tok = '__BP_SCRIPT_HASHES__';
    if (bpStart === -1 || shell.indexOf(tok) === -1) { console.error('\x1b[31mFATAL: /bitcoin HTML or its CSP token not found in the shell\x1b[0m'); process.exit(17); }
    let j = bpStart + 'const bpHtml = '.length, q = j + 1;
    while (q < shell.length) { if (shell[q] === '\\') { q += 2; continue; } if (shell[q] === '"') break; q++; }
    const bpHtml = JSON.parse(shell.slice(j, q + 1));
    const bodies = []; const re = /<script\b([^>]*)>([\s\S]*?)<\/script>/gi; let m;
    while ((m = re.exec(bpHtml)) !== null) { if (!/\bsrc\s*=/.test(m[1] || '')) bodies.push(m[2]); }
    if (!bodies.length) { console.error('\x1b[31mFATAL: no inline scripts found in /bitcoin HTML\x1b[0m'); process.exit(17); }
    if (bodies.some((b) => b.indexOf('{{') !== -1)) { console.error('\x1b[31mFATAL: a /bitcoin inline script contains a {{placeholder}} — its hash would not match at request time\x1b[0m'); process.exit(17); }
    const bpHashes = bodies.map((b) => "'sha256-" + require('crypto').createHash('sha256').update(b, 'utf8').digest('base64') + "'");
    shell = shell.replace(tok, bpHashes.join(' '));
    console.log(`csp-bitcoin: ${bpHashes.length} inline script hash(es) into the /bitcoin CSP; 'unsafe-inline' removed from its script-src`);
  }
}

// 1) HTML: replace the quoted token with a properly-escaped JS string literal.
const HTML_TOKEN = '"__INDEX_HTML_PLACEHOLDER__"';
if (shell.indexOf(HTML_TOKEN) === -1) {
  console.error('FATAL: ' + HTML_TOKEN + ' not found in shell'); process.exit(2);
}
/* v2: function replacement. With a string, String.prototype.replace interprets
 * `$&`, `$'`, `$\`` and `$1` inside the HTML — so any `$&` in index.html (a
 * regex-escape idiom) re-inserted the placeholder and the build died with
 * "a placeholder survived". A function returns the text verbatim. */
shell = shell.replace(HTML_TOKEN, function(){ return JSON.stringify(index); });

// 2) KV schema: wrap source in an IIFE returning the export object.
const KV_TOKEN = '__KV_SCHEMA_PLACEHOLDER__';
if (shell.indexOf(KV_TOKEN) === -1) {
  console.error('FATAL: ' + KV_TOKEN + ' not found in shell'); process.exit(3);
}
const kvIife =
  '(function(){ var module = undefined;\n' +
  kv +
  '\nreturn { SCHEMA_VERSION: SCHEMA_VERSION, SNAPSHOT_KEY: SNAPSHOT_KEY, ' +
  'EXIT_RELAYS_LATEST: EXIT_RELAYS_LATEST, validate: validate, extract: extract };\n})()';
shell = shell.replace(KV_TOKEN, function(){ return kvIife; });

// Guard: ensure no placeholder survived.
if (/__(INDEX_HTML|KV_SCHEMA)_PLACEHOLDER__/.test(shell)) {
  console.error('FATAL: a placeholder survived the build'); process.exit(4);
}

fs.writeFileSync(outPath, shell);
console.error('built ' + outPath + ' (' + shell.length + ' bytes)');
})();
