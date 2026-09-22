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
index = await minifyIndex(index);

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
