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
    console.error('\x1b[33m⚠  lint-xss.js not found beside build-worker.js — XSS gate NOT enforced.\x1b[0m');
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

let shell = fs.readFileSync(shellPath, 'utf8');
const kv = fs.readFileSync(kvPath, 'utf8');
const index = fs.readFileSync(indexPath, 'utf8');

// 1) HTML: replace the quoted token with a properly-escaped JS string literal.
const HTML_TOKEN = '"__INDEX_HTML_PLACEHOLDER__"';
if (shell.indexOf(HTML_TOKEN) === -1) {
  console.error('FATAL: ' + HTML_TOKEN + ' not found in shell'); process.exit(2);
}
shell = shell.replace(HTML_TOKEN, JSON.stringify(index));

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
shell = shell.replace(KV_TOKEN, kvIife);

// Guard: ensure no placeholder survived.
if (/__(INDEX_HTML|KV_SCHEMA)_PLACEHOLDER__/.test(shell)) {
  console.error('FATAL: a placeholder survived the build'); process.exit(4);
}

fs.writeFileSync(outPath, shell);
console.error('built ' + outPath + ' (' + shell.length + ' bytes)');
