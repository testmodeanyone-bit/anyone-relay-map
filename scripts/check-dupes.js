#!/usr/bin/env node
// check-dupes.js — scan a JS file for duplicate keys in object literals.
//
// Why this exists: v391 shipped a worker that emitted a Response with TWO
// 'Cache-Control' headers in the same `headers: { ... }` object. JS quietly
// applies last-wins, so the bug was invisible at runtime. Catching it pre-deploy
// is the entire point of this script.
//
// Catches:
//   - duplicate single- or double-quoted keys ('foo': X ... 'foo': Y)
//   - works on the giant single-line embedded-HTML worker structure
//
// Does NOT catch:
//   - duplicate bareword keys (foo: 1, foo: 2) — needs a real JS parser
//   - computed property names ([k]: 1, [k]: 2)
//
// Exit codes:
//   0  clean
//   1  duplicates found
//   2  usage / file error

"use strict";

const fs = require("fs");

const file = process.argv[2];
if (!file) {
  console.error("usage: node check-dupes.js <file.js>");
  process.exit(2);
}
if (!fs.existsSync(file)) {
  console.error("error: file not found: " + file);
  process.exit(2);
}

const src = fs.readFileSync(file, "utf8");
const N = src.length;

// Cache line/col lookups. Build a sorted array of newline indices once.
const newlines = [-1];
for (let i = 0; i < N; i++) {
  if (src.charCodeAt(i) === 10) newlines.push(i);
}
function lineCol(idx) {
  // Binary search for the largest newline index <= idx.
  let lo = 0, hi = newlines.length - 1;
  while (lo < hi) {
    const mid = (lo + hi + 1) >> 1;
    if (newlines[mid] <= idx) lo = mid;
    else hi = mid - 1;
  }
  return { line: lo + 1, col: idx - newlines[lo] };
}

let dupeCount = 0;

// State machine walking the source character by character.
// Tracks: strings (with escapes), line/block comments, regex literals,
// and a stack of active object-literal scopes.
const objStack = [];           // stack of Map<key, firstIdx> for current object literals, or null for non-object braces
let inString = 0;              // 0, or charCode of opening quote (39, 34, 96)
let inLineComment = false;
let inBlockComment = false;
let inRegex = false;
let lastNonWhiteCh = 0;        // last non-whitespace, non-comment charCode

let i = 0;
while (i < N) {
  const cc = src.charCodeAt(i);
  const nc = i + 1 < N ? src.charCodeAt(i + 1) : 0;

  if (inLineComment) {
    if (cc === 10) inLineComment = false;
    i++;
    continue;
  }
  if (inBlockComment) {
    if (cc === 42 && nc === 47) { inBlockComment = false; i += 2; continue; }
    i++;
    continue;
  }
  if (inString) {
    if (cc === 92) { i += 2; continue; }     // backslash escape
    if (cc === inString) inString = 0;
    i++;
    continue;
  }
  if (inRegex) {
    if (cc === 92) { i += 2; continue; }
    if (cc === 47 || cc === 10) inRegex = false;
    i++;
    continue;
  }

  // Comments
  if (cc === 47 && nc === 47) { inLineComment = true; i += 2; continue; }
  if (cc === 47 && nc === 42) { inBlockComment = true; i += 2; continue; }

  // Regex literal — / is regex if preceded by an operator-like char (or BOF)
  if (cc === 47) {
    const p = lastNonWhiteCh;
    // 0 (BOF), = ( , ; : ! & | ? + - * % ~ ^ < > { [ also covers /=
    const isRegex =
      p === 0 || p === 61 || p === 40 || p === 44 || p === 59 || p === 58 ||
      p === 33 || p === 38 || p === 124 || p === 63 || p === 43 || p === 45 ||
      p === 42 || p === 37 || p === 126 || p === 94 || p === 60 || p === 62 ||
      p === 123 || p === 91;
    if (isRegex) {
      inRegex = true;
      i++;
      continue;
    }
  }

  // String starts (single, double, backtick)
  if (cc === 39 || cc === 34 || cc === 96) {
    // Before treating this as a regular string, check if it's a quoted KEY:
    // a string literal followed (after whitespace) by ":" inside an object literal.
    const top = objStack.length ? objStack[objStack.length - 1] : null;

    if (top) {
      // Scan to find the matching close quote on the same logical line
      let j = i + 1;
      let key = "";
      let aborted = false;
      while (j < N) {
        const ch = src.charCodeAt(j);
        if (ch === 92) {                      // escape — consume next as literal
          if (j + 1 < N) key += src[j + 1];
          j += 2;
          continue;
        }
        if (ch === cc) break;                 // closing quote
        if (ch === 10) { aborted = true; break; }
        key += src[j];
        j++;
      }

      if (!aborted && j < N) {
        // Look past closing quote for whitespace then ":"
        let k = j + 1;
        while (k < N) {
          const wc = src.charCodeAt(k);
          if (wc === 32 || wc === 9 || wc === 10 || wc === 13) { k++; continue; }
          break;
        }
        if (k < N && src.charCodeAt(k) === 58) {
          // It IS a key. Check duplicate within the current object scope.
          if (top.has(key)) {
            const firstIdx = top.get(key);
            const f = lineCol(firstIdx);
            const d = lineCol(i);
            console.log(
              "DUPLICATE KEY \"" + key + "\" at line " + d.line + ":" + d.col +
              " (first seen at line " + f.line + ":" + f.col + ")"
            );
            dupeCount++;
          } else {
            top.set(key, i);
          }
          i = k + 1;        // skip past the colon
          lastNonWhiteCh = 58;
          continue;
        }
      }
    }

    // Not a key — enter string mode normally
    inString = cc;
    lastNonWhiteCh = cc;
    i++;
    continue;
  }

  if (cc === 123) {
    // {  — Decide if this opens an object literal.
    // Object-literal context: preceded by = : , ( [ ? ! & | (or BOF).
    // Block context (function body, if body, etc.): preceded by ) or alpha (function name).
    const p = lastNonWhiteCh;
    const isObj =
      p === 0 || p === 61 || p === 58 || p === 44 || p === 40 || p === 91 ||
      p === 63 || p === 33 || p === 38 || p === 124 || p === 59 || p === 123;
    if (isObj) {
      objStack.push(new Map());
    } else {
      objStack.push(null);
    }
    lastNonWhiteCh = 123;
    i++;
    continue;
  }

  if (cc === 125) {
    // }
    objStack.pop();
    lastNonWhiteCh = 125;
    i++;
    continue;
  }

  // Update lastNonWhiteCh
  if (cc !== 32 && cc !== 9 && cc !== 10 && cc !== 13) {
    lastNonWhiteCh = cc;
  }
  i++;
}

if (dupeCount === 0) {
  console.log("OK — no duplicate keys found in " + file);
  process.exit(0);
} else {
  console.log("");
  console.log("FAIL — " + dupeCount + " duplicate key(s) found in " + file);
  process.exit(1);
}
