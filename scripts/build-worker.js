#!/usr/bin/env node
/* scripts/build-worker.js — RETIRED SHIM (2026-10-16).
 *
 * The real build lives at the repository root (build-worker.js, run as
 * `npm run build`). This copy used to be an older build without the XSS lint,
 * the dead-id/dead-fn gates, the i18n pack split, minification and CSP
 * hashing, and CI was committing its broken output. Anything that still calls
 * this path gets the real build. Flags from the old interface (--no-bump,
 * --dry-run-bump) are accepted and ignored. */
const path = require('path');
const { spawnSync } = require('child_process');
const args = process.argv.slice(2).filter(a => a !== '--no-bump' && a !== '--dry-run-bump');
const r = spawnSync(process.execPath, [path.join(__dirname, '..', 'build-worker.js'), ...args], { stdio: 'inherit' });
process.exit(r.status == null ? 1 : r.status);
