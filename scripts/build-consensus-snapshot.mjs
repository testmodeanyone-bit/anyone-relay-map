#!/usr/bin/env node
/* ============================================================================
 * build-consensus-snapshot.mjs
 * ============================================================================
 * Parses an Anyone Protocol (Tor-format) network consensus document into a
 * compact { fingerprint(hex) -> IPv4 } JSON map and writes it to
 * data/consensus-snapshot.json.
 *
 * WHY THIS EXISTS
 * ---------------
 * The Anyone directory authorities serve the consensus over the ORPort tunnel
 * (port 9201) and return HTTP 403 on the plain DirPort (9230) — verified live
 * 2026-05 across all 7 authorities. Cloudflare Workers cannot speak the ORPort
 * tunnel protocol, so neither anyclip-proxy nor anyone-geo-enrichment can fetch
 * consensus directly. This mirror runs on a GitHub Actions runner (which CAN run
 * the real `anon` client and reach the ORPort), parses the consensus it produces,
 * and commits a small JSON map. The workers then read it over plain HTTPS from
 * raw.githubusercontent.com — the same pattern anyonemap-worker v393 used to
 * route around the bitnodes 530 block.
 *
 * INPUT
 * -----
 * A consensus document on disk. Path via argv[2] or CONSENSUS_FILE env.
 * Typically /var/lib/anon/cached-consensus (or cached-microdesc-consensus),
 * written by a bootstrapped `anon` client.
 *
 * OUTPUT
 * ------
 * data/consensus-snapshot.json (path via argv[3] or OUT_FILE env):
 *   {
 *     "builtAt": 1779400000,            // unix seconds, when this ran
 *     "validAfter": "2026-05-21 21:00:00",   // from consensus header, if present
 *     "validUntil": "2026-05-22 00:00:00",   // from consensus header, if present
 *     "relayCount": 7568,
 *     "format": "full" | "microdesc",
 *     "fp_to_ip": { "AAAA...40hex": "1.2.3.4", ... }
 *   }
 *
 * The worker only needs fp_to_ip; the rest is for staleness checks / debugging.
 *
 * PARSING CONTRACT (must match the worker's parseConsensus)
 * ---------------------------------------------------------
 * Each router status entry is an `r ` line. In the FULL consensus the fields are:
 *   r nickname identity digest publication(date) publication(time) IP ORPort DirPort
 *   index:  0    1        2       3        4              5          6    7       8
 * So identity = f[2] (base64), IP = f[6]. We replicate the worker's decodeFp
 * (base64 -> 40-char uppercase hex) so the keys match exactly what the worker's
 * enrichFromCache lookups expect.
 *
 * In the MICRODESC consensus the `r` line drops the descriptor-digest field, so
 * IP shifts to f[5]. We detect format from the consensus header and index
 * accordingly — this is the format-fragility that, in the worker, forced us to
 * pin the full consensus. Doing it here once, with validation, removes that
 * fragility from the hot path.
 * ============================================================================ */

import { readFileSync, writeFileSync } from "node:fs";

const inPath = process.argv[2] || process.env.CONSENSUS_FILE || "/var/lib/anon/cached-consensus";
const outPath = process.argv[3] || process.env.OUT_FILE || "data/consensus-snapshot.json";

/* base64 identity -> 40-char uppercase hex fingerprint.
 * Mirrors the worker's decodeFp exactly: url-safe chars normalized, padded to a
 * multiple of 4, then byte-by-byte to hex. A 20-byte fingerprint is 27 b64 chars
 * + one '=' of padding. */
function decodeFp(b64id) {
  let s = String(b64id).replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) s += "=";
  const bin = Buffer.from(s, "base64");
  if (bin.length !== 20) throw new Error(`bad fingerprint length ${bin.length}`);
  return [...bin].map((b) => b.toString(16).padStart(2, "0")).join("").toUpperCase();
}

const FP_RE = /^[A-F0-9]{40}$/;
const IPV4_RE = /^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$/;

function parseConsensus(txt) {
  /* Header sanity: a real Tor/Anon consensus starts with this line. */
  if (!/^network-status-version 3/m.test(txt)) {
    throw new Error("input does not look like a consensus (missing 'network-status-version 3')");
  }
  /* Detect microdesc vs full. The microdesc consensus declares
   * "network-status-version 3 microdesc". */
  const isMicrodesc = /^network-status-version 3 microdesc/m.test(txt);
  const ipIndex = isMicrodesc ? 5 : 6; // see header comment for field layout

  const validAfter = (txt.match(/^valid-after (.+)$/m) || [])[1] || null;
  const validUntil = (txt.match(/^valid-until (.+)$/m) || [])[1] || null;

  const fp_to_ip = {};
  let relayCount = 0, skipped = 0;
  for (const line of txt.split("\n")) {
    if (!line.startsWith("r ")) continue;
    const f = line.split(" ");
    let fp;
    try { fp = decodeFp(f[2]); } catch (_) { skipped++; continue; }
    const ip = f[ipIndex];
    if (FP_RE.test(fp) && ip && IPV4_RE.test(ip)) {
      fp_to_ip[fp] = ip;
      relayCount++;
    } else {
      skipped++;
    }
  }
  return { fp_to_ip, relayCount, skipped, isMicrodesc, validAfter, validUntil };
}

function main() {
  let txt;
  try {
    txt = readFileSync(inPath, "utf8");
  } catch (e) {
    console.error(`[build-consensus-snapshot] cannot read input '${inPath}': ${e.message}`);
    process.exit(2);
  }

  let parsed;
  try {
    parsed = parseConsensus(txt);
  } catch (e) {
    console.error(`[build-consensus-snapshot] parse failed: ${e.message}`);
    process.exit(3);
  }

  /* Refuse to publish a degenerate snapshot. Overwriting a good committed file
   * with an empty/garbage one would propagate to the workers and zero out geo
   * enrichment. A real Anyone consensus has thousands of relays; require a sane
   * floor so a half-bootstrapped anon client (which can emit a tiny partial
   * consensus) doesn't clobber the last-known-good commit. */
  const MIN_RELAYS = 500;
  if (parsed.relayCount < MIN_RELAYS) {
    console.error(`[build-consensus-snapshot] only ${parsed.relayCount} relays parsed (< ${MIN_RELAYS} floor) — refusing to write, preserving last-known-good`);
    process.exit(4);
  }

  const snapshot = {
    builtAt: Math.floor(Date.now() / 1000),
    validAfter: parsed.validAfter,
    validUntil: parsed.validUntil,
    relayCount: parsed.relayCount,
    format: parsed.isMicrodesc ? "microdesc" : "full",
    fp_to_ip: parsed.fp_to_ip
  };

  writeFileSync(outPath, JSON.stringify(snapshot) + "\n");
  console.log(`[build-consensus-snapshot] wrote ${outPath}: ${parsed.relayCount} relays (${snapshot.format}), skipped ${parsed.skipped}, validUntil=${parsed.validUntil}`);
}

main();
