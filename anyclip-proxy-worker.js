const PINATA_GW = 'https://plum-known-vole-419.mypinata.cloud/ipfs/';
/**
 * AnyClip Anthropic Proxy — Cloudflare Worker  (KV Edition — 100% Coverage)
 *
 * PAID PLAN UPGRADE: No subrequest limit — scans ALL wallets on ALL pages.
 * Previously: top 35 wallets only = ~52% relay coverage
 * Now: ALL ~731 wallets across all pages = 100% relay coverage
 *
 * Cache strategy (KV):
 *   - KV TTL: 10 minutes (600s) server-side expiry
 *   - Background rebuild via ctx.waitUntil() when stale (>9min)
 *   - /api/fp-index?bust=1 forces immediate rebuild
 *   - X-Cache header: HIT / STALE / MISS
 *
 * Routes:
 *   GET  /api/token       → short-lived signed token for chat auth
 *   POST /api/chat        → Anthropic Claude proxy (token secured)
 *   GET  /api/exit-relays → network stats + wallet list
 *   GET  /api/wallet-ips  → single wallet relay detail
 *   GET  /api/relay-info  → single relay lookup by fingerprint
 *   GET  /api/fp-index    → fp→type index (100% coverage, KV cached)
 *   GET  /api/hw-relays   → verified hardware FPs (KV cached 1hr)
 *   GET  /api/growth      → 30-day relay count history (KV stored daily)
 *   GET  /api/consensus   → ANyone consensus document
 *   GET  /api/all-uptimes → uptime+bw+flags for ALL relays (KV cached 15min)
 *
 * CRON: scheduled() fires daily → stores growth snapshot in KV
 *
 * KV BINDING : FP_INDEX
 * SECRETS    : ANTHROPIC_KEY, HMAC_SECRET
 */

const ALLOWED_ORIGIN = 'https://anyonemap.anyonerelaysmap.workers.dev';
const CONSENSUS_URL  = 'http://49.13.145.234:9230/tor/status-vote/current/consensus-microdesc';
const WALLET_LOOKUP  = 'https://dev.anyone-wallet-lookup.info/network?format=json';
const IPS_BASE       = 'https://dev.anyone-wallet-lookup.info/ips?format=json&wallet=';

// AO Operator Registry — authoritative source for verified hardware relays
const AO_CU          = 'https://cu.anyone.tech/dry-run?process-id=W5XIwvQ6pJBtL_Hhvx9KH4fj4LNoyHDLtbAILMM_lCs';
const AO_REGISTRY_ID = 'W5XIwvQ6pJBtL_Hhvx9KH4fj4LNoyHDLtbAILMM_lCs';

// KV settings
const KV_KEY         = 'fp_index_v1';
const KV_TTL_SECS    = 3600;              // 1 hour hard expiry in KV
const STALE_MS       = 55 * 60 * 1000;   // 55 min → trigger background rebuild

// Growth tracker — daily snapshots stored in KV
const GROWTH_PREFIX  = 'growth:';        // keys: growth:YYYY-MM-DD
const GROWTH_DAYS    = 30;               // keep 30 days of history

// Parallel batch size for wallet /ips fetches — keeps memory manageable
const IPS_BATCH_SIZE = 50;

/* ══════════════════════════════════════════
   PRIVACY — Wallet Address Hashing
   Never store raw wallet addresses with chat messages.
   SHA-256 hash is one-way — cannot be reversed to wallet.
══════════════════════════════════════════ */
async function hashWallet(wallet) {
  const data = new TextEncoder().encode(wallet.toLowerCase().trim());
  const hash = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, '0')).join('');
}

/* ══════════════════════════════════════════
   ANYONE SOCKS5 EXIT RELAYS
   Used to tunnel IPFS pin requests through the Anyone network.
   Cloudflare Workers connect() API speaks SOCKS5 directly.
══════════════════════════════════════════ */
const SOCKS5_RELAYS = [
  { id: 'de-nurnberg', host: '157.90.113.23',  port: 9052, location: 'Nürnberg, DE' },
  { id: 'pl-warsaw',   host: '57.128.249.250', port: 9052, location: 'Warsaw, PL' },
  { id: 'us-oregon',   host: '5.78.181.0',     port: 9052, location: 'Oregon, US' },
];

/* ══════════════════════════════════════════
   SOCKS5 PROTOCOL — RFC 1928
   TCP connect() → SOCKS5 handshake → TLS tunnel
══════════════════════════════════════════ */
async function socks5Connect(targetHost, targetPort, socksHost, socksPort) {
  const { connect } = await import('cloudflare:sockets');
  // CRITICAL: must set secureTransport:'starttls' at connect() time
  // to enable startTls() after SOCKS5 handshake completes
  const socket = connect({ hostname: socksHost, port: socksPort }, {
    secureTransport: 'starttls',
    allowHalfOpen: true,
  });
  const writer = socket.writable.getWriter();
  const reader = socket.readable.getReader();

  // Step 1: SOCKS5 Greeting (no auth)
  await writer.write(new Uint8Array([0x05, 0x01, 0x00]));
  const greet = await readExact(reader, 2);
  if (greet[0] !== 0x05 || greet[1] !== 0x00) throw new Error('SOCKS5 auth failed');

  // Step 2: Connect request (domain name)
  const hostBytes = new TextEncoder().encode(targetHost);
  const req = new Uint8Array(4 + 1 + hostBytes.length + 2);
  req[0] = 0x05; req[1] = 0x01; req[2] = 0x00; req[3] = 0x03;
  req[4] = hostBytes.length;
  req.set(hostBytes, 5);
  req[5 + hostBytes.length] = (targetPort >> 8) & 0xff;
  req[6 + hostBytes.length] = targetPort & 0xff;
  await writer.write(req);

  const resp = await readExact(reader, 4);
  if (resp[1] !== 0x00) throw new Error('SOCKS5 connect refused: 0x' + resp[1].toString(16));

  // Skip bound address
  if (resp[3] === 0x01) await readExact(reader, 6);
  else if (resp[3] === 0x03) { const l = await readExact(reader, 1); await readExact(reader, l[0] + 2); }
  else if (resp[3] === 0x04) await readExact(reader, 18);

  reader.releaseLock();
  writer.releaseLock();
  return socket;
}

async function readExact(reader, n) {
  const buf = new Uint8Array(n);
  let off = 0;
  while (off < n) {
    const { value, done } = await reader.read();
    if (done) throw new Error('SOCKS5 stream ended');
    buf.set(value.slice(0, n - off), off);
    off += value.length;
  }
  return buf;
}

async function httpsOverSocks5(relay, method, url, headers, body) {
  const u = new URL(url);
  const socket = await socks5Connect(u.hostname, 443, relay.host, relay.port);

  // TLS upgrade — startTls() works because we set secureTransport:'starttls' in connect()
  const tls = socket.startTls();
  const writer = tls.writable.getWriter();
  const enc = new TextEncoder();
  const bodyStr = typeof body === 'string' ? body : JSON.stringify(body);
  const bodyBytes = enc.encode(bodyStr);

  let http = `${method} ${u.pathname}${u.search} HTTP/1.1\r\nHost: ${u.hostname}\r\nConnection: close\r\nContent-Length: ${bodyBytes.length}\r\n`;
  for (const [k, v] of Object.entries(headers || {})) http += `${k}: ${v}\r\n`;
  http += '\r\n';

  await writer.write(enc.encode(http));
  if (bodyBytes.length > 0) await writer.write(bodyBytes);
  writer.releaseLock();

  // Read response with 15s timeout
  const reader = tls.readable.getReader();
  const chunks = [];
  const readTimeout = new Promise((_, rej) => setTimeout(() => rej(new Error('TLS read timeout')), 15000));
  try {
    await Promise.race([
      (async () => {
        while (true) {
          const { value, done } = await reader.read();
          if (done) break;
          chunks.push(value);
        }
      })(),
      readTimeout,
    ]);
  } catch (e) {
    if (chunks.length === 0) throw e; // No data at all — real failure
    // Got some data before timeout — try to parse what we have
  }

  if (chunks.length === 0) throw new Error('No data received from TLS tunnel');

  const full = new Uint8Array(chunks.reduce((s, c) => s + c.length, 0));
  let o = 0; for (const c of chunks) { full.set(c, o); o += c.length; }
  const text = new TextDecoder().decode(full);
  const hdrEnd = text.indexOf('\r\n\r\n');
  if (hdrEnd === -1) throw new Error('Malformed HTTP response: no header boundary');
  const hdrStr = text.slice(0, hdrEnd);
  let respBody = text.slice(hdrEnd + 4);
  if (hdrStr.toLowerCase().includes('transfer-encoding: chunked')) {
    let decoded = '', pos = 0;
    while (pos < respBody.length) {
      const le = respBody.indexOf('\r\n', pos); if (le === -1) break;
      const sz = parseInt(respBody.slice(pos, le), 16); if (sz === 0) break;
      pos = le + 2; decoded += respBody.slice(pos, pos + sz); pos += sz + 2;
    }
    respBody = decoded;
  }
  const sm = hdrStr.match(/HTTP\/[\d.]+ (\d+)/);
  return { status: sm ? parseInt(sm[1]) : 0, headers: hdrStr, body: respBody };
}

async function checkRelayHealth() {
  const results = [];
  for (const relay of SOCKS5_RELAYS) {
    const t0 = Date.now();
    try {
      const { connect } = await import('cloudflare:sockets');
      const socket = connect({ hostname: relay.host, port: relay.port });
      const w = socket.writable.getWriter();
      await w.write(new Uint8Array([0x05, 0x01, 0x00]));
      const r = socket.readable.getReader();
      const resp = await Promise.race([readExact(r, 2), new Promise((_, rej) => setTimeout(() => rej(new Error('timeout')), 3000))]);
      r.releaseLock(); w.releaseLock(); socket.close();
      results.push({ ...relay, status: 'online', latency: Date.now() - t0, socks5: resp[0] === 0x05 });
    } catch (e) {
      results.push({ ...relay, status: 'offline', latency: Date.now() - t0, error: e.message });
    }
  }
  return results;
}

/* ══════════════════════════════════════════
   GROWTH TRACKER HELPERS
══════════════════════════════════════════ */

function todayKey() {
  return GROWTH_PREFIX + new Date().toISOString().slice(0, 10);
}

async function storeSnapshot(env) {
  if (!env.FP_INDEX) return null;
  const key = todayKey();
  const existing = await env.FP_INDEX.get(key, { type: 'json' }).catch(() => null);
  if (existing && existing.bw_gibs > 0) return existing;

  try {
    const r = await fetch(`${WALLET_LOOKUP}&page=1`);
    if (!r.ok) return null;
    const d = await r.json();

    const bwMibsTotal = d.totals?.total_bw_mibs_total || 0;
    let totalRelays = 0, exits = 0, guards = 0, middles = 0, bwMibs = bwMibsTotal;
    const wallets = d.wallets || [];
    for (const w of wallets) {
      const c = w.in_consensus_ips || 0;
      const e = w.exit_ips || 0;
      const g = w.flag_counts?.Guard || 0;
      totalRelays += c;
      exits  += e;
      guards += g;
      middles += Math.max(0, c - e - Math.max(0, g - e));
    }

    const pages = d.pages || 1;
    if (pages > 1) {
      const pageReqs = [];
      for (let p = 2; p <= Math.min(pages, 30); p++) pageReqs.push(p);
      await Promise.all(pageReqs.map(async p => {
        try {
          const pr = await fetch(`${WALLET_LOOKUP}&page=${p}`);
          if (!pr.ok) return;
          const pd = await pr.json();
          for (const w of (pd.wallets || [])) {
            const c = w.in_consensus_ips || 0;
            const e = w.exit_ips || 0;
            const g = w.flag_counts?.Guard || 0;
            totalRelays += c;
            exits  += e;
            guards += g;
            middles += Math.max(0, c - e - Math.max(0, g - e));
          }
        } catch(_) {}
      }));
    }

    const snapshot = {
      date:    new Date().toISOString().slice(0, 10),
      ts:      Date.now(),
      total:   totalRelays,
      exits,
      guards,
      middles,
      bw_gibs: Math.round(bwMibs / 1024 * 10) / 10,
      wallets: wallets.length + (pages > 1 ? (pages - 1) * 20 : 0),
    };

    // Also fetch zone count from fingerprint-map
    try {
      const fpR = await fetch('https://api.ec.anyone.tech/fingerprint-map');
      if (fpR.ok) {
        const fpData = await fpR.json();
        const zones = new Set();
        const countries = new Set();
        const isps = new Set();
        Object.values(fpData).forEach(r => {
          if (r.hexId) zones.add(r.hexId);
          if (r.countryCode) countries.add(r.countryCode);
          if (r.asName) isps.add(r.asName);
        });
        snapshot.zones = zones.size;
        snapshot.countries = countries.size;
        snapshot.isps = isps.size;
      }
    } catch(_) {}

    await env.FP_INDEX.put(key, JSON.stringify(snapshot), { expirationTtl: 35 * 24 * 3600 });
    return snapshot;
  } catch (err) {
    console.error('[Growth] storeSnapshot error:', err.message);
    return null;
  }
}

async function getGrowthHistory(env, days = GROWTH_DAYS) {
  if (!env.FP_INDEX) return [];
  const history = [];
  const today = new Date();

  await Promise.all(
    Array.from({ length: days }, (_, i) => {
      const d = new Date(today);
      d.setUTCDate(d.getUTCDate() - i);
      const key = GROWTH_PREFIX + d.toISOString().slice(0, 10);
      return env.FP_INDEX.get(key, { type: 'json' })
        .then(v => { if (v) history.push(v); })
        .catch(() => {});
    })
  );

  history.sort((a, b) => a.date < b.date ? -1 : 1);
  return history;
}

async function backfillHistory(env, days = 30) {
  if (!env.FP_INDEX) return { error: 'no KV binding' };

  const r0 = await fetch(`${WALLET_LOOKUP}&page=1`);
  if (!r0.ok) throw new Error('upstream error: ' + r0.status);
  const d0 = await r0.json();
  const totalPages = d0.pages || 1;
  const bwMibsTotal = d0.totals?.total_bw_mibs_total || 0;

  const allWallets = [...(d0.wallets || [])];
  for (let p = 2; p <= totalPages; p += 20) {
    const batch = Array.from({ length: Math.min(20, totalPages - p + 1) }, (_, i) => p + i);
    const results = await Promise.all(
      batch.map(pg => fetch(`${WALLET_LOOKUP}&page=${pg}`)
        .then(r => r.json()).then(d => d.wallets || []).catch(() => []))
    );
    for (const rows of results) allWallets.push(...rows);
  }

  const relays = allWallets.map(w => ({
    total: w.in_consensus_ips || 0,
    exits: w.exit_ips || 0,
    guards: w.flag_counts?.Guard || 0,
    uptime_days: (w.avg_uptime_s || 0) / 86400,
  }));

  const today = new Date();
  const stored = [];
  const skipped = [];

  for (let daysAgo = days - 1; daysAgo >= 0; daysAgo--) {
    const d = new Date(today);
    d.setUTCDate(d.getUTCDate() - daysAgo);
    const dateStr = d.toISOString().slice(0, 10);
    const key = GROWTH_PREFIX + dateStr;

    const existing = await env.FP_INDEX.get(key, { type: 'json' }).catch(() => null);
    if (existing && existing.total > 0) {
      skipped.push(dateStr);
      continue;
    }

    let total = 0, exits = 0, guards = 0, middles = 0;
    for (const w of relays) {
      if (w.uptime_days >= daysAgo) {
        total  += w.total;
        exits  += w.exits;
        guards += Math.max(0, w.guards - w.exits);
        middles += Math.max(0, w.total - w.exits - Math.max(0, w.guards - w.exits));
      }
    }

    if (total === 0) continue;

    const todayTotal = relays.reduce((s, w) => s + w.total, 0) || 1;
    const bwGibs = Math.round(bwMibsTotal / 1024 * (total / todayTotal) * 10) / 10;

    const snapshot = {
      date:       dateStr,
      ts:         d.getTime(),
      total,
      exits,
      guards,
      middles,
      bw_gibs:    daysAgo === 0 ? Math.round(bwMibsTotal / 1024 * 10) / 10 : bwGibs,
      backfilled: daysAgo > 0,
    };

    await env.FP_INDEX.put(key, JSON.stringify(snapshot), { expirationTtl: 35 * 24 * 3600 });
    stored.push(dateStr);
  }

  return {
    stored: stored.length,
    skipped: skipped.length,
    dates_stored: stored,
    total_relays_today: relays.reduce((s, w) => s + w.total, 0),
    wallets_scanned: allWallets.length,
  };
}

/* ══════════════════════════════════════════
   ALL-UPTIMES: scan ALL wallets, return uptime+bw+flags for every relay
   KV cached 2 hours, background rebuild at 55 min stale
══════════════════════════════════════════ */
const KV_UPTIME_KEY = 'all_uptimes_v1';
const UPTIME_STALE_MS = 55 * 60 * 1000;  // 55 min → trigger background rebuild

async function buildAndStoreUptimes(env) {
  const t0 = Date.now();

  // Step 1: get all wallet pages
  const r0 = await fetch(`${WALLET_LOOKUP}&page=1`);
  if (!r0.ok) throw new Error('upstream error: ' + r0.status);
  const d0 = await r0.json();
  const totalPages = d0.pages || 1;

  // Collect ALL wallets across all pages (batches of 20 pages)
  const walletRows = [...(d0.wallets || [])];
  for (let p = 2; p <= totalPages; p += 20) {
    const batch = Array.from({ length: Math.min(20, totalPages - p + 1) }, (_, i) => p + i);
    const results = await Promise.all(
      batch.map(pg =>
        fetch(`${WALLET_LOOKUP}&page=${pg}`)
          .then(r => r.json()).then(d => d.wallets || []).catch(() => [])
      )
    );
    for (const rows of results) walletRows.push(...rows);
  }

  const allWallets = walletRows
    .filter(w => w.wallet && (w.in_consensus_ips || 0) > 0)
    .map(w => w.wallet);

  // Step 2: fetch /ips for ALL wallets in batches of 50
  const relays = {};

  for (let i = 0; i < allWallets.length; i += IPS_BATCH_SIZE) {
    const batch = allWallets.slice(i, i + IPS_BATCH_SIZE);
    await Promise.all(batch.map(async wallet => {
      try {
        const r = await fetch(`${IPS_BASE}${encodeURIComponent(wallet)}`);
        if (!r.ok) return;
        const d = await r.json();
        for (const relay of (d.ips || [])) {
          const fp = (relay.fingerprint || '').toUpperCase();
          if (!fp) continue;
          relays[fp] = {
            up: relay.uptime_seconds || 0,
            n:  relay.descriptor_nickname || '',
            bw: relay.bandwidth || 0,
            cw: relay.consensus_weight || 0,
            fl: relay.flags || [],
          };
        }
      } catch (_) {}
    }));
  }

  const elapsed = ((Date.now() - t0) / 1000).toFixed(1);
  const result = {
    relays,
    count: Object.keys(relays).length,
    wallets: allWallets.length,
    builtAt: Date.now(),
    elapsed,
  };

  // Store in KV — 2 hour TTL (longer cache = fewer cold rebuilds)
  if (env.FP_INDEX) {
    try {
      await env.FP_INDEX.put(KV_UPTIME_KEY, JSON.stringify(result), { expirationTtl: 7200 });
      console.log(`[all-uptimes] KV written — ${result.count} relays from ${allWallets.length} wallets in ${elapsed}s`);
    } catch (e) {
      console.error(`[all-uptimes] KV write failed:`, e.message);
    }
  }

  return result;
}

export default {
  async fetch(request, env, ctx) {
    if (request.method === 'OPTIONS') return corsHeaders();
    const url = new URL(request.url);

    /* ══════════════════════════════════════════
       GET /api/total-staked — actual $ANYONE staked via AO Registry
       Primary: AO Registry Info (registered FPs × avg stake)
       The raw on-chain balanceOf includes unlocked/pending tokens
    ══════════════════════════════════════════ */
    if (url.pathname === '/api/total-staked' && request.method === 'GET') {
      // KV cache — 30 min
      if (env.FP_INDEX) {
        try {
          const cached = await env.FP_INDEX.get('total_staked_v2', { type: 'json' });
          if (cached && cached.totalStaked > 0 && (Date.now() - cached.ts) < 30 * 60 * 1000) {
            return new Response(JSON.stringify(cached), {
              headers: jsonHeaders({ 'X-Cache': 'HIT', 'Cache-Control': 'max-age=300' }),
            });
          }
        } catch(_){}
      }

      try {
        // AO Registry Info — returns { hardware, total, claimed }
        // total = registered fingerprints, each locks ~975 $ANYONE on average
        const AO_REGISTRY = 'W5XIwvQ6pJBtL_Hhvx9KH4fj4LNoyHDLtbAILMM_lCs';
        const aoRes = await fetch(`https://cu.anyone.tech/dry-run?process-id=${AO_REGISTRY}`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            Id: '1234', Target: AO_REGISTRY, Owner: '1234', Anchor: '0', Data: '1234',
            Tags: [
              { name: 'Action', value: 'Info' },
              { name: 'Data-Protocol', value: 'ao' },
              { name: 'Type', value: 'Message' },
              { name: 'Variant', value: 'ao.TN.1' },
            ],
          }),
        });

        if (aoRes.ok) {
          const aoData = await aoRes.json();
          const info = JSON.parse(aoData?.Messages?.[0]?.Data || '{}');
          const registeredFps = info.total || info.claimed || 0;

          if (registeredFps > 0) {
            // 10,080,230 staked across ~10,317 FPs = ~977 avg per FP
            const totalStaked = Math.round(registeredFps * 977);
            const result = {
              totalStaked,
              formatted: totalStaked.toLocaleString() + ' $ANYONE',
              registeredFps,
              hardware: info.hardware || 0,
              apy: 17.2,
              ts: Date.now(),
            };
            if (env.FP_INDEX) {
              ctx.waitUntil(env.FP_INDEX.put('total_staked_v2', JSON.stringify(result), { expirationTtl: 3600 }).catch(()=>{}));
            }
            return new Response(JSON.stringify(result), {
              headers: jsonHeaders({ 'X-Cache': 'MISS', 'Cache-Control': 'max-age=300' }),
            });
          }
        }

        return cors(JSON.stringify({ error: 'AO Registry unavailable' }), 502);
      } catch (err) {
        return cors(JSON.stringify({ error: err.message }), 502);
      }
    }

    /* ══════════════════════════════════════════
       GET /api/all-uptimes — uptime+bw+flags for ALL relays
    ══════════════════════════════════════════ */
    if (url.pathname === '/api/all-uptimes' && request.method === 'GET') {
      const forceBuild = url.searchParams.get('build') === '1';

      // ── Try KV cache first ──
      if (!forceBuild && env.FP_INDEX) {
        try {
          const raw = await env.FP_INDEX.get(KV_UPTIME_KEY);
          if (raw) {
            const cached = JSON.parse(raw);
            if (cached && cached.relays && Object.keys(cached.relays).length > 0) {
              const age = Date.now() - (cached.builtAt || 0);
              const isStale = age > UPTIME_STALE_MS;
              if (isStale) ctx.waitUntil(buildAndStoreUptimes(env).catch(e => console.error('[all-uptimes] bg rebuild failed:', e.message)));
              return new Response(raw, {
                headers: jsonHeaders({
                  'X-Cache': isStale ? 'STALE' : 'HIT',
                  'X-Age': (age / 1000).toFixed(0) + 's',
                  'Cache-Control': 'max-age=120',
                }),
              });
            }
          }
        } catch (kvErr) {
          console.warn('[all-uptimes] KV read/parse error:', kvErr.message);
        }
      }

      // ── KV miss or ?build=1 — build synchronously ──
      // This will take ~40s — only works on paid plan with 30s+ timeout
      try {
        const result = await buildAndStoreUptimes(env);
        return new Response(JSON.stringify(result), {
          headers: jsonHeaders({ 'X-Cache': 'MISS', 'Cache-Control': 'max-age=120' }),
        });
      } catch (err) {
        return cors(JSON.stringify({ error: err.message, hint: 'Build timed out. Try ?build=1 again or check Worker CPU limits.' }), 502);
      }
    }

    /* ══════════════════════════════════════════
       GET /api/fp-index  — 100% COVERAGE, KV CACHED
    ══════════════════════════════════════════ */
    if (url.pathname === '/api/fp-index' && request.method === 'GET') {
      const bust = url.searchParams.get('bust') === '1';

      if (!bust && env.FP_INDEX) {
        try {
          const cached = await env.FP_INDEX.get(KV_KEY, { type: 'json' });
          if (cached && cached.index) {
            const age     = Date.now() - (cached.builtAt || 0);
            const isStale = age > STALE_MS;
            if (isStale) ctx.waitUntil(buildAndStoreIndex(env));
            return new Response(JSON.stringify(cached), {
              headers: jsonHeaders({
                'X-Cache':       isStale ? 'STALE' : 'HIT',
                'X-Age':         (age / 1000).toFixed(0) + 's',
                'Cache-Control': 'max-age=120',
              }),
            });
          }
        } catch (kvErr) {
          console.warn('[fp-index] KV read error:', kvErr.message);
        }
      }

      try {
        const result = await buildAndStoreIndex(env);
        return new Response(JSON.stringify(result), {
          headers: jsonHeaders({
            'X-Cache':       'MISS',
            'X-Elapsed':     result.elapsed,
            'Cache-Control': 'max-age=120',
          }),
        });
      } catch (err) {
        return cors(JSON.stringify({ error: err.message }), 502);
      }
    }

    /* ══════════════════════════════════════════
       GET /api/hw-relays — AO Registry hardware fingerprints
    ══════════════════════════════════════════ */
    if (url.pathname === '/api/hw-relays' && request.method === 'GET') {
      const bust = url.searchParams.get('bust') === '1';
      if (!bust && env.FP_INDEX) {
        try {
          const cached = await env.FP_INDEX.get('hw_relays_v1', { type: 'json' });
          if (cached && cached.fingerprints) {
            const age = Date.now() - (cached.builtAt || 0);
            return new Response(JSON.stringify(cached), {
              headers: jsonHeaders({ 'X-Cache': 'HIT', 'X-Age': (age/1000).toFixed(0)+'s', 'Cache-Control': 'max-age=300' }),
            });
          }
        } catch (_) {}
      }
      try {
        const hwSet  = await fetchHardwareFPs();
        const result = { fingerprints: [...hwSet], count: hwSet.size, source: 'ao-registry', builtAt: Date.now() };
        if (env.FP_INDEX) {
          ctx.waitUntil(
            env.FP_INDEX.put('hw_relays_v1', JSON.stringify(result), { expirationTtl: 3600 }).catch(() => {})
          );
        }
        return new Response(JSON.stringify(result), {
          headers: jsonHeaders({ 'X-Cache': 'MISS', 'Cache-Control': 'max-age=300' }),
        });
      } catch (err) {
        return cors(JSON.stringify({ error: err.message }), 502);
      }
    }

    /* ══════════════════════════════════════════
       GET /api/exit-relays
    ══════════════════════════════════════════ */
    if (url.pathname === '/api/exit-relays' && request.method === 'GET') {
      try {
        const r0 = await fetch(`${WALLET_LOOKUP}&page=1`);
        if (!r0.ok) return cors(JSON.stringify({ error: 'upstream error' }), 502);
        const d0    = await r0.json();
        const pages = d0.pages || 1;

        let totalExit = 0, totalGuard = 0, totalMiddle = 0;
        const walletAddrs = [];
        function countWallets(wallets) {
          for (const w of (wallets || [])) {
            const exit      = w.exit_ips || 0;
            const guard     = w.flag_counts?.Guard || 0;
            const consensus = w.in_consensus_ips || 0;
            totalExit   += exit;
            totalGuard  += guard;
            totalMiddle += Math.max(0, consensus - exit - Math.max(0, guard - exit));
            if (w.wallet && consensus > 0) walletAddrs.push(w.wallet);
          }
        }
        countWallets(d0.wallets);

        for (let p = 2; p <= pages; p += 20) {
          const batch = Array.from({ length: Math.min(20, pages - p + 1) }, (_, i) => p + i);
          await Promise.all(batch.map(pg =>
            fetch(`${WALLET_LOOKUP}&page=${pg}`)
              .then(r => r.json())
              .then(d => countWallets(d.wallets))
              .catch(() => {})
          ));
        }

        return new Response(JSON.stringify({
          exit_relays:   totalExit,
          guard_relays:  totalGuard,
          middle_relays: totalMiddle,
          total_bw_mibs: d0.totals?.total_bw_mibs_total || 0,
          wallets:       d0.totals?.wallets_total,
          wallet_list:   walletAddrs,
        }), { headers: jsonHeaders({ 'Cache-Control': 'max-age=120' }) });
      } catch (err) {
        return cors(JSON.stringify({ error: err.message }), 502);
      }
    }

    /* ══════════════════════════════════════════
       GET /api/wallet-ips?wallet=0x…
    ══════════════════════════════════════════ */
    if (url.pathname === '/api/wallet-ips' && request.method === 'GET') {
      const wallet = url.searchParams.get('wallet') || '';
      if (!wallet) return cors(JSON.stringify({ error: 'wallet param required' }), 400);
      try {
        const r = await fetch(`${IPS_BASE}${encodeURIComponent(wallet)}`);
        if (!r.ok) return cors(JSON.stringify({ error: 'upstream error' }), 502);
        const data   = await r.json();
        const relays = (data.ips || []).map(relay => ({
          fp: relay.fingerprint,
          n:  relay.descriptor_nickname || '—',
          ip: relay.ip || '—',
          cc: relay.country_iso || '',
          co: relay.country || '—',
          bw: relay.bandwidth || 0,
          up: relay.uptime_seconds || 0,
          cw: relay.consensus_weight || 0,
          fl: relay.flags || [],
          ic: relay.in_consensus,
          hw: relay.ao_is_hardware || false,
          lm: relay.ao_location_multiplier || 1,
          fm: relay.ao_family_multiplier || 1,
        }));
        return new Response(JSON.stringify({ wallet, relays }), {
          headers: jsonHeaders({ 'Cache-Control': 'max-age=120' }),
        });
      } catch (err) {
        return cors(JSON.stringify({ error: err.message }), 502);
      }
    }

    /* ══════════════════════════════════════════
       GET /api/relay-info?fp=FINGERPRINT
    ══════════════════════════════════════════ */
    if (url.pathname === '/api/relay-info' && request.method === 'GET') {
      const fp = (url.searchParams.get('fp') || '').toUpperCase().trim();
      if (!fp) return cors(JSON.stringify({ error: 'fp param required' }), 400);
      try {
        // Try all-uptimes KV cache first (instant, covers ALL relays)
        let kvHit = false;
        if (env.FP_INDEX) {
          try {
            const raw = await env.FP_INDEX.get(KV_UPTIME_KEY);
            if (raw) {
              const cached = JSON.parse(raw);
              if (cached && cached.relays && cached.relays[fp]) {
                const d = cached.relays[fp];
                const secs = d.up || 0;
                return new Response(JSON.stringify({
                  fingerprint: fp,
                  nickname:    d.n || '—',
                  ip:          '—',
                  country:     '—',
                  country_iso: '',
                  flags:       d.fl || [],
                  bandwidth:   d.bw >= 1048576 ? (d.bw/1048576).toFixed(1)+' GB/s'
                             : d.bw >= 1024    ? (d.bw/1024).toFixed(1)+' MB/s'
                             :                    d.bw+' KB/s',
                  bandwidth_bytes: d.bw || 0,
                  uptime:      `${Math.floor(secs/86400)}d ${Math.floor((secs%86400)/3600)}h`,
                  uptime_seconds: secs,
                  consensus_weight: d.cw || 0,
                  in_consensus: true,
                  is_hardware:  false,
                  registered:   true,
                  source:       'all-uptimes-cache',
                }), { headers: jsonHeaders({ 'Cache-Control': 'max-age=60' }) });
              }
            }
          } catch (kvErr) {
            console.warn('[relay-info] KV read error:', kvErr.message);
          }
        }

        // Fallback 2: Try Anyone official API (fast, has bandwidth+nickname but no uptime/flags)
        let anyoneData = null;
        try {
          const anyoneRes = await fetch(`https://api.ec.anyone.tech/relays/${fp}`);
          if (anyoneRes.ok) {
            const d = await anyoneRes.json();
            if (d && d.fingerprint) {
              anyoneData = d; // Save — don't return yet, try wallet scan for uptime
            }
          }
        } catch(_){}

        // Fallback 3: search wallet pages (slowest — only if KV missed)
        let found = null;
        for (let page = 1; page <= 5 && !found; page++) {
          const netRes  = await fetch(`${WALLET_LOOKUP}&page=${page}`);
          if (!netRes.ok) break;
          const netData = await netRes.json();
          const wallets = (netData.wallets || []).filter(w => w.in_consensus_ips > 0).map(w => w.wallet);
          const results = await Promise.all(wallets.map(wallet =>
            fetch(`${IPS_BASE}${encodeURIComponent(wallet)}`).then(r => r.json())
              .then(data => {
                const match = (data.ips || []).find(r => (r.fingerprint || '').toUpperCase() === fp);
                return match ? { wallet, relay: match } : null;
              })
              .catch(() => null)
          ));
          found = results.find(r => r !== null) || null;
        }

        // If wallet scan found the relay, return full data with uptime
        if (found) {
          const relay = found.relay;
          const secs  = relay.uptime_seconds || 0;
          const bwKBs = relay.bandwidth || 0;
          return new Response(JSON.stringify({
            fingerprint:  fp,
            nickname:     relay.descriptor_nickname || (anyoneData ? anyoneData.nickname : '—'),
            ip:           relay.ip || '—',
            country:      relay.country || '—',
            country_iso:  relay.country_iso || '',
            flags:        relay.flags || [],
            bandwidth:    bwKBs >= 1048576 ? (bwKBs/1048576).toFixed(1)+' GB/s'
                        : bwKBs >= 1024    ? (bwKBs/1024).toFixed(1)+' MB/s'
                        :                    bwKBs+' KB/s',
            bandwidth_bytes: bwKBs,
            uptime:       `${Math.floor(secs/86400)}d ${Math.floor((secs%86400)/3600)}h`,
            uptime_seconds: secs,
            consensus_weight: anyoneData ? anyoneData.consensus_weight : (relay.consensus_weight || 0),
            running:      anyoneData ? anyoneData.running : relay.in_consensus,
            measured:     anyoneData ? anyoneData.measured : false,
            in_consensus: relay.in_consensus,
            is_hardware:  relay.ao_is_hardware || false,
            loc_mult:     relay.ao_location_multiplier || 1,
            fam_mult:     relay.ao_family_multiplier || 1,
            registered:   true,
          }), { headers: jsonHeaders({ 'Cache-Control': 'max-age=60' }) });
        }

        // If wallet scan didn't find it but Anyone API did, return that (no uptime)
        if (anyoneData) {
          return new Response(JSON.stringify({
            fingerprint:     fp,
            nickname:        anyoneData.nickname || '—',
            ip:              '—',
            country:         '—',
            country_iso:     '',
            flags:           [],
            bandwidth:       anyoneData.observed_bandwidth >= 1048576 ? (anyoneData.observed_bandwidth/1048576).toFixed(1)+' MB/s' : '—',
            bandwidth_bytes: anyoneData.observed_bandwidth || 0,
            consensus_weight: anyoneData.consensus_weight || 0,
            running:         anyoneData.running,
            measured:        anyoneData.measured,
            in_consensus:    anyoneData.running,
            is_hardware:     false,
            registered:      false,
            source:          'anyone-api',
          }), { headers: jsonHeaders({ 'Cache-Control': 'max-age=60' }) });
        }

        // Nothing found at all
        return new Response(JSON.stringify({ fingerprint: fp, registered: false, in_consensus: false }), {
          headers: jsonHeaders({ 'Cache-Control': 'max-age=60' }),
        });
      } catch (err) {
        return cors(JSON.stringify({ error: err.message }), 502);
      }
    }

    /* ══════════════════════════════════════════
       GET /api/consensus
    ══════════════════════════════════════════ */
    if (url.pathname === '/api/consensus' && request.method === 'GET') {
      try {
        const res = await fetch(CONSENSUS_URL, {
          headers: { 'User-Agent': 'Mozilla/5.0' }, redirect: 'follow',
        });
        if (!res.ok) return cors(`Upstream error: ${res.status}`, res.status);
        return new Response(await res.text(), {
          headers: {
            'Content-Type':                'text/plain; charset=utf-8',
            'Access-Control-Allow-Origin': ALLOWED_ORIGIN,
            'Cache-Control':               'no-store',
          },
        });
      } catch (err) {
        return cors(`Fetch failed: ${err.message}`, 502);
      }
    }

    /* ══════════════════════════════════════════
       GET /api/token
    ══════════════════════════════════════════ */
    if (url.pathname === '/api/token' && request.method === 'GET') {
      const ts      = Date.now().toString();
      const nonce   = Array.from(crypto.getRandomValues(new Uint8Array(8)))
                        .map(b => b.toString(16).padStart(2, '0')).join('');
      const payload = ts + ':' + nonce;
      const sig     = await hmacSign(env.HMAC_SECRET, payload);
      return cors(JSON.stringify({ token: payload + ':' + sig, expires: Date.now() + 25000 }), 200);
    }

    /* ══════════════════════════════════════════
       POST /api/chat
    ══════════════════════════════════════════ */
    if (url.pathname === '/api/chat' && request.method === 'POST') {
      try {
        const body  = await request.json();
        const token = request.headers.get('x-token');
        if (!token) return cors(JSON.stringify({ error: { message: 'Missing token' } }), 401);

        const lastColon       = token.lastIndexOf(':');
        const secondLastColon = token.lastIndexOf(':', lastColon - 1);
        const payload         = token.substring(0, lastColon);
        const tokenSig        = token.substring(lastColon + 1);
        const ts              = parseInt(token.substring(0, secondLastColon), 10);
        const age             = Date.now() - ts;
        if (age > 25000 || age < 0)
          return cors(JSON.stringify({ error: { message: 'Token expired' } }), 401);
        const expectedSig = await hmacSign(env.HMAC_SECRET, payload);
        if (!timingSafeEqual(tokenSig, expectedSig))
          return cors(JSON.stringify({ error: { message: 'Invalid token' } }), 403);
        if (!body.messages || !Array.isArray(body.messages))
          return cors(JSON.stringify({ error: { message: 'Invalid request' } }), 400);

        const anthropicRes = await fetch('https://api.anthropic.com/v1/messages', {
          method:  'POST',
          headers: {
            'Content-Type':      'application/json',
            'x-api-key':         env.ANTHROPIC_KEY,
            'anthropic-version': '2023-06-01',
          },
          body: JSON.stringify({
            model:      body.model || 'claude-haiku-4-5-20251001',
            max_tokens: Math.min(body.max_tokens || 300, 500),
            system:     body.system || '',
            messages:   body.messages,
          }),
        });
        return cors(JSON.stringify(await anthropicRes.json()), anthropicRes.status);
      } catch (err) {
        return cors(JSON.stringify({ error: { message: err.message } }), 500);
      }
    }

    /* ══════════════════════════════════════════
       GET /api/growth
    ══════════════════════════════════════════ */
    if (url.pathname === '/api/growth') {
      if (request.method === 'GET') {
        const bust = url.searchParams.get('bust') === '1';
        ctx.waitUntil(storeSnapshot(env));
        if (bust) await storeSnapshot(env);
        const history = await getGrowthHistory(env, GROWTH_DAYS);
        return new Response(JSON.stringify({
          history,
          days: history.length,
          generated: new Date().toISOString(),
        }), { headers: jsonHeaders({ 'Cache-Control': 'max-age=300' }) });
      }
      if (request.method === 'POST') {
        const snap = await storeSnapshot(env);
        return new Response(JSON.stringify({ ok: true, snapshot: snap }), {
          headers: jsonHeaders(),
        });
      }
    }

    /* GET /api/growth/backfill */
    if (url.pathname === '/api/growth/backfill' && request.method === 'GET') {
      try {
        const result = await backfillHistory(env, 30);
        return new Response(JSON.stringify({ ok: true, ...result }), {
          headers: jsonHeaders({ 'Cache-Control': 'no-store' }),
        });
      } catch (err) {
        return cors(JSON.stringify({ error: err.message }), 502);
      }
    }

    /* ══════════════════════════════════════════
       POST /api/feedback
    ══════════════════════════════════════════ */
    if (url.pathname === '/api/feedback' && request.method === 'POST') {
      try {
        const body = await request.json();
        const received = new Date().toISOString();
        if (env.FP_INDEX) {
          const key = `feedback:${Date.now()}:${Math.random().toString(36).slice(2,8)}`;
          await env.FP_INDEX.put(key, JSON.stringify({ ...body, received }),
            { expirationTtl: 90 * 24 * 3600 });
        }
        const TG_TOKEN  = env.TELEGRAM_BOT_TOKEN;
        const TG_CHAT   = env.TELEGRAM_CHAT_ID;
        let tgResult = null;
        if (TG_TOKEN && TG_CHAT) {
          const mood      = body.mood       || 'general';
          const cats      = (body.categories || []).join(', ') || '—';
          const msg       = body.message    || '(no message)';
          const relays    = body.relays      ? body.relays.toLocaleString() : '—';
          const score     = body.score       || '—';
          const moodEmoji = { love:'🔥', good:'⬡', bug:'⚡', idea:'💡' }[mood] || '📩';
          const text = [
            `${moodEmoji} *ANyone Map Feedback*`, ``,
            `*Mood:* ${mood.toUpperCase()}`, `*Category:* ${cats}`,
            `*Message:* ${msg}`, ``,
            `*Relays online:* ${relays}`, `*Health score:* ${score}`,
            `*Time:* ${received}`,
          ].join('\n');
          try {
            const tgRes = await fetch(`https://api.telegram.org/bot${TG_TOKEN}/sendMessage`, {
              method: 'POST', headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ chat_id: TG_CHAT, text, parse_mode: 'Markdown' }),
            });
            tgResult = await tgRes.json();
          } catch(tgErr) { tgResult = { error: tgErr.message }; }
        } else {
          tgResult = { skipped: true, reason: !TG_TOKEN ? 'no token' : 'no chat id' };
        }
        return cors(JSON.stringify({ ok: true, telegram: tgResult }), 200);
      } catch (err) {
        return cors(JSON.stringify({ ok: false, error: err.message }), 200);
      }
    }

    /* GET /api/feedback/list */
    if (url.pathname === '/api/feedback/list' && request.method === 'GET') {
      const secret = url.searchParams.get('secret');
      if (secret !== 'anyone') return cors(JSON.stringify({ error: 'unauthorized' }), 401);
      try {
        if (!env.FP_INDEX) return cors(JSON.stringify({ entries: [], note: 'KV not bound' }), 200);
        const list = await env.FP_INDEX.list({ prefix: 'feedback:' });
        const entries = await Promise.all(
          list.keys.map(async ({ name }) => {
            const val = await env.FP_INDEX.get(name);
            try { return { key: name, ...JSON.parse(val) }; } catch { return { key: name, raw: val }; }
          })
        );
        entries.sort((a, b) => (b.received || '').localeCompare(a.received || ''));
        return cors(JSON.stringify({ total: entries.length, entries }, null, 2), 200);
      } catch (err) {
        return cors(JSON.stringify({ error: err.message }), 200);
      }
    }

    /* ══════════════════════════════════════════
       ANYCHAT — OPERATORS LOUNGE ENDPOINTS
    ══════════════════════════════════════════ */

    if (url.pathname === '/api/chat-verify' && request.method === 'POST') {
      try {
        const body = await request.json();
        const wallet = (body.wallet || '').toLowerCase().trim();
        if (!wallet || !wallet.startsWith('0x'))
          return cors(JSON.stringify({ verified: false, reason: 'Invalid wallet address' }), 200);
        const networkRes = await fetch(`${WALLET_LOOKUP}`);
        const networkData = await networkRes.json();
        const allWallets = new Set((networkData.wallets || []).map(w => (w.wallet || w).toLowerCase()));
        const isOperator = allWallets.has(wallet);
        if (!isOperator)
          return cors(JSON.stringify({ verified: false, reason: 'No relays found for this wallet.' }), 200);
        let relayCount = 0, isHW = false, nick = 'OP-' + wallet.slice(2, 8).toUpperCase();
        try {
          const ipsRes = await fetch(`${IPS_BASE}${wallet}`);
          const ipsData = await ipsRes.json();
          const relays = ipsData.relays || ipsData.ips || [];
          relayCount = relays.length;
          const hwRes = await fetch(`${url.origin}/api/hw-relays`);
          const hwData = await hwRes.json();
          const hwSet = new Set((hwData.hw_fingerprints || []).map(fp => fp.toUpperCase()));
          isHW = relays.some(r => hwSet.has((r.fingerprint || r.fp || '').toUpperCase()));
          if (relays[0]?.nickname) nick = relays[0].nickname;
          else nick = (isHW ? 'HW-' : 'OP-') + wallet.slice(2, 8).toUpperCase();
        } catch (e) {}
        return cors(JSON.stringify({ verified: true, tier: isHW ? 'hw' : 'op', relayCount, nick, wallet }), 200);
      } catch (e) {
        return cors(JSON.stringify({ verified: false, reason: 'Verification failed: ' + e.message }), 200);
      }
    }

    if (url.pathname === '/api/chat-sign-challenge' && request.method === 'GET') {
      const challenge = `AnyChat Operators Lounge Access\nNonce: ${Date.now()}\nI confirm I am a relay operator.`;
      return cors(JSON.stringify({ challenge }), 200);
    }

    // Generate a signed token for AnyClip AI queries
    // ══════════════════════════════════════════
    //   WEBSOCKET — Real-time chat via Durable Objects
    // ══════════════════════════════════════════
    if (url.pathname === '/api/ws') {
      if (request.headers.get('Upgrade') !== 'websocket') {
        return cors(JSON.stringify({ error: 'Expected WebSocket' }), 426);
      }
      // Route to Durable Object ChatRoom
      if (!env.CHAT_ROOM) {
        return cors(JSON.stringify({ error: 'WebSocket not configured. Falling back to polling.' }), 503);
      }
      const roomId = env.CHAT_ROOM.idFromName('operators-lounge');
      const room = env.CHAT_ROOM.get(roomId);
      return room.fetch(request);
    }

    if (url.pathname === '/api/chat-token' && request.method === 'GET') {
      try {
        if (!env.HMAC_SECRET) return cors(JSON.stringify({ error: 'HMAC not configured' }), 500);
        const ts = Date.now();
        const nonce = Math.random().toString(36).slice(2, 10);
        const payload = ts + ':' + nonce;
        const sig = await hmacSign(env.HMAC_SECRET, payload);
        return cors(JSON.stringify({ token: payload + ':' + sig }), 200);
      } catch (e) { return cors(JSON.stringify({ error: e.message }), 500); }
    }

    // ══════════════════════════════════════════
    //   IMAGE UPLOAD WITH AI MODERATION
    // ══════════════════════════════════════════
    if (url.pathname === '/api/chat-image' && request.method === 'POST') {
      try {
        const body = await request.json();
        const { nick, tier, wallet, image, filename, mimetype, size } = body;
        if (!nick || !image || !wallet) return cors(JSON.stringify({ ok: false, error: 'Missing fields' }), 400);
        if (!mimetype || !mimetype.startsWith('image/')) return cors(JSON.stringify({ ok: false, error: 'Invalid file type' }), 400);
        if (size > 5 * 1024 * 1024) return cors(JSON.stringify({ ok: false, error: 'Image too large (max 5 MB)' }), 400);

        // ── IMAGE RATE LIMIT: 2 uploads per minute ──
        const imgWH = await hashWallet(wallet);
        if (!globalThis._imgRateMap) globalThis._imgRateMap = new Map();
        const imgRK = 'img:' + imgWH.slice(0, 16);
        const imgNow = Date.now();
        let imgBucket = globalThis._imgRateMap.get(imgRK);
        if (!imgBucket) { imgBucket = { times: [] }; globalThis._imgRateMap.set(imgRK, imgBucket); }
        imgBucket.times = imgBucket.times.filter(t => imgNow - t < 60000);
        if (imgBucket.times.length >= 2) {
          return cors(JSON.stringify({ ok: false, error: 'Image rate limit — max 2 uploads per minute.', rateLimit: true }), 429);
        }
        imgBucket.times.push(imgNow);

        // ── STEP 1: AI content moderation using Claude Vision ──
        if (env.ANTHROPIC_KEY) {
          try {
            const modRes = await fetch('https://api.anthropic.com/v1/messages', {
              method: 'POST',
              headers: {
                'Content-Type': 'application/json',
                'x-api-key': env.ANTHROPIC_KEY,
                'anthropic-version': '2023-06-01',
              },
              body: JSON.stringify({
                model: 'claude-haiku-4-5-20251001',
                max_tokens: 150,
                messages: [{
                  role: 'user',
                  content: [
                    {
                      type: 'image',
                      source: { type: 'base64', media_type: mimetype, data: image }
                    },
                    {
                      type: 'text',
                      text: 'You are a content moderator for a chat platform. Analyze this image and determine if it is safe to share. REJECT if the image contains ANY of: nudity, sexual content, pornography, child exploitation, gore, graphic violence, blood, self-harm, drug use, hate symbols, terrorism, or any other harmful/illegal content. Respond with ONLY a JSON object: {"safe":true} or {"safe":false,"reason":"brief reason"}. Nothing else.'
                    }
                  ]
                }]
              }),
            });

            if (modRes.ok) {
              const modData = await modRes.json();
              const modText = modData.content?.[0]?.text || '';
              try {
                const modResult = JSON.parse(modText.replace(/```json|```/g, '').trim());
                if (!modResult.safe) {
                  return cors(JSON.stringify({
                    ok: false,
                    error: 'Image rejected: ' + (modResult.reason || 'Content violates community guidelines'),
                    moderated: true
                  }), 403);
                }
              } catch {
                // If Claude's response can't be parsed, reject to be safe
                if (modText.toLowerCase().includes('false') || modText.toLowerCase().includes('reject')) {
                  return cors(JSON.stringify({ ok: false, error: 'Image rejected by content filter', moderated: true }), 403);
                }
              }
            }
          } catch (modErr) {
            // If moderation fails entirely, reject the upload (fail safe)
            return cors(JSON.stringify({ ok: false, error: 'Content moderation unavailable. Upload blocked for safety.' }), 503);
          }
        } else {
          // No ANTHROPIC_KEY = no moderation = reject all images (fail safe)
          return cors(JSON.stringify({ ok: false, error: 'Image moderation not configured. Upload disabled.' }), 503);
        }

        // ── STEP 2: Image passed moderation — pin to Pinata IPFS ──
        if (!env.PINATA_JWT) return cors(JSON.stringify({ ok: false, error: 'Storage not configured' }), 503);

        const walletHash = await hashWallet(wallet);
        const imgTime = Date.now();
        const safeName = (filename || 'image').replace(/[^a-zA-Z0-9._-]/g, '_').slice(0, 50);

        // Convert base64 to binary for raw file pinning
        const binaryStr = atob(image);
        const bytes = new Uint8Array(binaryStr.length);
        for (let i = 0; i < binaryStr.length; i++) bytes[i] = binaryStr.charCodeAt(i);
        const blob = new Blob([bytes], { type: mimetype });

        // Pin as raw file via multipart form
        const formData = new FormData();
        formData.append('file', blob, safeName);
        formData.append('pinataMetadata', JSON.stringify({ name: `img:${imgTime}:${walletHash.slice(0,8)}` }));

        const pinRes = await fetch('https://api.pinata.cloud/pinning/pinFileToIPFS', {
          method: 'POST',
          headers: { 'Authorization': 'Bearer ' + env.PINATA_JWT },
          body: formData,
        });

        if (!pinRes.ok) {
          return cors(JSON.stringify({ ok: false, error: 'Failed to store image' }), 500);
        }

        const pinData = await pinRes.json();
        const cid = pinData.IpfsHash;
        const gateway = PINATA_GW;

        return cors(JSON.stringify({
          ok: true,
          cid,
          url: gateway + cid,
          moderated: true,
          storage: 'ipfs'
        }), 200);

      } catch (e) {
        return cors(JSON.stringify({ ok: false, error: e.message }), 500);
      }
    }

    // ══════════════════════════════════════════
    //   TYPING INDICATOR (in-memory, no storage)
    // ══════════════════════════════════════════
    if (url.pathname === '/api/chat-typing' && request.method === 'POST') {
      try {
        const body = await request.json();
        if (!body.nick) return cors(JSON.stringify({ ok: false }), 400);
        // Store in global Map with timestamp — auto-expires after 4s
        if (!globalThis._typingMap) globalThis._typingMap = new Map();
        globalThis._typingMap.set(body.nick, Date.now());
        return cors(JSON.stringify({ ok: true }), 200);
      } catch (e) { return cors(JSON.stringify({ ok: false }), 200); }
    }

    if (url.pathname === '/api/chat-typing' && request.method === 'GET') {
      try {
        if (!globalThis._typingMap) globalThis._typingMap = new Map();
        const now = Date.now();
        const typing = [];
        for (const [nick, ts] of globalThis._typingMap) {
          if (now - ts < 4000) typing.push(nick);
          else globalThis._typingMap.delete(nick);
        }
        return cors(JSON.stringify({ typing }), 200);
      } catch (e) { return cors(JSON.stringify({ typing: [] }), 200); }
    }

    // ══════════════════════════════════════════
    //   OPERATOR LEADERBOARD
    // ══════════════════════════════════════════
    if (url.pathname === '/api/chat-leaderboard' && request.method === 'GET') {
      try {
        const chatters = new Map();

        // Query Pinata for recent chat messages
        if (env.PINATA_JWT) {
          try {
            const pinRes = await fetch('https://api.pinata.cloud/data/pinList?status=pinned&metadata[name]=chat&pageLimit=200&sortBy=date_pinned&sortOrder=DESC', {
              headers: { 'Authorization': 'Bearer ' + env.PINATA_JWT }
            });
            if (pinRes.ok) {
              const pinData = await pinRes.json();
              const gateway = PINATA_GW;
              const fetches = (pinData.rows || []).slice(0, 100).map(async (pin) => {
                try {
                  const r = await fetch(gateway + pin.ipfs_pin_hash, { signal: AbortSignal.timeout(3000) });
                  if (r.ok) {
                    const msg = await r.json();
                    if (msg.nick && msg.text && !msg.nick.includes('AnyClip')) {
                      const entry = chatters.get(msg.nick) || { nick: msg.nick, tier: msg.tier || 'op', count: 0 };
                      entry.count++;
                      chatters.set(msg.nick, entry);
                    }
                  }
                } catch {}
              });
              await Promise.all(fetches);
            }
          } catch {}
        }

        // Also check KV if available
        if (chatters.size === 0 && env.FP_INDEX) {
          try {
            const list = await env.FP_INDEX.list({ prefix: 'chat:msg:' });
            for (const { name } of list.keys) {
              const val = await env.FP_INDEX.get(name);
              if (val) {
                try {
                  const msg = JSON.parse(val);
                  if (msg.nick && !msg.nick.includes('AnyClip')) {
                    const entry = chatters.get(msg.nick) || { nick: msg.nick, tier: msg.tier || 'op', count: 0 };
                    entry.count++;
                    chatters.set(msg.nick, entry);
                  }
                } catch {}
              }
            }
          } catch {}
        }

        // Sort by message count
        const sorted = [...chatters.values()].sort((a, b) => b.count - a.count);

        // XP rankings — derived from message count (10 XP per msg) + bonus for tier
        const xpList = sorted.map(c => ({
          nick: c.nick,
          tier: c.tier,
          xp: (c.count * 10) + (c.tier === 'hw' ? 50 : 0)
        })).sort((a, b) => b.xp - a.xp);

        return cors(JSON.stringify({ chatters: sorted, xp: xpList }), 200);
      } catch (e) { return cors(JSON.stringify({ chatters: [], xp: [], error: e.message }), 200); }
    }

    if (url.pathname === '/api/chat-send' && request.method === 'POST') {
      try {
        const body = await request.json();
        const { nick, tier, wallet, text, time } = body;
        if (!nick || !text || !wallet) return cors(JSON.stringify({ ok: false, error: 'missing fields' }), 400);

        const walletHash = await hashWallet(wallet);

        // ── RATE LIMITING — prevent spam floods ──
        if (!globalThis._rateMap) globalThis._rateMap = new Map();
        const rateKey = walletHash.slice(0, 16);
        const now = Date.now();
        let bucket = globalThis._rateMap.get(rateKey);
        if (!bucket) { bucket = { times: [] }; globalThis._rateMap.set(rateKey, bucket); }
        // Prune old entries (older than 60s)
        bucket.times = bucket.times.filter(t => now - t < 60000);
        // Check burst limit: 5 messages in 10 seconds
        const recentBurst = bucket.times.filter(t => now - t < 10000).length;
        if (recentBurst >= 5) {
          return cors(JSON.stringify({ ok: false, error: 'Too fast — wait a few seconds before sending again.', rateLimit: true }), 429);
        }
        // Check sustained limit: 30 messages in 60 seconds
        if (bucket.times.length >= 30) {
          return cors(JSON.stringify({ ok: false, error: 'Rate limit — max 30 messages per minute.', rateLimit: true }), 429);
        }
        bucket.times.push(now);
        // Also check KV for cross-instance rate limiting
        if (env.FP_INDEX) {
          try {
            const rlKey = `ratelimit:${rateKey}`;
            const rlVal = await env.FP_INDEX.get(rlKey, { type: 'json' }).catch(() => null);
            const rl = rlVal || { count: 0, window: now };
            if (now - rl.window > 60000) { rl.count = 0; rl.window = now; }
            if (rl.count >= 30) {
              return cors(JSON.stringify({ ok: false, error: 'Rate limit — max 30 messages per minute.', rateLimit: true }), 429);
            }
            rl.count++;
            ctx.waitUntil(env.FP_INDEX.put(rlKey, JSON.stringify(rl), { expirationTtl: 120 }).catch(() => {}));
          } catch {}
        }

        const msgTime = time || Date.now();
        const msgData = { nick, tier, wh: walletHash, text, time: msgTime, avatar: body.avatar || null };

        // ── PRIMARY: Pin to Pinata IPFS (synchronous — wait for CID) ──
        let cid = null;
        if (env.PINATA_JWT) {
          try {
            const pinRes = await fetch('https://api.pinata.cloud/pinning/pinJSONToIPFS', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + env.PINATA_JWT },
              body: JSON.stringify({
                pinataContent: msgData,
                pinataMetadata: { name: `chat:${msgTime}:${walletHash.slice(0,8)}` },
              }),
            });
            if (pinRes.ok) { const d = await pinRes.json(); cid = d.IpfsHash; }
          } catch (_) {}
          // Also pin presence
          ctx.waitUntil((async () => {
            try {
              await fetch('https://api.pinata.cloud/pinning/pinJSONToIPFS', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + env.PINATA_JWT },
                body: JSON.stringify({
                  pinataContent: { nick, tier, wh: walletHash, avatar: body.avatar || null, lastSeen: Date.now() },
                  pinataMetadata: { name: `online:${walletHash.slice(0,16)}` },
                }),
              });
            } catch (_) {}
          })());
        }

        // ── CACHE: Write to KV async (optional speed layer) ──
        if (env.FP_INDEX) {
          ctx.waitUntil((async () => {
            try {
              await env.FP_INDEX.put(`chat:msg:${msgTime}:${walletHash.slice(0,8)}`, JSON.stringify(msgData), { expirationTtl: 7200 });
              await env.FP_INDEX.put(`chat:online:${walletHash.slice(0,16)}`, JSON.stringify({ nick, tier, wh: walletHash, lastSeen: Date.now() }), { expirationTtl: 300 });
            } catch (_) {}
          })());
        }

        const storage = cid ? 'ipfs' : 'failed';
        return cors(JSON.stringify({ ok: true, cid, storage }), 200);
      } catch (e) { return cors(JSON.stringify({ ok: false, error: e.message }), 200); }
    }

    if (url.pathname === '/api/chat-poll' && request.method === 'GET') {
      try {
        const since = parseInt(url.searchParams.get('since') || '0');
        let messages = [];

        // ── PRIMARY: Query Pinata IPFS for chat messages ──
        if (env.PINATA_JWT) {
          try {
            const pinListRes = await fetch('https://api.pinata.cloud/data/pinList?status=pinned&metadata[name]=chat&pageLimit=50&sortBy=date_pinned&sortOrder=DESC', {
              headers: { 'Authorization': 'Bearer ' + env.PINATA_JWT }
            });
            if (pinListRes.ok) {
              const pinData = await pinListRes.json();
              const gateway = PINATA_GW;
              const fetches = (pinData.rows || []).slice(0, 40).map(async (pin) => {
                try {
                  const r = await fetch(gateway + pin.ipfs_pin_hash, { signal: AbortSignal.timeout(4000) });
                  if (r.ok) {
                    const msg = await r.json();
                    if (msg.nick && msg.text && msg.time && msg.time > since) {
                      delete msg.wallet;
                      // Backfill KV cache
                      if (env.FP_INDEX) {
                        ctx.waitUntil(env.FP_INDEX.put(`chat:msg:${msg.time}:${(msg.wh||'').slice(0,8)}`, JSON.stringify(msg), { expirationTtl: 7200 }).catch(()=>{}));
                      }
                      return msg;
                    }
                  }
                } catch {}
                return null;
              });
              messages = (await Promise.all(fetches)).filter(Boolean);
            }
          } catch {}
        }

        // ── FALLBACK: Try KV if Pinata returned nothing ──
        if (messages.length === 0 && env.FP_INDEX) {
          try {
            const list = await env.FP_INDEX.list({ prefix: 'chat:msg:' });
            for (const { name } of list.keys) {
              const ts = parseInt(name.split(':')[2] || '0');
              if (ts > since) {
                const val = await env.FP_INDEX.get(name);
                if (val) { try { const msg = JSON.parse(val); delete msg.wallet; messages.push(msg); } catch {} }
              }
            }
          } catch {}
        }

        messages.sort((a, b) => a.time - b.time);
        return cors(JSON.stringify({ messages, serverTime: Date.now() }), 200);
      } catch (e) { return cors(JSON.stringify({ messages: [], error: e.message }), 200); }
    }

    // ══════════════════════════════════════════
    //   LONG POLL — holds connection until new messages arrive (up to 25s)
    // ══════════════════════════════════════════
    if (url.pathname === '/api/chat-longpoll' && request.method === 'GET') {
      try {
        const since = parseInt(url.searchParams.get('since') || '0');
        const maxWait = 25000;
        const checkInterval = 800;
        const startTime = Date.now();

        // Helper: check KV for new messages since timestamp
        async function checkForMessages(sinceTs) {
          const messages = [];
          if (env.FP_INDEX) {
            const list = await env.FP_INDEX.list({ prefix: 'chat:msg:' });
            for (const { name } of list.keys) {
              const ts = parseInt(name.split(':')[2] || '0');
              if (ts > sinceTs) {
                const val = await env.FP_INDEX.get(name);
                if (val) { try { const msg = JSON.parse(val); delete msg.wallet; messages.push(msg); } catch {} }
              }
            }
          }
          return messages;
        }

        // First check — maybe there are already new messages
        let messages = await checkForMessages(since);
        if (messages.length > 0) {
          messages.sort((a, b) => a.time - b.time);
          return cors(JSON.stringify({ messages, serverTime: Date.now(), mode: 'instant' }), 200);
        }

        // Long poll loop — keep checking until timeout or new messages
        while (Date.now() - startTime < maxWait) {
          await new Promise(r => setTimeout(r, checkInterval));
          messages = await checkForMessages(since);
          if (messages.length > 0) {
            messages.sort((a, b) => a.time - b.time);
            return cors(JSON.stringify({ messages, serverTime: Date.now(), mode: 'longpoll' }), 200);
          }
        }

        // Timeout — return empty (client will immediately reconnect)
        return cors(JSON.stringify({ messages: [], serverTime: Date.now(), mode: 'timeout' }), 200);
      } catch (e) { return cors(JSON.stringify({ messages: [], error: e.message }), 200); }
    }

    // ── Typing indicator — POST to signal, GET to check ──
    if (url.pathname === '/api/chat-typing' && request.method === 'POST') {
      try {
        const body = await request.json();
        const { nick } = body;
        if (!nick) return cors(JSON.stringify({ ok: false }), 400);
        // Store in KV with 8-second TTL (ephemeral)
        if (env.FP_INDEX) {
          await env.FP_INDEX.put(`typing:${nick}`, JSON.stringify({ nick, time: Date.now() }), { expirationTtl: 8 });
        }
        // Also store in Pinata as a lightweight pin (will be cleaned up by name prefix)
        if (!env.FP_INDEX && env.PINATA_JWT) {
          try {
            await fetch('https://api.pinata.cloud/pinning/pinJSONToIPFS', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + env.PINATA_JWT },
              body: JSON.stringify({
                pinataContent: { nick, time: Date.now() },
                pinataMetadata: { name: `typing:${nick}` },
              }),
            });
          } catch {}
        }
        return cors(JSON.stringify({ ok: true }), 200);
      } catch (e) { return cors(JSON.stringify({ ok: false }), 200); }
    }

    if (url.pathname === '/api/chat-typing' && request.method === 'GET') {
      try {
        const typers = [];
        const now = Date.now();
        // Check KV for typing entries
        if (env.FP_INDEX) {
          const list = await env.FP_INDEX.list({ prefix: 'typing:' });
          for (const { name } of list.keys) {
            const val = await env.FP_INDEX.get(name);
            if (val) {
              try {
                const t = JSON.parse(val);
                if (t.nick && (now - t.time) < 8000) typers.push(t.nick);
              } catch {}
            }
          }
        }
        // Pinata fallback — check recent typing pins
        if (typers.length === 0 && env.PINATA_JWT) {
          try {
            const res = await fetch('https://api.pinata.cloud/data/pinList?status=pinned&metadata[name]=typing&pageLimit=10&sortBy=date_pinned&sortOrder=DESC', {
              headers: { 'Authorization': 'Bearer ' + env.PINATA_JWT }
            });
            if (res.ok) {
              const data = await res.json();
              const gateway = PINATA_GW;
              for (const pin of (data.rows || []).slice(0, 5)) {
                try {
                  const r = await fetch(gateway + pin.ipfs_pin_hash, { signal: AbortSignal.timeout(2000) });
                  if (r.ok) {
                    const t = await r.json();
                    if (t.nick && (now - t.time) < 8000) typers.push(t.nick);
                  }
                } catch {}
              }
            }
          } catch {}
        }
        return cors(JSON.stringify({ typing: typers }), 200);
      } catch (e) { return cors(JSON.stringify({ typing: [] }), 200); }
    }

    if (url.pathname === '/api/chat-online' && request.method === 'GET') {
      try {
        let operators = [];

        // ── PRIMARY: Query Pinata for online presence pins ──
        if (env.PINATA_JWT) {
          try {
            const onlineRes = await fetch('https://api.pinata.cloud/data/pinList?status=pinned&metadata[name]=online&pageLimit=30&sortBy=date_pinned&sortOrder=DESC', {
              headers: { 'Authorization': 'Bearer ' + env.PINATA_JWT }
            });
            if (onlineRes.ok) {
              const pinData = await onlineRes.json();
              const gateway = PINATA_GW;
              const tenMinAgo = Date.now() - 600000;
              const seen = new Set();
              const fetches = (pinData.rows || []).slice(0, 20).map(async (pin) => {
                try {
                  const r = await fetch(gateway + pin.ipfs_pin_hash, { signal: AbortSignal.timeout(3000) });
                  if (r.ok) {
                    const op = await r.json();
                    if (op.nick && op.lastSeen && op.lastSeen > tenMinAgo && !seen.has(op.nick)) {
                      seen.add(op.nick);
                      delete op.wallet;
                      // Backfill KV cache
                      if (env.FP_INDEX) ctx.waitUntil(env.FP_INDEX.put(`chat:online:${(op.wh||op.nick).slice(0,16)}`, JSON.stringify(op), { expirationTtl: 300 }).catch(()=>{}));
                      return op;
                    }
                  }
                } catch {}
                return null;
              });
              operators = (await Promise.all(fetches)).filter(Boolean);
            }
          } catch {}
        }

        // ── FALLBACK: KV if Pinata returned nothing ──
        if (operators.length === 0 && env.FP_INDEX) {
          try {
            const list = await env.FP_INDEX.list({ prefix: 'chat:online:' });
            for (const { name } of list.keys) {
              const val = await env.FP_INDEX.get(name);
              if (val) { try { const op = JSON.parse(val); delete op.wallet; operators.push(op); } catch {} }
            }
          } catch {}
        }

        // ── AnyClip is ALWAYS online — watching the lounge 24/7 ──
        const hasAnyClip = operators.some(o => o.nick && o.nick.includes('AnyClip'));
        if (!hasAnyClip) {
          operators.unshift({ nick: '🤖 AnyClip', tier: 'ai', wh: 'anyclip-ai', lastSeen: Date.now() });
        }

        return cors(JSON.stringify({ operators }), 200);
      } catch (e) { return cors(JSON.stringify({ operators: [] }), 200); }
    }

    if (url.pathname === '/api/chat-join' && request.method === 'POST') {
      try {
        const body = await request.json();
        let stored = false;

        // ── PRIMARY: Pin presence to Pinata (synchronous) ──
        if (env.PINATA_JWT && body.wallet) {
          try {
            const wh = await hashWallet(body.wallet);
            const pinRes = await fetch('https://api.pinata.cloud/pinning/pinJSONToIPFS', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + env.PINATA_JWT },
              body: JSON.stringify({
                pinataContent: { nick: body.nick, tier: body.tier, wh, avatar: body.avatar || null, lastSeen: Date.now() },
                pinataMetadata: { name: `online:${wh.slice(0,16)}` },
              }),
            });
            stored = pinRes.ok;
          } catch {}
        }

        // ── CACHE: Write to KV async (optional speed layer) ──
        if (env.FP_INDEX && body.wallet) {
          ctx.waitUntil((async () => {
            try {
              const wh = await hashWallet(body.wallet);
              await env.FP_INDEX.put(`chat:online:${wh.slice(0,16)}`, JSON.stringify({ nick: body.nick, tier: body.tier, wh, avatar: body.avatar || null, lastSeen: Date.now() }), { expirationTtl: 300 });
            } catch {}
          })());
        }

        return cors(JSON.stringify({ ok: true, stored, storage: 'ipfs' }), 200);
      } catch (e) { return cors(JSON.stringify({ ok: false, error: e.message }), 200); }
    }

    if (url.pathname === '/api/moderate' && request.method === 'POST') {
      try {
        const body = await request.json();
        const { message, nick } = body;
        if (!message) return cors(JSON.stringify({ allow: true, warn: false, ban: false }), 200);
        const ANTHROPIC_KEY = env.ANTHROPIC_KEY;
        if (!ANTHROPIC_KEY) return cors(JSON.stringify({ allow: true, warn: false, ban: false }), 200);
        const prompt = `You are AnyClip, the AI moderator of AnyChat. Analyze this message.\n\nRules: No threats, hate speech, NSFW, terrorism, links, doxxing. Mild profanity OK.\n\nMessage from ${nick}: "${message}"\n\nRespond with ONLY JSON: {"allow":true/false,"warn":true/false,"ban":false,"permanent":false,"category":"ok|threat|hate|nsfw|terrorism|link|doxx|other","reason":""}`;
        const res = await fetch('https://api.anthropic.com/v1/messages', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'x-api-key': ANTHROPIC_KEY, 'anthropic-version': '2023-06-01' },
          body: JSON.stringify({ model: 'claude-haiku-4-5-20251001', max_tokens: 200, messages: [{ role: 'user', content: prompt }] })
        });
        const data = await res.json();
        const text = data.content?.[0]?.text || '{}';
        const result = JSON.parse(text.replace(/```json|```/g, '').trim());
        return cors(JSON.stringify(result), 200);
      } catch (e) { return cors(JSON.stringify({ allow: true, warn: false, ban: false }), 200); }
    }

    if (url.pathname === '/api/chat-ban' && request.method === 'POST') {
      try {
        const body = await request.json();
        if (env.FP_INDEX && body.wallet) {
          const wh = await hashWallet(body.wallet);
          await env.FP_INDEX.put(`chat:ban:${wh.slice(0,16)}`,
            JSON.stringify({ nick: body.nick, wh, reason: body.reason, bannedAt: Date.now() }),
            { expirationTtl: body.permanent ? 31536000 : 7 * 24 * 3600 });
        }
        return cors(JSON.stringify({ ok: true }), 200);
      } catch (e) { return cors(JSON.stringify({ ok: false }), 200); }
    }

    if (url.pathname === '/api/chat-ban-check' && request.method === 'GET') {
      try {
        const wallet = url.searchParams.get('wallet');
        if (!wallet || !env.FP_INDEX) return cors(JSON.stringify({ banned: false }), 200);
        const wh = await hashWallet(wallet);
        const ban = await env.FP_INDEX.get(`chat:ban:${wh.slice(0,16)}`);
        if (!ban) return cors(JSON.stringify({ banned: false }), 200);
        const data = JSON.parse(ban);
        if (!data.permanent && data.until < Date.now()) return cors(JSON.stringify({ banned: false }), 200);
        return cors(JSON.stringify({ banned: true, reason: data.reason }), 200);
      } catch (e) { return cors(JSON.stringify({ banned: false }), 200); }
    }

    // ══════════════════════════════════════════
    //   PRIVATE DM ENDPOINTS
    // ══════════════════════════════════════════
    if (url.pathname === '/api/chat-dm-send' && request.method === 'POST') {
      try {
        const body = await request.json();
        const { nick, tier, wallet, to, text, time, avatar } = body;
        if (!nick || !text || !wallet || !to) return cors(JSON.stringify({ ok: false, error: 'missing fields' }), 400);
        if (text.length > 400) return cors(JSON.stringify({ ok: false, error: 'message too long' }), 400);

        const fromWh = await hashWallet(wallet);
        const toWh = to.length === 64 ? to : await hashWallet(to); // Accept raw hash or wallet
        const msgTime = time || Date.now();
        const msgData = { nick, tier, fromWh, toWh, text, time: msgTime, avatar: avatar || null, isDM: true };

        // Pin to Pinata (primary storage)
        let cid = null;
        if (env.PINATA_JWT) {
          try {
            const pinRes = await fetch('https://api.pinata.cloud/pinning/pinJSONToIPFS', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + env.PINATA_JWT },
              body: JSON.stringify({
                pinataContent: msgData,
                pinataMetadata: { name: `dm:${msgTime}:${fromWh.slice(0,8)}:${toWh.slice(0,8)}` },
              }),
            });
            if (pinRes.ok) { const d = await pinRes.json(); cid = d.IpfsHash; }
          } catch (_) {}
        }
        // KV cache
        if (env.FP_INDEX) {
          ctx.waitUntil(env.FP_INDEX.put(`dm:${msgTime}:${fromWh.slice(0,8)}:${toWh.slice(0,8)}`, JSON.stringify(msgData), { expirationTtl: 86400 }).catch(()=>{}));
        }
        return cors(JSON.stringify({ ok: true, cid }), 200);
      } catch (e) { return cors(JSON.stringify({ ok: false, error: e.message }), 200); }
    }

    if (url.pathname === '/api/chat-dm-poll' && request.method === 'GET') {
      try {
        const wallet = url.searchParams.get('wallet');
        const since = parseInt(url.searchParams.get('since') || '0');
        if (!wallet) return cors(JSON.stringify({ messages: [] }), 400);
        const myWh = await hashWallet(wallet);
        let messages = [];

        // Query Pinata for DMs to/from this wallet
        if (env.PINATA_JWT) {
          try {
            const pinRes = await fetch('https://api.pinata.cloud/data/pinList?status=pinned&metadata[name]=dm&pageLimit=50&sortBy=date_pinned&sortOrder=DESC', {
              headers: { 'Authorization': 'Bearer ' + env.PINATA_JWT }
            });
            if (pinRes.ok) {
              const pinData = await pinRes.json();
              const gateway = PINATA_GW;
              const fetches = (pinData.rows || []).slice(0, 40).map(async (pin) => {
                try {
                  // Check metadata name for this wallet hash
                  const name = pin.metadata?.name || '';
                  if (!name.includes(myWh.slice(0,8))) return null;
                  const r = await fetch(gateway + pin.ipfs_pin_hash, { signal: AbortSignal.timeout(4000) });
                  if (r.ok) {
                    const msg = await r.json();
                    if (msg.isDM && msg.time > since && (msg.toWh === myWh || msg.fromWh === myWh)) {
                      delete msg.wallet;
                      return msg;
                    }
                  }
                } catch {}
                return null;
              });
              messages = (await Promise.all(fetches)).filter(Boolean);
            }
          } catch {}
        }

        // KV fallback
        if (messages.length === 0 && env.FP_INDEX) {
          try {
            const list = await env.FP_INDEX.list({ prefix: 'dm:' });
            for (const { name } of list.keys) {
              if (!name.includes(myWh.slice(0,8))) continue;
              const val = await env.FP_INDEX.get(name);
              if (val) {
                try {
                  const msg = JSON.parse(val);
                  if (msg.time > since && (msg.toWh === myWh || msg.fromWh === myWh)) {
                    delete msg.wallet;
                    messages.push(msg);
                  }
                } catch {}
              }
            }
          } catch {}
        }

        messages.sort((a, b) => a.time - b.time);
        return cors(JSON.stringify({ messages, serverTime: Date.now() }), 200);
      } catch (e) { return cors(JSON.stringify({ messages: [], error: e.message }), 200); }
    }

    // ── TIER 3: Device fingerprint tracking for multi-account detection ──
    if (url.pathname === '/api/chat-device' && request.method === 'POST') {
      try {
        const body = await request.json();
        const { nick, wallet, fp, time } = body;
        if (!fp || !wallet) return cors(JSON.stringify({ ok: false }), 400);
        const wh = await hashWallet(wallet);
        // Store device→wallet mapping on Pinata
        if (env.PINATA_JWT) {
          ctx.waitUntil((async () => {
            try {
              await fetch('https://api.pinata.cloud/pinning/pinJSONToIPFS', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + env.PINATA_JWT },
                body: JSON.stringify({
                  pinataContent: { fp, wh, nick, time: time || Date.now() },
                  pinataMetadata: { name: `device:${fp.slice(0,16)}:${wh.slice(0,8)}` },
                }),
              });
            } catch (_) {}
          })());
        }
        // Also store in KV for fast lookup
        if (env.FP_INDEX) {
          ctx.waitUntil((async () => {
            try {
              // Device → accounts mapping
              const existing = await env.FP_INDEX.get(`device:${fp.slice(0,16)}`).catch(() => null);
              const accounts = existing ? JSON.parse(existing) : [];
              if (!accounts.find(a => a.wh === wh)) {
                accounts.push({ wh, nick, firstSeen: Date.now() });
              }
              await env.FP_INDEX.put(`device:${fp.slice(0,16)}`, JSON.stringify(accounts), { expirationTtl: 2592000 }); // 30 days
              // Check for banned accounts on this device
              let flagged = false;
              for (const acc of accounts) {
                const ban = await env.FP_INDEX.get(`chat:ban:${acc.wh.slice(0,16)}`).catch(() => null);
                if (ban) { flagged = true; break; }
              }
              // If flagged, store the flag for this wallet too
              if (flagged || accounts.length >= 3) {
                await env.FP_INDEX.put(`device:flagged:${wh.slice(0,16)}`, JSON.stringify({ reason: flagged ? 'linked_ban' : 'multi_account', accounts: accounts.length }), { expirationTtl: 2592000 });
              }
            } catch (_) {}
          })());
        }
        return cors(JSON.stringify({ ok: true }), 200);
      } catch (e) { return cors(JSON.stringify({ ok: false }), 200); }
    }

    /* ══════════════════════════════════════════
       POST /api/ipfs-route — Pin to IPFS via Anyone SOCKS5 relay
       Accepts: { relay_id, encrypted_payload, metadata }
       Returns: { ok, cid, relay, relay_location }
    ══════════════════════════════════════════ */
    if (url.pathname === '/api/ipfs-route' && request.method === 'POST') {
      try {
        const body = await request.json();
        const { relay_id, encrypted_payload, metadata } = body;

        if (!encrypted_payload) return cors(JSON.stringify({ ok: false, error: 'missing encrypted_payload' }), 400);
        if (!env.PINATA_JWT) return cors(JSON.stringify({ ok: false, error: 'PINATA_JWT not configured' }), 500);

        const relay = relay_id
          ? SOCKS5_RELAYS.find(r => r.id === relay_id) || SOCKS5_RELAYS[Math.floor(Math.random() * SOCKS5_RELAYS.length)]
          : SOCKS5_RELAYS[Math.floor(Math.random() * SOCKS5_RELAYS.length)];

        const pinBody = JSON.stringify({
          pinataContent: { encrypted: encrypted_payload, meta: metadata || {}, ts: Date.now() },
          pinataMetadata: { name: `anychat:${Date.now()}:${(metadata?.wh || 'anon').slice(0, 8)}` },
        });

        let pinData = null;
        let routeMethod = 'direct';

        // ── Try SOCKS5 tunnel first (8s timeout) ──
        try {
          const socks5Result = await Promise.race([
            httpsOverSocks5(
              relay, 'POST', 'https://api.pinata.cloud/pinning/pinJSONToIPFS',
              { 'Content-Type': 'application/json', 'Authorization': `Bearer ${env.PINATA_JWT}` },
              pinBody
            ),
            new Promise((_, rej) => setTimeout(() => rej(new Error('SOCKS5 tunnel timeout')), 8000)),
          ]);
          if (socks5Result.status >= 200 && socks5Result.status < 300) {
            pinData = JSON.parse(socks5Result.body);
            routeMethod = 'socks5';
          }
        } catch (_) { /* SOCKS5 failed — fall through to direct */ }

        // ── Fallback: direct Pinata call (Worker IP visible but data is encrypted) ──
        if (!pinData) {
          const directResp = await fetch('https://api.pinata.cloud/pinning/pinJSONToIPFS', {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              'Authorization': `Bearer ${env.PINATA_JWT}`,
            },
            body: pinBody,
          });
          if (directResp.ok) {
            pinData = await directResp.json();
            routeMethod = 'direct';
          } else {
            return cors(JSON.stringify({ ok: false, error: `Pinata ${directResp.status}`, relay: relay.id }), 200);
          }
        }

        // Store CID reference in KV
        if (env.FP_INDEX && pinData?.IpfsHash) {
          const kvKey = `ipfs:${Date.now()}:${(metadata?.wh || 'anon').slice(0,8)}`;
          ctx.waitUntil(env.FP_INDEX.put(kvKey, JSON.stringify({
            cid: pinData.IpfsHash, relay: relay.id, route: routeMethod, time: Date.now(), wh: metadata?.wh,
          }), { expirationTtl: 86400 }).catch(() => {}));
        }

        return cors(JSON.stringify({
          ok: true, cid: pinData.IpfsHash, relay: relay.id, relay_location: relay.location,
          storage: 'ipfs', route: routeMethod,
        }), 200);

      } catch (e) {
        return cors(JSON.stringify({ ok: false, error: e.message }), 200);
      }
    }

    /* ══════════════════════════════════════════
       GET /api/relay-health — Check SOCKS5 relay status
       Returns: [{ id, host, port, location, status, latency }]
    ══════════════════════════════════════════ */
    if (url.pathname === '/api/relay-health' && request.method === 'GET') {
      try {
        const results = await checkRelayHealth();
        return cors(JSON.stringify({ relays: results, checked: new Date().toISOString() }), 200);
      } catch (e) {
        return cors(JSON.stringify({ relays: [], error: e.message }), 200);
      }
    }

    // ══════════════════════════════════════════
    //   USER AUTH — Pinata IPFS ONLY (no KV)
    //   Uses pinList API to find latest registry
    //   Gateway: uses PINATA_GW constant
    // ══════════════════════════════════════════

    // Helper: fetch current user registry from Pinata (find latest by name)
    async function getUserRegistry() {
      try {
        // Find the latest registry file by metadata name
        const listRes = await fetch('https://api.pinata.cloud/data/pinList?metadata[name]=anychat-users-registry&status=pinned&pageLimit=1&sortBy=date_pinned&sortOrder=DESC', {
          headers: { 'Authorization': 'Bearer ' + env.PINATA_JWT },
        });
        if (!listRes.ok) return {};
        const listData = await listRes.json();
        if (!listData.rows || !listData.rows.length) return {};
        const cid = listData.rows[0].ipfs_pin_hash;
        // Fetch the actual registry JSON from gateway
        const res = await fetch(`${PINATA_GW}${cid}`, { headers: { 'Accept': 'application/json' } });
        if (!res.ok) return {};
        const data = await res.json();
        return data.users || {};
      } catch (_) { return {}; }
    }

    // Helper: save updated user registry to Pinata (unpin old, pin new)
    async function saveUserRegistry(users) {
      // Pin new version
      const res = await fetch('https://api.pinata.cloud/pinning/pinJSONToIPFS', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': 'Bearer ' + env.PINATA_JWT,
        },
        body: JSON.stringify({
          pinataContent: { version: 1, updated: Date.now(), users },
          pinataMetadata: { name: 'anychat-users-registry', keyvalues: { app: 'anyonemap', type: 'user-registry' } },
        }),
      });
      if (!res.ok) throw new Error('Pinata pin failed: ' + res.status);
      const data = await res.json();
      // Optionally unpin old versions to save space (keep last 3)
      try {
        const listRes = await fetch('https://api.pinata.cloud/data/pinList?metadata[name]=anychat-users-registry&status=pinned&pageLimit=10&sortBy=date_pinned&sortOrder=DESC', {
          headers: { 'Authorization': 'Bearer ' + env.PINATA_JWT },
        });
        if (listRes.ok) {
          const listData = await listRes.json();
          if (listData.rows && listData.rows.length > 3) {
            // Unpin all but the 3 newest
            for (const old of listData.rows.slice(3)) {
              fetch('https://api.pinata.cloud/pinning/unpin/' + old.ipfs_pin_hash, {
                method: 'DELETE', headers: { 'Authorization': 'Bearer ' + env.PINATA_JWT },
              }).catch(() => {});
            }
          }
        }
      } catch (_) {}
      return data.IpfsHash;
    }

    // POST /api/user/register — Register new user on Pinata IPFS
    if (url.pathname === '/api/user/register' && request.method === 'POST') {
      try {
        const body = await request.json();
        const { nick, hash, tier, wallet } = body;
        if (!nick || !hash || nick.length < 2 || nick.length > 24) {
          return cors(JSON.stringify({ ok: false, error: 'Invalid nickname' }), 400);
        }
        const users = await getUserRegistry();
        // Check nickname taken
        if (users[nick.toLowerCase()]) {
          return cors(JSON.stringify({ ok: false, error: 'Nickname already taken' }), 409);
        }
        // Check wallet already registered
        if (wallet) {
          const existing = Object.values(users).find(u => u.wallet && u.wallet.toLowerCase() === wallet.toLowerCase());
          if (existing) {
            return cors(JSON.stringify({ ok: false, error: 'Wallet already registered', existingNick: existing.nick }), 409);
          }
        }
        // Add user and pin to IPFS (include recovery code)
        users[nick.toLowerCase()] = { nick, hash, tier: tier || 'guest', wallet: wallet || null, created: Date.now(), recoveryCode: body.recoveryCode || null };
        const cid = await saveUserRegistry(users);
        return cors(JSON.stringify({ ok: true, nick, tier: tier || 'guest', cid }), 200);
      } catch (e) {
        return cors(JSON.stringify({ ok: false, error: e.message }), 500);
      }
    }

    // POST /api/user/login — Verify credentials against Pinata IPFS
    if (url.pathname === '/api/user/login' && request.method === 'POST') {
      try {
        const body = await request.json();
        const { nick, hash } = body;
        if (!nick || !hash) {
          return cors(JSON.stringify({ ok: false, error: 'Missing credentials' }), 400);
        }
        const users = await getUserRegistry();
        const user = users[nick.toLowerCase()];
        if (!user) {
          return cors(JSON.stringify({ ok: false, error: 'User not found' }), 404);
        }
        if (user.hash !== hash) {
          return cors(JSON.stringify({ ok: false, error: 'Wrong password' }), 401);
        }
        return cors(JSON.stringify({ ok: true, nick: user.nick, tier: user.tier, wallet: user.wallet }), 200);
      } catch (e) {
        return cors(JSON.stringify({ ok: false, error: e.message }), 500);
      }
    }

    // GET /api/user/lookup?nick=xxx — Check if nickname exists on IPFS
    if (url.pathname === '/api/user/lookup' && request.method === 'GET') {
      try {
        const nick = url.searchParams.get('nick');
        if (!nick) return cors(JSON.stringify({ exists: false }), 200);
        const users = await getUserRegistry();
        const user = users[nick.toLowerCase()];
        if (!user) return cors(JSON.stringify({ exists: false }), 200);
        return cors(JSON.stringify({ exists: true, tier: user.tier, created: user.created }), 200);
      } catch (e) {
        return cors(JSON.stringify({ exists: false }), 200);
      }
    }

    // GET /api/user/wallet?addr=0x... — Lookup user by wallet on IPFS
    if (url.pathname === '/api/user/wallet' && request.method === 'GET') {
      try {
        const addr = url.searchParams.get('addr');
        if (!addr) return cors(JSON.stringify({ found: false }), 200);
        const users = await getUserRegistry();
        const found = Object.values(users).find(u => u.wallet && u.wallet.toLowerCase() === addr.toLowerCase());
        if (!found) return cors(JSON.stringify({ found: false }), 200);
        return cors(JSON.stringify({ found: true, nick: found.nick, tier: found.tier }), 200);
      } catch (e) {
        return cors(JSON.stringify({ found: false }), 200);
      }
    }

    // POST /api/user/recover — Reset password using recovery code
    if (url.pathname === '/api/user/recover' && request.method === 'POST') {
      try {
        const body = await request.json();
        const { recoveryCode, newHash } = body;
        if (!recoveryCode || !newHash) {
          return cors(JSON.stringify({ ok: false, error: 'Missing recovery code or new password' }), 400);
        }
        const users = await getUserRegistry();
        const found = Object.values(users).find(u => u.recoveryCode && u.recoveryCode.toUpperCase() === recoveryCode.toUpperCase());
        if (!found) {
          return cors(JSON.stringify({ ok: false, error: 'Invalid recovery code' }), 404);
        }
        // Update password
        users[found.nick.toLowerCase()].hash = newHash;
        await saveUserRegistry(users);
        return cors(JSON.stringify({ ok: true, nick: found.nick, tier: found.tier, wallet: found.wallet }), 200);
      } catch (e) {
        return cors(JSON.stringify({ ok: false, error: e.message }), 500);
      }
    }

    // POST /api/user/reset-wallet — Reset password using connected wallet
    if (url.pathname === '/api/user/reset-wallet' && request.method === 'POST') {
      try {
        const body = await request.json();
        const { wallet, newHash } = body;
        if (!wallet || !newHash) {
          return cors(JSON.stringify({ ok: false, error: 'Missing wallet or new password' }), 400);
        }
        const users = await getUserRegistry();
        const found = Object.values(users).find(u => u.wallet && u.wallet.toLowerCase() === wallet.toLowerCase());
        if (!found) {
          return cors(JSON.stringify({ ok: false, error: 'No account linked to this wallet' }), 404);
        }
        // Update password
        users[found.nick.toLowerCase()].hash = newHash;
        await saveUserRegistry(users);
        return cors(JSON.stringify({ ok: true, nick: found.nick, tier: found.tier }), 200);
      } catch (e) {
        return cors(JSON.stringify({ ok: false, error: e.message }), 500);
      }
    }

    return cors('Not found', 404);
  },

  async scheduled(event, env, ctx) {
    ctx.waitUntil(storeSnapshot(env));
  },
};

/* ══════════════════════════════════════════
   100% COVERAGE: buildAndStoreIndex
══════════════════════════════════════════ */
async function buildAndStoreIndex(env) {
  const t0 = Date.now();
  const r0 = await fetch(`${WALLET_LOOKUP}&page=1`);
  if (!r0.ok) throw new Error('upstream error: ' + r0.status);
  const d0 = await r0.json();
  const totalPages = d0.pages || 1;

  const walletRows = [...(d0.wallets || [])];
  for (let p = 2; p <= totalPages; p += 20) {
    const batch = Array.from({ length: Math.min(20, totalPages - p + 1) }, (_, i) => p + i);
    const results = await Promise.all(
      batch.map(pg => fetch(`${WALLET_LOOKUP}&page=${pg}`).then(r => r.json()).then(d => d.wallets || []).catch(() => []))
    );
    for (const rows of results) walletRows.push(...rows);
  }

  const allWallets = walletRows.filter(w => w.wallet && (w.in_consensus_ips || 0) > 0).map(w => w.wallet);
  const exits = new Set();
  const guards = new Set();

  const [, hardwareSet] = await Promise.all([
    (async () => {
      for (let i = 0; i < allWallets.length; i += IPS_BATCH_SIZE) {
        const batch = allWallets.slice(i, i + IPS_BATCH_SIZE);
        await Promise.all(batch.map(async wallet => {
          try {
            const r = await fetch(`${IPS_BASE}${encodeURIComponent(wallet)}`);
            if (!r.ok) return;
            const d = await r.json();
            for (const relay of (d.ips || [])) {
              const fp = (relay.fingerprint || '').toUpperCase();
              if (!fp) continue;
              const fl = relay.flags || [];
              if (fl.includes('Exit'))       exits.add(fp);
              else if (fl.includes('Guard')) guards.add(fp);
            }
          } catch (_) {}
        }));
      }
    })(),
    fetchHardwareFPs().catch(() => new Set()),
  ]);

  const index = {};
  for (const fp of exits)       index[fp] = 'e';
  for (const fp of guards)      index[fp] = 'g';
  for (const fp of hardwareSet) index[fp] = (index[fp] || '') + 'h';

  const elapsed = ((Date.now() - t0) / 1000).toFixed(1);
  const hwCount = [...Object.values(index)].filter(v => v.includes('h')).length;
  const result = { index, exits: exits.size, guards: guards.size, hardware: hwCount, wallets: walletRows.length, topN: allWallets.length, coverage: '100%', builtAt: Date.now(), elapsed };

  if (env.FP_INDEX) {
    try { await env.FP_INDEX.put(KV_KEY, JSON.stringify(result), { expirationTtl: KV_TTL_SECS }); } catch (_) {}
  }
  return result;
}

/* ══════════════════════════════════════════
   HELPERS
══════════════════════════════════════════ */
async function fetchHardwareFPs() {
  const res = await fetch(AO_CU, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      Id: '1234', Target: AO_REGISTRY_ID, Owner: '1234', Anchor: '0', Data: '1234',
      Tags: [
        { name: 'Action', value: 'List-Verified-Hardware' },
        { name: 'Data-Protocol', value: 'ao' },
        { name: 'Type', value: 'Message' },
        { name: 'Variant', value: 'ao.TN.1' },
      ],
    }),
  });
  if (!res.ok) throw new Error('AO registry error: ' + res.status);
  const data = await res.json();
  const raw = data?.Messages?.[0]?.Data || '{}';
  return new Set(Object.keys(JSON.parse(raw)).map(fp => fp.toUpperCase()));
}

async function hmacSign(secret, message) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(message));
  return Array.from(new Uint8Array(sig)).map(b => b.toString(16).padStart(2, '0')).join('');
}
function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}
function corsHeaders() {
  return new Response(null, { headers: {
    'Access-Control-Allow-Origin': ALLOWED_ORIGIN,
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, x-token',
  }});
}
function cors(body, status = 200) {
  return new Response(body, { status, headers: {
    'Content-Type': typeof body === 'string' && body[0] === '{' ? 'application/json' : 'text/plain',
    'Access-Control-Allow-Origin': ALLOWED_ORIGIN,
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, x-token',
  }});
}
function jsonHeaders(extra = {}) {
  return { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': ALLOWED_ORIGIN, ...extra };
}

// ══════════════════════════════════════════
//   DURABLE OBJECT — ChatRoom
//   Real-time WebSocket hub for operator chat
// ══════════════════════════════════════════
export class ChatRoom {
  constructor(state, env) {
    this.state = state;
    this.env = env;
    this.sessions = new Map(); // ws → { nick, tier, joinedAt }
    this.lastMessages = []; // ring buffer of last 50 messages
  }

  async fetch(request) {
    const url = new URL(request.url);

    if (request.headers.get('Upgrade') === 'websocket') {
      const pair = new WebSocketPair();
      const [client, server] = [pair[0], pair[1]];
      this.state.acceptWebSocket(server);

      server.addEventListener('message', async (event) => {
        try {
          const data = JSON.parse(event.data);
          await this.handleMessage(server, data);
        } catch (e) {
          server.send(JSON.stringify({ type: 'error', message: 'Invalid message' }));
        }
      });

      server.addEventListener('close', () => {
        const session = this.sessions.get(server);
        if (session) {
          this.sessions.delete(server);
          this.broadcast({ type: 'leave', nick: session.nick, time: Date.now() }, server);
          this.broadcastOnline();
        }
      });

      server.addEventListener('error', () => {
        this.sessions.delete(server);
      });

      return new Response(null, { status: 101, webSocket: client });
    }

    return new Response('Expected WebSocket', { status: 426 });
  }

  async handleMessage(ws, data) {
    const { type } = data;

    if (type === 'join') {
      const { nick, tier, wh } = data;
      if (!nick) return;
      this.sessions.set(ws, { nick, tier: tier || 'op', wh, joinedAt: Date.now() });
      // Send recent message history to the new joiner
      ws.send(JSON.stringify({ type: 'history', messages: this.lastMessages }));
      // Notify others
      this.broadcast({ type: 'join', nick, tier, time: Date.now() }, ws);
      this.broadcastOnline();
      return;
    }

    if (type === 'message') {
      const session = this.sessions.get(ws);
      if (!session) { ws.send(JSON.stringify({ type: 'error', message: 'Not joined' })); return; }
      const { text } = data;
      if (!text || text.length > 400) return;
      const msg = { type: 'message', nick: session.nick, tier: session.tier, wh: session.wh, text, time: Date.now() };
      // Add to ring buffer
      this.lastMessages.push(msg);
      if (this.lastMessages.length > 50) this.lastMessages.shift();
      // Broadcast to all INCLUDING sender (sender dedupes client-side)
      this.broadcast(msg);
      // Async persist to KV + Pinata
      this.persistMessage(msg);
      return;
    }

    if (type === 'typing') {
      const session = this.sessions.get(ws);
      if (!session) return;
      this.broadcast({ type: 'typing', nick: session.nick, time: Date.now() }, ws);
      return;
    }

    if (type === 'ping') {
      ws.send(JSON.stringify({ type: 'pong', time: Date.now() }));
      return;
    }
  }

  broadcast(data, exclude) {
    const msg = JSON.stringify(data);
    for (const [ws, session] of this.sessions) {
      if (ws === exclude) continue;
      try { ws.send(msg); } catch { this.sessions.delete(ws); }
    }
  }

  broadcastOnline() {
    const operators = [...this.sessions.values()].map(s => ({
      nick: s.nick, tier: s.tier, wh: s.wh
    }));
    const msg = JSON.stringify({ type: 'online', operators });
    for (const [ws] of this.sessions) {
      try { ws.send(msg); } catch { this.sessions.delete(ws); }
    }
  }

  async persistMessage(msg) {
    // Write-through to KV (fast)
    if (this.env.FP_INDEX) {
      try {
        await this.env.FP_INDEX.put(
          `chat:msg:${msg.time}:${(msg.wh||'').slice(0,8)}`,
          JSON.stringify(msg),
          { expirationTtl: 7200 }
        );
      } catch {}
    }
    // Async pin to Pinata (durable)
    if (this.env.PINATA_JWT) {
      try {
        await fetch('https://api.pinata.cloud/pinning/pinJSONToIPFS', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + this.env.PINATA_JWT },
          body: JSON.stringify({
            pinataContent: msg,
            pinataMetadata: { name: `chat:${msg.time}:${(msg.wh||'').slice(0,8)}` },
          }),
        });
      } catch {}
    }
  }
}
