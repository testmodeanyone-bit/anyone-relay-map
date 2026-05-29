/* ============================================================================
 * worker-shell.js — anyonemap worker logic (without the SPA)
 * ============================================================================
 *
 * This file is the SOURCE for the anyonemap Cloudflare Worker. It contains
 * all the request handlers, routes, KV reads, and response framing — but
 * NOT the embedded HTML page. The HTML lives in index.html and gets
 * injected at build time, replacing a unique placeholder marker that the
 * build script knows about (search the build script for the exact marker).
 *
 * To deploy a change:
 *   1. Edit this file OR index.html
 *   2. Run: node scripts/build-worker.js worker-shell.js index.html anyonemap-worker.js
 *   3. Paste the built anyonemap-worker.js into the Cloudflare dashboard
 *
 * Pairs with:
 *   - index.html               (the SPA, edited as a normal HTML file)
 *   - scripts/build-worker.js  (combines this + index.html → anyonemap-worker.js)
 *   - scripts/extract-html.js  (reverse: pulls index.html out of a built worker)
 *
 * Deployed at: https://anyonemap.anyonerelaysmap.workers.dev
 * Bindings:    SNAPSHOT_KV (shared with anyclip-proxy), ANALYTICS,
 *              RL_ANALYTICS, RL_BITNODES (rate-limit counters)
 * ============================================================================
 */

/* v385: single source of truth for the worker version. Used by /sw.js to
 * derive the Service Worker cache name (anyonemap-${WORKER_VERSION}). The
 * v374 SW handler hardcoded 'anyonemap-v375' as a string literal and that
 * string was never bumped — by v384 the SW was still keyed at v375, so
 * users with the PWA installed served v375-era precached CSS/icons for
 * up to a year despite seven worker deploys touching the embedded HTML.
 * Bumping this constant per deploy triggers the SW install→activate cycle
 * on next page navigation, which deletes the old cache (the activate
 * handler filters keys !== CACHE) and re-precaches STATIC against the
 * current worker. Bump per release. */
const WORKER_VERSION = 'v513';

/* v410: shared cross-worker KV schema. Inlined at build time from kv-schema.js
 * (single source of truth). Exposes _kvSchema.validate(obj, schema, opts) and
 * _kvSchema.extract(obj, schema). The placeholder below is the contract that
 * build-worker.js fills — if you edit this file by hand and remove the
 * placeholder, the build will fail with a clear error. */
const _kvSchema = __KV_SCHEMA_PLACEHOLDER__;


/* ===== BASEMAP SERVING (self-hosted MapLibre tiles from R2 binding BASEMAP) =====
 * Inlined plain functions (no import/export) so build-worker.js bundles them.
 * Verified end-to-end against a real Protomaps PMTiles file. */
const _BM_HEADER_SIZE = 127;

async function _bmGunzip(buf) {
  const ds = new DecompressionStream('gzip');
  const stream = new Response(buf).body.pipeThrough(ds);
  return new Uint8Array(await new Response(stream).arrayBuffer());
}
function _bmU8(dv, p) { return dv.getUint8(p); }
function _bmU64(dv, p) { const lo = dv.getUint32(p, true), hi = dv.getUint32(p + 4, true); return hi * 4294967296 + lo; }
function _bmVarint(arr, pos) { let r = 0, s = 0, b; do { b = arr[pos++]; r += (b & 0x7f) * Math.pow(2, s); s += 7; } while (b & 0x80); return [r, pos]; }
function _bmZxyToTileId(z, x, y) {
  let acc = 0; for (let t = 0; t < z; t++) acc += Math.pow(4, t);
  let n = Math.pow(2, z), rx, ry, d = 0, xx = x, yy = y;
  for (let s = n / 2; s >= 1; s = Math.floor(s / 2)) {
    rx = (xx & s) > 0 ? 1 : 0; ry = (yy & s) > 0 ? 1 : 0;
    d += s * s * ((3 * rx) ^ ry);
    if (ry === 0) { if (rx === 1) { xx = s - 1 - xx; yy = s - 1 - yy; } const tmp = xx; xx = yy; yy = tmp; }
  }
  return acc + d;
}

// per-isolate cache of header + root directory
let _bmHeader = null, _bmRootDir = null;

async function _bmRead(env, offset, length) {
  const obj = await env.BASEMAP.get('planet.pmtiles', { range: { offset, length } });
  if (!obj) throw new Error('planet.pmtiles missing in R2');
  return await obj.arrayBuffer();
}
async function _bmGetHeader(env) {
  if (_bmHeader) return _bmHeader;
  const ab = await _bmRead(env, 0, _BM_HEADER_SIZE);
  const dv = new DataView(ab);
  const magic = String.fromCharCode(_bmU8(dv,0),_bmU8(dv,1),_bmU8(dv,2),_bmU8(dv,3),_bmU8(dv,4),_bmU8(dv,5),_bmU8(dv,6));
  if (magic !== 'PMTiles') throw new Error('bad pmtiles magic');
  if (_bmU8(dv, 7) !== 3) throw new Error('pmtiles spec != 3');
  _bmHeader = {
    rootDirOffset: _bmU64(dv, 8), rootDirLength: _bmU64(dv, 16),
    leafDirOffset: _bmU64(dv, 40),
    tileDataOffset: _bmU64(dv, 56),
    internalCompression: _bmU8(dv, 97), tileCompression: _bmU8(dv, 98),
    minZoom: _bmU8(dv, 100), maxZoom: _bmU8(dv, 101)
  };
  return _bmHeader;
}
async function _bmReadDir(env, offset, length) {
  const ab = await _bmRead(env, offset, length);
  let bytes = new Uint8Array(ab);
  if (_bmHeader.internalCompression === 2) bytes = await _bmGunzip(bytes);
  let pos = 0, n; [n, pos] = _bmVarint(bytes, pos);
  const e = new Array(n); let last = 0;
  for (let i = 0; i < n; i++) { let v; [v, pos] = _bmVarint(bytes, pos); last += v; e[i] = { tileId: last, runLength: 0, length: 0, offset: 0 }; }
  for (let i = 0; i < n; i++) { let v; [v, pos] = _bmVarint(bytes, pos); e[i].runLength = v; }
  for (let i = 0; i < n; i++) { let v; [v, pos] = _bmVarint(bytes, pos); e[i].length = v; }
  for (let i = 0; i < n; i++) { let v; [v, pos] = _bmVarint(bytes, pos); e[i].offset = (v === 0 && i > 0) ? (e[i-1].offset + e[i-1].length) : (v - 1); }
  return e;
}
function _bmFind(entries, tileId) {
  let lo = 0, hi = entries.length - 1, ans = null;
  while (lo <= hi) { const mid = (lo + hi) >> 1, en = entries[mid];
    if (tileId < en.tileId) hi = mid - 1;
    else if (tileId > en.tileId) { if (tileId < en.tileId + Math.max(en.runLength,1)) { ans = en; break; } lo = mid + 1; ans = en; }
    else { ans = en; break; } }
  return ans;
}
async function _bmGetTile(env, z, x, y) {
  const h = await _bmGetHeader(env);
  if (z < h.minZoom || z > h.maxZoom) return null;
  const tileId = _bmZxyToTileId(z, x, y);
  if (!_bmRootDir) _bmRootDir = await _bmReadDir(env, h.rootDirOffset, h.rootDirLength);
  let entries = _bmRootDir, e = _bmFind(entries, tileId), guard = 0;
  while (e && e.runLength === 0 && guard++ < 4) { entries = await _bmReadDir(env, h.leafDirOffset + e.offset, e.length); e = _bmFind(entries, tileId); }
  if (!e || e.runLength === 0) return null;
  if (tileId < e.tileId || tileId >= e.tileId + e.runLength) return null;
  const ab = await _bmRead(env, h.tileDataOffset + e.offset, e.length);
  let bytes = new Uint8Array(ab);
  /* PMTiles stores MVT gzip-compressed (tileCompression===2). MapLibre's worker
   * expects raw protobuf, and serving with Content-Encoding:gzip double-confused
   * the chain (parse errors). So decompress here and serve raw MVT. */
  if (h.tileCompression === 2) { try { bytes = await _bmGunzip(bytes); } catch(_e) {} }
  return bytes;
}

// main basemap router — returns a Response, or null if not a /basemap/ path
const _BM_CACHE_VER = 'v8';  // bump to invalidate all edge-cached basemap responses (v8: force a brand-new internal cache key so the stale immutable-cached maplibre-worker.js entry can't be served; route now uses max-age=300, no immutable)
async function _bmHandle(request, env, ctx) {
  const url = new URL(request.url);
  const path = url.pathname;
  if (!path.startsWith('/basemap/')) return null;
  const cache = caches.default;
  /* Versioned cache key: a synthetic same-origin URL carrying _BM_CACHE_VER, so
   * bumping the version sidesteps stale entries (e.g. the gzip-encoded tiles
   * cached before the raw-MVT fix) without needing a manual dashboard purge. */
  const cacheKey = new Request(url.origin + '/__bmcache/' + _BM_CACHE_VER + path, request);
  /* v449: the maplibre-worker.js script must NOT be served from the internal edge
   * cache — a stale (streamed, hang-prone) copy got pinned there and kept blocking
   * the map load. Always run the route fresh for it (it's tiny + buffered now), and
   * skip writing it back to the internal cache below. */
  const _isWorkerScript = (path === '/basemap/maplibre-worker.js');
  if (!_isWorkerScript) {
    const hit = await cache.match(cacheKey);
    if (hit) return hit;
  }
  let resp;
  try {
    if (path === '/basemap/style.json') {
      const obj = await env.BASEMAP.get('style.json');
      if (!obj) resp = new Response('no style', { status: 404 });
      else { let txt = await obj.text(); txt = txt.replace(/__ORIGIN__/g, url.origin);
        /* Inject the self-hosted glyphs endpoint so symbol layers (cluster counts)
         * can render text. Added at serve time so the R2 style.json doesn't need
         * re-uploading. Only added if the style doesn't already declare glyphs. */
        try { const st = JSON.parse(txt); if (!st.glyphs) { st.glyphs = url.origin + '/basemap/glyphs/{fontstack}/{range}.pbf'; txt = JSON.stringify(st); } } catch(_e) {}
        resp = new Response(txt, { headers: { 'Content-Type': 'application/json', 'Cache-Control': 'public, max-age=3600' } }); }
    } else if (path.startsWith('/basemap/tiles/')) {
      const m = path.match(/\/basemap\/tiles\/(\d+)\/(\d+)\/(\d+)\.(mvt|pbf)$/);
      if (!m) resp = new Response('bad tile', { status: 400 });
      else {
        const tile = await _bmGetTile(env, +m[1], +m[2], +m[3]);
        if (!tile) resp = new Response('', { status: 204 });
        else resp = new Response(tile, { headers: { 'Content-Type': 'application/x-protobuf', 'Cache-Control': 'public, max-age=86400, immutable' } });
      }
    } else if (path.startsWith('/basemap/hd/')) {
      /* v384: high-detail vector tiles proxied from MapTiler (OpenMapTiles v3
       * schema), for deep/street-level zoom that our self-hosted z0-7 planet file
       * doesn't carry. The MapTiler API key lives ONLY here as a worker secret
       * (env.MAPTILER_KEY) — it's injected server-side and never reaches the client,
       * the style.json, or any browser request. The browser only ever talks to our
       * own origin (/basemap/hd/...), which also keeps the strict CSP happy.
       * Edge-cached so repeat views don't burn MapTiler quota. */
      const m = path.match(/\/basemap\/hd\/(\d+)\/(\d+)\/(\d+)\.(?:pbf|mvt)$/);
      if (!m) resp = new Response('bad hd tile', { status: 400 });
      else if (!env.MAPTILER_KEY) resp = new Response('', { status: 204 });
      else {
        const up = 'https://api.maptiler.com/tiles/v3/' + m[1] + '/' + m[2] + '/' + m[3] + '.pbf?key=' + env.MAPTILER_KEY;
        const r = await fetch(up, { cf: { cacheTtl: 86400, cacheEverything: true } });
        if (r.status === 200) {
          /* v494: buffer the upstream body before building the response. The old
           * `new Response(r.body, …)` streamed MapTiler's body straight through, and
           * the `cache.put(cacheKey, resp.clone())` at the end of _bmHandle tees that
           * single upstream stream into two consumers — the exact stall-and-hang the
           * v394 fix removed for maplibre-worker.js (a stalled upstream leaves the
           * client response pending forever). HD tiles are small, so a full
           * ArrayBuffer read is cheap and cannot stall mid-transfer.
           *
           * Content-Encoding: forward it ONLY when still present on the upstream
           * response. The runtime auto-decompresses gzip/brotli and strips the
           * header before this Worker sees it (so arrayBuffer() is identity and we
           * send no header); it passes zstd through UNTOUCHED — header present,
           * bytes still compressed — so we must forward the header for the browser
           * to decode. Verified live (2026-05): MapTiler currently serves zstd, so
           * dropping the header here would serve raw zstd as identity protobuf and
           * break tile parsing. The old code's `|| ''` emitted an empty (malformed)
           * Content-Encoding when absent; omitting the header is the correct form. */
          const buf = await r.arrayBuffer();
          const hdrs = { 'Content-Type': 'application/x-protobuf', 'Cache-Control': 'public, max-age=86400, immutable' };
          const enc = r.headers.get('content-encoding');
          if (enc) hdrs['Content-Encoding'] = enc;
          resp = new Response(buf, { headers: hdrs });
        } else {
          /* non-200 (204 empty tile, 400 out of bounds, etc) — pass through as empty
           * so MapLibre moves on. (The old `r.status === 200 ? 200 : 204` ternary was
           * dead: this branch is the else of `r.status === 200`, so it is always 204.) */
          resp = new Response('', { status: 204 });
        }
      }
    } else if (path === '/basemap/hd/tiles.json') {
      /* TileJSON for the MapTiler source, rewritten so tile URLs point at OUR proxy
       * (not MapTiler directly), keeping the key server-side. */
      resp = new Response(JSON.stringify({
        tilejson: '2.2.0', scheme: 'xyz', minzoom: 0, maxzoom: 14,
        tiles: [url.origin + '/basemap/hd/{z}/{x}/{y}.pbf'],
        vector_layers: [] // MapLibre reads layers from the tiles; style references source-layers directly
      }), { headers: { 'Content-Type': 'application/json', 'Cache-Control': 'public, max-age=3600' } });
    } else if (path === '/basemap/maplibre-worker.js') {
      /* MapLibre's tile-parsing Web Worker, self-hosted same-origin so it loads
       * under the strict CSP (blob: workers are blocked; 'self' workers are not).
       * The file maplibre-gl-csp-worker.js is stored in R2 alongside the tiles.
       * v394: BUFFER the body fully (arrayBuffer) instead of streaming obj.body.
       * Streaming the R2 ReadableStream and then resp.clone()-ing it for the edge
       * cache tees one upstream stream into two consumers; if R2 stalls mid-stream
       * the client response hangs in "pending" forever — which blocked MapLibre's
       * load event entirely (no relay layers, blank map) intermittently. A fully
       * buffered ArrayBuffer response can't stall mid-transfer and caches cleanly.
       * This script is small + static, so buffering is cheap. */
      const obj = await env.BASEMAP.get('maplibre-gl-csp-worker.js');
      if (!obj) resp = new Response('no worker', { status: 404 });
      else {
        const buf = await obj.arrayBuffer();
        /* v448: short max-age (5min) instead of immutable/24h. The worker script is
         * tiny and rarely changes, but the previous immutable header let Cloudflare's
         * CDN pin a stale (hang-prone) copy for 24h, masking the buffered fix. A short
         * TTL means any future change propagates in minutes. The client also versions
         * the URL (?wv=) for instant cache-busting on known changes. */
        /* v449: no-store so neither Cloudflare's CDN nor the internal edge cache pins
         * this response. The earlier immutable/long-max-age headers let the CDN keep a
         * stale streamed (hang-prone) copy for hours, masking the buffered fix. The
         * script is tiny (~340KB) and the client versions the URL (?wv=), so serving it
         * fresh from R2 each time is cheap and guarantees correctness. */
        resp = new Response(buf, { headers: { 'Content-Type': 'text/javascript; charset=utf-8', 'Cache-Control': 'no-store', 'Content-Length': String(buf.byteLength) } });
      }
    } else if (path.startsWith('/basemap/glyphs/')) {
      /* Glyph PBFs for symbol-layer text (cluster count labels). MapLibre requests
       * /basemap/glyphs/{fontstack}/{range}.pbf. We host Open Sans Regular ranges
       * in R2 under glyphs/{fontstack}/{range}.pbf. We only ship the 0-255 range
       * (digits + Latin), which covers cluster counts; any other requested range
       * returns 204 so MapLibre falls back gracefully without erroring. */
      const gm = path.match(/\/basemap\/glyphs\/([^/]+)\/(\d+-\d+)\.pbf$/);
      if (!gm) resp = new Response('bad glyph', { status: 400 });
      else {
        const range = gm[2];
        /* v382: place labels (city/country names) need accented-Latin glyphs, so we
         * now host ranges 0-255, 256-511 and 512-767 (covers all name:en values
         * worldwide — é, ü, ș, ă, etc). Any OTHER requested range returns 204 so
         * MapLibre falls back gracefully (e.g. CJK/Cyrillic ranges we don't ship;
         * we use name:en in the label layers so those aren't needed). */
        const HOSTED_RANGES = new Set(['0-255', '256-511', '512-767']);
        if (!HOSTED_RANGES.has(range)) { resp = new Response('', { status: 204 }); }
        else {
          const stack = decodeURIComponent(gm[1]);
          /* Flat key first (simplest to upload to R2 — no folders/spaces), then
           * fall back to folder-style keys. Any requested fontstack maps to the
           * same hosted Open Sans Regular files, so the style's font name doesn't
           * have to match byte-for-byte. */
          let obj = await env.BASEMAP.get('maplibre-glyphs-' + range + '.pbf');
          if (!obj) obj = await env.BASEMAP.get('glyphs/' + stack + '/' + range + '.pbf');
          if (!obj) obj = await env.BASEMAP.get('glyphs/Open Sans Regular/' + range + '.pbf');
          if (!obj) resp = new Response('', { status: 204 });
          else resp = new Response(obj.body, { headers: { 'Content-Type': 'application/x-protobuf', 'Cache-Control': 'public, max-age=86400, immutable' } });
        }
      }
    } else resp = new Response('not found', { status: 404 });
  } catch (e) { resp = new Response('basemap error: ' + e.message, { status: 500 }); }
  if (resp.ok && request.method === 'GET' && !_isWorkerScript) ctx.waitUntil(cache.put(cacheKey, resp.clone()));
  return resp;
}
/* ===== END BASEMAP SERVING ===== */

export default { async fetch(request, env, ctx) { const _url = new URL(request.url); const _h = _url.hostname; const _path = _url.pathname; /* v300: exact match instead of .endsWith — endsWith would allow attacker-named subdomains and any *localhost suffix in client-controlled Host headers. */ const _allowedHosts = new Set(["anyonemap.anyonerelaysmap.workers.dev","map.anyone.io","localhost"]); if(!_allowedHosts.has(_h)){ return new Response("Unauthorized domain",{status:403}); }
      const _bm = await _bmHandle(request, env, ctx);
      if (_bm) return _bm; /* v373: _url and _path are now hoisted above — every route below reuses them instead of calling `new URL(request.url)` again. Saves 8 redundant URL parses per request and unifies the routing style. */ /* Analytics: record request shape. Non-blocking, safe if binding absent.
   * v380: separate static-asset traffic into its own kind. Previously the
   * sw.js / design-tokens.css / icon / manifest / robots fetches all landed
   * in 'subpage_view' alongside actual user navigations to /bitcoin and
   * /style-guide, which made the dashboard useless for distinguishing
   * "people viewed a sub-page" from "browser revalidated the SW precache."
   * Workers Analytics Engine bills per data point regardless, so we keep
   * the visibility (for debugging cache behavior) but in a separate bucket.
   *
   * v388: skip this top-of-handler write for /api/analytics specifically.
   * That route writes its own data point downstream with the actual client-
   * reported event (page_view, ws_connect, etc — see the allowlist at line
   * ~92). Without this skip, every analytics beacon produced TWO WAE
   * writes: one here indexed 'api_call', one in the route body indexed
   * with the real event. The 'api_call' index became polluted with what
   * were actually beacons reporting page_view/etc events, breaking the
   * "is the API endpoint healthy" interpretation of that index. Note:
   * other API routes (e.g. /api/bitnodes) still get the top-of-handler
   * write — they don't have a downstream WAE call. Historical 'api_call'
   * counts before v388 are inflated; cumulative queries should add a
   * date filter excluding pre-v388 data.
   *
   * v390: also exclude /healthcheck. Monitoring services typically poll
   * health endpoints every 30s or so; including those in 'api_call' would
   * dominate the index with traffic that's structurally not user-driven.
   * /healthcheck is intentionally cheap and unbilled \u2014 don't WAE it. */ try {   if (env.ANALYTICS && _path !== '/api/analytics' && _path !== '/healthcheck') {     const _ac = request.headers.get("CF-IPCountry") || "XX";     const _statics = new Set(['/sw.js','/design-tokens.css','/manifest.json','/icon-192.svg','/icon-512.svg','/robots.txt']);     const _kind = _path === '/' ? 'page_view' : (_path.startsWith('/api/') ? 'api_call' : (_statics.has(_path) ? 'static_asset' : 'subpage_view'));     env.ANALYTICS.writeDataPoint({       blobs: [_kind, _path.slice(0,80), _ac],       doubles: [1, 0],       indexes: [_kind]     });   } } catch(_){}  if (_path === '/robots.txt') {
    return new Response('User-agent: *\nAllow: /\nDisallow: /api/\n', {
      headers: { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'public, max-age=86400', 'X-Content-Type-Options': 'nosniff' }
    });
  }

  /* v390: /healthcheck \u2014 returns liveness info, deployed version, binding presence,
   * and a KV reachability probe. Intentionally unauthenticated, cheap, and
   * returns 200 even when underlying systems (KV) are degraded \u2014 the body
   * tells the caller what's working underneath, while 200 means "this
   * endpoint responded." This matches industry convention (k8s liveness vs
   * readiness; AWS ALB health checks; etc).
   *
   * Use case 1: external uptime monitoring. Hit /healthcheck, check HTTP
   * status. If you get anything but 2xx, the worker itself is down.
   *
   * Use case 2: deployment verification. Hit /healthcheck after a deploy,
   * confirm `version` matches what you just pushed. Today we had to verify
   * deploys by parsing the SW source for CACHE='...'; this is the right
   * primitive.
   *
   * Use case 3: cron diagnosis. The kv.snapshot_present field tells you
   * whether the bitnodes cron has populated KV at least once. If you've
   * been running for 24h and this is still false, the cron isn't writing.
   *
   * NOT instrumented in WAE (see top-of-handler skip above) \u2014 polled traffic
   * would dominate the 'api_call' bucket. */
  if (_path === '/healthcheck') {
    const _snapKv = env.SNAPSHOT_KV ?? env.RL_KV;
    let _kvProbe = { reachable: false, snapshot_present: false, snapshot_size_bytes: 0 };
    if (_snapKv) {
      try {
        const _snap = await _snapKv.get('bitnodes-snapshot:latest');
        _kvProbe = {
          reachable: true,
          snapshot_present: _snap !== null && _snap !== undefined,
          snapshot_size_bytes: typeof _snap === 'string' ? _snap.length : 0
        };
      } catch (_e) {
        /* KV threw \u2014 leave _kvProbe.reachable = false. The worker itself is */
        /* fine; the underlying namespace is the issue. */
      }
    }
    const _body = {
      ok: true,
      version: WORKER_VERSION,
      timestamp: Math.floor(Date.now() / 1000),
      bindings: {
        ANALYTICS: !!env.ANALYTICS,
        RL_ANALYTICS: !!env.RL_ANALYTICS,
        RL_BITNODES: !!env.RL_BITNODES,
        SNAPSHOT_KV: !!env.SNAPSHOT_KV,
        RL_KV: !!env.RL_KV
      },
      kv: _kvProbe
    };
    return new Response(JSON.stringify(_body), {
      headers: {
        'Content-Type': 'application/json',
        'Cache-Control': 'no-store',
        'Access-Control-Allow-Origin': '*',
        'X-Content-Type-Options': 'nosniff'
      }
    });
  }

  /* Privacy-safe analytics endpoint — accepts client beacons, writes to WAE */
  if (_path === '/api/analytics' && request.method === 'POST') {
    /* v382: per-IP rate limit migrated from RL_KV read-modify-write to the
     * official Cloudflare Rate Limiting binding (RL_ANALYTICS, 60/60s). The
     * v300 KV-based limiter was bypassable under concurrency — KV has no
     * compare-and-swap and is eventually consistent, so N parallel requests
     * all read count=0, all pass the gate, and the last writer wins. The
     * Rate Limiting binding is atomic at the edge with no KV round-trip.
     * Binding is optional; absent → no-op (graceful degradation, same as
     * the v300 behavior). The v300 threat model still holds: cap Analytics
     * Engine writes from a single IP to prevent quota burn and event-string
     * cardinality attacks. */
    try {
      /* v389: WAE visibility into rejected beacons. v388 stopped the top-of-handler */
      /* write from firing on /api/analytics (it was double-counting), but that */
      /* left rejection paths (rate limit, missing/bad Content-Length, oversized */
      /* body) with zero analytics. Without this, the dashboard can't answer */
      /* "how often is the endpoint rejecting traffic, and why?" \u2014 a question that */
      /* matters when something's actually going wrong. Single index for low */
      /* cardinality (v382 lesson); reason in blob1 is the dimension you filter */
      /* on in the WAE query. Empty-body 204 is NOT instrumented here \u2014 it's a */
      /* legitimate no-op, not a rejection; the whole point of v387 was to stop */
      /* logging it as noise. */
      const _aRej = (reason) => {
        if (env.ANALYTICS) {
          env.ANALYTICS.writeDataPoint({
            blobs: ['analytics_rejected', reason, request.headers.get('CF-IPCountry') || 'XX'],
            doubles: [1, 0],
            indexes: ['analytics_rejected']
          });
        }
      };
      if (env.RL_ANALYTICS) {
        const _ip = request.headers.get('CF-Connecting-IP') || 'unknown';
        const { success } = await env.RL_ANALYTICS.limit({ key: _ip }).catch(() => ({ success: true }));
        if (!success) {
          _aRej('rate_limit');
          return new Response(null, { status: 429, headers: { 'Cache-Control': 'no-store' } });
        }
      }
      /* v384: require Content-Length explicitly. The v378 guard read */
      /* Content-Length but treated missing/malformed values as "0" and */
      /* proceeded to await request.text() anyway, expecting the secondary */
      /* check on _alText.length to catch oversized payloads. That secondary */
      /* check fires AFTER request.text() has fully buffered the body — */
      /* Workers reads up to its 100MB request limit before returning. So */
      /* a client sending chunked transfer-encoding with no Content-Length */
      /* could force the worker to buffer megabytes before the 413 fires, */
      /* burning CPU and connection time. v384 closes that bypass: */
      /*   - Missing Content-Length → 411 Length Required (RFC 7230 §3.3.3) */
      /*   - Negative, non-numeric, or oversized Content-Length → 413 */
      /* Both legitimate client paths (fetch with string body, sendBeacon) */
      /* set Content-Length automatically. The endpoint is intended only */
      /* for the embedded client; external integrations are expected to */
      /* behave like normal HTTP clients and include the header. */
      /* v394: clarified what the secondary _alText.length check does. */
      /* Previous comment claimed it was "defense-in-depth in case Workers */
      /* ever returns more bytes than the declared length" — that's not */
      /* a real risk; Workers honors the declared Content-Length. The */
      /* secondary check is a sanity assert against the much narrower */
      /* case of a malformed client that declares Content-Length: 500 but */
      /* the actual body string somehow exceeds it (encoding mismatch, */
      /* etc.). At this 1024-byte ceiling, the buffering has already */
      /* happened by the time we look at it, so this is *not* a buffering */
      /* defense — it's a "the data we parse from here on is actually */
      /* under the cap" guarantee. The real buffering defense is the */
      /* Content-Length check above. Mislabeling it as defense-in-depth */
      /* invited the wrong intuition during code review. */
      const _clRaw = request.headers.get('Content-Length');
      if (_clRaw === null) {
        _aRej('no_length');
        return new Response(null, { status: 411, headers: { 'Cache-Control': 'no-store' } });
      }
      const _alLen = parseInt(_clRaw, 10);
      if (!Number.isFinite(_alLen) || _alLen < 0 || _alLen > 1024) {
        _aRej('bad_length');
        return new Response(null, { status: 413, headers: { 'Cache-Control': 'no-store' } });
      }
      const _alText = await request.text();
      if (_alText.length > 1024) {
        _aRej('oversize_body');
        return new Response(null, { status: 413, headers: { 'Cache-Control': 'no-store' } });
      }
      /* v387: short-circuit empty bodies. A POST with Content-Length: 0 is valid */
      /* HTTP and some sendBeacon code paths produce it. JSON.parse('') throws, */
      /* which v382's verbose catch logs as "Unexpected end of JSON input" \u2014 */
      /* legitimate traffic showing up as warnings made the tail logs noisy when */
      /* actually debugging. Empty body = no event to record = quietly 204. */
      if (_alText.length === 0) {
        return new Response(null, { status: 204, headers: { 'Cache-Control': 'no-store' } });
      }
      const body = JSON.parse(_alText);
      /* v382: allowlist body.event before it reaches the Analytics Engine index.
       * The v300 comment correctly noted that high cardinality on `indexes`
       * degrades query performance — but the cap-to-32-chars defense only
       * limited per-event size, not the count of distinct events. With the
       * v300 RMW rate limit shown to be bypassable (see analytics block above),
       * an attacker could write hundreds of thousands of distinct event strings
       * and poison the index. Allowlist anchors cardinality at a small constant.
       * Anything off-list is bucketed under 'unknown' so we keep volume signal
       * without paying cardinality cost. Keep this list in sync with the client
       * instrumentation. */
      const _ALLOWED_EVENTS = new Set([
        'page_view', 'subpage_view', 'api_call', 'static_asset',
        'relay_click', 'health_check', 'comparison_toggle',
        'panel_open', 'panel_close', 'search', 'filter_apply',
        'ws_connect', 'ws_disconnect', 'auth_login', 'auth_register',
        'quest_progress', 'game_start', 'game_finish', 'unknown'
      ]);
      if (env.ANALYTICS && body && typeof body.event === 'string') {
        const rawEvt = body.event.slice(0, 32);
        const evt = _ALLOWED_EVENTS.has(rawEvt) ? rawEvt : 'unknown';
        const path = (typeof body.path === 'string' ? body.path : '').slice(0, 80);
        const cc = request.headers.get("CF-IPCountry") || "XX";
        const status = typeof body.status === 'number' ? body.status : 0;
        env.ANALYTICS.writeDataPoint({
          blobs: [evt, path, cc],
          doubles: [1, status],
          indexes: [evt]
        });
      }
    } catch(e){
      /* v382: previously `catch(_){}` swallowed every error silently — including
       * Analytics Engine write failures (invalid schema, binding misconfigured)
       * and JSON.parse errors on malformed beacons. Both classes are operationally
       * useful to see in tail logs without changing the response (still 204 so
       * clients don't retry). console.warn is free on this path. */
      console.warn('analytics handler: ' + (e && e.message ? e.message : String(e)));
    }
    return new Response(null, { status: 204, headers: { "Cache-Control": "no-store" } });
  }

  if (_path === '/bitcoin') {   const bpHtml = "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"UTF-8\">\n<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n<title>Anyone for Bitcoin &mdash; Private Node Configuration</title>\n<meta name=\"description\" content=\"Route your Bitcoin node through Anyone Protocol for IP privacy. Free bitcoin.conf generator with Anyone SOCKS5 proxy.\">\n<link rel=\"preconnect\" href=\"https://fonts.googleapis.com\">\n<link rel=\"preconnect\" href=\"https://fonts.gstatic.com\" crossorigin>\n<link href=\"https://fonts.googleapis.com/css2?family=Orbitron:wght@400;600;700;800;900&family=JetBrains+Mono:wght@400;500;700&display=swap\" rel=\"stylesheet\">\n<link rel=\"stylesheet\" href=\"/design-tokens.css\">\n<style>\n:root {\n  /* v375: shared --an-* tokens moved to /design-tokens.css. Only --btc-* remain. */\n  --btc-orange: #f7931a; --btc-orange-bright: #ffb84d; --btc-orange-title: #ffa940;\n  --btc-muted: rgba(247,147,26,.08); --btc-border: rgba(247,147,26,.3);\n}\n* { margin: 0; padding: 0; box-sizing: border-box; }\nbody {\n  background: var(--an-dark); color: var(--an-text);\n  font-family: system-ui, -apple-system, sans-serif; font-size: 15px; line-height: 1.6;\n  min-height: 100vh;\n}\n.bp-container { max-width: 960px; margin: 0 auto; padding: 32px 24px; }\n\n/* Hero */\n.bp-hero {\n  text-align: center; padding: 48px 0 32px; border-bottom: 1px solid var(--an-teal-border);\n  margin-bottom: 48px;\n}\n.bp-hero-badge {\n  display: inline-flex; align-items: center; gap: 8px;\n  background: var(--btc-muted); border: 1px solid var(--btc-border);\n  color: var(--btc-orange-title); padding: 6px 14px;\n  border-radius: 999px; font-family: Orbitron, sans-serif;\n  font-size: 10px; font-weight: 700; letter-spacing: 2px; text-transform: uppercase;\n  margin-bottom: 20px;\n}\n.bp-hero h1 {\n  font-family: Orbitron, sans-serif; font-size: 44px; font-weight: 800;\n  background: linear-gradient(135deg, var(--an-teal-bright), var(--btc-orange-bright));\n  -webkit-background-clip: text; -webkit-text-fill-color: transparent;\n  background-clip: text; letter-spacing: 1px; margin-bottom: 14px;\n  line-height: 1.2;\n}\n.bp-hero p {\n  color: var(--an-text-dim); font-size: 18px; max-width: 640px;\n  margin: 0 auto 24px;\n}\n.bp-hero-meta {\n  display: flex; gap: 32px; justify-content: center; flex-wrap: wrap;\n  color: var(--an-text-muted); font-size: 13px;\n  font-family: \"JetBrains Mono\", monospace;\n}\n.bp-hero-meta b { color: var(--an-teal-text); }\n\n/* Sections */\n.bp-section {\n  margin-bottom: 56px;\n}\n.bp-section-label {\n  font-family: Orbitron, sans-serif; font-size: 10px; color: var(--an-teal-text);\n  letter-spacing: 3px; text-transform: uppercase; font-weight: 700;\n  margin-bottom: 10px; display: flex; align-items: center; gap: 10px;\n}\n.bp-section-label::after {\n  content: \"\"; flex: 1; height: 1px;\n  background: linear-gradient(90deg, var(--an-teal-border), transparent);\n}\n.bp-section h2 {\n  font-family: Orbitron, sans-serif; font-size: 26px; font-weight: 700;\n  color: var(--an-text); margin-bottom: 12px; letter-spacing: 0.5px;\n}\n.bp-section > p { color: var(--an-text-dim); margin-bottom: 24px; font-size: 15px; }\n\n/* Why card */\n.bp-why-grid {\n  display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 16px;\n}\n.bp-why-card {\n  background: var(--an-surface); border: 1px solid rgba(148,163,184,.1);\n  border-radius: 12px; padding: 22px;\n}\n.bp-why-card h3 {\n  font-family: Orbitron, sans-serif; font-size: 14px; color: var(--an-teal-text);\n  letter-spacing: 1px; text-transform: uppercase; font-weight: 700; margin-bottom: 10px;\n}\n.bp-why-card p { color: var(--an-text-dim); font-size: 13px; line-height: 1.6; }\n\n/* Config generator */\n.bp-gen {\n  background: var(--an-surface); border: 1px solid var(--an-teal-border);\n  border-radius: 16px; overflow: hidden;\n  box-shadow: 0 0 40px rgba(45,212,191,0.05);\n}\n.bp-gen-header {\n  padding: 20px 24px; border-bottom: 1px solid rgba(148,163,184,.08);\n  display: flex; align-items: center; justify-content: space-between; gap: 16px;\n  flex-wrap: wrap;\n}\n.bp-gen-title {\n  font-family: Orbitron, sans-serif; font-size: 16px; color: var(--an-teal-text);\n  letter-spacing: 1.5px; text-transform: uppercase; font-weight: 700;\n}\n.bp-gen-body { display: grid; grid-template-columns: 1fr 1fr; }\n@media (max-width: 780px) { .bp-gen-body { grid-template-columns: 1fr; } }\n.bp-gen-controls { padding: 24px; border-right: 1px solid rgba(148,163,184,.08); }\n@media (max-width: 780px) { .bp-gen-controls { border-right: none; border-bottom: 1px solid rgba(148,163,184,.08); } }\n.bp-gen-output {\n  background: var(--an-dark); position: relative; overflow: hidden;\n}\n.bp-control-group { margin-bottom: 22px; }\n.bp-control-group:last-child { margin-bottom: 0; }\n.bp-control-label {\n  display: block; font-family: Orbitron, sans-serif; font-size: 10px;\n  color: var(--an-teal-text); letter-spacing: 2px; text-transform: uppercase;\n  font-weight: 700; margin-bottom: 10px;\n}\n.bp-input {\n  width: 100%; padding: 10px 12px; background: var(--an-dark);\n  border: 1px solid rgba(148,163,184,.15); border-radius: 6px;\n  color: var(--an-text); font-family: \"JetBrains Mono\", monospace; font-size: 13px;\n  transition: border-color .15s;\n}\n.bp-input:focus {\n  outline: none; border-color: var(--an-teal);\n  box-shadow: 0 0 0 2px rgba(45,212,191,.15);\n}\n.bp-input.bp-input-invalid {\n  border-color: var(--an-coral);\n  box-shadow: 0 0 0 2px rgba(255,107,107,.15);\n}\n.bp-input.bp-input-invalid:focus {\n  border-color: var(--an-coral);\n  box-shadow: 0 0 0 2px rgba(255,107,107,.25);\n}\n.bp-input-error {\n  color: var(--an-coral);\n  font-size: 12px;\n  margin-top: 6px;\n  font-family: system-ui, -apple-system, sans-serif;\n}\n.bp-input-error[hidden] { display: none; }\n.bp-checkbox-group { display: flex; flex-direction: column; gap: 10px; }\n.bp-checkbox {\n  display: flex; align-items: flex-start; gap: 10px;\n  padding: 10px 12px; background: rgba(148,163,184,.03);\n  border: 1px solid rgba(148,163,184,.1); border-radius: 8px;\n  cursor: pointer; transition: all .15s; user-select: none;\n}\n.bp-checkbox:hover { background: rgba(45,212,191,.06); border-color: var(--an-teal-border); }\n.bp-checkbox input { margin-top: 2px; accent-color: var(--an-teal); cursor: pointer; }\n.bp-checkbox-body { flex: 1; }\n.bp-checkbox-title { font-size: 13px; color: var(--an-text); font-weight: 500; }\n.bp-checkbox-desc { font-size: 11px; color: var(--an-text-dim); margin-top: 2px; line-height: 1.4; }\n\n.bp-output-toolbar {\n  padding: 12px 20px; border-bottom: 1px solid rgba(148,163,184,.08);\n  display: flex; align-items: center; gap: 10px;\n  background: rgba(10,22,40,.5);\n}\n.bp-output-dots { display: flex; gap: 6px; }\n.bp-output-dot {\n  width: 10px; height: 10px; border-radius: 50%;\n  background: rgba(148,163,184,.2);\n}\n.bp-output-dot:nth-child(1) { background: rgba(248,113,113,.5); }\n.bp-output-dot:nth-child(2) { background: rgba(251,191,36,.5); }\n.bp-output-dot:nth-child(3) { background: rgba(52,211,153,.5); }\n.bp-output-file {\n  font-family: \"JetBrains Mono\", monospace; font-size: 11px;\n  color: var(--an-text-dim); margin-left: auto;\n}\n.bp-output-copy {\n  padding: 5px 12px; background: var(--an-teal-muted);\n  border: 1px solid var(--an-teal-border); border-radius: 4px;\n  color: var(--an-teal-text); font-family: Orbitron, sans-serif; font-size: 10px;\n  font-weight: 700; letter-spacing: 1.5px; text-transform: uppercase;\n  cursor: pointer; transition: all .15s;\n}\n.bp-output-copy:hover { background: rgba(45,212,191,.18); color: var(--an-teal-bright); }\n.bp-output-copy.copied { background: rgba(52,211,153,.15); color: var(--an-green); border-color: var(--an-green); }\n.bp-output-download {\n  padding: 5px 12px; background: var(--btc-muted);\n  border: 1px solid var(--btc-border); border-radius: 4px;\n  color: var(--btc-orange-title); font-family: Orbitron, sans-serif; font-size: 10px;\n  font-weight: 700; letter-spacing: 1.5px; text-transform: uppercase;\n  cursor: pointer; transition: all .15s; margin-left: 6px; text-decoration: none;\n  display: inline-block;\n}\n.bp-output-download:hover { background: rgba(247,147,26,.15); color: var(--btc-orange-bright); }\n\n.bp-output-code {\n  padding: 20px 24px; overflow-x: auto;\n  font-family: \"JetBrains Mono\", monospace; font-size: 13px;\n  line-height: 1.75; color: var(--an-text);\n  white-space: pre; min-height: 400px;\n  max-height: 500px; overflow-y: auto;\n}\n.bp-output-code .comment { color: var(--an-text-muted); font-style: italic; }\n.bp-output-code .key { color: var(--an-teal-text); }\n.bp-output-code .val { color: var(--btc-orange-bright); }\n.bp-output-code .section { color: var(--an-amber); font-weight: 700; }\n\n/* Comparison */\n.bp-comp {\n  background: var(--an-surface); border: 1px solid rgba(148,163,184,.1);\n  border-radius: 12px; overflow: hidden;\n}\n.bp-comp-table { width: 100%; border-collapse: collapse; }\n.bp-comp-table th {\n  padding: 14px 18px; text-align: left; font-family: Orbitron, sans-serif;\n  font-size: 10px; letter-spacing: 2px; text-transform: uppercase;\n  color: var(--an-text-dim); background: rgba(10,22,40,.5);\n  border-bottom: 1px solid var(--an-teal-border); font-weight: 700;\n}\n.bp-comp-table th:nth-child(2) { color: var(--an-teal-text); }\n.bp-comp-table th:nth-child(3) { color: var(--an-text-dim); }\n.bp-comp-table td {\n  padding: 14px 18px; font-size: 13px;\n  border-bottom: 1px solid rgba(148,163,184,.05);\n}\n.bp-comp-table tr:last-child td { border-bottom: none; }\n.bp-comp-table td:first-child {\n  font-family: Orbitron, sans-serif; color: var(--an-text);\n  letter-spacing: 0.5px; font-weight: 500; font-size: 12px;\n}\n.bp-comp-table td:nth-child(2) { color: var(--an-text); }\n.bp-comp-table td:nth-child(3) { color: var(--an-text-dim); }\n.bp-comp-yes { color: var(--an-green) !important; font-weight: 600; }\n.bp-comp-no { color: var(--an-red) !important; }\n.bp-comp-partial { color: var(--an-amber) !important; }\n.bp-comp-asof { color: var(--an-text-muted); font-size: 11px; font-family: \"JetBrains Mono\", monospace; padding: 12px 22px 0; text-align: right; }\n.bp-comp-asof.stale { color: var(--an-amber); }\n\n/* Install steps */\n.bp-steps { display: flex; flex-direction: column; gap: 16px; }\n.bp-step {\n  background: var(--an-surface); border: 1px solid rgba(148,163,184,.1);\n  border-radius: 12px; padding: 20px 24px;\n  display: grid; grid-template-columns: auto 1fr; gap: 18px; align-items: start;\n}\n.bp-step-num {\n  width: 36px; height: 36px; border-radius: 50%;\n  background: var(--an-teal-muted); border: 1px solid var(--an-teal-border);\n  display: flex; align-items: center; justify-content: center;\n  color: var(--an-teal-text); font-family: Orbitron, sans-serif;\n  font-weight: 700; font-size: 16px;\n}\n.bp-step-body h3 {\n  font-family: Orbitron, sans-serif; font-size: 14px; color: var(--an-text);\n  letter-spacing: 1px; text-transform: uppercase; font-weight: 700; margin-bottom: 6px;\n}\n.bp-step-body p { color: var(--an-text-dim); font-size: 13px; margin-bottom: 10px; }\n.bp-code-inline {\n  background: var(--an-dark); border: 1px solid rgba(148,163,184,.1);\n  border-radius: 6px; padding: 8px 12px; font-family: \"JetBrains Mono\", monospace;\n  font-size: 12px; color: var(--an-teal-text);\n  display: block; overflow-x: auto; white-space: pre-wrap;\n}\n\n/* FAQ */\n.bp-faq-item {\n  background: var(--an-surface); border: 1px solid rgba(148,163,184,.1);\n  border-radius: 10px; margin-bottom: 10px; overflow: hidden;\n}\n.bp-faq-q {\n  padding: 14px 20px; cursor: pointer; user-select: none;\n  font-weight: 500; color: var(--an-text); font-size: 14px;\n  display: flex; align-items: center; justify-content: space-between; gap: 12px;\n}\n.bp-faq-q::after {\n  content: \"+\"; font-family: Orbitron, sans-serif; color: var(--an-teal-text);\n  font-size: 18px; font-weight: 300; transition: transform .2s;\n}\n.bp-faq-item.open .bp-faq-q::after { content: \"-\"; }\n.bp-faq-a {\n  padding: 0 20px 16px; color: var(--an-text-dim); font-size: 13px;\n  line-height: 1.7; display: none;\n}\n.bp-faq-item.open .bp-faq-a { display: block; }\n\n/* Warnings */\n.bp-warn {\n  background: rgba(251,191,36,.06); border: 1px solid rgba(251,191,36,.2);\n  border-radius: 10px; padding: 14px 18px; margin: 16px 0;\n  display: flex; gap: 12px; align-items: flex-start;\n}\n.bp-warn-icon { color: var(--an-amber); flex-shrink: 0; margin-top: 2px; }\n.bp-warn-body { color: var(--an-text); font-size: 13px; line-height: 1.6; }\n.bp-warn-body b { color: var(--an-amber); }\n\n/* Footer */\n.bp-footer {\n  padding: 32px 0; text-align: center; border-top: 1px solid rgba(148,163,184,.08);\n  color: var(--an-text-muted); font-size: 12px; margin-top: 48px;\n}\n.bp-footer a { color: var(--an-teal-text); text-decoration: none; }\n.bp-footer a:hover { color: var(--an-teal-bright); }\n\n/* Nav */\n.bp-nav {\n  position: sticky; top: 0; z-index: 10;\n  background: rgba(2,11,18,.9); backdrop-filter: blur(10px);\n  border-bottom: 1px solid rgba(45,212,191,.1);\n  padding: 12px 24px; display: flex; align-items: center; gap: 16px;\n}\n.bp-nav-brand {\n  font-family: Orbitron, sans-serif; font-size: 13px; font-weight: 800;\n  letter-spacing: 2px; color: var(--an-teal-text); text-decoration: none;\n}\n.bp-nav-spacer { flex: 1; }\n.bp-nav-link {\n  font-family: Orbitron, sans-serif; font-size: 10px; letter-spacing: 1.5px;\n  color: var(--an-text-dim); text-decoration: none; text-transform: uppercase;\n  padding: 6px 12px; border-radius: 6px; transition: all .15s;\n}\n.bp-nav-link:hover { color: var(--an-teal-text); background: var(--an-teal-muted); }\n</style>\n</head>\n<body>\n<nav class=\"bp-nav\">\n  <a href=\"/\" class=\"bp-nav-brand\">&#8900; ANYONE</a>\n  <div class=\"bp-nav-spacer\"></div>\n  <a href=\"/\" class=\"bp-nav-link\">Map</a>\n  <a href=\"/style-guide\" class=\"bp-nav-link\">Style Guide</a>\n  <a href=\"#generator\" class=\"bp-nav-link\">Config Generator</a>\n</nav>\n\n<div class=\"bp-container\">\n  <header class=\"bp-hero\">\n    <div class=\"bp-hero-badge\">&#8383; Anyone for Bitcoin</div>\n    <h1>Run your Bitcoin node<br>without leaking your IP</h1>\n    <p>Route your Bitcoin Core node through Anyone Protocol&#39;s SOCKS5 proxy for network-layer privacy. Drop-in replacement for Tor, with staked relay operators.</p>\n    <div class=\"bp-hero-meta\">\n      <span>Port: <b>9050</b></span>\n      <span>Protocol: <b>SOCKS5</b></span>\n      <span>Status: <b style=\"color:var(--an-amber)\">Experimental</b></span>\n    </div>\n  </header>\n\n  <section class=\"bp-section\">\n    <div class=\"bp-section-label\">Why Anyone</div>\n    <h2>Your Bitcoin node leaks more than you think</h2>\n    <p>Every peer your node connects to learns your IP address. Chain analysis firms map node operators by IP. Your ISP sees that you&#39;re running Bitcoin. Anyone Protocol solves this at the network layer, not the wallet layer.</p>\n    <div class=\"bp-why-grid\">\n      <div class=\"bp-why-card\">\n        <h3>Drop-in SOCKS5</h3>\n        <p>Same port (9050), same protocol as Tor. One line in bitcoin.conf. No wallet changes, no rebuilding, no new software to learn.</p>\n      </div>\n      <div class=\"bp-why-card\">\n        <h3>Staked relays</h3>\n        <p>Relay operators have economic skin in the game. Bad behavior means losing stake &mdash; a model Tor never offered.</p>\n      </div>\n      <div class=\"bp-why-card\">\n        <h3>ISP diversity</h3>\n        <p>Anyone covers 40+ countries across 400+ ISPs. <a href=\"/\" style=\"color:var(--an-teal-text)\">Live map</a> shows coverage in your region.</p>\n      </div>\n    </div>\n  </section>\n\n  <section class=\"bp-section\" id=\"generator\">\n    <div class=\"bp-section-label\">&#8383; Config Generator</div>\n    <h2>Build your bitcoin.conf</h2>\n    <p>Configure options below, copy the generated config into <code style=\"background:var(--an-surface);padding:2px 6px;border-radius:4px;font-family:'JetBrains Mono',monospace;font-size:12px;color:var(--an-teal-text)\">~/.bitcoin/bitcoin.conf</code>, then restart Bitcoin Core.</p>\n    \n    <div class=\"bp-gen\">\n      <div class=\"bp-gen-header\">\n        <div class=\"bp-gen-title\">Configuration Options</div>\n        <div style=\"color:var(--an-text-dim);font-size:11px;font-family:'JetBrains Mono',monospace\">Live preview &rarr;</div>\n      </div>\n      <div class=\"bp-gen-body\">\n        <div class=\"bp-gen-controls\">\n          <div class=\"bp-control-group\">\n            <label class=\"bp-control-label\">Anyone Proxy Address</label>\n            <input type=\"text\" class=\"bp-input\" id=\"proxy-addr\" value=\"127.0.0.1:9050\" placeholder=\"127.0.0.1:9050\" aria-describedby=\"proxy-addr-error\" autocomplete=\"off\" spellcheck=\"false\">\\n            <div class=\"bp-input-error\" id=\"proxy-addr-error\" role=\"alert\" hidden>Invalid proxy address. Use host:port (e.g. 127.0.0.1:9050, [::1]:9050, or my-proxy.lan:9050).</div>\n          </div>\n          <div class=\"bp-control-group\">\n            <label class=\"bp-control-label\">Network Mode</label>\n            <div class=\"bp-checkbox-group\">\n              <label class=\"bp-checkbox\">\n                <input type=\"radio\" name=\"mode\" value=\"hybrid\" checked>\n                <div class=\"bp-checkbox-body\">\n                  <div class=\"bp-checkbox-title\">Hybrid (recommended)</div>\n                  <div class=\"bp-checkbox-desc\">Route clearnet &amp; onion through Anyone. Still accept inbound connections.</div>\n                </div>\n              </label>\n              <label class=\"bp-checkbox\">\n                <input type=\"radio\" name=\"mode\" value=\"strict\">\n                <div class=\"bp-checkbox-body\">\n                  <div class=\"bp-checkbox-title\">Strict (Anyone only)</div>\n                  <div class=\"bp-checkbox-desc\">All traffic through Anyone. Maximum privacy, less connectivity.</div>\n                </div>\n              </label>\n              <label class=\"bp-checkbox\">\n                <input type=\"radio\" name=\"mode\" value=\"outbound\">\n                <div class=\"bp-checkbox-body\">\n                  <div class=\"bp-checkbox-title\">Outbound only</div>\n                  <div class=\"bp-checkbox-desc\">Route outbound through Anyone, don&#39;t listen for inbound connections.</div>\n                </div>\n              </label>\n            </div>\n          </div>\n          <div class=\"bp-control-group\">\n            <label class=\"bp-control-label\">Options</label>\n            <div class=\"bp-checkbox-group\">\n              <label class=\"bp-checkbox\">\n                <input type=\"checkbox\" id=\"opt-prune\" checked>\n                <div class=\"bp-checkbox-body\">\n                  <div class=\"bp-checkbox-title\">Prune mode (550 MB)</div>\n                  <div class=\"bp-checkbox-desc\">Save disk space. Recommended for non-archival nodes.</div>\n                </div>\n              </label>\n              <label class=\"bp-checkbox\">\n                <input type=\"checkbox\" id=\"opt-debug\">\n                <div class=\"bp-checkbox-body\">\n                  <div class=\"bp-checkbox-title\">Verbose proxy logging</div>\n                  <div class=\"bp-checkbox-desc\">Enable debug=proxy to verify routing in debug.log.</div>\n                </div>\n              </label>\n              <label class=\"bp-checkbox\">\n                <input type=\"checkbox\" id=\"opt-comments\" checked>\n                <div class=\"bp-checkbox-body\">\n                  <div class=\"bp-checkbox-title\">Include inline comments</div>\n                  <div class=\"bp-checkbox-desc\">Document what each option does (recommended).</div>\n                </div>\n              </label>\n            </div>\n          </div>\n        </div>\n        \n        <div class=\"bp-gen-output\">\n          <div class=\"bp-output-toolbar\">\n            <div class=\"bp-output-dots\">\n              <div class=\"bp-output-dot\"></div>\n              <div class=\"bp-output-dot\"></div>\n              <div class=\"bp-output-dot\"></div>\n            </div>\n            <div class=\"bp-output-file\">bitcoin.conf</div>\n            <button class=\"bp-output-copy\" id=\"btn-copy\">Copy</button>\n            <a class=\"bp-output-download\" id=\"btn-download\" download=\"bitcoin.conf\">Download</a>\n          </div>\n          <pre class=\"bp-output-code\" id=\"output\"></pre>\n        </div>\n      </div>\n    </div>\n    \n    <div class=\"bp-warn\">\n      <svg class=\"bp-warn-icon\" width=\"20\" height=\"20\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\"><path d=\"M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z\"/><line x1=\"12\" y1=\"9\" x2=\"12\" y2=\"13\"/><line x1=\"12\" y1=\"17\" x2=\"12.01\" y2=\"17\"/></svg>\n      <div class=\"bp-warn-body\">\n        <b>Experimental.</b> Anyone Protocol integration with Bitcoin Core is not officially supported by the Bitcoin Core team. Test with a pruned node on testnet or signet first. Keep backups of your existing <code>bitcoin.conf</code>.\n      </div>\n    </div>\n  </section>\n\n  <section class=\"bp-section\">\n    <div class=\"bp-section-label\">Quick Install</div>\n    <h2>Get the Anyone relay running locally</h2>\n    <p>Install the Anyone SOCKS5 proxy on the same machine as your Bitcoin node (or on your LAN). Then point Bitcoin Core at it.</p>\n    <div class=\"bp-steps\">\n      <div class=\"bp-step\">\n        <div class=\"bp-step-num\">1</div>\n        <div class=\"bp-step-body\">\n          <h3>Install Anyone relay</h3>\n          <p>Follow the official Anyone install guide for your OS:</p>\n          <code class=\"bp-code-inline\"># Ubuntu / Debian\ncurl -fsSL https://deb.en.anyone.tech/anon.asc | sudo tee /etc/apt/keyrings/anon.asc\necho \"deb [signed-by=/etc/apt/keyrings/anon.asc] https://deb.en.anyone.tech anon-live-jammy main\" | sudo tee /etc/apt/sources.list.d/anon.list\nsudo apt update &amp;&amp; sudo apt install -y anon</code>\n        </div>\n      </div>\n      <div class=\"bp-step\">\n        <div class=\"bp-step-num\">2</div>\n        <div class=\"bp-step-body\">\n          <h3>Enable SOCKS5 port</h3>\n          <p>Edit <code style=\"color:var(--an-teal-text);font-family:'JetBrains Mono',monospace;font-size:12px\">/etc/anon/anonrc</code> and add:</p>\n          <code class=\"bp-code-inline\">SocksPort 127.0.0.1:9050\nSocksPolicy accept 127.0.0.1\nSocksPolicy reject *</code>\n        </div>\n      </div>\n      <div class=\"bp-step\">\n        <div class=\"bp-step-num\">3</div>\n        <div class=\"bp-step-body\">\n          <h3>Start Anyone, then Bitcoin</h3>\n          <p>Start the Anyone daemon, wait for it to bootstrap (~60s), then restart Bitcoin Core:</p>\n          <code class=\"bp-code-inline\">sudo systemctl restart anon\nsudo systemctl status anon   # check it&#39;s running\nbitcoind -daemon              # start your node</code>\n        </div>\n      </div>\n      <div class=\"bp-step\">\n        <div class=\"bp-step-num\">4</div>\n        <div class=\"bp-step-body\">\n          <h3>Verify routing</h3>\n          <p>In Bitcoin Core console or CLI, check that peers are being discovered through the proxy:</p>\n          <code class=\"bp-code-inline\">bitcoin-cli getnetworkinfo | grep -A 5 \"networks\"\nbitcoin-cli getpeerinfo | jq &#39;.[].addr&#39; | head</code>\n        </div>\n      </div>\n    </div>\n  </section>\n\n  <section class=\"bp-section\">\n    <div class=\"bp-section-label\">Honest Comparison</div>\n    <h2>Anyone vs Tor for Bitcoin</h2>\n    <p>Both route your traffic. Both run on port 9050. The differences matter for different users.</p>\n    <div class=\"bp-comp\">\n      <table class=\"bp-comp-table\">\n        <thead>\n          <tr>\n            <th>Dimension</th>\n            <th>Anyone</th>\n            <th>Tor</th>\n          </tr>\n        </thead>\n        <tbody>\n          <tr>\n            <td>Maturity</td>\n            <td class=\"bp-comp-partial\">Experimental (2024+)</td>\n            <td class=\"bp-comp-yes\">20 years of cryptographic scrutiny</td>\n          </tr>\n          <tr>\n            <td>Relay incentives</td>\n            <td class=\"bp-comp-yes\">Staked operators (skin in game)</td>\n            <td class=\"bp-comp-partial\">Volunteer only</td>\n          </tr>\n          <tr>\n            <td>Bitcoin Core official support</td>\n            <td class=\"bp-comp-no\">Not yet</td>\n            <td class=\"bp-comp-yes\">First-class (docs, onion services)</td>\n          </tr>\n          <tr>\n            <td>Onion service (.onion)</td>\n            <td class=\"bp-comp-no\">No (use Tor for inbound)</td>\n            <td class=\"bp-comp-yes\">Yes</td>\n          </tr>\n          <tr>\n            <td>ISP diversity</td>\n            <td class=\"bp-comp-partial\">Growing (400+ ISPs)</td>\n            <td class=\"bp-comp-yes\">Broader today</td>\n          </tr>\n          <tr>\n            <td>Network-layer IP privacy</td>\n            <td class=\"bp-comp-yes\">Yes</td>\n            <td class=\"bp-comp-yes\">Yes</td>\n          </tr>\n          <tr>\n            <td>Exit relay count</td>\n            <td class=\"bp-comp-yes\">{{exit_count}}</td>\n            <td class=\"bp-comp-partial\">Comparable scale</td>\n          </tr>\n          <tr>\n            <td>Aggregate exit bandwidth</td>\n            <td class=\"bp-comp-yes\">{{exit_bw}}</td>\n            <td>Not directly comparable</td>\n          </tr>\n          <tr>\n            <td>Exit block rate for Bitcoin</td>\n            <td class=\"bp-comp-yes\">Lower (less targeted)</td>\n            <td class=\"bp-comp-partial\">Increasing blocks</td>\n          </tr>\n        </tbody>\n      </table>\n      <div class=\"bp-comp-asof\" title=\"Data published at {{absTs}}\">Live counts updated {{freshness}} ({{updated}}) \\u2014 pulled from the AnyoneMap network feed.</div>\n    </div>\n    <div class=\"bp-warn\">\n      <svg class=\"bp-warn-icon\" width=\"20\" height=\"20\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\"><circle cx=\"12\" cy=\"12\" r=\"10\"/><line x1=\"12\" y1=\"16\" x2=\"12\" y2=\"12\"/><line x1=\"12\" y1=\"8\" x2=\"12.01\" y2=\"8\"/></svg>\n      <div class=\"bp-warn-body\">\n        <b>Our honest take.</b> If you need a .onion service for inbound connections, use Tor. If you need outbound IP privacy with a staked operator model, try Anyone. Nothing stops you from using both &mdash; Bitcoin Core supports <code>-proxy</code> and <code>-onion</code> as separate options.\n      </div>\n    </div>\n  </section>\n\n  <section class=\"bp-section\">\n    <div class=\"bp-section-label\">FAQ</div>\n    <h2>Common questions</h2>\n    \n    <div class=\"bp-faq-item\">\n      <div class=\"bp-faq-q\">Will this slow down my node&#39;s initial block download?</div>\n      <div class=\"bp-faq-a\">Yes, somewhat. Routing through any proxy adds latency. For initial sync (downloading 600+ GB of blockchain), you may want to do IBD over clearnet or VPN, then switch to Anyone for ongoing operation. Steady-state operation adds minimal overhead.</div>\n    </div>\n    <div class=\"bp-faq-item\">\n      <div class=\"bp-faq-q\">Do I need to stake ANYONE tokens to use the proxy?</div>\n      <div class=\"bp-faq-a\">No. Running a relay requires stake. Using a relay as a client (SOCKS5 proxy) is free. Your traffic routes through relays that other people staked on.</div>\n    </div>\n    <div class=\"bp-faq-item\">\n      <div class=\"bp-faq-q\">Can I run Anyone and Tor simultaneously?</div>\n      <div class=\"bp-faq-a\">Yes, but not out of the box. Anyone and Tor both default their SOCKS port to 9050, so they collide if you run both at once &mdash; you&#39;ll need to move one. For example, leave Tor on 9050 and set Anyone&#39;s <code>SocksPort</code> to 9052, then point <code>-proxy=127.0.0.1:9052</code> at Anyone and <code>-onion=127.0.0.1:9050</code> at Tor to split clearnet and onion traffic.</div>\n    </div>\n    <div class=\"bp-faq-item\">\n      <div class=\"bp-faq-q\">What breaks if Anyone relays go offline?</div>\n      <div class=\"bp-faq-a\">Your node loses connectivity to peers until Anyone recovers or you disable the proxy. Bitcoin Core won&#39;t fall back to clearnet automatically. Keep <code>-proxy</code> as a conscious choice, and monitor the <a href=\"/\" style=\"color:var(--an-teal-text)\">AnyoneMap</a> for network health.</div>\n    </div>\n    <div class=\"bp-faq-item\">\n      <div class=\"bp-faq-q\">Does this affect my wallet transactions?</div>\n      <div class=\"bp-faq-a\">Not directly. The proxy operates below the application layer. Your transactions are the same; only your IP is hidden from peers. CoinJoin and other privacy tools still work.</div>\n    </div>\n    <div class=\"bp-faq-item\">\n      <div class=\"bp-faq-q\">Is this production-ready?</div>\n      <div class=\"bp-faq-a\">Honestly: not yet, not for high-value nodes. Anyone Protocol is experimental. Use it on pruned nodes, testnet, or alongside other privacy tools. We&#39;ll update this page as the integration matures.</div>\n    </div>\n  </section>\n\n  <footer class=\"bp-footer\">\n    <p>AnyoneMap v1.2 &middot; <a href=\"/\">Back to map</a> &middot; <a href=\"/style-guide\">Style guide</a></p>\n    <p style=\"margin-top:8px;font-size:11px\">This page is educational. It is not officially endorsed by the Bitcoin Core project or Anyone Protocol. Verify all configs before running on mainnet.</p>\n  </footer>\n</div>\n\n<script>\n(function() {\n  var proxyAddr = document.getElementById(\"proxy-addr\");\n  var optPrune = document.getElementById(\"opt-prune\");\n  var optDebug = document.getElementById(\"opt-debug\");\n  var optComments = document.getElementById(\"opt-comments\");\n  var output = document.getElementById(\"output\");\n  var btnCopy = document.getElementById(\"btn-copy\");\n  var btnDownload = document.getElementById(\"btn-download\");\n\n  function getMode() {\n    var radios = document.querySelectorAll(\"input[name='mode']\");\n    for (var i = 0; i < radios.length; i++) if (radios[i].checked) return radios[i].value;\n    return \"hybrid\";\n  }\n\n  function esc(s) { return s.replace(/[<>&]/g, function(c){ return {\"<\":\"&lt;\",\">\":\"&gt;\",\"&\":\"&amp;\"}[c]; }); }\n\n  /* v395: validate proxy-addr input strictly. Previously a multi-line paste */\n  /* like \"127.0.0.1:9050\\\\nrpcuser=x\" would have its newlines stripped and */\n  /* concatenated into the proxy= line, silently producing a broken bitcoin.conf */\n  /* (proxy=127.0.0.1:9050rpcuser=x — an unparseable host:port). The output */\n  /* uses textContent so this was never an XSS, but the resulting config file */\n  /* would either fail to parse or, worse, parse with the user's actual proxy */\n  /* misconfigured. Strict validation refuses bad input outright and surfaces */\n  /* the reason via an aria-live error message; the preview keeps its previous */\n  /* good value (no surprise mutation of user intent). */\n  var addrErrorEl = document.getElementById(\"proxy-addr-error\");\n  var IPV4_RE = /^(?:(?:25[0-5]|2[0-4]\\d|[01]?\\d\\d?)\\.){3}(?:25[0-5]|2[0-4]\\d|[01]?\\d\\d?)$/;\n  var IPV6_BRACKETED_RE = /^\\[[0-9a-fA-F:]+\\]$/;\n  var HOSTNAME_RE = /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$/;\n  function validateProxyAddr(raw) {\n    if (typeof raw !== \"string\") return null;\n    var s = raw.trim();\n    if (s === \"\") return \"127.0.0.1:9050\"; /* empty input \\u2192 default */\n    /* Quick guard: no whitespace or newlines anywhere. */\n    if (/\\s/.test(s)) return null;\n    /* Split on the LAST colon to handle IPv6 brackets. */\n    var idx = s.lastIndexOf(\":\");\n    if (idx <= 0 || idx === s.length - 1) return null;\n    var host = s.slice(0, idx);\n    var port = s.slice(idx + 1);\n    if (!/^[1-9]\\d{0,4}$/.test(port)) return null;\n    var portN = parseInt(port, 10);\n    if (portN < 1 || portN > 65535) return null;\n    /* Host: total length cap + one of three forms. */\n    if (host.length > 253) return null;\n    /* If the host LOOKS IPv4 (four dotted numeric octets) but doesn't pass */\n    /* the strict octet check, reject rather than falling through to the */\n    /* hostname regex \\u2014 which would accept e.g. 999.999.999.999 because it's */\n    /* all valid hostname characters. */\n    if (/^\\d+(\\.\\d+){3}$/.test(host) && !IPV4_RE.test(host)) return null;\n    if (IPV4_RE.test(host)) return host + \":\" + portN;\n    if (IPV6_BRACKETED_RE.test(host)) return host + \":\" + portN;\n    if (HOSTNAME_RE.test(host)) return host + \":\" + portN;\n    return null;\n  }\n  function setAddrError(show) {\n    if (proxyAddr) proxyAddr.setAttribute(\"aria-invalid\", show ? \"true\" : \"false\");\n    if (proxyAddr) proxyAddr.classList.toggle(\"bp-input-invalid\", !!show);\n    if (addrErrorEl) addrErrorEl.hidden = !show;\n  }\n\n  function generate() {\n    var mode = getMode();\n    var validated = validateProxyAddr(proxyAddr.value);\n    if (validated === null) {\n      setAddrError(true);\n      return; /* keep the previous preview; user fixes input before regenerating */\n    }\n    setAddrError(false);\n    var addr = validated;\n    var comments = optComments.checked;\n    var prune = optPrune.checked;\n    var debug = optDebug.checked;\n    var lines = [];\n    var raw = [];\n\n    if (comments) {\n      raw.push(\"# bitcoin.conf - Anyone Protocol privacy configuration\");\n      raw.push(\"# Generated by https://anyonemap.anyonerelaysmap.workers.dev/bitcoin\");\n      raw.push(\"# Mode: \" + mode);\n      raw.push(\"\");\n      raw.push(\"# ==========================================\");\n      raw.push(\"# ANYONE PROXY ROUTING\");\n      raw.push(\"# ==========================================\");\n      raw.push(\"\");\n      raw.push(\"# Route all outbound clearnet traffic through Anyone SOCKS5\");\n    }\n    raw.push(\"proxy=\" + addr);\n\n    if (mode === \"hybrid\") {\n      if (comments) {\n        raw.push(\"\");\n        raw.push(\"# Use a separate Tor proxy for .onion peers (optional — requires Tor running locally)\");\n        raw.push(\"# Anyone is a SOCKS5 proxy that doesn't speak Tor; .onion peers will silently fail\");\n        raw.push(\"# if you point onion= at Anyone. Uncomment and set the line below ONLY if you also\");\n        raw.push(\"# run Tor (Tor Browser binds 9150; pure Tor daemon binds 9050 — use a different\");\n        raw.push(\"# port than Anyone to avoid conflicts).\");\n      }\n      raw.push(\"#onion=127.0.0.1:9150\");\n\n      if (comments) {\n        raw.push(\"\");\n        raw.push(\"# Accept inbound IPv4/IPv6 connections (dual-stack)\");\n        raw.push(\"# Omit 'listen' to disable inbound entirely\");\n      }\n      raw.push(\"listen=1\");\n    } else if (mode === \"strict\") {\n      if (comments) {\n        raw.push(\"\");\n        raw.push(\"# Privacy-maximizing: route everything through Anyone, refuse direct clearnet, no inbound.\");\n        raw.push(\"# We restrict outbound to IPv4+IPv6 (NOT onion) because Anyone is a clearnet SOCKS5\");\n        raw.push(\"# proxy and can't route to .onion peers. onlynet=onion would leave the node with zero\");\n        raw.push(\"# peers since the onion network would be unreachable via Anyone alone.\");\n      }\n      raw.push(\"onlynet=ipv4\");\n      raw.push(\"onlynet=ipv6\");\n      if (comments) raw.push(\"# Don't listen for inbound (prevents IP leaks)\");\n      raw.push(\"listen=0\");\n    } else { // outbound\n      if (comments) {\n        raw.push(\"\");\n        raw.push(\"# Outbound only - don't accept inbound connections\");\n        raw.push(\"# (prevents exposing your IP to peers connecting in)\");\n      }\n      raw.push(\"listen=0\");\n    }\n\n    if (comments) {\n      raw.push(\"\");\n      raw.push(\"# ==========================================\");\n      raw.push(\"# NODE SETTINGS\");\n      raw.push(\"# ==========================================\");\n    }\n    raw.push(\"\");\n    if (prune) {\n      if (comments) raw.push(\"# Prune mode - keep only last 550 MB of blocks\");\n      raw.push(\"prune=550\");\n    } else {\n      if (comments) raw.push(\"# Archival node - store all blocks\");\n      raw.push(\"txindex=1\");\n    }\n\n    if (comments) {\n      raw.push(\"\");\n      raw.push(\"# Reduce memory usage for the mempool (optional)\");\n    }\n    raw.push(\"maxmempool=300\");\n\n    if (debug) {\n      if (comments) {\n        raw.push(\"\");\n        raw.push(\"# Debug logging - verify routing is working\");\n        raw.push(\"# Check ~/.bitcoin/debug.log for 'SOCKS5' entries\");\n      }\n      raw.push(\"debug=proxy\");\n      raw.push(\"debug=net\");\n    }\n\n    if (comments) {\n      raw.push(\"\");\n      raw.push(\"# ==========================================\");\n      raw.push(\"# RPC SETTINGS (local only)\");\n      raw.push(\"# ==========================================\");\n    }\n    raw.push(\"\");\n    if (comments) raw.push(\"# Only allow RPC from localhost\");\n    raw.push(\"rpcbind=127.0.0.1\");\n    raw.push(\"rpcallowip=127.0.0.1\");\n\n    if (comments) {\n      raw.push(\"\");\n      raw.push(\"# End of configuration. Restart bitcoind after saving:\");\n      raw.push(\"#   bitcoin-cli stop\");\n      raw.push(\"#   bitcoind -daemon\");\n    }\n\n    // Syntax highlight\n    var html = raw.map(function(line) {\n      if (line.indexOf(\"#\") === 0) {\n        if (line.indexOf(\"==========\") > -1 || line.toUpperCase() === line.trim() && line.length > 3) {\n          return \"<span class='section'>\" + esc(line) + \"</span>\";\n        }\n        return \"<span class='comment'>\" + esc(line) + \"</span>\";\n      }\n      if (line.indexOf(\"=\") > 0) {\n        var parts = line.split(\"=\");\n        return \"<span class='key'>\" + esc(parts[0]) + \"</span>=<span class='val'>\" + esc(parts.slice(1).join(\"=\")) + \"</span>\";\n      }\n      return esc(line);\n    }).join(\"\\n\");\n\n    output.innerHTML = html;\n    \n    // Update download link\n    var raw_text = raw.join(\"\\n\");\n    var blob = new Blob([raw_text], { type: \"text/plain\" });\n    if (btnDownload._url) URL.revokeObjectURL(btnDownload._url);\n    btnDownload._url = URL.createObjectURL(blob);\n    btnDownload.href = btnDownload._url;\n\n    // Store raw for copy\n    btnCopy._raw = raw_text;\n  }\n\n  // Wire up events\n  document.querySelectorAll(\"input\").forEach(function(el){\n    el.addEventListener(\"change\", generate);\n    if (el.type === \"text\") el.addEventListener(\"input\", generate);\n  });\n\n  btnCopy.addEventListener(\"click\", function() {\n    var text = btnCopy._raw || \"\";\n    if (navigator.clipboard) {\n      navigator.clipboard.writeText(text).then(function(){\n        btnCopy.textContent = \"Copied!\";\n        btnCopy.classList.add(\"copied\");\n        setTimeout(function(){\n          btnCopy.textContent = \"Copy\";\n          btnCopy.classList.remove(\"copied\");\n        }, 2000);\n      });\n    } else {\n      var ta = document.createElement(\"textarea\");\n      ta.value = text;\n      document.body.appendChild(ta);\n      ta.select();\n      document.execCommand(\"copy\");\n      ta.remove();\n      btnCopy.textContent = \"Copied!\";\n      btnCopy.classList.add(\"copied\");\n      setTimeout(function(){ btnCopy.textContent = \"Copy\"; btnCopy.classList.remove(\"copied\"); }, 2000);\n    }\n  });\n\n  // FAQ accordion\n  document.querySelectorAll(\".bp-faq-item\").forEach(function(item){\n    item.querySelector(\".bp-faq-q\").addEventListener(\"click\", function(){\n      item.classList.toggle(\"open\");\n    });\n  });\n\n  generate();\n})();\n</script>\n<!-- PROXY CHIP ENHANCEMENT -->\n<style>\n.bp-proxy-chip {\n  position: fixed; bottom: 24px; right: 24px; z-index: 100;\n  background: var(--an-surface); border: 1px solid var(--an-teal-border);\n  border-radius: 999px; padding: 8px 14px 8px 10px;\n  display: flex; align-items: center; gap: 10px;\n  font-family: \"JetBrains Mono\", monospace; font-size: 12px;\n  color: var(--an-text); cursor: pointer; user-select: none;\n  box-shadow: 0 8px 24px rgba(0,0,0,.4), 0 0 0 1px rgba(45,212,191,.08);\n  transition: all .2s; backdrop-filter: blur(8px);\n  background: rgba(10,22,40,.92); max-width: calc(100vw - 48px);\n}\n.bp-proxy-chip:hover {\n  border-color: var(--an-teal); transform: translateY(-2px);\n  box-shadow: 0 12px 32px rgba(0,0,0,.5), 0 0 20px rgba(45,212,191,.15);\n}\n.bp-proxy-chip.copied {\n  border-color: var(--an-green);\n  box-shadow: 0 8px 24px rgba(0,0,0,.4), 0 0 20px rgba(52,211,153,.25);\n}\n.bp-proxy-chip-dot {\n  width: 8px; height: 8px; border-radius: 50%;\n  background: var(--an-teal); box-shadow: 0 0 8px var(--an-teal);\n  animation: bpChipPulse 2s ease-in-out infinite; flex-shrink: 0;\n}\n.bp-proxy-chip.copied .bp-proxy-chip-dot { background: var(--an-green); box-shadow: 0 0 8px var(--an-green); }\n@keyframes bpChipPulse { 0%,100% { opacity: 1; } 50% { opacity: .4; } }\n.bp-proxy-chip-label {\n  font-family: Orbitron, sans-serif; font-size: 9px; font-weight: 700;\n  color: var(--an-teal-text); letter-spacing: 1.5px; text-transform: uppercase;\n}\n.bp-proxy-chip-addr {\n  color: var(--an-text); font-weight: 500;\n  white-space: nowrap; overflow: hidden; text-overflow: ellipsis;\n  max-width: 180px;\n}\n.bp-proxy-chip-mode {\n  padding: 2px 8px; background: var(--an-teal-muted);\n  border: 1px solid var(--an-teal-border); border-radius: 999px;\n  font-family: Orbitron, sans-serif; font-size: 8px; font-weight: 700;\n  color: var(--an-teal-text); letter-spacing: 1px; text-transform: uppercase;\n  flex-shrink: 0;\n}\n.bp-proxy-chip-mode.strict { background: rgba(251,191,36,.1); border-color: rgba(251,191,36,.3); color: var(--an-amber); }\n.bp-proxy-chip-mode.outbound { background: rgba(167,139,250,.1); border-color: rgba(167,139,250,.3); color: #a78bfa; }\n.bp-proxy-chip-copy-hint {\n  font-family: Orbitron, sans-serif; font-size: 9px; color: var(--an-text-muted);\n  letter-spacing: 1px; text-transform: uppercase; flex-shrink: 0;\n}\n.bp-proxy-chip.copied .bp-proxy-chip-copy-hint { color: var(--an-green); }\n@media (max-width: 640px) {\n  .bp-proxy-chip { bottom: 16px; right: 16px; padding: 6px 12px 6px 8px; }\n  .bp-proxy-chip-addr { max-width: 120px; font-size: 11px; }\n  .bp-proxy-chip-label { display: none; }\n}\n</style>\n<div class=\"bp-proxy-chip\" id=\"bp-proxy-chip\" role=\"button\" tabindex=\"0\" title=\"Click to copy proxy address\">\n  <span class=\"bp-proxy-chip-dot\" aria-hidden=\"true\"></span>\n  <span class=\"bp-proxy-chip-label\">Proxy</span>\n  <span class=\"bp-proxy-chip-addr\" id=\"bp-proxy-chip-addr\">127.0.0.1:9050</span>\n  <span class=\"bp-proxy-chip-mode\" id=\"bp-proxy-chip-mode\">Hybrid</span>\n  <span class=\"bp-proxy-chip-copy-hint\" id=\"bp-proxy-chip-hint\">Copy</span>\n</div>\n<script>\n(function(){\n  var chip = document.getElementById(\"bp-proxy-chip\");\n  var addrEl = document.getElementById(\"bp-proxy-chip-addr\");\n  var modeEl = document.getElementById(\"bp-proxy-chip-mode\");\n  var hintEl = document.getElementById(\"bp-proxy-chip-hint\");\n  var addrInput = document.getElementById(\"proxy-addr\");\n  if (!chip || !addrInput) return;\n  var MODE_LABELS = { hybrid: \"Hybrid\", strict: \"Strict\", outbound: \"Outbound\" };\n  function currentMode(){\n    var radios = document.querySelectorAll(\"input[name='mode']\");\n    for (var i = 0; i < radios.length; i++) if (radios[i].checked) return radios[i].value;\n    return \"hybrid\";\n  }\n  function sync(){\n    var addr = (addrInput.value || \"\").trim() || \"127.0.0.1:9050\";\n    var mode = currentMode();\n    addrEl.textContent = addr;\n    modeEl.textContent = MODE_LABELS[mode] || mode;\n    modeEl.className = \"bp-proxy-chip-mode\" + (mode !== \"hybrid\" ? \" \" + mode : \"\");\n    chip.setAttribute(\"aria-label\", \"Proxy \" + addr + \", mode \" + (MODE_LABELS[mode] || mode) + \". Click to copy.\");\n  }\n  function flashCopied(){\n    chip.classList.add(\"copied\");\n    hintEl.textContent = \"Copied\";\n    setTimeout(function(){ chip.classList.remove(\"copied\"); hintEl.textContent = \"Copy\"; }, 1500);\n  }\n  function copyAddr(){\n    var text = addrEl.textContent;\n    if (navigator.clipboard && navigator.clipboard.writeText) {\n      navigator.clipboard.writeText(text).then(flashCopied).catch(fallback);\n    } else { fallback(); }\n    function fallback(){\n      var ta = document.createElement(\"textarea\");\n      ta.value = text; ta.style.position = \"fixed\"; ta.style.opacity = \"0\";\n      document.body.appendChild(ta); ta.select();\n      try { document.execCommand(\"copy\"); flashCopied(); } catch(e) {}\n      ta.remove();\n    }\n  }\n  chip.addEventListener(\"click\", copyAddr);\n  chip.addEventListener(\"keydown\", function(e){\n    if (e.key === \"Enter\" || e.key === \" \") { e.preventDefault(); copyAddr(); }\n  });\n  addrInput.addEventListener(\"input\", sync);\n  addrInput.addEventListener(\"change\", sync);\n  document.querySelectorAll(\"input[name='mode']\").forEach(function(r){\n    r.addEventListener(\"change\", sync);\n  });\n  sync();\n})();\n</script>\n</body>\n</html>\n";   /* v397: live-data interpolation for the Anyone-vs-Tor comparison table. Three placeholders ({{exit_count}}, {{exit_bw}}, {{updated}}) are filled from anyclip-proxy/api/exit-relays. On any failure (proxy down, JSON malformed, missing fields), placeholders resolve to "\u2014" so the page still renders informatively rather than showing literal {{...}} tokens. The sibling fetch is edge-cached for 5 minutes via cf.cacheTtl, matching this page's own Cache-Control max-age=300 \u2014 so the live data isn't pulled per-request, it's pulled once per edge per 5 min. The "as of" footer shows the date of the fetch; if anyclip-proxy returns a cachedAt timestamp older than 1 hour, the footer gets a .stale CSS class to flag it visually. Previously the table had hardcoded "4,360 (Apr 2026)" / "~477 Gbps" numbers and a hardcoded Tor count of "3,184" \u2014 those went out of date the moment they were written and there's no easy live Tor source from this worker. v397 keeps Anyone live, swaps the Tor numeric for "Comparable scale" (truthful, future-proof). */   let _liveBtc = { exit_count: "\u2014", exit_bw: "\u2014", updated: "\u2014", freshness: "\u2014", absTs: "", staleCls: "" };   try {     /* v402: read from SNAPSHOT_KV instead of fetching anyclip-proxy over HTTP. */     /* The cross-worker HTTP fetch hit Cloudflare error 1042 ("Worker tried to */     /* fetch from another Worker on the same zone via a public hostname") and */     /* surfaced as a generic 404 with body "error code: 1042" \u2014 confirmed via */     /* the v401 X-Live-Diag header before this version. Architectural fix mirrors */     /* the bitnodes pattern from v393: a producer worker (anyclip-proxy v50) writes */     /* a snapshot into shared SNAPSHOT_KV under stable key "exit-relays:latest" on */     /* every cron tick; this consumer worker reads from the same KV. No HTTP, no */     /* same-zone-loop, and a KV read is ~1-5ms locally. The publisher includes a */     /* cachedAt unix timestamp and converts bandwidth to Gbps so we don't have to */     /* duplicate the conversion arithmetic in two places. */     const _bcdRaw = env.SNAPSHOT_KV ? await env.SNAPSHOT_KV.get(_kvSchema.SNAPSHOT_KEY, { type: "json" }) : null;     /* v410: validate the snapshot shape. Permissive mode so any deploy skew between producer and consumer doesn't break the page — we log issues and proceed with defaults. The extract() call applies the schema's `default` value for any field that's missing or wrong-typed, so downstream code can stop doing its own typeof checks. */     const _bcdValidation = _kvSchema.validate(_bcdRaw, _kvSchema.EXIT_RELAYS_LATEST, { mode: "permissive", context: "read" });     if (_bcdValidation.warnings.length > 0 || _bcdValidation.fields_unknown.length > 0) {       console.warn("[v410 kv-schema] /bitcoin SNAPSHOT_KV read had warnings:", JSON.stringify({ warnings: _bcdValidation.warnings, unknown: _bcdValidation.fields_unknown, fields_seen: _bcdValidation.fields_seen }));     }     const _bcd = _kvSchema.extract(_bcdRaw, _kvSchema.EXIT_RELAYS_LATEST);     if (_bcd && typeof _bcd === "object") {       if (typeof _bcd.exit_relays === "number") _liveBtc.exit_count = _bcd.exit_relays.toLocaleString("en-US");       if (typeof _bcd.bw_gbps === "number") _liveBtc.exit_bw = "~" + Math.round(_bcd.bw_gbps) + " Gbps";       const _tsMs = (typeof _bcd.cachedAt === "number" ? _bcd.cachedAt * 1000 : Date.now());       _liveBtc.updated = new Date(_tsMs).toISOString().slice(0, 10);       /* v409: render a relative-time freshness string so the user sees how fresh the data actually is. Anyclip-proxy v52 writes to SNAPSHOT_KV on every /api/exit-relays request, so the data is typically seconds fresh, but day-level resolution hides that. Buckets are chosen to communicate freshness without false precision. The full ISO timestamp is preserved in _liveBtc.absTs for the hover title. */       _liveBtc.absTs = new Date(_tsMs).toISOString().replace("T", " ").slice(0, 19) + " UTC";       const _ageMs = Date.now() - _tsMs;       if (_ageMs < 60 * 1000) _liveBtc.freshness = "just now";       else if (_ageMs < 60 * 60 * 1000) _liveBtc.freshness = Math.floor(_ageMs / 60000) + " min ago";       else if (_ageMs < 24 * 60 * 60 * 1000) _liveBtc.freshness = Math.floor(_ageMs / 3600000) + "h ago";       else if (_ageMs < 48 * 60 * 60 * 1000) _liveBtc.freshness = "yesterday";       else _liveBtc.freshness = Math.floor(_ageMs / (24 * 3600000)) + "d ago";       /* If the publisher hasn't refreshed in 24h something is wrong upstream. */       /* The bp-comp-asof.stale CSS rule (defined in the embedded stylesheet) */       /* tints the footer amber so the user sees the date is questionable. */       if (_ageMs > 24 * 3600 * 1000) _liveBtc.staleCls = " stale";     }   } catch (_e) { /* fall through with \u2014 placeholders */ }   const _bpFilled = bpHtml     .replace(/{{exit_count}}/g, _liveBtc.exit_count)     .replace(/{{exit_bw}}/g, _liveBtc.exit_bw)     .replace(/{{updated}}/g, _liveBtc.updated)     .replace(/{{freshness}}/g, _liveBtc.freshness)     .replace(/{{absTs}}/g, _liveBtc.absTs)     .replace(/bp-comp-asof"/g, 'bp-comp-asof' + _liveBtc.staleCls + '"');   return new Response(_bpFilled, {     headers: {       'Content-Type': 'text/html; charset=utf-8',       'Cache-Control': 'public, max-age=300',       'X-Content-Type-Options': 'nosniff',       'X-Frame-Options': 'DENY',       /* v396: header parity with the / route. Previous /bitcoin and /style-guide responses had only Content-Type, Cache-Control, X-Content-Type-Options, X-Frame-Options — missing Permissions-Policy (so every browser feature was unconstrained on these pages even though they use none of them), Referrer-Policy (so outbound link clicks leaked the full URL to third parties), and Content-Security-Policy (so any XSS that slipped past the existing esc() function would have full network reach). The / route was hardened in v391 after the duplicate-key bug was found there; /bitcoin and /style-guide were untouched at the time. Permissions-Policy denies everything since these pages use no privileged browser features — distinct from the / route which grants microphone=(self) for the Operators Lounge voice-record feature. CSP allowlist is minimal: 'self' for everything plus Google Fonts (the only external dependency). 'unsafe-inline' is required for the inline <style> and <script> blocks; without it the entire page wouldn't render. The esc() function on /bitcoin already strips <>& from user-supplied input before innerHTML, so 'unsafe-inline' is not load-bearing for the v395 proxy-input validation. */       'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), payment=()',       'Referrer-Policy': 'strict-origin-when-cross-origin',       'Content-Security-Policy': "default-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; script-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"     }   }); } if (_path === '/style-guide') {   const sgHtml = "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"UTF-8\">\n<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n<meta name=\"robots\" content=\"noindex, nofollow\">\n<title>AnyoneMap Style Guide \u2014 Design Tokens & Components</title>\n<link rel=\"preconnect\" href=\"https://fonts.googleapis.com\">\n<link rel=\"preconnect\" href=\"https://fonts.gstatic.com\" crossorigin>\n<link href=\"https://fonts.googleapis.com/css2?family=Orbitron:wght@400;600;700;800;900&family=JetBrains+Mono:wght@400;500;700&display=swap\" rel=\"stylesheet\">\n<link rel=\"stylesheet\" href=\"/design-tokens.css\">\n<style>\n/* v375: page :root removed — all 38 tokens were duplicates of /design-tokens.css. */* { margin: 0; padding: 0; box-sizing: border-box; }\nbody {\n  background: var(--an-dark);\n  color: var(--an-text);\n  font-family: var(--an-font-body);\n  font-size: 14px;\n  line-height: 1.6;\n  padding: var(--an-space-8);\n  min-height: 100vh;\n}\n.sg-container { max-width: 1200px; margin: 0 auto; }\n.sg-header {\n  border-bottom: 1px solid var(--an-teal-border);\n  padding-bottom: var(--an-space-6);\n  margin-bottom: var(--an-space-8);\n}\n.sg-header h1 {\n  font-family: var(--an-font-display);\n  font-size: var(--an-text-2xl);\n  font-weight: 800;\n  color: var(--an-teal-text);\n  letter-spacing: 2px;\n  text-transform: uppercase;\n  text-shadow: 0 0 20px rgba(45,212,191,.4);\n}\n.sg-header p { color: var(--an-text-dim); margin-top: var(--an-space-2); font-size: var(--an-text-md); }\n.sg-header .sg-link { color: var(--an-teal); text-decoration: none; border-bottom: 1px dashed var(--an-teal-border); }\n.sg-header .sg-link:hover { color: var(--an-teal-bright); }\n\n.sg-section {\n  margin-bottom: var(--an-space-10);\n  padding: var(--an-space-6);\n  background: var(--an-surface);\n  border: 1px solid var(--an-teal-border);\n  border-radius: var(--an-radius-lg);\n}\n.sg-section h2 {\n  font-family: var(--an-font-display);\n  font-size: var(--an-text-xl);\n  font-weight: 700;\n  color: var(--an-teal-text);\n  letter-spacing: 1.5px;\n  text-transform: uppercase;\n  margin-bottom: var(--an-space-2);\n}\n.sg-section .sg-section-desc {\n  color: var(--an-text-dim);\n  font-size: var(--an-text-md);\n  margin-bottom: var(--an-space-6);\n}\n.sg-section h3 {\n  font-family: var(--an-font-display);\n  font-size: var(--an-text-md);\n  font-weight: 600;\n  color: var(--an-text);\n  letter-spacing: 1px;\n  text-transform: uppercase;\n  margin: var(--an-space-6) 0 var(--an-space-3);\n  padding-bottom: var(--an-space-2);\n  border-bottom: 1px solid rgba(148,163,184,.1);\n}\n\n/* Color swatches */\n.sg-color-grid {\n  display: grid;\n  grid-template-columns: repeat(auto-fill, minmax(180px, 1fr));\n  gap: var(--an-space-3);\n}\n.sg-color {\n  padding: var(--an-space-3);\n  border-radius: var(--an-radius-md);\n  border: 1px solid rgba(148,163,184,.15);\n  background: var(--an-dark);\n  transition: transform .15s;\n}\n.sg-color:hover { transform: translateY(-2px); border-color: var(--an-teal-border); }\n.sg-color-swatch {\n  width: 100%;\n  height: 60px;\n  border-radius: var(--an-radius-sm);\n  margin-bottom: var(--an-space-3);\n  border: 1px solid rgba(255,255,255,.08);\n}\n.sg-color-name {\n  font-family: var(--an-font-mono);\n  font-size: var(--an-text-sm);\n  color: var(--an-text);\n  font-weight: 500;\n}\n.sg-color-val {\n  font-family: var(--an-font-mono);\n  font-size: var(--an-text-xs);\n  color: var(--an-text-dim);\n  margin-top: var(--an-space-1);\n  word-break: break-all;\n}\n\n/* Typography specimens */\n.sg-type-row {\n  display: flex;\n  align-items: baseline;\n  gap: var(--an-space-5);\n  padding: var(--an-space-3) 0;\n  border-bottom: 1px solid rgba(148,163,184,.08);\n}\n.sg-type-row:last-child { border-bottom: none; }\n.sg-type-label {\n  font-family: var(--an-font-mono);\n  font-size: var(--an-text-xs);\n  color: var(--an-text-dim);\n  min-width: 120px;\n  padding-top: 4px;\n}\n.sg-type-specimen { color: var(--an-text); flex: 1; }\n.sg-type-val { font-family: var(--an-font-mono); font-size: var(--an-text-xs); color: var(--an-text-muted); }\n\n/* Spacing demo */\n.sg-spacing-row {\n  display: flex;\n  align-items: center;\n  gap: var(--an-space-4);\n  padding: var(--an-space-2) 0;\n}\n.sg-spacing-label {\n  font-family: var(--an-font-mono);\n  font-size: var(--an-text-sm);\n  color: var(--an-text-dim);\n  min-width: 100px;\n}\n.sg-spacing-bar {\n  height: 16px;\n  background: var(--an-teal);\n  border-radius: var(--an-radius-sm);\n}\n.sg-spacing-val { font-family: var(--an-font-mono); font-size: var(--an-text-sm); color: var(--an-text); }\n\n/* Radius demo */\n.sg-radius-grid {\n  display: grid;\n  grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));\n  gap: var(--an-space-4);\n}\n.sg-radius-box {\n  aspect-ratio: 1;\n  background: linear-gradient(135deg, rgba(45,212,191,.1), rgba(167,139,250,.1));\n  border: 1px solid var(--an-teal-border);\n  display: flex;\n  flex-direction: column;\n  align-items: center;\n  justify-content: center;\n  gap: var(--an-space-1);\n  padding: var(--an-space-3);\n}\n.sg-radius-name { font-family: var(--an-font-display); font-size: var(--an-text-md); color: var(--an-teal-text); font-weight: 700; }\n.sg-radius-val { font-family: var(--an-font-mono); font-size: var(--an-text-xs); color: var(--an-text-dim); }\n\n/* Button gallery */\n.sg-btn-row { display: flex; flex-wrap: wrap; gap: var(--an-space-3); align-items: center; }\n.sg-btn {\n  padding: 10px 18px;\n  border-radius: var(--an-radius-md);\n  font-family: var(--an-font-display);\n  font-size: var(--an-text-sm);\n  font-weight: 700;\n  letter-spacing: 1.5px;\n  text-transform: uppercase;\n  cursor: pointer;\n  border: 1px solid var(--an-teal-border);\n  background: var(--an-teal-muted);\n  color: var(--an-teal-text);\n  transition: all .15s;\n}\n.sg-btn:hover {\n  background: rgba(45,212,191,.2);\n  border-color: var(--an-teal);\n  color: var(--an-teal-bright);\n  box-shadow: 0 0 12px rgba(45,212,191,.3);\n}\n.sg-btn-orange {\n  background: rgba(247,147,26,.08);\n  border-color: rgba(247,147,26,.3);\n  color: #ffa940;\n}\n.sg-btn-orange:hover { background: rgba(247,147,26,.15); color: #ffb84d; box-shadow: 0 0 12px rgba(247,147,26,.3); }\n.sg-btn-danger {\n  background: rgba(248,113,113,.08);\n  border-color: rgba(248,113,113,.3);\n  color: var(--an-red);\n}\n.sg-btn-ghost {\n  background: transparent;\n  border: 1px solid rgba(148,163,184,.15);\n  color: var(--an-text-dim);\n}\n\n/* Widget examples */\n.sg-widget-grid {\n  display: grid;\n  grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));\n  gap: var(--an-space-4);\n}\n.sg-widget {\n  padding: var(--an-space-4);\n  background: var(--an-teal-muted);\n  border: 1px solid var(--an-teal-border);\n  border-radius: var(--an-radius-md);\n}\n.sg-widget h4 {\n  font-family: var(--an-font-display);\n  font-size: var(--an-text-xs);\n  color: var(--an-teal-text);\n  letter-spacing: 2.5px;\n  font-weight: 700;\n  text-transform: uppercase;\n  margin-bottom: var(--an-space-3);\n}\n.sg-widget-row {\n  display: grid;\n  grid-template-columns: 1fr auto;\n  gap: var(--an-space-2);\n  padding: 4px 0;\n  font-size: var(--an-text-sm);\n  color: rgba(228,228,233,.85);\n  white-space: nowrap;\n}\n.sg-widget-row b {\n  color: var(--an-teal-text);\n  font-family: var(--an-font-display);\n  font-weight: 900;\n  font-size: 13px;\n  text-align: right;\n}\n.sg-widget-orange { background: rgba(247,147,26,.08); border-color: rgba(247,147,26,.3); }\n.sg-widget-orange h4 { color: #ffa940; }\n.sg-widget-orange .sg-widget-row { color: rgba(255,220,180,.95); }\n.sg-widget-orange .sg-widget-row b { color: #ffb84d; }\n\n/* Node markers (for map) */\n.sg-markers-grid {\n  display: grid;\n  grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));\n  gap: var(--an-space-4);\n  margin-top: var(--an-space-3);\n}\n.sg-marker-cell {\n  display: flex;\n  flex-direction: column;\n  align-items: center;\n  gap: var(--an-space-2);\n  padding: var(--an-space-3);\n  background: var(--an-dark);\n  border: 1px solid rgba(148,163,184,.1);\n  border-radius: var(--an-radius-md);\n}\n.sg-marker-label { font-family: var(--an-font-mono); font-size: var(--an-text-xs); color: var(--an-text-dim); }\n.sg-marker-type { font-family: var(--an-font-display); font-size: var(--an-text-sm); color: var(--an-text); font-weight: 600; }\n\n/* Code sample */\n.sg-code {\n  font-family: var(--an-font-mono);\n  font-size: var(--an-text-sm);\n  background: var(--an-dark);\n  border: 1px solid rgba(148,163,184,.1);\n  border-radius: var(--an-radius-md);\n  padding: var(--an-space-4);\n  color: var(--an-teal-text);\n  overflow-x: auto;\n  margin-top: var(--an-space-3);\n  line-height: 1.7;\n}\n.sg-code .comment { color: var(--an-text-dim); }\n.sg-code .keyword { color: var(--an-purple); }\n\n/* Table of contents */\n.sg-toc {\n  position: fixed;\n  top: var(--an-space-8);\n  right: var(--an-space-8);\n  background: var(--an-surface);\n  border: 1px solid var(--an-teal-border);\n  border-radius: var(--an-radius-md);\n  padding: var(--an-space-4);\n  width: 200px;\n  font-size: var(--an-text-sm);\n}\n.sg-toc h5 {\n  font-family: var(--an-font-display);\n  font-size: var(--an-text-xs);\n  color: var(--an-teal-text);\n  letter-spacing: 2px;\n  text-transform: uppercase;\n  margin-bottom: var(--an-space-2);\n  font-weight: 700;\n}\n.sg-toc a {\n  display: block;\n  color: var(--an-text-dim);\n  text-decoration: none;\n  padding: 4px 0;\n  font-size: var(--an-text-sm);\n  transition: color .1s;\n}\n.sg-toc a:hover { color: var(--an-teal-text); }\n@media (max-width: 1100px) { .sg-toc { display: none; } }\n</style>\n</head>\n<body>\n<nav class=\"sg-toc\">\n  <h5>Sections</h5>\n  <a href=\"#colors\">Colors</a>\n  <a href=\"#typography\">Typography</a>\n  <a href=\"#spacing\">Spacing</a>\n  <a href=\"#radius\">Radius</a>\n  <a href=\"#buttons\">Buttons</a>\n  <a href=\"#widgets\">Widgets</a>\n  <a href=\"#markers\">Map Markers</a>\n  <a href=\"#usage\">Usage</a>\n</nav>\n\n<div class=\"sg-container\">\n<header class=\"sg-header\">\n  <h1>AnyoneMap Style Guide</h1>\n  <p>Design tokens and components for AnyoneMap v1.2 &mdash; <a class=\"sg-link\" href=\"/\">back to map</a></p>\n</header>\n\n<section id=\"colors\" class=\"sg-section\">\n  <h2>Colors</h2>\n  <p class=\"sg-section-desc\">Brand palette. Teal is the primary Anyone color. Orange is reserved for Bitcoin integration. Use semantic colors (red/amber/green) for status.</p>\n\n  <h3>Brand &mdash; Teal</h3>\n  <div class=\"sg-color-grid\">\n    <div class=\"sg-color\"><div class=\"sg-color-swatch\" style=\"background:#2dd4bf\"></div><div class=\"sg-color-name\">--an-teal</div><div class=\"sg-color-val\">#2dd4bf</div></div>\n    <div class=\"sg-color\"><div class=\"sg-color-swatch\" style=\"background:#5eead4\"></div><div class=\"sg-color-name\">--an-teal-text</div><div class=\"sg-color-val\">#5eead4</div></div>\n    <div class=\"sg-color\"><div class=\"sg-color-swatch\" style=\"background:#99f6e4\"></div><div class=\"sg-color-name\">--an-teal-bright</div><div class=\"sg-color-val\">#99f6e4</div></div>\n    <div class=\"sg-color\"><div class=\"sg-color-swatch\" style=\"background:rgba(45,212,191,.1);border:1px dashed rgba(45,212,191,.3)\"></div><div class=\"sg-color-name\">--an-teal-muted</div><div class=\"sg-color-val\">rgba(45,212,191,.1)</div></div>\n  </div>\n\n  <h3>Semantic</h3>\n  <div class=\"sg-color-grid\">\n    <div class=\"sg-color\"><div class=\"sg-color-swatch\" style=\"background:#34d399\"></div><div class=\"sg-color-name\">--an-green</div><div class=\"sg-color-val\">#34d399 &mdash; success</div></div>\n    <div class=\"sg-color\"><div class=\"sg-color-swatch\" style=\"background:#fbbf24\"></div><div class=\"sg-color-name\">--an-amber</div><div class=\"sg-color-val\">#fbbf24 &mdash; warning</div></div>\n    <div class=\"sg-color\"><div class=\"sg-color-swatch\" style=\"background:#f87171\"></div><div class=\"sg-color-name\">--an-red</div><div class=\"sg-color-val\">#f87171 &mdash; error</div></div>\n    <div class=\"sg-color\"><div class=\"sg-color-swatch\" style=\"background:#a78bfa\"></div><div class=\"sg-color-name\">--an-purple</div><div class=\"sg-color-val\">#a78bfa &mdash; accent</div></div>\n    <div class=\"sg-color\"><div class=\"sg-color-swatch\" style=\"background:#ff6b6b\"></div><div class=\"sg-color-name\">--an-coral</div><div class=\"sg-color-val\">#ff6b6b &mdash; danger alt</div></div>\n  </div>\n\n  <h3>Bitcoin Integration</h3>\n  <div class=\"sg-color-grid\">\n    <div class=\"sg-color\"><div class=\"sg-color-swatch\" style=\"background:#f7931a\"></div><div class=\"sg-color-name\">Bitcoin Orange</div><div class=\"sg-color-val\">#f7931a &mdash; brand</div></div>\n    <div class=\"sg-color\"><div class=\"sg-color-swatch\" style=\"background:#ffa940\"></div><div class=\"sg-color-name\">Bitcoin Title</div><div class=\"sg-color-val\">#ffa940 &mdash; headings</div></div>\n    <div class=\"sg-color\"><div class=\"sg-color-swatch\" style=\"background:#ffb84d\"></div><div class=\"sg-color-name\">Bitcoin Value</div><div class=\"sg-color-val\">#ffb84d &mdash; stat numbers</div></div>\n  </div>\n\n  <h3>Surfaces &amp; Text</h3>\n  <div class=\"sg-color-grid\">\n    <div class=\"sg-color\"><div class=\"sg-color-swatch\" style=\"background:#020b12\"></div><div class=\"sg-color-name\">--an-dark</div><div class=\"sg-color-val\">#020b12 &mdash; body bg</div></div>\n    <div class=\"sg-color\"><div class=\"sg-color-swatch\" style=\"background:#0a1628\"></div><div class=\"sg-color-name\">--an-surface</div><div class=\"sg-color-val\">#0a1628 &mdash; cards</div></div>\n    <div class=\"sg-color\"><div class=\"sg-color-swatch\" style=\"background:#0f1f36\"></div><div class=\"sg-color-name\">--an-surface-hover</div><div class=\"sg-color-val\">#0f1f36</div></div>\n    <div class=\"sg-color\"><div class=\"sg-color-swatch\" style=\"background:#e4e4e9\"></div><div class=\"sg-color-name\">--an-text</div><div class=\"sg-color-val\">#e4e4e9 &mdash; primary</div></div>\n    <div class=\"sg-color\"><div class=\"sg-color-swatch\" style=\"background:#94a3b8\"></div><div class=\"sg-color-name\">--an-text-dim</div><div class=\"sg-color-val\">#94a3b8 &mdash; secondary</div></div>\n  </div>\n</section>\n\n<section id=\"typography\" class=\"sg-section\">\n  <h2>Typography</h2>\n  <p class=\"sg-section-desc\">Three font families. Orbitron for display (headings, values, UI chrome). System UI for body text. JetBrains Mono for code and technical values.</p>\n\n  <h3>Fonts</h3>\n  <div class=\"sg-type-row\">\n    <div class=\"sg-type-label\">Display</div>\n    <div class=\"sg-type-specimen\" style=\"font-family:Orbitron,sans-serif;font-size:20px;letter-spacing:1px\">ANYONE PROTOCOL</div>\n    <div class=\"sg-type-val\">--an-font-display</div>\n  </div>\n  <div class=\"sg-type-row\">\n    <div class=\"sg-type-label\">Body</div>\n    <div class=\"sg-type-specimen\" style=\"font-family:system-ui;font-size:14px\">The quick brown fox jumps over the lazy dog.</div>\n    <div class=\"sg-type-val\">--an-font-body</div>\n  </div>\n  <div class=\"sg-type-row\">\n    <div class=\"sg-type-label\">Mono</div>\n    <div class=\"sg-type-specimen\" style=\"font-family:JetBrains Mono,monospace;font-size:13px\">const _path = new URL(request.url).pathname;</div>\n    <div class=\"sg-type-val\">--an-font-mono</div>\n  </div>\n\n  <h3>Scale</h3>\n  <div class=\"sg-type-row\"><div class=\"sg-type-label\">xs &mdash; 9px</div><div class=\"sg-type-specimen\" style=\"font-size:9px\">Tiny label text &mdash; tickers, tags</div><div class=\"sg-type-val\">--an-text-xs</div></div>\n  <div class=\"sg-type-row\"><div class=\"sg-type-label\">sm &mdash; 11px</div><div class=\"sg-type-specimen\" style=\"font-size:11px\">Small body text &mdash; widgets, rows</div><div class=\"sg-type-val\">--an-text-sm</div></div>\n  <div class=\"sg-type-row\"><div class=\"sg-type-label\">md &mdash; 13px</div><div class=\"sg-type-specimen\" style=\"font-size:13px\">Standard UI text &mdash; buttons, values</div><div class=\"sg-type-val\">--an-text-md</div></div>\n  <div class=\"sg-type-row\"><div class=\"sg-type-label\">lg &mdash; 16px</div><div class=\"sg-type-specimen\" style=\"font-size:16px\">Larger emphasis text</div><div class=\"sg-type-val\">--an-text-lg</div></div>\n  <div class=\"sg-type-row\"><div class=\"sg-type-label\">xl &mdash; 20px</div><div class=\"sg-type-specimen\" style=\"font-size:20px\">Section headings</div><div class=\"sg-type-val\">--an-text-xl</div></div>\n  <div class=\"sg-type-row\"><div class=\"sg-type-label\">2xl &mdash; 28px</div><div class=\"sg-type-specimen\" style=\"font-size:28px\">Page titles</div><div class=\"sg-type-val\">--an-text-2xl</div></div>\n  <div class=\"sg-type-row\"><div class=\"sg-type-label\">3xl &mdash; 36px</div><div class=\"sg-type-specimen\" style=\"font-size:36px;font-family:Orbitron;font-weight:800\">HERO</div><div class=\"sg-type-val\">--an-text-3xl</div></div>\n</section>\n\n<section id=\"spacing\" class=\"sg-section\">\n  <h2>Spacing</h2>\n  <p class=\"sg-section-desc\">4px-based scale. Use for padding, margins, and gaps. Always prefer tokens over arbitrary values.</p>\n  <div class=\"sg-spacing-row\"><div class=\"sg-spacing-label\">--an-space-1</div><div class=\"sg-spacing-bar\" style=\"width:4px\"></div><div class=\"sg-spacing-val\">4px</div></div>\n  <div class=\"sg-spacing-row\"><div class=\"sg-spacing-label\">--an-space-2</div><div class=\"sg-spacing-bar\" style=\"width:8px\"></div><div class=\"sg-spacing-val\">8px</div></div>\n  <div class=\"sg-spacing-row\"><div class=\"sg-spacing-label\">--an-space-3</div><div class=\"sg-spacing-bar\" style=\"width:12px\"></div><div class=\"sg-spacing-val\">12px</div></div>\n  <div class=\"sg-spacing-row\"><div class=\"sg-spacing-label\">--an-space-4</div><div class=\"sg-spacing-bar\" style=\"width:16px\"></div><div class=\"sg-spacing-val\">16px</div></div>\n  <div class=\"sg-spacing-row\"><div class=\"sg-spacing-label\">--an-space-5</div><div class=\"sg-spacing-bar\" style=\"width:20px\"></div><div class=\"sg-spacing-val\">20px</div></div>\n  <div class=\"sg-spacing-row\"><div class=\"sg-spacing-label\">--an-space-6</div><div class=\"sg-spacing-bar\" style=\"width:24px\"></div><div class=\"sg-spacing-val\">24px</div></div>\n  <div class=\"sg-spacing-row\"><div class=\"sg-spacing-label\">--an-space-8</div><div class=\"sg-spacing-bar\" style=\"width:32px\"></div><div class=\"sg-spacing-val\">32px</div></div>\n  <div class=\"sg-spacing-row\"><div class=\"sg-spacing-label\">--an-space-10</div><div class=\"sg-spacing-bar\" style=\"width:40px\"></div><div class=\"sg-spacing-val\">40px</div></div>\n</section>\n\n<section id=\"radius\" class=\"sg-section\">\n  <h2>Border Radius</h2>\n  <p class=\"sg-section-desc\">Five levels. Use sm for tight UI, md as default, lg for cards, xl for modals, pill for badges.</p>\n  <div class=\"sg-radius-grid\">\n    <div class=\"sg-radius-box\" style=\"border-radius:4px\"><div class=\"sg-radius-name\">SM</div><div class=\"sg-radius-val\">4px</div></div>\n    <div class=\"sg-radius-box\" style=\"border-radius:8px\"><div class=\"sg-radius-name\">MD</div><div class=\"sg-radius-val\">8px &mdash; default</div></div>\n    <div class=\"sg-radius-box\" style=\"border-radius:12px\"><div class=\"sg-radius-name\">LG</div><div class=\"sg-radius-val\">12px</div></div>\n    <div class=\"sg-radius-box\" style=\"border-radius:16px\"><div class=\"sg-radius-name\">XL</div><div class=\"sg-radius-val\">16px</div></div>\n    <div class=\"sg-radius-box\" style=\"border-radius:999px\"><div class=\"sg-radius-name\">PILL</div><div class=\"sg-radius-val\">full round</div></div>\n  </div>\n</section>\n\n<section id=\"buttons\" class=\"sg-section\">\n  <h2>Buttons</h2>\n  <p class=\"sg-section-desc\">All buttons use Orbitron font, uppercase, with 1.5px letter-spacing. Primary teal for main actions, orange for Bitcoin features, red for destructive actions, ghost for tertiary.</p>\n\n  <h3>Variants</h3>\n  <div class=\"sg-btn-row\">\n    <button class=\"sg-btn\">Primary</button>\n    <button class=\"sg-btn sg-btn-orange\">&#8383; Bitcoin</button>\n    <button class=\"sg-btn sg-btn-danger\">Danger</button>\n    <button class=\"sg-btn sg-btn-ghost\">Ghost</button>\n  </div>\n\n  <h3>Specification</h3>\n  <div class=\"sg-code\">\n<span class=\"comment\">/* Primary button */</span>\n<span class=\"keyword\">padding</span>: 10px 18px;\n<span class=\"keyword\">border-radius</span>: <span style=\"color:var(--an-teal)\">var(--an-radius-md)</span>;\n<span class=\"keyword\">font-family</span>: <span style=\"color:var(--an-teal)\">var(--an-font-display)</span>;\n<span class=\"keyword\">font-size</span>: 11px;\n<span class=\"keyword\">font-weight</span>: 700;\n<span class=\"keyword\">letter-spacing</span>: 1.5px;\n<span class=\"keyword\">text-transform</span>: uppercase;\n<span class=\"keyword\">background</span>: <span style=\"color:var(--an-teal)\">var(--an-teal-muted)</span>;\n<span class=\"keyword\">border</span>: 1px solid <span style=\"color:var(--an-teal)\">var(--an-teal-border)</span>;\n<span class=\"keyword\">color</span>: <span style=\"color:var(--an-teal)\">var(--an-teal-text)</span>;\n<span class=\"keyword\">transition</span>: all .15s;\n  </div>\n</section>\n\n<section id=\"widgets\" class=\"sg-section\">\n  <h2>Sidebar Widgets</h2>\n  <p class=\"sg-section-desc\">Info panels shown in the left sidebar. Two flavors: Anyone (teal) and Bitcoin (orange). All use grid-based rows with labels left, values right.</p>\n  <div class=\"sg-widget-grid\">\n    <div class=\"sg-widget\">\n      <h4>Network Stats</h4>\n      <div class=\"sg-widget-row\"><span>Active relays</span><b>7,602</b></div>\n      <div class=\"sg-widget-row\"><span>Bandwidth</span><b>76.7 GB/s</b></div>\n      <div class=\"sg-widget-row\"><span>Health score</span><b>78 / 100</b></div>\n    </div>\n    <div class=\"sg-widget sg-widget-orange\">\n      <h4>&#8383; Bitcoin Network</h4>\n      <div class=\"sg-widget-row\"><span>Total nodes</span><b>20,847</b></div>\n      <div class=\"sg-widget-row\"><span>Showing on map</span><b>56</b></div>\n      <div class=\"sg-widget-row\"><span>Both</span><b>36 / 42</b></div>\n    </div>\n  </div>\n</section>\n\n<section id=\"markers\" class=\"sg-section\">\n  <h2>Map Markers</h2>\n  <p class=\"sg-section-desc\">SVG shapes for the map. Each relay type has a distinct color. Bitcoin nodes use a distinct shape (hexagon) to differentiate from Anyone relays.</p>\n  <div class=\"sg-markers-grid\">\n    <div class=\"sg-marker-cell\">\n      <svg width=\"40\" height=\"40\" viewBox=\"-20 -20 40 40\"><polygon points=\"0,-12 12,0 0,12 -12,0\" fill=\"#ff6b6b\" stroke=\"#fff\" stroke-width=\"0.5\" opacity=\"0.9\"/></svg>\n      <div class=\"sg-marker-type\">Exit Relay</div>\n      <div class=\"sg-marker-label\">diamond &mdash; red</div>\n    </div>\n    <div class=\"sg-marker-cell\">\n      <svg width=\"40\" height=\"40\" viewBox=\"-20 -20 40 40\"><polygon points=\"0,-12 12,0 0,12 -12,0\" fill=\"#a78bfa\" stroke=\"#fff\" stroke-width=\"0.5\" opacity=\"0.9\"/></svg>\n      <div class=\"sg-marker-type\">Guard Relay</div>\n      <div class=\"sg-marker-label\">diamond &mdash; purple</div>\n    </div>\n    <div class=\"sg-marker-cell\">\n      <svg width=\"40\" height=\"40\" viewBox=\"-20 -20 40 40\"><circle cx=\"0\" cy=\"0\" r=\"10\" fill=\"#2dd4bf\" stroke=\"#fff\" stroke-width=\"0.5\" opacity=\"0.9\"/></svg>\n      <div class=\"sg-marker-type\">Middle Relay</div>\n      <div class=\"sg-marker-label\">circle &mdash; teal</div>\n    </div>\n    <div class=\"sg-marker-cell\">\n      <svg width=\"40\" height=\"40\" viewBox=\"-20 -20 40 40\"><polygon points=\"0,-12 12,0 0,12 -12,0\" fill=\"#fbbf24\" stroke=\"#fff\" stroke-width=\"0.5\" opacity=\"0.9\"/></svg>\n      <div class=\"sg-marker-type\">Hardware</div>\n      <div class=\"sg-marker-label\">diamond &mdash; amber</div>\n    </div>\n    <div class=\"sg-marker-cell\">\n      <svg width=\"40\" height=\"40\" viewBox=\"-20 -20 40 40\"><polygon points=\"0,-10 8.7,-5 8.7,5 0,10 -8.7,5 -8.7,-5\" fill=\"#f7931a\" stroke=\"#fff\" stroke-width=\"0.5\" opacity=\"0.9\"/></svg>\n      <div class=\"sg-marker-type\">Bitcoin Node</div>\n      <div class=\"sg-marker-label\">hexagon &mdash; orange</div>\n    </div>\n  </div>\n</section>\n\n<section id=\"usage\" class=\"sg-section\">\n  <h2>Usage Guidelines</h2>\n  <p class=\"sg-section-desc\">Principles to maintain consistency when adding new features.</p>\n\n  <h3>Always</h3>\n  <ul style=\"color:var(--an-text-dim);line-height:1.9;padding-left:20px;font-size:13px\">\n    <li>Use design tokens (<code style=\"color:var(--an-teal-text);font-family:var(--an-font-mono);font-size:12px\">var(--an-*)</code>) instead of hard-coded values</li>\n    <li>Use Orbitron for UI chrome (buttons, headers, stat values)</li>\n    <li>Use system-ui for prose and body text</li>\n    <li>Uppercase + letter-spacing for labels and buttons</li>\n    <li>Tabular numerals for stat values (<code style=\"color:var(--an-teal-text);font-family:var(--an-font-mono);font-size:12px\">font-variant-numeric: tabular-nums</code>)</li>\n    <li>44px minimum touch target for all interactive elements</li>\n    <li>Keyboard shortcut hints in button titles (<code style=\"color:var(--an-teal-text);font-family:var(--an-font-mono);font-size:12px\">title=\"Toggle (B)\"</code>)</li>\n  </ul>\n\n  <h3>Never</h3>\n  <ul style=\"color:var(--an-text-dim);line-height:1.9;padding-left:20px;font-size:13px\">\n    <li>Hard-code colors &mdash; always use tokens</li>\n    <li>Use magic numbers for spacing &mdash; use <code style=\"color:var(--an-teal-text);font-family:var(--an-font-mono);font-size:12px\">--an-space-*</code></li>\n    <li>Use multiple fonts within a single component</li>\n    <li>Use emoji as core UI icons (SVG only)</li>\n    <li>Register duplicate event handlers (inline <code style=\"color:var(--an-teal-text);font-family:var(--an-font-mono);font-size:12px\">onclick</code> OR <code style=\"color:var(--an-teal-text);font-family:var(--an-font-mono);font-size:12px\">addEventListener</code>, not both)</li>\n  </ul>\n</section>\n\n<footer style=\"text-align:center;padding:var(--an-space-8) 0;color:var(--an-text-muted);font-size:var(--an-text-sm)\">\n  AnyoneMap v1.2 &mdash; <a style=\"color:var(--an-teal-text);text-decoration:none\" href=\"/\">Back to map</a>\n</footer>\n</div>\n</body>\n</html>\n";   return new Response(sgHtml, {     headers: {       'Content-Type': 'text/html; charset=utf-8',       'Cache-Control': 'public, max-age=300',       'X-Content-Type-Options': 'nosniff',       'X-Frame-Options': 'DENY',       /* v396: see rationale in the /bitcoin Response above. Same hardening, same reasoning \\u2014 /style-guide is also a static page with no privileged-feature use and identical external dependency footprint (Google Fonts only). */       'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), payment=()',       'Referrer-Policy': 'strict-origin-when-cross-origin',       'Content-Security-Policy': "default-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; script-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"     }   }); } if (_path === '/api/bitnodes') {
      /* v382: per-IP rate limit migrated to Cloudflare Rate Limiting binding
       * (RL_BITNODES, 60/60s). The v378 KV-based limiter was bypassable under
       * concurrency for the same reason as the analytics one — see the comment
       * on the analytics block at the top of this fetch handler. Atomic edge
       * limiter eliminates the race and the KV read on every request. Separate
       * binding from analytics so the limits don't share quota across endpoints. */
      if (env.RL_BITNODES) {
        const _btIp = request.headers.get('CF-Connecting-IP') || 'unknown';
        const { success: _btOk } = await env.RL_BITNODES.limit({ key: _btIp }).catch(() => ({ success: true }));
        if (!_btOk) {
          return new Response(JSON.stringify({ error: 'Rate limit reached' }), { status: 429, headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*', 'X-Content-Type-Options': 'nosniff' } });
        }
      }
      /* v377: read from KV-cached snapshot instead of fetching bitnodes.io on every */
      /* request. The upstream has a 10-requests-per-day-per-IP limit which is */
      /* structurally hostile to a serverless edge platform with thousands of */
      /* outbound IPs \u2014 calls were near-universally returning 429, so users always */
      /* saw the static fallback. A daily cron now populates the snapshot KV with */
      /* a fresh sample (see scheduled() at the bottom of this module). Static */
      /* fallback survives as a true fallback for the first-deploy gap and KV outages. */
      /* v386: prefer SNAPSHOT_KV (new name reflecting actual role), fall back to */
      /* RL_KV (v300\u2013v385 name, kept as alias during the dashboard rename rollout). */
      /* Once SNAPSHOT_KV is bound in the dashboard and verified, drop the RL_KV */
      /* fallback in a future cleanup version. */
      try {
        const _snapKv = env.SNAPSHOT_KV ?? env.RL_KV;
        if (_snapKv) {
          /* v387: read as text, not as JSON. The cron writes JSON.stringify(snapshot) */
          /* to KV (a string). v386 and earlier read this back with {type:'json'}, */
          /* which parses the bytes into an object, then re-serialized the object */
          /* back to a string for the Response body. On a ~50KB snapshot that's */
          /* 1-3ms of CPU wasted on every cache miss. v387 reads the bytes as a */
          /* string and hands them straight to the Response \u2014 zero serialization */
          /* work on the read path. The cheap structural check below catches the */
          /* one case we care about (KV returned empty/truncated/non-JSON) without */
          /* having to actually parse. The cron's empty-write guard at the */
          /* scheduled() bottom prevents storing pathological snapshots in the */
          /* first place, so we trust what KV gives us beyond the prefix check. */
          const _btSnap = await _snapKv.get('bitnodes-snapshot:latest').catch(() => null);
          /* Cheap structural sanity check, no parsing. A valid snapshot is */
          /* JSON.stringify of {total, source, sample: [\u2026]} \u2014 always starts with */
          /* '{' and is at minimum a few hundred bytes (header fields + at least */
          /* one sample). Anything else (null, '', a stray byte, an error blob) */
          /* falls through to the static fallback. */
          if (_btSnap && _btSnap.length > 100 && _btSnap.charCodeAt(0) === 123) {
            /* v383: cache-control aligned to cron interval. v382 used max-age=600 */
            /* but the cron runs every 30 min (1800s), so an edge cache populated  */
            /* just after a cron tick was correct for 10 minutes and then stale for*/
            /* 20 minutes with no signal to refresh. max-age=1800 covers exactly   */
            /* one cron interval; stale-while-revalidate=1800 lets edges keep      */
            /* serving the old response (capped at 2 cron intervals = 1 hour total)*/
            /* while a background fetch refreshes from origin. Worst-case          */
            /* staleness: 60 min in pathological cases (back-to-back cron failures)*/
            /* vs unbounded with the v382 setting. Keep this in sync with the cron */
            /* trigger schedule \u2014 if you change the cron interval, change both numbers. */
            /* v387: _btSnap is already a JSON string from KV. No re-serialize. */
            return new Response(_btSnap, {
              headers: { 'Content-Type': 'application/json', 'Cache-Control': 'public, max-age=1800, stale-while-revalidate=1800', 'Access-Control-Allow-Origin': '*', 'X-Content-Type-Options': 'nosniff' }
            });
          }
        }
        /* No KV snapshot yet (first deploy, or cron hasn't run). Serve fallback. */
        /* The v376 client-side warning fires on source:'fallback-static' \u2014 users */
        /* will see the stale-data banner until the next cron run populates KV. */
        const fallback = {
          total: 20847,
          source: 'fallback-static',
          note: 'Live bitnodes.io snapshot not yet cached; showing representative sample',
          sample: [
            {lat:52.5,lon:13.4,cc:'DE',city:'Berlin',org:'Hetzner'},
            {lat:50.1,lon:8.7,cc:'DE',city:'Frankfurt',org:'OVH'},
            {lat:48.8,lon:2.3,cc:'FR',city:'Paris',org:'Online SAS'},
            {lat:51.5,lon:-0.1,cc:'GB',city:'London',org:'Amazon AWS'},
            {lat:52.4,lon:4.9,cc:'NL',city:'Amsterdam',org:'LeaseWeb'},
            {lat:60.2,lon:24.9,cc:'FI',city:'Helsinki',org:'Hetzner'},
            {lat:59.3,lon:18.1,cc:'SE',city:'Stockholm',org:'Bahnhof'},
            {lat:55.7,lon:12.6,cc:'DK',city:'Copenhagen',org:'Bahnhof'},
            {lat:47.4,lon:8.5,cc:'CH',city:'Zurich',org:'Init7'},
            {lat:46.2,lon:6.1,cc:'CH',city:'Geneva',org:'Init7'},
            {lat:45.5,lon:9.2,cc:'IT',city:'Milan',org:'Aruba'},
            {lat:40.4,lon:-3.7,cc:'ES',city:'Madrid',org:'Telefonica'},
            {lat:38.7,lon:-9.1,cc:'PT',city:'Lisbon',org:'NOS'},
            {lat:50.1,lon:14.4,cc:'CZ',city:'Prague',org:'CzechSpace'},
            {lat:50.0,lon:19.9,cc:'PL',city:'Krakow',org:'OVH'},
            {lat:47.5,lon:19.0,cc:'HU',city:'Budapest',org:'Magyar Telekom'},
            {lat:44.4,lon:26.1,cc:'RO',city:'Bucharest',org:'M247'},
            {lat:42.7,lon:23.3,cc:'BG',city:'Sofia',org:'A1 Bulgaria'},
            {lat:37.9,lon:23.7,cc:'GR',city:'Athens',org:'OTE'},
            {lat:41.0,lon:28.9,cc:'TR',city:'Istanbul',org:'Turkcell'},
            {lat:55.7,lon:37.6,cc:'RU',city:'Moscow',org:'Beget'},
            {lat:40.7,lon:-74.0,cc:'US',city:'New York',org:'DigitalOcean'},
            {lat:39.0,lon:-77.5,cc:'US',city:'Ashburn',org:'Amazon AWS'},
            {lat:41.9,lon:-87.6,cc:'US',city:'Chicago',org:'Linode'},
            {lat:37.4,lon:-122.1,cc:'US',city:'Mountain View',org:'Google'},
            {lat:34.0,lon:-118.2,cc:'US',city:'Los Angeles',org:'OVH'},
            {lat:47.6,lon:-122.3,cc:'US',city:'Seattle',org:'Amazon AWS'},
            {lat:32.7,lon:-96.8,cc:'US',city:'Dallas',org:'Hivelocity'},
            {lat:25.7,lon:-80.2,cc:'US',city:'Miami',org:'Hivelocity'},
            {lat:43.6,lon:-79.4,cc:'CA',city:'Toronto',org:'OVH'},
            {lat:45.5,lon:-73.6,cc:'CA',city:'Montreal',org:'OVH'},
            {lat:49.3,lon:-123.1,cc:'CA',city:'Vancouver',org:'Telus'},
            {lat:35.7,lon:139.7,cc:'JP',city:'Tokyo',org:'Sakura'},
            {lat:34.7,lon:135.5,cc:'JP',city:'Osaka',org:'Sakura'},
            {lat:37.5,lon:127.0,cc:'KR',city:'Seoul',org:'KT'},
            {lat:1.3,lon:103.8,cc:'SG',city:'Singapore',org:'DigitalOcean'},
            {lat:22.3,lon:114.2,cc:'HK',city:'Hong Kong',org:'PCCW'},
            {lat:25.0,lon:121.5,cc:'TW',city:'Taipei',org:'Chunghwa'},
            {lat:13.7,lon:100.5,cc:'TH',city:'Bangkok',org:'TOT'},
            {lat:14.6,lon:121.0,cc:'PH',city:'Manila',org:'PLDT'},
            {lat:-6.2,lon:106.8,cc:'ID',city:'Jakarta',org:'Telkom'},
            {lat:3.1,lon:101.7,cc:'MY',city:'Kuala Lumpur',org:'TM'},
            {lat:-33.9,lon:151.2,cc:'AU',city:'Sydney',org:'Amazon AWS'},
            {lat:-37.8,lon:144.9,cc:'AU',city:'Melbourne',org:'NextDC'},
            {lat:-36.8,lon:174.7,cc:'NZ',city:'Auckland',org:'Vocus'},
            {lat:-23.5,lon:-46.6,cc:'BR',city:'Sao Paulo',org:'UOL'},
            {lat:-34.6,lon:-58.4,cc:'AR',city:'Buenos Aires',org:'Telefonica'},
            {lat:-33.4,lon:-70.6,cc:'CL',city:'Santiago',org:'GTD'},
            {lat:4.6,lon:-74.0,cc:'CO',city:'Bogota',org:'Claro'},
            {lat:19.4,lon:-99.1,cc:'MX',city:'Mexico City',org:'Telmex'},
            {lat:-26.2,lon:28.0,cc:'ZA',city:'Johannesburg',org:'Vox'},
            {lat:30.0,lon:31.2,cc:'EG',city:'Cairo',org:'TE Data'},
            {lat:25.2,lon:55.3,cc:'AE',city:'Dubai',org:'Etisalat'},
            {lat:32.1,lon:34.8,cc:'IL',city:'Tel Aviv',org:'Bezeq'},
            {lat:19.1,lon:72.9,cc:'IN',city:'Mumbai',org:'Reliance Jio'},
            {lat:28.6,lon:77.2,cc:'IN',city:'New Delhi',org:'Airtel'}
          ]
        };
        return new Response(JSON.stringify(fallback), {
          /* v383: drop fallback cache from 300s to 30s + must-revalidate. The     */
          /* fallback path means KV is empty or returned a broken snapshot \u2014 a    */
          /* transient state we want users to escape from as soon as the cron     */
          /* recovers, not 5 minutes later. must-revalidate tells caches not to  */
          /* serve this past max-age even under network failure. This also       */
          /* makes the debugging story sane: when KV is in a bad state, hitting */
          /* the endpoint repeatedly during diagnosis reflects the current      */
          /* server-side reality instead of a 5-minute-old edge cached fallback. */
          headers: { 'Content-Type': 'application/json', 'Cache-Control': 'public, max-age=30, must-revalidate', 'Access-Control-Allow-Origin': '*', 'X-Content-Type-Options': 'nosniff' }
        });
      } catch (e) {
        /* v383: explicit no-store. Default cacheability for 5xx responses on    */
        /* Cloudflare is "no" in most cases, but being explicit prevents any    */
        /* intermediate proxy or browser cache from holding onto an error.     */
        return new Response(JSON.stringify({error: e.message, source: 'exception'}), {status: 500, headers: {'Content-Type': 'application/json', 'Cache-Control': 'no-store', 'Access-Control-Allow-Origin': '*', 'X-Content-Type-Options': 'nosniff'}});
      }
    } /* ── IP/country/Tor signals. v392: clientIP removed; was previously injected into HTML body as a meta tag, which leaked the visitor IP into intermediate proxies and defeated edge caching. CF-Connecting-IP is still available via request.headers.get() for any server-side use that doesn't echo it back to the wire. ── */ const cfCountry = request.headers.get("CF-IPCountry") || "XX"; const isTor = request.headers.get("CF-IPCountry") === "T1"; /* ═══════════════════════════════════════════════════════════════════════\n * AnyoneMap v1.2 — AnyChat Operators Lounge\n * Single-file Cloudflare Worker (HTML + CSS + JS)\n *\n * TABLE OF CONTENTS\n * ═════════════════\n * CSS SECTIONS (~160KB)\n *   [L001] Map CSS — Globe, zones, nodes, signals\n *   [L002] Relay Browser — Search, filters, relay cards\n *   [L003] Header — Logo, clock, action buttons\n *   [L004] Left Sidebar — Network stats, zone stats, health\n *   [L005] Foundation Beacon — .anyone domains overlay\n *   [L006] AnyChat Panel — Shell, theme variables\n *   [L007] AnyChat Light Theme — Premium UX overhaul\n *   [L008] Command Palette — Ctrl+K search\n *   [L009] Network Comparison — Anyone vs Tor\n *   [L010] AnyChat OP Style — Contacts, profile, status\n *   [L011] Chat Column — Messages, bubbles, reactions\n *   [L012] Input Area — Telegram-style input, send button\n *   [L013] Quest System — Cards, progress, badges\n *   [L014] Game Cards — Arcade, trivia, leaderboard\n *   [L015] Responsive — Mobile breakpoints\n *\n * JS SECTIONS — Script #1 (~530KB)\n *   [J001] State & Config — AC namespace, constants\n *   [J002] Auth — Login, register, wallet connect\n *   [J003] WebSocket — Connect, reconnect, message handlers\n *   [J004] Chat Core — Send, receive, poll, typing\n *   [J005] Moderation — Auto-reply, scam detection, reports\n *   [J006] UI Rendering — Messages, contacts, profiles\n *   [J007] Reactions — Emoji reactions on messages\n *   [J008] Threading — Quote blocks, scroll-to-quoted\n *   [J009] Slash Commands — Autocomplete, /help, /trivia\n *   [J010] AnyClip Chat — Query classification, memory\n *   [J011] Quests — Progress tracking, XP, badges\n *   [J012] Games — Trivia, country quiz, RPS, leaderboard\n *   [J013] Social — Badge wall, relay of the day\n *   [J014] Notifications — Browser push, permission\n *   [J015] Keyboard Shortcuts — Escape, Ctrl+/, Ctrl+F\n *   [J016] Connection Indicator — WS latency tracking\n *\n * JS SECTIONS — Script #2 (~62KB)\n *   [J020] AnyClip Brain — System prompt builder, IIFE\n *\n * HTML MARKUP (~100KB)\n *   [H001] Head — Meta, fonts, favicon\n *   [H002] Header Bar — Logo, clock, buttons\n *   [H003] Map Container — SVG globe, nodes layer\n *   [H004] Left Sidebar — Stats panels\n *   [H005] AnyChat Panel — Auth, chat, quests, games\n *   [H006] Overlays — Relay browser, health, comparison\n *   [H007] Foundation Beacon — .anyone domains\n * ═════════════════════════════════════════════════════════════════════════\n */ 
/* v373: removed the CHAT BACKEND 410-gone stub. Tail logs were clean — no client
 * is still calling /api/chat-* on the map worker; all chat traffic goes directly
 * to anyclip-proxy.anyonerelaysmap.workers.dev. Also removed:
 *   - const _chatHeaders   (only consumer was the deleted stub)
 *   - the redundant `const _url = new URL(request.url); const _path = _url.pathname`
 *     pair down here (both are now hoisted at the top of the fetch handler)
 *   - the OPTIONS short-circuit using _chatHeaders (the only origin doing CORS
 *     preflight against this worker was the now-removed chat block; everything
 *     else is same-origin or handled by route-specific headers).
 */


// ═══ PWA MANIFEST & ICONS ═══
if (_path === "/manifest.json") {
  return new Response(`{
  "name": "AnyoneMap — Global Relay Network",
  "short_name": "AnyoneMap",
  "description": "Real-time visualization of the Anyone Protocol relay network. Monitor 7,500+ relays, health scores, and operator stats.",
  "start_url": "/",
  "display": "standalone",
  "orientation": "any",
  "background_color": "#020b12",
  "theme_color": "#2dd4bf",
  "categories": ["utilities", "productivity", "security"],
  "icons": [
    { "src": "/icon-192.svg", "sizes": "192x192", "type": "image/svg+xml", "purpose": "any maskable" },
    { "src": "/icon-512.svg", "sizes": "512x512", "type": "image/svg+xml", "purpose": "any maskable" }
  ],
  "screenshots": [],
  "related_applications": [],
  "prefer_related_applications": false
}`, {
    headers: { "Content-Type": "application/manifest+json", "Access-Control-Allow-Origin": "*", "Cache-Control": "public, max-age=86400", "X-Content-Type-Options": "nosniff" }
  });
}
if (_path === "/icon-192.svg" || _path === "/icon-512.svg") {
  return new Response(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512">
<rect width="512" height="512" rx="96" fill="#020b12"/>
<g transform="translate(256,256)">
<polygon points="0,-140 121,-70 121,70 0,140 -121,70 -121,-70" fill="none" stroke="#2dd4bf" stroke-width="8"/>
<polygon points="0,-80 69,-40 69,40 0,80 -69,40 -69,-40" fill="none" stroke="#2dd4bf" stroke-width="4" opacity=".4"/>
<circle r="20" fill="#2dd4bf"/>
<circle r="140" fill="none" stroke="#2dd4bf" stroke-width="2" opacity=".15"/>
</g>
<text x="256" y="390" text-anchor="middle" fill="#2dd4bf" font-family="system-ui" font-size="48" font-weight="800" letter-spacing="4">ANYONE</text>
</svg>`, {
    headers: { "Content-Type": "image/svg+xml", "Cache-Control": "public, max-age=604800", "X-Content-Type-Options": "nosniff" }
  });
}


if (_path === "/sw.js") {
  /* v385: cache name derived from WORKER_VERSION (top of file) instead of */
  /* a hardcoded literal. v374 introduced precaching but the cache key was */
  /* a constant string never bumped across deploys — bumping WORKER_VERSION */
  /* once per release is now the only required step to invalidate stale */
  /* clients. The SW lifecycle handles the rest: when the browser fetches */
  /* /sw.js on next navigation and sees byte-changed source, it triggers */
  /* install (which precaches against the new key) and activate (which */
  /* deletes any cache key not matching the current CACHE). */
  /* v374: SW now actually uses the CACHE constant. Previous version declared
   * `const CACHE` but only deleted caches and passed navigations through —
   * the whole machinery was dead. Now it precaches the static assets on
   * install (manifest, icons) so PWA installs feel snappier and the icons
   * load instantly on repeat visits. Versioned cache name forces a clean
   * cache rebuild whenever the worker is redeployed. */
  return new Response(`const CACHE='anyonemap-${WORKER_VERSION}';const STATIC=['/manifest.json','/icon-192.svg','/icon-512.svg','/robots.txt','/design-tokens.css'];self.addEventListener('install',e=>{self.skipWaiting();e.waitUntil(caches.open(CACHE).then(c=>c.addAll(STATIC)).catch(()=>{}))});self.addEventListener('activate',e=>{self.clients.claim();e.waitUntil(caches.keys().then(ks=>Promise.all(ks.filter(k=>k!==CACHE).map(k=>caches.delete(k)))))});self.addEventListener('fetch',e=>{const r=e.request;if(r.method!=='GET'||r.url.includes('/api/'))return;if(r.mode==='navigate'||r.destination==='document'){e.respondWith(fetch(r,{cache:'no-store'}));return}const u=new URL(r.url);if(STATIC.includes(u.pathname)){e.respondWith(caches.open(CACHE).then(c=>c.match(r).then(m=>m||fetch(r).then(res=>{if(res&&res.ok)c.put(r,res.clone());return res}))));return}});`, {
    headers: { "Content-Type": "application/javascript", "Cache-Control": "no-cache", "X-Content-Type-Options": "nosniff" }
  });
}


if (_path === "/design-tokens.css") {
  /* v375: shared design tokens for /, /bitcoin, /style-guide. Single source of truth.
   * SW precaches this so PWA users pay the extra HTTP request at most once.
   * 1yr immutable cache; bump worker version to invalidate. */
  return new Response(":root{--an-teal:#2dd4bf;--an-teal-text:#5eead4;--an-teal-bright:#99f6e4;--an-teal-muted:rgba(45,212,191,.1);--an-teal-border:rgba(45,212,191,.2);--an-green:#34d399;--an-red:#f87171;--an-amber:#fbbf24;--an-coral:#ff6b6b;--an-purple:#a78bfa;--an-dark:#020b12;--an-surface:#0a1628;--an-surface-hover:#0f1f36;--an-overlay:rgba(2,11,18,.85);--an-text:#e4e4e9;--an-text-dim:#94a3b8;--an-text-muted:rgba(228,228,233,.4);--an-font-body:system-ui,-apple-system,BlinkMacSystemFont,sans-serif;--an-font-display:'Orbitron',system-ui,sans-serif;--an-font-display-light:'Inter Tight','Inter',system-ui,sans-serif;--an-font-body-light:'Inter',system-ui,-apple-system,sans-serif;--an-font-mono:'JetBrains Mono','SF Mono','Fira Code',monospace;--an-text-xs:9px;--an-text-sm:11px;--an-text-md:13px;--an-text-lg:16px;--an-text-xl:20px;--an-text-2xl:28px;--an-text-3xl:36px;--an-space-1:4px;--an-space-2:8px;--an-space-3:12px;--an-space-4:16px;--an-space-5:20px;--an-space-6:24px;--an-space-8:32px;--an-space-10:40px;--an-radius-sm:4px;--an-radius-md:8px;--an-radius-lg:12px;--an-radius-xl:16px;--an-radius-pill:999px;--an-shadow-sm:0 1px 3px rgba(0,0,0,.3);--an-shadow-md:0 4px 12px rgba(0,0,0,.4);--an-shadow-lg:0 8px 24px rgba(0,0,0,.5);--an-shadow-glow:0 0 12px rgba(45,212,191,.3);--an-ease:cubic-bezier(.4,0,.2,1);--an-duration-fast:150ms;--an-duration-normal:250ms;--an-duration-slow:400ms;--an-z-base:1;--an-z-sidebar:500;--an-z-panel:1000;--an-z-modal:5000;--an-z-chat:8500;--an-z-overlay:99999;--an-z-max:100000;}", {
    headers: {
      "Content-Type": "text/css; charset=utf-8",
      "Cache-Control": "public, max-age=31536000, immutable",
      "X-Content-Type-Options": "nosniff",
      "Access-Control-Allow-Origin": "*"
    }
  });
}



const html = "__INDEX_HTML_PLACEHOLDER__"; /* v300/v392: HTML-attribute escape for the meta tags. v300 added this because clientIP (then injected as ac-client-ip) fell back to client-controlled X-Forwarded-For, which would let an attacker break out of the attribute. v392 removed the IP meta tag entirely (see _ipMeta comment below) so the original threat is gone, but the escape stays for defense-in-depth on cfCountry/isTor: they're Cloudflare-trusted today, but a future code change that derives them differently shouldn't be able to silently introduce an XSS. Cheap insurance. */ const _attrEsc = function(s){ return String(s == null ? '' : s).replace(/[&<>"']/g, function(c){ return ({ '&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#39;' })[c]; }); }; /* v392: ac-client-ip meta tag removed. Echoing the client's IP back into the HTML body was a privacy regression: it bled into intermediate proxies, defeated edge caching (Vary: CF-Connecting-IP was never set), and exposed the IP to any script running on the page including third-party CDN-loaded libraries. The only client-side consumer was the abuse-report POST body, which is unnecessary — the receiving worker (anyclip-proxy/api/chat-abuse-report) already knows the reporter's IP from its own CF-Connecting-IP header. Server-side enrichment is both more correct (client can't spoof it) and more private (never enters HTML). country and isTor stay: country is a coarse signal the server already sends in many headers, and isTor is a derived boolean — neither uniquely identifies a user. */ const _ipMeta = `<meta name="ac-client-country" content="${_attrEsc(cfCountry)}"><meta name="ac-is-tor" content="${_attrEsc(isTor)}">`; const _html = html.replace("</head>", _ipMeta + "</head>"); return new Response(_html, { headers: { "Content-Type": "text/html; charset=utf-8", /* v391: dedup'd headers object. v300 fixed duplicate Content-Security-Policy (last-key-wins silently dropped the strict allowlist); the same pattern had silently regressed on FIVE other keys. Cache-Control had no-store vs no-cache,no-store,must-revalidate (same intent, kept the stricter). X-Frame-Options, X-Content-Type-Options, Referrer-Policy were duplicates with identical values (harmless but noise). Permissions-Policy was the dangerous one: an early entry granted microphone=(self) for the Operators Lounge voice-message feature; a later entry "camera=(), microphone=(), geolocation=(), payment=()" REVOKED mic. Last-key-wins meant voice-record was silently broken in-browser despite the mic-grant being right there in source. Merged into one policy: mic granted to self, everything else explicitly empty. Add a lint rule for duplicate object keys before this happens a third time. */ "Permissions-Policy": "microphone=(self), camera=(), geolocation=(), payment=()", "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY", "Referrer-Policy": "strict-origin-when-cross-origin", "Content-Security-Policy": "default-src 'self'; worker-src 'self' blob:; script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdnjs.cloudflare.com https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; connect-src 'self' https://*.anyone.tech https://*.partykit.dev wss://*.partykit.dev https://api.allorigins.win https://corsproxy.io https://cdn.jsdelivr.net https://anyclip-proxy.anyonerelaysmap.workers.dev https://api.pinata.cloud https://*.mypinata.cloud https://*.ably.io wss://*.ably.io https://fonts.googleapis.com https://fonts.gstatic.com; img-src 'self' data: blob: https:; media-src 'self' blob:; font-src 'self' https://fonts.gstatic.com; frame-ancestors 'none'; base-uri 'self'; form-action 'self';", "Cache-Control": "no-cache, no-store, must-revalidate" } }); } ,

  /* v377: cron-triggered job that pulls a fresh bitnodes.io snapshot once a day
   * and stores it in KV. Requires a cron trigger in wrangler.toml/jsonc:
   *   [triggers]
   *   crons = ["0 3 * * *"]
   * Runs at 03:00 UTC daily. bitnodes.io enforces 10 requests per day per IP;
   * a single cron run is well within budget and means /api/bitnodes can serve
   * fresh-ish data without ever hitting the upstream from the request path.
   *
   * If this job fails (network blip, upstream rate limit, etc.) the previous
   * KV value persists and the route keeps serving it. Worst case: the snapshot
   * ages until the next successful cron run. If KV is empty entirely, the
   * route falls back to the static array and the client surfaces the v376
   * stale-data warning.
   *
   * The user must manually trigger this job once after first deploy via the
   * Cloudflare dashboard ("Trigger" button on the Cron Triggers page) to
   * populate KV; otherwise users see fallback-static for up to 24 hours after
   * deployment. */
  async scheduled(controller, env, ctx) {
    /* v386: prefer SNAPSHOT_KV, fall back to RL_KV during the dashboard */
    /* rename rollout. Once SNAPSHOT_KV is bound and verified, drop the */
    /* RL_KV alias in a future cleanup version. The log message names both */
    /* so debuggers know to check either binding. */
    const _snapKv = env.SNAPSHOT_KV ?? env.RL_KV;
    if (!_snapKv) {
      console.warn('bitnodes-snapshot cron: SNAPSHOT_KV (or legacy RL_KV) binding missing, aborting');
      return;
    }
    try {
      /* v393: upstream switched from bitnodes.io to a GitHub Actions mirror. */
      /* bitnodes.io is fronted by Cloudflare; Workers-to-Workers fetch traffic */
      /* to other Cloudflare-protected origins returns HTTP 530 from the WAF */
      /* (observed in the v392 cron logs — every run for 24+ hours failed with */
      /* status=530, wallTimeMs=14, no body). The fix routes around the block: */
      /* a GitHub Actions workflow at testmodeanyone-bit/anyone-relay-map runs */
      /* every 30 min, fetches bitnodes.io from a GitHub runner IP (not CF), */
      /* validates the response shape, and commits the result to a JSON file. */
      /* The worker reads from raw.githubusercontent.com, which CF Workers can */
      /* reach normally. The data schema matches bitnodes.io's exactly; only */
      /* the transport changed. If the mirror falls behind (workflow failure, */
      /* GitHub queue jitter), we serve the last-good commit — same graceful- */
      /* degradation property as the previous KV-cached-snapshot design, just */
      /* with git history as the audit log instead of KV's last-write-wins. */
      const r = await fetch('https://raw.githubusercontent.com/testmodeanyone-bit/anyone-relay-map/main/data/bitnodes-snapshot.json', {
        headers: { 'User-Agent': 'AnyoneMap/1.2 (https://map.anyone.io)' },
        cf: { cacheTtl: 60, cacheEverything: true }
      });
      if (!r.ok) {
        console.warn('bitnodes-snapshot cron: mirror returned ' + r.status + ' ' + r.statusText);
        return;
      }
      const data = await r.json();
      const nodes = data.nodes || {};
      const TARGET = 200;
      /* v379: stratified sampling by country. Previous version iterated the */
      /* nodes object in insertion order and took the first 200 \u2014 since */
      /* bitnodes keys by "ip:port", this systematically over-represented */
      /* countries with low-numbered IP ranges (US AWS, EU Hetzner) and */
      /* under-represented or missed everything else. Now: bucket every */
      /* valid node by country, give each country at least one slot (largest */
      /* first if the budget is tight), then distribute the remaining slots */
      /* proportionally by country size using largest-remainder. The result: */
      /* a sample that shows the actual geographic spread of the Bitcoin */
      /* network rather than IP-allocation artifacts. Within each country, */
      /* nodes are picked from a Fisher-Yates shuffle seeded by the upstream */
      /* timestamp \u2014 same input \u2192 same output, but daily refresh varies. */
      const buckets = {};
      let totalValid = 0;
      for (const addr in nodes) {
        const n = nodes[addr];
        /* Bitnodes node array schema (also matches the mirror's DNS-seeders */
        /* fallback when bitnodes itself is unreachable): */
        /* [0]=protocol, [1]=user-agent, [2]=last-seen, [3]=services, */
        /* [4]=height, [5]=host, [6]=port, [7]=country, [8]=lat, [9]=lon, */
        /* [10]=timezone, [11]=ASN, [12]=org, [13]=city. */
        /* v393: city was being read from n[6] (port) and silently coerced to */
        /* the string "8333" on every record. The bug pre-existed v392 but */
        /* was masked: the cron's bitnodes.io fetch always 530'd, so KV stayed */
        /* empty, so the static fallback (with hand-coded correct city names) */
        /* was what users actually saw. With v393's working mirror, this code */
        /* path finally exercises real data; fixed to read city from n[13]. */
        if (n[8] && n[9] && n[7]) {
          const cc = n[7];
          if (!buckets[cc]) buckets[cc] = [];
          buckets[cc].push({ lat: n[8], lon: n[9], cc, city: n[13] || '', org: n[12] || '', ua: (n[1] || '').substring(0, 40) });
          totalValid++;
        }
      }
      let reduced;
      if (totalValid <= TARGET) {
        /* Fewer valid nodes than slots \u2014 include them all. */
        reduced = [];
        for (const cc in buckets) for (const node of buckets[cc]) reduced.push(node);
      } else {
        /* Seeded PRNG (mulberry32) so the within-country shuffle is */
        /* deterministic for a given snapshot but varies as the snapshot */
        /* changes. v394: seed source switched from data.timestamp to a */
        /* hash of the sorted node addresses. The previous source had two */
        /* issues: (1) the fallback to Date.now() when timestamp was */
        /* missing silently broke the "same input → same output" promise */
        /* the comment claimed; (2) it tightly coupled the shuffle to one */
        /* optional field of the upstream schema. The new seed depends on */
        /* the *content* — the set of node addresses present in the */
        /* snapshot — so identical snapshots always produce identical */
        /* shuffles regardless of which upstream metadata fields are */
        /* present. Sorting the keys before hashing makes this robust to */
        /* the upstream changing its iteration order (object key order */
        /* is implementation-defined; JSON parsers may differ). */
        let seed = 0;
        const seedKeys = Object.keys(nodes).sort();
        for (let i = 0; i < seedKeys.length; i++) {
          const k = seedKeys[i];
          for (let j = 0; j < k.length; j++) seed = (seed * 31 + k.charCodeAt(j)) >>> 0;
        }
        const rand = (function(s) {
          return function() {
            s = (s + 0x6D2B79F5) >>> 0;
            let t = s;
            t = Math.imul(t ^ (t >>> 15), t | 1);
            t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
            return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
          };
        })(seed);
        /* Fisher-Yates shuffle each country's bucket. */
        for (const cc in buckets) {
          const arr = buckets[cc];
          for (let i = arr.length - 1; i > 0; i--) {
            const j = Math.floor(rand() * (i + 1));
            const tmp = arr[i]; arr[i] = arr[j]; arr[j] = tmp;
          }
        }
        const countries = Object.keys(buckets);
        const allocations = {};
        let allocated = 0;
        /* Pass 1: reserve 1 slot per country, processing largest first. */
        /* If TARGET is smaller than the country count (pathological), the */
        /* smallest countries drop out rather than the largest. At our */
        /* scale (TARGET=200, ~150 countries) every country gets a slot. */
        const byCountrySize = countries.slice().sort((a, b) => buckets[b].length - buckets[a].length);
        for (const cc of byCountrySize) {
          if (allocated >= TARGET) { allocations[cc] = 0; continue; }
          allocations[cc] = 1;
          allocated++;
        }
        /* Pass 2: distribute remaining slots proportionally to country */
        /* size. Each country's "extra share" is its proportional fraction */
        /* of the bonus pool (TARGET - countries.length). Use largest- */
        /* remainder method to deal with fractional shares. */
        if (allocated < TARGET) {
          const bonus = TARGET - countries.length;
          if (bonus > 0) {
            const extras = countries.map(cc => {
              const share = (buckets[cc].length / totalValid) * bonus;
              return { cc, floor: Math.floor(share), rem: share - Math.floor(share) };
            });
            for (const e of extras) {
              const newAlloc = allocations[e.cc] + e.floor;
              const max = Math.min(newAlloc, buckets[e.cc].length);
              const added = max - allocations[e.cc];
              allocations[e.cc] = max;
              allocated += added;
            }
            extras.sort((a, b) => b.rem - a.rem);
            /* v382: bound was `extras.length * 4`, which silently under-allocated */
            /* when buckets cap out and the remaining slack has to be absorbed by */
            /* a small number of large countries. The true worst-case iteration */
            /* count is bounded by the remaining slots (TARGET - allocated <= TARGET) */
            /* plus the number of skipped-cap rounds (<= countries.length). */
            /* Use TARGET + countries.length to cover both terms with margin. */
            /* Silent under-allocation passed the v381 empty-sample guard since */
            /* reduced.length > 0 there — only fully-empty samples were rejected. */
            let ri = 0;
            const _lrBound = TARGET + countries.length;
            while (allocated < TARGET && ri < _lrBound) {
              const cc = extras[ri % extras.length].cc;
              if (allocations[cc] < buckets[cc].length) {
                allocations[cc]++;
                allocated++;
              }
              ri++;
            }
            if (allocated < TARGET) {
              /* All remaining buckets are at cap. Sample will be smaller than */
              /* TARGET but still representative. Warn so we notice if this */
              /* becomes common — it indicates upstream returned an unusually */
              /* sparse set of valid (lat, lon, country) tuples. */
              console.warn('bitnodes-snapshot cron: short allocation — ' + allocated + '/' + TARGET + ' slots filled, all remaining buckets at cap (totalValid=' + totalValid + ')');
            }
          }
        }
        /* Build the final sample from shuffled buckets. */
        reduced = [];
        for (const cc of countries) {
          const take = allocations[cc] || 0;
          for (let i = 0; i < take && i < buckets[cc].length; i++) {
            reduced.push(buckets[cc][i]);
          }
        }
      }
      const snapshot = {
        total: Object.keys(nodes).length,
        sample: reduced,
        timestamp: data.timestamp,
        cachedAt: Math.floor(Date.now() / 1000),
        source: 'kv-snapshot'
      };
      /* v381: guard against persisting empty snapshots. If bitnodes returned */
      /* zero valid nodes (every entry failed the lat/lon/country validity */
      /* check, or the nodes object was empty), reduced is []. Writing that */
      /* to KV would either (a) replace a previously-good snapshot with */
      /* garbage, or (b) lock first-deploy users into "Total: X, Showing: 0" */
      /* until the next successful cron. Skipping the put keeps the previous */
      /* snapshot (or the static fallback, which surfaces the v376 stale */
      /* warning) \u2014 honest UX over deceptive completeness. */
      if (reduced.length === 0) {
        console.warn('bitnodes-snapshot cron: upstream returned ' + Object.keys(nodes).length + ' nodes but none passed validation, skipping KV write to preserve last-known-good');
        return;
      }
      /* KV value has no TTL \u2014 we want the last-known-good snapshot to persist */
      /* indefinitely if the upstream fetch later fails. The next successful */
      /* cron run will overwrite it. */
      /* M4 NOTE: this is INTENTIONALLY different from the sibling */
      /* exit-relays:latest key (anyclip-proxy/storeSnapshot, 7-day TTL) and the */
      /* two should NOT be harmonized. TTL tracks writer reliability: bitnodes.io */
      /* is heavily rate-limited (~10 req/day/IP) so cron failures are expected — */
      /* a stale-but-real snapshot beats none, and the /bitcoin .stale flag warns */
      /* when it's old; self-expiry here would drop users to the static fallback */
      /* during exactly the outages the no-TTL is meant to ride out. exit-relays, */
      /* by contrast, has a reliable producer (cron + every request post-M2), so a */
      /* 7-day gap there genuinely means broken and SHOULD self-expire. Leave as-is. */
      await _snapKv.put('bitnodes-snapshot:latest', JSON.stringify(snapshot));
      console.log('bitnodes-snapshot cron: stored snapshot with ' + reduced.length + ' nodes across ' + Object.keys(buckets).length + ' countries (total network: ' + snapshot.total + ')');
    } catch (e) {
      console.warn('bitnodes-snapshot cron: ' + e.message);
    }
  }
}