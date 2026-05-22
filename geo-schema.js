/* ============================================================================
 * geo-schema.js — shared schema for the GEO_ENRICH KV namespace (geo:<fp>)
 * ============================================================================
 *
 * Closes seam "S2": the cross-worker contract for geo:<fp> records was
 * informal. The enrichment worker WRITES these records; the producer
 * (anyclip-proxy) READS them in enrichFromCache() to un-quarantine relays
 * whose IP geolocation MaxMind could resolve. There was no shared definition
 * of the record shape — the two workers agreed only by convention, which is
 * exactly how the exit-relays:latest schema drifted (see kv-schema.js / S1).
 *
 * This file is the single source of truth for that shape. Like kv-schema.js it
 * is self-contained (no imports), exports minimal names, and is meant to be
 * inlined into BOTH workers at build time AND require()'d by the CI guard.
 *
 * TWO RECORD VARIANTS under the geo:<fp> key (discriminated by `failed`):
 *
 *   SUCCESS   { c:[lat,lng], cc, city, hexId, builtAt }
 *             — MaxMind resolved this fp's IP to a usable location.
 *             enrichFromCache consumes c (required), and cc/city/hexId
 *             (each optional — applied only when truthy).
 *
 *   TOMBSTONE { failed:true, reason, failCount, builtAt }
 *             — lookup failed (noIp/noGeo). Written so the slice backs the fp
 *             off (exponential backoff) instead of re-grinding it every run.
 *             The producer's reader IGNORES tombstones automatically because
 *             they have no `c` (its `Array.isArray(rec.c)` filter drops them).
 *
 * Design philosophy (same as kv-schema.js): strict on writes, permissive on
 * reads. The enrichment worker should refuse to WRITE a record that doesn't
 * match one of the two variants (one upstream alarm beats silently poisoning
 * the producer's KV). The producer keeps its existing permissive inline checks
 * on READ — this schema is the CONTRACT and the CI guard's reference, not a
 * replacement for the producer's already-correct defensive parsing.
 *
 * To add a field (e.g. asName/asNumber for the ASN-enrichment project):
 *   1. Add it to the relevant variant's `fields` below.
 *   2. Update the enrichment worker's write to emit it.
 *   3. Update the producer's enrichFromCache to consume it.
 *   4. Rebuild both workers AND bump SCHEMA_VERSION.
 *   The CI guard (check-geo-schema-sync.js) fails the build if the inlined
 *   copies drift from this canonical file — so step 4 can't be forgotten.
 * ============================================================================
 */

const GEO_SCHEMA_VERSION = '1.0.0';

/* The KV key prefix. Actual keys are `geo:<UPPERCASE_FINGERPRINT>`.
 * The reserved cursor key `geo:_cursor` is NOT a geo record and is excluded
 * from this contract (it's enrichment-internal run bookkeeping). */
const GEO_KEY_PREFIX = 'geo:';
const GEO_CURSOR_KEY = 'geo:_cursor';

/* Success-record contract. `default` values are sentinels the permissive
 * extractor substitutes on read; chosen so downstream can tell "missing" from
 * a real value. `sanity` is an extra plausibility test beyond typeof. */
const GEO_SUCCESS = {
  schemaVersion: GEO_SCHEMA_VERSION,
  variant: 'success',
  fields: {
    /* [lat, lng]. The single field enrichFromCache truly requires. Validated
     * there as: array of length 2, both finite numbers, lat in [-90,90],
     * lng in [-180,180], not [0,0]. We mark it required + sanity-checked here
     * so a malformed success write is rejected at the source. */
    c: {
      type: 'array',
      required: true,
      default: null,
      sanity: (v) => Array.isArray(v) && v.length === 2 &&
        typeof v[0] === 'number' && typeof v[1] === 'number' &&
        isFinite(v[0]) && isFinite(v[1]) &&
        v[0] >= -90 && v[0] <= 90 && v[1] >= -180 && v[1] <= 180 &&
        !(v[0] === 0 && v[1] === 0)
    },
    cc:      { type: 'string', required: false, default: '' },
    city:    { type: 'string', required: false, default: '' },
    /* H3 cell id at res 4; the producer only applies it when truthy. */
    hexId:   { type: 'string', required: false, default: null },
    builtAt: {
      type: 'number',
      required: true,
      default: null,
      /* Unix MILLIseconds (Date.now()), unlike exit-relays cachedAt which is
       * seconds. Reject obviously bad: not negative/zero, after 2024-01-01 in
       * ms, not more than a year ahead. */
      sanity: (v) => v > 1704067200000 && v < Date.now() + 31536000000
    }
  }
};

/* Tombstone-record contract. */
const GEO_TOMBSTONE = {
  schemaVersion: GEO_SCHEMA_VERSION,
  variant: 'tombstone',
  fields: {
    failed:    { type: 'boolean', required: true,  default: true, sanity: (v) => v === true },
    reason:    { type: 'string',  required: true,  default: 'unknown' },
    failCount: { type: 'number',  required: true,  default: 1, sanity: (v) => v >= 1 && v < 100000 },
    builtAt: {
      type: 'number',
      required: true,
      default: null,
      sanity: (v) => v > 1704067200000 && v < Date.now() + 31536000000
    }
  }
};

/* Decide which variant an object is, WITHOUT validating it. A record with a
 * truthy `failed` is a tombstone; otherwise it's treated as a (possibly
 * malformed) success record. Returns 'tombstone' | 'success'. This mirrors how
 * the producer's reader discriminates (tombstones lack `c`). */
function classify(obj) {
  if (obj && typeof obj === 'object' && obj.failed === true) return 'tombstone';
  return 'success';
}

/* Validate an object against a specific variant schema.
 * Mirrors kv-schema.js validate(): same return shape, same modes.
 *   opts: { mode: 'strict' | 'permissive', context: 'write' | 'read' }
 *   returns { ok, errors[], warnings[], fields_seen, fields_unknown[] }
 * In strict mode (writes), errors block; in permissive mode (reads), they're
 * downgraded to warnings. */
function validateVariant(obj, schema, opts) {
  opts = opts || {};
  const mode = opts.mode || 'permissive';
  const result = { ok: true, errors: [], warnings: [], fields_seen: 0, fields_unknown: [] };

  if (obj === null || obj === undefined) {
    result.ok = false;
    result.errors.push('geo record is null or undefined');
    return result;
  }
  if (typeof obj !== 'object' || Array.isArray(obj)) {
    result.ok = false;
    result.errors.push('geo record is not a plain object (got ' + (Array.isArray(obj) ? 'array' : typeof obj) + ')');
    return result;
  }

  for (const name in schema.fields) {
    const spec = schema.fields[name];
    const present = Object.prototype.hasOwnProperty.call(obj, name);
    if (!present) {
      if (spec.required) {
        const msg = 'missing required field: ' + name;
        if (mode === 'strict') result.errors.push(msg); else result.warnings.push(msg);
      }
      continue;
    }
    result.fields_seen++;
    const val = obj[name];
    /* typeof check. Note Array.isArray for the 'array' type since typeof []
     * === 'object'. null is treated as missing-ish for object/array fields. */
    let typeOk;
    if (spec.type === 'array') typeOk = Array.isArray(val);
    else if (val === null) typeOk = false;
    else typeOk = (typeof val === spec.type);

    if (!typeOk) {
      const actual = (val === null ? 'null' : (Array.isArray(val) ? 'array' : typeof val));
      const msg = 'field ' + name + ' has wrong type: expected ' + spec.type + ', got ' + actual;
      if (mode === 'strict') result.errors.push(msg); else result.warnings.push(msg);
      continue;
    }
    if (spec.sanity && !spec.sanity(val)) {
      const msg = 'field ' + name + ' failed sanity check (value: ' + JSON.stringify(val).slice(0, 80) + ')';
      if (mode === 'strict') result.errors.push(msg); else result.warnings.push(msg);
    }
  }

  for (const name in obj) {
    if (!Object.prototype.hasOwnProperty.call(schema.fields, name)) result.fields_unknown.push(name);
  }

  if (result.errors.length > 0) result.ok = false;
  return result;
}

/* Convenience: classify then validate against the right variant. This is what
 * the enrichment worker should call on WRITE in strict mode:
 *   const v = geoSchema.validate(record, { mode: 'strict', context: 'write' });
 *   if (!v.ok) { console.error(...); skip the put; }
 */
function validate(obj, opts) {
  const variant = classify(obj);
  const schema = variant === 'tombstone' ? GEO_TOMBSTONE : GEO_SUCCESS;
  const res = validateVariant(obj, schema, opts);
  res.variant = variant;
  return res;
}

/* Permissive read extractor for the SUCCESS variant: returns a new object with
 * every success field present, falling back to `default` when missing or
 * wrong-typed. Returns null for tombstones (caller should skip them, exactly
 * as the producer already does). Mirrors kv-schema.js extract(). */
function extractSuccess(obj) {
  if (classify(obj) === 'tombstone') return null;
  const out = {};
  obj = (obj && typeof obj === 'object' && !Array.isArray(obj)) ? obj : {};
  for (const name in GEO_SUCCESS.fields) {
    const spec = GEO_SUCCESS.fields[name];
    const val = obj[name];
    let usable = true;
    if (val === undefined) usable = false;
    else if (spec.type === 'array') usable = Array.isArray(val);
    else if (val === null) usable = false;
    else if (typeof val !== spec.type) usable = false;
    if (usable && spec.sanity && !spec.sanity(val)) usable = false;
    out[name] = usable ? val : spec.default;
  }
  return out;
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    GEO_SCHEMA_VERSION,
    GEO_KEY_PREFIX,
    GEO_CURSOR_KEY,
    GEO_SUCCESS,
    GEO_TOMBSTONE,
    classify,
    validate,
    extractSuccess
  };
}
