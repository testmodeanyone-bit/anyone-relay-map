/* ============================================================================
 * kv-schema.js — shared schema for AnyoneMap KV writes
 * ============================================================================
 *
 * Single source of truth for the cross-worker contract on what gets written to
 * SNAPSHOT_KV. Both workers (anyclip-proxy as producer, anyonemap-worker as
 * consumer) inline this file at build time. There is NO runtime import — each
 * built worker contains its own complete copy, mechanically generated from
 * this source.
 *
 * Design philosophy: strict on writes, permissive on reads.
 *   - Producer aborts on invalid shape (one upstream alarm beats thousands of
 *     downstream "Invalid Date" renders).
 *   - Consumer logs and degrades gracefully (every deploy moment has skew, so
 *     rejecting reads turns every release into an outage).
 *
 * Self-contained: no imports, no runtime deps. The exported names are also
 * minimal — `SCHEMA`, `validate`, and `extract` — so name collisions when
 * inlined into either worker are unlikely.
 *
 * To add a new field:
 *   1. Add it to EXIT_RELAYS_LATEST.fields below
 *   2. Rebuild both workers (build-worker.js, build-anyclip.js)
 *   3. Producer code that writes to KV starts including the new field
 *   4. Consumer code can read it — old snapshots will lack it; the validator's
 *      permissive read mode handles that.
 *
 * To remove a field: same as above but in reverse, and run for at least one
 * full TTL cycle (7 days) before assuming no snapshots have the old field.
 *
 * Version this file when the shape changes meaningfully. The validator
 * doesn't enforce version match — it's just for logs and tracing.
 * ============================================================================
 */

const SCHEMA_VERSION = '1.0.0';

/* The SNAPSHOT_KV key under which the exit-relays snapshot lives.
 * Both workers MUST agree on this exact string. */
const SNAPSHOT_KEY = 'exit-relays:latest';

/* Field-level contract for exit-relays:latest.
 *
 * type:       'number' | 'string' | 'object' | 'array' — typeof check
 * required:   true means strict-mode writes that lack it are rejected
 * default:    fallback value the extract() helper substitutes on permissive
 *             read when the field is missing/wrong type. Use sentinels (null,
 *             '\u2014', 0) — not random plausible numbers, since downstream
 *             rendering must be able to tell "data missing" from "data is 0".
 * sanity:     optional secondary check beyond typeof — returns true if value
 *             passes additional plausibility test (e.g. positive integer)
 */
const EXIT_RELAYS_LATEST = {
  schemaVersion: SCHEMA_VERSION,
  key: SNAPSHOT_KEY,
  fields: {
    cachedAt: {
      type: 'number',
      required: true,
      default: null,
      /* Unix epoch seconds. Reject obviously bad timestamps: not negative,
       * not zero, not before 2024 (any AnyoneMap snapshot is post-2024),
       * not more than a year in the future (clock skew tolerance). */
      sanity: (v) => v > 1704067200 && v < (Date.now() / 1000) + 31536000
    },
    exit_relays:     { type: 'number', required: true,  default: null, sanity: (v) => v >= 0 && v < 1000000 },
    guard_relays:    { type: 'number', required: false, default: null, sanity: (v) => v >= 0 && v < 1000000 },
    middle_relays:   { type: 'number', required: false, default: null, sanity: (v) => v >= 0 && v < 1000000 },
    total_relays:    { type: 'number', required: false, default: null, sanity: (v) => v >= 0 && v < 1000000 },
    hardware_relays: { type: 'number', required: false, default: null, sanity: (v) => v >= 0 && v < 1000000 },
    bw_gbps:         { type: 'number', required: true,  default: null, sanity: (v) => v >= 0 && v < 100000 },
    wallets:         { type: 'number', required: false, default: null, sanity: (v) => v >= 0 && v < 10000000 },
    zones:           { type: 'object', required: false, default: null },
    countries:       { type: 'object', required: false, default: null },
    isps:            { type: 'object', required: false, default: null },
    source:          { type: 'string', required: false, default: 'unknown' },
    fp_built_at:     { type: 'number', required: false, default: null }
  }
};

/* Validate a snapshot object against a schema.
 *
 * @param {object} obj    — the value coming in (from JSON.parse or directly)
 * @param {object} schema — one of the schemas above (e.g. EXIT_RELAYS_LATEST)
 * @param {object} opts   — { mode: 'strict' | 'permissive', context: 'write' | 'read' }
 *
 * @returns {object}
 *   {
 *     ok: boolean,         — true iff zero errors (warnings are OK)
 *     errors: string[],    — fatal problems (only blocks if mode === 'strict')
 *     warnings: string[],  — non-fatal shape concerns (always logged, never blocks)
 *     fields_seen: number, — how many fields from the schema were present
 *     fields_unknown: string[] — fields in obj that are NOT in the schema
 *   }
 */
function validate(obj, schema, opts) {
  opts = opts || {};
  const mode = opts.mode || 'permissive';
  const context = opts.context || 'read';
  const result = { ok: true, errors: [], warnings: [], fields_seen: 0, fields_unknown: [] };

  if (obj === null || obj === undefined) {
    result.ok = false;
    result.errors.push('snapshot is null or undefined');
    return result;
  }
  if (typeof obj !== 'object' || Array.isArray(obj)) {
    result.ok = false;
    result.errors.push('snapshot is not a plain object (got ' + (Array.isArray(obj) ? 'array' : typeof obj) + ')');
    return result;
  }

  /* Check every schema field against the candidate object */
  for (const name in schema.fields) {
    const spec = schema.fields[name];
    const present = Object.prototype.hasOwnProperty.call(obj, name);
    if (!present) {
      if (spec.required) {
        const msg = 'missing required field: ' + name;
        if (mode === 'strict') result.errors.push(msg);
        else result.warnings.push(msg);
      }
      continue;
    }
    result.fields_seen++;
    const val = obj[name];
    /* typeof check. Note typeof null === 'object', so we treat null as missing
     * rather than wrong-typed when the schema expects 'object'. */
    const actualType = (val === null ? 'null' : typeof val);
    if (spec.type === 'object' && val === null) {
      /* explicit null for an object field is allowed — most "this didn't compute"
       * markers come through as null. Skip the typeof check. */
    } else if (actualType !== spec.type) {
      const msg = 'field ' + name + ' has wrong type: expected ' + spec.type + ', got ' + actualType;
      if (mode === 'strict') result.errors.push(msg);
      else result.warnings.push(msg);
      continue; /* don't run sanity check on wrong-typed value */
    }
    /* sanity check */
    if (spec.sanity && val !== null && !spec.sanity(val)) {
      const msg = 'field ' + name + ' failed sanity check (value: ' + JSON.stringify(val).slice(0, 80) + ')';
      if (mode === 'strict') result.errors.push(msg);
      else result.warnings.push(msg);
    }
  }

  /* Note unknown fields — never fatal, just informational. Catches typos in
   * the producer ("cached_at" vs "cachedAt"). */
  for (const name in obj) {
    if (!Object.prototype.hasOwnProperty.call(schema.fields, name)) {
      result.fields_unknown.push(name);
    }
  }

  if (result.errors.length > 0) result.ok = false;
  return result;
}

/* Extract fields with defaults applied — for consumer reads when you want to
 * proceed regardless of validation state.
 *
 * Returns a NEW object with every schema field present, falling back to the
 * field's `default` when the input has it missing or wrong-typed.
 *
 * Use this AFTER calling validate() (so you've logged any issues) when you
 * want to render the page anyway. */
function extract(obj, schema) {
  const out = {};
  obj = (obj && typeof obj === 'object' && !Array.isArray(obj)) ? obj : {};
  for (const name in schema.fields) {
    const spec = schema.fields[name];
    const val = obj[name];
    const actualType = (val === null ? 'null' : typeof val);
    let usable = true;
    if (val === undefined) usable = false;
    else if (spec.type === 'object' && val === null) usable = true; /* null OK for object */
    else if (actualType !== spec.type) usable = false;
    else if (spec.sanity && val !== null && !spec.sanity(val)) usable = false;
    out[name] = usable ? val : spec.default;
  }
  return out;
}

/* Module exports — both workers will rebind these to local names when inlined.
 * In CommonJS context (Node tests, build scripts), this binds to module.exports.
 * In the inlined worker context, the build script wraps everything in an IIFE
 * that returns this same object literal.
 */
if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    SCHEMA_VERSION,
    SNAPSHOT_KEY,
    EXIT_RELAYS_LATEST,
    validate,
    extract
  };
}
