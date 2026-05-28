/* ── Minimal Buffer polyfill (self-installing global) ───────────────────────
 * Cloudflare's nodejs_compat provides Buffer at request time, but mmdb-lib's
 * metadata.js calls Buffer.from() at MODULE TOP LEVEL (load time), where the
 * polyfill may not be installed yet. This shim guarantees Buffer exists for
 * exactly the methods mmdb-lib uses, independent of nodejs_compat timing.
 * Backed by Uint8Array + DataView. Only the needed surface is implemented.
 * ────────────────────────────────────────────────────────────────────────── */
(function () {
  if (typeof globalThis.Buffer !== 'undefined' && globalThis.Buffer.__mmdbShim) return;

  class B extends Uint8Array {
    static __mmdbShim = true;
    static isBuffer(x) { return x instanceof B || (x && x.__isBuf === true); }
    static alloc(n) { return new B(n); }
    static allocUnsafe(n) { return new B(n); }
    static concat(list) { let len=0; for(const b of list) len+=b.length; const o=new B(len); let off=0; for(const b of list){o.set(b,off);off+=b.length;} return o; }
    static from(data, enc) {
      if (typeof data === 'string') {
        if (enc === 'hex') {
          const out = new B(data.length / 2);
          for (let i = 0; i < out.length; i++) out[i] = parseInt(data.substr(i * 2, 2), 16);
          return out;
        }
        // utf8 default
        const enc2 = new TextEncoder().encode(data);
        const out = new B(enc2.length); out.set(enc2); return out;
      }
      if (data instanceof ArrayBuffer) { const o = new B(data.byteLength); o.set(new Uint8Array(data)); return o; }
      if (ArrayBuffer.isView(data)) { const o = new B(data.byteLength); o.set(new Uint8Array(data.buffer, data.byteOffset, data.byteLength)); return o; }
      const o = new B(data.length); o.set(data); return o;
    }
    get __isBuf() { return true; }
    _dv() { return new DataView(this.buffer, this.byteOffset, this.byteLength); }
    readUInt8(o) { return this[o]; }
    readUInt16BE(o) { return this._dv().getUint16(o, false); }
    readUInt32BE(o) { return this._dv().getUint32(o, false); }
    readInt32BE(o) { return this._dv().getInt32(o, false); }
    readFloatBE(o) { return this._dv().getFloat32(o, false); }
    readDoubleBE(o) { return this._dv().getFloat64(o, false); }
    readUIntBE(o, len) {
      let v = 0;
      for (let i = 0; i < len; i++) v = v * 256 + this[o + i];
      return v;
    }
    // subarray inherited from Uint8Array returns Uint8Array; re-wrap as B so chained methods exist
    subarray(a, b) { const u = Uint8Array.prototype.subarray.call(this, a, b); const o = new B(u.length); o.set(u); return o; }
    slice(a, b) { return this.subarray(a, b); }
    toString(enc, start, end) {
      const slice = (start != null || end != null) ? Uint8Array.prototype.subarray.call(this, start || 0, end) : this;
      return new TextDecoder('utf-8').decode(slice);
    }
  }
  globalThis.Buffer = B;
})();

/* ── Inlined geo-schema (S2 contract for geo:<fp> records) ──────────────────
 * Canonical source: geo-schema.js. This inlined copy is kept in sync by the
 * CI guard scripts/check-geo-schema-sync.js (fails the build on drift).
 * Used below to validate every geo:<fp> record BEFORE writing it to
 * GEO_ENRICH, so a malformed record never reaches the producer's KV.
 * ────────────────────────────────────────────────────────────────────────── */
const _geoSchema = (function() {
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

const GEO_SCHEMA_VERSION = '1.1.0';

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

/* Country-only-record contract (schema 1.1.0+). MaxMind gave a confident
 * COUNTRY but not a precise location. Carries the country code and NO
 * coordinate — the producer centroids it for display. Discriminated by
 * `countryOnly===true`. NOTE: this variant is intentionally NOT compared by
 * check-geo-schema-sync.js (which only diffs SUCCESS + TOMBSTONE); cross-copy
 * consistency for it is enforced by GEO_SCHEMA_VERSION + this shared file being
 * inlined verbatim. */
const GEO_COUNTRY_ONLY = {
  schemaVersion: GEO_SCHEMA_VERSION,
  variant: 'country_only',
  fields: {
    /* Discriminator. Strict-true so a stray countryOnly:false can't misroute. */
    countryOnly: { type: 'boolean', required: true, default: true, sanity: (v) => v === true },
    /* ISO 3166-1 alpha-2 from MaxMind country.iso_code. Required + sanity:
     * exactly two A-Z letters, so an empty/garbage cc can't produce a
     * country-less approximate record (which would be useless to the producer). */
    cc: { type: 'string', required: true, default: '', sanity: (v) => /^[A-Z]{2}$/.test(v) },
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
  if (obj && typeof obj === 'object' && obj.countryOnly === true) return 'country_only';
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
  const schema = variant === 'tombstone' ? GEO_TOMBSTONE
               : variant === 'country_only' ? GEO_COUNTRY_ONLY
               : GEO_SUCCESS;
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

  return {
    GEO_SCHEMA_VERSION, GEO_KEY_PREFIX, GEO_CURSOR_KEY,
    GEO_SUCCESS, GEO_TOMBSTONE, GEO_COUNTRY_ONLY, classify, validate, extractSuccess
  };
})();
const _geoValidate = _geoSchema.validate;
var __create = Object.create;
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __getProtoOf = Object.getPrototypeOf;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __esm = (fn, res) => function __init() {
  return fn && (res = (0, fn[__getOwnPropNames(fn)[0]])(fn = 0)), res;
};
var __commonJS = (cb, mod) => function __require() {
  return mod || (0, cb[__getOwnPropNames(cb)[0]])((mod = { exports: {} }).exports, mod), mod.exports;
};
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toESM = (mod, isNodeMode, target) => (target = mod != null ? __create(__getProtoOf(mod)) : {}, __copyProps(
  // If the importer is in node compatibility mode or this is not an ESM
  // file that has been converted to a CommonJS file using a Babel-
  // compatible transform (i.e. "__esModule" has not been set), then set
  // "default" to the CommonJS "module.exports" for node compatibility.
  isNodeMode || !mod || !mod.__esModule ? __defProp(target, "default", { value: mod, enumerable: true }) : target,
  mod
));
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// ../node_modules/mmdb-lib/lib/utils.js
var require_utils = __commonJS({
  "../node_modules/mmdb-lib/lib/utils.js"(exports) {
    "use strict";
    Object.defineProperty(exports, "__esModule", { value: true });
    var legacyErrorMessage = `Maxmind v2 module has changed API.
Upgrade instructions can be found here: https://github.com/runk/node-maxmind/wiki/Migration-guide
If you want to use legacy library then explicitly install maxmind@1`;
    var assert = (condition, message) => {
      if (!condition) {
        throw new Error(message);
      }
    };
    exports.default = {
      assert,
      legacyErrorMessage
    };
  }
});

// ../node_modules/mmdb-lib/lib/decoder.js
var require_decoder = __commonJS({
  "../node_modules/mmdb-lib/lib/decoder.js"(exports) {
    "use strict";
    var __importDefault = exports && exports.__importDefault || function(mod) {
      return mod && mod.__esModule ? mod : { "default": mod };
    };
    Object.defineProperty(exports, "__esModule", { value: true });
    var utils_1 = __importDefault(require_utils());
    utils_1.default.assert(typeof BigInt !== "undefined", "Apparently you are using old version of node. Please upgrade to node 10.4.x or above.");
    var MAX_INT_32 = 2147483647;
    var DataType;
    (function(DataType2) {
      DataType2[DataType2["Extended"] = 0] = "Extended";
      DataType2[DataType2["Pointer"] = 1] = "Pointer";
      DataType2[DataType2["Utf8String"] = 2] = "Utf8String";
      DataType2[DataType2["Double"] = 3] = "Double";
      DataType2[DataType2["Bytes"] = 4] = "Bytes";
      DataType2[DataType2["Uint16"] = 5] = "Uint16";
      DataType2[DataType2["Uint32"] = 6] = "Uint32";
      DataType2[DataType2["Map"] = 7] = "Map";
      DataType2[DataType2["Int32"] = 8] = "Int32";
      DataType2[DataType2["Uint64"] = 9] = "Uint64";
      DataType2[DataType2["Uint128"] = 10] = "Uint128";
      DataType2[DataType2["Array"] = 11] = "Array";
      DataType2[DataType2["Container"] = 12] = "Container";
      DataType2[DataType2["EndMarker"] = 13] = "EndMarker";
      DataType2[DataType2["Boolean"] = 14] = "Boolean";
      DataType2[DataType2["Float"] = 15] = "Float";
    })(DataType || (DataType = {}));
    var pointerValueOffset = [0, 2048, 526336, 0];
    var noCache = {
      get: () => void 0,
      set: () => void 0
    };
    var cursor = (value, offset) => ({ value, offset });
    var Decoder = class {
      constructor(db, baseOffset = 0, cache = noCache) {
        this.telemetry = {};
        utils_1.default.assert(Boolean(db), "Database buffer is required");
        this.db = db;
        this.baseOffset = baseOffset;
        this.cache = cache;
      }
      decode(offset) {
        let tmp;
        const ctrlByte = this.db[offset++];
        let type = ctrlByte >> 5;
        if (type === DataType.Pointer) {
          tmp = this.decodePointer(ctrlByte, offset);
          return cursor(this.decodeFast(tmp.value).value, tmp.offset);
        }
        if (type === DataType.Extended) {
          tmp = this.db[offset] + 7;
          if (tmp < 8) {
            throw new Error("Invalid Extended Type at offset " + offset + " val " + tmp);
          }
          type = tmp;
          offset++;
        }
        const size = this.sizeFromCtrlByte(ctrlByte, offset);
        return this.decodeByType(type, size.offset, size.value);
      }
      decodeFast(offset) {
        const cached = this.cache.get(offset);
        if (cached) {
          return cached;
        }
        const result = this.decode(offset);
        this.cache.set(offset, result);
        return result;
      }
      decodeByType(type, offset, size) {
        const newOffset = offset + size;
        switch (type) {
          case DataType.Utf8String:
            return cursor(this.decodeString(offset, size), newOffset);
          case DataType.Map:
            return this.decodeMap(size, offset);
          case DataType.Uint32:
            return cursor(this.decodeUint(offset, size), newOffset);
          case DataType.Double:
            return cursor(this.decodeDouble(offset), newOffset);
          case DataType.Array:
            return this.decodeArray(size, offset);
          case DataType.Boolean:
            return cursor(this.decodeBoolean(size), offset);
          case DataType.Float:
            return cursor(this.decodeFloat(offset), newOffset);
          case DataType.Bytes:
            return cursor(this.decodeBytes(offset, size), newOffset);
          case DataType.Uint16:
            return cursor(this.decodeUint(offset, size), newOffset);
          case DataType.Int32:
            return cursor(this.decodeInt32(offset, size), newOffset);
          case DataType.Uint64:
            return cursor(this.decodeBigUint(offset, size), newOffset);
          case DataType.Uint128:
            return cursor(this.decodeBigUint(offset, size), newOffset);
        }
        throw new Error("Unknown type " + type + " at offset " + offset);
      }
      sizeFromCtrlByte(ctrlByte, offset) {
        const size = ctrlByte & 31;
        if (size < 29) {
          return cursor(size, offset);
        }
        if (size === 29) {
          return cursor(29 + this.db[offset], offset + 1);
        }
        if (size === 30) {
          return cursor(285 + this.db.readUInt16BE(offset), offset + 2);
        }
        return cursor(65821 + this.db.readUIntBE(offset, 3), offset + 3);
      }
      decodeBytes(offset, size) {
        return this.db.subarray(offset, offset + size);
      }
      decodePointer(ctrlByte, offset) {
        const pointerSize = ctrlByte >> 3 & 3;
        const pointer = this.baseOffset + pointerValueOffset[pointerSize];
        let packed = 0;
        if (pointerSize === 0) {
          packed = (ctrlByte & 7) << 8 | this.db[offset];
        } else if (pointerSize === 1) {
          packed = (ctrlByte & 7) << 16 | this.db.readUInt16BE(offset);
        } else if (pointerSize === 2) {
          packed = (ctrlByte & 7) << 24 | this.db.readUIntBE(offset, 3);
        } else {
          packed = this.db.readUInt32BE(offset);
        }
        offset += pointerSize + 1;
        return cursor(pointer + packed, offset);
      }
      decodeArray(size, offset) {
        let tmp;
        const array = new Array(size);
        for (let i = 0; i < size; i++) {
          tmp = this.decode(offset);
          offset = tmp.offset;
          array[i] = tmp.value;
        }
        return cursor(array, offset);
      }
      decodeBoolean(size) {
        return size !== 0;
      }
      decodeDouble(offset) {
        return this.db.readDoubleBE(offset);
      }
      decodeFloat(offset) {
        return this.db.readFloatBE(offset);
      }
      decodeMap(size, offset) {
        let tmp;
        let key;
        const map = {};
        for (let i = 0; i < size; i++) {
          tmp = this.decode(offset);
          key = tmp.value;
          tmp = this.decode(tmp.offset);
          offset = tmp.offset;
          map[key] = tmp.value;
        }
        return cursor(map, offset);
      }
      decodeInt32(offset, size) {
        if (size === 0) {
          return 0;
        }
        if (size < 4) {
          return this.db.readUIntBE(offset, size);
        }
        return this.db.readInt32BE(offset);
      }
      decodeUint(offset, size) {
        if (size === 0) {
          return 0;
        }
        if (size <= 4) {
          return this.db.readUIntBE(offset, size);
        }
        throw new Error(`Invalid size for unsigned integer: ${size}`);
      }
      decodeString(offset, size) {
        const newOffset = offset + size;
        return newOffset >= MAX_INT_32 ? this.db.subarray(offset, newOffset).toString("utf8") : this.db.toString("utf8", offset, newOffset);
      }
      decodeBigUint(offset, size) {
        if (size > 16) {
          throw new Error(`Invalid size for big unsigned integer: ${size}`);
        }
        let integer = 0n;
        for (let i = 0; i < size; i++) {
          integer <<= 8n;
          integer |= BigInt(this.db.readUInt8(offset + i));
        }
        return integer;
      }
    };
    exports.default = Decoder;
  }
});

// net-shim.js
var net_shim_exports = {};
__export(net_shim_exports, {
  default: () => net_shim_default,
  isIP: () => isIP
});
function isIP(s) {
  if (typeof s !== "string") return 0;
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(s) && s.split(".").every((o) => +o >= 0 && +o <= 255)) return 4;
  if (s.indexOf(":") !== -1) return 6;
  return 0;
}
var net_shim_default;
var init_net_shim = __esm({
  "net-shim.js"() {
    net_shim_default = { isIP };
  }
});

// ../node_modules/mmdb-lib/lib/ip.js
var require_ip = __commonJS({
  "../node_modules/mmdb-lib/lib/ip.js"(exports) {
    "use strict";
    var __importDefault = exports && exports.__importDefault || function(mod) {
      return mod && mod.__esModule ? mod : { "default": mod };
    };
    Object.defineProperty(exports, "__esModule", { value: true });
    var net_1 = __importDefault((init_net_shim(), __toCommonJS(net_shim_exports)));
    var parseIPv4 = (input) => {
      const ip = input.split(".", 4);
      const o0 = parseInt(ip[0]);
      const o1 = parseInt(ip[1]);
      const o2 = parseInt(ip[2]);
      const o3 = parseInt(ip[3]);
      return [o0, o1, o2, o3];
    };
    var hex = (v) => {
      const h = parseInt(v, 10).toString(16);
      return h.length === 2 ? h : "0" + h;
    };
    var parseIPv6 = (input) => {
      const addr = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
      let i;
      let parsed;
      let chunk;
      const ip = input.indexOf(".") > -1 ? input.replace(/(\d+)\.(\d+)\.(\d+)\.(\d+)/, (match, a, b, c, d) => {
        return hex(a) + hex(b) + ":" + hex(c) + hex(d);
      }) : input;
      const [left, right] = ip.split("::", 2);
      if (left) {
        parsed = left.split(":");
        for (i = 0; i < parsed.length; i++) {
          chunk = parseInt(parsed[i], 16);
          addr[i * 2] = chunk >> 8;
          addr[i * 2 + 1] = chunk & 255;
        }
      }
      if (right) {
        parsed = right.split(":");
        const offset = 16 - parsed.length * 2;
        for (i = 0; i < parsed.length; i++) {
          chunk = parseInt(parsed[i], 16);
          addr[offset + i * 2] = chunk >> 8;
          addr[offset + (i * 2 + 1)] = chunk & 255;
        }
      }
      return addr;
    };
    var parse = (ip) => {
      return ip.indexOf(":") === -1 ? parseIPv4(ip) : parseIPv6(ip);
    };
    var bitAt = (rawAddress, idx) => {
      const bufIdx = idx >> 3;
      const bitIdx = 7 ^ idx & 7;
      return rawAddress[bufIdx] >>> bitIdx & 1;
    };
    var validate = (ip) => {
      const version = net_1.default.isIP(ip);
      return version === 4 || version === 6;
    };
    exports.default = {
      bitAt,
      parse,
      validate
    };
  }
});

// ../node_modules/mmdb-lib/lib/metadata.js
var require_metadata = __commonJS({
  "../node_modules/mmdb-lib/lib/metadata.js"(exports) {
    "use strict";
    var __importDefault = exports && exports.__importDefault || function(mod) {
      return mod && mod.__esModule ? mod : { "default": mod };
    };
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.isLegacyFormat = exports.parseMetadata = void 0;
    var decoder_1 = __importDefault(require_decoder());
    var utils_1 = __importDefault(require_utils());
    var METADATA_START_MARKER = Buffer.from("ABCDEF4D61784D696E642E636F6D", "hex");
    var parseMetadata = (db) => {
      const offset = findStart(db);
      const decoder = new decoder_1.default(db, offset);
      const metadata = decoder.decode(offset).value;
      if (!metadata) {
        throw new Error((0, exports.isLegacyFormat)(db) ? utils_1.default.legacyErrorMessage : "Cannot parse binary database");
      }
      utils_1.default.assert([24, 28, 32].indexOf(metadata.record_size) > -1, "Unsupported record size");
      return {
        binaryFormatMajorVersion: metadata.binary_format_major_version,
        binaryFormatMinorVersion: metadata.binary_format_minor_version,
        buildEpoch: new Date(Number(metadata.build_epoch) * 1e3),
        databaseType: metadata.database_type,
        description: metadata.description,
        ipVersion: metadata.ip_version,
        languages: metadata.languages,
        nodeByteSize: metadata.record_size / 4,
        nodeCount: metadata.node_count,
        recordSize: metadata.record_size,
        searchTreeSize: metadata.node_count * metadata.record_size / 4,
        // Depth depends on the IP version, it's 32 for IPv4 and 128 for IPv6.
        treeDepth: Math.pow(2, metadata.ip_version + 1)
      };
    };
    exports.parseMetadata = parseMetadata;
    var findStart = (db) => {
      let found = 0;
      let fsize = db.length - 1;
      const mlen = METADATA_START_MARKER.length - 1;
      while (found <= mlen && fsize-- > 0) {
        found += db[fsize] === METADATA_START_MARKER[mlen - found] ? 1 : -found;
      }
      return fsize + found;
    };
    var isLegacyFormat = (db) => {
      const structureInfoMaxSize = 20;
      for (let i = 0; i < structureInfoMaxSize; i++) {
        const delim = db.slice(db.length - 3 - i, db.length - i);
        if (delim[0] === 255 && delim[1] === 255 && delim[2] === 255) {
          return true;
        }
      }
      return false;
    };
    exports.isLegacyFormat = isLegacyFormat;
  }
});

// ../node_modules/mmdb-lib/lib/reader/walker.js
var require_walker = __commonJS({
  "../node_modules/mmdb-lib/lib/reader/walker.js"(exports) {
    "use strict";
    Object.defineProperty(exports, "__esModule", { value: true });
    var readNodeRight24 = (db) => (offset) => db.readUIntBE(offset + 3, 3);
    var readNodeLeft24 = (db) => (offset) => db.readUIntBE(offset, 3);
    var readNodeLeft28 = (db) => (offset) => (db[offset + 3] & 240) << 20 | db.readUIntBE(offset, 3);
    var readNodeRight28 = (db) => (offset) => (db[offset + 3] & 15) << 24 | db.readUIntBE(offset + 4, 3);
    var readNodeLeft32 = (db) => (offset) => db.readUInt32BE(offset);
    var readNodeRight32 = (db) => (offset) => db.readUInt32BE(offset + 4);
    exports.default = (db, recordSize) => {
      switch (recordSize) {
        case 24:
          return { left: readNodeLeft24(db), right: readNodeRight24(db) };
        case 28:
          return { left: readNodeLeft28(db), right: readNodeRight28(db) };
        case 32:
          return { left: readNodeLeft32(db), right: readNodeRight32(db) };
      }
      throw new Error("Unsupported record size");
    };
  }
});

// ../node_modules/mmdb-lib/lib/reader/response.js
var require_response = __commonJS({
  "../node_modules/mmdb-lib/lib/reader/response.js"(exports) {
    "use strict";
    Object.defineProperty(exports, "__esModule", { value: true });
  }
});

// ../node_modules/mmdb-lib/lib/index.js
var require_lib = __commonJS({
  "../node_modules/mmdb-lib/lib/index.js"(exports) {
    "use strict";
    var __createBinding = exports && exports.__createBinding || (Object.create ? (function(o, m, k, k2) {
      if (k2 === void 0) k2 = k;
      var desc = Object.getOwnPropertyDescriptor(m, k);
      if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
        desc = { enumerable: true, get: function() {
          return m[k];
        } };
      }
      Object.defineProperty(o, k2, desc);
    }) : (function(o, m, k, k2) {
      if (k2 === void 0) k2 = k;
      o[k2] = m[k];
    }));
    var __exportStar = exports && exports.__exportStar || function(m, exports2) {
      for (var p in m) if (p !== "default" && !Object.prototype.hasOwnProperty.call(exports2, p)) __createBinding(exports2, m, p);
    };
    var __importDefault = exports && exports.__importDefault || function(mod) {
      return mod && mod.__esModule ? mod : { "default": mod };
    };
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.Reader = void 0;
    var decoder_1 = __importDefault(require_decoder());
    var ip_1 = __importDefault(require_ip());
    var metadata_1 = require_metadata();
    var walker_1 = __importDefault(require_walker());
    var DATA_SECTION_SEPARATOR_SIZE = 16;
    var Reader2 = class {
      constructor(db, opts = {}) {
        this.opts = opts;
        this.load(db);
      }
      load(db) {
        if (!Buffer.isBuffer(db)) {
          throw new Error(`mmdb-lib expects an instance of Buffer, got: ${typeof db}`);
        }
        this.db = db;
        this.metadata = (0, metadata_1.parseMetadata)(this.db);
        this.decoder = new decoder_1.default(this.db, this.metadata.searchTreeSize + DATA_SECTION_SEPARATOR_SIZE, this.opts.cache);
        this.walker = (0, walker_1.default)(this.db, this.metadata.recordSize);
        this.ipv4StartNodeNumber = this.ipv4Start();
      }
      get(ipAddress) {
        const [data] = this.getWithPrefixLength(ipAddress);
        return data;
      }
      getWithPrefixLength(ipAddress) {
        const [pointer, prefixLength] = this.findAddressInTree(ipAddress);
        const data = pointer ? this.resolveDataPointer(pointer) : null;
        return [data, prefixLength];
      }
      findAddressInTree(ipAddress) {
        const rawAddress = ip_1.default.parse(ipAddress);
        const nodeCount = this.metadata.nodeCount;
        const bitLength = rawAddress.length * 8;
        let bit;
        let nodeNumber = 0;
        let offset;
        let depth = 0;
        if (rawAddress.length === 4) {
          nodeNumber = this.ipv4StartNodeNumber;
        }
        for (; depth < bitLength && nodeNumber < nodeCount; depth++) {
          bit = ip_1.default.bitAt(rawAddress, depth);
          offset = nodeNumber * this.metadata.nodeByteSize;
          nodeNumber = bit ? this.walker.right(offset) : this.walker.left(offset);
        }
        if (nodeNumber > nodeCount) {
          return [nodeNumber, depth];
        }
        return [null, depth];
      }
      resolveDataPointer(pointer) {
        const resolved = pointer - this.metadata.nodeCount + this.metadata.searchTreeSize;
        return this.decoder.decodeFast(resolved).value;
      }
      ipv4Start() {
        if (this.metadata.ipVersion === 4) {
          return 0;
        }
        const nodeCount = this.metadata.nodeCount;
        let pointer = 0;
        let i = 0;
        for (; i < 96 && pointer < nodeCount; i++) {
          const offset = pointer * this.metadata.nodeByteSize;
          pointer = this.walker.left(offset);
        }
        return pointer;
      }
    };
    exports.Reader = Reader2;
    __exportStar(require_response(), exports);
  }
});

// enrichment-worker.js
var import_mmdb_lib = __toESM(require_lib());
// ── Inlined h3-js@4.1.0 (latLngToCell only), bundled via esbuild ──────────────
// Scope-isolated in an IIFE so its esbuild helper vars don't collide with the
// worker's own esbuild helpers (__create, __commonJS, etc.).
var __h3_latLngToCell = (function () {
var __create = Object.create;
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __getProtoOf = Object.getPrototypeOf;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __commonJS = (cb, mod) => function __require() {
  return mod || (0, cb[__getOwnPropNames(cb)[0]])((mod = { exports: {} }).exports, mod), mod.exports;
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toESM = (mod, isNodeMode, target) => (target = mod != null ? __create(__getProtoOf(mod)) : {}, __copyProps(
  // If the importer is in node compatibility mode or this is not an ESM
  // file that has been converted to a CommonJS file using a Babel-
  // compatible transform (i.e. "__esModule" has not been set), then set
  // "default" to the CommonJS "module.exports" for node compatibility.
  isNodeMode || !mod || !mod.__esModule ? __defProp(target, "default", { value: mod, enumerable: true }) : target,
  mod
));

// node_modules/h3-js/dist/browser/h3-js.js
var require_h3_js = __commonJS({
  "node_modules/h3-js/dist/browser/h3-js.js"(exports) {
    var libh3 = (function(libh32) {
      libh32 = libh32 || {};
      var Module = typeof libh32 !== "undefined" ? libh32 : {};
      var moduleOverrides = {};
      var key;
      for (key in Module) {
        if (Module.hasOwnProperty(key)) {
          moduleOverrides[key] = Module[key];
        }
      }
      var arguments_ = [];
      var scriptDirectory = "";
      function locateFile(path) {
        if (Module["locateFile"]) {
          return Module["locateFile"](path, scriptDirectory);
        }
        return scriptDirectory + path;
      }
      var readAsync;
      {
        if (typeof document !== "undefined" && document.currentScript) {
          scriptDirectory = document.currentScript.src;
        }
        if (scriptDirectory.indexOf("blob:") !== 0) {
          scriptDirectory = scriptDirectory.substr(0, scriptDirectory.lastIndexOf("/") + 1);
        } else {
          scriptDirectory = "";
        }
        readAsync = function readAsync2(url, onload, onerror) {
          var xhr = new XMLHttpRequest();
          xhr.open("GET", url, true);
          xhr.responseType = "arraybuffer";
          xhr.onload = function xhr_onload() {
            if (xhr.status == 200 || xhr.status == 0 && xhr.response) {
              onload(xhr.response);
              return;
            }
            var data = tryParseAsDataURI(url);
            if (data) {
              onload(data.buffer);
              return;
            }
            onerror();
          };
          xhr.onerror = onerror;
          xhr.send(null);
        };
      }
      var out = Module["print"] || console.log.bind(console);
      var err = Module["printErr"] || console.warn.bind(console);
      for (key in moduleOverrides) {
        if (moduleOverrides.hasOwnProperty(key)) {
          Module[key] = moduleOverrides[key];
        }
      }
      moduleOverrides = null;
      if (Module["arguments"]) {
        arguments_ = Module["arguments"];
      }
      var tempRet0 = 0;
      var setTempRet0 = function(value) {
        tempRet0 = value;
      };
      var getTempRet0 = function() {
        return tempRet0;
      };
      var GLOBAL_BASE = 8;
      function setValue(ptr, value, type, noSafe) {
        type = type || "i8";
        if (type.charAt(type.length - 1) === "*") {
          type = "i32";
        }
        switch (type) {
          case "i1":
            HEAP8[ptr >> 0] = value;
            break;
          case "i8":
            HEAP8[ptr >> 0] = value;
            break;
          case "i16":
            HEAP16[ptr >> 1] = value;
            break;
          case "i32":
            HEAP32[ptr >> 2] = value;
            break;
          case "i64":
            tempI64 = [value >>> 0, (tempDouble = value, +Math_abs(tempDouble) >= 1 ? tempDouble > 0 ? (Math_min(+Math_floor(tempDouble / 4294967296), 4294967295) | 0) >>> 0 : ~~+Math_ceil((tempDouble - +(~~tempDouble >>> 0)) / 4294967296) >>> 0 : 0)], HEAP32[ptr >> 2] = tempI64[0], HEAP32[ptr + 4 >> 2] = tempI64[1];
            break;
          case "float":
            HEAPF32[ptr >> 2] = value;
            break;
          case "double":
            HEAPF64[ptr >> 3] = value;
            break;
          default:
            abort("invalid type for setValue: " + type);
        }
      }
      function getValue(ptr, type, noSafe) {
        type = type || "i8";
        if (type.charAt(type.length - 1) === "*") {
          type = "i32";
        }
        switch (type) {
          case "i1":
            return HEAP8[ptr >> 0];
          case "i8":
            return HEAP8[ptr >> 0];
          case "i16":
            return HEAP16[ptr >> 1];
          case "i32":
            return HEAP32[ptr >> 2];
          case "i64":
            return HEAP32[ptr >> 2];
          case "float":
            return HEAPF32[ptr >> 2];
          case "double":
            return HEAPF64[ptr >> 3];
          default:
            abort("invalid type for getValue: " + type);
        }
        return null;
      }
      var ABORT = false;
      function assert(condition, text) {
        if (!condition) {
          abort("Assertion failed: " + text);
        }
      }
      function getCFunc(ident) {
        var func = Module["_" + ident];
        assert(func, "Cannot call unknown function " + ident + ", make sure it is exported");
        return func;
      }
      function ccall(ident, returnType, argTypes, args, opts) {
        var toC = {
          "string": function(str) {
            var ret2 = 0;
            if (str !== null && str !== void 0 && str !== 0) {
              var len = (str.length << 2) + 1;
              ret2 = stackAlloc(len);
              stringToUTF8(str, ret2, len);
            }
            return ret2;
          },
          "array": function(arr) {
            var ret2 = stackAlloc(arr.length);
            writeArrayToMemory(arr, ret2);
            return ret2;
          }
        };
        function convertReturnValue(ret2) {
          if (returnType === "string") {
            return UTF8ToString(ret2);
          }
          if (returnType === "boolean") {
            return Boolean(ret2);
          }
          return ret2;
        }
        var func = getCFunc(ident);
        var cArgs = [];
        var stack = 0;
        if (args) {
          for (var i = 0; i < args.length; i++) {
            var converter = toC[argTypes[i]];
            if (converter) {
              if (stack === 0) {
                stack = stackSave();
              }
              cArgs[i] = converter(args[i]);
            } else {
              cArgs[i] = args[i];
            }
          }
        }
        var ret = func.apply(null, cArgs);
        ret = convertReturnValue(ret);
        if (stack !== 0) {
          stackRestore(stack);
        }
        return ret;
      }
      function cwrap(ident, returnType, argTypes, opts) {
        argTypes = argTypes || [];
        var numericArgs = argTypes.every(function(type) {
          return type === "number";
        });
        var numericRet = returnType !== "string";
        if (numericRet && numericArgs && !opts) {
          return getCFunc(ident);
        }
        return function() {
          return ccall(ident, returnType, argTypes, arguments, opts);
        };
      }
      var UTF8Decoder = typeof TextDecoder !== "undefined" ? new TextDecoder("utf8") : void 0;
      function UTF8ArrayToString(u8Array, idx, maxBytesToRead) {
        var endIdx = idx + maxBytesToRead;
        var endPtr = idx;
        while (u8Array[endPtr] && !(endPtr >= endIdx)) {
          ++endPtr;
        }
        if (endPtr - idx > 16 && u8Array.subarray && UTF8Decoder) {
          return UTF8Decoder.decode(u8Array.subarray(idx, endPtr));
        } else {
          var str = "";
          while (idx < endPtr) {
            var u0 = u8Array[idx++];
            if (!(u0 & 128)) {
              str += String.fromCharCode(u0);
              continue;
            }
            var u1 = u8Array[idx++] & 63;
            if ((u0 & 224) == 192) {
              str += String.fromCharCode((u0 & 31) << 6 | u1);
              continue;
            }
            var u2 = u8Array[idx++] & 63;
            if ((u0 & 240) == 224) {
              u0 = (u0 & 15) << 12 | u1 << 6 | u2;
            } else {
              u0 = (u0 & 7) << 18 | u1 << 12 | u2 << 6 | u8Array[idx++] & 63;
            }
            if (u0 < 65536) {
              str += String.fromCharCode(u0);
            } else {
              var ch = u0 - 65536;
              str += String.fromCharCode(55296 | ch >> 10, 56320 | ch & 1023);
            }
          }
        }
        return str;
      }
      function UTF8ToString(ptr, maxBytesToRead) {
        return ptr ? UTF8ArrayToString(HEAPU8, ptr, maxBytesToRead) : "";
      }
      function stringToUTF8Array(str, outU8Array, outIdx, maxBytesToWrite) {
        if (!(maxBytesToWrite > 0)) {
          return 0;
        }
        var startIdx = outIdx;
        var endIdx = outIdx + maxBytesToWrite - 1;
        for (var i = 0; i < str.length; ++i) {
          var u = str.charCodeAt(i);
          if (u >= 55296 && u <= 57343) {
            var u1 = str.charCodeAt(++i);
            u = 65536 + ((u & 1023) << 10) | u1 & 1023;
          }
          if (u <= 127) {
            if (outIdx >= endIdx) {
              break;
            }
            outU8Array[outIdx++] = u;
          } else if (u <= 2047) {
            if (outIdx + 1 >= endIdx) {
              break;
            }
            outU8Array[outIdx++] = 192 | u >> 6;
            outU8Array[outIdx++] = 128 | u & 63;
          } else if (u <= 65535) {
            if (outIdx + 2 >= endIdx) {
              break;
            }
            outU8Array[outIdx++] = 224 | u >> 12;
            outU8Array[outIdx++] = 128 | u >> 6 & 63;
            outU8Array[outIdx++] = 128 | u & 63;
          } else {
            if (outIdx + 3 >= endIdx) {
              break;
            }
            outU8Array[outIdx++] = 240 | u >> 18;
            outU8Array[outIdx++] = 128 | u >> 12 & 63;
            outU8Array[outIdx++] = 128 | u >> 6 & 63;
            outU8Array[outIdx++] = 128 | u & 63;
          }
        }
        outU8Array[outIdx] = 0;
        return outIdx - startIdx;
      }
      function stringToUTF8(str, outPtr, maxBytesToWrite) {
        return stringToUTF8Array(str, HEAPU8, outPtr, maxBytesToWrite);
      }
      var UTF16Decoder = typeof TextDecoder !== "undefined" ? new TextDecoder("utf-16le") : void 0;
      function writeArrayToMemory(array, buffer2) {
        HEAP8.set(array, buffer2);
      }
      function alignUp(x, multiple) {
        if (x % multiple > 0) {
          x += multiple - x % multiple;
        }
        return x;
      }
      var buffer, HEAP8, HEAPU8, HEAP16, HEAPU16, HEAP32, HEAPU32, HEAPF32, HEAPF64;
      function updateGlobalBufferAndViews(buf) {
        buffer = buf;
        Module["HEAP8"] = HEAP8 = new Int8Array(buf);
        Module["HEAP16"] = HEAP16 = new Int16Array(buf);
        Module["HEAP32"] = HEAP32 = new Int32Array(buf);
        Module["HEAPU8"] = HEAPU8 = new Uint8Array(buf);
        Module["HEAPU16"] = HEAPU16 = new Uint16Array(buf);
        Module["HEAPU32"] = HEAPU32 = new Uint32Array(buf);
        Module["HEAPF32"] = HEAPF32 = new Float32Array(buf);
        Module["HEAPF64"] = HEAPF64 = new Float64Array(buf);
      }
      var DYNAMIC_BASE = 5267040, DYNAMICTOP_PTR = 24128;
      var INITIAL_TOTAL_MEMORY = Module["TOTAL_MEMORY"] || 33554432;
      if (Module["buffer"]) {
        buffer = Module["buffer"];
      } else {
        buffer = new ArrayBuffer(INITIAL_TOTAL_MEMORY);
      }
      INITIAL_TOTAL_MEMORY = buffer.byteLength;
      updateGlobalBufferAndViews(buffer);
      HEAP32[DYNAMICTOP_PTR >> 2] = DYNAMIC_BASE;
      function callRuntimeCallbacks(callbacks) {
        while (callbacks.length > 0) {
          var callback = callbacks.shift();
          if (typeof callback == "function") {
            callback();
            continue;
          }
          var func = callback.func;
          if (typeof func === "number") {
            if (callback.arg === void 0) {
              Module["dynCall_v"](func);
            } else {
              Module["dynCall_vi"](func, callback.arg);
            }
          } else {
            func(callback.arg === void 0 ? null : callback.arg);
          }
        }
      }
      var __ATPRERUN__ = [];
      var __ATINIT__ = [];
      var __ATMAIN__ = [];
      var __ATPOSTRUN__ = [];
      function preRun() {
        if (Module["preRun"]) {
          if (typeof Module["preRun"] == "function") {
            Module["preRun"] = [Module["preRun"]];
          }
          while (Module["preRun"].length) {
            addOnPreRun(Module["preRun"].shift());
          }
        }
        callRuntimeCallbacks(__ATPRERUN__);
      }
      function initRuntime() {
        callRuntimeCallbacks(__ATINIT__);
      }
      function preMain() {
        callRuntimeCallbacks(__ATMAIN__);
      }
      function postRun() {
        if (Module["postRun"]) {
          if (typeof Module["postRun"] == "function") {
            Module["postRun"] = [Module["postRun"]];
          }
          while (Module["postRun"].length) {
            addOnPostRun(Module["postRun"].shift());
          }
        }
        callRuntimeCallbacks(__ATPOSTRUN__);
      }
      function addOnPreRun(cb) {
        __ATPRERUN__.unshift(cb);
      }
      function addOnPostRun(cb) {
        __ATPOSTRUN__.unshift(cb);
      }
      var Math_abs = Math.abs;
      var Math_ceil = Math.ceil;
      var Math_floor = Math.floor;
      var Math_min = Math.min;
      var runDependencies = 0;
      var runDependencyWatcher = null;
      var dependenciesFulfilled = null;
      function addRunDependency(id) {
        runDependencies++;
        if (Module["monitorRunDependencies"]) {
          Module["monitorRunDependencies"](runDependencies);
        }
      }
      function removeRunDependency(id) {
        runDependencies--;
        if (Module["monitorRunDependencies"]) {
          Module["monitorRunDependencies"](runDependencies);
        }
        if (runDependencies == 0) {
          if (runDependencyWatcher !== null) {
            clearInterval(runDependencyWatcher);
            runDependencyWatcher = null;
          }
          if (dependenciesFulfilled) {
            var callback = dependenciesFulfilled;
            dependenciesFulfilled = null;
            callback();
          }
        }
      }
      Module["preloadedImages"] = {};
      Module["preloadedAudios"] = {};
      var memoryInitializer = null;
      var dataURIPrefix = "data:application/octet-stream;base64,";
      function isDataURI(filename) {
        return String.prototype.startsWith ? filename.startsWith(dataURIPrefix) : filename.indexOf(dataURIPrefix) === 0;
      }
      var tempDouble;
      var tempI64;
      memoryInitializer = "data:application/octet-stream;base64,AAAAAAAAAAAAAAAAAQAAAAIAAAADAAAABAAAAAUAAAAGAAAAAQAAAAQAAAADAAAABgAAAAUAAAACAAAAAAAAAAIAAAADAAAAAQAAAAQAAAAGAAAAAAAAAAUAAAADAAAABgAAAAQAAAAFAAAAAAAAAAEAAAACAAAABAAAAAUAAAAGAAAAAAAAAAIAAAADAAAAAQAAAAUAAAACAAAAAAAAAAEAAAADAAAABgAAAAQAAAAGAAAAAAAAAAUAAAACAAAAAQAAAAQAAAADAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAEAAAAAAAAABQAAAAAAAAAAAAAAAAAAAAIAAAADAAAAAAAAAAAAAAACAAAAAAAAAAEAAAADAAAAAwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAAABAAAAAYAAAAAAAAABQAAAAAAAAAAAAAABAAAAAUAAAAAAAAAAAAAAAAAAAACAAAAAAAAAAYAAAAAAAAABgAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAgAAAAMAAAAEAAAABQAAAAYAAAABAAAAAgAAAAMAAAAEAAAABQAAAAYAAAAAAAAAAgAAAAMAAAAEAAAABQAAAAYAAAAAAAAAAQAAAAMAAAAEAAAABQAAAAYAAAAAAAAAAQAAAAIAAAAEAAAABQAAAAYAAAAAAAAAAQAAAAIAAAADAAAABQAAAAYAAAAAAAAAAQAAAAIAAAADAAAABAAAAAYAAAAAAAAAAQAAAAIAAAADAAAABAAAAAUAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAwAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAgAAAAIAAAAAAAAAAAAAAAYAAAAAAAAAAwAAAAIAAAADAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAAFAAAABAAAAAAAAAABAAAAAAAAAAAAAAAFAAAABQAAAAAAAAAAAAAAAAAAAAYAAAAAAAAABAAAAAAAAAAGAAAAAAAAAAAAAAAAAAAAAAAAAAEAAAAFAAAAAgAAAAQAAAADAAAACAAAAAEAAAAHAAAABgAAAAkAAAAAAAAAAwAAAAIAAAACAAAABgAAAAoAAAALAAAAAAAAAAEAAAAFAAAAAwAAAA0AAAABAAAABwAAAAQAAAAMAAAAAAAAAAQAAAB/AAAADwAAAAgAAAADAAAAAAAAAAwAAAAFAAAAAgAAABIAAAAKAAAACAAAAAAAAAAQAAAABgAAAA4AAAALAAAAEQAAAAEAAAAJAAAAAgAAAAcAAAAVAAAACQAAABMAAAADAAAADQAAAAEAAAAIAAAABQAAABYAAAAQAAAABAAAAAAAAAAPAAAACQAAABMAAAAOAAAAFAAAAAEAAAAHAAAABgAAAAoAAAALAAAAGAAAABcAAAAFAAAAAgAAABIAAAALAAAAEQAAABcAAAAZAAAAAgAAAAYAAAAKAAAADAAAABwAAAANAAAAGgAAAAQAAAAPAAAAAwAAAA0AAAAaAAAAFQAAAB0AAAADAAAADAAAAAcAAAAOAAAAfwAAABEAAAAbAAAACQAAABQAAAAGAAAADwAAABYAAAAcAAAAHwAAAAQAAAAIAAAADAAAABAAAAASAAAAIQAAAB4AAAAIAAAABQAAABYAAAARAAAACwAAAA4AAAAGAAAAIwAAABkAAAAbAAAAEgAAABgAAAAeAAAAIAAAAAUAAAAKAAAAEAAAABMAAAAiAAAAFAAAACQAAAAHAAAAFQAAAAkAAAAUAAAADgAAABMAAAAJAAAAKAAAABsAAAAkAAAAFQAAACYAAAATAAAAIgAAAA0AAAAdAAAABwAAABYAAAAQAAAAKQAAACEAAAAPAAAACAAAAB8AAAAXAAAAGAAAAAsAAAAKAAAAJwAAACUAAAAZAAAAGAAAAH8AAAAgAAAAJQAAAAoAAAAXAAAAEgAAABkAAAAXAAAAEQAAAAsAAAAtAAAAJwAAACMAAAAaAAAAKgAAAB0AAAArAAAADAAAABwAAAANAAAAGwAAACgAAAAjAAAALgAAAA4AAAAUAAAAEQAAABwAAAAfAAAAKgAAACwAAAAMAAAADwAAABoAAAAdAAAAKwAAACYAAAAvAAAADQAAABoAAAAVAAAAHgAAACAAAAAwAAAAMgAAABAAAAASAAAAIQAAAB8AAAApAAAALAAAADUAAAAPAAAAFgAAABwAAAAgAAAAHgAAABgAAAASAAAANAAAADIAAAAlAAAAIQAAAB4AAAAxAAAAMAAAABYAAAAQAAAAKQAAACIAAAATAAAAJgAAABUAAAA2AAAAJAAAADMAAAAjAAAALgAAAC0AAAA4AAAAEQAAABsAAAAZAAAAJAAAABQAAAAiAAAAEwAAADcAAAAoAAAANgAAACUAAAAnAAAANAAAADkAAAAYAAAAFwAAACAAAAAmAAAAfwAAACIAAAAzAAAAHQAAAC8AAAAVAAAAJwAAACUAAAAZAAAAFwAAADsAAAA5AAAALQAAACgAAAAbAAAAJAAAABQAAAA8AAAALgAAADcAAAApAAAAMQAAADUAAAA9AAAAFgAAACEAAAAfAAAAKgAAADoAAAArAAAAPgAAABwAAAAsAAAAGgAAACsAAAA+AAAALwAAAEAAAAAaAAAAKgAAAB0AAAAsAAAANQAAADoAAABBAAAAHAAAAB8AAAAqAAAALQAAACcAAAAjAAAAGQAAAD8AAAA7AAAAOAAAAC4AAAA8AAAAOAAAAEQAAAAbAAAAKAAAACMAAAAvAAAAJgAAACsAAAAdAAAARQAAADMAAABAAAAAMAAAADEAAAAeAAAAIQAAAEMAAABCAAAAMgAAADEAAAB/AAAAPQAAAEIAAAAhAAAAMAAAACkAAAAyAAAAMAAAACAAAAAeAAAARgAAAEMAAAA0AAAAMwAAAEUAAAA2AAAARwAAACYAAAAvAAAAIgAAADQAAAA5AAAARgAAAEoAAAAgAAAAJQAAADIAAAA1AAAAPQAAAEEAAABLAAAAHwAAACkAAAAsAAAANgAAAEcAAAA3AAAASQAAACIAAAAzAAAAJAAAADcAAAAoAAAANgAAACQAAABIAAAAPAAAAEkAAAA4AAAARAAAAD8AAABNAAAAIwAAAC4AAAAtAAAAOQAAADsAAABKAAAATgAAACUAAAAnAAAANAAAADoAAAB/AAAAPgAAAEwAAAAsAAAAQQAAACoAAAA7AAAAPwAAAE4AAABPAAAAJwAAAC0AAAA5AAAAPAAAAEgAAABEAAAAUAAAACgAAAA3AAAALgAAAD0AAAA1AAAAMQAAACkAAABRAAAASwAAAEIAAAA+AAAAKwAAADoAAAAqAAAAUgAAAEAAAABMAAAAPwAAAH8AAAA4AAAALQAAAE8AAAA7AAAATQAAAEAAAAAvAAAAPgAAACsAAABUAAAARQAAAFIAAABBAAAAOgAAADUAAAAsAAAAVgAAAEwAAABLAAAAQgAAAEMAAABRAAAAVQAAADEAAAAwAAAAPQAAAEMAAABCAAAAMgAAADAAAABXAAAAVQAAAEYAAABEAAAAOAAAADwAAAAuAAAAWgAAAE0AAABQAAAARQAAADMAAABAAAAALwAAAFkAAABHAAAAVAAAAEYAAABDAAAANAAAADIAAABTAAAAVwAAAEoAAABHAAAAWQAAAEkAAABbAAAAMwAAAEUAAAA2AAAASAAAAH8AAABJAAAANwAAAFAAAAA8AAAAWAAAAEkAAABbAAAASAAAAFgAAAA2AAAARwAAADcAAABKAAAATgAAAFMAAABcAAAANAAAADkAAABGAAAASwAAAEEAAAA9AAAANQAAAF4AAABWAAAAUQAAAEwAAABWAAAAUgAAAGAAAAA6AAAAQQAAAD4AAABNAAAAPwAAAEQAAAA4AAAAXQAAAE8AAABaAAAATgAAAEoAAAA7AAAAOQAAAF8AAABcAAAATwAAAE8AAABOAAAAPwAAADsAAABdAAAAXwAAAE0AAABQAAAARAAAAEgAAAA8AAAAYwAAAFoAAABYAAAAUQAAAFUAAABeAAAAZQAAAD0AAABCAAAASwAAAFIAAABgAAAAVAAAAGIAAAA+AAAATAAAAEAAAABTAAAAfwAAAEoAAABGAAAAZAAAAFcAAABcAAAAVAAAAEUAAABSAAAAQAAAAGEAAABZAAAAYgAAAFUAAABXAAAAZQAAAGYAAABCAAAAQwAAAFEAAABWAAAATAAAAEsAAABBAAAAaAAAAGAAAABeAAAAVwAAAFMAAABmAAAAZAAAAEMAAABGAAAAVQAAAFgAAABIAAAAWwAAAEkAAABjAAAAUAAAAGkAAABZAAAAYQAAAFsAAABnAAAARQAAAFQAAABHAAAAWgAAAE0AAABQAAAARAAAAGoAAABdAAAAYwAAAFsAAABJAAAAWQAAAEcAAABpAAAAWAAAAGcAAABcAAAAUwAAAE4AAABKAAAAbAAAAGQAAABfAAAAXQAAAE8AAABaAAAATQAAAG0AAABfAAAAagAAAF4AAABWAAAAUQAAAEsAAABrAAAAaAAAAGUAAABfAAAAXAAAAE8AAABOAAAAbQAAAGwAAABdAAAAYAAAAGgAAABiAAAAbgAAAEwAAABWAAAAUgAAAGEAAAB/AAAAYgAAAFQAAABnAAAAWQAAAG8AAABiAAAAbgAAAGEAAABvAAAAUgAAAGAAAABUAAAAYwAAAFAAAABpAAAAWAAAAGoAAABaAAAAcQAAAGQAAABmAAAAUwAAAFcAAABsAAAAcgAAAFwAAABlAAAAZgAAAGsAAABwAAAAUQAAAFUAAABeAAAAZgAAAGUAAABXAAAAVQAAAHIAAABwAAAAZAAAAGcAAABbAAAAYQAAAFkAAAB0AAAAaQAAAG8AAABoAAAAawAAAG4AAABzAAAAVgAAAF4AAABgAAAAaQAAAFgAAABnAAAAWwAAAHEAAABjAAAAdAAAAGoAAABdAAAAYwAAAFoAAAB1AAAAbQAAAHEAAABrAAAAfwAAAGUAAABeAAAAcwAAAGgAAABwAAAAbAAAAGQAAABfAAAAXAAAAHYAAAByAAAAbQAAAG0AAABsAAAAXQAAAF8AAAB1AAAAdgAAAGoAAABuAAAAYgAAAGgAAABgAAAAdwAAAG8AAABzAAAAbwAAAGEAAABuAAAAYgAAAHQAAABnAAAAdwAAAHAAAABrAAAAZgAAAGUAAAB4AAAAcwAAAHIAAABxAAAAYwAAAHQAAABpAAAAdQAAAGoAAAB5AAAAcgAAAHAAAABkAAAAZgAAAHYAAAB4AAAAbAAAAHMAAABuAAAAawAAAGgAAAB4AAAAdwAAAHAAAAB0AAAAZwAAAHcAAABvAAAAcQAAAGkAAAB5AAAAdQAAAH8AAABtAAAAdgAAAHEAAAB5AAAAagAAAHYAAAB4AAAAbAAAAHIAAAB1AAAAeQAAAG0AAAB3AAAAbwAAAHMAAABuAAAAeQAAAHQAAAB4AAAAeAAAAHMAAAByAAAAcAAAAHkAAAB3AAAAdgAAAHkAAAB0AAAAeAAAAHcAAAB1AAAAcQAAAHYAAAAAAAAAAAAAAAAAAAAFAAAAAAAAAAAAAAABAAAABQAAAAEAAAAAAAAAAAAAAAEAAAAAAAAAAQAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAFAAAAAAAAAAAAAAAFAAAAAAAAAAAAAAACAAAABQAAAAEAAAAAAAAA/////wEAAAAAAAAAAwAAAAQAAAACAAAAAAAAAAAAAAABAAAAAAAAAAEAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAMAAAAFAAAABQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAUAAAAAAAAAAAAAAAUAAAAAAAAAAAAAAAAAAAAFAAAAAQAAAAAAAAAAAAAAAQAAAAMAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAEAAAADAAAAAAAAAAAAAAABAAAAAAAAAAMAAAADAAAAAwAAAAAAAAAAAAAAAAAAAAAAAAAFAAAAAAAAAAAAAAADAAAABQAAAAEAAAAAAAAAAAAAAAEAAAAAAAAAAQAAAAAAAAABAAAAAAAAAP////8DAAAAAAAAAAUAAAACAAAAAAAAAAAAAAAFAAAAAAAAAAAAAAAEAAAABQAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAUAAAAAAAAAAAAAAAMAAAADAAAAAwAAAAMAAAAAAAAAAwAAAAAAAAAAAAAAAAAAAAMAAAAFAAAABQAAAAAAAAAAAAAAAwAAAAMAAAADAAAAAAAAAAAAAAAAAAAAAAAAAAMAAAADAAAAAwAAAAAAAAADAAAAAAAAAAAAAAAAAAAAAAAAAAMAAAAFAAAABQAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAQAAAAAAAAABAAAAAAAAAAMAAAADAAAAAwAAAAAAAAADAAAAAAAAAAAAAAD/////AwAAAAAAAAAFAAAAAgAAAAAAAAAAAAAAAAAAAAAAAAADAAAAAAAAAAAAAAADAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAFAAAAAAAAAAAAAAADAAAAAAAAAAAAAAAAAAAAAwAAAAMAAAAAAAAAAAAAAAEAAAAAAAAAAQAAAAAAAAABAAAAAAAAAAAAAAABAAAAAwAAAAAAAAAAAAAAAQAAAAAAAAADAAAAAwAAAAMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAUAAAAAAAAAAAAAAAMAAAADAAAAAwAAAAMAAAAAAAAAAwAAAAAAAAAAAAAAAQAAAAMAAAAAAAAAAAAAAAEAAAAAAAAAAwAAAAMAAAADAAAAAwAAAAAAAAADAAAAAAAAAAAAAAADAAAAAAAAAAMAAAAAAAAAAwAAAAAAAAAAAAAAAAAAAAMAAAAAAAAAAAAAAAMAAAAAAAAAAwAAAAAAAAAAAAAAAAAAAAMAAAADAAAAAAAAAP////8DAAAAAAAAAAUAAAACAAAAAAAAAAAAAAADAAAAAAAAAAAAAAADAAAAAwAAAAAAAAAAAAAAAwAAAAAAAAAAAAAAAwAAAAMAAAAAAAAAAAAAAAAAAAAAAAAAAwAAAAUAAAAFAAAAAAAAAAAAAAAAAAAAAAAAAAMAAAAFAAAABQAAAAAAAAAAAAAAAwAAAAMAAAADAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAwAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAAwAAAAAAAAAAAAAAAwAAAAMAAAAAAAAAAAAAAAAAAAADAAAAAAAAAAMAAAAAAAAAAAAAAAMAAAADAAAAAwAAAAAAAAADAAAAAAAAAAAAAAADAAAAAwAAAAMAAAAAAAAAAwAAAAAAAAAAAAAA/////wMAAAAAAAAABQAAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAwAAAAAAAAAAAAAAAwAAAAAAAAADAAAAAAAAAAAAAAAAAAAAAwAAAAMAAAAAAAAAAAAAAAMAAAAAAAAAAwAAAAAAAAADAAAAAAAAAAMAAAADAAAAAwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwAAAAAAAAADAAAAAAAAAAMAAAAAAAAAAAAAAAMAAAAAAAAAAAAAAAMAAAADAAAAAAAAAAMAAAADAAAAAwAAAAAAAAAAAAAAAwAAAAAAAAAAAAAAAAAAAAMAAAAAAAAAAwAAAAAAAAAAAAAA/////wMAAAAAAAAABQAAAAIAAAAAAAAAAAAAAAMAAAADAAAAAwAAAAMAAAADAAAAAAAAAAAAAAADAAAAAwAAAAMAAAADAAAAAwAAAAAAAAAAAAAAAwAAAAMAAAADAAAAAwAAAAAAAAADAAAAAAAAAAMAAAADAAAAAwAAAAMAAAAAAAAAAwAAAAAAAAD/////AwAAAAAAAAAFAAAAAgAAAAAAAAAAAAAAAAAAAAAAAAADAAAAAAAAAAAAAAADAAAAAAAAAAMAAAADAAAAAwAAAAAAAAADAAAAAAAAAAAAAAADAAAAAAAAAAAAAAAAAAAAAwAAAAMAAAAAAAAAAwAAAAAAAAAAAAAAAwAAAAMAAAAAAAAAAAAAAAMAAAADAAAAAwAAAAAAAAAAAAAAAAAAAAAAAAADAAAAAAAAAAAAAAADAAAAAwAAAAAAAAAAAAAAAAAAAAMAAAAAAAAAAAAAAAMAAAADAAAAAAAAAAAAAAAAAAAAAwAAAAAAAAADAAAAAAAAAAAAAAD/////AwAAAAAAAAAFAAAAAgAAAAAAAAAAAAAAAwAAAAMAAAADAAAAAAAAAAAAAAADAAAAAAAAAAMAAAADAAAAAwAAAAAAAAAAAAAAAwAAAAAAAAAAAAAAAAAAAAMAAAAAAAAAAAAAAAMAAAAAAAAAAwAAAAAAAAAAAAAAAAAAAAMAAAADAAAAAAAAAAAAAAAAAAAAAwAAAAAAAAAFAAAAAAAAAAAAAAADAAAAAwAAAAMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAAADAAAAAQAAAAAAAAABAAAAAAAAAAAAAAABAAAAAwAAAAEAAAAAAAAAAQAAAAAAAAAAAAAAAwAAAAAAAAADAAAAAAAAAAMAAAAAAAAAAAAAAAMAAAAAAAAAAwAAAAAAAAADAAAAAAAAAP////8DAAAAAAAAAAUAAAACAAAAAAAAAAAAAAAAAAAAAwAAAAAAAAAAAAAAAwAAAAMAAAAAAAAAAAAAAAAAAAADAAAAAAAAAAMAAAAAAAAAAAAAAAMAAAAAAAAAAAAAAAMAAAADAAAAAAAAAAAAAAADAAAAAwAAAAMAAAADAAAAAwAAAAAAAAAAAAAAAAAAAAAAAAADAAAAAAAAAAUAAAAAAAAAAAAAAAMAAAADAAAAAwAAAAMAAAADAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAwAAAAMAAAADAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwAAAAAAAAAFAAAAAAAAAAAAAAAFAAAAAAAAAAAAAAAFAAAABQAAAAAAAAAAAAAAAAAAAAMAAAAAAAAAAAAAAAMAAAADAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAMAAAAAAAAAAwAAAAAAAAAAAAAA/////wMAAAAAAAAABQAAAAIAAAAAAAAAAAAAAAMAAAADAAAAAwAAAAAAAAAAAAAAAwAAAAAAAAAFAAAAAAAAAAAAAAAFAAAABQAAAAAAAAAAAAAAAAAAAAEAAAADAAAAAQAAAAAAAAABAAAAAAAAAAMAAAADAAAAAwAAAAAAAAAAAAAAAwAAAAAAAAADAAAAAwAAAAMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAAADAAAAAQAAAAAAAAABAAAAAAAAAAMAAAADAAAAAwAAAAMAAAADAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAEAAAAAAAAAAwAAAAUAAAABAAAAAAAAAP////8DAAAAAAAAAAUAAAACAAAAAAAAAAAAAAAFAAAAAAAAAAAAAAAFAAAABQAAAAAAAAAAAAAAAAAAAAEAAAAAAAAABAAAAAUAAAABAAAAAAAAAAMAAAADAAAAAwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAMAAAAAAAAABQAAAAAAAAAAAAAAAAAAAAAAAAADAAAAAAAAAAUAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAIAAAAFAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAEAAAADAAAAAQAAAAAAAAABAAAAAAAAAAUAAAAAAAAAAAAAAAUAAAAFAAAAAAAAAAAAAAD/////AQAAAAAAAAADAAAABAAAAAIAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAUAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAAAAAAAFAAAAAAAAAAAAAAAFAAAABQAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAQAAAAUAAAABAAAAAAAAAAAAAAABAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAAAAEAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIAAAAAAAAAAAAAAAEAAAD//////////wEAAAABAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAQAAAAEAAAAAAAAAAAAAAAAAAAADAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwAAAAEAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAsAAAACAAAAAAAAAAAAAAABAAAAAgAAAAYAAAAEAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAgAAAAAAAAABAAAAAQAAAAAAAAAAAAAAAAAAAAcAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAACAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAEAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAYAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAAKAAAAAgAAAAAAAAAAAAAAAQAAAAEAAAAFAAAABgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAALAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAEAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAMAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAAABAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAUAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAAAAAAABwAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAsAAAABAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAHAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACgAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwAAAACAAAAAAAAAAAAAAABAAAAAwAAAAcAAAAGAAAAAQAAAAAAAAABAAAAAAAAAAAAAAAAAAAABwAAAAEAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAADAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAwAAAAAAAAABAAAAAQAAAAAAAAAAAAAAAAAAAAQAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAGAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAAFAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAADgAAAAIAAAAAAAAAAAAAAAEAAAAAAAAACQAAAAUAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAMAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACgAAAAEAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAAAAAAAAQAAAAEAAAAAAAAAAAAAAAAAAAAMAAAAAQAAAAEAAAAAAAAAAAAAAAAAAAAAAAAABwAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAsAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADQAAAAIAAAAAAAAAAAAAAAEAAAAEAAAACAAAAAoAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAALAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAACQAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAgAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAGAAAAAgAAAAAAAAAAAAAAAQAAAAsAAAAPAAAACAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAkAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAAOAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABQAAAAEAAAAAAAAAAQAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAQAAAAEAAAAAAAAAAAAAAAAAAAAIAAAAAQAAAAAAAAABAAAAAAAAAAAAAAAAAAAABQAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAHAAAAAgAAAAAAAAAAAAAAAQAAAAwAAAAQAAAADAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAoAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAJAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADQAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAAPAAAAAAAAAAEAAAABAAAAAAAAAAAAAAAAAAAADwAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAOAAAAAQAAAAEAAAAAAAAAAAAAAAAAAAAAAAAADQAAAAEAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAUAAAACAAAAAAAAAAAAAAABAAAACgAAABMAAAAIAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAkAAAABAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAAOAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAEQAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAwAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEQAAAAAAAAABAAAAAQAAAAAAAAAAAAAAAAAAAA8AAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAAQAAAAAQAAAAAAAAABAAAAAAAAAAAAAAAAAAAACQAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA8AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAANAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAAAAAIAAAAAAAAAAAAAAAEAAAANAAAAEQAAAA0AAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAARAAAAAQAAAAAAAAABAAAAAAAAAAAAAAAAAAAAEwAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAA4AAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAATAAAAAAAAAAEAAAABAAAAAAAAAAAAAAAAAAAAEQAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAA0AAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAARAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAkAAAACAAAAAAAAAAAAAAABAAAADgAAABIAAAAPAAAAAQAAAAAAAAABAAAAAAAAAAAAAAAAAAAADwAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABIAAAAAAAAAAQAAAAEAAAAAAAAAAAAAAAAAAAASAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAEwAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAAAAAABEAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAATAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEgAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAABIAAAABAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAATAAAAAgAAAAAAAAAAAAAAAQAAAP//////////EwAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAATAAAAAQAAAAAAAAABAAAAAAAAAAAAAAAAAAAAEgAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAASAAAAAAAAABgAAAAAAAAAIQAAAAAAAAAeAAAAAAAAACAAAAADAAAAMQAAAAEAAAAwAAAAAwAAADIAAAADAAAACAAAAAAAAAAFAAAABQAAAAoAAAAFAAAAFgAAAAAAAAAQAAAAAAAAABIAAAAAAAAAKQAAAAEAAAAhAAAAAAAAAB4AAAAAAAAABAAAAAAAAAAAAAAABQAAAAIAAAAFAAAADwAAAAEAAAAIAAAAAAAAAAUAAAAFAAAAHwAAAAEAAAAWAAAAAAAAABAAAAAAAAAAAgAAAAAAAAAGAAAAAAAAAA4AAAAAAAAACgAAAAAAAAALAAAAAAAAABEAAAADAAAAGAAAAAEAAAAXAAAAAwAAABkAAAADAAAAAAAAAAAAAAABAAAABQAAAAkAAAAFAAAABQAAAAAAAAACAAAAAAAAAAYAAAAAAAAAEgAAAAEAAAAKAAAAAAAAAAsAAAAAAAAABAAAAAEAAAADAAAABQAAAAcAAAAFAAAACAAAAAEAAAAAAAAAAAAAAAEAAAAFAAAAEAAAAAEAAAAFAAAAAAAAAAIAAAAAAAAABwAAAAAAAAAVAAAAAAAAACYAAAAAAAAACQAAAAAAAAATAAAAAAAAACIAAAADAAAADgAAAAEAAAAUAAAAAwAAACQAAAADAAAAAwAAAAAAAAANAAAABQAAAB0AAAAFAAAAAQAAAAAAAAAHAAAAAAAAABUAAAAAAAAABgAAAAEAAAAJAAAAAAAAABMAAAAAAAAABAAAAAIAAAAMAAAABQAAABoAAAAFAAAAAAAAAAEAAAADAAAAAAAAAA0AAAAFAAAAAgAAAAEAAAABAAAAAAAAAAcAAAAAAAAAGgAAAAAAAAAqAAAAAAAAADoAAAAAAAAAHQAAAAAAAAArAAAAAAAAAD4AAAADAAAAJgAAAAEAAAAvAAAAAwAAAEAAAAADAAAADAAAAAAAAAAcAAAABQAAACwAAAAFAAAADQAAAAAAAAAaAAAAAAAAACoAAAAAAAAAFQAAAAEAAAAdAAAAAAAAACsAAAAAAAAABAAAAAMAAAAPAAAABQAAAB8AAAAFAAAAAwAAAAEAAAAMAAAAAAAAABwAAAAFAAAABwAAAAEAAAANAAAAAAAAABoAAAAAAAAAHwAAAAAAAAApAAAAAAAAADEAAAAAAAAALAAAAAAAAAA1AAAAAAAAAD0AAAADAAAAOgAAAAEAAABBAAAAAwAAAEsAAAADAAAADwAAAAAAAAAWAAAABQAAACEAAAAFAAAAHAAAAAAAAAAfAAAAAAAAACkAAAAAAAAAKgAAAAEAAAAsAAAAAAAAADUAAAAAAAAABAAAAAQAAAAIAAAABQAAABAAAAAFAAAADAAAAAEAAAAPAAAAAAAAABYAAAAFAAAAGgAAAAEAAAAcAAAAAAAAAB8AAAAAAAAAMgAAAAAAAAAwAAAAAAAAADEAAAADAAAAIAAAAAAAAAAeAAAAAwAAACEAAAADAAAAGAAAAAMAAAASAAAAAwAAABAAAAADAAAARgAAAAAAAABDAAAAAAAAAEIAAAADAAAANAAAAAMAAAAyAAAAAAAAADAAAAAAAAAAJQAAAAMAAAAgAAAAAAAAAB4AAAADAAAAUwAAAAAAAABXAAAAAwAAAFUAAAADAAAASgAAAAMAAABGAAAAAAAAAEMAAAAAAAAAOQAAAAEAAAA0AAAAAwAAADIAAAAAAAAAGQAAAAAAAAAXAAAAAAAAABgAAAADAAAAEQAAAAAAAAALAAAAAwAAAAoAAAADAAAADgAAAAMAAAAGAAAAAwAAAAIAAAADAAAALQAAAAAAAAAnAAAAAAAAACUAAAADAAAAIwAAAAMAAAAZAAAAAAAAABcAAAAAAAAAGwAAAAMAAAARAAAAAAAAAAsAAAADAAAAPwAAAAAAAAA7AAAAAwAAADkAAAADAAAAOAAAAAMAAAAtAAAAAAAAACcAAAAAAAAALgAAAAMAAAAjAAAAAwAAABkAAAAAAAAAJAAAAAAAAAAUAAAAAAAAAA4AAAADAAAAIgAAAAAAAAATAAAAAwAAAAkAAAADAAAAJgAAAAMAAAAVAAAAAwAAAAcAAAADAAAANwAAAAAAAAAoAAAAAAAAABsAAAADAAAANgAAAAMAAAAkAAAAAAAAABQAAAAAAAAAMwAAAAMAAAAiAAAAAAAAABMAAAADAAAASAAAAAAAAAA8AAAAAwAAAC4AAAADAAAASQAAAAMAAAA3AAAAAAAAACgAAAAAAAAARwAAAAMAAAA2AAAAAwAAACQAAAAAAAAAQAAAAAAAAAAvAAAAAAAAACYAAAADAAAAPgAAAAAAAAArAAAAAwAAAB0AAAADAAAAOgAAAAMAAAAqAAAAAwAAABoAAAADAAAAVAAAAAAAAABFAAAAAAAAADMAAAADAAAAUgAAAAMAAABAAAAAAAAAAC8AAAAAAAAATAAAAAMAAAA+AAAAAAAAACsAAAADAAAAYQAAAAAAAABZAAAAAwAAAEcAAAADAAAAYgAAAAMAAABUAAAAAAAAAEUAAAAAAAAAYAAAAAMAAABSAAAAAwAAAEAAAAAAAAAASwAAAAAAAABBAAAAAAAAADoAAAADAAAAPQAAAAAAAAA1AAAAAwAAACwAAAADAAAAMQAAAAMAAAApAAAAAwAAAB8AAAADAAAAXgAAAAAAAABWAAAAAAAAAEwAAAADAAAAUQAAAAMAAABLAAAAAAAAAEEAAAAAAAAAQgAAAAMAAAA9AAAAAAAAADUAAAADAAAAawAAAAAAAABoAAAAAwAAAGAAAAADAAAAZQAAAAMAAABeAAAAAAAAAFYAAAAAAAAAVQAAAAMAAABRAAAAAwAAAEsAAAAAAAAAOQAAAAAAAAA7AAAAAAAAAD8AAAADAAAASgAAAAAAAABOAAAAAwAAAE8AAAADAAAAUwAAAAMAAABcAAAAAwAAAF8AAAADAAAAJQAAAAAAAAAnAAAAAwAAAC0AAAADAAAANAAAAAAAAAA5AAAAAAAAADsAAAAAAAAARgAAAAMAAABKAAAAAAAAAE4AAAADAAAAGAAAAAAAAAAXAAAAAwAAABkAAAADAAAAIAAAAAMAAAAlAAAAAAAAACcAAAADAAAAMgAAAAMAAAA0AAAAAAAAADkAAAAAAAAALgAAAAAAAAA8AAAAAAAAAEgAAAADAAAAOAAAAAAAAABEAAAAAwAAAFAAAAADAAAAPwAAAAMAAABNAAAAAwAAAFoAAAADAAAAGwAAAAAAAAAoAAAAAwAAADcAAAADAAAAIwAAAAAAAAAuAAAAAAAAADwAAAAAAAAALQAAAAMAAAA4AAAAAAAAAEQAAAADAAAADgAAAAAAAAAUAAAAAwAAACQAAAADAAAAEQAAAAMAAAAbAAAAAAAAACgAAAADAAAAGQAAAAMAAAAjAAAAAAAAAC4AAAAAAAAARwAAAAAAAABZAAAAAAAAAGEAAAADAAAASQAAAAAAAABbAAAAAwAAAGcAAAADAAAASAAAAAMAAABYAAAAAwAAAGkAAAADAAAAMwAAAAAAAABFAAAAAwAAAFQAAAADAAAANgAAAAAAAABHAAAAAAAAAFkAAAAAAAAANwAAAAMAAABJAAAAAAAAAFsAAAADAAAAJgAAAAAAAAAvAAAAAwAAAEAAAAADAAAAIgAAAAMAAAAzAAAAAAAAAEUAAAADAAAAJAAAAAMAAAA2AAAAAAAAAEcAAAAAAAAAYAAAAAAAAABoAAAAAAAAAGsAAAADAAAAYgAAAAAAAABuAAAAAwAAAHMAAAADAAAAYQAAAAMAAABvAAAAAwAAAHcAAAADAAAATAAAAAAAAABWAAAAAwAAAF4AAAADAAAAUgAAAAAAAABgAAAAAAAAAGgAAAAAAAAAVAAAAAMAAABiAAAAAAAAAG4AAAADAAAAOgAAAAAAAABBAAAAAwAAAEsAAAADAAAAPgAAAAMAAABMAAAAAAAAAFYAAAADAAAAQAAAAAMAAABSAAAAAAAAAGAAAAAAAAAAVQAAAAAAAABXAAAAAAAAAFMAAAADAAAAZQAAAAAAAABmAAAAAwAAAGQAAAADAAAAawAAAAMAAABwAAAAAwAAAHIAAAADAAAAQgAAAAAAAABDAAAAAwAAAEYAAAADAAAAUQAAAAAAAABVAAAAAAAAAFcAAAAAAAAAXgAAAAMAAABlAAAAAAAAAGYAAAADAAAAMQAAAAAAAAAwAAAAAwAAADIAAAADAAAAPQAAAAMAAABCAAAAAAAAAEMAAAADAAAASwAAAAMAAABRAAAAAAAAAFUAAAAAAAAAXwAAAAAAAABcAAAAAAAAAFMAAAAAAAAATwAAAAAAAABOAAAAAAAAAEoAAAADAAAAPwAAAAEAAAA7AAAAAwAAADkAAAADAAAAbQAAAAAAAABsAAAAAAAAAGQAAAAFAAAAXQAAAAEAAABfAAAAAAAAAFwAAAAAAAAATQAAAAEAAABPAAAAAAAAAE4AAAAAAAAAdQAAAAQAAAB2AAAABQAAAHIAAAAFAAAAagAAAAEAAABtAAAAAAAAAGwAAAAAAAAAWgAAAAEAAABdAAAAAQAAAF8AAAAAAAAAWgAAAAAAAABNAAAAAAAAAD8AAAAAAAAAUAAAAAAAAABEAAAAAAAAADgAAAADAAAASAAAAAEAAAA8AAAAAwAAAC4AAAADAAAAagAAAAAAAABdAAAAAAAAAE8AAAAFAAAAYwAAAAEAAABaAAAAAAAAAE0AAAAAAAAAWAAAAAEAAABQAAAAAAAAAEQAAAAAAAAAdQAAAAMAAABtAAAABQAAAF8AAAAFAAAAcQAAAAEAAABqAAAAAAAAAF0AAAAAAAAAaQAAAAEAAABjAAAAAQAAAFoAAAAAAAAAaQAAAAAAAABYAAAAAAAAAEgAAAAAAAAAZwAAAAAAAABbAAAAAAAAAEkAAAADAAAAYQAAAAEAAABZAAAAAwAAAEcAAAADAAAAcQAAAAAAAABjAAAAAAAAAFAAAAAFAAAAdAAAAAEAAABpAAAAAAAAAFgAAAAAAAAAbwAAAAEAAABnAAAAAAAAAFsAAAAAAAAAdQAAAAIAAABqAAAABQAAAFoAAAAFAAAAeQAAAAEAAABxAAAAAAAAAGMAAAAAAAAAdwAAAAEAAAB0AAAAAQAAAGkAAAAAAAAAdwAAAAAAAABvAAAAAAAAAGEAAAAAAAAAcwAAAAAAAABuAAAAAAAAAGIAAAADAAAAawAAAAEAAABoAAAAAwAAAGAAAAADAAAAeQAAAAAAAAB0AAAAAAAAAGcAAAAFAAAAeAAAAAEAAAB3AAAAAAAAAG8AAAAAAAAAcAAAAAEAAABzAAAAAAAAAG4AAAAAAAAAdQAAAAEAAABxAAAABQAAAGkAAAAFAAAAdgAAAAEAAAB5AAAAAAAAAHQAAAAAAAAAcgAAAAEAAAB4AAAAAQAAAHcAAAAAAAAAcgAAAAAAAABwAAAAAAAAAGsAAAAAAAAAZAAAAAAAAABmAAAAAAAAAGUAAAADAAAAUwAAAAEAAABXAAAAAwAAAFUAAAADAAAAdgAAAAAAAAB4AAAAAAAAAHMAAAAFAAAAbAAAAAEAAAByAAAAAAAAAHAAAAAAAAAAXAAAAAEAAABkAAAAAAAAAGYAAAAAAAAAdQAAAAAAAAB5AAAABQAAAHcAAAAFAAAAbQAAAAEAAAB2AAAAAAAAAHgAAAAAAAAAXwAAAAEAAABsAAAAAQAAAHIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAEAAAAAAAAAAAAAAAEAAAABAAAAAQAAAAAAAAAAAAAAAQAAAAAAAAABAAAAAQAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAMAAAAGAAAAAgAAAAUAAAABAAAABAAAAAAAAAAAAAAABQAAAAMAAAABAAAABgAAAAQAAAACAAAAAAAAAH6iBfbytuk/Gq6akm/58z/Xrm0Liez0P5doSdOpSwRAWs602ULg8D/dT7Rcbo/1v1N1RQHFNOM/g9Snx7HW3L8HWsP8Q3jfP6VwOLosutk/9rjk1YQcxj+gnmKMsNn6P/HDeuPFY+M/YHwDjqKhB0Ci19/fCVrbP4UxKkDWOP6/pvljWa09tL9wi7wrQXjnv/Z6yLImkM2/3yTlOzY14D+m+WNZrT20PzwKVQnrQwNA9nrIsiaQzT/g40rFrRQFwPa45NWEHMa/kbslHEZq97/xw3rjxWPjv4cLC2SMBci/otff3wla27+rKF5oIAv0P1N1RQHFNOO/iDJPGyWHBUAHWsP8Q3jfvwQf/by16gXAfqIF9vK26b8XrO0Vh0r+v9eubQuJ7PS/BxLrA0ZZ479azrTZQuDwv1MK1EuItPw/yscgV9Z6FkAwHBR2WjQMQJNRzXsQ5vY/GlUHVJYKF0DONuFv2lMNQNCGZ28QJfk/0WUwoIL36D8ggDOMQuATQNqMOeAy/wZAWFYOYM+M2z/LWC4uH3oSQDE+LyTsMgRAkJzhRGWFGEDd4soovCQQQKqk0DJMEP8/rGmNdwOLBUAW2X/9xCbjP4hu3dcqJhNAzuYItRvdB0CgzW3zJW/sPxotm/Y2TxRAQAk9XmdDDEC1Kx9MKgT3P1M+NctcghZAFVqcLlb0C0Bgzd3sB2b2P77mZDPUWhZAFROHJpUGCEDAfma5CxXtPz1DWq/zYxRAmhYY5824F0DOuQKWSbAOQNCMqrvu3fs/L6DR22K2wT9nAAxPBU8RQGiN6mW43AFAZhu25b633D8c1YgmzowSQNM25BRKWARArGS08/lNxD+LFssHwmMRQLC5aNcxBgJABL9HT0WRF0CjCmJmOGEOQHsuaVzMP/s/TWJCaGGwBUCeu1PAPLzjP9nqN9DZOBNAKE4JcydbCkCGtbd1qjPzP8dgm9U8jhVAtPeKTkVwDkCeCLss5l37P401XMPLmBdAFd29VMVQDUBg0yA55h75Pz6odcYLCRdApBM4rBrkAkDyAVWgQxbRP4XDMnK20hFAymLlF7EmzD8GUgo9XBHlP3lbK7T9COc/k+OhPthhy7+YGEpnrOvCPzBFhLs15u4/epbqB6H4uz9IuuLF5svev6lzLKY31es/CaQ0envF5z8ZY0xlUADXv7zaz7HYEuI/CfbK1sn16T8uAQfWwxLWPzKn/YuFN94/5KdbC1AFu793fyCSnlfvPzK2y4doAMY/NRg5t1/X6b/shq4QJaHDP5yNIAKPOeI/vpn7BSE30r/X4YQrO6nrv78Ziv/Thto/DqJ1Y6+y5z9l51NaxFrlv8QlA65HOLS/86dxiEc96z+Hj0+LFjneP6LzBZ8LTc2/DaJ1Y6+y579l51NaxFrlP8QlA65HOLQ/8qdxiEc967+Jj0+LFjnev6LzBZ8LTc0/1qdbC1AFuz93fyCSnlfvvzK2y4doAMa/NRg5t1/X6T/vhq4QJaHDv5yNIAKPOeK/wJn7BSE30j/W4YQrO6nrP78Ziv/Thtq/CaQ0envF578XY0xlUADXP7zaz7HYEuK/CvbK1sn16b8rAQfWwxLWvzKn/YuFN96/zWLlF7EmzL8GUgo9XBHlv3lbK7T9COe/kOOhPthhyz+cGEpnrOvCvzBFhLs15u6/c5bqB6H4u79IuuLF5sveP6lzLKY31eu/AQAAAP////8HAAAA/////zEAAAD/////VwEAAP////9hCQAA/////6dBAAD/////kcsBAP/////3kAwA/////8H2VwAAAAAAAAAAAAAAAAACAAAA/////w4AAAD/////YgAAAP////+uAgAA/////8ISAAD/////ToMAAP////8ilwMA/////+4hGQD/////gu2vAAAAAAAAAAAAAAAAAAAAAAACAAAA//////////8BAAAAAwAAAP//////////////////////////////////////////////////////////////////////////AQAAAAAAAAACAAAA////////////////AwAAAP//////////////////////////////////////////////////////////////////////////AQAAAAAAAAACAAAA////////////////AwAAAP//////////////////////////////////////////////////////////////////////////AQAAAAAAAAACAAAA////////////////AwAAAP//////////////////////////////////////////////////////////AgAAAP//////////AQAAAAAAAAD/////////////////////AwAAAP////////////////////////////////////////////////////8DAAAA/////////////////////wAAAAD/////////////////////AQAAAP///////////////wIAAAD///////////////////////////////8DAAAA/////////////////////wAAAAD///////////////8CAAAAAQAAAP////////////////////////////////////////////////////8DAAAA/////////////////////wAAAAD///////////////8CAAAAAQAAAP////////////////////////////////////////////////////8DAAAA/////////////////////wAAAAD///////////////8CAAAAAQAAAP////////////////////////////////////////////////////8DAAAA/////////////////////wAAAAD///////////////8CAAAAAQAAAP////////////////////////////////////////////////////8BAAAAAgAAAP///////////////wAAAAD/////////////////////AwAAAP////////////////////////////////////////////////////8BAAAAAgAAAP///////////////wAAAAD/////////////////////AwAAAP////////////////////////////////////////////////////8BAAAAAgAAAP///////////////wAAAAD/////////////////////AwAAAP////////////////////////////////////////////////////8BAAAAAgAAAP///////////////wAAAAD/////////////////////AwAAAP///////////////////////////////wIAAAD///////////////8BAAAA/////////////////////wAAAAD/////////////////////AwAAAP////////////////////////////////////////////////////8DAAAA/////////////////////wAAAAABAAAA//////////8CAAAA//////////////////////////////////////////////////////////8DAAAA////////////////AgAAAAAAAAABAAAA//////////////////////////////////////////////////////////////////////////8DAAAA////////////////AgAAAAAAAAABAAAA//////////////////////////////////////////////////////////////////////////8DAAAA////////////////AgAAAAAAAAABAAAA//////////////////////////////////////////////////////////////////////////8DAAAAAQAAAP//////////AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAACAAAAAAAAAAIAAAABAAAAAQAAAAIAAAACAAAAAAAAAAUAAAAFAAAAAAAAAAIAAAACAAAAAwAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIAAAAAAAAAAgAAAAEAAAACAAAAAgAAAAIAAAAAAAAABQAAAAYAAAAAAAAAAgAAAAIAAAADAAAAAgAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAgAAAAAAAAACAAAAAQAAAAMAAAACAAAAAgAAAAAAAAAFAAAABwAAAAAAAAACAAAAAgAAAAMAAAADAAAAAAAAAAAAAAAAAAAAAAAAAAIAAAACAAAAAAAAAAIAAAABAAAABAAAAAIAAAACAAAAAAAAAAUAAAAIAAAAAAAAAAIAAAACAAAAAwAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAwAAAAIAAAAAAAAAAgAAAAEAAAAAAAAAAgAAAAIAAAAAAAAABQAAAAkAAAAAAAAAAgAAAAIAAAADAAAABQAAAAAAAAAAAAAAAAAAAAAAAAAKAAAAAgAAAAIAAAAAAAAAAwAAAA4AAAACAAAAAAAAAAIAAAADAAAAAAAAAAAAAAACAAAAAgAAAAMAAAAGAAAAAAAAAAAAAAAAAAAAAAAAAAsAAAACAAAAAgAAAAAAAAADAAAACgAAAAIAAAAAAAAAAgAAAAMAAAABAAAAAAAAAAIAAAACAAAAAwAAAAcAAAAAAAAAAAAAAAAAAAAAAAAADAAAAAIAAAACAAAAAAAAAAMAAAALAAAAAgAAAAAAAAACAAAAAwAAAAIAAAAAAAAAAgAAAAIAAAADAAAACAAAAAAAAAAAAAAAAAAAAAAAAAANAAAAAgAAAAIAAAAAAAAAAwAAAAwAAAACAAAAAAAAAAIAAAADAAAAAwAAAAAAAAACAAAAAgAAAAMAAAAJAAAAAAAAAAAAAAAAAAAAAAAAAA4AAAACAAAAAgAAAAAAAAADAAAADQAAAAIAAAAAAAAAAgAAAAMAAAAEAAAAAAAAAAIAAAACAAAAAwAAAAoAAAAAAAAAAAAAAAAAAAAAAAAABQAAAAIAAAACAAAAAAAAAAMAAAAGAAAAAgAAAAAAAAACAAAAAwAAAA8AAAAAAAAAAgAAAAIAAAADAAAACwAAAAAAAAAAAAAAAAAAAAAAAAAGAAAAAgAAAAIAAAAAAAAAAwAAAAcAAAACAAAAAAAAAAIAAAADAAAAEAAAAAAAAAACAAAAAgAAAAMAAAAMAAAAAAAAAAAAAAAAAAAAAAAAAAcAAAACAAAAAgAAAAAAAAADAAAACAAAAAIAAAAAAAAAAgAAAAMAAAARAAAAAAAAAAIAAAACAAAAAwAAAA0AAAAAAAAAAAAAAAAAAAAAAAAACAAAAAIAAAACAAAAAAAAAAMAAAAJAAAAAgAAAAAAAAACAAAAAwAAABIAAAAAAAAAAgAAAAIAAAADAAAADgAAAAAAAAAAAAAAAAAAAAAAAAAJAAAAAgAAAAIAAAAAAAAAAwAAAAUAAAACAAAAAAAAAAIAAAADAAAAEwAAAAAAAAACAAAAAgAAAAMAAAAPAAAAAAAAAAAAAAAAAAAAAAAAABAAAAACAAAAAAAAAAIAAAABAAAAEwAAAAIAAAACAAAAAAAAAAUAAAAKAAAAAAAAAAIAAAACAAAAAwAAABAAAAAAAAAAAAAAAAAAAAAAAAAAEQAAAAIAAAAAAAAAAgAAAAEAAAAPAAAAAgAAAAIAAAAAAAAABQAAAAsAAAAAAAAAAgAAAAIAAAADAAAAEQAAAAAAAAAAAAAAAAAAAAAAAAASAAAAAgAAAAAAAAACAAAAAQAAABAAAAACAAAAAgAAAAAAAAAFAAAADAAAAAAAAAACAAAAAgAAAAMAAAASAAAAAAAAAAAAAAAAAAAAAAAAABMAAAACAAAAAAAAAAIAAAABAAAAEQAAAAIAAAACAAAAAAAAAAUAAAANAAAAAAAAAAIAAAACAAAAAwAAABMAAAAAAAAAAAAAAAAAAAAAAAAADwAAAAIAAAAAAAAAAgAAAAEAAAASAAAAAgAAAAIAAAAAAAAABQAAAA4AAAAAAAAAAgAAAAIAAAADAAAAAgAAAAEAAAAAAAAAAQAAAAIAAAAAAAAAAAAAAAIAAAABAAAAAAAAAAEAAAACAAAAAQAAAAAAAAACAAAAAAAAAAUAAAAEAAAAAAAAAAEAAAAFAAAAAAAAAAAAAAAFAAAABAAAAAAAAAABAAAABQAAAAQAAAAAAAAABQAAAAAAAAACAAAAAQAAAAAAAAABAAAAAgAAAAAAAAAAAAAAAgAAAAEAAAAAAAAAAQAAAAIAAAABAAAAAAAAAAIAAAACAAAAAAAAAAEAAAAAAAAAAAAAAAUAAAAEAAAAAAAAAAEAAAAFAAAAAAAAAAAAAAAFAAAABAAAAAAAAAABAAAABQAAAAQAAAAAAAAABQAAAAUAAAAAAAAAAQAAAAAAAAAAAAAAOgehWlKfUEEz1zLi+JsiQa2og3wcMfVAWCbHorc0yEDi+Yn/Y6mbQJ11/mfsnG9At6bnG4UQQkBvMCQWKqUUQJVmwwswmOc/3hVgVBL3uj//qqOEOdGOPw/WDN4gnGE/H3ANkCUgND+AA8btKgAHPwTXBqJVSdo+XfRQAqsKrj4fc+zLYbSPQklEmCZHv2FCUP+uDso1NEKYtPhwphUHQptxnyFXYdpB7CddZAMmrkGAt1AxSTqBQUibBVdTsFNBSuX3MV+AJkFocv82SLf5QAqmgj7AY81A23VDSEnLoEDGEJVSeDFzQDYrqvBk70VA8U157pcRGUBWfEF+ZKbsP7KBdLHZTpFAqKYk69AqekDbeGY41MdjQD8AZzHK501A1vcrrjubNkD5LnquvBYhQCbiRRD71QlAqt72EbOH8z8Eu+jL1YbdP4uaox/xUcY/abedg1XfsD+BsUdzJ4KZP5wE9YFySIM/rW1kAKMpbT+rZFthVRhWPy4PKlXIs0A/qMZLlwDnMEHByqEF0I0ZQQYSFD8lUQNBPpY+dFs07UAH8BZImBPWQN9RY0I0sMBA2T7kLfc6qUByFYvfhBKTQMq+0Mis1XxA0XQbeQXMZUBJJ5aEGXpQQP7/SY0a6ThAaMD92b/UIkAs8s8yqXoMQNIegOvCk/U/aOi7NZJP4D8AAAAA/////wAAAAAAAAAAAAAAAAAAAAAAAAAA/////////////////////////////////////wAAAAD/////AAAAAAAAAAAAAAAAAQAAAAAAAAAAAAAA/////wAAAAAAAAAAAQAAAAEAAAAAAAAAAAAAAP////8AAAAABQAAAAAAAAAAAAAAAAAAAAAAAAD/////BQAAAAUAAAAAAAAAAAAAAAAAAAAAAAAA/////wAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAP////////////////////////////////////8AAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAFAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABQAAAAAAAAAFAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD/////////////////////////////////////AAAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAQAAAAAAAAAAAAAABQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAAAAAAAABQAAAAEAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/////////////////////////////////////wAAAAABAAAAAQAAAAEAAAABAAAAAQAAAAEAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAEAAAABAAAAAQAAAAAAAAABAAAAAAAAAAUAAAABAAAAAQAAAAAAAAAAAAAAAQAAAAEAAAAAAAAAAQAAAAEAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQEAAAAAAAEAAQAAAQEAAAAAAAEAAAABAAAAAQABAAAAAAAAAAAAAAAAAAAAAAcAAAAHAAAAAQAAAAIAAAAEAAAAAwAAAAAAAAAAAAAABwAAAAMAAAABAAAAAgAAAAUAAAAEAAAAAAAAAAAAAAAEAAAABAAAAAAAAAACAAAAAQAAAAMAAAAOAAAABgAAAAsAAAACAAAABwAAAAEAAAAYAAAABQAAAAoAAAABAAAABgAAAAAAAAAmAAAABwAAAAwAAAADAAAACAAAAAIAAAAxAAAACQAAAA4AAAAAAAAABQAAAAQAAAA6AAAACAAAAA0AAAAEAAAACQAAAAMAAAA/AAAACwAAAAYAAAAPAAAACgAAABAAAABIAAAADAAAAAcAAAAQAAAACwAAABEAAABTAAAACgAAAAUAAAATAAAADgAAAA8AAABhAAAADQAAAAgAAAARAAAADAAAABIAAABrAAAADgAAAAkAAAASAAAADQAAABMAAAB1AAAADwAAABMAAAARAAAAEgAAABAAAAAGAAAAAgAAAAMAAAAFAAAABAAAAAAAAAAAAAAAAAAAAAYAAAACAAAAAwAAAAEAAAAFAAAABAAAAAAAAAAAAAAABwAAAAUAAAADAAAABAAAAAEAAAAAAAAAAgAAAAAAAAACAAAAAwAAAAEAAAAFAAAABAAAAAYAAAAAAAAAAAAAAGFsZ29zLmMAaDNOZWlnaGJvclJvdGF0aW9ucwBjb29yZGlqay5jAF91cEFwN0NoZWNrZWQAX3VwQXA3ckNoZWNrZWQAZGlyZWN0ZWRFZGdlLmMAZGlyZWN0ZWRFZGdlVG9Cb3VuZGFyeQBhZGphY2VudEZhY2VEaXJbdG1wRmlqay5mYWNlXVtmaWprLmZhY2VdID09IEtJAGZhY2VpamsuYwBfZmFjZUlqa1BlbnRUb0NlbGxCb3VuZGFyeQBhZGphY2VudEZhY2VEaXJbY2VudGVySUpLLmZhY2VdW2ZhY2UyXSA9PSBLSQBfZmFjZUlqa1RvQ2VsbEJvdW5kYXJ5AGgzSW5kZXguYwBjb21wYWN0Q2VsbHMAbGF0TG5nVG9DZWxsAGNlbGxUb0NoaWxkUG9zAHZhbGlkYXRlQ2hpbGRQb3MAbGF0TG5nLmMAY2VsbEFyZWFSYWRzMgBwb2x5Z29uLT5uZXh0ID09IE5VTEwAbGlua2VkR2VvLmMAYWRkTmV3TGlua2VkUG9seWdvbgBuZXh0ICE9IE5VTEwAbG9vcCAhPSBOVUxMAGFkZE5ld0xpbmtlZExvb3AAcG9seWdvbi0+Zmlyc3QgPT0gTlVMTABhZGRMaW5rZWRMb29wAGNvb3JkICE9IE5VTEwAYWRkTGlua2VkQ29vcmQAbG9vcC0+Zmlyc3QgPT0gTlVMTABpbm5lckxvb3BzICE9IE5VTEwAbm9ybWFsaXplTXVsdGlQb2x5Z29uAGJib3hlcyAhPSBOVUxMAGNhbmRpZGF0ZXMgIT0gTlVMTABmaW5kUG9seWdvbkZvckhvbGUAY2FuZGlkYXRlQkJveGVzICE9IE5VTEwAcmV2RGlyICE9IElOVkFMSURfRElHSVQAbG9jYWxpai5jAGNlbGxUb0xvY2FsSWprAGJhc2VDZWxsICE9IG9yaWdpbkJhc2VDZWxsACEob3JpZ2luT25QZW50ICYmIGluZGV4T25QZW50KQBiYXNlQ2VsbCA9PSBvcmlnaW5CYXNlQ2VsbABiYXNlQ2VsbCAhPSBJTlZBTElEX0JBU0VfQ0VMTABsb2NhbElqa1RvQ2VsbAAhX2lzQmFzZUNlbGxQZW50YWdvbihiYXNlQ2VsbCkAYmFzZUNlbGxSb3RhdGlvbnMgPj0gMABncmlkUGF0aENlbGxzADAAdmVydGV4LmMAY2VsbFRvVmVydGV4AGdyYXBoLT5idWNrZXRzICE9IE5VTEwAdmVydGV4R3JhcGguYwBpbml0VmVydGV4R3JhcGgAbm9kZSAhPSBOVUxMAGFkZFZlcnRleE5vZGU=";
      var tempDoublePtr = 24144;
      function demangle(func) {
        return func;
      }
      function demangleAll(text) {
        var regex = /\b__Z[\w\d_]+/g;
        return text.replace(regex, function(x) {
          var y = demangle(x);
          return x === y ? x : y + " [" + x + "]";
        });
      }
      function jsStackTrace() {
        var err2 = new Error();
        if (!err2.stack) {
          try {
            throw new Error(0);
          } catch (e) {
            err2 = e;
          }
          if (!err2.stack) {
            return "(no stack trace available)";
          }
        }
        return err2.stack.toString();
      }
      function stackTrace() {
        var js = jsStackTrace();
        if (Module["extraStackTrace"]) {
          js += "\n" + Module["extraStackTrace"]();
        }
        return demangleAll(js);
      }
      function ___assert_fail(condition, filename, line, func) {
        abort("Assertion failed: " + UTF8ToString(condition) + ", at: " + [filename ? UTF8ToString(filename) : "unknown filename", line, func ? UTF8ToString(func) : "unknown function"]);
      }
      function _emscripten_get_heap_size() {
        return HEAP8.length;
      }
      function _emscripten_memcpy_big(dest, src, num) {
        HEAPU8.set(HEAPU8.subarray(src, src + num), dest);
      }
      function ___setErrNo(value) {
        if (Module["___errno_location"]) {
          HEAP32[Module["___errno_location"]() >> 2] = value;
        }
        return value;
      }
      function abortOnCannotGrowMemory(requestedSize) {
        abort("OOM");
      }
      function emscripten_realloc_buffer(size) {
        try {
          var newBuffer = new ArrayBuffer(size);
          if (newBuffer.byteLength != size) {
            return;
          }
          new Int8Array(newBuffer).set(HEAP8);
          _emscripten_replace_memory(newBuffer);
          updateGlobalBufferAndViews(newBuffer);
          return 1;
        } catch (e) {
        }
      }
      function _emscripten_resize_heap(requestedSize) {
        var oldSize = _emscripten_get_heap_size();
        var PAGE_MULTIPLE = 16777216;
        var LIMIT = 2147483648 - PAGE_MULTIPLE;
        if (requestedSize > LIMIT) {
          return false;
        }
        var MIN_TOTAL_MEMORY = 16777216;
        var newSize = Math.max(oldSize, MIN_TOTAL_MEMORY);
        while (newSize < requestedSize) {
          if (newSize <= 536870912) {
            newSize = alignUp(2 * newSize, PAGE_MULTIPLE);
          } else {
            newSize = Math.min(alignUp((3 * newSize + 2147483648) / 4, PAGE_MULTIPLE), LIMIT);
          }
        }
        var replacement = emscripten_realloc_buffer(newSize);
        if (!replacement) {
          return false;
        }
        return true;
      }
      var decodeBase64 = typeof atob === "function" ? atob : function(input) {
        var keyStr = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
        var output = "";
        var chr1, chr2, chr3;
        var enc1, enc2, enc3, enc4;
        var i = 0;
        input = input.replace(/[^A-Za-z0-9\+\/\=]/g, "");
        do {
          enc1 = keyStr.indexOf(input.charAt(i++));
          enc2 = keyStr.indexOf(input.charAt(i++));
          enc3 = keyStr.indexOf(input.charAt(i++));
          enc4 = keyStr.indexOf(input.charAt(i++));
          chr1 = enc1 << 2 | enc2 >> 4;
          chr2 = (enc2 & 15) << 4 | enc3 >> 2;
          chr3 = (enc3 & 3) << 6 | enc4;
          output = output + String.fromCharCode(chr1);
          if (enc3 !== 64) {
            output = output + String.fromCharCode(chr2);
          }
          if (enc4 !== 64) {
            output = output + String.fromCharCode(chr3);
          }
        } while (i < input.length);
        return output;
      };
      function intArrayFromBase64(s) {
        try {
          var decoded = decodeBase64(s);
          var bytes = new Uint8Array(decoded.length);
          for (var i = 0; i < decoded.length; ++i) {
            bytes[i] = decoded.charCodeAt(i);
          }
          return bytes;
        } catch (_) {
          throw new Error("Converting base64 string to bytes failed.");
        }
      }
      function tryParseAsDataURI(filename) {
        if (!isDataURI(filename)) {
          return;
        }
        return intArrayFromBase64(filename.slice(dataURIPrefix.length));
      }
      var asmGlobalArg = {
        "Math": Math,
        "Int8Array": Int8Array,
        "Int32Array": Int32Array,
        "Uint8Array": Uint8Array,
        "Float32Array": Float32Array,
        "Float64Array": Float64Array
      };
      var asmLibraryArg = {
        "a": abort,
        "b": setTempRet0,
        "c": getTempRet0,
        "d": ___assert_fail,
        "e": ___setErrNo,
        "f": _emscripten_get_heap_size,
        "g": _emscripten_memcpy_big,
        "h": _emscripten_resize_heap,
        "i": abortOnCannotGrowMemory,
        "j": demangle,
        "k": demangleAll,
        "l": emscripten_realloc_buffer,
        "m": jsStackTrace,
        "n": stackTrace,
        "o": tempDoublePtr,
        "p": DYNAMICTOP_PTR
      };
      var asm = (
        /** @suppress {uselessCode} */
        (function(global, env, buffer2) {
          "almost asm";
          var a = new global.Int8Array(buffer2), b = new global.Int32Array(buffer2), c = new global.Uint8Array(buffer2), d = new global.Float32Array(buffer2), e = new global.Float64Array(buffer2), f = env.o | 0, g = env.p | 0, p = global.Math.floor, q = global.Math.abs, r = global.Math.sqrt, s = global.Math.pow, t = global.Math.cos, u = global.Math.sin, v = global.Math.tan, w = global.Math.acos, x = global.Math.asin, y = global.Math.atan, z = global.Math.atan2, A = global.Math.ceil, B = global.Math.imul, C = global.Math.min, D = global.Math.max, E = global.Math.clz32, G = env.b, H = env.c, I = env.d, J = env.e, K = env.f, L = env.g, M = env.h, N = env.i, T = 24160;
          function W(newBuffer) {
            a = new Int8Array(newBuffer);
            c = new Uint8Array(newBuffer);
            b = new Int32Array(newBuffer);
            d = new Float32Array(newBuffer);
            e = new Float64Array(newBuffer);
            buffer2 = newBuffer;
            return true;
          }
          function X(a2) {
            a2 = a2 | 0;
            var b2 = 0;
            b2 = T;
            T = T + a2 | 0;
            T = T + 15 & -16;
            return b2 | 0;
          }
          function Y() {
            return T | 0;
          }
          function Z(a2) {
            a2 = a2 | 0;
            T = a2;
          }
          function _(a2, b2) {
            a2 = a2 | 0;
            b2 = b2 | 0;
            T = a2;
          }
          function $(a2, c2) {
            a2 = a2 | 0;
            c2 = c2 | 0;
            var d2 = 0, e2 = 0, f2 = 0;
            if ((a2 | 0) < 0) {
              c2 = 2;
              return c2 | 0;
            }
            if ((a2 | 0) > 13780509) {
              c2 = ic(15, c2) | 0;
              return c2 | 0;
            } else {
              d2 = ((a2 | 0) < 0) << 31 >> 31;
              f2 = rd(a2 | 0, d2 | 0, 3, 0) | 0;
              e2 = H() | 0;
              d2 = ld(a2 | 0, d2 | 0, 1, 0) | 0;
              d2 = rd(f2 | 0, e2 | 0, d2 | 0, H() | 0) | 0;
              d2 = ld(d2 | 0, H() | 0, 1, 0) | 0;
              a2 = H() | 0;
              b[c2 >> 2] = d2;
              b[c2 + 4 >> 2] = a2;
              c2 = 0;
              return c2 | 0;
            }
            return 0;
          }
          function aa(a2, b2, c2, d2) {
            a2 = a2 | 0;
            b2 = b2 | 0;
            c2 = c2 | 0;
            d2 = d2 | 0;
            return ba(a2, b2, c2, d2, 0) | 0;
          }
          function ba(a2, c2, d2, e2, f2) {
            a2 = a2 | 0;
            c2 = c2 | 0;
            d2 = d2 | 0;
            e2 = e2 | 0;
            f2 = f2 | 0;
            var g2 = 0, h = 0, i = 0, j = 0, k = 0;
            j = T;
            T = T + 16 | 0;
            h = j;
            if (!(ca(a2, c2, d2, e2, f2) | 0)) {
              e2 = 0;
              T = j;
              return e2 | 0;
            }
            do {
              if ((d2 | 0) >= 0) {
                if ((d2 | 0) > 13780509) {
                  g2 = ic(15, h) | 0;
                  if (g2 | 0) {
                    break;
                  }
                  i = h;
                  h = b[i >> 2] | 0;
                  i = b[i + 4 >> 2] | 0;
                } else {
                  g2 = ((d2 | 0) < 0) << 31 >> 31;
                  k = rd(d2 | 0, g2 | 0, 3, 0) | 0;
                  i = H() | 0;
                  g2 = ld(d2 | 0, g2 | 0, 1, 0) | 0;
                  g2 = rd(k | 0, i | 0, g2 | 0, H() | 0) | 0;
                  g2 = ld(g2 | 0, H() | 0, 1, 0) | 0;
                  i = H() | 0;
                  b[h >> 2] = g2;
                  b[h + 4 >> 2] = i;
                  h = g2;
                }
                Bd(e2 | 0, 0, h << 3 | 0) | 0;
                if (f2 | 0) {
                  Bd(f2 | 0, 0, h << 2 | 0) | 0;
                  g2 = da(a2, c2, d2, e2, f2, h, i, 0) | 0;
                  break;
                }
                g2 = kd(h, 4) | 0;
                if (!g2) {
                  g2 = 13;
                } else {
                  k = da(a2, c2, d2, e2, g2, h, i, 0) | 0;
                  jd(g2);
                  g2 = k;
                }
              } else {
                g2 = 2;
              }
            } while (0);
            k = g2;
            T = j;
            return k | 0;
          }
          function ca(a2, c2, d2, e2, f2) {
            a2 = a2 | 0;
            c2 = c2 | 0;
            d2 = d2 | 0;
            e2 = e2 | 0;
            f2 = f2 | 0;
            var g2 = 0, h = 0, i = 0, j = 0, k = 0, l = 0, m = 0, n = 0, o = 0, p2 = 0, q2 = 0;
            q2 = T;
            T = T + 16 | 0;
            o = q2;
            p2 = q2 + 8 | 0;
            n = o;
            b[n >> 2] = a2;
            b[n + 4 >> 2] = c2;
            if ((d2 | 0) < 0) {
              p2 = 2;
              T = q2;
              return p2 | 0;
            }
            g2 = e2;
            b[g2 >> 2] = a2;
            b[g2 + 4 >> 2] = c2;
            g2 = (f2 | 0) != 0;
            if (g2) {
              b[f2 >> 2] = 0;
            }
            if (xb(a2, c2) | 0) {
              p2 = 9;
              T = q2;
              return p2 | 0;
            }
            b[p2 >> 2] = 0;
            a: do {
              if ((d2 | 0) >= 1) {
                if (g2) {
                  l = 1;
                  k = 0;
                  m = 0;
                  n = 1;
                  g2 = a2;
                  while (1) {
                    if (!(k | m)) {
                      g2 = ea(g2, c2, 4, p2, o) | 0;
                      if (g2 | 0) {
                        break a;
                      }
                      c2 = o;
                      g2 = b[c2 >> 2] | 0;
                      c2 = b[c2 + 4 >> 2] | 0;
                      if (xb(g2, c2) | 0) {
                        g2 = 9;
                        break a;
                      }
                    }
                    g2 = ea(g2, c2, b[22384 + (m << 2) >> 2] | 0, p2, o) | 0;
                    if (g2 | 0) {
                      break a;
                    }
                    c2 = o;
                    g2 = b[c2 >> 2] | 0;
                    c2 = b[c2 + 4 >> 2] | 0;
                    a2 = e2 + (l << 3) | 0;
                    b[a2 >> 2] = g2;
                    b[a2 + 4 >> 2] = c2;
                    b[f2 + (l << 2) >> 2] = n;
                    a2 = k + 1 | 0;
                    h = (a2 | 0) == (n | 0);
                    i = m + 1 | 0;
                    j = (i | 0) == 6;
                    if (xb(g2, c2) | 0) {
                      g2 = 9;
                      break a;
                    }
                    n = n + (j & h & 1) | 0;
                    if ((n | 0) > (d2 | 0)) {
                      g2 = 0;
                      break;
                    } else {
                      l = l + 1 | 0;
                      k = h ? 0 : a2;
                      m = h ? j ? 0 : i : m;
                    }
                  }
                } else {
                  l = 1;
                  k = 0;
                  m = 0;
                  n = 1;
                  g2 = a2;
                  while (1) {
                    if (!(k | m)) {
                      g2 = ea(g2, c2, 4, p2, o) | 0;
                      if (g2 | 0) {
                        break a;
                      }
                      c2 = o;
                      g2 = b[c2 >> 2] | 0;
                      c2 = b[c2 + 4 >> 2] | 0;
                      if (xb(g2, c2) | 0) {
                        g2 = 9;
                        break a;
                      }
                    }
                    g2 = ea(g2, c2, b[22384 + (m << 2) >> 2] | 0, p2, o) | 0;
                    if (g2 | 0) {
                      break a;
                    }
                    c2 = o;
                    g2 = b[c2 >> 2] | 0;
                    c2 = b[c2 + 4 >> 2] | 0;
                    a2 = e2 + (l << 3) | 0;
                    b[a2 >> 2] = g2;
                    b[a2 + 4 >> 2] = c2;
                    a2 = k + 1 | 0;
                    h = (a2 | 0) == (n | 0);
                    i = m + 1 | 0;
                    j = (i | 0) == 6;
                    if (xb(g2, c2) | 0) {
                      g2 = 9;
                      break a;
                    }
                    n = n + (j & h & 1) | 0;
                    if ((n | 0) > (d2 | 0)) {
                      g2 = 0;
                      break;
                    } else {
                      l = l + 1 | 0;
                      k = h ? 0 : a2;
                      m = h ? j ? 0 : i : m;
                    }
                  }
                }
              } else {
                g2 = 0;
              }
            } while (0);
            p2 = g2;
            T = q2;
            return p2 | 0;
          }
          function da(a2, c2, d2, e2, f2, g2, h, i) {
            a2 = a2 | 0;
            c2 = c2 | 0;
            d2 = d2 | 0;
            e2 = e2 | 0;
            f2 = f2 | 0;
            g2 = g2 | 0;
            h = h | 0;
            i = i | 0;
            var j = 0, k = 0, l = 0, m = 0, n = 0, o = 0, p2 = 0, q2 = 0, r2 = 0, s2 = 0;
            q2 = T;
            T = T + 16 | 0;
            o = q2 + 8 | 0;
            p2 = q2;
            j = td(a2 | 0, c2 | 0, g2 | 0, h | 0) | 0;
            l = H() | 0;
            m = e2 + (j << 3) | 0;
            r2 = m;
            s2 = b[r2 >> 2] | 0;
            r2 = b[r2 + 4 >> 2] | 0;
            k = (s2 | 0) == (a2 | 0) & (r2 | 0) == (c2 | 0);
            if (!((s2 | 0) == 0 & (r2 | 0) == 0 | k)) {
              do {
                j = ld(j | 0, l | 0, 1, 0) | 0;
                j = sd(j | 0, H() | 0, g2 | 0, h | 0) | 0;
                l = H() | 0;
                m = e2 + (j << 3) | 0;
                s2 = m;
                r2 = b[s2 >> 2] | 0;
                s2 = b[s2 + 4 >> 2] | 0;
                k = (r2 | 0) == (a2 | 0) & (s2 | 0) == (c2 | 0);
              } while (!((r2 | 0) == 0 & (s2 | 0) == 0 | k));
            }
            j = f2 + (j << 2) | 0;
            if (k ? (b[j >> 2] | 0) <= (i | 0) : 0) {
              s2 = 0;
              T = q2;
              return s2 | 0;
            }
            s2 = m;
            b[s2 >> 2] = a2;
            b[s2 + 4 >> 2] = c2;
            b[j >> 2] = i;
            if ((i | 0) >= (d2 | 0)) {
              s2 = 0;
              T = q2;
              return s2 | 0;
            }
            k = i + 1 | 0;
            b[o >> 2] = 0;
            j = ea(a2, c2, 2, o, p2) | 0;
            switch (j | 0) {
              case 9: {
                n = 9;
                break;
              }
              case 0: {
                j = p2;
                j = da(b[j >> 2] | 0, b[j + 4 >> 2] | 0, d2, e2, f2, g2, h, k) | 0;
                if (!j) {
                  n = 9;
                }
                break;
              }
              default:
            }
            a: do {
              if ((n | 0) == 9) {
                b[o >> 2] = 0;
                j = ea(a2, c2, 3, o, p2) | 0;
                switch (j | 0) {
                  case 9:
                    break;
                  case 0: {
                    j = p2;
                    j = da(b[j >> 2] | 0, b[j + 4 >> 2] | 0, d2, e2, f2, g2, h, k) | 0;
                    if (j | 0) {
                      break a;
                    }
                    break;
                  }
                  default:
                    break a;
                }
                b[o >> 2] = 0;
                j = ea(a2, c2, 1, o, p2) | 0;
                switch (j | 0) {
                  case 9:
                    break;
                  case 0: {
                    j = p2;
                    j = da(b[j >> 2] | 0, b[j + 4 >> 2] | 0, d2, e2, f2, g2, h, k) | 0;
                    if (j | 0) {
                      break a;
                    }
                    break;
                  }
                  default:
                    break a;
                }
                b[o >> 2] = 0;
                j = ea(a2, c2, 5, o, p2) | 0;
                switch (j | 0) {
                  case 9:
                    break;
                  case 0: {
                    j = p2;
                    j = da(b[j >> 2] | 0, b[j + 4 >> 2] | 0, d2, e2, f2, g2, h, k) | 0;
                    if (j | 0) {
                      break a;
                    }
                    break;
                  }
                  default:
                    break a;
                }
                b[o >> 2] = 0;
                j = ea(a2, c2, 4, o, p2) | 0;
                switch (j | 0) {
                  case 9:
                    break;
                  case 0: {
                    j = p2;
                    j = da(b[j >> 2] | 0, b[j + 4 >> 2] | 0, d2, e2, f2, g2, h, k) | 0;
                    if (j | 0) {
                      break a;
                    }
                    break;
                  }
                  default:
                    break a;
                }
                b[o >> 2] = 0;
                j = ea(a2, c2, 6, o, p2) | 0;
                switch (j | 0) {
                  case 9:
                    break;
                  case 0: {
                    j = p2;
                    j = da(b[j >> 2] | 0, b[j + 4 >> 2] | 0, d2, e2, f2, g2, h, k) | 0;
                    if (j | 0) {
                      break a;
                    }
                    break;
                  }
                  default:
                    break a;
                }
                s2 = 0;
                T = q2;
                return s2 | 0;
              }
            } while (0);
            s2 = j;
            T = q2;
            return s2 | 0;
          }
          function ea(a2, c2, d2, e2, f2) {
            a2 = a2 | 0;
            c2 = c2 | 0;
            d2 = d2 | 0;
            e2 = e2 | 0;
            f2 = f2 | 0;
            var g2 = 0, h = 0, i = 0, j = 0, k = 0, l = 0, m = 0, n = 0, o = 0, p2 = 0;
            if (d2 >>> 0 > 6) {
              f2 = 1;
              return f2 | 0;
            }
            m = (b[e2 >> 2] | 0) % 6 | 0;
            b[e2 >> 2] = m;
            if ((m | 0) > 0) {
              g2 = 0;
              do {
                d2 = Sa(d2) | 0;
                g2 = g2 + 1 | 0;
              } while ((g2 | 0) < (b[e2 >> 2] | 0));
            }
            m = vd(a2 | 0, c2 | 0, 45) | 0;
            H() | 0;
            l = m & 127;
            if (l >>> 0 > 121) {
              f2 = 5;
              return f2 | 0;
            }
            j = Fb(a2, c2) | 0;
            g2 = vd(a2 | 0, c2 | 0, 52) | 0;
            H() | 0;
            g2 = g2 & 15;
            a: do {
              if (!g2) {
                k = 8;
              } else {
                while (1) {
                  h = (15 - g2 | 0) * 3 | 0;
                  i = vd(a2 | 0, c2 | 0, h | 0) | 0;
                  H() | 0;
                  i = i & 7;
                  if ((i | 0) == 7) {
                    c2 = 5;
                    break;
                  }
                  p2 = (Lb(g2) | 0) == 0;
                  g2 = g2 + -1 | 0;
                  n = wd(7, 0, h | 0) | 0;
                  c2 = c2 & ~(H() | 0);
                  o = wd(b[(p2 ? 432 : 16) + (i * 28 | 0) + (d2 << 2) >> 2] | 0, 0, h | 0) | 0;
                  h = H() | 0;
                  d2 = b[(p2 ? 640 : 224) + (i * 28 | 0) + (d2 << 2) >> 2] | 0;
                  a2 = o | a2 & ~n;
                  c2 = h | c2;
                  if (!d2) {
                    d2 = 0;
                    break a;
                  }
                  if (!g2) {
                    k = 8;
                    break a;
                  }
                }
                return c2 | 0;
              }
            } while (0);
            if ((k | 0) == 8) {
              p2 = b[848 + (l * 28 | 0) + (d2 << 2) >> 2] | 0;
              o = wd(p2 | 0, 0, 45) | 0;
              a2 = o | a2;
              c2 = H() | 0 | c2 & -1040385;
              d2 = b[4272 + (l * 28 | 0) + (d2 << 2) >> 2] | 0;
              if ((p2 & 127 | 0) == 127) {
                p2 = wd(b[848 + (l * 28 | 0) + 20 >> 2] | 0, 0, 45) | 0;
                c2 = H() | 0 | c2 & -1040385;
                d2 = b[4272 + (l * 28 | 0) + 20 >> 2] | 0;
                a2 = Hb(p2 | a2, c2) | 0;
                c2 = H() | 0;
                b[e2 >> 2] = (b[e2 >> 2] | 0) + 1;
              }
            }
            i = vd(a2 | 0, c2 | 0, 45) | 0;
            H() | 0;
            i = i & 127;
            b: do {
              if (!(ma(i) | 0)) {
                if ((d2 | 0) > 0) {
                  g2 = 0;
                  do {
                    a2 = Hb(a2, c2) | 0;
                    c2 = H() | 0;
                    g2 = g2 + 1 | 0;
                  } while ((g2 | 0) != (d2 | 0));
                }
              } else {
                c: do {
                  if ((Fb(a2, c2) | 0) == 1) {
                    if ((l | 0) != (i | 0)) {
                      if (sa(i, b[7696 + (l * 28 | 0) >> 2] | 0) | 0) {
                        a2 = Jb(a2, c2) | 0;
                        h = 1;
                        c2 = H() | 0;
                        break;
                      } else {
                        I(23313, 22416, 436, 22424);
                      }
                    }
                    switch (j | 0) {
                      case 3: {
                        a2 = Hb(a2, c2) | 0;
                        c2 = H() | 0;
                        b[e2 >> 2] = (b[e2 >> 2] | 0) + 1;
                        h = 0;
                        break c;
                      }
                      case 5: {
                        a2 = Jb(a2, c2) | 0;
                        c2 = H() | 0;
                        b[e2 >> 2] = (b[e2 >> 2] | 0) + 5;
                        h = 0;
                        break c;
                      }
                      case 0: {
                        p2 = 9;
                        return p2 | 0;
                      }
                      default: {
                        p2 = 1;
                        return p2 | 0;
                      }
                    }
                  } else {
                    h = 0;
                  }
                } while (0);
                if ((d2 | 0) > 0) {
                  g2 = 0;
                  do {
                    a2 = Gb(a2, c2) | 0;
                    c2 = H() | 0;
                    g2 = g2 + 1 | 0;
                  } while ((g2 | 0) != (d2 | 0));
                }
                if ((l | 0) != (i | 0)) {
                  if (!(na(i) | 0)) {
                    if ((h | 0) != 0 | (Fb(a2, c2) | 0) != 5) {
                      break;
                    }
                    b[e2 >> 2] = (b[e2 >> 2] | 0) + 1;
                    break;
                  }
                  switch (m & 127) {
                    case 8:
                    case 118:
                      break b;
                    default:
                  }
                  if ((Fb(a2, c2) | 0) != 3) {
                    b[e2 >> 2] = (b[e2 >> 2] | 0) + 1;
                  }
                }
              }
            } while (0);
            b[e2 >> 2] = ((b[e2 >> 2] | 0) + d2 | 0) % 6 | 0;
            p2 = f2;
            b[p2 >> 2] = a2;
            b[p2 + 4 >> 2] = c2;
            p2 = 0;
            return p2 | 0;
          }
          function fa(a2, c2, d2, e2) {
            a2 = a2 | 0;
            c2 = c2 | 0;
            d2 = d2 | 0;
            e2 = e2 | 0;
            var f2 = 0, g2 = 0, h = 0, i = 0, j = 0, k = 0;
            i = T;
            T = T + 16 | 0;
            g2 = i;
            h = i + 8 | 0;
            f2 = (xb(a2, c2) | 0) == 0;
            f2 = f2 ? 1 : 2;
            while (1) {
              b[h >> 2] = 0;
              k = (ea(a2, c2, f2, h, g2) | 0) == 0;
              j = g2;
              if (k & ((b[j >> 2] | 0) == (d2 | 0) ? (b[j + 4 >> 2] | 0) == (e2 | 0) : 0)) {
                a2 = 4;
                break;
              }
              f2 = f2 + 1 | 0;
              if (f2 >>> 0 >= 7) {
                f2 = 7;
                a2 = 4;
                break;
              }
            }
            if ((a2 | 0) == 4) {
              T = i;
              return f2 | 0;
            }
            return 0;
          }
          function ga(a2, c2, d2, e2) {
            a2 = a2 | 0;
            c2 = c2 | 0;
            d2 = d2 | 0;
            e2 = e2 | 0;
            var f2 = 0, g2 = 0, h = 0, i = 0, j = 0, k = 0, l = 0, m = 0, n = 0, o = 0, p2 = 0;
            p2 = T;
            T = T + 16 | 0;
            n = p2;
            o = p2 + 8 | 0;
            m = n;
            b[m >> 2] = a2;
            b[m + 4 >> 2] = c2;
            if (!d2) {
              o = e2;
              b[o >> 2] = a2;
              b[o + 4 >> 2] = c2;
              o = 0;
              T = p2;
              return o | 0;
            }
            b[o >> 2] = 0;
            a: do {
              if (!(xb(a2, c2) | 0)) {
                g2 = (d2 | 0) > 0;
                if (g2) {
                  f2 = 0;
                  m = a2;
                  do {
                    a2 = ea(m, c2, 4, o, n) | 0;
                    if (a2 | 0) {
                      break a;
                    }
                    c2 = n;
                    m = b[c2 >> 2] | 0;
                    c2 = b[c2 + 4 >> 2] | 0;
                    f2 = f2 + 1 | 0;
                    if (xb(m, c2) | 0) {
                      a2 = 9;
                      break a;
                    }
                  } while ((f2 | 0) < (d2 | 0));
                  l = e2;
                  b[l >> 2] = m;
                  b[l + 4 >> 2] = c2;
                  l = d2 + -1 | 0;
                  if (g2) {
                    k = 0;
                    a2 = 1;
                    do {
                      f2 = 22384 + (k << 2) | 0;
                      if ((k | 0) == 5) {
                        h = b[f2 >> 2] | 0;
                        g2 = 0;
                        f2 = a2;
                        while (1) {
                          a2 = n;
                          a2 = ea(b[a2 >> 2] | 0, b[a2 + 4 >> 2] | 0, h, o, n) | 0;
                          if (a2 | 0) {
                            break a;
                          }
                          if ((g2 | 0) != (l | 0)) {
                            j = n;
                            i = b[j >> 2] | 0;
                            j = b[j + 4 >> 2] | 0;
                            a2 = e2 + (f2 << 3) | 0;
                            b[a2 >> 2] = i;
                            b[a2 + 4 >> 2] = j;
                            if (!(xb(i, j) | 0)) {
                              a2 = f2 + 1 | 0;
                            } else {
                              a2 = 9;
                              break a;
                            }
                          } else {
                            a2 = f2;
                          }
                          g2 = g2 + 1 | 0;
                          if ((g2 | 0) >= (d2 | 0)) {
                            break;
                          } else {
                            f2 = a2;
                          }
                        }
                      } else {
                        h = n;
                        j = b[f2 >> 2] | 0;
                        i = 0;
                        f2 = a2;
                        g2 = b[h >> 2] | 0;
                        h = b[h + 4 >> 2] | 0;
                        while (1) {
                          a2 = ea(g2, h, j, o, n) | 0;
                          if (a2 | 0) {
                            break a;
                          }
                          h = n;
                          g2 = b[h >> 2] | 0;
                          h = b[h + 4 >> 2] | 0;
                          a2 = e2 + (f2 << 3) | 0;
                          b[a2 >> 2] = g2;
                          b[a2 + 4 >> 2] = h;
                          a2 = f2 + 1 | 0;
                          if (xb(g2, h) | 0) {
                            a2 = 9;
                            break a;
                          }
                          i = i + 1 | 0;
                          if ((i | 0) >= (d2 | 0)) {
                            break;
                          } else {
                            f2 = a2;
                          }
                        }
                      }
                      k = k + 1 | 0;
                    } while (k >>> 0 < 6);
                    a2 = n;
                    h = m;
                    f2 = b[a2 >> 2] | 0;
                    g2 = c2;
                    a2 = b[a2 + 4 >> 2] | 0;
                  } else {
                    h = m;
                    f2 = m;
                    g2 = c2;
                    a2 = c2;
                  }
                } else {
                  h = e2;
                  b[h >> 2] = a2;
                  b[h + 4 >> 2] = c2;
                  h = a2;
                  f2 = a2;
                  g2 = c2;
                  a2 = c2;
                }
                a2 = (h | 0) == (f2 | 0) & (g2 | 0) == (a2 | 0) ? 0 : 9;
              } else {
                a2 = 9;
              }
            } while (0);
            o = a2;
            T = p2;
            return o | 0;
          }
          function ha(a2, c2, d2, e2) {
            a2 = a2 | 0;
            c2 = c2 | 0;
            d2 = d2 | 0;
            e2 = e2 | 0;
            var f2 = 0, g2 = 0, h = 0, i = 0, j = 0, k = 0;
            i = T;
            T = T + 48 | 0;
            f2 = i + 16 | 0;
            g2 = i + 8 | 0;
            h = i;
            if (d2 | 0) {
              h = 15;
              T = i;
              return h | 0;
            }
            k = a2;
            j = b[k + 4 >> 2] | 0;
            d2 = g2;
            b[d2 >> 2] = b[k >> 2];
            b[d2 + 4 >> 2] = j;
            Ec(g2, f2);
            c2 = za(f2, c2, h) | 0;
            if (!c2) {
              d2 = b[g2 >> 2] | 0;
              g2 = b[a2 + 8 >> 2] | 0;
              if ((g2 | 0) > 0) {
                f2 = b[a2 + 12 >> 2] | 0;
                c2 = 0;
                do {
                  d2 = (b[f2 + (c2 << 3) >> 2] | 0) + d2 | 0;
                  c2 = c2 + 1 | 0;
                } while ((c2 | 0) < (g2 | 0));
              }
              c2 = h;
              f2 = b[c2 >> 2] | 0;
              c2 = b[c2 + 4 >> 2] | 0;
              g2 = ((d2 | 0) < 0) << 31 >> 31;
              if ((c2 | 0) < (g2 | 0) | (c2 | 0) == (g2 | 0) & f2 >>> 0 < d2 >>> 0) {
                c2 = h;
                b[c2 >> 2] = d2;
                b[c2 + 4 >> 2] = g2;
                c2 = g2;
              } else {
                d2 = f2;
              }
              j = ld(d2 | 0, c2 | 0, 12, 0) | 0;
              k = H() | 0;
              c2 = h;
              b[c2 >> 2] = j;
              b[c2 + 4 >> 2] = k;
              c2 = e2;
              b[c2 >> 2] = j;
              b[c2 + 4 >> 2] = k;
              c2 = 0;
            }
            k = c2;
            T = i;
            return k | 0;
          }
          function ia(a2, c2, d2, f2, g2, h, i) {
            a2 = a2 | 0;
            c2 = c2 | 0;
            d2 = d2 | 0;
            f2 = f2 | 0;
            g2 = g2 | 0;
            h = h | 0;
            i = i | 0;
            var j = 0, k = 0, l = 0, m = 0, n = 0, o = 0, p2 = 0, q2 = 0, r2 = 0, s2 = 0, t2 = 0, u2 = 0, v2 = 0, w2 = 0, x2 = 0, y2 = 0, z2 = 0, A2 = 0, B2 = 0, C2 = 0, D2 = 0, E2 = 0, F = 0, G2 = 0, I2 = 0, J2 = 0, K2 = 0, L2 = 0, M2 = 0;
            I2 = T;
            T = T + 64 | 0;
            D2 = I2 + 48 | 0;
            E2 = I2 + 32 | 0;
            F = I2 + 24 | 0;
            x2 = I2 + 8 | 0;
            y2 = I2;
            k = b[a2 >> 2] | 0;
            if ((k | 0) <= 0) {
              G2 = 0;
              T = I2;
              return G2 | 0;
            }
            z2 = a2 + 4 | 0;
            A2 = D2 + 8 | 0;
            B2 = E2 + 8 | 0;
            C2 = x2 + 8 | 0;
            j = 0;
            v2 = 0;
            while (1) {
              l = b[z2 >> 2] | 0;
              u2 = l + (v2 << 4) | 0;
              b[D2 >> 2] = b[u2 >> 2];
              b[D2 + 4 >> 2] = b[u2 + 4 >> 2];
              b[D2 + 8 >> 2] = b[u2 + 8 >> 2];
              b[D2 + 12 >> 2] = b[u2 + 12 >> 2];
              if ((v2 | 0) == (k + -1 | 0)) {
                b[E2 >> 2] = b[l >> 2];
                b[E2 + 4 >> 2] = b[l + 4 >> 2];
                b[E2 + 8 >> 2] = b[l + 8 >> 2];
                b[E2 + 12 >> 2] = b[l + 12 >> 2];
              } else {
                u2 = l + (v2 + 1 << 4) | 0;
                b[E2 >> 2] = b[u2 >> 2];
                b[E2 + 4 >> 2] = b[u2 + 4 >> 2];
                b[E2 + 8 >> 2] = b[u2 + 8 >> 2];
                b[E2 + 12 >> 2] = b[u2 + 12 >> 2];
              }
              k = Aa(D2, E2, f2, F) | 0;
              a: do {
                if (!k) {
                  l = F;
                  k = b[l >> 2] | 0;
                  l = b[l + 4 >> 2] | 0;
                  if ((l | 0) > 0 | (l | 0) == 0 & k >>> 0 > 0) {
                    t2 = 0;
                    u2 = 0;
                    b: while (1) {
                      M2 = +e[D2 >> 3];
                      s2 = md(k | 0, l | 0, t2 | 0, u2 | 0) | 0;
                      L2 = +(s2 >>> 0) + 4294967296 * +(H() | 0);
                      J2 = +(k >>> 0) + 4294967296 * +(l | 0);
                      K2 = +(t2 >>> 0) + 4294967296 * +(u2 | 0);
                      e[x2 >> 3] = M2 * L2 / J2 + +e[E2 >> 3] * K2 / J2;
                      e[C2 >> 3] = +e[A2 >> 3] * L2 / J2 + +e[B2 >> 3] * K2 / J2;
                      k = Mb(x2, f2, y2) | 0;
                      if (k | 0) {
                        j = k;
                        break;
                      }
                      s2 = y2;
                      r2 = b[s2 >> 2] | 0;
                      s2 = b[s2 + 4 >> 2] | 0;
                      o = td(r2 | 0, s2 | 0, c2 | 0, d2 | 0) | 0;
                      m = H() | 0;
                      k = i + (o << 3) | 0;
                      n = k;
                      l = b[n >> 2] | 0;
                      n = b[n + 4 >> 2] | 0;
                      c: do {
                        if ((l | 0) == 0 & (n | 0) == 0) {
                          w2 = k;
                          G2 = 16;
                        } else {
                          p2 = 0;
                          q2 = 0;
                          while (1) {
                            if ((p2 | 0) > (d2 | 0) | (p2 | 0) == (d2 | 0) & q2 >>> 0 > c2 >>> 0) {
                              j = 1;
                              break b;
                            }
                            if ((l | 0) == (r2 | 0) & (n | 0) == (s2 | 0)) {
                              break c;
                            }
                            k = ld(o | 0, m | 0, 1, 0) | 0;
                            o = sd(k | 0, H() | 0, c2 | 0, d2 | 0) | 0;
                            m = H() | 0;
                            q2 = ld(q2 | 0, p2 | 0, 1, 0) | 0;
                            p2 = H() | 0;
                            k = i + (o << 3) | 0;
                            n = k;
                            l = b[n >> 2] | 0;
                            n = b[n + 4 >> 2] | 0;
                            if ((l | 0) == 0 & (n | 0) == 0) {
                              w2 = k;
                              G2 = 16;
                              break;
                            }
                          }
                        }
                      } while (0);
                      if ((G2 | 0) == 16 ? (G2 = 0, !((r2 | 0) == 0 & (s2 | 0) == 0)) : 0) {
                        q2 = w2;
                        b[q2 >> 2] = r2;
                        b[q2 + 4 >> 2] = s2;
                        q2 = h + (b[g2 >> 2] << 3) | 0;
                        b[q2 >> 2] = r2;
                        b[q2 + 4 >> 2] = s2;
                        q2 = g2;
                        q2 = ld(b[q2 >> 2] | 0, b[q2 + 4 >> 2] | 0, 1, 0) | 0;
                        r2 = H() | 0;
                        s2 = g2;
                        b[s2 >> 2] = q2;
                        b[s2 + 4 >> 2] = r2;
                      }
                      t2 = ld(t2 | 0, u2 | 0, 1, 0) | 0;
                      u2 = H() | 0;
                      l = F;
                      k = b[l >> 2] | 0;
                      l = b[l + 4 >> 2] | 0;
                      if (!((l | 0) > (u2 | 0) | (l | 0) == (u2 | 0) & k >>> 0 > t2 >>> 0)) {
                        l = 1;
                        break a;
                      }
                    }
                    l = 0;
                  } else {
                    l = 1;
                  }
                } else {
                  l = 0;
                  j = k;
                }
              } while (0);
              v2 = v2 + 1 | 0;
              if (!l) {
                G2 = 21;
                break;
              }
              k = b[a2 >> 2] | 0;
              if ((v2 | 0) >= (k | 0)) {
                j = 0;
                G2 = 21;
                break;
              }
            }
            if ((G2 | 0) == 21) {
              T = I2;
              return j | 0;
            }
            return 0;
          }
          function ja(a2, c2, d2, e2) {
            a2 = a2 | 0;
            c2 = c2 | 0;
            d2 = d2 | 0;
            e2 = e2 | 0;
            var f2 = 0, g2 = 0, h = 0, i = 0, j = 0, k = 0, l = 0, m = 0, n = 0, o = 0, p2 = 0, q2 = 0, r2 = 0, s2 = 0, t2 = 0, u2 = 0, v2 = 0, w2 = 0, x2 = 0, y2 = 0, z2 = 0, A2 = 0, B2 = 0, C2 = 0, D2 = 0, E2 = 0, F = 0, G2 = 0, I2 = 0, J2 = 0, K2 = 0;
            K2 = T;
            T = T + 112 | 0;
            F = K2 + 80 | 0;
            j = K2 + 72 | 0;
            G2 = K2;
            I2 = K2 + 56 | 0;
            if (d2 | 0) {
              J2 = 15;
              T = K2;
              return J2 | 0;
            }
            k = a2 + 8 | 0;
            J2 = id((b[k >> 2] << 5) + 32 | 0) | 0;
            if (!J2) {
              J2 = 13;
              T = K2;
              return J2 | 0;
            }
            Fc(a2, J2);
            D2 = a2;
            E2 = b[D2 + 4 >> 2] | 0;
            d2 = j;
            b[d2 >> 2] = b[D2 >> 2];
            b[d2 + 4 >> 2] = E2;
            Ec(j, F);
            d2 = za(F, c2, G2) | 0;
            if (!d2) {
              d2 = b[j >> 2] | 0;
              g2 = b[k >> 2] | 0;
              if ((g2 | 0) > 0) {
                h = b[a2 + 12 >> 2] | 0;
                f2 = 0;
                do {
                  d2 = (b[h + (f2 << 3) >> 2] | 0) + d2 | 0;
                  f2 = f2 + 1 | 0;
                } while ((f2 | 0) != (g2 | 0));
                f2 = d2;
              } else {
                f2 = d2;
              }
              d2 = G2;
              g2 = b[d2 >> 2] | 0;
              d2 = b[d2 + 4 >> 2] | 0;
              h = ((f2 | 0) < 0) << 31 >> 31;
              if ((d2 | 0) < (h | 0) | (d2 | 0) == (h | 0) & g2 >>> 0 < f2 >>> 0) {
                d2 = G2;
                b[d2 >> 2] = f2;
                b[d2 + 4 >> 2] = h;
                d2 = h;
              } else {
                f2 = g2;
              }
              D2 = ld(f2 | 0, d2 | 0, 12, 0) | 0;
              E2 = H() | 0;
              d2 = G2;
              b[d2 >> 2] = D2;
              b[d2 + 4 >> 2] = E2;
              d2 = 0;
            } else {
              D2 = 0;
              E2 = 0;
            }
            if (d2 | 0) {
              jd(J2);
              J2 = d2;
              T = K2;
              return J2 | 0;
            }
            f2 = kd(D2, 8) | 0;
            if (!f2) {
              jd(J2);
              J2 = 13;
              T = K2;
              return J2 | 0;
            }
            i = kd(D2, 8) | 0;
            if (!i) {
              jd(J2);
              jd(f2);
              J2 = 13;
              T = K2;
              return J2 | 0;
            }
            B2 = F;
            b[B2 >> 2] = 0;
            b[B2 + 4 >> 2] = 0;
            B2 = a2;
            C2 = b[B2 + 4 >> 2] | 0;
            d2 = j;
            b[d2 >> 2] = b[B2 >> 2];
            b[d2 + 4 >> 2] = C2;
            d2 = ia(j, D2, E2, c2, F, f2, i) | 0;
            a: do {
              if (!d2) {
                b: do {
                  if ((b[k >> 2] | 0) > 0) {
                    h = a2 + 12 | 0;
                    g2 = 0;
                    while (1) {
                      d2 = ia((b[h >> 2] | 0) + (g2 << 3) | 0, D2, E2, c2, F, f2, i) | 0;
                      g2 = g2 + 1 | 0;
                      if (d2 | 0) {
                        break;
                      }
                      if ((g2 | 0) >= (b[k >> 2] | 0)) {
                        break b;
                      }
                    }
                    jd(f2);
                    jd(i);
                    jd(J2);
                    break a;
                  }
                } while (0);
                if ((E2 | 0) > 0 | (E2 | 0) == 0 & D2 >>> 0 > 0) {
                  Bd(i | 0, 0, D2 << 3 | 0) | 0;
                }
                C2 = F;
                B2 = b[C2 + 4 >> 2] | 0;
                c: do {
                  if ((B2 | 0) > 0 | (B2 | 0) == 0 & (b[C2 >> 2] | 0) >>> 0 > 0) {
                    y2 = f2;
                    z2 = i;
                    A2 = f2;
                    B2 = i;
                    C2 = f2;
                    d2 = f2;
                    v2 = f2;
                    w2 = i;
                    x2 = i;
                    f2 = i;
                    d: while (1) {
                      r2 = 0;
                      s2 = 0;
                      t2 = 0;
                      u2 = 0;
                      g2 = 0;
                      h = 0;
                      while (1) {
                        i = G2;
                        j = i + 56 | 0;
                        do {
                          b[i >> 2] = 0;
                          i = i + 4 | 0;
                        } while ((i | 0) < (j | 0));
                        c2 = y2 + (r2 << 3) | 0;
                        k = b[c2 >> 2] | 0;
                        c2 = b[c2 + 4 >> 2] | 0;
                        if (ca(k, c2, 1, G2, 0) | 0) {
                          i = G2;
                          j = i + 56 | 0;
                          do {
                            b[i >> 2] = 0;
                            i = i + 4 | 0;
                          } while ((i | 0) < (j | 0));
                          i = kd(7, 4) | 0;
                          if (i | 0) {
                            da(k, c2, 1, G2, i, 7, 0, 0) | 0;
                            jd(i);
                          }
                        }
                        q2 = 0;
                        while (1) {
                          p2 = G2 + (q2 << 3) | 0;
                          o = b[p2 >> 2] | 0;
                          p2 = b[p2 + 4 >> 2] | 0;
                          e: do {
                            if (!((o | 0) == 0 & (p2 | 0) == 0)) {
                              l = td(o | 0, p2 | 0, D2 | 0, E2 | 0) | 0;
                              k = H() | 0;
                              i = e2 + (l << 3) | 0;
                              c2 = i;
                              j = b[c2 >> 2] | 0;
                              c2 = b[c2 + 4 >> 2] | 0;
                              if (!((j | 0) == 0 & (c2 | 0) == 0)) {
                                m = 0;
                                n = 0;
                                do {
                                  if ((m | 0) > (E2 | 0) | (m | 0) == (E2 | 0) & n >>> 0 > D2 >>> 0) {
                                    break d;
                                  }
                                  if ((j | 0) == (o | 0) & (c2 | 0) == (p2 | 0)) {
                                    i = g2;
                                    j = h;
                                    break e;
                                  }
                                  i = ld(l | 0, k | 0, 1, 0) | 0;
                                  l = sd(i | 0, H() | 0, D2 | 0, E2 | 0) | 0;
                                  k = H() | 0;
                                  n = ld(n | 0, m | 0, 1, 0) | 0;
                                  m = H() | 0;
                                  i = e2 + (l << 3) | 0;
                                  c2 = i;
                                  j = b[c2 >> 2] | 0;
                                  c2 = b[c2 + 4 >> 2] | 0;
                                } while (!((j | 0) == 0 & (c2 | 0) == 0));
                              }
                              if (!((o | 0) == 0 & (p2 | 0) == 0)) {
                                Pb(o, p2, I2) | 0;
                                if (Gc(a2, J2, I2) | 0) {
                                  n = ld(g2 | 0, h | 0, 1, 0) | 0;
                                  h = H() | 0;
                                  m = i;
                                  b[m >> 2] = o;
                                  b[m + 4 >> 2] = p2;
                                  g2 = z2 + (g2 << 3) | 0;
                                  b[g2 >> 2] = o;
                                  b[g2 + 4 >> 2] = p2;
                                  g2 = n;
                                }
                                i = g2;
                                j = h;
                              } else {
                                i = g2;
                                j = h;
                              }
                            } else {
                              i = g2;
                              j = h;
                            }
                          } while (0);
                          q2 = q2 + 1 | 0;
                          if (q2 >>> 0 >= 7) {
                            break;
                          } else {
                            g2 = i;
                            h = j;
                          }
                        }
                        r2 = ld(r2 | 0, s2 | 0, 1, 0) | 0;
                        s2 = H() | 0;
                        t2 = ld(t2 | 0, u2 | 0, 1, 0) | 0;
                        u2 = H() | 0;
                        h = F;
                        g2 = b[h >> 2] | 0;
                        h = b[h + 4 >> 2] | 0;
                        if (!((u2 | 0) < (h | 0) | (u2 | 0) == (h | 0) & t2 >>> 0 < g2 >>> 0)) {
                          break;
                        } else {
                          g2 = i;
                          h = j;
                        }
                      }
                      if ((h | 0) > 0 | (h | 0) == 0 & g2 >>> 0 > 0) {
                        g2 = 0;
                        h = 0;
                        do {
                          u2 = y2 + (g2 << 3) | 0;
                          b[u2 >> 2] = 0;
                          b[u2 + 4 >> 2] = 0;
                          g2 = ld(g2 | 0, h | 0, 1, 0) | 0;
                          h = H() | 0;
                          u2 = F;
                          t2 = b[u2 + 4 >> 2] | 0;
                        } while ((h | 0) < (t2 | 0) | ((h | 0) == (t2 | 0) ? g2 >>> 0 < (b[u2 >> 2] | 0) >>> 0 : 0));
                      }
                      u2 = F;
                      b[u2 >> 2] = i;
                      b[u2 + 4 >> 2] = j;
                      if ((j | 0) > 0 | (j | 0) == 0 & i >>> 0 > 0) {
                        q2 = f2;
                        r2 = x2;
                        s2 = C2;
                        t2 = w2;
                        u2 = z2;
                        f2 = v2;
                        x2 = d2;
                        w2 = A2;
                        v2 = q2;
                        d2 = r2;
                        C2 = B2;
                        B2 = s2;
                        A2 = t2;
                        z2 = y2;
                        y2 = u2;
                      } else {
                        break c;
                      }
                    }
                    jd(A2);
                    jd(B2);
                    jd(J2);
                    d2 = 1;
                    break a;
                  } else {
                    d2 = i;
                  }
                } while (0);
                jd(J2);
                jd(f2);
                jd(d2);
                d2 = 0;
              } else {
                jd(f2);
                jd(i);
                jd(J2);
              }
            } while (0);
            J2 = d2;
            T = K2;
            return J2 | 0;
          }
          function ka(a2, c2, d2) {
            a2 = a2 | 0;
            c2 = c2 | 0;
            d2 = d2 | 0;
            var e2 = 0, f2 = 0, g2 = 0, h = 0, i = 0, j = 0, k = 0, l = 0;
            l = T;
            T = T + 176 | 0;
            j = l;
            if ((c2 | 0) < 1) {
              _c(d2, 0, 0);
              k = 0;
              T = l;
              return k | 0;
            }
            i = a2;
            i = vd(b[i >> 2] | 0, b[i + 4 >> 2] | 0, 52) | 0;
            H() | 0;
            _c(d2, (c2 | 0) > 6 ? c2 : 6, i & 15);
            i = 0;
            while (1) {
              e2 = a2 + (i << 3) | 0;
              e2 = Qb(b[e2 >> 2] | 0, b[e2 + 4 >> 2] | 0, j) | 0;
              if (e2 | 0) {
                break;
              }
              e2 = b[j >> 2] | 0;
              if ((e2 | 0) > 0) {
                h = 0;
                do {
                  g2 = j + 8 + (h << 4) | 0;
                  h = h + 1 | 0;
                  e2 = j + 8 + (((h | 0) % (e2 | 0) | 0) << 4) | 0;
                  f2 = dd(d2, e2, g2) | 0;
                  if (!f2) {
                    cd(d2, g2, e2) | 0;
                  } else {
                    bd(d2, f2) | 0;
                  }
                  e2 = b[j >> 2] | 0;
                } while ((h | 0) < (e2 | 0));
              }
              i = i + 1 | 0;
              if ((i | 0) >= (c2 | 0)) {
                e2 = 0;
                k = 13;
                break;
              }
            }
            if ((k | 0) == 13) {
              T = l;
              return e2 | 0;
            }
            $c(d2);
            k = e2;
            T = l;
            return k | 0;
          }
          function la(a2, c2, d2) {
            a2 = a2 | 0;
            c2 = c2 | 0;
            d2 = d2 | 0;
            var e2 = 0, f2 = 0, g2 = 0, h = 0;
            g2 = T;
            T = T + 32 | 0;
            e2 = g2;
            f2 = g2 + 16 | 0;
            a2 = ka(a2, c2, f2) | 0;
            if (a2 | 0) {
              d2 = a2;
              T = g2;
              return d2 | 0;
            }
            b[d2 >> 2] = 0;
            b[d2 + 4 >> 2] = 0;
            b[d2 + 8 >> 2] = 0;
            a2 = ad(f2) | 0;
            if (a2 | 0) {
              do {
                c2 = qc(d2) | 0;
                do {
                  rc(c2, a2) | 0;
                  h = a2 + 16 | 0;
                  b[e2 >> 2] = b[h >> 2];
                  b[e2 + 4 >> 2] = b[h + 4 >> 2];
                  b[e2 + 8 >> 2] = b[h + 8 >> 2];
                  b[e2 + 12 >> 2] = b[h + 12 >> 2];
                  bd(f2, a2) | 0;
                  a2 = ed(f2, e2) | 0;
                } while ((a2 | 0) != 0);
                a2 = ad(f2) | 0;
              } while ((a2 | 0) != 0);
            }
            $c(f2);
            a2 = tc(d2) | 0;
            if (!a2) {
              h = 0;
              T = g2;
              return h | 0;
            }
            sc(d2);
            h = a2;
            T = g2;
            return h | 0;
          }
          function ma(a2) {
            a2 = a2 | 0;
            if (a2 >>> 0 > 121) {
              a2 = 0;
              return a2 | 0;
            }
            a2 = b[7696 + (a2 * 28 | 0) + 16 >> 2] | 0;
            return a2 | 0;
          }
          function na(a2) {
            a2 = a2 | 0;
            return (a2 | 0) == 4 | (a2 | 0) == 117 | 0;
          }
          function oa(a2) {
            a2 = a2 | 0;
            return b[11120 + ((b[a2 >> 2] | 0) * 216 | 0) + ((b[a2 + 4 >> 2] | 0) * 72 | 0) + ((b[a2 + 8 >> 2] | 0) * 24 | 0) + (b[a2 + 12 >> 2] << 3) >> 2] | 0;
          }
          function pa(a2) {
            a2 = a2 | 0;
            return b[11120 + ((b[a2 >> 2] | 0) * 216 | 0) + ((b[a2 + 4 >> 2] | 0) * 72 | 0) + ((b[a2 + 8 >> 2] | 0) * 24 | 0) + (b[a2 + 12 >> 2] << 3) + 4 >> 2] | 0;
          }
          function qa(a2, c2) {
            a2 = a2 | 0;
            c2 = c2 | 0;
            a2 = 7696 + (a2 * 28 | 0) | 0;
            b[c2 >> 2] = b[a2 >> 2];
            b[c2 + 4 >> 2] = b[a2 + 4 >> 2];
            b[c2 + 8 >> 2] = b[a2 + 8 >> 2];
            b[c2 + 12 >> 2] = b[a2 + 12 >> 2];
            return;
          }
          function ra(a2, c2) {
            a2 = a2 | 0;
            c2 = c2 | 0;
            var d2 = 0, e2 = 0;
            if (c2 >>> 0 > 20) {
              c2 = -1;
              return c2 | 0;
            }
            do {
              if ((b[11120 + (c2 * 216 | 0) >> 2] | 0) != (a2 | 0)) {
                if ((b[11120 + (c2 * 216 | 0) + 8 >> 2] | 0) != (a2 | 0)) {
                  if ((b[11120 + (c2 * 216 | 0) + 16 >> 2] | 0) != (a2 | 0)) {
                    if ((b[11120 + (c2 * 216 | 0) + 24 >> 2] | 0) != (a2 | 0)) {
                      if ((b[11120 + (c2 * 216 | 0) + 32 >> 2] | 0) != (a2 | 0)) {
                        if ((b[11120 + (c2 * 216 | 0) + 40 >> 2] | 0) != (a2 | 0)) {
                          if ((b[11120 + (c2 * 216 | 0) + 48 >> 2] | 0) != (a2 | 0)) {
                            if ((b[11120 + (c2 * 216 | 0) + 56 >> 2] | 0) != (a2 | 0)) {
                              if ((b[11120 + (c2 * 216 | 0) + 64 >> 2] | 0) != (a2 | 0)) {
                                if ((b[11120 + (c2 * 216 | 0) + 72 >> 2] | 0) != (a2 | 0)) {
                                  if ((b[11120 + (c2 * 216 | 0) + 80 >> 2] | 0) != (a2 | 0)) {
                                    if ((b[11120 + (c2 * 216 | 0) + 88 >> 2] | 0) != (a2 | 0)) {
                                      if ((b[11120 + (c2 * 216 | 0) + 96 >> 2] | 0) != (a2 | 0)) {
                                        if ((b[11120 + (c2 * 216 | 0) + 104 >> 2] | 0) != (a2 | 0)) {
                                          if ((b[11120 + (c2 * 216 | 0) + 112 >> 2] | 0) != (a2 | 0)) {
                                            if ((b[11120 + (c2 * 216 | 0) + 120 >> 2] | 0) != (a2 | 0)) {
                                              if ((b[11120 + (c2 * 216 | 0) + 128 >> 2] | 0) != (a2 | 0)) {
                                                if ((b[11120 + (c2 * 216 | 0) + 136 >> 2] | 0) == (a2 | 0)) {
                                                  a2 = 2;
                                                  d2 = 1;
                                                  e2 = 2;
                                                } else {
                                                  if ((b[11120 + (c2 * 216 | 0) + 144 >> 2] | 0) == (a2 | 0)) {
                                                    a2 = 0;
                                                    d2 = 2;
                                                    e2 = 0;
                                                    break;
                                                  }
                                                  if ((b[11120 + (c2 * 216 | 0) + 152 >> 2] | 0) == (a2 | 0)) {
                                                    a2 = 0;
                                                    d2 = 2;
                                                    e2 = 1;
                                                    break;
                                                  }
                                                  if ((b[11120 + (c2 * 216 | 0) + 160 >> 2] | 0) == (a2 | 0)) {
                                                    a2 = 0;
                                                    d2 = 2;
                                                    e2 = 2;
                                                    break;
                                                  }
                                                  if ((b[11120 + (c2 * 216 | 0) + 168 >> 2] | 0) == (a2 | 0)) {
                                                    a2 = 1;
                                                    d2 = 2;
                                                    e2 = 0;
                                                    break;
                                                  }
                                                  if ((b[11120 + (c2 * 216 | 0) + 176 >> 2] | 0) == (a2 | 0)) {
                                                    a2 = 1;
                                                    d2 = 2;
                                                    e2 = 1;
                                                    break;
                                                  }
                                                  if ((b[11120 + (c2 * 216 | 0) + 184 >> 2] | 0) == (a2 | 0)) {
                                                    a2 = 1;
                                                    d2 = 2;
                                                    e2 = 2;
                                                    break;
                                                  }
                                                  if ((b[11120 + (c2 * 216 | 0) + 192 >> 2] | 0) == (a2 | 0)) {
                                                    a2 = 2;
                                                    d2 = 2;
                                                    e2 = 0;
                                                    break;
                                                  }
                                                  if ((b[11120 + (c2 * 216 | 0) + 200 >> 2] | 0) == (a2 | 0)) {
                                                    a2 = 2;
                                                    d2 = 2;
                                                    e2 = 1;
                                                    break;
                                                  }
                                                  if ((b[11120 + (c2 * 216 | 0) + 208 >> 2] | 0) == (a2 | 0)) {
                                                    a2 = 2;
                                                    d2 = 2;
                                                    e2 = 2;
                                                    break;
                                                  } else {
                                                    a2 = -1;
                                                  }
                                                  return a2 | 0;
                                                }
                                              } else {
                                                a2 = 2;
                                                d2 = 1;
                                                e2 = 1;
                                              }
                                            } else {
                                              a2 = 2;
                                              d2 = 1;
                                              e2 = 0;
                                            }
                                          } else {
                                            a2 = 1;
                                            d2 = 1;
                                            e2 = 2;
                                          }
                                        } else {
                                          a2 = 1;
                                          d2 = 1;
                                          e2 = 1;
                                        }
                                      } else {
                                        a2 = 1;
                                        d2 = 1;
                                        e2 = 0;
                                      }
                                    } else {
                                      a2 = 0;
                                      d2 = 1;
                                      e2 = 2;
                                    }
                                  } else {
                                    a2 = 0;
                                    d2 = 1;
                                    e2 = 1;
                                  }
                                } else {
                                  a2 = 0;
                                  d2 = 1;
                                  e2 = 0;
                                }
                              } else {
                                a2 = 2;
                                d2 = 0;
                                e2 = 2;
                              }
                            } else {
                              a2 = 2;
                              d2 = 0;
                              e2 = 1;
                            }
                          } else {
                            a2 = 2;
                            d2 = 0;
                            e2 = 0;
                          }
                        } else {
                          a2 = 1;
                          d2 = 0;
                          e2 = 2;
                        }
                      } else {
                        a2 = 1;
                        d2 = 0;
                        e2 = 1;
                      }
                    } else {
                      a2 = 1;
                      d2 = 0;
                      e2 = 0;
                    }
                  } else {
                    a2 = 0;
                    d2 = 0;
                    e2 = 2;
                  }
                } else {
                  a2 = 0;
                  d2 = 0;
                  e2 = 1;
                }
              } else {
                a2 = 0;
                d2 = 0;
                e2 = 0;
              }
            } while (0);
            c2 = b[11120 + (c2 * 216 | 0) + (d2 * 72 | 0) + (a2 * 24 | 0) + (e2 << 3) + 4 >> 2] | 0;
            return c2 | 0;
          }
          function sa(a2, c2) {
            a2 = a2 | 0;
            c2 = c2 | 0;
            if ((b[7696 + (a2 * 28 | 0) + 20 >> 2] | 0) == (c2 | 0)) {
              c2 = 1;
              return c2 | 0;
            }
            c2 = (b[7696 + (a2 * 28 | 0) + 24 >> 2] | 0) == (c2 | 0);
            return c2 | 0;
          }
          function ta(a2, c2) {
            a2 = a2 | 0;
            c2 = c2 | 0;
            return b[848 + (a2 * 28 | 0) + (c2 << 2) >> 2] | 0;
          }
          function ua(a2, c2) {
            a2 = a2 | 0;
            c2 = c2 | 0;
            if ((b[848 + (a2 * 28 | 0) >> 2] | 0) == (c2 | 0)) {
              c2 = 0;
              return c2 | 0;
            }
            if ((b[848 + (a2 * 28 | 0) + 4 >> 2] | 0) == (c2 | 0)) {
              c2 = 1;
              return c2 | 0;
            }
            if ((b[848 + (a2 * 28 | 0) + 8 >> 2] | 0) == (c2 | 0)) {
              c2 = 2;
              return c2 | 0;
            }
            if ((b[848 + (a2 * 28 | 0) + 12 >> 2] | 0) == (c2 | 0)) {
              c2 = 3;
              return c2 | 0;
            }
            if ((b[848 + (a2 * 28 | 0) + 16 >> 2] | 0) == (c2 | 0)) {
              c2 = 4;
              return c2 | 0;
            }
            if ((b[848 + (a2 * 28 | 0) + 20 >> 2] | 0) == (c2 | 0)) {
              c2 = 5;
              return c2 | 0;
            } else {
              return ((b[848 + (a2 * 28 | 0) + 24 >> 2] | 0) == (c2 | 0) ? 6 : 7) | 0;
            }
            return 0;
          }
          function va() {
            return 122;
          }
          function wa(a2) {
            a2 = a2 | 0;
            var c2 = 0, d2 = 0, e2 = 0;
            c2 = 0;
            do {
              wd(c2 | 0, 0, 45) | 0;
              e2 = H() | 0 | 134225919;
              d2 = a2 + (c2 << 3) | 0;
              b[d2 >> 2] = -1;
              b[d2 + 4 >> 2] = e2;
              c2 = c2 + 1 | 0;
            } while ((c2 | 0) != 122);
            return 0;
          }
          function xa(a2) {
            a2 = a2 | 0;
            return +e[a2 + 16 >> 3] < +e[a2 + 24 >> 3] | 0;
          }
          function ya(a2, b2) {
            a2 = a2 | 0;
            b2 = b2 | 0;
            var c2 = 0, d2 = 0, f2 = 0;
            c2 = +e[b2 >> 3];
            if (!(c2 >= +e[a2 + 8 >> 3])) {
              b2 = 0;
              return b2 | 0;
            }
            if (!(c2 <= +e[a2 >> 3])) {
              b2 = 0;
              return b2 | 0;
            }
            d2 = +e[a2 + 16 >> 3];
            c2 = +e[a2 + 24 >> 3];
            f2 = +e[b2 + 8 >> 3];
            b2 = f2 >= c2;
            a2 = f2 <= d2 & 1;
            if (d2 < c2) {
              if (b2) {
                a2 = 1;
              }
            } else if (!b2) {
              a2 = 0;
            }
            b2 = (a2 | 0) != 0;
            return b2 | 0;
          }
          function za(a2, c2, d2) {
            a2 = a2 | 0;
            c2 = c2 | 0;
            d2 = d2 | 0;
            var g2 = 0, h = 0, i = 0, j = 0, k = 0, l = 0, m = 0, n = 0, o = 0, r2 = 0, s2 = 0, t2 = 0, u2 = 0, v2 = 0;
            t2 = T;
            T = T + 288 | 0;
            n = t2 + 264 | 0;
            o = t2 + 96 | 0;
            m = t2;
            k = m;
            l = k + 96 | 0;
            do {
              b[k >> 2] = 0;
              k = k + 4 | 0;
            } while ((k | 0) < (l | 0));
            c2 = Ub(c2, m) | 0;
            if (c2 | 0) {
              s2 = c2;
              T = t2;
              return s2 | 0;
            }
            l = m;
            m = b[l >> 2] | 0;
            l = b[l + 4 >> 2] | 0;
            Pb(m, l, n) | 0;
            Qb(m, l, o) | 0;
            j = +ac(n, o + 8 | 0);
            e[n >> 3] = +e[a2 >> 3];
            l = n + 8 | 0;
            e[l >> 3] = +e[a2 + 16 >> 3];
            e[o >> 3] = +e[a2 + 8 >> 3];
            m = o + 8 | 0;
            e[m >> 3] = +e[a2 + 24 >> 3];
            h = +ac(n, o);
            v2 = +e[l >> 3] - +e[m >> 3];
            i = +q(+v2);
            u2 = +e[n >> 3] - +e[o >> 3];
            g2 = +q(+u2);
            if (!(v2 == 0 | u2 == 0) ? (v2 = +xd(+i, +g2), v2 = +A(+(h * h / +yd(+(v2 / +yd(+i, +g2)), 3) / (j * (j * 2.59807621135) * 0.8))), e[f >> 3] = v2, r2 = ~~v2 >>> 0, s2 = +q(v2) >= 1 ? v2 > 0 ? ~~+C(+p(v2 / 4294967296), 4294967295) >>> 0 : ~~+A((v2 - +(~~v2 >>> 0)) / 4294967296) >>> 0 : 0, !((b[f + 4 >> 2] & 2146435072 | 0) == 2146435072)) : 0) {
              o = (r2 | 0) == 0 & (s2 | 0) == 0;
              c2 = d2;
              b[c2 >> 2] = o ? 1 : r2;
              b[c2 + 4 >> 2] = o ? 0 : s2;
              c2 = 0;
            } else {
              c2 = 1;
            }
            s2 = c2;
            T = t2;
            return s2 | 0;
          }
          function Aa(a2, c2, d2, g2) {
            a2 = a2 | 0;
            c2 = c2 | 0;
            d2 = d2 | 0;
            g2 = g2 | 0;
            var h = 0, i = 0, j = 0, k = 0, l = 0, m = 0, n = 0;
            m = T;
            T = T + 288 | 0;
            j = m + 264 | 0;
            k = m + 96 | 0;
            l = m;
            h = l;
            i = h + 96 | 0;
            do {
              b[h >> 2] = 0;
              h = h + 4 | 0;
            } while ((h | 0) < (i | 0));
            d2 = Ub(d2, l) | 0;
            if (d2 | 0) {
              g2 = d2;
              T = m;
              return g2 | 0;
            }
            d2 = l;
            h = b[d2 >> 2] | 0;
            d2 = b[d2 + 4 >> 2] | 0;
            Pb(h, d2, j) | 0;
            Qb(h, d2, k) | 0;
            n = +ac(j, k + 8 | 0);
            n = +A(+(+ac(a2, c2) / (n * 2)));
            e[f >> 3] = n;
            d2 = ~~n >>> 0;
            h = +q(n) >= 1 ? n > 0 ? ~~+C(+p(n / 4294967296), 4294967295) >>> 0 : ~~+A((n - +(~~n >>> 0)) / 4294967296) >>> 0 : 0;
            if ((b[f + 4 >> 2] & 2146435072 | 0) == 2146435072) {
              g2 = 1;
              T = m;
              return g2 | 0;
            }
            l = (d2 | 0) == 0 & (h | 0) == 0;
            b[g2 >> 2] = l ? 1 : d2;
            b[g2 + 4 >> 2] = l ? 0 : h;
            g2 = 0;
            T = m;
            return g2 | 0;
          }
          function Ba(a2, c2, d2, e2) {
            a2 = a2 | 0;
            c2 = c2 | 0;
            d2 = d2 | 0;
            e2 = e2 | 0;
            b[a2 >> 2] = c2;
            b[a2 + 4 >> 2] = d2;
            b[a2 + 8 >> 2] = e2;
            return;
          }
          function Ca(a2, c2) {
            a2 = a2 | 0;
            c2 = c2 | 0;
            var d2 = 0, f2 = 0, g2 = 0, h = 0, i = 0, j = 0, k = 0, l = 0, m = 0, n = 0, o = 0;
            n = c2 + 8 | 0;
            b[n >> 2] = 0;
            k = +e[a2 >> 3];
            i = +q(+k);
            l = +e[a2 + 8 >> 3];
            j = +q(+l) / 0.8660254037844386;
            i = i + j * 0.5;
            d2 = ~~i;
            a2 = ~~j;
            i = i - +(d2 | 0);
            j = j - +(a2 | 0);
            do {
              if (i < 0.5) {
                if (i < 0.3333333333333333) {
                  b[c2 >> 2] = d2;
                  if (j < (i + 1) * 0.5) {
                    b[c2 + 4 >> 2] = a2;
                    break;
                  } else {
                    a2 = a2 + 1 | 0;
                    b[c2 + 4 >> 2] = a2;
                    break;
                  }
                } else {
                  o = 1 - i;
                  a2 = (!(j < o) & 1) + a2 | 0;
                  b[c2 + 4 >> 2] = a2;
                  if (o <= j & j < i * 2) {
                    d2 = d2 + 1 | 0;
                    b[c2 >> 2] = d2;
                    break;
                  } else {
                    b[c2 >> 2] = d2;
                    break;
                  }
                }
              } else {
                if (!(i < 0.6666666666666666)) {
                  d2 = d2 + 1 | 0;
                  b[c2 >> 2] = d2;
                  if (j < i * 0.5) {
                    b[c2 + 4 >> 2] = a2;
                    break;
                  } else {
                    a2 = a2 + 1 | 0;
                    b[c2 + 4 >> 2] = a2;
                    break;
                  }
                }
                if (j < 1 - i) {
                  b[c2 + 4 >> 2] = a2;
                  if (i * 2 + -1 < j) {
                    b[c2 >> 2] = d2;
                    break;
                  }
                } else {
                  a2 = a2 + 1 | 0;
                  b[c2 + 4 >> 2] = a2;
                }
                d2 = d2 + 1 | 0;
                b[c2 >> 2] = d2;
              }
            } while (0);
            do {
              if (k < 0) {
                if (!(a2 & 1)) {
                  m = (a2 | 0) / 2 | 0;
                  m = md(d2 | 0, ((d2 | 0) < 0) << 31 >> 31 | 0, m | 0, ((m | 0) < 0) << 31 >> 31 | 0) | 0;
                  d2 = ~~(+(d2 | 0) - (+(m >>> 0) + 4294967296 * +(H() | 0)) * 2);
                  b[c2 >> 2] = d2;
                  break;
                } else {
                  m = (a2 + 1 | 0) / 2 | 0;
                  m = md(d2 | 0, ((d2 | 0) < 0) << 31 >> 31 | 0, m | 0, ((m | 0) < 0) << 31 >> 31 | 0) | 0;
                  d2 = ~~(+(d2 | 0) - ((+(m >>> 0) + 4294967296 * +(H() | 0)) * 2 + 1));
                  b[c2 >> 2] = d2;
                  break;
                }
              }
            } while (0);
            m = c2 + 4 | 0;
            if (l < 0) {
              d2 = d2 - ((a2 << 1 | 1 | 0) / 2 | 0) | 0;
              b[c2 >> 2] = d2;
              a2 = 0 - a2 | 0;
              b[m >> 2] = a2;
            }
            f2 = a2 - d2 | 0;
            if ((d2 | 0) < 0) {
              g2 = 0 - d2 | 0;
              b[m >> 2] = f2;
              b[n >> 2] = g2;
              b[c2 >> 2] = 0;
              a2 = f2;
              d2 = 0;
            } else {
              g2 = 0;
            }
            if ((a2 | 0) < 0) {
              d2 = d2 - a2 | 0;
              b[c2 >> 2] = d2;
              g2 = g2 - a2 | 0;
              b[n >> 2] = g2;
              b[m >> 2] = 0;
              a2 = 0;
            }
            h = d2 - g2 | 0;
            f2 = a2 - g2 | 0;
            if ((g2 | 0) < 0) {
              b[c2 >> 2] = h;
              b[m >> 2] = f2;
              b[n >> 2] = 0;
              a2 = f2;
              d2 = h;
              g2 = 0;
            }
            f2 = (a2 | 0) < (d2 | 0) ? a2 : d2;
            f2 = (g2 | 0) < (f2 | 0) ? g2 : f2;
            if ((f2 | 0) <= 0) {
              return;
            }
            b[c2 >> 2] = d2 - f2;
            b[m >> 2] = a2 - f2;
            b[n >> 2] = g2 - f2;
            return;
          }
          function Da(a2) {
            a2 = a2 | 0;
            var c2 = 0, d2 = 0, e2 = 0, f2 = 0, g2 = 0, h = 0;
            c2 = b[a2 >> 2] | 0;
            h = a2 + 4 | 0;
            d2 = b[h >> 2] | 0;
            if ((c2 | 0) < 0) {
              d2 = d2 - c2 | 0;
              b[h >> 2] = d2;
              g2 = a2 + 8 | 0;
              b[g2 >> 2] = (b[g2 >> 2] | 0) - c2;
              b[a2 >> 2] = 0;
              c2 = 0;
            }
            if ((d2 | 0) < 0) {
              c2 = c2 - d2 | 0;
              b[a2 >> 2] = c2;
              g2 = a2 + 8 | 0;
              f2 = (b[g2 >> 2] | 0) - d2 | 0;
              b[g2 >> 2] = f2;
              b[h >> 2] = 0;
              d2 = 0;
            } else {
              f2 = a2 + 8 | 0;
              g2 = f2;
              f2 = b[f2 >> 2] | 0;
            }
            if ((f2 | 0) < 0) {
              c2 = c2 - f2 | 0;
              b[a2 >> 2] = c2;
              d2 = d2 - f2 | 0;
              b[h >> 2] = d2;
              b[g2 >> 2] = 0;
              f2 = 0;
            }
            e2 = (d2 | 0) < (c2 | 0) ? d2 : c2;
            e2 = (f2 | 0) < (e2 | 0) ? f2 : e2;
            if ((e2 | 0) <= 0) {
              return;
            }
            b[a2 >> 2] = c2 - e2;
            b[h >> 2] = d2 - e2;
            b[g2 >> 2] = f2 - e2;
            return;
          }
          function Ea(a2, c2) {
            a2 = a2 | 0;
            c2 = c2 | 0;
            var d2 = 0, f2 = 0;
            f2 = b[a2 + 8 >> 2] | 0;
            d2 = +((b[a2 + 4 >> 2] | 0) - f2 | 0);
            e[c2 >> 3] = +((b[a2 >> 2] | 0) - f2 | 0) - d2 * 0.5;
            e[c2 + 8 >> 3] = d2 * 0.8660254037844386;
            return;
          }
          function Fa(a2, c2, d2) {
            a2 = a2 | 0;
            c2 = c2 | 0;
            d2 = d2 | 0;
            b[d2 >> 2] = (b[c2 >> 2] | 0) + (b[a2 >> 2] | 0);
            b[d2 + 4 >> 2] = (b[c2 + 4 >> 2] | 0) + (b[a2 + 4 >> 2] | 0);
            b[d2 + 8 >> 2] = (b[c2 + 8 >> 2] | 0) + (b[a2 + 8 >> 2] | 0);
            return;
          }
          function Ga(a2, c2, d2) {
            a2 = a2 | 0;
            c2 = c2 | 0;
            d2 = d2 | 0;
            b[d2 >> 2] = (b[a2 >> 2] | 0) - (b[c2 >> 2] | 0);
            b[d2 + 4 >> 2] = (b[a2 + 4 >> 2] | 0) - (b[c2 + 4 >> 2] | 0);
            b[d2 + 8 >> 2] = (b[a2 + 8 >> 2] | 0) - (b[c2 + 8 >> 2] | 0);
            return;
          }
          function Ha(a2, c2) {
            a2 = a2 | 0;
            c2 = c2 | 0;
            var d2 = 0, e2 = 0;
            d2 = B(b[a2 >> 2] | 0, c2) | 0;
            b[a2 >> 2] = d2;
            d2 = a2 + 4 | 0;
            e2 = B(b[d2 >> 2] | 0, c2) | 0;
            b[d2 >> 2] = e2;
            a2 = a2 + 8 | 0;
            c2 = B(b[a2 >> 2] | 0, c2) | 0;
            b[a2 >> 2] = c2;
            return;
          }
          function Ia(a2) {
            a2 = a2 | 0;
            var c2 = 0, d2 = 0, e2 = 0, f2 = 0, g2 = 0, h = 0, i = 0;
            h = b[a2 >> 2] | 0;
            i = (h | 0) < 0;
            e2 = (b[a2 + 4 >> 2] | 0) - (i ? h : 0) | 0;
            g2 = (e2 | 0) < 0;
            f2 = (g2 ? 0 - e2 | 0 : 0) + ((b[a2 + 8 >> 2] | 0) - (i ? h : 0)) | 0;
            d2 = (f2 | 0) < 0;
            a2 = d2 ? 0 : f2;
            c2 = (g2 ? 0 : e2) - (d2 ? f2 : 0) | 0;
            f2 = (i ? 0 : h) - (g2 ? e2 : 0) - (d2 ? f2 : 0) | 0;
            d2 = (c2 | 0) < (f2 | 0) ? c2 : f2;
            d2 = (a2 | 0) < (d2 | 0) ? a2 : d2;
            e2 = (d2 | 0) > 0;
            a2 = a2 - (e2 ? d2 : 0) | 0;
            c2 = c2 - (e2 ? d2 : 0) | 0;
            a: do {
              switch (f2 - (e2 ? d2 : 0) | 0) {
                case 0:
                  switch (c2 | 0) {
                    case 0: {
                      i = (a2 | 0) == 0 ? 0 : (a2 | 0) == 1 ? 1 : 7;
                      return i | 0;
                    }
                    case 1: {
                      i = (a2 | 0) == 0 ? 2 : (a2 | 0) == 1 ? 3 : 7;
                      return i | 0;
                    }
                    default:
                      break a;
                  }
                case 1:
                  switch (c2 | 0) {
                    case 0: {
                      i = (a2 | 0) == 0 ? 4 : (a2 | 0) == 1 ? 5 : 7;
                      return i | 0;
                    }
                    case 1: {
                      if (!a2) {
                        a2 = 6;
                      } else {
                        break a;
                      }
                      return a2 | 0;
                    }
                    default:
                      break a;
                  }
                default:
              }
            } while (0);
            i = 7;
            return i | 0;
          }
          function Ja(a2) {
            a2 = a2 | 0;
            var c2 = 0, d2 = 0, e2 = 0, f2 = 0, g2 = 0, h = 0, i = 0;
            h = a2 + 8 | 0;
            f2 = b[h >> 2] | 0;
            g2 = (b[a2 >> 2] | 0) - f2 | 0;
            i = a2 + 4 | 0;
            f2 = (b[i >> 2] | 0) - f2 | 0;
            do {
              if (g2 >>> 0 > 715827881 | f2 >>> 0 > 715827881) {
                d2 = (g2 | 0) > 0;
                if (d2) {
                  if ((2147483647 - g2 | 0) < (g2 | 0)) {
                    i = 1;
                    return i | 0;
                  }
                  if ((2147483647 - (g2 << 1) | 0) < (g2 | 0)) {
                    i = 1;
                    return i | 0;
                  }
                } else {
                  if ((-2147483648 - g2 | 0) > (g2 | 0)) {
                    i = 1;
                    return i | 0;
                  }
                  if ((-2147483648 - (g2 << 1) | 0) > (g2 | 0)) {
                    i = 1;
                    return i | 0;
                  }
                }
                c2 = g2 * 3 | 0;
                if ((f2 | 0) > 0) {
                  if ((2147483647 - f2 | 0) < (f2 | 0)) {
                    i = 1;
                    return i | 0;
                  }
                } else if ((-2147483648 - f2 | 0) > (f2 | 0)) {
                  i = 1;
                  return i | 0;
                }
                e2 = f2 << 1;
                if ((g2 | 0) > -1) {
                  if ((c2 | -2147483648 | 0) >= (f2 | 0)) {
                    i = 1;
                    return i | 0;
                  }
                } else if ((c2 ^ -2147483648 | 0) < (f2 | 0)) {
                  i = 1;
                  return i | 0;
                }
                if (d2) {
                  if ((2147483647 - g2 | 0) < (e2 | 0)) {
                    c2 = 1;
                  } else {
                    d2 = e2;
                    break;
                  }
                  return c2 | 0;
                } else {
                  if ((-2147483648 - g2 | 0) > (e2 | 0)) {
                    c2 = 1;
                  } else {
                    d2 = e2;
                    break;
                  }
                  return c2 | 0;
                }
              } else {
                d2 = f2 << 1;
                c2 = g2 * 3 | 0;
              }
            } while (0);
            e2 = hd(+(c2 - f2 | 0) / 7) | 0;
            b[a2 >> 2] = e2;
            f2 = hd(+(d2 + g2 | 0) / 7) | 0;
            b[i >> 2] = f2;
            b[h >> 2] = 0;
            d2 = (f2 | 0) < (e2 | 0);
            c2 = d2 ? e2 : f2;
            d2 = d2 ? f2 : e2;
            do {
              if ((d2 | 0) < 0) {
                if ((c2 | 0) > 0) {
                  if ((c2 | -2147483648 | 0) < (d2 | 0) & ((d2 | 0) != -2147483648 & (2147483647 - c2 | 0) >= (d2 | 0))) {
                    break;
                  }
                  I(23313, 22444, 355, 22455);
                }
                if ((d2 | 0) == -2147483648 | (-2147483648 - c2 | 0) > (d2 | 0)) {
                  I(23313, 22444, 355, 22455);
                }
                if ((c2 | 0) > -1) {
                  if ((c2 | -2147483648 | 0) < (d2 | 0)) {
                    break;
                  }
                  I(23313, 22444, 355, 22455);
                } else {
                  if ((c2 ^ -2147483648 | 0) >= (d2 | 0)) {
                    break;
                  }
                  I(23313, 22444, 355, 22455);
                }
              }
            } while (0);
            c2 = f2 - e2 | 0;
            if ((e2 | 0) < 0) {
              d2 = 0 - e2 | 0;
              b[i >> 2] = c2;
              b[h >> 2] = d2;
              b[a2 >> 2] = 0;
              e2 = 0;
            } else {
              c2 = f2;
              d2 = 0;
            }
            if ((c2 | 0) < 0) {
              e2 = e2 - c2 | 0;
              b[a2 >> 2] = e2;
              d2 = d2 - c2 | 0;
              b[h >> 2] = d2;
              b[i >> 2] = 0;
              c2 = 0;
            }
            g2 = e2 - d2 | 0;
            f2 = c2 - d2 | 0;
            if ((d2 | 0) < 0) {
              b[a2 >> 2] = g2;
              b[i >> 2] = f2;
              b[h >> 2] = 0;
              c2 = f2;
              f2 = g2;
              d2 = 0;
            } else {
              f2 = e2;
            }
            e2 = (c2 | 0) < (f2 | 0) ? c2 : f2;
            e2 = (d2 | 0) < (e2 | 0) ? d2 : e2;
            if ((e2 | 0) <= 0) {
              i = 0;
              return i | 0;
            }
            b[a2 >> 2] = f2 - e2;
            b[i >> 2] = c2 - e2;
            b[h >> 2] = d2 - e2;
            i = 0;
            return i | 0;
          }
          function Ka(a2) {
            a2 = a2 | 0;
            var c2 = 0, d2 = 0, e2 = 0, f2 = 0, g2 = 0, h = 0, i = 0;
            h = a2 + 8 | 0;
            f2 = b[h >> 2] | 0;
            g2 = (b[a2 >> 2] | 0) - f2 | 0;
            i = a2 + 4 | 0;
            f2 = (b[i >> 2] | 0) - f2 | 0;
            do {
              if (g2 >>> 0 > 715827881 | f2 >>> 0 > 715827881) {
                d2 = (g2 | 0) > 0;
                if (d2) {
                  if ((2147483647 - g2 | 0) < (g2 | 0)) {
                    i = 1;
                    return i | 0;
                  }
                } else if ((-2147483648 - g2 | 0) > (g2 | 0)) {
                  i = 1;
                  return i | 0;
                }
                c2 = g2 << 1;
                if ((f2 | 0) > 0) {
                  if ((2147483647 - f2 | 0) < (f2 | 0)) {
                    i = 1;
                    return i | 0;
                  }
                  if ((2147483647 - (f2 << 1) | 0) < (f2 | 0)) {
                    i = 1;
                    return i | 0;
                  }
                } else {
                  if ((-2147483648 - f2 | 0) > (f2 | 0)) {
                    i = 1;
                    return i | 0;
                  }
                  if ((-2147483648 - (f2 << 1) | 0) > (f2 | 0)) {
                    i = 1;
                    return i | 0;
                  }
                }
                e2 = f2 * 3 | 0;
                if (d2) {
                  if ((2147483647 - c2 | 0) < (f2 | 0)) {
                    i = 1;
                    return i | 0;
                  }
                } else if ((-2147483648 - c2 | 0) > (f2 | 0)) {
                  i = 1;
                  return i | 0;
                }
                if ((f2 | 0) > -1) {
                  if ((e2 | -2147483648 | 0) < (g2 | 0)) {
                    d2 = e2;
                    break;
                  } else {
                    c2 = 1;
                  }
                  return c2 | 0;
                } else {
                  if ((e2 ^ -2147483648 | 0) < (g2 | 0)) {
                    c2 = 1;
                  } else {
                    d2 = e2;
                    break;
                  }
                  return c2 | 0;
                }
              } else {
                d2 = f2 * 3 | 0;
                c2 = g2 << 1;
              }
            } while (0);
            e2 = hd(+(c2 + f2 | 0) / 7) | 0;
            b[a2 >> 2] = e2;
            f2 = hd(+(d2 - g2 | 0) / 7) | 0;
            b[i >> 2] = f2;
            b[h >> 2] = 0;
            d2 = (f2 | 0) < (e2 | 0);
            c2 = d2 ? e2 : f2;
            d2 = d2 ? f2 : e2;
            do {
              if ((d2 | 0) < 0) {
                if ((c2 | 0) > 0) {
                  if ((c2 | -2147483648 | 0) < (d2 | 0) & ((d2 | 0) != -2147483648 & (2147483647 - c2 | 0) >= (d2 | 0))) {
                    break;
                  }
                  I(23313, 22444, 404, 22469);
                }
                if ((d2 | 0) == -2147483648 | (-2147483648 - c2 | 0) > (d2 | 0)) {
                  I(23313, 22444, 404, 22469);
                }
                if ((c2 | 0) > -1) {
                  if ((c2 | -2147483648 | 0) < (d2 | 0)) {
                    break;
                  }
                  I(23313, 22444, 404, 22469);
                } else {
                  if ((c2 ^ -2147483648 | 0) >= (d2 | 0)) {
                    break;
                  }
                  I(23313, 22444, 404, 22469);
                }
              }
            } while (0);
            c2 = f2 - e2 | 0;
            if ((e2 | 0) < 0) {
              d2 = 0 - e2 | 0;
              b[i >> 2] = c2;
              b[h >> 2] = d2;
              b[a2 >> 2] = 0;
              e2 = 0;
            } else {
              c2 = f2;
              d2 = 0;
            }
            if ((c2 | 0) < 0) {
              e2 = e2 - c2 | 0;
              b[a2 >> 2] = e2;
              d2 = d2 - c2 | 0;
              b[h >> 2] = d2;
              b[i >> 2] = 0;
              c2 = 0;
            }
            g2 = e2 - d2 | 0;
            f2 = c2 - d2 | 0;
            if ((d2 | 0) < 0) {
              b[a2 >> 2] = g2;
              b[i >> 2] = f2;
              b[h >> 2] = 0;
              c2 = f2;
              f2 = g2;
              d2 = 0;
            } else {
              f2 = e2;
            }
            e2 = (c2 | 0) < (f2 | 0) ? c2 : f2;
            e2 = (d2 | 0) < (e2 | 0) ? d2 : e2;
            if ((e2 | 0) <= 0) {
              i = 0;
              return i | 0;
            }
            b[a2 >> 2] = f2 - e2;
            b[i >> 2] = c2 - e2;
            b[h >> 2] = d2 - e2;
            i = 0;
            return i | 0;
          }
          function La(a2) {
            a2 = a2 | 0;
            var c2 = 0, d2 = 0, e2 = 0, f2 = 0, g2 = 0, h = 0, i = 0;
            h = a2 + 8 | 0;
            d2 = b[h >> 2] | 0;
            c2 = (b[a2 >> 2] | 0) - d2 | 0;
            i = a2 + 4 | 0;
            d2 = (b[i >> 2] | 0) - d2 | 0;
            e2 = hd(+((c2 * 3 | 0) - d2 | 0) / 7) | 0;
            b[a2 >> 2] = e2;
            c2 = hd(+((d2 << 1) + c2 | 0) / 7) | 0;
            b[i >> 2] = c2;
            b[h >> 2] = 0;
            d2 = c2 - e2 | 0;
            if ((e2 | 0) < 0) {
              g2 = 0 - e2 | 0;
              b[i >> 2] = d2;
              b[h >> 2] = g2;
              b[a2 >> 2] = 0;
              c2 = d2;
              e2 = 0;
              d2 = g2;
            } else {
              d2 = 0;
            }
            if ((c2 | 0) < 0) {
              e2 = e2 - c2 | 0;
              b[a2 >> 2] = e2;
              d2 = d2 - c2 | 0;
              b[h >> 2] = d2;
              b[i >> 2] = 0;
              c2 = 0;
            }
            g2 = e2 - d2 | 0;
            f2 = c2 - d2 | 0;
            if ((d2 | 0) < 0) {
              b[a2 >> 2] = g2;
              b[i >> 2] = f2;
              b[h >> 2] = 0;
              c2 = f2;
              f2 = g2;
              d2 = 0;
            } else {
              f2 = e2;
            }
            e2 = (c2 | 0) < (f2 | 0) ? c2 : f2;
            e2 = (d2 | 0) < (e2 | 0) ? d2 : e2;
            if ((e2 | 0) <= 0) {
              return;
            }
            b[a2 >> 2] = f2 - e2;
            b[i >> 2] = c2 - e2;
            b[h >> 2] = d2 - e2;
            return;
          }
          function Ma(a2) {
            a2 = a2 | 0;
            var c2 = 0, d2 = 0, e2 = 0, f2 = 0, g2 = 0, h = 0, i = 0;
            h = a2 + 8 | 0;
            d2 = b[h >> 2] | 0;
            c2 = (b[a2 >> 2] | 0) - d2 | 0;
            i = a2 + 4 | 0;
            d2 = (b[i >> 2] | 0) - d2 | 0;
            e2 = hd(+((c2 << 1) + d2 | 0) / 7) | 0;
            b[a2 >> 2] = e2;
            c2 = hd(+((d2 * 3 | 0) - c2 | 0) / 7) | 0;
            b[i >> 2] = c2;
            b[h >> 2] = 0;
            d2 = c2 - e2 | 0;
            if ((e2 | 0) < 0) {
              g2 = 0 - e2 | 0;
              b[i >> 2] = d2;
              b[h >> 2] = g2;
              b[a2 >> 2] = 0;
              c2 = d2;
              e2 = 0;
              d2 = g2;
            } else {
              d2 = 0;
            }
            if ((c2 | 0) < 0) {
              e2 = e2 - c2 | 0;
              b[a2 >> 2] = e2;
              d2 = d2 - c2 | 0;
              b[h >> 2] = d2;
              b[i >> 2] = 0;
              c2 = 0;
            }
            g2 = e2 - d2 | 0;
            f2 = c2 - d2 | 0;
            if ((d2 | 0) < 0) {
              b[a2 >> 2] = g2;
              b[i >> 2] = f2;
              b[h >> 2] = 0;
              c2 = f2;
              f2 = g2;
              d2 = 0;
            } else {
              f2 = e2;
            }
            e2 = (c2 | 0) < (f2 | 0) ? c2 : f2;
            e2 = (d2 | 0) < (e2 | 0) ? d2 : e2;
            if ((e2 | 0) <= 0) {
              return;
            }
            b[a2 >> 2] = f2 - e2;
            b[i >> 2] = c2 - e2;
            b[h >> 2] = d2 - e2;
            return;
          }
          function Na(a2) {
            a2 = a2 | 0;
            var c2 = 0, d2 = 0, e2 = 0, f2 = 0, g2 = 0, h = 0, i = 0;
            c2 = b[a2 >> 2] | 0;
            h = a2 + 4 | 0;
            d2 = b[h >> 2] | 0;
            i = a2 + 8 | 0;
            e2 = b[i >> 2] | 0;
            f2 = d2 + (c2 * 3 | 0) | 0;
            b[a2 >> 2] = f2;
            d2 = e2 + (d2 * 3 | 0) | 0;
            b[h >> 2] = d2;
            c2 = (e2 * 3 | 0) + c2 | 0;
            b[i >> 2] = c2;
            e2 = d2 - f2 | 0;
            if ((f2 | 0) < 0) {
              c2 = c2 - f2 | 0;
              b[h >> 2] = e2;
              b[i >> 2] = c2;
              b[a2 >> 2] = 0;
              d2 = e2;
              e2 = 0;
            } else {
              e2 = f2;
            }
            if ((d2 | 0) < 0) {
              e2 = e2 - d2 | 0;
              b[a2 >> 2] = e2;
              c2 = c2 - d2 | 0;
              b[i >> 2] = c2;
              b[h >> 2] = 0;
              d2 = 0;
            }
            g2 = e2 - c2 | 0;
            f2 = d2 - c2 | 0;
            if ((c2 | 0) < 0) {
              b[a2 >> 2] = g2;
              b[h >> 2] = f2;
              b[i >> 2] = 0;
              e2 = g2;
              c2 = 0;
            } else {
              f2 = d2;
            }
            d2 = (f2 | 0) < (e2 | 0) ? f2 : e2;
            d2 = (c2 | 0) < (d2 | 0) ? c2 : d2;
            if ((d2 | 0) <= 0) {
              return;
            }
            b[a2 >> 2] = e2 - d2;
            b[h >> 2] = f2 - d2;
            b[i >> 2] = c2 - d2;
            return;
          }
          function Oa(a2) {
            a2 = a2 | 0;
            var c2 = 0, d2 = 0, e2 = 0, f2 = 0, g2 = 0, h = 0, i = 0;
            f2 = b[a2 >> 2] | 0;
            h = a2 + 4 | 0;
            c2 = b[h >> 2] | 0;
            i = a2 + 8 | 0;
            d2 = b[i >> 2] | 0;
            e2 = (c2 * 3 | 0) + f2 | 0;
            f2 = d2 + (f2 * 3 | 0) | 0;
            b[a2 >> 2] = f2;
            b[h >> 2] = e2;
            c2 = (d2 * 3 | 0) + c2 | 0;
            b[i >> 2] = c2;
            d2 = e2 - f2 | 0;
            if ((f2 | 0) < 0) {
              c2 = c2 - f2 | 0;
              b[h >> 2] = d2;
              b[i >> 2] = c2;
              b[a2 >> 2] = 0;
              f2 = 0;
            } else {
              d2 = e2;
            }
            if ((d2 | 0) < 0) {
              f2 = f2 - d2 | 0;
              b[a2 >> 2] = f2;
              c2 = c2 - d2 | 0;
              b[i >> 2] = c2;
              b[h >> 2] = 0;
              d2 = 0;
            }
            g2 = f2 - c2 | 0;
            e2 = d2 - c2 | 0;
            if ((c2 | 0) < 0) {
              b[a2 >> 2] = g2;
              b[h >> 2] = e2;
              b[i >> 2] = 0;
              f2 = g2;
              c2 = 0;
            } else {
              e2 = d2;
            }
            d2 = (e2 | 0) < (f2 | 0) ? e2 : f2;
            d2 = (c2 | 0) < (d2 | 0) ? c2 : d2;
            if ((d2 | 0) <= 0) {
              return;
            }
            b[a2 >> 2] = f2 - d2;
            b[h >> 2] = e2 - d2;
            b[i >> 2] = c2 - d2;
            return;
          }
          function Pa(a2, c2) {
            a2 = a2 | 0;
            c2 = c2 | 0;
            var d2 = 0, e2 = 0, f2 = 0, g2 = 0, h = 0, i = 0;
            if ((c2 + -1 | 0) >>> 0 >= 6) {
              return;
            }
            f2 = (b[15440 + (c2 * 12 | 0) >> 2] | 0) + (b[a2 >> 2] | 0) | 0;
            b[a2 >> 2] = f2;
            i = a2 + 4 | 0;
            e2 = (b[15440 + (c2 * 12 | 0) + 4 >> 2] | 0) + (b[i >> 2] | 0) | 0;
            b[i >> 2] = e2;
            h = a2 + 8 | 0;
            c2 = (b[15440 + (c2 * 12 | 0) + 8 >> 2] | 0) + (b[h >> 2] | 0) | 0;
            b[h >> 2] = c2;
            d2 = e2 - f2 | 0;
            if ((f2 | 0) < 0) {
              c2 = c2 - f2 | 0;
              b[i >> 2] = d2;
              b[h >> 2] = c2;
              b[a2 >> 2] = 0;
              e2 = 0;
            } else {
              d2 = e2;
              e2 = f2;
            }
            if ((d2 | 0) < 0) {
              e2 = e2 - d2 | 0;
              b[a2 >> 2] = e2;
              c2 = c2 - d2 | 0;
              b[h >> 2] = c2;
              b[i >> 2] = 0;
              d2 = 0;
            }
            g2 = e2 - c2 | 0;
            f2 = d2 - c2 | 0;
            if ((c2 | 0) < 0) {
              b[a2 >> 2] = g2;
              b[i >> 2] = f2;
              b[h >> 2] = 0;
              e2 = g2;
              c2 = 0;
            } else {
              f2 = d2;
            }
            d2 = (f2 | 0) < (e2 | 0) ? f2 : e2;
            d2 = (c2 | 0) < (d2 | 0) ? c2 : d2;
            if ((d2 | 0) <= 0) {
              return;
            }
            b[a2 >> 2] = e2 - d2;
            b[i >> 2] = f2 - d2;
            b[h >> 2] = c2 - d2;
            return;
          }
          function Qa(a2) {
            a2 = a2 | 0;
            var c2 = 0, d2 = 0, e2 = 0, f2 = 0, g2 = 0, h = 0, i = 0;
            f2 = b[a2 >> 2] | 0;
            h = a2 + 4 | 0;
            c2 = b[h >> 2] | 0;
            i = a2 + 8 | 0;
            d2 = b[i >> 2] | 0;
            e2 = c2 + f2 | 0;
            f2 = d2 + f2 | 0;
            b[a2 >> 2] = f2;
            b[h >> 2] = e2;
            c2 = d2 + c2 | 0;
            b[i >> 2] = c2;
            d2 = e2 - f2 | 0;
            if ((f2 | 0) < 0) {
              c2 = c2 - f2 | 0;
              b[h >> 2] = d2;
              b[i >> 2] = c2;
              b[a2 >> 2] = 0;
              e2 = 0;
            } else {
              d2 = e2;
              e2 = f2;
            }
            if ((d2 | 0) < 0) {
              e2 = e2 - d2 | 0;
              b[a2 >> 2] = e2;
              c2 = c2 - d2 | 0;
              b[i >> 2] = c2;
              b[h >> 2] = 0;
              d2 = 0;
            }
            g2 = e2 - c2 | 0;
            f2 = d2 - c2 | 0;
            if ((c2 | 0) < 0) {
              b[a2 >> 2] = g2;
              b[h >> 2] = f2;
              b[i >> 2] = 0;
              e2 = g2;
              c2 = 0;
            } else {
              f2 = d2;
            }
            d2 = (f2 | 0) < (e2 | 0) ? f2 : e2;
            d2 = (c2 | 0) < (d2 | 0) ? c2 : d2;
            if ((d2 | 0) <= 0) {
              return;
            }
            b[a2 >> 2] = e2 - d2;
            b[h >> 2] = f2 - d2;
            b[i >> 2] = c2 - d2;
            return;
          }
          function Ra(a2) {
            a2 = a2 | 0;
            var c2 = 0, d2 = 0, e2 = 0, f2 = 0, g2 = 0, h = 0, i = 0;
            c2 = b[a2 >> 2] | 0;
            h = a2 + 4 | 0;
            e2 = b[h >> 2] | 0;
            i = a2 + 8 | 0;
            d2 = b[i >> 2] | 0;
            f2 = e2 + c2 | 0;
            b[a2 >> 2] = f2;
            e2 = d2 + e2 | 0;
            b[h >> 2] = e2;
            c2 = d2 + c2 | 0;
            b[i >> 2] = c2;
            d2 = e2 - f2 | 0;
            if ((f2 | 0) < 0) {
              c2 = c2 - f2 | 0;
              b[h >> 2] = d2;
              b[i >> 2] = c2;
              b[a2 >> 2] = 0;
              e2 = 0;
            } else {
              d2 = e2;
              e2 = f2;
            }
            if ((d2 | 0) < 0) {
              e2 = e2 - d2 | 0;
              b[a2 >> 2] = e2;
              c2 = c2 - d2 | 0;
              b[i >> 2] = c2;
              b[h >> 2] = 0;
              d2 = 0;
            }
            g2 = e2 - c2 | 0;
            f2 = d2 - c2 | 0;
            if ((c2 | 0) < 0) {
              b[a2 >> 2] = g2;
              b[h >> 2] = f2;
              b[i >> 2] = 0;
              e2 = g2;
              c2 = 0;
            } else {
              f2 = d2;
            }
            d2 = (f2 | 0) < (e2 | 0) ? f2 : e2;
            d2 = (c2 | 0) < (d2 | 0) ? c2 : d2;
            if ((d2 | 0) <= 0) {
              return;
            }
            b[a2 >> 2] = e2 - d2;
            b[h >> 2] = f2 - d2;
            b[i >> 2] = c2 - d2;
            return;
          }
          function Sa(a2) {
            a2 = a2 | 0;
            switch (a2 | 0) {
              case 1: {
                a2 = 5;
                break;
              }
              case 5: {
                a2 = 4;
                break;
              }
              case 4: {
                a2 = 6;
                break;
              }
              case 6: {
                a2 = 2;
                break;
              }
              case 2: {
                a2 = 3;
                break;
              }
              case 3: {
                a2 = 1;
                break;
              }
              default:
            }
            return a2 | 0;
          }
          function Ta(a2) {
            a2 = a2 | 0;
            switch (a2 | 0) {
              case 1: {
                a2 = 3;
                break;
              }
              case 3: {
                a2 = 2;
                break;
              }
              case 2: {
                a2 = 6;
                break;
              }
              case 6: {
                a2 = 4;
                break;
              }
              case 4: {
                a2 = 5;
                break;
              }
              case 5: {
                a2 = 1;
                break;
              }
              default:
            }
            return a2 | 0;
          }
          function Ua(a2) {
            a2 = a2 | 0;
            var c2 = 0, d2 = 0, e2 = 0, f2 = 0, g2 = 0, h = 0, i = 0;
            c2 = b[a2 >> 2] | 0;
            h = a2 + 4 | 0;
            d2 = b[h >> 2] | 0;
            i = a2 + 8 | 0;
            e2 = b[i >> 2] | 0;
            f2 = d2 + (c2 << 1) | 0;
            b[a2 >> 2] = f2;
            d2 = e2 + (d2 << 1) | 0;
            b[h >> 2] = d2;
            c2 = (e2 << 1) + c2 | 0;
            b[i >> 2] = c2;
            e2 = d2 - f2 | 0;
            if ((f2 | 0) < 0) {
              c2 = c2 - f2 | 0;
              b[h >> 2] = e2;
              b[i >> 2] = c2;
              b[a2 >> 2] = 0;
              d2 = e2;
              e2 = 0;
            } else {
              e2 = f2;
            }
            if ((d2 | 0) < 0) {
              e2 = e2 - d2 | 0;
              b[a2 >> 2] = e2;
              c2 = c2 - d2 | 0;
              b[i >> 2] = c2;
              b[h >> 2] = 0;
              d2 = 0;
            }
            g2 = e2 - c2 | 0;
            f2 = d2 - c2 | 0;
            if ((c2 | 0) < 0) {
              b[a2 >> 2] = g2;
              b[h >> 2] = f2;
              b[i >> 2] = 0;
              e2 = g2;
              c2 = 0;
            } else {
              f2 = d2;
            }
            d2 = (f2 | 0) < (e2 | 0) ? f2 : e2;
            d2 = (c2 | 0) < (d2 | 0) ? c2 : d2;
            if ((d2 | 0) <= 0) {
              return;
            }
            b[a2 >> 2] = e2 - d2;
            b[h >> 2] = f2 - d2;
            b[i >> 2] = c2 - d2;
            return;
          }
          function Va(a2) {
            a2 = a2 | 0;
            var c2 = 0, d2 = 0, e2 = 0, f2 = 0, g2 = 0, h = 0, i = 0;
            f2 = b[a2 >> 2] | 0;
            h = a2 + 4 | 0;
            c2 = b[h >> 2] | 0;
            i = a2 + 8 | 0;
            d2 = b[i >> 2] | 0;
            e2 = (c2 << 1) + f2 | 0;
            f2 = d2 + (f2 << 1) | 0;
            b[a2 >> 2] = f2;
            b[h >> 2] = e2;
            c2 = (d2 << 1) + c2 | 0;
            b[i >> 2] = c2;
            d2 = e2 - f2 | 0;
            if ((f2 | 0) < 0) {
              c2 = c2 - f2 | 0;
              b[h >> 2] = d2;
              b[i >> 2] = c2;
              b[a2 >> 2] = 0;
              f2 = 0;
            } else {
              d2 = e2;
            }
            if ((d2 | 0) < 0) {
              f2 = f2 - d2 | 0;
              b[a2 >> 2] = f2;
              c2 = c2 - d2 | 0;
              b[i >> 2] = c2;
              b[h >> 2] = 0;
              d2 = 0;
            }
            g2 = f2 - c2 | 0;
            e2 = d2 - c2 | 0;
            if ((c2 | 0) < 0) {
              b[a2 >> 2] = g2;
              b[h >> 2] = e2;
              b[i >> 2] = 0;
              f2 = g2;
              c2 = 0;
            } else {
              e2 = d2;
            }
            d2 = (e2 | 0) < (f2 | 0) ? e2 : f2;
            d2 = (c2 | 0) < (d2 | 0) ? c2 : d2;
            if ((d2 | 0) <= 0) {
              return;
            }
            b[a2 >> 2] = f2 - d2;
            b[h >> 2] = e2 - d2;
            b[i >> 2] = c2 - d2;
            return;
          }
          function Wa(a2, c2) {
            a2 = a2 | 0;
            c2 = c2 | 0;
            var d2 = 0, e2 = 0, f2 = 0, g2 = 0, h = 0, i = 0;
            h = (b[a2 >> 2] | 0) - (b[c2 >> 2] | 0) | 0;
            i = (h | 0) < 0;
            e2 = (b[a2 + 4 >> 2] | 0) - (b[c2 + 4 >> 2] | 0) - (i ? h : 0) | 0;
            g2 = (e2 | 0) < 0;
            f2 = (i ? 0 - h | 0 : 0) + (b[a2 + 8 >> 2] | 0) - (b[c2 + 8 >> 2] | 0) + (g2 ? 0 - e2 | 0 : 0) | 0;
            a2 = (f2 | 0) < 0;
            c2 = a2 ? 0 : f2;
            d2 = (g2 ? 0 : e2) - (a2 ? f2 : 0) | 0;
            f2 = (i ? 0 : h) - (g2 ? e2 : 0) - (a2 ? f2 : 0) | 0;
            a2 = (d2 | 0) < (f2 | 0) ? d2 : f2;
            a2 = (c2 | 0) < (a2 | 0) ? c2 : a2;
            e2 = (a2 | 0) > 0;
            c2 = c2 - (e2 ? a2 : 0) | 0;
            d2 = d2 - (e2 ? a2 : 0) | 0;
            a2 = f2 - (e2 ? a2 : 0) | 0;
            a2 = (a2 | 0) > -1 ? a2 : 0 - a2 | 0;
            d2 = (d2 | 0) > -1 ? d2 : 0 - d2 | 0;
            c2 = (c2 | 0) > -1 ? c2 : 0 - c2 | 0;
            c2 = (d2 | 0) > (c2 | 0) ? d2 : c2;
            return ((a2 | 0) > (c2 | 0) ? a2 : c2) | 0;
          }
          function Xa(a2, c2) {
            a2 = a2 | 0;
            c2 = c2 | 0;
            var d2 = 0;
            d2 = b[a2 + 8 >> 2] | 0;
            b[c2 >> 2] = (b[a2 >> 2] | 0) - d2;
            b[c2 + 4 >> 2] = (b[a2 + 4 >> 2] | 0) - d2;
            return;
          }
          function Ya(a2, c2) {
            a2 = a2 | 0;
            c2 = c2 | 0;
            var d2 = 0, e2 = 0, f2 = 0, g2 = 0, h = 0, i = 0;
            e2 = b[a2 >> 2] | 0;
            b[c2 >> 2] = e2;
            f2 = b[a2 + 4 >> 2] | 0;
            h = c2 + 4 | 0;
            b[h >> 2] = f2;
            i = c2 + 8 | 0;
            b[i >> 2] = 0;
            d2 = (f2 | 0) < (e2 | 0);
            a2 = d2 ? e2 : f2;
            d2 = d2 ? f2 : e2;
            do {
              if ((d2 | 0) < 0) {
                if ((a2 | 0) > 0) {
                  if ((a2 | -2147483648 | 0) < (d2 | 0) & ((d2 | 0) != -2147483648 & (2147483647 - a2 | 0) >= (d2 | 0))) {
                    break;
                  } else {
                    a2 = 1;
                  }
                  return a2 | 0;
                }
                if ((d2 | 0) == -2147483648 | (-2147483648 - a2 | 0) > (d2 | 0)) {
                  c2 = 1;
                  return c2 | 0;
                }
                if ((a2 | 0) > -1) {
                  if ((a2 | -2147483648 | 0) < (d2 | 0)) {
                    break;
                  } else {
                    a2 = 1;
                  }
                  return a2 | 0;
                } else {
                  if ((a2 ^ -2147483648 | 0) < (d2 | 0)) {
                    a2 = 1;
                  } else {
                    break;
                  }
                  return a2 | 0;
                }
              }
            } while (0);
            a2 = f2 - e2 | 0;
            if ((e2 | 0) < 0) {
              d2 = 0 - e2 | 0;
              b[h >> 2] = a2;
              b[i >> 2] = d2;
              b[c2 >> 2] = 0;
              e2 = 0;
            } else {
              a2 = f2;
              d2 = 0;
            }
            if ((a2 | 0) < 0) {
              e2 = e2 - a2 | 0;
              b[c2 >> 2] = e2;
              d2 = d2 - a2 | 0;
              b[i >> 2] = d2;
              b[h >> 2] = 0;
              a2 = 0;
            }
            g2 = e2 - d2 | 0;
            f2 = a2 - d2 | 0;
            if ((d2 | 0) < 0) {
              b[c2 >> 2] = g2;
              b[h >> 2] = f2;
              b[i >> 2] = 0;
              a2 = f2;
              f2 = g2;
              d2 = 0;
            } else {
              f2 = e2;
            }
            e2 = (a2 | 0) < (f2 | 0) ? a2 : f2;
            e2 = (d2 | 0) < (e2 | 0) ? d2 : e2;
            if ((e2 | 0) <= 0) {
              c2 = 0;
              return c2 | 0;
            }
            b[c2 >> 2] = f2 - e2;
            b[h >> 2] = a2 - e2;
            b[i >> 2] = d2 - e2;
            c2 = 0;
            return c2 | 0;
          }
          function Za(a2) {
            a2 = a2 | 0;
            var c2 = 0, d2 = 0, e2 = 0, f2 = 0;
            c2 = a2 + 8 | 0;
            f2 = b[c2 >> 2] | 0;
            d2 = f2 - (b[a2 >> 2] | 0) | 0;
            b[a2 >> 2] = d2;
            e2 = a2 + 4 | 0;
            a2 = (b[e2 >> 2] | 0) - f2 | 0;
            b[e2 >> 2] = a2;
            b[c2 >> 2] = 0 - (a2 + d2);
            return;
          }
          function _a(a2) {
            a2 = a2 | 0;
            var c2 = 0, d2 = 0, e2 = 0, f2 = 0, g2 = 0, h = 0, i = 0;
            d2 = b[a2 >> 2] | 0;
            c2 = 0 - d2 | 0;
            b[a2 >> 2] = c2;
            h = a2 + 8 | 0;
            b[h >> 2] = 0;
            i = a2 + 4 | 0;
            e2 = b[i >> 2] | 0;
            f2 = e2 + d2 | 0;
            if ((d2 | 0) > 0) {
              b[i >> 2] = f2;
              b[h >> 2] = d2;
              b[a2 >> 2] = 0;
              c2 = 0;
              e2 = f2;
            } else {
              d2 = 0;
            }
            if ((e2 | 0) < 0) {
              g2 = c2 - e2 | 0;
              b[a2 >> 2] = g2;
              d2 = d2 - e2 | 0;
              b[h >> 2] = d2;
              b[i >> 2] = 0;
              f2 = g2 - d2 | 0;
              c2 = 0 - d2 | 0;
              if ((d2 | 0) < 0) {
                b[a2 >> 2] = f2;
                b[i >> 2] = c2;
                b[h >> 2] = 0;
                e2 = c2;
                d2 = 0;
              } else {
                e2 = 0;
                f2 = g2;
              }
            } else {
              f2 = c2;
            }
            c2 = (e2 | 0) < (f2 | 0) ? e2 : f2;
            c2 = (d2 | 0) < (c2 | 0) ? d2 : c2;
            if ((c2 | 0) <= 0) {
              return;
            }
            b[a2 >> 2] = f2 - c2;
            b[i >> 2] = e2 - c2;
            b[h >> 2] = d2 - c2;
            return;
          }
          function $a(a2, c2, d2, e2, f2) {
            a2 = a2 | 0;
            c2 = c2 | 0;
            d2 = d2 | 0;
            e2 = e2 | 0;
            f2 = f2 | 0;
            var g2 = 0, h = 0, i = 0, j = 0, k = 0, l = 0, m = 0;
            m = T;
            T = T + 64 | 0;
            l = m;
            i = m + 56 | 0;
            if (!(true & (c2 & 2013265920 | 0) == 134217728 & (true & (e2 & 2013265920 | 0) == 134217728))) {
              f2 = 5;
              T = m;
              return f2 | 0;
            }
            if ((a2 | 0) == (d2 | 0) & (c2 | 0) == (e2 | 0)) {
              b[f2 >> 2] = 0;
              f2 = 0;
              T = m;
              return f2 | 0;
            }
            h = vd(a2 | 0, c2 | 0, 52) | 0;
            H() | 0;
            h = h & 15;
            k = vd(d2 | 0, e2 | 0, 52) | 0;
            H() | 0;
            if ((h | 0) != (k & 15 | 0)) {
              f2 = 12;
              T = m;
              return f2 | 0;
            }
            g2 = h + -1 | 0;
            if (h >>> 0 > 1) {
              vb(a2, c2, g2, l) | 0;
              vb(d2, e2, g2, i) | 0;
              k = l;
              j = b[k >> 2] | 0;
              k = b[k + 4 >> 2] | 0;
              a: do {
                if ((j | 0) == (b[i >> 2] | 0) ? (k | 0) == (b[i + 4 >> 2] | 0) : 0) {
                  h = (h ^ 15) * 3 | 0;
                  g2 = vd(a2 | 0, c2 | 0, h | 0) | 0;
                  H() | 0;
                  g2 = g2 & 7;
                  h = vd(d2 | 0, e2 | 0, h | 0) | 0;
                  H() | 0;
                  h = h & 7;
                  do {
                    if (!((g2 | 0) == 0 | (h | 0) == 0)) {
                      if ((g2 | 0) == 7) {
                        g2 = 5;
                      } else {
                        if ((g2 | 0) == 1 | (h | 0) == 1 ? xb(j, k) | 0 : 0) {
                          g2 = 5;
                          break;
                        }
                        if ((b[15536 + (g2 << 2) >> 2] | 0) != (h | 0) ? (b[15568 + (g2 << 2) >> 2] | 0) != (h | 0) : 0) {
                          break a;
                        }
                        b[f2 >> 2] = 1;
                        g2 = 0;
                      }
                    } else {
                      b[f2 >> 2] = 1;
                      g2 = 0;
                    }
                  } while (0);
                  f2 = g2;
                  T = m;
                  return f2 | 0;
                }
              } while (0);
            }
            g2 = l;
            h = g2 + 56 | 0;
            do {
              b[g2 >> 2] = 0;
              g2 = g2 + 4 | 0;
            } while ((g2 | 0) < (h | 0));
            aa(a2, c2, 1, l) | 0;
            c2 = l;
            if (((((!((b[c2 >> 2] | 0) == (d2 | 0) ? (b[c2 + 4 >> 2] | 0) == (e2 | 0) : 0) ? (c2 = l + 8 | 0, !((b[c2 >> 2] | 0) == (d2 | 0) ? (b[c2 + 4 >> 2] | 0) == (e2 | 0) : 0)) : 0) ? (c2 = l + 16 | 0, !((b[c2 >> 2] | 0) == (d2 | 0) ? (b[c2 + 4 >> 2] | 0) == (e2 | 0) : 0)) : 0) ? (c2 = l + 24 | 0, !((b[c2 >> 2] | 0) == (d2 | 0) ? (b[c2 + 4 >> 2] | 0) == (e2 | 0) : 0)) : 0) ? (c2 = l + 32 | 0, !((b[c2 >> 2] | 0) == (d2 | 0) ? (b[c2 + 4 >> 2] | 0) == (e2 | 0) : 0)) : 0) ? (c2 = l + 40 | 0, !((b[c2 >> 2] | 0) == (d2 | 0) ? (b[c2 + 4 >> 2] | 0) == (e2 | 0) : 0)) : 0) {
              g2 = l + 48 | 0;
              g2 = ((b[g2 >> 2] | 0) == (d2 | 0) ? (b[g2 + 4 >> 2] | 0) == (e2 | 0) : 0) & 1;
            } else {
              g2 = 1;
            }
            b[f2 >> 2] = g2;
            f2 = 0;
            T = m;
            return f2 | 0;
          }
          function ab(a2, c2, d2, e2, f2) {
            a2 = a2 | 0;
            c2 = c2 | 0;
            d2 = d2 | 0;
            e2 = e2 | 0;
            f2 = f2 | 0;
            d2 = fa(a2, c2, d2, e2) | 0;
            if ((d2 | 0) == 7) {
              f2 = 11;
              return f2 | 0;
            }
            e2 = wd(d2 | 0, 0, 56) | 0;
            c2 = c2 & -2130706433 | (H() | 0) | 268435456;
            b[f2 >> 2] = a2 | e2;
            b[f2 + 4 >> 2] = c2;
            f2 = 0;
            return f2 | 0;
          }
          function bb(a2, c2, d2) {
            a2 = a2 | 0;
            c2 = c2 | 0;
            d2 = d2 | 0;
            if (!(true & (c2 & 2013265920 | 0) == 268435456)) {
              d2 = 6;
              return d2 | 0;
            }
            b[d2 >> 2] = a2;
            b[d2 + 4 >> 2] = c2 & -2130706433 | 134217728;
            d2 = 0;
            return d2 | 0;
          }
          function cb(a2, c2, d2) {
            a2 = a2 | 0;
            c2 = c2 | 0;
            d2 = d2 | 0;
            var e2 = 0, f2 = 0, g2 = 0;
            f2 = T;
            T = T + 16 | 0;
            e2 = f2;
            b[e2 >> 2] = 0;
            if (!(true & (c2 & 2013265920 | 0) == 268435456)) {
              e2 = 6;
              T = f2;
              return e2 | 0;
            }
            g2 = vd(a2 | 0, c2 | 0, 56) | 0;
            H() | 0;
            e2 = ea(a2, c2 & -2130706433 | 134217728, g2 & 7, e2, d2) | 0;
            T = f2;
            return e2 | 0;
          }
          function db(a2, b2) {
            a2 = a2 | 0;
            b2 = b2 | 0;
            var c2 = 0;
            c2 = vd(a2 | 0, b2 | 0, 56) | 0;
            H() | 0;
            switch (c2 & 7) {
              case 0:
              case 7: {
                c2 = 0;
                return c2 | 0;
              }
              default:
            }
            c2 = b2 & -2130706433 | 134217728;
            if (!(true & (b2 & 2013265920 | 0) == 268435456)) {
              c2 = 0;
              return c2 | 0;
            }
            if (true & (b2 & 117440512 | 0) == 16777216 & (xb(a2, c2) | 0) != 0) {
              c2 = 0;
              return c2 | 0;
            }
            c2 = ub(a2, c2) | 0;
            return c2 | 0;
          }
          function eb(a2, c2, d2) {
            a2 = a2 | 0;
            c2 = c2 | 0;
            d2 = d2 | 0;
            var e2 = 0, f2 = 0, g2 = 0, h = 0;
            f2 = T;
            T = T + 16 | 0;
            e2 = f2;
            if (!(true & (c2 & 2013265920 | 0) == 268435456)) {
              e2 = 6;
              T = f2;
              return e2 | 0;
            }
            g2 = c2 & -2130706433 | 134217728;
            h = d2;
            b[h >> 2] = a2;
            b[h + 4 >> 2] = g2;
            b[e2 >> 2] = 0;
            c2 = vd(a2 | 0, c2 | 0, 56) | 0;
            H() | 0;
            e2 = ea(a2, g2, c2 & 7, e2, d2 + 8 | 0) | 0;
            T = f2;
            return e2 | 0;
          }
          function fb(a2, c2, d2) {
            a2 = a2 | 0;
            c2 = c2 | 0;
            d2 = d2 | 0;
            var e2 = 0, f2 = 0;
            f2 = (xb(a2, c2) | 0) == 0;
            c2 = c2 & -2130706433;
            e2 = d2;
            b[e2 >> 2] = f2 ? a2 : 0;
            b[e2 + 4 >> 2] = f2 ? c2 | 285212672 : 0;
            e2 = d2 + 8 | 0;
            b[e2 >> 2] = a2;
            b[e2 + 4 >> 2] = c2 | 301989888;
            e2 = d2 + 16 | 0;
            b[e2 >> 2] = a2;
            b[e2 + 4 >> 2] = c2 | 318767104;
            e2 = d2 + 24 | 0;
            b[e2 >> 2] = a2;
            b[e2 + 4 >> 2] = c2 | 335544320;
            e2 = d2 + 32 | 0;
            b[e2 >> 2] = a2;
            b[e2 + 4 >> 2] = c2 | 352321536;
            d2 = d2 + 40 | 0;
            b[d2 >> 2] = a2;
            b[d2 + 4 >> 2] = c2 | 369098752;
            return 0;
          }
          function gb(a2, c2, d2) {
            a2 = a2 | 0;
            c2 = c2 | 0;
            d2 = d2 | 0;
            var e2 = 0, f2 = 0, g2 = 0, h = 0;
            h = T;
            T = T + 16 | 0;
            f2 = h;
            g2 = c2 & -2130706433 | 134217728;
            if (!(true & (c2 & 2013265920 | 0) == 268435456)) {
              g2 = 6;
              T = h;
              return g2 | 0;
            }
            e2 = vd(a2 | 0, c2 | 0, 56) | 0;
            H() | 0;
            e2 = Uc(a2, g2, e2 & 7) | 0;
            if ((e2 | 0) == -1) {
              b[d2 >> 2] = 0;
              g2 = 6;
              T = h;
              return g2 | 0;
            }
            if (Ob(a2, g2, f2) | 0) {
              I(23313, 22484, 282, 22499);
            }
            c2 = vd(a2 | 0, c2 | 0, 52) | 0;
            H() | 0;
            c2 = c2 & 15;
            if (!(xb(a2, g2) | 0)) {
              qb(f2, c2, e2, 2, d2);
            } else {
              mb(f2, c2, e2, 2, d2);
            }
            g2 = 0;
            T = h;
            return g2 | 0;
          }
          function hb(a2, b2, c2) {
            a2 = a2 | 0;
            b2 = b2 | 0;
            c2 = c2 | 0;
            var d2 = 0, e2 = 0;
            d2 = T;
            T = T + 16 | 0;
            e2 = d2;
            ib(a2, b2, c2, e2);
            Ca(e2, c2 + 4 | 0);
            T = d2;
            return;
          }
          function ib(a2, c2, d2, f2) {
            a2 = a2 | 0;
            c2 = c2 | 0;
            d2 = d2 | 0;
            f2 = f2 | 0;
            var g2 = 0, h = 0, i = 0, j = 0, k = 0;
            j = T;
            T = T + 16 | 0;
            k = j;
            jb(a2, d2, k);
            h = +w(+(1 - +e[k >> 3] * 0.5));
            if (h < 1e-16) {
              b[f2 >> 2] = 0;
              b[f2 + 4 >> 2] = 0;
              b[f2 + 8 >> 2] = 0;
              b[f2 + 12 >> 2] = 0;
              T = j;
              return;
            }
            k = b[d2 >> 2] | 0;
            g2 = +e[15920 + (k * 24 | 0) >> 3];
            g2 = +Zb(g2 - +Zb(+cc(15600 + (k << 4) | 0, a2)));
            if (!(Lb(c2) | 0)) {
              i = g2;
            } else {
              i = +Zb(g2 + -0.3334731722518321);
            }
            g2 = +v(+h) / 0.381966011250105;
            if ((c2 | 0) > 0) {
              a2 = 0;
              do {
                g2 = g2 * 2.6457513110645907;
                a2 = a2 + 1 | 0;
              } while ((a2 | 0) != (c2 | 0));
            }
            h = +t(+i) * g2;
            e[f2 >> 3] = h;
            i = +u(+i) * g2;
            e[f2 + 8 >> 3] = i;
            T = j;
            return;
          }
          function jb(a2, c2, d2) {
            a2 = a2 | 0;
            c2 = c2 | 0;
            d2 = d2 | 0;
            var f2 = 0, g2 = 0, h = 0;
            h = T;
            T = T + 32 | 0;
            g2 = h;
            Tc(a2, g2);
            b[c2 >> 2] = 0;
            e[d2 >> 3] = 5;
            f2 = +Sc(16400, g2);
            if (f2 < +e[d2 >> 3]) {
              b[c2 >> 2] = 0;
              e[d2 >> 3] = f2;
            }
            f2 = +Sc(16424, g2);
            if (f2 < +e[d2 >> 3]) {
              b[c2 >> 2] = 1;
              e[d2 >> 3] = f2;
            }
            f2 = +Sc(16448, g2);
            if (f2 < +e[d2 >> 3]) {
              b[c2 >> 2] = 2;
              e[d2 >> 3] = f2;
            }
            f2 = +Sc(16472, g2);
            if (f2 < +e[d2 >> 3]) {
              b[c2 >> 2] = 3;
              e[d2 >> 3] = f2;
            }
            f2 = +Sc(16496, g2);
            if (f2 < +e[d2 >> 3]) {
              b[c2 >> 2] = 4;
              e[d2 >> 3] = f2;
            }
            f2 = +Sc(16520, g2);
            if (f2 < +e[d2 >> 3]) {
              b[c2 >> 2] = 5;
              e[d2 >> 3] = f2;
            }
            f2 = +Sc(16544, g2);
            if (f2 < +e[d2 >> 3]) {
              b[c2 >> 2] = 6;
              e[d2 >> 3] = f2;
            }
            f2 = +Sc(16568, g2);
            if (f2 < +e[d2 >> 3]) {
              b[c2 >> 2] = 7;
              e[d2 >> 3] = f2;
            }
            f2 = +Sc(16592, g2);
            if (f2 < +e[d2 >> 3]) {
              b[c2 >> 2] = 8;
              e[d2 >> 3] = f2;
            }
            f2 = +Sc(16616, g2);
            if (f2 < +e[d2 >> 3]) {
              b[c2 >> 2] = 9;
              e[d2 >> 3] = f2;
            }
            f2 = +Sc(16640, g2);
            if (f2 < +e[d2 >> 3]) {
              b[c2 >> 2] = 10;
              e[d2 >> 3] = f2;
            }
            f2 = +Sc(16664, g2);
            if (f2 < +e[d2 >> 3]) {
              b[c2 >> 2] = 11;
              e[d2 >> 3] = f2;
            }
            f2 = +Sc(16688, g2);
            if (f2 < +e[d2 >> 3]) {
              b[c2 >> 2] = 12;
              e[d2 >> 3] = f2;
            }
            f2 = +Sc(16712, g2);
            if (f2 < +e[d2 >> 3]) {
              b[c2 >> 2] = 13;
              e[d2 >> 3] = f2;
            }
            f2 = +Sc(16736, g2);
            if (f2 < +e[d2 >> 3]) {
              b[c2 >> 2] = 14;
              e[d2 >> 3] = f2;
            }
            f2 = +Sc(16760, g2);
            if (f2 < +e[d2 >> 3]) {
              b[c2 >> 2] = 15;
              e[d2 >> 3] = f2;
            }
            f2 = +Sc(16784, g2);
            if (f2 < +e[d2 >> 3]) {
              b[c2 >> 2] = 16;
              e[d2 >> 3] = f2;
            }
            f2 = +Sc(16808, g2);
            if (f2 < +e[d2 >> 3]) {
              b[c2 >> 2] = 17;
              e[d2 >> 3] = f2;
            }
            f2 = +Sc(16832, g2);
            if (f2 < +e[d2 >> 3]) {
              b[c2 >> 2] = 18;
              e[d2 >> 3] = f2;
            }
            f2 = +Sc(16856, g2);
            if (!(f2 < +e[d2 >> 3])) {
              T = h;
              return;
            }
            b[c2 >> 2] = 19;
            e[d2 >> 3] = f2;
            T = h;
            return;
          }
          function kb(a2, c2, d2, f2, g2) {
            a2 = a2 | 0;
            c2 = c2 | 0;
            d2 = d2 | 0;
            f2 = f2 | 0;
            g2 = g2 | 0;
            var h = 0, i = 0;
            h = +Pc(a2);
            if (h < 1e-16) {
              c2 = 15600 + (c2 << 4) | 0;
              b[g2 >> 2] = b[c2 >> 2];
              b[g2 + 4 >> 2] = b[c2 + 4 >> 2];
              b[g2 + 8 >> 2] = b[c2 + 8 >> 2];
              b[g2 + 12 >> 2] = b[c2 + 12 >> 2];
              return;
            }
            i = +z(+ +e[a2 + 8 >> 3], + +e[a2 >> 3]);
            if ((d2 | 0) > 0) {
              a2 = 0;
              do {
                h = h / 2.6457513110645907;
                a2 = a2 + 1 | 0;
              } while ((a2 | 0) != (d2 | 0));
            }
            if (!f2) {
              h = +y(+(h * 0.381966011250105));
              if (Lb(d2) | 0) {
                i = +Zb(i + 0.3334731722518321);
              }
            } else {
              h = h / 3;
              d2 = (Lb(d2) | 0) == 0;
              h = +y(+((d2 ? h : h / 2.6457513110645907) * 0.381966011250105));
            }
            dc(15600 + (c2 << 4) | 0, +Zb(+e[15920 + (c2 * 24 | 0) >> 3] - i), h, g2);
            return;
          }
          function lb(a2, c2, d2) {
            a2 = a2 | 0;
            c2 = c2 | 0;
            d2 = d2 | 0;
            var e2 = 0, f2 = 0;
            e2 = T;
            T = T + 16 | 0;
            f2 = e2;
            Ea(a2 + 4 | 0, f2);
            kb(f2, b[a2 >> 2] | 0, c2, 0, d2);
            T = e2;
            return;
          }
          function mb(a2, c2, d2, f2, g2) {
            a2 = a2 | 0;
            c2 = c2 | 0;
            d2 = d2 | 0;
            f2 = f2 | 0;
            g2 = g2 | 0;
            var h = 0, i = 0, j = 0, k = 0, l = 0, m = 0, n = 0, o = 0, p2 = 0, q2 = 0, r2 = 0, s2 = 0, t2 = 0, u2 = 0, v2 = 0, w2 = 0, x2 = 0, y2 = 0, z2 = 0, A2 = 0, B2 = 0, C2 = 0, D2 = 0, E2 = 0, F = 0, G2 = 0, H2 = 0, J2 = 0;
            G2 = T;
            T = T + 272 | 0;
            h = G2 + 256 | 0;
            u2 = G2 + 240 | 0;
            D2 = G2;
            E2 = G2 + 224 | 0;
            F = G2 + 208 | 0;
            v2 = G2 + 176 | 0;
            w2 = G2 + 160 | 0;
            x2 = G2 + 192 | 0;
            y2 = G2 + 144 | 0;
            z2 = G2 + 128 | 0;
            A2 = G2 + 112 | 0;
            B2 = G2 + 96 | 0;
            C2 = G2 + 80 | 0;
            b[h >> 2] = c2;
            b[u2 >> 2] = b[a2 >> 2];
            b[u2 + 4 >> 2] = b[a2 + 4 >> 2];
            b[u2 + 8 >> 2] = b[a2 + 8 >> 2];
            b[u2 + 12 >> 2] = b[a2 + 12 >> 2];
            nb(u2, h, D2);
            b[g2 >> 2] = 0;
            u2 = f2 + d2 + ((f2 | 0) == 5 & 1) | 0;
            if ((u2 | 0) <= (d2 | 0)) {
              T = G2;
              return;
            }
            k = b[h >> 2] | 0;
            l = E2 + 4 | 0;
            m = v2 + 4 | 0;
            n = d2 + 5 | 0;
            o = 16880 + (k << 2) | 0;
            p2 = 16960 + (k << 2) | 0;
            q2 = z2 + 8 | 0;
            r2 = A2 + 8 | 0;
            s2 = B2 + 8 | 0;
            t2 = F + 4 | 0;
            j = d2;
            a: while (1) {
              i = D2 + (((j | 0) % 5 | 0) << 4) | 0;
              b[F >> 2] = b[i >> 2];
              b[F + 4 >> 2] = b[i + 4 >> 2];
              b[F + 8 >> 2] = b[i + 8 >> 2];
              b[F + 12 >> 2] = b[i + 12 >> 2];
              do {
              } while ((ob(F, k, 0, 1) | 0) == 2);
              if ((j | 0) > (d2 | 0) & (Lb(c2) | 0) != 0) {
                b[v2 >> 2] = b[F >> 2];
                b[v2 + 4 >> 2] = b[F + 4 >> 2];
                b[v2 + 8 >> 2] = b[F + 8 >> 2];
                b[v2 + 12 >> 2] = b[F + 12 >> 2];
                Ea(l, w2);
                f2 = b[v2 >> 2] | 0;
                h = b[17040 + (f2 * 80 | 0) + (b[E2 >> 2] << 2) >> 2] | 0;
                b[v2 >> 2] = b[18640 + (f2 * 80 | 0) + (h * 20 | 0) >> 2];
                i = b[18640 + (f2 * 80 | 0) + (h * 20 | 0) + 16 >> 2] | 0;
                if ((i | 0) > 0) {
                  a2 = 0;
                  do {
                    Qa(m);
                    a2 = a2 + 1 | 0;
                  } while ((a2 | 0) < (i | 0));
                }
                i = 18640 + (f2 * 80 | 0) + (h * 20 | 0) + 4 | 0;
                b[x2 >> 2] = b[i >> 2];
                b[x2 + 4 >> 2] = b[i + 4 >> 2];
                b[x2 + 8 >> 2] = b[i + 8 >> 2];
                Ha(x2, (b[o >> 2] | 0) * 3 | 0);
                Fa(m, x2, m);
                Da(m);
                Ea(m, y2);
                H2 = +(b[p2 >> 2] | 0);
                e[z2 >> 3] = H2 * 3;
                e[q2 >> 3] = 0;
                J2 = H2 * -1.5;
                e[A2 >> 3] = J2;
                e[r2 >> 3] = H2 * 2.598076211353316;
                e[B2 >> 3] = J2;
                e[s2 >> 3] = H2 * -2.598076211353316;
                switch (b[17040 + ((b[v2 >> 2] | 0) * 80 | 0) + (b[F >> 2] << 2) >> 2] | 0) {
                  case 1: {
                    a2 = A2;
                    f2 = z2;
                    break;
                  }
                  case 3: {
                    a2 = B2;
                    f2 = A2;
                    break;
                  }
                  case 2: {
                    a2 = z2;
                    f2 = B2;
                    break;
                  }
                  default: {
                    a2 = 12;
                    break a;
                  }
                }
                Qc(w2, y2, f2, a2, C2);
                kb(C2, b[v2 >> 2] | 0, k, 1, g2 + 8 + (b[g2 >> 2] << 4) | 0);
                b[g2 >> 2] = (b[g2 >> 2] | 0) + 1;
              }
              if ((j | 0) < (n | 0)) {
                Ea(t2, v2);
                kb(v2, b[F >> 2] | 0, k, 1, g2 + 8 + (b[g2 >> 2] << 4) | 0);
                b[g2 >> 2] = (b[g2 >> 2] | 0) + 1;
              }
              b[E2 >> 2] = b[F >> 2];
              b[E2 + 4 >> 2] = b[F + 4 >> 2];
              b[E2 + 8 >> 2] = b[F + 8 >> 2];
              b[E2 + 12 >> 2] = b[F + 12 >> 2];
              j = j + 1 | 0;
              if ((j | 0) >= (u2 | 0)) {
                a2 = 3;
                break;
              }
            }
            if ((a2 | 0) == 3) {
              T = G2;
              return;
            } else if ((a2 | 0) == 12) {
              I(22522, 22569, 571, 22579);
            }
          }
          function nb(a2, c2, d2) {
            a2 = a2 | 0;
            c2 = c2 | 0;
            d2 = d2 | 0;
            var e2 = 0, f2 = 0, g2 = 0, h = 0, i = 0, j = 0;
            j = T;
            T = T + 128 | 0;
            e2 = j + 64 | 0;
            f2 = j;
            g2 = e2;
            h = 20240;
            i = g2 + 60 | 0;
            do {
              b[g2 >> 2] = b[h >> 2];
              g2 = g2 + 4 | 0;
              h = h + 4 | 0;
            } while ((g2 | 0) < (i | 0));
            g2 = f2;
            h = 20304;
            i = g2 + 60 | 0;
            do {
              b[g2 >> 2] = b[h >> 2];
              g2 = g2 + 4 | 0;
              h = h + 4 | 0;
            } while ((g2 | 0) < (i | 0));
            i = (Lb(b[c2 >> 2] | 0) | 0) == 0;
            e2 = i ? e2 : f2;
            f2 = a2 + 4 | 0;
            Ua(f2);
            Va(f2);
            if (Lb(b[c2 >> 2] | 0) | 0) {
              Oa(f2);
              b[c2 >> 2] = (b[c2 >> 2] | 0) + 1;
            }
            b[d2 >> 2] = b[a2 >> 2];
            c2 = d2 + 4 | 0;
            Fa(f2, e2, c2);
            Da(c2);
            b[d2 + 16 >> 2] = b[a2 >> 2];
            c2 = d2 + 20 | 0;
            Fa(f2, e2 + 12 | 0, c2);
            Da(c2);
            b[d2 + 32 >> 2] = b[a2 >> 2];
            c2 = d2 + 36 | 0;
            Fa(f2, e2 + 24 | 0, c2);
            Da(c2);
            b[d2 + 48 >> 2] = b[a2 >> 2];
            c2 = d2 + 52 | 0;
            Fa(f2, e2 + 36 | 0, c2);
            Da(c2);
            b[d2 + 64 >> 2] = b[a2 >> 2];
            d2 = d2 + 68 | 0;
            Fa(f2, e2 + 48 | 0, d2);
            Da(d2);
            T = j;
            return;
          }
          function ob(a2, c2, d2, e2) {
            a2 = a2 | 0;
            c2 = c2 | 0;
            d2 = d2 | 0;
            e2 = e2 | 0;
            var f2 = 0, g2 = 0, h = 0, i = 0, j = 0, k = 0, l = 0, m = 0, n = 0, o = 0, p2 = 0;
            p2 = T;
            T = T + 32 | 0;
            n = p2 + 12 | 0;
            i = p2;
            o = a2 + 4 | 0;
            m = b[16960 + (c2 << 2) >> 2] | 0;
            l = (e2 | 0) != 0;
            m = l ? m * 3 | 0 : m;
            f2 = b[o >> 2] | 0;
            k = a2 + 8 | 0;
            h = b[k >> 2] | 0;
            if (l) {
              g2 = a2 + 12 | 0;
              e2 = b[g2 >> 2] | 0;
              f2 = h + f2 + e2 | 0;
              if ((f2 | 0) == (m | 0)) {
                o = 1;
                T = p2;
                return o | 0;
              } else {
                j = g2;
              }
            } else {
              j = a2 + 12 | 0;
              e2 = b[j >> 2] | 0;
              f2 = h + f2 + e2 | 0;
            }
            if ((f2 | 0) <= (m | 0)) {
              o = 0;
              T = p2;
              return o | 0;
            }
            do {
              if ((e2 | 0) > 0) {
                e2 = b[a2 >> 2] | 0;
                if ((h | 0) > 0) {
                  g2 = 18640 + (e2 * 80 | 0) + 60 | 0;
                  e2 = a2;
                  break;
                }
                e2 = 18640 + (e2 * 80 | 0) + 40 | 0;
                if (!d2) {
                  g2 = e2;
                  e2 = a2;
                } else {
                  Ba(n, m, 0, 0);
                  Ga(o, n, i);
                  Ra(i);
                  Fa(i, n, o);
                  g2 = e2;
                  e2 = a2;
                }
              } else {
                g2 = 18640 + ((b[a2 >> 2] | 0) * 80 | 0) + 20 | 0;
                e2 = a2;
              }
            } while (0);
            b[e2 >> 2] = b[g2 >> 2];
            f2 = g2 + 16 | 0;
            if ((b[f2 >> 2] | 0) > 0) {
              e2 = 0;
              do {
                Qa(o);
                e2 = e2 + 1 | 0;
              } while ((e2 | 0) < (b[f2 >> 2] | 0));
            }
            a2 = g2 + 4 | 0;
            b[n >> 2] = b[a2 >> 2];
            b[n + 4 >> 2] = b[a2 + 4 >> 2];
            b[n + 8 >> 2] = b[a2 + 8 >> 2];
            c2 = b[16880 + (c2 << 2) >> 2] | 0;
            Ha(n, l ? c2 * 3 | 0 : c2);
            Fa(o, n, o);
            Da(o);
            if (l) {
              e2 = ((b[k >> 2] | 0) + (b[o >> 2] | 0) + (b[j >> 2] | 0) | 0) == (m | 0) ? 1 : 2;
            } else {
              e2 = 2;
            }
            o = e2;
            T = p2;
            return o | 0;
          }
          function pb(a2, b2) {
            a2 = a2 | 0;
            b2 = b2 | 0;
            var c2 = 0;
            do {
              c2 = ob(a2, b2, 0, 1) | 0;
            } while ((c2 | 0) == 2);
            return c2 | 0;
          }
          function qb(a2, c2, d2, f2, g2) {
            a2 = a2 | 0;
            c2 = c2 | 0;
            d2 = d2 | 0;
            f2 = f2 | 0;
            g2 = g2 | 0;
            var h = 0, i = 0, j = 0, k = 0, l = 0, m = 0, n = 0, o = 0, p2 = 0, q2 = 0, r2 = 0, s2 = 0, t2 = 0, u2 = 0, v2 = 0, w2 = 0, x2 = 0, y2 = 0, z2 = 0, A2 = 0, B2 = 0, C2 = 0, D2 = 0;
            B2 = T;
            T = T + 240 | 0;
            h = B2 + 224 | 0;
            x2 = B2 + 208 | 0;
            y2 = B2;
            z2 = B2 + 192 | 0;
            A2 = B2 + 176 | 0;
            s2 = B2 + 160 | 0;
            t2 = B2 + 144 | 0;
            u2 = B2 + 128 | 0;
            v2 = B2 + 112 | 0;
            w2 = B2 + 96 | 0;
            b[h >> 2] = c2;
            b[x2 >> 2] = b[a2 >> 2];
            b[x2 + 4 >> 2] = b[a2 + 4 >> 2];
            b[x2 + 8 >> 2] = b[a2 + 8 >> 2];
            b[x2 + 12 >> 2] = b[a2 + 12 >> 2];
            rb(x2, h, y2);
            b[g2 >> 2] = 0;
            r2 = f2 + d2 + ((f2 | 0) == 6 & 1) | 0;
            if ((r2 | 0) <= (d2 | 0)) {
              T = B2;
              return;
            }
            k = b[h >> 2] | 0;
            l = d2 + 6 | 0;
            m = 16960 + (k << 2) | 0;
            n = t2 + 8 | 0;
            o = u2 + 8 | 0;
            p2 = v2 + 8 | 0;
            q2 = z2 + 4 | 0;
            i = 0;
            j = d2;
            f2 = -1;
            a: while (1) {
              h = (j | 0) % 6 | 0;
              a2 = y2 + (h << 4) | 0;
              b[z2 >> 2] = b[a2 >> 2];
              b[z2 + 4 >> 2] = b[a2 + 4 >> 2];
              b[z2 + 8 >> 2] = b[a2 + 8 >> 2];
              b[z2 + 12 >> 2] = b[a2 + 12 >> 2];
              a2 = i;
              i = ob(z2, k, 0, 1) | 0;
              if ((j | 0) > (d2 | 0) & (Lb(c2) | 0) != 0 ? (a2 | 0) != 1 ? (b[z2 >> 2] | 0) != (f2 | 0) : 0 : 0) {
                Ea(y2 + (((h + 5 | 0) % 6 | 0) << 4) + 4 | 0, A2);
                Ea(y2 + (h << 4) + 4 | 0, s2);
                C2 = +(b[m >> 2] | 0);
                e[t2 >> 3] = C2 * 3;
                e[n >> 3] = 0;
                D2 = C2 * -1.5;
                e[u2 >> 3] = D2;
                e[o >> 3] = C2 * 2.598076211353316;
                e[v2 >> 3] = D2;
                e[p2 >> 3] = C2 * -2.598076211353316;
                h = b[x2 >> 2] | 0;
                switch (b[17040 + (h * 80 | 0) + (((f2 | 0) == (h | 0) ? b[z2 >> 2] | 0 : f2) << 2) >> 2] | 0) {
                  case 1: {
                    a2 = u2;
                    f2 = t2;
                    break;
                  }
                  case 3: {
                    a2 = v2;
                    f2 = u2;
                    break;
                  }
                  case 2: {
                    a2 = t2;
                    f2 = v2;
                    break;
                  }
                  default: {
                    a2 = 8;
                    break a;
                  }
                }
                Qc(A2, s2, f2, a2, w2);
                if (!(Rc(A2, w2) | 0) ? !(Rc(s2, w2) | 0) : 0) {
                  kb(w2, b[x2 >> 2] | 0, k, 1, g2 + 8 + (b[g2 >> 2] << 4) | 0);
                  b[g2 >> 2] = (b[g2 >> 2] | 0) + 1;
                }
              }
              if ((j | 0) < (l | 0)) {
                Ea(q2, A2);
                kb(A2, b[z2 >> 2] | 0, k, 1, g2 + 8 + (b[g2 >> 2] << 4) | 0);
                b[g2 >> 2] = (b[g2 >> 2] | 0) + 1;
              }
              j = j + 1 | 0;
              if ((j | 0) >= (r2 | 0)) {
                a2 = 3;
                break;
              } else {
                f2 = b[z2 >> 2] | 0;
              }
            }
            if ((a2 | 0) == 3) {
              T = B2;
              return;
            } else if ((a2 | 0) == 8) {
              I(22606, 22569, 736, 22651);
            }
          }
          function rb(a2, c2, d2) {
            a2 = a2 | 0;
            c2 = c2 | 0;
            d2 = d2 | 0;
            var e2 = 0, f2 = 0, g2 = 0, h = 0, i = 0, j = 0;
            j = T;
            T = T + 160 | 0;
            e2 = j + 80 | 0;
            f2 = j;
            g2 = e2;
            h = 20368;
            i = g2 + 72 | 0;
            do {
              b[g2 >> 2] = b[h >> 2];
              g2 = g2 + 4 | 0;
              h = h + 4 | 0;
            } while ((g2 | 0) < (i | 0));
            g2 = f2;
            h = 20448;
            i = g2 + 72 | 0;
            do {
              b[g2 >> 2] = b[h >> 2];
              g2 = g2 + 4 | 0;
              h = h + 4 | 0;
            } while ((g2 | 0) < (i | 0));
            i = (Lb(b[c2 >> 2] | 0) | 0) == 0;
            e2 = i ? e2 : f2;
            f2 = a2 + 4 | 0;
            Ua(f2);
            Va(f2);
            if (Lb(b[c2 >> 2] | 0) | 0) {
              Oa(f2);
              b[c2 >> 2] = (b[c2 >> 2] | 0) + 1;
            }
            b[d2 >> 2] = b[a2 >> 2];
            c2 = d2 + 4 | 0;
            Fa(f2, e2, c2);
            Da(c2);
            b[d2 + 16 >> 2] = b[a2 >> 2];
            c2 = d2 + 20 | 0;
            Fa(f2, e2 + 12 | 0, c2);
            Da(c2);
            b[d2 + 32 >> 2] = b[a2 >> 2];
            c2 = d2 + 36 | 0;
            Fa(f2, e2 + 24 | 0, c2);
            Da(c2);
            b[d2 + 48 >> 2] = b[a2 >> 2];
            c2 = d2 + 52 | 0;
            Fa(f2, e2 + 36 | 0, c2);
            Da(c2);
            b[d2 + 64 >> 2] = b[a2 >> 2];
            c2 = d2 + 68 | 0;
            Fa(f2, e2 + 48 | 0, c2);
            Da(c2);
            b[d2 + 80 >> 2] = b[a2 >> 2];
            d2 = d2 + 84 | 0;
            Fa(f2, e2 + 60 | 0, d2);
            Da(d2);
            T = j;
            return;
          }
          function sb(a2, b2) {
            a2 = a2 | 0;
            b2 = b2 | 0;
            b2 = vd(a2 | 0, b2 | 0, 52) | 0;
            H() | 0;
            return b2 & 15 | 0;
          }
          function tb(a2, b2) {
            a2 = a2 | 0;
            b2 = b2 | 0;
            b2 = vd(a2 | 0, b2 | 0, 45) | 0;
            H() | 0;
            return b2 & 127 | 0;
          }
          function ub(a2, b2) {
            a2 = a2 | 0;
            b2 = b2 | 0;
            var c2 = 0, d2 = 0, e2 = 0, f2 = 0, g2 = 0, h = 0;
            if (!(true & (b2 & -16777216 | 0) == 134217728)) {
              b2 = 0;
              return b2 | 0;
            }
            g2 = vd(a2 | 0, b2 | 0, 45) | 0;
            H() | 0;
            g2 = g2 & 127;
            if (g2 >>> 0 > 121) {
              b2 = 0;
              return b2 | 0;
            }
            c2 = vd(a2 | 0, b2 | 0, 52) | 0;
            H() | 0;
            c2 = c2 & 15;
            do {
              if (c2 | 0) {
                e2 = 1;
                d2 = 0;
                while (1) {
                  f2 = vd(a2 | 0, b2 | 0, (15 - e2 | 0) * 3 | 0) | 0;
                  H() | 0;
                  f2 = f2 & 7;
                  if ((f2 | 0) != 0 & (d2 ^ 1)) {
                    if ((f2 | 0) == 1 & (ma(g2) | 0) != 0) {
                      h = 0;
                      d2 = 13;
                      break;
                    } else {
                      d2 = 1;
                    }
                  }
                  if ((f2 | 0) == 7) {
                    h = 0;
                    d2 = 13;
                    break;
                  }
                  if (e2 >>> 0 < c2 >>> 0) {
                    e2 = e2 + 1 | 0;
                  } else {
                    d2 = 9;
                    break;
                  }
                }
                if ((d2 | 0) == 9) {
                  if ((c2 | 0) == 15) {
                    h = 1;
                  } else {
                    break;
                  }
                  return h | 0;
                } else if ((d2 | 0) == 13) {
                  return h | 0;
                }
              }
            } while (0);
            while (1) {
              h = vd(a2 | 0, b2 | 0, (14 - c2 | 0) * 3 | 0) | 0;
              H() | 0;
              if (!((h & 7 | 0) == 7 & true)) {
                h = 0;
                d2 = 13;
                break;
              }
              if (c2 >>> 0 < 14) {
                c2 = c2 + 1 | 0;
              } else {
                h = 1;
                d2 = 13;
                break;
              }
            }
            if ((d2 | 0) == 13) {
              return h | 0;
            }
            return 0;
          }
          function vb(a2, c2, d2, e2) {
            a2 = a2 | 0;
            c2 = c2 | 0;
            d2 = d2 | 0;
            e2 = e2 | 0;
            var f2 = 0, g2 = 0;
            g2 = vd(a2 | 0, c2 | 0, 52) | 0;
            H() | 0;
            g2 = g2 & 15;
            if (d2 >>> 0 > 15) {
              e2 = 4;
              return e2 | 0;
            }
            if ((g2 | 0) < (d2 | 0)) {
              e2 = 12;
              return e2 | 0;
            }
            if ((g2 | 0) == (d2 | 0)) {
              b[e2 >> 2] = a2;
              b[e2 + 4 >> 2] = c2;
              e2 = 0;
              return e2 | 0;
            }
            f2 = wd(d2 | 0, 0, 52) | 0;
            f2 = f2 | a2;
            a2 = H() | 0 | c2 & -15728641;
            if ((g2 | 0) > (d2 | 0)) {
              do {
                c2 = wd(7, 0, (14 - d2 | 0) * 3 | 0) | 0;
                d2 = d2 + 1 | 0;
                f2 = c2 | f2;
                a2 = H() | 0 | a2;
              } while ((d2 | 0) < (g2 | 0));
            }
            b[e2 >> 2] = f2;
            b[e2 + 4 >> 2] = a2;
            e2 = 0;
            return e2 | 0;
          }
          function wb(a2, c2, d2, e2) {
            a2 = a2 | 0;
            c2 = c2 | 0;
            d2 = d2 | 0;
            e2 = e2 | 0;
            var f2 = 0, g2 = 0, h = 0;
            g2 = vd(a2 | 0, c2 | 0, 52) | 0;
            H() | 0;
            g2 = g2 & 15;
            if (!((d2 | 0) < 16 & (g2 | 0) <= (d2 | 0))) {
              e2 = 4;
              return e2 | 0;
            }
            f2 = d2 - g2 | 0;
            d2 = vd(a2 | 0, c2 | 0, 45) | 0;
            H() | 0;
            a: do {
              if (!(ma(d2 & 127) | 0)) {
                d2 = Cc(7, 0, f2, ((f2 | 0) < 0) << 31 >> 31) | 0;
                f2 = H() | 0;
              } else {
                b: do {
                  if (g2 | 0) {
                    d2 = 1;
                    while (1) {
                      h = wd(7, 0, (15 - d2 | 0) * 3 | 0) | 0;
                      if (!((h & a2 | 0) == 0 & ((H() | 0) & c2 | 0) == 0)) {
                        break;
                      }
                      if (d2 >>> 0 < g2 >>> 0) {
                        d2 = d2 + 1 | 0;
                      } else {
                        break b;
                      }
                    }
                    d2 = Cc(7, 0, f2, ((f2 | 0) < 0) << 31 >> 31) | 0;
                    f2 = H() | 0;
                    break a;
                  }
                } while (0);
                d2 = Cc(7, 0, f2, ((f2 | 0) < 0) << 31 >> 31) | 0;
                d2 = rd(d2 | 0, H() | 0, 5, 0) | 0;
                d2 = ld(d2 | 0, H() | 0, -5, -1) | 0;
                d2 = pd(d2 | 0, H() | 0, 6, 0) | 0;
                d2 = ld(d2 | 0, H() | 0, 1, 0) | 0;
                f2 = H() | 0;
              }
            } while (0);
            h = e2;
            b[h >> 2] = d2;
            b[h + 4 >> 2] = f2;
            h = 0;
            return h | 0;
          }
          function xb(a2, b2) {
            a2 = a2 | 0;
            b2 = b2 | 0;
            var c2 = 0, d2 = 0, e2 = 0;
            e2 = vd(a2 | 0, b2 | 0, 45) | 0;
            H() | 0;
            if (!(ma(e2 & 127) | 0)) {
              e2 = 0;
              return e2 | 0;
            }
            e2 = vd(a2 | 0, b2 | 0, 52) | 0;
            H() | 0;
            e2 = e2 & 15;
            a: do {
              if (!e2) {
                c2 = 0;
              } else {
                d2 = 1;
                while (1) {
                  c2 = vd(a2 | 0, b2 | 0, (15 - d2 | 0) * 3 | 0) | 0;
                  H() | 0;
                  c2 = c2 & 7;
                  if (c2 | 0) {
                    break a;
                  }
                  if (d2 >>> 0 < e2 >>> 0) {
                    d2 = d2 + 1 | 0;
                  } else {
                    c2 = 0;
                    break;
                  }
                }
              }
            } while (0);
            e2 = (c2 | 0) == 0 & 1;
            return e2 | 0;
          }
          function yb(a2, c2, d2, e2) {
            a2 = a2 | 0;
            c2 = c2 | 0;
            d2 = d2 | 0;
            e2 = e2 | 0;
            var f2 = 0, g2 = 0, h = 0, i = 0;
            h = T;
            T = T + 16 | 0;
            g2 = h;
            Xb(g2, a2, c2, d2);
            c2 = g2;
            a2 = b[c2 >> 2] | 0;
            c2 = b[c2 + 4 >> 2] | 0;
            if ((a2 | 0) == 0 & (c2 | 0) == 0) {
              T = h;
              return 0;
            }
            f2 = 0;
            d2 = 0;
            do {
              i = e2 + (f2 << 3) | 0;
              b[i >> 2] = a2;
              b[i + 4 >> 2] = c2;
              f2 = ld(f2 | 0, d2 | 0, 1, 0) | 0;
              d2 = H() | 0;
              Yb(g2);
              i = g2;
              a2 = b[i >> 2] | 0;
              c2 = b[i + 4 >> 2] | 0;
            } while (!((a2 | 0) == 0 & (c2 | 0) == 0));
            T = h;
            return 0;
          }
          function zb(a2, b2, c2, d2) {
            a2 = a2 | 0;
            b2 = b2 | 0;
            c2 = c2 | 0;
            d2 = d2 | 0;
            if ((d2 | 0) < (c2 | 0)) {
              c2 = b2;
              d2 = a2;
              G(c2 | 0);
              return d2 | 0;
            }
            c2 = wd(-1, -1, ((d2 - c2 | 0) * 3 | 0) + 3 | 0) | 0;
            d2 = wd(~c2 | 0, ~(H() | 0) | 0, (15 - d2 | 0) * 3 | 0) | 0;
            c2 = ~(H() | 0) & b2;
            d2 = ~d2 & a2;
            G(c2 | 0);
            return d2 | 0;
          }
          function Ab(a2, c2, d2, e2) {
            a2 = a2 | 0;
            c2 = c2 | 0;
            d2 = d2 | 0;
            e2 = e2 | 0;
            var f2 = 0;
            f2 = vd(a2 | 0, c2 | 0, 52) | 0;
            H() | 0;
            f2 = f2 & 15;
            if (!((d2 | 0) < 16 & (f2 | 0) <= (d2 | 0))) {
              e2 = 4;
              return e2 | 0;
            }
            if ((f2 | 0) < (d2 | 0)) {
              f2 = wd(-1, -1, ((d2 + -1 - f2 | 0) * 3 | 0) + 3 | 0) | 0;
              f2 = wd(~f2 | 0, ~(H() | 0) | 0, (15 - d2 | 0) * 3 | 0) | 0;
              c2 = ~(H() | 0) & c2;
              a2 = ~f2 & a2;
            }
            f2 = wd(d2 | 0, 0, 52) | 0;
            d2 = c2 & -15728641 | (H() | 0);
            b[e2 >> 2] = a2 | f2;
            b[e2 + 4 >> 2] = d2;
            e2 = 0;
            return e2 | 0;
          }
          function Bb(a2, c2, d2, e2) {
            a2 = a2 | 0;
            c2 = c2 | 0;
            d2 = d2 | 0;
            e2 = e2 | 0;
            var f2 = 0, g2 = 0, h = 0, i = 0, j = 0, k = 0, l = 0, m = 0, n = 0, o = 0, p2 = 0, q2 = 0, r2 = 0, s2 = 0, t2 = 0, u2 = 0, v2 = 0, w2 = 0, x2 = 0, y2 = 0, z2 = 0;
            if ((d2 | 0) == 0 & (e2 | 0) == 0) {
              y2 = 0;
              return y2 | 0;
            }
            f2 = a2;
            g2 = b[f2 >> 2] | 0;
            f2 = b[f2 + 4 >> 2] | 0;
            if (true & (f2 & 15728640 | 0) == 0) {
              if (!((e2 | 0) > 0 | (e2 | 0) == 0 & d2 >>> 0 > 0)) {
                y2 = 0;
                return y2 | 0;
              }
              y2 = c2;
              b[y2 >> 2] = g2;
              b[y2 + 4 >> 2] = f2;
              if ((d2 | 0) == 1 & (e2 | 0) == 0) {
                y2 = 0;
                return y2 | 0;
              }
              f2 = 1;
              do {
                w2 = a2 + (f2 << 3) | 0;
                x2 = b[w2 + 4 >> 2] | 0;
                y2 = c2 + (f2 << 3) | 0;
                b[y2 >> 2] = b[w2 >> 2];
                b[y2 + 4 >> 2] = x2;
                f2 = f2 + 1 | 0;
              } while (0 < (e2 | 0) | 0 == (e2 | 0) & f2 >>> 0 < d2 >>> 0);
              f2 = 0;
              return f2 | 0;
            }
            v2 = d2 << 3;
            x2 = id(v2) | 0;
            if (!x2) {
              y2 = 13;
              return y2 | 0;
            }
            Ad(x2 | 0, a2 | 0, v2 | 0) | 0;
            w2 = kd(d2, 8) | 0;
            if (!w2) {
              jd(x2);
              y2 = 13;
              return y2 | 0;
            }
            a: do {
              if (d2 | 0) {
                b: while (1) {
                  f2 = x2;
                  s2 = b[f2 >> 2] | 0;
                  f2 = b[f2 + 4 >> 2] | 0;
                  t2 = vd(s2 | 0, f2 | 0, 52) | 0;
                  H() | 0;
                  t2 = t2 & 15;
                  u2 = t2 + -1 | 0;
                  r2 = (d2 | 0) > 0;
                  c: do {
                    if ((t2 | 0) != 0 & r2) {
                      o = ((d2 | 0) < 0) << 31 >> 31;
                      p2 = wd(u2 | 0, 0, 52) | 0;
                      q2 = H() | 0;
                      if (u2 >>> 0 > 15) {
                        if (!((s2 | 0) == 0 & (f2 | 0) == 0)) {
                          y2 = 17;
                          break b;
                        }
                        g2 = 0;
                        while (1) {
                          g2 = g2 + 1 | 0;
                          if ((g2 | 0) >= (d2 | 0)) {
                            break c;
                          }
                          e2 = x2 + (g2 << 3) | 0;
                          q2 = b[e2 >> 2] | 0;
                          e2 = b[e2 + 4 >> 2] | 0;
                          if (!((q2 | 0) == 0 & (e2 | 0) == 0)) {
                            f2 = e2;
                            y2 = 17;
                            break b;
                          }
                        }
                      }
                      g2 = 0;
                      a2 = s2;
                      e2 = f2;
                      while (1) {
                        if (!((a2 | 0) == 0 & (e2 | 0) == 0)) {
                          if (!(true & (e2 & 117440512 | 0) == 0)) {
                            y2 = 22;
                            break b;
                          }
                          i = vd(a2 | 0, e2 | 0, 52) | 0;
                          H() | 0;
                          i = i & 15;
                          if ((i | 0) < (u2 | 0)) {
                            f2 = 12;
                            y2 = 28;
                            break b;
                          }
                          if ((i | 0) != (u2 | 0)) {
                            a2 = a2 | p2;
                            e2 = e2 & -15728641 | q2;
                            if (i >>> 0 >= t2 >>> 0) {
                              h = u2;
                              do {
                                n = wd(7, 0, (14 - h | 0) * 3 | 0) | 0;
                                h = h + 1 | 0;
                                a2 = n | a2;
                                e2 = H() | 0 | e2;
                              } while (h >>> 0 < i >>> 0);
                            }
                          }
                          h = td(a2 | 0, e2 | 0, d2 | 0, o | 0) | 0;
                          H() | 0;
                          k = w2 + (h << 3) | 0;
                          i = k;
                          j = b[i >> 2] | 0;
                          i = b[i + 4 >> 2] | 0;
                          if ((j | 0) == 0 & (i | 0) == 0) {
                            h = k;
                          } else {
                            n = 0;
                            while (1) {
                              if ((n | 0) > (d2 | 0)) {
                                y2 = 32;
                                break b;
                              }
                              if ((j | 0) == (a2 | 0) & (i & -117440513 | 0) == (e2 | 0)) {
                                l = vd(j | 0, i | 0, 56) | 0;
                                H() | 0;
                                l = l & 7;
                                m = l + 1 | 0;
                                z2 = vd(j | 0, i | 0, 45) | 0;
                                H() | 0;
                                d: do {
                                  if (!(ma(z2 & 127) | 0)) {
                                    i = 7;
                                  } else {
                                    j = vd(j | 0, i | 0, 52) | 0;
                                    H() | 0;
                                    j = j & 15;
                                    if (!j) {
                                      i = 6;
                                      break;
                                    }
                                    i = 1;
                                    while (1) {
                                      z2 = wd(7, 0, (15 - i | 0) * 3 | 0) | 0;
                                      if (!((z2 & a2 | 0) == 0 & ((H() | 0) & e2 | 0) == 0)) {
                                        i = 7;
                                        break d;
                                      }
                                      if (i >>> 0 < j >>> 0) {
                                        i = i + 1 | 0;
                                      } else {
                                        i = 6;
                                        break;
                                      }
                                    }
                                  }
                                } while (0);
                                if ((l + 2 | 0) >>> 0 > i >>> 0) {
                                  y2 = 42;
                                  break b;
                                }
                                z2 = wd(m | 0, 0, 56) | 0;
                                e2 = H() | 0 | e2 & -117440513;
                                m = k;
                                b[m >> 2] = 0;
                                b[m + 4 >> 2] = 0;
                                a2 = z2 | a2;
                              } else {
                                h = (h + 1 | 0) % (d2 | 0) | 0;
                              }
                              k = w2 + (h << 3) | 0;
                              i = k;
                              j = b[i >> 2] | 0;
                              i = b[i + 4 >> 2] | 0;
                              if ((j | 0) == 0 & (i | 0) == 0) {
                                h = k;
                                break;
                              } else {
                                n = n + 1 | 0;
                              }
                            }
                          }
                          z2 = h;
                          b[z2 >> 2] = a2;
                          b[z2 + 4 >> 2] = e2;
                        }
                        g2 = g2 + 1 | 0;
                        if ((g2 | 0) >= (d2 | 0)) {
                          break c;
                        }
                        e2 = x2 + (g2 << 3) | 0;
                        a2 = b[e2 >> 2] | 0;
                        e2 = b[e2 + 4 >> 2] | 0;
                      }
                    }
                  } while (0);
                  if ((d2 + 5 | 0) >>> 0 < 11) {
                    y2 = 85;
                    break;
                  }
                  q2 = kd((d2 | 0) / 6 | 0, 8) | 0;
                  if (!q2) {
                    y2 = 49;
                    break;
                  }
                  e: do {
                    if (r2) {
                      n = 0;
                      m = 0;
                      do {
                        i = w2 + (n << 3) | 0;
                        e2 = i;
                        g2 = b[e2 >> 2] | 0;
                        e2 = b[e2 + 4 >> 2] | 0;
                        if (!((g2 | 0) == 0 & (e2 | 0) == 0)) {
                          j = vd(g2 | 0, e2 | 0, 56) | 0;
                          H() | 0;
                          j = j & 7;
                          a2 = j + 1 | 0;
                          k = e2 & -117440513;
                          z2 = vd(g2 | 0, e2 | 0, 45) | 0;
                          H() | 0;
                          f: do {
                            if (ma(z2 & 127) | 0) {
                              l = vd(g2 | 0, e2 | 0, 52) | 0;
                              H() | 0;
                              l = l & 15;
                              if (l | 0) {
                                h = 1;
                                while (1) {
                                  z2 = wd(7, 0, (15 - h | 0) * 3 | 0) | 0;
                                  if (!((g2 & z2 | 0) == 0 & (k & (H() | 0) | 0) == 0)) {
                                    break f;
                                  }
                                  if (h >>> 0 < l >>> 0) {
                                    h = h + 1 | 0;
                                  } else {
                                    break;
                                  }
                                }
                              }
                              e2 = wd(a2 | 0, 0, 56) | 0;
                              g2 = e2 | g2;
                              e2 = H() | 0 | k;
                              a2 = i;
                              b[a2 >> 2] = g2;
                              b[a2 + 4 >> 2] = e2;
                              a2 = j + 2 | 0;
                            }
                          } while (0);
                          if ((a2 | 0) == 7) {
                            z2 = q2 + (m << 3) | 0;
                            b[z2 >> 2] = g2;
                            b[z2 + 4 >> 2] = e2 & -117440513;
                            m = m + 1 | 0;
                          }
                        }
                        n = n + 1 | 0;
                      } while ((n | 0) != (d2 | 0));
                      if (r2) {
                        n = ((d2 | 0) < 0) << 31 >> 31;
                        o = wd(u2 | 0, 0, 52) | 0;
                        p2 = H() | 0;
                        if (u2 >>> 0 > 15) {
                          if (!((s2 | 0) == 0 & (f2 | 0) == 0)) {
                            f2 = 4;
                            y2 = 84;
                            break b;
                          }
                          f2 = 0;
                          while (1) {
                            f2 = f2 + 1 | 0;
                            if ((f2 | 0) >= (d2 | 0)) {
                              g2 = 0;
                              f2 = m;
                              break e;
                            }
                            z2 = x2 + (f2 << 3) | 0;
                            if (!((b[z2 >> 2] | 0) == 0 & (b[z2 + 4 >> 2] | 0) == 0)) {
                              f2 = 4;
                              y2 = 84;
                              break b;
                            }
                          }
                        }
                        l = 0;
                        g2 = 0;
                        k = s2;
                        while (1) {
                          do {
                            if (!((k | 0) == 0 & (f2 | 0) == 0)) {
                              i = vd(k | 0, f2 | 0, 52) | 0;
                              H() | 0;
                              i = i & 15;
                              if ((i | 0) < (u2 | 0)) {
                                f2 = 12;
                                y2 = 84;
                                break b;
                              }
                              do {
                                if ((i | 0) == (u2 | 0)) {
                                  e2 = k;
                                  i = f2;
                                } else {
                                  e2 = k | o;
                                  a2 = f2 & -15728641 | p2;
                                  if (i >>> 0 < t2 >>> 0) {
                                    i = a2;
                                    break;
                                  }
                                  h = u2;
                                  do {
                                    z2 = wd(7, 0, (14 - h | 0) * 3 | 0) | 0;
                                    h = h + 1 | 0;
                                    e2 = z2 | e2;
                                    a2 = H() | 0 | a2;
                                  } while (h >>> 0 < i >>> 0);
                                  i = a2;
                                }
                              } while (0);
                              h = td(e2 | 0, i | 0, d2 | 0, n | 0) | 0;
                              H() | 0;
                              a2 = 0;
                              while (1) {
                                if ((a2 | 0) > (d2 | 0)) {
                                  y2 = 77;
                                  break b;
                                }
                                z2 = w2 + (h << 3) | 0;
                                j = b[z2 + 4 >> 2] | 0;
                                if ((j & -117440513 | 0) == (i | 0) ? (b[z2 >> 2] | 0) == (e2 | 0) : 0) {
                                  y2 = 79;
                                  break;
                                }
                                h = (h + 1 | 0) % (d2 | 0) | 0;
                                z2 = w2 + (h << 3) | 0;
                                if ((b[z2 >> 2] | 0) == (e2 | 0) ? (b[z2 + 4 >> 2] | 0) == (i | 0) : 0) {
                                  break;
                                } else {
                                  a2 = a2 + 1 | 0;
                                }
                              }
                              if ((y2 | 0) == 79 ? (y2 = 0, true & (j & 117440512 | 0) == 100663296) : 0) {
                                break;
                              }
                              z2 = c2 + (g2 << 3) | 0;
                              b[z2 >> 2] = k;
                              b[z2 + 4 >> 2] = f2;
                              g2 = g2 + 1 | 0;
                            }
                          } while (0);
                          f2 = l + 1 | 0;
                          if ((f2 | 0) >= (d2 | 0)) {
                            f2 = m;
                            break e;
                          }
                          z2 = x2 + (f2 << 3) | 0;
                          l = f2;
                          k = b[z2 >> 2] | 0;
                          f2 = b[z2 + 4 >> 2] | 0;
                        }
                      } else {
                        g2 = 0;
                        f2 = m;
                      }
                    } else {
                      g2 = 0;
                      f2 = 0;
                    }
                  } while (0);
                  Bd(w2 | 0, 0, v2 | 0) | 0;
                  Ad(x2 | 0, q2 | 0, f2 << 3 | 0) | 0;
                  jd(q2);
                  if (!f2) {
                    break a;
                  } else {
                    c2 = c2 + (g2 << 3) | 0;
                    d2 = f2;
                  }
                }
                if ((y2 | 0) == 17) {
                  if (true & (f2 & 117440512 | 0) == 0) {
                    f2 = 4;
                    y2 = 28;
                  } else {
                    y2 = 22;
                  }
                } else if ((y2 | 0) == 32) {
                  I(23313, 22674, 362, 22684);
                } else if ((y2 | 0) == 42) {
                  jd(x2);
                  jd(w2);
                  z2 = 10;
                  return z2 | 0;
                } else if ((y2 | 0) == 49) {
                  jd(x2);
                  jd(w2);
                  z2 = 13;
                  return z2 | 0;
                } else if ((y2 | 0) == 77) {
                  I(23313, 22674, 462, 22684);
                } else if ((y2 | 0) == 84) {
                  jd(q2);
                  jd(x2);
                  jd(w2);
                  z2 = f2;
                  return z2 | 0;
                } else if ((y2 | 0) == 85) {
                  Ad(c2 | 0, x2 | 0, d2 << 3 | 0) | 0;
                  break;
                }
                if ((y2 | 0) == 22) {
                  jd(x2);
                  jd(w2);
                  z2 = 5;
                  return z2 | 0;
                } else if ((y2 | 0) == 28) {
                  jd(x2);
                  jd(w2);
                  z2 = f2;
                  return z2 | 0;
                }
              }
            } while (0);
            jd(x2);
            jd(w2);
            z2 = 0;
            return z2 | 0;
          }
          function Cb(a2, c2, d2, e2, f2, g2, h) {
            a2 = a2 | 0;
            c2 = c2 | 0;
            d2 = d2 | 0;
            e2 = e2 | 0;
            f2 = f2 | 0;
            g2 = g2 | 0;
            h = h | 0;
            var i = 0, j = 0, k = 0, l = 0, m = 0, n = 0, o = 0, p2 = 0, q2 = 0;
            q2 = T;
            T = T + 16 | 0;
            p2 = q2;
            if (!((d2 | 0) > 0 | (d2 | 0) == 0 & c2 >>> 0 > 0)) {
              p2 = 0;
              T = q2;
              return p2 | 0;
            }
            if ((h | 0) >= 16) {
              p2 = 12;
              T = q2;
              return p2 | 0;
            }
            n = 0;
            o = 0;
            m = 0;
            i = 0;
            a: while (1) {
              k = a2 + (n << 3) | 0;
              j = b[k >> 2] | 0;
              k = b[k + 4 >> 2] | 0;
              l = vd(j | 0, k | 0, 52) | 0;
              H() | 0;
              if ((l & 15 | 0) > (h | 0)) {
                i = 12;
                j = 11;
                break;
              }
              Xb(p2, j, k, h);
              l = p2;
              k = b[l >> 2] | 0;
              l = b[l + 4 >> 2] | 0;
              if ((k | 0) == 0 & (l | 0) == 0) {
                j = m;
              } else {
                j = m;
                do {
                  if (!((i | 0) < (g2 | 0) | (i | 0) == (g2 | 0) & j >>> 0 < f2 >>> 0)) {
                    j = 10;
                    break a;
                  }
                  m = e2 + (j << 3) | 0;
                  b[m >> 2] = k;
                  b[m + 4 >> 2] = l;
                  j = ld(j | 0, i | 0, 1, 0) | 0;
                  i = H() | 0;
                  Yb(p2);
                  m = p2;
                  k = b[m >> 2] | 0;
                  l = b[m + 4 >> 2] | 0;
                } while (!((k | 0) == 0 & (l | 0) == 0));
              }
              n = ld(n | 0, o | 0, 1, 0) | 0;
              o = H() | 0;
              if (!((o | 0) < (d2 | 0) | (o | 0) == (d2 | 0) & n >>> 0 < c2 >>> 0)) {
                i = 0;
                j = 11;
                break;
              } else {
                m = j;
              }
            }
            if ((j | 0) == 10) {
              p2 = 14;
              T = q2;
              return p2 | 0;
            } else if ((j | 0) == 11) {
              T = q2;
              return i | 0;
            }
            return 0;
          }
          function Db(a2, c2, d2, e2, f2) {
            a2 = a2 | 0;
            c2 = c2 | 0;
            d2 = d2 | 0;
            e2 = e2 | 0;
            f2 = f2 | 0;
            var g2 = 0, h = 0, i = 0, j = 0, k = 0, l = 0, m = 0, n = 0;
            n = T;
            T = T + 16 | 0;
            m = n;
            a: do {
              if ((d2 | 0) > 0 | (d2 | 0) == 0 & c2 >>> 0 > 0) {
                k = 0;
                h = 0;
                g2 = 0;
                l = 0;
                while (1) {
                  j = a2 + (k << 3) | 0;
                  i = b[j >> 2] | 0;
                  j = b[j + 4 >> 2] | 0;
                  if (!((i | 0) == 0 & (j | 0) == 0)) {
                    j = (wb(i, j, e2, m) | 0) == 0;
                    i = m;
                    h = ld(b[i >> 2] | 0, b[i + 4 >> 2] | 0, h | 0, g2 | 0) | 0;
                    g2 = H() | 0;
                    if (!j) {
                      g2 = 12;
                      break;
                    }
                  }
                  k = ld(k | 0, l | 0, 1, 0) | 0;
                  l = H() | 0;
                  if (!((l | 0) < (d2 | 0) | (l | 0) == (d2 | 0) & k >>> 0 < c2 >>> 0)) {
                    break a;
                  }
                }
                T = n;
                return g2 | 0;
              } else {
                h = 0;
                g2 = 0;
              }
            } while (0);
            b[f2 >> 2] = h;
            b[f2 + 4 >> 2] = g2;
            f2 = 0;
            T = n;
            return f2 | 0;
          }
          function Eb(a2, b2) {
            a2 = a2 | 0;
            b2 = b2 | 0;
            b2 = vd(a2 | 0, b2 | 0, 52) | 0;
            H() | 0;
            return b2 & 1 | 0;
          }
          function Fb(a2, b2) {
            a2 = a2 | 0;
            b2 = b2 | 0;
            var c2 = 0, d2 = 0, e2 = 0;
            e2 = vd(a2 | 0, b2 | 0, 52) | 0;
            H() | 0;
            e2 = e2 & 15;
            if (!e2) {
              e2 = 0;
              return e2 | 0;
            }
            d2 = 1;
            while (1) {
              c2 = vd(a2 | 0, b2 | 0, (15 - d2 | 0) * 3 | 0) | 0;
              H() | 0;
              c2 = c2 & 7;
              if (c2 | 0) {
                d2 = 5;
                break;
              }
              if (d2 >>> 0 < e2 >>> 0) {
                d2 = d2 + 1 | 0;
              } else {
                c2 = 0;
                d2 = 5;
                break;
              }
            }
            if ((d2 | 0) == 5) {
              return c2 | 0;
            }
            return 0;
          }
          function Gb(a2, b2) {
            a2 = a2 | 0;
            b2 = b2 | 0;
            var c2 = 0, d2 = 0, e2 = 0, f2 = 0, g2 = 0, h = 0, i = 0;
            i = vd(a2 | 0, b2 | 0, 52) | 0;
            H() | 0;
            i = i & 15;
            if (!i) {
              h = b2;
              i = a2;
              G(h | 0);
              return i | 0;
            }
            h = 1;
            c2 = 0;
            while (1) {
              f2 = (15 - h | 0) * 3 | 0;
              d2 = wd(7, 0, f2 | 0) | 0;
              e2 = H() | 0;
              g2 = vd(a2 | 0, b2 | 0, f2 | 0) | 0;
              H() | 0;
              f2 = wd(Sa(g2 & 7) | 0, 0, f2 | 0) | 0;
              g2 = H() | 0;
              a2 = f2 | a2 & ~d2;
              b2 = g2 | b2 & ~e2;
              a: do {
                if (!c2) {
                  if (!((f2 & d2 | 0) == 0 & (g2 & e2 | 0) == 0)) {
                    d2 = vd(a2 | 0, b2 | 0, 52) | 0;
                    H() | 0;
                    d2 = d2 & 15;
                    if (!d2) {
                      c2 = 1;
                    } else {
                      c2 = 1;
                      b: while (1) {
                        g2 = vd(a2 | 0, b2 | 0, (15 - c2 | 0) * 3 | 0) | 0;
                        H() | 0;
                        switch (g2 & 7) {
                          case 1:
                            break b;
                          case 0:
                            break;
                          default: {
                            c2 = 1;
                            break a;
                          }
                        }
                        if (c2 >>> 0 < d2 >>> 0) {
                          c2 = c2 + 1 | 0;
                        } else {
                          c2 = 1;
                          break a;
                        }
                      }
                      c2 = 1;
                      while (1) {
                        g2 = (15 - c2 | 0) * 3 | 0;
                        e2 = vd(a2 | 0, b2 | 0, g2 | 0) | 0;
                        H() | 0;
                        f2 = wd(7, 0, g2 | 0) | 0;
                        b2 = b2 & ~(H() | 0);
                        g2 = wd(Sa(e2 & 7) | 0, 0, g2 | 0) | 0;
                        a2 = a2 & ~f2 | g2;
                        b2 = b2 | (H() | 0);
                        if (c2 >>> 0 < d2 >>> 0) {
                          c2 = c2 + 1 | 0;
                        } else {
                          c2 = 1;
                          break;
                        }
                      }
                    }
                  } else {
                    c2 = 0;
                  }
                }
              } while (0);
              if (h >>> 0 < i >>> 0) {
                h = h + 1 | 0;
              } else {
                break;
              }
            }
            G(b2 | 0);
            return a2 | 0;
          }
          function Hb(a2, b2) {
            a2 = a2 | 0;
            b2 = b2 | 0;
            var c2 = 0, d2 = 0, e2 = 0, f2 = 0, g2 = 0;
            d2 = vd(a2 | 0, b2 | 0, 52) | 0;
            H() | 0;
            d2 = d2 & 15;
            if (!d2) {
              c2 = b2;
              d2 = a2;
              G(c2 | 0);
              return d2 | 0;
            }
            c2 = 1;
            while (1) {
              f2 = (15 - c2 | 0) * 3 | 0;
              g2 = vd(a2 | 0, b2 | 0, f2 | 0) | 0;
              H() | 0;
              e2 = wd(7, 0, f2 | 0) | 0;
              b2 = b2 & ~(H() | 0);
              f2 = wd(Sa(g2 & 7) | 0, 0, f2 | 0) | 0;
              a2 = f2 | a2 & ~e2;
              b2 = H() | 0 | b2;
              if (c2 >>> 0 < d2 >>> 0) {
                c2 = c2 + 1 | 0;
              } else {
                break;
              }
            }
            G(b2 | 0);
            return a2 | 0;
          }
          function Ib(a2, b2) {
            a2 = a2 | 0;
            b2 = b2 | 0;
            var c2 = 0, d2 = 0, e2 = 0, f2 = 0, g2 = 0, h = 0, i = 0;
            i = vd(a2 | 0, b2 | 0, 52) | 0;
            H() | 0;
            i = i & 15;
            if (!i) {
              h = b2;
              i = a2;
              G(h | 0);
              return i | 0;
            }
            h = 1;
            c2 = 0;
            while (1) {
              f2 = (15 - h | 0) * 3 | 0;
              d2 = wd(7, 0, f2 | 0) | 0;
              e2 = H() | 0;
              g2 = vd(a2 | 0, b2 | 0, f2 | 0) | 0;
              H() | 0;
              f2 = wd(Ta(g2 & 7) | 0, 0, f2 | 0) | 0;
              g2 = H() | 0;
              a2 = f2 | a2 & ~d2;
              b2 = g2 | b2 & ~e2;
              a: do {
                if (!c2) {
                  if (!((f2 & d2 | 0) == 0 & (g2 & e2 | 0) == 0)) {
                    d2 = vd(a2 | 0, b2 | 0, 52) | 0;
                    H() | 0;
                    d2 = d2 & 15;
                    if (!d2) {
                      c2 = 1;
                    } else {
                      c2 = 1;
                      b: while (1) {
                        g2 = vd(a2 | 0, b2 | 0, (15 - c2 | 0) * 3 | 0) | 0;
                        H() | 0;
                        switch (g2 & 7) {
                          case 1:
                            break b;
                          case 0:
                            break;
                          default: {
                            c2 = 1;
                            break a;
                          }
                        }
                        if (c2 >>> 0 < d2 >>> 0) {
                          c2 = c2 + 1 | 0;
                        } else {
                          c2 = 1;
                          break a;
                        }
                      }
                      c2 = 1;
                      while (1) {
                        e2 = (15 - c2 | 0) * 3 | 0;
                        f2 = wd(7, 0, e2 | 0) | 0;
                        g2 = b2 & ~(H() | 0);
                        b2 = vd(a2 | 0, b2 | 0, e2 | 0) | 0;
                        H() | 0;
                        b2 = wd(Ta(b2 & 7) | 0, 0, e2 | 0) | 0;
                        a2 = a2 & ~f2 | b2;
                        b2 = g2 | (H() | 0);
                        if (c2 >>> 0 < d2 >>> 0) {
                          c2 = c2 + 1 | 0;
                        } else {
                          c2 = 1;
                          break;
                        }
                      }
                    }
                  } else {
                    c2 = 0;
                  }
                }
              } while (0);
              if (h >>> 0 < i >>> 0) {
                h = h + 1 | 0;
              } else {
                break;
              }
            }
            G(b2 | 0);
            return a2 | 0;
          }
          function Jb(a2, b2) {
            a2 = a2 | 0;
            b2 = b2 | 0;
            var c2 = 0, d2 = 0, e2 = 0, f2 = 0, g2 = 0;
            d2 = vd(a2 | 0, b2 | 0, 52) | 0;
            H() | 0;
            d2 = d2 & 15;
            if (!d2) {
              c2 = b2;
              d2 = a2;
              G(c2 | 0);
              return d2 | 0;
            }
            c2 = 1;
            while (1) {
              g2 = (15 - c2 | 0) * 3 | 0;
              f2 = wd(7, 0, g2 | 0) | 0;
              e2 = b2 & ~(H() | 0);
              b2 = vd(a2 | 0, b2 | 0, g2 | 0) | 0;
              H() | 0;
              b2 = wd(Ta(b2 & 7) | 0, 0, g2 | 0) | 0;
              a2 = b2 | a2 & ~f2;
              b2 = H() | 0 | e2;
              if (c2 >>> 0 < d2 >>> 0) {
                c2 = c2 + 1 | 0;
              } else {
                break;
              }
            }
            G(b2 | 0);
            return a2 | 0;
          }
          function Kb(a2, c2) {
            a2 = a2 | 0;
            c2 = c2 | 0;
            var d2 = 0, e2 = 0, f2 = 0, g2 = 0, h = 0, i = 0, j = 0, k = 0, l = 0;
            j = T;
            T = T + 64 | 0;
            i = j + 40 | 0;
            e2 = j + 24 | 0;
            f2 = j + 12 | 0;
            g2 = j;
            wd(c2 | 0, 0, 52) | 0;
            d2 = H() | 0 | 134225919;
            if (!c2) {
              if ((b[a2 + 4 >> 2] | 0) > 2) {
                h = 0;
                i = 0;
                G(h | 0);
                T = j;
                return i | 0;
              }
              if ((b[a2 + 8 >> 2] | 0) > 2) {
                h = 0;
                i = 0;
                G(h | 0);
                T = j;
                return i | 0;
              }
              if ((b[a2 + 12 >> 2] | 0) > 2) {
                h = 0;
                i = 0;
                G(h | 0);
                T = j;
                return i | 0;
              }
              wd(oa(a2) | 0, 0, 45) | 0;
              h = H() | 0 | d2;
              i = -1;
              G(h | 0);
              T = j;
              return i | 0;
            }
            b[i >> 2] = b[a2 >> 2];
            b[i + 4 >> 2] = b[a2 + 4 >> 2];
            b[i + 8 >> 2] = b[a2 + 8 >> 2];
            b[i + 12 >> 2] = b[a2 + 12 >> 2];
            h = i + 4 | 0;
            if ((c2 | 0) > 0) {
              a2 = -1;
              while (1) {
                b[e2 >> 2] = b[h >> 2];
                b[e2 + 4 >> 2] = b[h + 4 >> 2];
                b[e2 + 8 >> 2] = b[h + 8 >> 2];
                if (!(c2 & 1)) {
                  Ma(h);
                  b[f2 >> 2] = b[h >> 2];
                  b[f2 + 4 >> 2] = b[h + 4 >> 2];
                  b[f2 + 8 >> 2] = b[h + 8 >> 2];
                  Oa(f2);
                } else {
                  La(h);
                  b[f2 >> 2] = b[h >> 2];
                  b[f2 + 4 >> 2] = b[h + 4 >> 2];
                  b[f2 + 8 >> 2] = b[h + 8 >> 2];
                  Na(f2);
                }
                Ga(e2, f2, g2);
                Da(g2);
                l = (15 - c2 | 0) * 3 | 0;
                k = wd(7, 0, l | 0) | 0;
                d2 = d2 & ~(H() | 0);
                l = wd(Ia(g2) | 0, 0, l | 0) | 0;
                a2 = l | a2 & ~k;
                d2 = H() | 0 | d2;
                if ((c2 | 0) > 1) {
                  c2 = c2 + -1 | 0;
                } else {
                  break;
                }
              }
            } else {
              a2 = -1;
            }
            a: do {
              if (((b[h >> 2] | 0) <= 2 ? (b[i + 8 >> 2] | 0) <= 2 : 0) ? (b[i + 12 >> 2] | 0) <= 2 : 0) {
                e2 = oa(i) | 0;
                c2 = wd(e2 | 0, 0, 45) | 0;
                c2 = c2 | a2;
                a2 = H() | 0 | d2 & -1040385;
                g2 = pa(i) | 0;
                if (!(ma(e2) | 0)) {
                  if ((g2 | 0) <= 0) {
                    break;
                  }
                  f2 = 0;
                  while (1) {
                    e2 = vd(c2 | 0, a2 | 0, 52) | 0;
                    H() | 0;
                    e2 = e2 & 15;
                    if (e2) {
                      d2 = 1;
                      while (1) {
                        l = (15 - d2 | 0) * 3 | 0;
                        i = vd(c2 | 0, a2 | 0, l | 0) | 0;
                        H() | 0;
                        k = wd(7, 0, l | 0) | 0;
                        a2 = a2 & ~(H() | 0);
                        l = wd(Sa(i & 7) | 0, 0, l | 0) | 0;
                        c2 = c2 & ~k | l;
                        a2 = a2 | (H() | 0);
                        if (d2 >>> 0 < e2 >>> 0) {
                          d2 = d2 + 1 | 0;
                        } else {
                          break;
                        }
                      }
                    }
                    f2 = f2 + 1 | 0;
                    if ((f2 | 0) == (g2 | 0)) {
                      break a;
                    }
                  }
                }
                f2 = vd(c2 | 0, a2 | 0, 52) | 0;
                H() | 0;
                f2 = f2 & 15;
                b: do {
                  if (f2) {
                    d2 = 1;
                    c: while (1) {
                      l = vd(c2 | 0, a2 | 0, (15 - d2 | 0) * 3 | 0) | 0;
                      H() | 0;
                      switch (l & 7) {
                        case 1:
                          break c;
                        case 0:
                          break;
                        default:
                          break b;
                      }
                      if (d2 >>> 0 < f2 >>> 0) {
                        d2 = d2 + 1 | 0;
                      } else {
                        break b;
                      }
                    }
                    if (sa(e2, b[i >> 2] | 0) | 0) {
                      d2 = 1;
                      while (1) {
                        i = (15 - d2 | 0) * 3 | 0;
                        k = wd(7, 0, i | 0) | 0;
                        l = a2 & ~(H() | 0);
                        a2 = vd(c2 | 0, a2 | 0, i | 0) | 0;
                        H() | 0;
                        a2 = wd(Ta(a2 & 7) | 0, 0, i | 0) | 0;
                        c2 = c2 & ~k | a2;
                        a2 = l | (H() | 0);
                        if (d2 >>> 0 < f2 >>> 0) {
                          d2 = d2 + 1 | 0;
                        } else {
                          break;
                        }
                      }
                    } else {
                      d2 = 1;
                      while (1) {
                        l = (15 - d2 | 0) * 3 | 0;
                        i = vd(c2 | 0, a2 | 0, l | 0) | 0;
                        H() | 0;
                        k = wd(7, 0, l | 0) | 0;
                        a2 = a2 & ~(H() | 0);
                        l = wd(Sa(i & 7) | 0, 0, l | 0) | 0;
                        c2 = c2 & ~k | l;
                        a2 = a2 | (H() | 0);
                        if (d2 >>> 0 < f2 >>> 0) {
                          d2 = d2 + 1 | 0;
                        } else {
                          break;
                        }
                      }
                    }
                  }
                } while (0);
                if ((g2 | 0) > 0) {
                  d2 = 0;
                  do {
                    c2 = Gb(c2, a2) | 0;
                    a2 = H() | 0;
                    d2 = d2 + 1 | 0;
                  } while ((d2 | 0) != (g2 | 0));
                }
              } else {
                c2 = 0;
                a2 = 0;
              }
            } while (0);
            k = a2;
            l = c2;
            G(k | 0);
            T = j;
            return l | 0;
          }
          function Lb(a2) {
            a2 = a2 | 0;
            return (a2 | 0) % 2 | 0 | 0;
          }
          function Mb(a2, c2, d2) {
            a2 = a2 | 0;
            c2 = c2 | 0;
            d2 = d2 | 0;
            var e2 = 0, f2 = 0;
            f2 = T;
            T = T + 16 | 0;
            e2 = f2;
            if (c2 >>> 0 > 15) {
              e2 = 4;
              T = f2;
              return e2 | 0;
            }
            if ((b[a2 + 4 >> 2] & 2146435072 | 0) == 2146435072) {
              e2 = 3;
              T = f2;
              return e2 | 0;
            }
            if ((b[a2 + 8 + 4 >> 2] & 2146435072 | 0) == 2146435072) {
              e2 = 3;
              T = f2;
              return e2 | 0;
            }
            hb(a2, c2, e2);
            c2 = Kb(e2, c2) | 0;
            e2 = H() | 0;
            b[d2 >> 2] = c2;
            b[d2 + 4 >> 2] = e2;
            if ((c2 | 0) == 0 & (e2 | 0) == 0) {
              I(23313, 22674, 786, 22697);
            }
            e2 = 0;
            T = f2;
            return e2 | 0;
          }
          function Nb(a2, c2, d2) {
            a2 = a2 | 0;
            c2 = c2 | 0;
            d2 = d2 | 0;
            var e2 = 0, f2 = 0, g2 = 0, h = 0;
            f2 = d2 + 4 | 0;
            g2 = vd(a2 | 0, c2 | 0, 52) | 0;
            H() | 0;
            g2 = g2 & 15;
            h = vd(a2 | 0, c2 | 0, 45) | 0;
            H() | 0;
            e2 = (g2 | 0) == 0;
            if (!(ma(h & 127) | 0)) {
              if (e2) {
                h = 0;
                return h | 0;
              }
              if ((b[f2 >> 2] | 0) == 0 ? (b[d2 + 8 >> 2] | 0) == 0 : 0) {
                e2 = (b[d2 + 12 >> 2] | 0) != 0 & 1;
              } else {
                e2 = 1;
              }
            } else if (e2) {
              h = 1;
              return h | 0;
            } else {
              e2 = 1;
            }
            d2 = 1;
            while (1) {
              if (!(d2 & 1)) {
                Oa(f2);
              } else {
                Na(f2);
              }
              h = vd(a2 | 0, c2 | 0, (15 - d2 | 0) * 3 | 0) | 0;
              H() | 0;
              Pa(f2, h & 7);
              if (d2 >>> 0 < g2 >>> 0) {
                d2 = d2 + 1 | 0;
              } else {
                break;
              }
            }
            return e2 | 0;
          }
          function Ob(a2, c2, d2) {
            a2 = a2 | 0;
            c2 = c2 | 0;
            d2 = d2 | 0;
            var e2 = 0, f2 = 0, g2 = 0, h = 0, i = 0, j = 0, k = 0, l = 0;
            l = T;
            T = T + 16 | 0;
            j = l;
            k = vd(a2 | 0, c2 | 0, 45) | 0;
            H() | 0;
            k = k & 127;
            if (k >>> 0 > 121) {
              b[d2 >> 2] = 0;
              b[d2 + 4 >> 2] = 0;
              b[d2 + 8 >> 2] = 0;
              b[d2 + 12 >> 2] = 0;
              k = 5;
              T = l;
              return k | 0;
            }
            a: do {
              if ((ma(k) | 0) != 0 ? (g2 = vd(a2 | 0, c2 | 0, 52) | 0, H() | 0, g2 = g2 & 15, (g2 | 0) != 0) : 0) {
                e2 = 1;
                b: while (1) {
                  i = vd(a2 | 0, c2 | 0, (15 - e2 | 0) * 3 | 0) | 0;
                  H() | 0;
                  switch (i & 7) {
                    case 5:
                      break b;
                    case 0:
                      break;
                    default: {
                      e2 = c2;
                      break a;
                    }
                  }
                  if (e2 >>> 0 < g2 >>> 0) {
                    e2 = e2 + 1 | 0;
                  } else {
                    e2 = c2;
                    break a;
                  }
                }
                f2 = 1;
                e2 = c2;
                while (1) {
                  c2 = (15 - f2 | 0) * 3 | 0;
                  h = wd(7, 0, c2 | 0) | 0;
                  i = e2 & ~(H() | 0);
                  e2 = vd(a2 | 0, e2 | 0, c2 | 0) | 0;
                  H() | 0;
                  e2 = wd(Ta(e2 & 7) | 0, 0, c2 | 0) | 0;
                  a2 = a2 & ~h | e2;
                  e2 = i | (H() | 0);
                  if (f2 >>> 0 < g2 >>> 0) {
                    f2 = f2 + 1 | 0;
                  } else {
                    break;
                  }
                }
              } else {
                e2 = c2;
              }
            } while (0);
            i = 7696 + (k * 28 | 0) | 0;
            b[d2 >> 2] = b[i >> 2];
            b[d2 + 4 >> 2] = b[i + 4 >> 2];
            b[d2 + 8 >> 2] = b[i + 8 >> 2];
            b[d2 + 12 >> 2] = b[i + 12 >> 2];
            if (!(Nb(a2, e2, d2) | 0)) {
              k = 0;
              T = l;
              return k | 0;
            }
            h = d2 + 4 | 0;
            b[j >> 2] = b[h >> 2];
            b[j + 4 >> 2] = b[h + 4 >> 2];
            b[j + 8 >> 2] = b[h + 8 >> 2];
            g2 = vd(a2 | 0, e2 | 0, 52) | 0;
            H() | 0;
            i = g2 & 15;
            if (!(g2 & 1)) {
              g2 = i;
            } else {
              Oa(h);
              g2 = i + 1 | 0;
            }
            if (!(ma(k) | 0)) {
              e2 = 0;
            } else {
              c: do {
                if (!i) {
                  e2 = 0;
                } else {
                  c2 = 1;
                  while (1) {
                    f2 = vd(a2 | 0, e2 | 0, (15 - c2 | 0) * 3 | 0) | 0;
                    H() | 0;
                    f2 = f2 & 7;
                    if (f2 | 0) {
                      e2 = f2;
                      break c;
                    }
                    if (c2 >>> 0 < i >>> 0) {
                      c2 = c2 + 1 | 0;
                    } else {
                      e2 = 0;
                      break;
                    }
                  }
                }
              } while (0);
              e2 = (e2 | 0) == 4 & 1;
            }
            if (!(ob(d2, g2, e2, 0) | 0)) {
              if ((g2 | 0) != (i | 0)) {
                b[h >> 2] = b[j >> 2];
                b[h + 4 >> 2] = b[j + 4 >> 2];
                b[h + 8 >> 2] = b[j + 8 >> 2];
              }
            } else {
              if (ma(k) | 0) {
                do {
                } while ((ob(d2, g2, 0, 0) | 0) != 0);
              }
              if ((g2 | 0) != (i | 0)) {
                Ma(h);
              }
            }
            k = 0;
            T = l;
            return k | 0;
          }
          function Pb(a2, b2, c2) {
            a2 = a2 | 0;
            b2 = b2 | 0;
            c2 = c2 | 0;
            var d2 = 0, e2 = 0, f2 = 0;
            f2 = T;
            T = T + 16 | 0;
            d2 = f2;
            e2 = Ob(a2, b2, d2) | 0;
            if (e2 | 0) {
              T = f2;
              return e2 | 0;
            }
            e2 = vd(a2 | 0, b2 | 0, 52) | 0;
            H() | 0;
            lb(d2, e2 & 15, c2);
            e2 = 0;
            T = f2;
            return e2 | 0;
          }
          function Qb(a2, b2, c2) {
            a2 = a2 | 0;
            b2 = b2 | 0;
            c2 = c2 | 0;
            var d2 = 0, e2 = 0, f2 = 0, g2 = 0, h = 0;
            g2 = T;
            T = T + 16 | 0;
            f2 = g2;
            d2 = Ob(a2, b2, f2) | 0;
            if (d2 | 0) {
              f2 = d2;
              T = g2;
              return f2 | 0;
            }
            d2 = vd(a2 | 0, b2 | 0, 45) | 0;
            H() | 0;
            d2 = (ma(d2 & 127) | 0) == 0;
            e2 = vd(a2 | 0, b2 | 0, 52) | 0;
            H() | 0;
            e2 = e2 & 15;
            a: do {
              if (!d2) {
                if (e2 | 0) {
                  d2 = 1;
                  while (1) {
                    h = wd(7, 0, (15 - d2 | 0) * 3 | 0) | 0;
                    if (!((h & a2 | 0) == 0 & ((H() | 0) & b2 | 0) == 0)) {
                      break a;
                    }
                    if (d2 >>> 0 < e2 >>> 0) {
                      d2 = d2 + 1 | 0;
                    } else {
                      break;
                    }
                  }
                }
                mb(f2, e2, 0, 5, c2);
                h = 0;
                T = g2;
                return h | 0;
              }
            } while (0);
            qb(f2, e2, 0, 6, c2);
            h = 0;
            T = g2;
            return h | 0;
          }
          function Rb(a2, c2, d2) {
            a2 = a2 | 0;
            c2 = c2 | 0;
            d2 = d2 | 0;
            var e2 = 0, f2 = 0, g2 = 0;
            f2 = vd(a2 | 0, c2 | 0, 45) | 0;
            H() | 0;
            if (!(ma(f2 & 127) | 0)) {
              f2 = 2;
              b[d2 >> 2] = f2;
              return 0;
            }
            f2 = vd(a2 | 0, c2 | 0, 52) | 0;
            H() | 0;
            f2 = f2 & 15;
            if (!f2) {
              f2 = 5;
              b[d2 >> 2] = f2;
              return 0;
            }
            e2 = 1;
            while (1) {
              g2 = wd(7, 0, (15 - e2 | 0) * 3 | 0) | 0;
              if (!((g2 & a2 | 0) == 0 & ((H() | 0) & c2 | 0) == 0)) {
                e2 = 2;
                a2 = 6;
                break;
              }
              if (e2 >>> 0 < f2 >>> 0) {
                e2 = e2 + 1 | 0;
              } else {
                e2 = 5;
                a2 = 6;
                break;
              }
            }
            if ((a2 | 0) == 6) {
              b[d2 >> 2] = e2;
              return 0;
            }
            return 0;
          }
          function Sb(a2, c2, d2) {
            a2 = a2 | 0;
            c2 = c2 | 0;
            d2 = d2 | 0;
            var e2 = 0, f2 = 0, g2 = 0, h = 0, i = 0, j = 0, k = 0, l = 0, m = 0;
            m = T;
            T = T + 128 | 0;
            k = m + 112 | 0;
            g2 = m + 96 | 0;
            l = m;
            f2 = vd(a2 | 0, c2 | 0, 52) | 0;
            H() | 0;
            i = f2 & 15;
            b[k >> 2] = i;
            h = vd(a2 | 0, c2 | 0, 45) | 0;
            H() | 0;
            h = h & 127;
            a: do {
              if (ma(h) | 0) {
                if (i | 0) {
                  e2 = 1;
                  while (1) {
                    j = wd(7, 0, (15 - e2 | 0) * 3 | 0) | 0;
                    if (!((j & a2 | 0) == 0 & ((H() | 0) & c2 | 0) == 0)) {
                      f2 = 0;
                      break a;
                    }
                    if (e2 >>> 0 < i >>> 0) {
                      e2 = e2 + 1 | 0;
                    } else {
                      break;
                    }
                  }
                }
                if (!(f2 & 1)) {
                  j = wd(i + 1 | 0, 0, 52) | 0;
                  l = H() | 0 | c2 & -15728641;
                  k = wd(7, 0, (14 - i | 0) * 3 | 0) | 0;
                  l = Sb((j | a2) & ~k, l & ~(H() | 0), d2) | 0;
                  T = m;
                  return l | 0;
                } else {
                  f2 = 1;
                }
              } else {
                f2 = 0;
              }
            } while (0);
            e2 = Ob(a2, c2, g2) | 0;
            if (!e2) {
              if (f2) {
                nb(g2, k, l);
                j = 5;
              } else {
                rb(g2, k, l);
                j = 6;
              }
              b: do {
                if (ma(h) | 0) {
                  if (!i) {
                    a2 = 5;
                  } else {
                    e2 = 1;
                    while (1) {
                      h = wd(7, 0, (15 - e2 | 0) * 3 | 0) | 0;
                      if (!((h & a2 | 0) == 0 & ((H() | 0) & c2 | 0) == 0)) {
                        a2 = 2;
                        break b;
                      }
                      if (e2 >>> 0 < i >>> 0) {
                        e2 = e2 + 1 | 0;
                      } else {
                        a2 = 5;
                        break;
                      }
                    }
                  }
                } else {
                  a2 = 2;
                }
              } while (0);
              Bd(d2 | 0, -1, a2 << 2 | 0) | 0;
              c: do {
                if (f2) {
                  g2 = 0;
                  while (1) {
                    h = l + (g2 << 4) | 0;
                    pb(h, b[k >> 2] | 0) | 0;
                    h = b[h >> 2] | 0;
                    i = b[d2 >> 2] | 0;
                    if ((i | 0) == -1 | (i | 0) == (h | 0)) {
                      e2 = d2;
                    } else {
                      f2 = 0;
                      do {
                        f2 = f2 + 1 | 0;
                        if (f2 >>> 0 >= a2 >>> 0) {
                          e2 = 1;
                          break c;
                        }
                        e2 = d2 + (f2 << 2) | 0;
                        i = b[e2 >> 2] | 0;
                      } while (!((i | 0) == -1 | (i | 0) == (h | 0)));
                    }
                    b[e2 >> 2] = h;
                    g2 = g2 + 1 | 0;
                    if (g2 >>> 0 >= j >>> 0) {
                      e2 = 0;
                      break;
                    }
                  }
                } else {
                  g2 = 0;
                  while (1) {
                    h = l + (g2 << 4) | 0;
                    ob(h, b[k >> 2] | 0, 0, 1) | 0;
                    h = b[h >> 2] | 0;
                    i = b[d2 >> 2] | 0;
                    if ((i | 0) == -1 | (i | 0) == (h | 0)) {
                      e2 = d2;
                    } else {
                      f2 = 0;
                      do {
                        f2 = f2 + 1 | 0;
                        if (f2 >>> 0 >= a2 >>> 0) {
                          e2 = 1;
                          break c;
                        }
                        e2 = d2 + (f2 << 2) | 0;
                        i = b[e2 >> 2] | 0;
                      } while (!((i | 0) == -1 | (i | 0) == (h | 0)));
                    }
                    b[e2 >> 2] = h;
                    g2 = g2 + 1 | 0;
                    if (g2 >>> 0 >= j >>> 0) {
                      e2 = 0;
                      break;
                    }
                  }
                }
              } while (0);
            }
            l = e2;
            T = m;
            return l | 0;
          }
          function Tb() {
            return 12;
          }
          function Ub(a2, c2) {
            a2 = a2 | 0;
            c2 = c2 | 0;
            var d2 = 0, e2 = 0, f2 = 0, g2 = 0, h = 0, i = 0, j = 0;
            if (a2 >>> 0 > 15) {
              i = 4;
              return i | 0;
            }
            wd(a2 | 0, 0, 52) | 0;
            i = H() | 0 | 134225919;
            if (!a2) {
              d2 = 0;
              e2 = 0;
              do {
                if (ma(e2) | 0) {
                  wd(e2 | 0, 0, 45) | 0;
                  h = i | (H() | 0);
                  a2 = c2 + (d2 << 3) | 0;
                  b[a2 >> 2] = -1;
                  b[a2 + 4 >> 2] = h;
                  d2 = d2 + 1 | 0;
                }
                e2 = e2 + 1 | 0;
              } while ((e2 | 0) != 122);
              d2 = 0;
              return d2 | 0;
            }
            d2 = 0;
            h = 0;
            do {
              if (ma(h) | 0) {
                wd(h | 0, 0, 45) | 0;
                e2 = 1;
                f2 = -1;
                g2 = i | (H() | 0);
                while (1) {
                  j = wd(7, 0, (15 - e2 | 0) * 3 | 0) | 0;
                  f2 = f2 & ~j;
                  g2 = g2 & ~(H() | 0);
                  if ((e2 | 0) == (a2 | 0)) {
                    break;
                  } else {
                    e2 = e2 + 1 | 0;
                  }
                }
                j = c2 + (d2 << 3) | 0;
                b[j >> 2] = f2;
                b[j + 4 >> 2] = g2;
                d2 = d2 + 1 | 0;
              }
              h = h + 1 | 0;
            } while ((h | 0) != 122);
            d2 = 0;
            return d2 | 0;
          }
          function Vb(a2, c2, d2, e2) {
            a2 = a2 | 0;
            c2 = c2 | 0;
            d2 = d2 | 0;
            e2 = e2 | 0;
            var f2 = 0, g2 = 0, h = 0, i = 0, j = 0, k = 0, l = 0, m = 0, n = 0, o = 0, p2 = 0, q2 = 0, r2 = 0, s2 = 0, t2 = 0;
            t2 = T;
            T = T + 16 | 0;
            r2 = t2;
            s2 = vd(a2 | 0, c2 | 0, 52) | 0;
            H() | 0;
            s2 = s2 & 15;
            if (d2 >>> 0 > 15) {
              s2 = 4;
              T = t2;
              return s2 | 0;
            }
            if ((s2 | 0) < (d2 | 0)) {
              s2 = 12;
              T = t2;
              return s2 | 0;
            }
            if ((s2 | 0) != (d2 | 0)) {
              g2 = wd(d2 | 0, 0, 52) | 0;
              g2 = g2 | a2;
              i = H() | 0 | c2 & -15728641;
              if ((s2 | 0) > (d2 | 0)) {
                j = d2;
                do {
                  q2 = wd(7, 0, (14 - j | 0) * 3 | 0) | 0;
                  j = j + 1 | 0;
                  g2 = q2 | g2;
                  i = H() | 0 | i;
                } while ((j | 0) < (s2 | 0));
                q2 = g2;
              } else {
                q2 = g2;
              }
            } else {
              q2 = a2;
              i = c2;
            }
            p2 = vd(q2 | 0, i | 0, 45) | 0;
            H() | 0;
            a: do {
              if (ma(p2 & 127) | 0) {
                j = vd(q2 | 0, i | 0, 52) | 0;
                H() | 0;
                j = j & 15;
                if (j | 0) {
                  g2 = 1;
                  while (1) {
                    p2 = wd(7, 0, (15 - g2 | 0) * 3 | 0) | 0;
                    if (!((p2 & q2 | 0) == 0 & ((H() | 0) & i | 0) == 0)) {
                      k = 33;
                      break a;
                    }
                    if (g2 >>> 0 < j >>> 0) {
                      g2 = g2 + 1 | 0;
                    } else {
                      break;
                    }
                  }
                }
                p2 = e2;
                b[p2 >> 2] = 0;
                b[p2 + 4 >> 2] = 0;
                if ((s2 | 0) > (d2 | 0)) {
                  p2 = c2 & -15728641;
                  o = s2;
                  while (1) {
                    n = o;
                    o = o + -1 | 0;
                    if (o >>> 0 > 15 | (s2 | 0) < (o | 0)) {
                      k = 19;
                      break;
                    }
                    if ((s2 | 0) != (o | 0)) {
                      g2 = wd(o | 0, 0, 52) | 0;
                      g2 = g2 | a2;
                      j = H() | 0 | p2;
                      if ((s2 | 0) < (n | 0)) {
                        m = g2;
                      } else {
                        k = o;
                        do {
                          m = wd(7, 0, (14 - k | 0) * 3 | 0) | 0;
                          k = k + 1 | 0;
                          g2 = m | g2;
                          j = H() | 0 | j;
                        } while ((k | 0) < (s2 | 0));
                        m = g2;
                      }
                    } else {
                      m = a2;
                      j = c2;
                    }
                    l = vd(m | 0, j | 0, 45) | 0;
                    H() | 0;
                    if (!(ma(l & 127) | 0)) {
                      g2 = 0;
                    } else {
                      l = vd(m | 0, j | 0, 52) | 0;
                      H() | 0;
                      l = l & 15;
                      b: do {
                        if (!l) {
                          g2 = 0;
                        } else {
                          k = 1;
                          while (1) {
                            g2 = vd(m | 0, j | 0, (15 - k | 0) * 3 | 0) | 0;
                            H() | 0;
                            g2 = g2 & 7;
                            if (g2 | 0) {
                              break b;
                            }
                            if (k >>> 0 < l >>> 0) {
                              k = k + 1 | 0;
                            } else {
                              g2 = 0;
                              break;
                            }
                          }
                        }
                      } while (0);
                      g2 = (g2 | 0) == 0 & 1;
                    }
                    j = vd(a2 | 0, c2 | 0, (15 - n | 0) * 3 | 0) | 0;
                    H() | 0;
                    j = j & 7;
                    if ((j | 0) == 7) {
                      f2 = 5;
                      k = 42;
                      break;
                    }
                    g2 = (g2 | 0) != 0;
                    if ((j | 0) == 1 & g2) {
                      f2 = 5;
                      k = 42;
                      break;
                    }
                    m = j + (((j | 0) != 0 & g2) << 31 >> 31) | 0;
                    if (m | 0) {
                      k = s2 - n | 0;
                      k = Cc(7, 0, k, ((k | 0) < 0) << 31 >> 31) | 0;
                      l = H() | 0;
                      if (g2) {
                        g2 = rd(k | 0, l | 0, 5, 0) | 0;
                        g2 = ld(g2 | 0, H() | 0, -5, -1) | 0;
                        g2 = pd(g2 | 0, H() | 0, 6, 0) | 0;
                        g2 = ld(g2 | 0, H() | 0, 1, 0) | 0;
                        j = H() | 0;
                      } else {
                        g2 = k;
                        j = l;
                      }
                      n = m + -1 | 0;
                      n = rd(k | 0, l | 0, n | 0, ((n | 0) < 0) << 31 >> 31 | 0) | 0;
                      n = ld(g2 | 0, j | 0, n | 0, H() | 0) | 0;
                      m = H() | 0;
                      l = e2;
                      l = ld(n | 0, m | 0, b[l >> 2] | 0, b[l + 4 >> 2] | 0) | 0;
                      m = H() | 0;
                      n = e2;
                      b[n >> 2] = l;
                      b[n + 4 >> 2] = m;
                    }
                    if ((o | 0) <= (d2 | 0)) {
                      k = 37;
                      break;
                    }
                  }
                  if ((k | 0) == 19) {
                    I(23313, 22674, 1099, 22710);
                  } else if ((k | 0) == 37) {
                    h = e2;
                    f2 = b[h + 4 >> 2] | 0;
                    h = b[h >> 2] | 0;
                    break;
                  } else if ((k | 0) == 42) {
                    T = t2;
                    return f2 | 0;
                  }
                } else {
                  f2 = 0;
                  h = 0;
                }
              } else {
                k = 33;
              }
            } while (0);
            c: do {
              if ((k | 0) == 33) {
                p2 = e2;
                b[p2 >> 2] = 0;
                b[p2 + 4 >> 2] = 0;
                if ((s2 | 0) > (d2 | 0)) {
                  g2 = s2;
                  while (1) {
                    f2 = vd(a2 | 0, c2 | 0, (15 - g2 | 0) * 3 | 0) | 0;
                    H() | 0;
                    f2 = f2 & 7;
                    if ((f2 | 0) == 7) {
                      f2 = 5;
                      break;
                    }
                    h = s2 - g2 | 0;
                    h = Cc(7, 0, h, ((h | 0) < 0) << 31 >> 31) | 0;
                    f2 = rd(h | 0, H() | 0, f2 | 0, 0) | 0;
                    h = H() | 0;
                    p2 = e2;
                    h = ld(b[p2 >> 2] | 0, b[p2 + 4 >> 2] | 0, f2 | 0, h | 0) | 0;
                    f2 = H() | 0;
                    p2 = e2;
                    b[p2 >> 2] = h;
                    b[p2 + 4 >> 2] = f2;
                    g2 = g2 + -1 | 0;
                    if ((g2 | 0) <= (d2 | 0)) {
                      break c;
                    }
                  }
                  T = t2;
                  return f2 | 0;
                } else {
                  f2 = 0;
                  h = 0;
                }
              }
            } while (0);
            if (wb(q2, i, s2, r2) | 0) {
              I(23313, 22674, 1063, 22725);
            }
            s2 = r2;
            r2 = b[s2 + 4 >> 2] | 0;
            if (((f2 | 0) > -1 | (f2 | 0) == -1 & h >>> 0 > 4294967295) & ((r2 | 0) > (f2 | 0) | ((r2 | 0) == (f2 | 0) ? (b[s2 >> 2] | 0) >>> 0 > h >>> 0 : 0))) {
              s2 = 0;
              T = t2;
              return s2 | 0;
            } else {
              I(23313, 22674, 1139, 22710);
            }
            return 0;
          }
          function Wb(a2, c2, d2, e2, f2, g2) {
            a2 = a2 | 0;
            c2 = c2 | 0;
            d2 = d2 | 0;
            e2 = e2 | 0;
            f2 = f2 | 0;
            g2 = g2 | 0;
            var h = 0, i = 0, j = 0, k = 0, l = 0, m = 0, n = 0, o = 0, p2 = 0, q2 = 0;
            m = T;
            T = T + 16 | 0;
            h = m;
            if (f2 >>> 0 > 15) {
              g2 = 4;
              T = m;
              return g2 | 0;
            }
            i = vd(d2 | 0, e2 | 0, 52) | 0;
            H() | 0;
            i = i & 15;
            if ((i | 0) > (f2 | 0)) {
              g2 = 12;
              T = m;
              return g2 | 0;
            }
            if (wb(d2, e2, f2, h) | 0) {
              I(23313, 22674, 1063, 22725);
            }
            l = h;
            k = b[l + 4 >> 2] | 0;
            if (!(((c2 | 0) > -1 | (c2 | 0) == -1 & a2 >>> 0 > 4294967295) & ((k | 0) > (c2 | 0) | ((k | 0) == (c2 | 0) ? (b[l >> 2] | 0) >>> 0 > a2 >>> 0 : 0)))) {
              g2 = 2;
              T = m;
              return g2 | 0;
            }
            l = f2 - i | 0;
            f2 = wd(f2 | 0, 0, 52) | 0;
            j = H() | 0 | e2 & -15728641;
            k = g2;
            b[k >> 2] = f2 | d2;
            b[k + 4 >> 2] = j;
            k = vd(d2 | 0, e2 | 0, 45) | 0;
            H() | 0;
            a: do {
              if (ma(k & 127) | 0) {
                if (i | 0) {
                  h = 1;
                  while (1) {
                    k = wd(7, 0, (15 - h | 0) * 3 | 0) | 0;
                    if (!((k & d2 | 0) == 0 & ((H() | 0) & e2 | 0) == 0)) {
                      break a;
                    }
                    if (h >>> 0 < i >>> 0) {
                      h = h + 1 | 0;
                    } else {
                      break;
                    }
                  }
                }
                if ((l | 0) < 1) {
                  g2 = 0;
                  T = m;
                  return g2 | 0;
                }
                k = i ^ 15;
                e2 = -1;
                j = 1;
                h = 1;
                while (1) {
                  i = l - j | 0;
                  i = Cc(7, 0, i, ((i | 0) < 0) << 31 >> 31) | 0;
                  d2 = H() | 0;
                  do {
                    if (h) {
                      h = rd(i | 0, d2 | 0, 5, 0) | 0;
                      h = ld(h | 0, H() | 0, -5, -1) | 0;
                      h = pd(h | 0, H() | 0, 6, 0) | 0;
                      f2 = H() | 0;
                      if ((c2 | 0) > (f2 | 0) | (c2 | 0) == (f2 | 0) & a2 >>> 0 > h >>> 0) {
                        c2 = ld(a2 | 0, c2 | 0, -1, -1) | 0;
                        c2 = md(c2 | 0, H() | 0, h | 0, f2 | 0) | 0;
                        h = H() | 0;
                        n = g2;
                        p2 = b[n >> 2] | 0;
                        n = b[n + 4 >> 2] | 0;
                        q2 = (k + e2 | 0) * 3 | 0;
                        o = wd(7, 0, q2 | 0) | 0;
                        n = n & ~(H() | 0);
                        e2 = pd(c2 | 0, h | 0, i | 0, d2 | 0) | 0;
                        a2 = H() | 0;
                        f2 = ld(e2 | 0, a2 | 0, 2, 0) | 0;
                        q2 = wd(f2 | 0, H() | 0, q2 | 0) | 0;
                        n = H() | 0 | n;
                        f2 = g2;
                        b[f2 >> 2] = q2 | p2 & ~o;
                        b[f2 + 4 >> 2] = n;
                        a2 = rd(e2 | 0, a2 | 0, i | 0, d2 | 0) | 0;
                        a2 = md(c2 | 0, h | 0, a2 | 0, H() | 0) | 0;
                        h = 0;
                        c2 = H() | 0;
                        break;
                      } else {
                        q2 = g2;
                        o = b[q2 >> 2] | 0;
                        q2 = b[q2 + 4 >> 2] | 0;
                        p2 = wd(7, 0, (k + e2 | 0) * 3 | 0) | 0;
                        q2 = q2 & ~(H() | 0);
                        h = g2;
                        b[h >> 2] = o & ~p2;
                        b[h + 4 >> 2] = q2;
                        h = 1;
                        break;
                      }
                    } else {
                      o = g2;
                      f2 = b[o >> 2] | 0;
                      o = b[o + 4 >> 2] | 0;
                      e2 = (k + e2 | 0) * 3 | 0;
                      n = wd(7, 0, e2 | 0) | 0;
                      o = o & ~(H() | 0);
                      q2 = pd(a2 | 0, c2 | 0, i | 0, d2 | 0) | 0;
                      h = H() | 0;
                      e2 = wd(q2 | 0, h | 0, e2 | 0) | 0;
                      o = H() | 0 | o;
                      p2 = g2;
                      b[p2 >> 2] = e2 | f2 & ~n;
                      b[p2 + 4 >> 2] = o;
                      h = rd(q2 | 0, h | 0, i | 0, d2 | 0) | 0;
                      a2 = md(a2 | 0, c2 | 0, h | 0, H() | 0) | 0;
                      h = 0;
                      c2 = H() | 0;
                    }
                  } while (0);
                  if ((l | 0) > (j | 0)) {
                    e2 = ~j;
                    j = j + 1 | 0;
                  } else {
                    c2 = 0;
                    break;
                  }
                }
                T = m;
                return c2 | 0;
              }
            } while (0);
            if ((l | 0) < 1) {
              q2 = 0;
              T = m;
              return q2 | 0;
            }
            f2 = i ^ 15;
            h = 1;
            while (1) {
              p2 = l - h | 0;
              p2 = Cc(7, 0, p2, ((p2 | 0) < 0) << 31 >> 31) | 0;
              q2 = H() | 0;
              j = g2;
              d2 = b[j >> 2] | 0;
              j = b[j + 4 >> 2] | 0;
              i = (f2 - h | 0) * 3 | 0;
              e2 = wd(7, 0, i | 0) | 0;
              j = j & ~(H() | 0);
              n = pd(a2 | 0, c2 | 0, p2 | 0, q2 | 0) | 0;
              o = H() | 0;
              i = wd(n | 0, o | 0, i | 0) | 0;
              j = H() | 0 | j;
              k = g2;
              b[k >> 2] = i | d2 & ~e2;
              b[k + 4 >> 2] = j;
              q2 = rd(n | 0, o | 0, p2 | 0, q2 | 0) | 0;
              a2 = md(a2 | 0, c2 | 0, q2 | 0, H() | 0) | 0;
              c2 = H() | 0;
              if ((l | 0) <= (h | 0)) {
                c2 = 0;
                break;
              } else {
                h = h + 1 | 0;
              }
            }
            T = m;
            return c2 | 0;
          }
          function Xb(a2, c2, d2, e2) {
            a2 = a2 | 0;
            c2 = c2 | 0;
            d2 = d2 | 0;
            e2 = e2 | 0;
            var f2 = 0, g2 = 0;
            f2 = vd(c2 | 0, d2 | 0, 52) | 0;
            H() | 0;
            f2 = f2 & 15;
            if ((c2 | 0) == 0 & (d2 | 0) == 0 | ((e2 | 0) > 15 | (f2 | 0) > (e2 | 0))) {
              e2 = -1;
              f2 = -1;
              c2 = 0;
              d2 = 0;
            } else {
              g2 = zb(c2, d2, f2 + 1 | 0, e2) | 0;
              d2 = (H() | 0) & -15728641;
              c2 = wd(e2 | 0, 0, 52) | 0;
              c2 = g2 | c2;
              d2 = d2 | (H() | 0);
              g2 = (xb(c2, d2) | 0) == 0;
              e2 = g2 ? -1 : e2;
            }
            g2 = a2;
            b[g2 >> 2] = c2;
            b[g2 + 4 >> 2] = d2;
            b[a2 + 8 >> 2] = f2;
            b[a2 + 12 >> 2] = e2;
            return;
          }
          function Yb(a2) {
            a2 = a2 | 0;
            var c2 = 0, d2 = 0, e2 = 0, f2 = 0, g2 = 0, h = 0, i = 0, j = 0, k = 0;
            d2 = a2;
            c2 = b[d2 >> 2] | 0;
            d2 = b[d2 + 4 >> 2] | 0;
            if ((c2 | 0) == 0 & (d2 | 0) == 0) {
              return;
            }
            e2 = vd(c2 | 0, d2 | 0, 52) | 0;
            H() | 0;
            e2 = e2 & 15;
            i = wd(1, 0, (e2 ^ 15) * 3 | 0) | 0;
            c2 = ld(i | 0, H() | 0, c2 | 0, d2 | 0) | 0;
            d2 = H() | 0;
            i = a2;
            b[i >> 2] = c2;
            b[i + 4 >> 2] = d2;
            i = a2 + 8 | 0;
            h = b[i >> 2] | 0;
            if ((e2 | 0) < (h | 0)) {
              return;
            }
            j = a2 + 12 | 0;
            g2 = e2;
            while (1) {
              if ((g2 | 0) == (h | 0)) {
                e2 = 5;
                break;
              }
              k = (g2 | 0) == (b[j >> 2] | 0);
              f2 = (15 - g2 | 0) * 3 | 0;
              e2 = vd(c2 | 0, d2 | 0, f2 | 0) | 0;
              H() | 0;
              e2 = e2 & 7;
              if (k & ((e2 | 0) == 1 & true)) {
                e2 = 7;
                break;
              }
              if (!((e2 | 0) == 7 & true)) {
                e2 = 10;
                break;
              }
              k = wd(1, 0, f2 | 0) | 0;
              c2 = ld(c2 | 0, d2 | 0, k | 0, H() | 0) | 0;
              d2 = H() | 0;
              k = a2;
              b[k >> 2] = c2;
              b[k + 4 >> 2] = d2;
              if ((g2 | 0) > (h | 0)) {
                g2 = g2 + -1 | 0;
              } else {
                e2 = 10;
                break;
              }
            }
            if ((e2 | 0) == 5) {
              k = a2;
              b[k >> 2] = 0;
              b[k + 4 >> 2] = 0;
              b[i >> 2] = -1;
              b[j >> 2] = -1;
              return;
            } else if ((e2 | 0) == 7) {
              h = wd(1, 0, f2 | 0) | 0;
              h = ld(c2 | 0, d2 | 0, h | 0, H() | 0) | 0;
              i = H() | 0;
              k = a2;
              b[k >> 2] = h;
              b[k + 4 >> 2] = i;
              b[j >> 2] = g2 + -1;
              return;
            } else if ((e2 | 0) == 10) {
              return;
            }
          }
          function Zb(a2) {
            a2 = +a2;
            var b2 = 0;
            b2 = a2 < 0 ? a2 + 6.283185307179586 : a2;
            return +(!(a2 >= 6.283185307179586) ? b2 : b2 + -6.283185307179586);
          }
          function _b(a2, b2) {
            a2 = a2 | 0;
            b2 = b2 | 0;
            if (!(+q(+(+e[a2 >> 3] - +e[b2 >> 3])) < 17453292519943298e-27)) {
              b2 = 0;
              return b2 | 0;
            }
            b2 = +q(+(+e[a2 + 8 >> 3] - +e[b2 + 8 >> 3])) < 17453292519943298e-27;
            return b2 | 0;
          }
          function $b(a2, b2) {
            a2 = a2 | 0;
            b2 = b2 | 0;
            var c2 = 0, d2 = 0, f2 = 0, g2 = 0;
            f2 = +e[b2 >> 3];
            d2 = +e[a2 >> 3];
            g2 = +u(+((f2 - d2) * 0.5));
            c2 = +u(+((+e[b2 + 8 >> 3] - +e[a2 + 8 >> 3]) * 0.5));
            c2 = g2 * g2 + c2 * (+t(+f2) * +t(+d2) * c2);
            return +(+z(+ +r(+c2), + +r(+(1 - c2))) * 2);
          }
          function ac(a2, b2) {
            a2 = a2 | 0;
            b2 = b2 | 0;
            var c2 = 0, d2 = 0, f2 = 0, g2 = 0;
            f2 = +e[b2 >> 3];
            d2 = +e[a2 >> 3];
            g2 = +u(+((f2 - d2) * 0.5));
            c2 = +u(+((+e[b2 + 8 >> 3] - +e[a2 + 8 >> 3]) * 0.5));
            c2 = g2 * g2 + c2 * (+t(+f2) * +t(+d2) * c2);
            return +(+z(+ +r(+c2), + +r(+(1 - c2))) * 2 * 6371.007180918475);
          }
          function bc(a2, b2) {
            a2 = a2 | 0;
            b2 = b2 | 0;
            var c2 = 0, d2 = 0, f2 = 0, g2 = 0;
            f2 = +e[b2 >> 3];
            d2 = +e[a2 >> 3];
            g2 = +u(+((f2 - d2) * 0.5));
            c2 = +u(+((+e[b2 + 8 >> 3] - +e[a2 + 8 >> 3]) * 0.5));
            c2 = g2 * g2 + c2 * (+t(+f2) * +t(+d2) * c2);
            return +(+z(+ +r(+c2), + +r(+(1 - c2))) * 2 * 6371.007180918475 * 1e3);
          }
          function cc(a2, b2) {
            a2 = a2 | 0;
            b2 = b2 | 0;
            var c2 = 0, d2 = 0, f2 = 0, g2 = 0, h = 0;
            g2 = +e[b2 >> 3];
            d2 = +t(+g2);
            f2 = +e[b2 + 8 >> 3] - +e[a2 + 8 >> 3];
            h = d2 * +u(+f2);
            c2 = +e[a2 >> 3];
            return + +z(+h, +(+u(+g2) * +t(+c2) - +t(+f2) * (d2 * +u(+c2))));
          }
          function dc(a2, c2, d2, f2) {
            a2 = a2 | 0;
            c2 = +c2;
            d2 = +d2;
            f2 = f2 | 0;
            var g2 = 0, h = 0, i = 0, j = 0;
            if (d2 < 1e-16) {
              b[f2 >> 2] = b[a2 >> 2];
              b[f2 + 4 >> 2] = b[a2 + 4 >> 2];
              b[f2 + 8 >> 2] = b[a2 + 8 >> 2];
              b[f2 + 12 >> 2] = b[a2 + 12 >> 2];
              return;
            }
            h = c2 < 0 ? c2 + 6.283185307179586 : c2;
            h = !(c2 >= 6.283185307179586) ? h : h + -6.283185307179586;
            do {
              if (h < 1e-16) {
                c2 = +e[a2 >> 3] + d2;
                e[f2 >> 3] = c2;
                g2 = f2;
              } else {
                g2 = +q(+(h + -3.141592653589793)) < 1e-16;
                c2 = +e[a2 >> 3];
                if (g2) {
                  c2 = c2 - d2;
                  e[f2 >> 3] = c2;
                  g2 = f2;
                  break;
                }
                i = +t(+d2);
                d2 = +u(+d2);
                c2 = i * +u(+c2) + +t(+h) * (d2 * +t(+c2));
                c2 = c2 > 1 ? 1 : c2;
                c2 = +x(+(c2 < -1 ? -1 : c2));
                e[f2 >> 3] = c2;
                if (+q(+(c2 + -1.5707963267948966)) < 1e-16) {
                  e[f2 >> 3] = 1.5707963267948966;
                  e[f2 + 8 >> 3] = 0;
                  return;
                }
                if (+q(+(c2 + 1.5707963267948966)) < 1e-16) {
                  e[f2 >> 3] = -1.5707963267948966;
                  e[f2 + 8 >> 3] = 0;
                  return;
                }
                j = +t(+c2);
                h = d2 * +u(+h) / j;
                d2 = +e[a2 >> 3];
                c2 = (i - +u(+c2) * +u(+d2)) / +t(+d2) / j;
                i = h > 1 ? 1 : h;
                c2 = c2 > 1 ? 1 : c2;
                c2 = +e[a2 + 8 >> 3] + +z(+(i < -1 ? -1 : i), +(c2 < -1 ? -1 : c2));
                if (c2 > 3.141592653589793) {
                  do {
                    c2 = c2 + -6.283185307179586;
                  } while (c2 > 3.141592653589793);
                }
                if (c2 < -3.141592653589793) {
                  do {
                    c2 = c2 + 6.283185307179586;
                  } while (c2 < -3.141592653589793);
                }
                e[f2 + 8 >> 3] = c2;
                return;
              }
            } while (0);
            if (+q(+(c2 + -1.5707963267948966)) < 1e-16) {
              e[g2 >> 3] = 1.5707963267948966;
              e[f2 + 8 >> 3] = 0;
              return;
            }
            if (+q(+(c2 + 1.5707963267948966)) < 1e-16) {
              e[g2 >> 3] = -1.5707963267948966;
              e[f2 + 8 >> 3] = 0;
              return;
            }
            c2 = +e[a2 + 8 >> 3];
            if (c2 > 3.141592653589793) {
              do {
                c2 = c2 + -6.283185307179586;
              } while (c2 > 3.141592653589793);
            }
            if (c2 < -3.141592653589793) {
              do {
                c2 = c2 + 6.283185307179586;
              } while (c2 < -3.141592653589793);
            }
            e[f2 + 8 >> 3] = c2;
            return;
          }
          function ec(a2, b2) {
            a2 = a2 | 0;
            b2 = b2 | 0;
            if (a2 >>> 0 > 15) {
              b2 = 4;
              return b2 | 0;
            }
            e[b2 >> 3] = +e[20528 + (a2 << 3) >> 3];
            b2 = 0;
            return b2 | 0;
          }
          function fc(a2, b2) {
            a2 = a2 | 0;
            b2 = b2 | 0;
            if (a2 >>> 0 > 15) {
              b2 = 4;
              return b2 | 0;
            }
            e[b2 >> 3] = +e[20656 + (a2 << 3) >> 3];
            b2 = 0;
            return b2 | 0;
          }
          function gc(a2, b2) {
            a2 = a2 | 0;
            b2 = b2 | 0;
            if (a2 >>> 0 > 15) {
              b2 = 4;
              return b2 | 0;
            }
            e[b2 >> 3] = +e[20784 + (a2 << 3) >> 3];
            b2 = 0;
            return b2 | 0;
          }
          function hc(a2, b2) {
            a2 = a2 | 0;
            b2 = b2 | 0;
            if (a2 >>> 0 > 15) {
              b2 = 4;
              return b2 | 0;
            }
            e[b2 >> 3] = +e[20912 + (a2 << 3) >> 3];
            b2 = 0;
            return b2 | 0;
          }
          function ic(a2, c2) {
            a2 = a2 | 0;
            c2 = c2 | 0;
            var d2 = 0;
            if (a2 >>> 0 > 15) {
              c2 = 4;
              return c2 | 0;
            }
            d2 = Cc(7, 0, a2, ((a2 | 0) < 0) << 31 >> 31) | 0;
            d2 = rd(d2 | 0, H() | 0, 120, 0) | 0;
            a2 = H() | 0;
            b[c2 >> 2] = d2 | 2;
            b[c2 + 4 >> 2] = a2;
            c2 = 0;
            return c2 | 0;
          }
          function jc(a2, b2, c2) {
            a2 = a2 | 0;
            b2 = b2 | 0;
            c2 = c2 | 0;
            var d2 = 0, f2 = 0, g2 = 0, h = 0, i = 0, j = 0, k = 0, l = 0, m = 0, n = 0;
            n = +e[b2 >> 3];
            l = +e[a2 >> 3];
            j = +u(+((n - l) * 0.5));
            g2 = +e[b2 + 8 >> 3];
            k = +e[a2 + 8 >> 3];
            h = +u(+((g2 - k) * 0.5));
            i = +t(+l);
            m = +t(+n);
            h = j * j + h * (m * i * h);
            h = +z(+ +r(+h), + +r(+(1 - h))) * 2;
            j = +e[c2 >> 3];
            n = +u(+((j - n) * 0.5));
            d2 = +e[c2 + 8 >> 3];
            g2 = +u(+((d2 - g2) * 0.5));
            f2 = +t(+j);
            g2 = n * n + g2 * (m * f2 * g2);
            g2 = +z(+ +r(+g2), + +r(+(1 - g2))) * 2;
            j = +u(+((l - j) * 0.5));
            d2 = +u(+((k - d2) * 0.5));
            d2 = j * j + d2 * (i * f2 * d2);
            d2 = +z(+ +r(+d2), + +r(+(1 - d2))) * 2;
            f2 = (h + g2 + d2) * 0.5;
            return +(+y(+ +r(+(+v(+(f2 * 0.5)) * +v(+((f2 - h) * 0.5)) * +v(+((f2 - g2) * 0.5)) * +v(+((f2 - d2) * 0.5))))) * 4);
          }
          function kc(a2, c2, d2) {
            a2 = a2 | 0;
            c2 = c2 | 0;
            d2 = d2 | 0;
            var f2 = 0, g2 = 0, h = 0, i = 0, j = 0;
            j = T;
            T = T + 192 | 0;
            h = j + 168 | 0;
            i = j;
            g2 = Pb(a2, c2, h) | 0;
            if (g2 | 0) {
              d2 = g2;
              T = j;
              return d2 | 0;
            }
            if (Qb(a2, c2, i) | 0) {
              I(23313, 22742, 386, 22751);
            }
            c2 = b[i >> 2] | 0;
            if ((c2 | 0) > 0) {
              f2 = +jc(i + 8 | 0, i + 8 + (((c2 | 0) != 1 & 1) << 4) | 0, h) + 0;
              if ((c2 | 0) != 1) {
                a2 = 1;
                do {
                  g2 = a2;
                  a2 = a2 + 1 | 0;
                  f2 = f2 + +jc(i + 8 + (g2 << 4) | 0, i + 8 + (((a2 | 0) % (c2 | 0) | 0) << 4) | 0, h);
                } while ((a2 | 0) < (c2 | 0));
              }
            } else {
              f2 = 0;
            }
            e[d2 >> 3] = f2;
            d2 = 0;
            T = j;
            return d2 | 0;
          }
          function lc(a2, b2, c2) {
            a2 = a2 | 0;
            b2 = b2 | 0;
            c2 = c2 | 0;
            a2 = kc(a2, b2, c2) | 0;
            if (a2 | 0) {
              return a2 | 0;
            }
            e[c2 >> 3] = +e[c2 >> 3] * 6371.007180918475 * 6371.007180918475;
            return a2 | 0;
          }
          function mc(a2, b2, c2) {
            a2 = a2 | 0;
            b2 = b2 | 0;
            c2 = c2 | 0;
            a2 = kc(a2, b2, c2) | 0;
            if (a2 | 0) {
              return a2 | 0;
            }
            e[c2 >> 3] = +e[c2 >> 3] * 6371.007180918475 * 6371.007180918475 * 1e3 * 1e3;
            return a2 | 0;
          }
          function nc(a2, c2, d2) {
            a2 = a2 | 0;
            c2 = c2 | 0;
            d2 = d2 | 0;
            var f2 = 0, g2 = 0, h = 0, i = 0, j = 0, k = 0, l = 0, m = 0;
            j = T;
            T = T + 176 | 0;
            i = j;
            a2 = gb(a2, c2, i) | 0;
            if (a2 | 0) {
              i = a2;
              T = j;
              return i | 0;
            }
            e[d2 >> 3] = 0;
            a2 = b[i >> 2] | 0;
            if ((a2 | 0) <= 1) {
              i = 0;
              T = j;
              return i | 0;
            }
            c2 = a2 + -1 | 0;
            a2 = 0;
            f2 = +e[i + 8 >> 3];
            g2 = +e[i + 16 >> 3];
            h = 0;
            do {
              a2 = a2 + 1 | 0;
              l = f2;
              f2 = +e[i + 8 + (a2 << 4) >> 3];
              m = +u(+((f2 - l) * 0.5));
              k = g2;
              g2 = +e[i + 8 + (a2 << 4) + 8 >> 3];
              k = +u(+((g2 - k) * 0.5));
              k = m * m + k * (+t(+f2) * +t(+l) * k);
              h = h + +z(+ +r(+k), + +r(+(1 - k))) * 2;
            } while ((a2 | 0) < (c2 | 0));
            e[d2 >> 3] = h;
            i = 0;
            T = j;
            return i | 0;
          }
          function oc(a2, c2, d2) {
            a2 = a2 | 0;
            c2 = c2 | 0;
            d2 = d2 | 0;
            var f2 = 0, g2 = 0, h = 0, i = 0, j = 0, k = 0, l = 0, m = 0;
            j = T;
            T = T + 176 | 0;
            i = j;
            a2 = gb(a2, c2, i) | 0;
            if (a2 | 0) {
              i = a2;
              h = +e[d2 >> 3];
              h = h * 6371.007180918475;
              e[d2 >> 3] = h;
              T = j;
              return i | 0;
            }
            e[d2 >> 3] = 0;
            a2 = b[i >> 2] | 0;
            if ((a2 | 0) <= 1) {
              i = 0;
              h = 0;
              h = h * 6371.007180918475;
              e[d2 >> 3] = h;
              T = j;
              return i | 0;
            }
            c2 = a2 + -1 | 0;
            a2 = 0;
            f2 = +e[i + 8 >> 3];
            g2 = +e[i + 16 >> 3];
            h = 0;
            do {
              a2 = a2 + 1 | 0;
              l = f2;
              f2 = +e[i + 8 + (a2 << 4) >> 3];
              m = +u(+((f2 - l) * 0.5));
              k = g2;
              g2 = +e[i + 8 + (a2 << 4) + 8 >> 3];
              k = +u(+((g2 - k) * 0.5));
              k = m * m + k * (+t(+l) * +t(+f2) * k);
              h = h + +z(+ +r(+k), + +r(+(1 - k))) * 2;
            } while ((a2 | 0) != (c2 | 0));
            e[d2 >> 3] = h;
            i = 0;
            m = h;
            m = m * 6371.007180918475;
            e[d2 >> 3] = m;
            T = j;
            return i | 0;
          }
          function pc(a2, c2, d2) {
            a2 = a2 | 0;
            c2 = c2 | 0;
            d2 = d2 | 0;
            var f2 = 0, g2 = 0, h = 0, i = 0, j = 0, k = 0, l = 0, m = 0;
            j = T;
            T = T + 176 | 0;
            i = j;
            a2 = gb(a2, c2, i) | 0;
            if (a2 | 0) {
              i = a2;
              h = +e[d2 >> 3];
              h = h * 6371.007180918475;
              h = h * 1e3;
              e[d2 >> 3] = h;
              T = j;
              return i | 0;
            }
            e[d2 >> 3] = 0;
            a2 = b[i >> 2] | 0;
            if ((a2 | 0) <= 1) {
              i = 0;
              h = 0;
              h = h * 6371.007180918475;
              h = h * 1e3;
              e[d2 >> 3] = h;
              T = j;
              return i | 0;
            }
            c2 = a2 + -1 | 0;
            a2 = 0;
            f2 = +e[i + 8 >> 3];
            g2 = +e[i + 16 >> 3];
            h = 0;
            do {
              a2 = a2 + 1 | 0;
              l = f2;
              f2 = +e[i + 8 + (a2 << 4) >> 3];
              m = +u(+((f2 - l) * 0.5));
              k = g2;
              g2 = +e[i + 8 + (a2 << 4) + 8 >> 3];
              k = +u(+((g2 - k) * 0.5));
              k = m * m + k * (+t(+l) * +t(+f2) * k);
              h = h + +z(+ +r(+k), + +r(+(1 - k))) * 2;
            } while ((a2 | 0) != (c2 | 0));
            e[d2 >> 3] = h;
            i = 0;
            m = h;
            m = m * 6371.007180918475;
            m = m * 1e3;
            e[d2 >> 3] = m;
            T = j;
            return i | 0;
          }
          function qc(a2) {
            a2 = a2 | 0;
            var c2 = 0, d2 = 0, e2 = 0;
            c2 = kd(1, 12) | 0;
            if (!c2) {
              I(22832, 22787, 49, 22845);
            }
            d2 = a2 + 4 | 0;
            e2 = b[d2 >> 2] | 0;
            if (e2 | 0) {
              e2 = e2 + 8 | 0;
              b[e2 >> 2] = c2;
              b[d2 >> 2] = c2;
              return c2 | 0;
            }
            if (b[a2 >> 2] | 0) {
              I(22862, 22787, 61, 22885);
            }
            e2 = a2;
            b[e2 >> 2] = c2;
            b[d2 >> 2] = c2;
            return c2 | 0;
          }
          function rc(a2, c2) {
            a2 = a2 | 0;
            c2 = c2 | 0;
            var d2 = 0, e2 = 0;
            e2 = id(24) | 0;
            if (!e2) {
              I(22899, 22787, 78, 22913);
            }
            b[e2 >> 2] = b[c2 >> 2];
            b[e2 + 4 >> 2] = b[c2 + 4 >> 2];
            b[e2 + 8 >> 2] = b[c2 + 8 >> 2];
            b[e2 + 12 >> 2] = b[c2 + 12 >> 2];
            b[e2 + 16 >> 2] = 0;
            c2 = a2 + 4 | 0;
            d2 = b[c2 >> 2] | 0;
            if (d2 | 0) {
              b[d2 + 16 >> 2] = e2;
              b[c2 >> 2] = e2;
              return e2 | 0;
            }
            if (b[a2 >> 2] | 0) {
              I(22928, 22787, 82, 22913);
            }
            b[a2 >> 2] = e2;
            b[c2 >> 2] = e2;
            return e2 | 0;
          }
          function sc(a2) {
            a2 = a2 | 0;
            var c2 = 0, d2 = 0, e2 = 0, f2 = 0;
            if (!a2) {
              return;
            }
            e2 = 1;
            while (1) {
              c2 = b[a2 >> 2] | 0;
              if (c2 | 0) {
                do {
                  d2 = b[c2 >> 2] | 0;
                  if (d2 | 0) {
                    do {
                      f2 = d2;
                      d2 = b[d2 + 16 >> 2] | 0;
                      jd(f2);
                    } while ((d2 | 0) != 0);
                  }
                  f2 = c2;
                  c2 = b[c2 + 8 >> 2] | 0;
                  jd(f2);
                } while ((c2 | 0) != 0);
              }
              c2 = a2;
              a2 = b[a2 + 8 >> 2] | 0;
              if (!e2) {
                jd(c2);
              }
              if (!a2) {
                break;
              } else {
                e2 = 0;
              }
            }
            return;
          }
          function tc(a2) {
            a2 = a2 | 0;
            var c2 = 0, d2 = 0, f2 = 0, g2 = 0, h = 0, i = 0, j = 0, k = 0, l = 0, m = 0, n = 0, o = 0, p2 = 0, r2 = 0, s2 = 0, t2 = 0, u2 = 0, v2 = 0, w2 = 0, x2 = 0, y2 = 0, z2 = 0, A2 = 0, B2 = 0, C2 = 0, D2 = 0, E2 = 0, F = 0, G2 = 0, H2 = 0, J2 = 0, K2 = 0;
            g2 = a2 + 8 | 0;
            if (b[g2 >> 2] | 0) {
              K2 = 1;
              return K2 | 0;
            }
            f2 = b[a2 >> 2] | 0;
            if (!f2) {
              K2 = 0;
              return K2 | 0;
            }
            c2 = f2;
            d2 = 0;
            do {
              d2 = d2 + 1 | 0;
              c2 = b[c2 + 8 >> 2] | 0;
            } while ((c2 | 0) != 0);
            if (d2 >>> 0 < 2) {
              K2 = 0;
              return K2 | 0;
            }
            H2 = id(d2 << 2) | 0;
            if (!H2) {
              I(22948, 22787, 317, 22967);
            }
            G2 = id(d2 << 5) | 0;
            if (!G2) {
              I(22989, 22787, 321, 22967);
            }
            b[a2 >> 2] = 0;
            z2 = a2 + 4 | 0;
            b[z2 >> 2] = 0;
            b[g2 >> 2] = 0;
            d2 = 0;
            F = 0;
            y2 = 0;
            n = 0;
            a: while (1) {
              m = b[f2 >> 2] | 0;
              if (m) {
                h = 0;
                i = m;
                do {
                  k = +e[i + 8 >> 3];
                  c2 = i;
                  i = b[i + 16 >> 2] | 0;
                  l = (i | 0) == 0;
                  g2 = l ? m : i;
                  j = +e[g2 + 8 >> 3];
                  if (+q(+(k - j)) > 3.141592653589793) {
                    K2 = 14;
                    break;
                  }
                  h = h + (j - k) * (+e[c2 >> 3] + +e[g2 >> 3]);
                } while (!l);
                if ((K2 | 0) == 14) {
                  K2 = 0;
                  h = 0;
                  c2 = m;
                  do {
                    x2 = +e[c2 + 8 >> 3];
                    E2 = c2 + 16 | 0;
                    D2 = b[E2 >> 2] | 0;
                    D2 = (D2 | 0) == 0 ? m : D2;
                    w2 = +e[D2 + 8 >> 3];
                    h = h + (+e[c2 >> 3] + +e[D2 >> 3]) * ((w2 < 0 ? w2 + 6.283185307179586 : w2) - (x2 < 0 ? x2 + 6.283185307179586 : x2));
                    c2 = b[((c2 | 0) == 0 ? f2 : E2) >> 2] | 0;
                  } while ((c2 | 0) != 0);
                }
                if (h > 0) {
                  b[H2 + (F << 2) >> 2] = f2;
                  F = F + 1 | 0;
                  g2 = y2;
                  c2 = n;
                } else {
                  K2 = 19;
                }
              } else {
                K2 = 19;
              }
              if ((K2 | 0) == 19) {
                K2 = 0;
                do {
                  if (!d2) {
                    if (!n) {
                      if (!(b[a2 >> 2] | 0)) {
                        g2 = z2;
                        i = a2;
                        c2 = f2;
                        d2 = a2;
                        break;
                      } else {
                        K2 = 27;
                        break a;
                      }
                    } else {
                      g2 = z2;
                      i = n + 8 | 0;
                      c2 = f2;
                      d2 = a2;
                      break;
                    }
                  } else {
                    c2 = d2 + 8 | 0;
                    if (b[c2 >> 2] | 0) {
                      K2 = 21;
                      break a;
                    }
                    d2 = kd(1, 12) | 0;
                    if (!d2) {
                      K2 = 23;
                      break a;
                    }
                    b[c2 >> 2] = d2;
                    g2 = d2 + 4 | 0;
                    i = d2;
                    c2 = n;
                  }
                } while (0);
                b[i >> 2] = f2;
                b[g2 >> 2] = f2;
                i = G2 + (y2 << 5) | 0;
                l = b[f2 >> 2] | 0;
                if (l) {
                  m = G2 + (y2 << 5) + 8 | 0;
                  e[m >> 3] = 17976931348623157e292;
                  n = G2 + (y2 << 5) + 24 | 0;
                  e[n >> 3] = 17976931348623157e292;
                  e[i >> 3] = -17976931348623157e292;
                  o = G2 + (y2 << 5) + 16 | 0;
                  e[o >> 3] = -17976931348623157e292;
                  u2 = 17976931348623157e292;
                  v2 = -17976931348623157e292;
                  g2 = 0;
                  p2 = l;
                  k = 17976931348623157e292;
                  s2 = 17976931348623157e292;
                  t2 = -17976931348623157e292;
                  j = -17976931348623157e292;
                  while (1) {
                    h = +e[p2 >> 3];
                    x2 = +e[p2 + 8 >> 3];
                    p2 = b[p2 + 16 >> 2] | 0;
                    r2 = (p2 | 0) == 0;
                    w2 = +e[(r2 ? l : p2) + 8 >> 3];
                    if (h < k) {
                      e[m >> 3] = h;
                      k = h;
                    }
                    if (x2 < s2) {
                      e[n >> 3] = x2;
                      s2 = x2;
                    }
                    if (h > t2) {
                      e[i >> 3] = h;
                    } else {
                      h = t2;
                    }
                    if (x2 > j) {
                      e[o >> 3] = x2;
                      j = x2;
                    }
                    u2 = x2 > 0 & x2 < u2 ? x2 : u2;
                    v2 = x2 < 0 & x2 > v2 ? x2 : v2;
                    g2 = g2 | +q(+(x2 - w2)) > 3.141592653589793;
                    if (r2) {
                      break;
                    } else {
                      t2 = h;
                    }
                  }
                  if (g2) {
                    e[o >> 3] = v2;
                    e[n >> 3] = u2;
                  }
                } else {
                  b[i >> 2] = 0;
                  b[i + 4 >> 2] = 0;
                  b[i + 8 >> 2] = 0;
                  b[i + 12 >> 2] = 0;
                  b[i + 16 >> 2] = 0;
                  b[i + 20 >> 2] = 0;
                  b[i + 24 >> 2] = 0;
                  b[i + 28 >> 2] = 0;
                }
                g2 = y2 + 1 | 0;
              }
              E2 = f2 + 8 | 0;
              f2 = b[E2 >> 2] | 0;
              b[E2 >> 2] = 0;
              if (!f2) {
                K2 = 45;
                break;
              } else {
                y2 = g2;
                n = c2;
              }
            }
            if ((K2 | 0) == 21) {
              I(22765, 22787, 35, 22799);
            } else if ((K2 | 0) == 23) {
              I(22819, 22787, 37, 22799);
            } else if ((K2 | 0) == 27) {
              I(22862, 22787, 61, 22885);
            } else if ((K2 | 0) == 45) {
              b: do {
                if ((F | 0) > 0) {
                  E2 = (g2 | 0) == 0;
                  C2 = g2 << 2;
                  D2 = (a2 | 0) == 0;
                  B2 = 0;
                  c2 = 0;
                  while (1) {
                    A2 = b[H2 + (B2 << 2) >> 2] | 0;
                    if (!E2) {
                      y2 = id(C2) | 0;
                      if (!y2) {
                        K2 = 50;
                        break;
                      }
                      z2 = id(C2) | 0;
                      if (!z2) {
                        K2 = 52;
                        break;
                      }
                      c: do {
                        if (!D2) {
                          g2 = 0;
                          d2 = 0;
                          i = a2;
                          while (1) {
                            f2 = G2 + (g2 << 5) | 0;
                            if (uc(b[i >> 2] | 0, f2, b[A2 >> 2] | 0) | 0) {
                              b[y2 + (d2 << 2) >> 2] = i;
                              b[z2 + (d2 << 2) >> 2] = f2;
                              r2 = d2 + 1 | 0;
                            } else {
                              r2 = d2;
                            }
                            i = b[i + 8 >> 2] | 0;
                            if (!i) {
                              break;
                            } else {
                              g2 = g2 + 1 | 0;
                              d2 = r2;
                            }
                          }
                          if ((r2 | 0) > 0) {
                            f2 = b[y2 >> 2] | 0;
                            if ((r2 | 0) == 1) {
                              d2 = f2;
                            } else {
                              o = 0;
                              p2 = -1;
                              d2 = f2;
                              n = f2;
                              while (1) {
                                l = b[n >> 2] | 0;
                                f2 = 0;
                                i = 0;
                                while (1) {
                                  g2 = b[b[y2 + (i << 2) >> 2] >> 2] | 0;
                                  if ((g2 | 0) == (l | 0)) {
                                    m = f2;
                                  } else {
                                    m = f2 + ((uc(g2, b[z2 + (i << 2) >> 2] | 0, b[l >> 2] | 0) | 0) & 1) | 0;
                                  }
                                  i = i + 1 | 0;
                                  if ((i | 0) == (r2 | 0)) {
                                    break;
                                  } else {
                                    f2 = m;
                                  }
                                }
                                g2 = (m | 0) > (p2 | 0);
                                d2 = g2 ? n : d2;
                                f2 = o + 1 | 0;
                                if ((f2 | 0) == (r2 | 0)) {
                                  break c;
                                }
                                o = f2;
                                p2 = g2 ? m : p2;
                                n = b[y2 + (f2 << 2) >> 2] | 0;
                              }
                            }
                          } else {
                            d2 = 0;
                          }
                        } else {
                          d2 = 0;
                        }
                      } while (0);
                      jd(y2);
                      jd(z2);
                      if (d2) {
                        g2 = d2 + 4 | 0;
                        f2 = b[g2 >> 2] | 0;
                        if (!f2) {
                          if (b[d2 >> 2] | 0) {
                            K2 = 70;
                            break;
                          }
                        } else {
                          d2 = f2 + 8 | 0;
                        }
                        b[d2 >> 2] = A2;
                        b[g2 >> 2] = A2;
                      } else {
                        K2 = 73;
                      }
                    } else {
                      K2 = 73;
                    }
                    if ((K2 | 0) == 73) {
                      K2 = 0;
                      c2 = b[A2 >> 2] | 0;
                      if (c2 | 0) {
                        do {
                          z2 = c2;
                          c2 = b[c2 + 16 >> 2] | 0;
                          jd(z2);
                        } while ((c2 | 0) != 0);
                      }
                      jd(A2);
                      c2 = 1;
                    }
                    B2 = B2 + 1 | 0;
                    if ((B2 | 0) >= (F | 0)) {
                      J2 = c2;
                      break b;
                    }
                  }
                  if ((K2 | 0) == 50) {
                    I(23004, 22787, 249, 23023);
                  } else if ((K2 | 0) == 52) {
                    I(23042, 22787, 252, 23023);
                  } else if ((K2 | 0) == 70) {
                    I(22862, 22787, 61, 22885);
                  }
                } else {
                  J2 = 0;
                }
              } while (0);
              jd(H2);
              jd(G2);
              K2 = J2;
              return K2 | 0;
            }
            return 0;
          }
          function uc(a2, c2, d2) {
            a2 = a2 | 0;
            c2 = c2 | 0;
            d2 = d2 | 0;
            var f2 = 0, g2 = 0, h = 0, i = 0, j = 0, k = 0, l = 0, m = 0;
            if (!(ya(c2, d2) | 0)) {
              a2 = 0;
              return a2 | 0;
            }
            c2 = xa(c2) | 0;
            f2 = +e[d2 >> 3];
            g2 = +e[d2 + 8 >> 3];
            g2 = c2 & g2 < 0 ? g2 + 6.283185307179586 : g2;
            a2 = b[a2 >> 2] | 0;
            if (!a2) {
              a2 = 0;
              return a2 | 0;
            }
            if (c2) {
              c2 = 0;
              l = g2;
              d2 = a2;
              a: while (1) {
                while (1) {
                  i = +e[d2 >> 3];
                  g2 = +e[d2 + 8 >> 3];
                  d2 = d2 + 16 | 0;
                  m = b[d2 >> 2] | 0;
                  m = (m | 0) == 0 ? a2 : m;
                  h = +e[m >> 3];
                  j = +e[m + 8 >> 3];
                  if (i > h) {
                    k = i;
                    i = j;
                  } else {
                    k = h;
                    h = i;
                    i = g2;
                    g2 = j;
                  }
                  f2 = f2 == h | f2 == k ? f2 + 2220446049250313e-31 : f2;
                  if (!(f2 < h | f2 > k)) {
                    break;
                  }
                  d2 = b[d2 >> 2] | 0;
                  if (!d2) {
                    d2 = 22;
                    break a;
                  }
                }
                j = i < 0 ? i + 6.283185307179586 : i;
                i = g2 < 0 ? g2 + 6.283185307179586 : g2;
                l = j == l | i == l ? l + -2220446049250313e-31 : l;
                k = j + (i - j) * ((f2 - h) / (k - h));
                if ((k < 0 ? k + 6.283185307179586 : k) > l) {
                  c2 = c2 ^ 1;
                }
                d2 = b[d2 >> 2] | 0;
                if (!d2) {
                  d2 = 22;
                  break;
                }
              }
              if ((d2 | 0) == 22) {
                return c2 | 0;
              }
            } else {
              c2 = 0;
              l = g2;
              d2 = a2;
              b: while (1) {
                while (1) {
                  i = +e[d2 >> 3];
                  g2 = +e[d2 + 8 >> 3];
                  d2 = d2 + 16 | 0;
                  m = b[d2 >> 2] | 0;
                  m = (m | 0) == 0 ? a2 : m;
                  h = +e[m >> 3];
                  j = +e[m + 8 >> 3];
                  if (i > h) {
                    k = i;
                    i = j;
                  } else {
                    k = h;
                    h = i;
                    i = g2;
                    g2 = j;
                  }
                  f2 = f2 == h | f2 == k ? f2 + 2220446049250313e-31 : f2;
                  if (!(f2 < h | f2 > k)) {
                    break;
                  }
                  d2 = b[d2 >> 2] | 0;
                  if (!d2) {
                    d2 = 22;
                    break b;
                  }
                }
                l = i == l | g2 == l ? l + -2220446049250313e-31 : l;
                if (i + (g2 - i) * ((f2 - h) / (k - h)) > l) {
                  c2 = c2 ^ 1;
                }
                d2 = b[d2 >> 2] | 0;
                if (!d2) {
                  d2 = 22;
                  break;
                }
              }
              if ((d2 | 0) == 22) {
                return c2 | 0;
              }
            }
            return 0;
          }
          function vc(c2, d2, e2, f2, g2) {
            c2 = c2 | 0;
            d2 = d2 | 0;
            e2 = e2 | 0;
            f2 = f2 | 0;
            g2 = g2 | 0;
            var h = 0, i = 0, j = 0, k = 0, l = 0, m = 0, n = 0, o = 0, p2 = 0, q2 = 0, r2 = 0, s2 = 0, t2 = 0, u2 = 0;
            u2 = T;
            T = T + 32 | 0;
            t2 = u2 + 16 | 0;
            s2 = u2;
            h = vd(c2 | 0, d2 | 0, 52) | 0;
            H() | 0;
            h = h & 15;
            p2 = vd(e2 | 0, f2 | 0, 52) | 0;
            H() | 0;
            if ((h | 0) != (p2 & 15 | 0)) {
              t2 = 12;
              T = u2;
              return t2 | 0;
            }
            l = vd(c2 | 0, d2 | 0, 45) | 0;
            H() | 0;
            l = l & 127;
            m = vd(e2 | 0, f2 | 0, 45) | 0;
            H() | 0;
            m = m & 127;
            if (l >>> 0 > 121 | m >>> 0 > 121) {
              t2 = 5;
              T = u2;
              return t2 | 0;
            }
            p2 = (l | 0) != (m | 0);
            if (p2) {
              j = ua(l, m) | 0;
              if ((j | 0) == 7) {
                t2 = 1;
                T = u2;
                return t2 | 0;
              }
              k = ua(m, l) | 0;
              if ((k | 0) == 7) {
                I(23066, 23090, 161, 23100);
              } else {
                q2 = j;
                i = k;
              }
            } else {
              q2 = 0;
              i = 0;
            }
            n = ma(l) | 0;
            o = ma(m) | 0;
            b[t2 >> 2] = 0;
            b[t2 + 4 >> 2] = 0;
            b[t2 + 8 >> 2] = 0;
            b[t2 + 12 >> 2] = 0;
            do {
              if (!q2) {
                Nb(e2, f2, t2) | 0;
                if ((n | 0) != 0 & (o | 0) != 0) {
                  if ((m | 0) != (l | 0)) {
                    I(23173, 23090, 261, 23100);
                  }
                  i = Fb(c2, d2) | 0;
                  h = Fb(e2, f2) | 0;
                  if (!((i | 0) == 7 | (h | 0) == 7)) {
                    if (!(a[21872 + (i * 7 | 0) + h >> 0] | 0)) {
                      i = b[21040 + (i * 28 | 0) + (h << 2) >> 2] | 0;
                      if ((i | 0) > 0) {
                        j = t2 + 4 | 0;
                        h = 0;
                        do {
                          Ra(j);
                          h = h + 1 | 0;
                        } while ((h | 0) != (i | 0));
                        r2 = 51;
                      } else {
                        r2 = 51;
                      }
                    } else {
                      h = 1;
                    }
                  } else {
                    h = 5;
                  }
                } else {
                  r2 = 51;
                }
              } else {
                m = b[4272 + (l * 28 | 0) + (q2 << 2) >> 2] | 0;
                j = (m | 0) > 0;
                if (!o) {
                  if (j) {
                    l = 0;
                    k = e2;
                    j = f2;
                    do {
                      k = Jb(k, j) | 0;
                      j = H() | 0;
                      i = Ta(i) | 0;
                      l = l + 1 | 0;
                    } while ((l | 0) != (m | 0));
                    m = i;
                    l = k;
                    k = j;
                  } else {
                    m = i;
                    l = e2;
                    k = f2;
                  }
                } else if (j) {
                  l = 0;
                  k = e2;
                  j = f2;
                  do {
                    k = Ib(k, j) | 0;
                    j = H() | 0;
                    i = Ta(i) | 0;
                    if ((i | 0) == 1) {
                      i = Ta(1) | 0;
                    }
                    l = l + 1 | 0;
                  } while ((l | 0) != (m | 0));
                  m = i;
                  l = k;
                  k = j;
                } else {
                  m = i;
                  l = e2;
                  k = f2;
                }
                Nb(l, k, t2) | 0;
                if (!p2) {
                  I(23115, 23090, 191, 23100);
                }
                j = (n | 0) != 0;
                i = (o | 0) != 0;
                if (j & i) {
                  I(23142, 23090, 192, 23100);
                }
                if (!j) {
                  if (i) {
                    i = Fb(l, k) | 0;
                    if ((i | 0) == 7) {
                      h = 5;
                      break;
                    }
                    if (a[21872 + (i * 7 | 0) + m >> 0] | 0) {
                      h = 1;
                      break;
                    }
                    l = 0;
                    k = b[21040 + (m * 28 | 0) + (i << 2) >> 2] | 0;
                  } else {
                    l = 0;
                    k = 0;
                  }
                } else {
                  i = Fb(c2, d2) | 0;
                  if ((i | 0) == 7) {
                    h = 5;
                    break;
                  }
                  if (a[21872 + (i * 7 | 0) + q2 >> 0] | 0) {
                    h = 1;
                    break;
                  }
                  k = b[21040 + (i * 28 | 0) + (q2 << 2) >> 2] | 0;
                  l = k;
                }
                if ((l | k | 0) < 0) {
                  h = 5;
                } else {
                  if ((k | 0) > 0) {
                    j = t2 + 4 | 0;
                    i = 0;
                    do {
                      Ra(j);
                      i = i + 1 | 0;
                    } while ((i | 0) != (k | 0));
                  }
                  b[s2 >> 2] = 0;
                  b[s2 + 4 >> 2] = 0;
                  b[s2 + 8 >> 2] = 0;
                  Pa(s2, q2);
                  if (h | 0) {
                    while (1) {
                      if (!(Lb(h) | 0)) {
                        Oa(s2);
                      } else {
                        Na(s2);
                      }
                      if ((h | 0) > 1) {
                        h = h + -1 | 0;
                      } else {
                        break;
                      }
                    }
                  }
                  if ((l | 0) > 0) {
                    h = 0;
                    do {
                      Ra(s2);
                      h = h + 1 | 0;
                    } while ((h | 0) != (l | 0));
                  }
                  r2 = t2 + 4 | 0;
                  Fa(r2, s2, r2);
                  Da(r2);
                  r2 = 51;
                }
              }
            } while (0);
            if ((r2 | 0) == 51) {
              h = t2 + 4 | 0;
              b[g2 >> 2] = b[h >> 2];
              b[g2 + 4 >> 2] = b[h + 4 >> 2];
              b[g2 + 8 >> 2] = b[h + 8 >> 2];
              h = 0;
            }
            t2 = h;
            T = u2;
            return t2 | 0;
          }
          function wc(a2, c2, d2, e2) {
            a2 = a2 | 0;
            c2 = c2 | 0;
            d2 = d2 | 0;
            e2 = e2 | 0;
            var f2 = 0, g2 = 0, h = 0, i = 0, j = 0, k = 0, l = 0, m = 0, n = 0, o = 0, p2 = 0, q2 = 0, r2 = 0, s2 = 0, t2 = 0, u2 = 0;
            q2 = T;
            T = T + 48 | 0;
            k = q2 + 36 | 0;
            h = q2 + 24 | 0;
            i = q2 + 12 | 0;
            j = q2;
            f2 = vd(a2 | 0, c2 | 0, 52) | 0;
            H() | 0;
            f2 = f2 & 15;
            n = vd(a2 | 0, c2 | 0, 45) | 0;
            H() | 0;
            n = n & 127;
            if (n >>> 0 > 121) {
              e2 = 5;
              T = q2;
              return e2 | 0;
            }
            l = ma(n) | 0;
            wd(f2 | 0, 0, 52) | 0;
            r2 = H() | 0 | 134225919;
            g2 = e2;
            b[g2 >> 2] = -1;
            b[g2 + 4 >> 2] = r2;
            if (!f2) {
              f2 = Ia(d2) | 0;
              if ((f2 | 0) == 7) {
                r2 = 1;
                T = q2;
                return r2 | 0;
              }
              f2 = ta(n, f2) | 0;
              if ((f2 | 0) == 127) {
                r2 = 1;
                T = q2;
                return r2 | 0;
              }
              o = wd(f2 | 0, 0, 45) | 0;
              p2 = H() | 0;
              n = e2;
              p2 = b[n + 4 >> 2] & -1040385 | p2;
              r2 = e2;
              b[r2 >> 2] = b[n >> 2] | o;
              b[r2 + 4 >> 2] = p2;
              r2 = 0;
              T = q2;
              return r2 | 0;
            }
            b[k >> 2] = b[d2 >> 2];
            b[k + 4 >> 2] = b[d2 + 4 >> 2];
            b[k + 8 >> 2] = b[d2 + 8 >> 2];
            d2 = f2;
            while (1) {
              g2 = d2;
              d2 = d2 + -1 | 0;
              b[h >> 2] = b[k >> 2];
              b[h + 4 >> 2] = b[k + 4 >> 2];
              b[h + 8 >> 2] = b[k + 8 >> 2];
              if (!(Lb(g2) | 0)) {
                f2 = Ka(k) | 0;
                if (f2 | 0) {
                  d2 = 13;
                  break;
                }
                b[i >> 2] = b[k >> 2];
                b[i + 4 >> 2] = b[k + 4 >> 2];
                b[i + 8 >> 2] = b[k + 8 >> 2];
                Oa(i);
              } else {
                f2 = Ja(k) | 0;
                if (f2 | 0) {
                  d2 = 13;
                  break;
                }
                b[i >> 2] = b[k >> 2];
                b[i + 4 >> 2] = b[k + 4 >> 2];
                b[i + 8 >> 2] = b[k + 8 >> 2];
                Na(i);
              }
              Ga(h, i, j);
              Da(j);
              f2 = e2;
              t2 = b[f2 >> 2] | 0;
              f2 = b[f2 + 4 >> 2] | 0;
              u2 = (15 - g2 | 0) * 3 | 0;
              s2 = wd(7, 0, u2 | 0) | 0;
              f2 = f2 & ~(H() | 0);
              u2 = wd(Ia(j) | 0, 0, u2 | 0) | 0;
              f2 = H() | 0 | f2;
              r2 = e2;
              b[r2 >> 2] = u2 | t2 & ~s2;
              b[r2 + 4 >> 2] = f2;
              if ((g2 | 0) <= 1) {
                d2 = 14;
                break;
              }
            }
            a: do {
              if ((d2 | 0) != 13) {
                if ((d2 | 0) == 14) {
                  if (((b[k >> 2] | 0) <= 1 ? (b[k + 4 >> 2] | 0) <= 1 : 0) ? (b[k + 8 >> 2] | 0) <= 1 : 0) {
                    d2 = Ia(k) | 0;
                    f2 = ta(n, d2) | 0;
                    if ((f2 | 0) == 127) {
                      j = 0;
                    } else {
                      j = ma(f2) | 0;
                    }
                    b: do {
                      if (!d2) {
                        if ((l | 0) != 0 & (j | 0) != 0) {
                          d2 = Fb(a2, c2) | 0;
                          g2 = e2;
                          g2 = Fb(b[g2 >> 2] | 0, b[g2 + 4 >> 2] | 0) | 0;
                          if ((d2 | 0) == 7 | (g2 | 0) == 7) {
                            f2 = 5;
                            break a;
                          }
                          g2 = b[21248 + (d2 * 28 | 0) + (g2 << 2) >> 2] | 0;
                          if ((g2 | 0) < 0) {
                            f2 = 5;
                            break a;
                          }
                          if (!g2) {
                            d2 = 59;
                          } else {
                            i = e2;
                            d2 = 0;
                            h = b[i >> 2] | 0;
                            i = b[i + 4 >> 2] | 0;
                            do {
                              h = Hb(h, i) | 0;
                              i = H() | 0;
                              u2 = e2;
                              b[u2 >> 2] = h;
                              b[u2 + 4 >> 2] = i;
                              d2 = d2 + 1 | 0;
                            } while ((d2 | 0) < (g2 | 0));
                            d2 = 58;
                          }
                        } else {
                          d2 = 58;
                        }
                      } else {
                        if (l) {
                          f2 = Fb(a2, c2) | 0;
                          if ((f2 | 0) == 7) {
                            f2 = 5;
                            break a;
                          }
                          g2 = b[21248 + (f2 * 28 | 0) + (d2 << 2) >> 2] | 0;
                          if ((g2 | 0) > 0) {
                            f2 = d2;
                            d2 = 0;
                            do {
                              f2 = Sa(f2) | 0;
                              d2 = d2 + 1 | 0;
                            } while ((d2 | 0) != (g2 | 0));
                          } else {
                            f2 = d2;
                          }
                          if ((f2 | 0) == 1) {
                            f2 = 9;
                            break a;
                          }
                          d2 = ta(n, f2) | 0;
                          if ((d2 | 0) == 127) {
                            I(23200, 23090, 411, 23230);
                          }
                          if (!(ma(d2) | 0)) {
                            p2 = d2;
                            o = g2;
                            m = f2;
                          } else {
                            I(23245, 23090, 412, 23230);
                          }
                        } else {
                          p2 = f2;
                          o = 0;
                          m = d2;
                        }
                        i = b[4272 + (n * 28 | 0) + (m << 2) >> 2] | 0;
                        if ((i | 0) <= -1) {
                          I(23276, 23090, 419, 23230);
                        }
                        if (!j) {
                          if ((o | 0) < 0) {
                            f2 = 5;
                            break a;
                          }
                          if (o | 0) {
                            g2 = e2;
                            f2 = 0;
                            d2 = b[g2 >> 2] | 0;
                            g2 = b[g2 + 4 >> 2] | 0;
                            do {
                              d2 = Hb(d2, g2) | 0;
                              g2 = H() | 0;
                              u2 = e2;
                              b[u2 >> 2] = d2;
                              b[u2 + 4 >> 2] = g2;
                              f2 = f2 + 1 | 0;
                            } while ((f2 | 0) < (o | 0));
                          }
                          if ((i | 0) <= 0) {
                            f2 = p2;
                            d2 = 58;
                            break;
                          }
                          g2 = e2;
                          f2 = 0;
                          d2 = b[g2 >> 2] | 0;
                          g2 = b[g2 + 4 >> 2] | 0;
                          while (1) {
                            d2 = Hb(d2, g2) | 0;
                            g2 = H() | 0;
                            u2 = e2;
                            b[u2 >> 2] = d2;
                            b[u2 + 4 >> 2] = g2;
                            f2 = f2 + 1 | 0;
                            if ((f2 | 0) == (i | 0)) {
                              f2 = p2;
                              d2 = 58;
                              break b;
                            }
                          }
                        }
                        h = ua(p2, n) | 0;
                        if ((h | 0) == 7) {
                          I(23066, 23090, 428, 23230);
                        }
                        f2 = e2;
                        d2 = b[f2 >> 2] | 0;
                        f2 = b[f2 + 4 >> 2] | 0;
                        if ((i | 0) > 0) {
                          g2 = 0;
                          do {
                            d2 = Hb(d2, f2) | 0;
                            f2 = H() | 0;
                            u2 = e2;
                            b[u2 >> 2] = d2;
                            b[u2 + 4 >> 2] = f2;
                            g2 = g2 + 1 | 0;
                          } while ((g2 | 0) != (i | 0));
                        }
                        f2 = Fb(d2, f2) | 0;
                        if ((f2 | 0) == 7) {
                          I(23313, 23090, 440, 23230);
                        }
                        d2 = na(p2) | 0;
                        d2 = b[(d2 ? 21664 : 21456) + (h * 28 | 0) + (f2 << 2) >> 2] | 0;
                        if ((d2 | 0) < 0) {
                          I(23313, 23090, 454, 23230);
                        }
                        if (!d2) {
                          f2 = p2;
                          d2 = 58;
                        } else {
                          h = e2;
                          f2 = 0;
                          g2 = b[h >> 2] | 0;
                          h = b[h + 4 >> 2] | 0;
                          do {
                            g2 = Gb(g2, h) | 0;
                            h = H() | 0;
                            u2 = e2;
                            b[u2 >> 2] = g2;
                            b[u2 + 4 >> 2] = h;
                            f2 = f2 + 1 | 0;
                          } while ((f2 | 0) < (d2 | 0));
                          f2 = p2;
                          d2 = 58;
                        }
                      }
                    } while (0);
                    if ((d2 | 0) == 58) {
                      if (j) {
                        d2 = 59;
                      }
                    }
                    if ((d2 | 0) == 59) {
                      u2 = e2;
                      if ((Fb(b[u2 >> 2] | 0, b[u2 + 4 >> 2] | 0) | 0) == 1) {
                        f2 = 9;
                        break;
                      }
                    }
                    u2 = e2;
                    s2 = b[u2 >> 2] | 0;
                    u2 = b[u2 + 4 >> 2] & -1040385;
                    t2 = wd(f2 | 0, 0, 45) | 0;
                    u2 = u2 | (H() | 0);
                    f2 = e2;
                    b[f2 >> 2] = s2 | t2;
                    b[f2 + 4 >> 2] = u2;
                    f2 = 0;
                  } else {
                    f2 = 1;
                  }
                }
              }
            } while (0);
            u2 = f2;
            T = q2;
            return u2 | 0;
          }
          function xc(a2, b2, c2, d2, e2, f2) {
            a2 = a2 | 0;
            b2 = b2 | 0;
            c2 = c2 | 0;
            d2 = d2 | 0;
            e2 = e2 | 0;
            f2 = f2 | 0;
            var g2 = 0, h = 0;
            h = T;
            T = T + 16 | 0;
            g2 = h;
            if (!e2) {
              a2 = vc(a2, b2, c2, d2, g2) | 0;
              if (!a2) {
                Xa(g2, f2);
                a2 = 0;
              }
            } else {
              a2 = 15;
            }
            T = h;
            return a2 | 0;
          }
          function yc(a2, b2, c2, d2, e2) {
            a2 = a2 | 0;
            b2 = b2 | 0;
            c2 = c2 | 0;
            d2 = d2 | 0;
            e2 = e2 | 0;
            var f2 = 0, g2 = 0;
            g2 = T;
            T = T + 16 | 0;
            f2 = g2;
            if (!d2) {
              c2 = Ya(c2, f2) | 0;
              if (!c2) {
                c2 = wc(a2, b2, f2, e2) | 0;
              }
            } else {
              c2 = 15;
            }
            T = g2;
            return c2 | 0;
          }
          function zc(a2, c2, d2, e2, f2) {
            a2 = a2 | 0;
            c2 = c2 | 0;
            d2 = d2 | 0;
            e2 = e2 | 0;
            f2 = f2 | 0;
            var g2 = 0, h = 0, i = 0, j = 0;
            j = T;
            T = T + 32 | 0;
            h = j + 12 | 0;
            i = j;
            g2 = vc(a2, c2, a2, c2, h) | 0;
            if (g2 | 0) {
              i = g2;
              T = j;
              return i | 0;
            }
            a2 = vc(a2, c2, d2, e2, i) | 0;
            if (a2 | 0) {
              i = a2;
              T = j;
              return i | 0;
            }
            h = Wa(h, i) | 0;
            i = f2;
            b[i >> 2] = h;
            b[i + 4 >> 2] = ((h | 0) < 0) << 31 >> 31;
            i = 0;
            T = j;
            return i | 0;
          }
          function Ac(a2, c2, d2, e2, f2) {
            a2 = a2 | 0;
            c2 = c2 | 0;
            d2 = d2 | 0;
            e2 = e2 | 0;
            f2 = f2 | 0;
            var g2 = 0, h = 0, i = 0, j = 0;
            j = T;
            T = T + 32 | 0;
            h = j + 12 | 0;
            i = j;
            g2 = vc(a2, c2, a2, c2, h) | 0;
            if (!g2) {
              g2 = vc(a2, c2, d2, e2, i) | 0;
              if (!g2) {
                e2 = Wa(h, i) | 0;
                e2 = ld(e2 | 0, ((e2 | 0) < 0) << 31 >> 31 | 0, 1, 0) | 0;
                h = H() | 0;
                i = f2;
                b[i >> 2] = e2;
                b[i + 4 >> 2] = h;
                i = 0;
                T = j;
                return i | 0;
              }
            }
            i = g2;
            T = j;
            return i | 0;
          }
          function Bc(a2, c2, d2, e2, f2) {
            a2 = a2 | 0;
            c2 = c2 | 0;
            d2 = d2 | 0;
            e2 = e2 | 0;
            f2 = f2 | 0;
            var g2 = 0, h = 0, i = 0, j = 0, k = 0, l = 0, m = 0, n = 0, o = 0, p2 = 0, r2 = 0, s2 = 0, t2 = 0, u2 = 0, v2 = 0, w2 = 0, x2 = 0, y2 = 0, z2 = 0, A2 = 0;
            z2 = T;
            T = T + 48 | 0;
            h = z2 + 24 | 0;
            i = z2 + 12 | 0;
            y2 = z2;
            g2 = vc(a2, c2, a2, c2, h) | 0;
            if (!g2) {
              g2 = vc(a2, c2, d2, e2, i) | 0;
              if (!g2) {
                w2 = Wa(h, i) | 0;
                x2 = ((w2 | 0) < 0) << 31 >> 31;
                b[h >> 2] = 0;
                b[h + 4 >> 2] = 0;
                b[h + 8 >> 2] = 0;
                b[i >> 2] = 0;
                b[i + 4 >> 2] = 0;
                b[i + 8 >> 2] = 0;
                if (vc(a2, c2, a2, c2, h) | 0) {
                  I(23313, 23090, 691, 23299);
                }
                if (vc(a2, c2, d2, e2, i) | 0) {
                  I(23313, 23090, 696, 23299);
                }
                Za(h);
                Za(i);
                if (!w2) {
                  g2 = h + 4 | 0;
                  d2 = h + 8 | 0;
                  t2 = g2;
                  u2 = d2;
                  v2 = h;
                  e2 = b[h >> 2] | 0;
                  g2 = b[g2 >> 2] | 0;
                  d2 = b[d2 >> 2] | 0;
                  r2 = 0;
                  s2 = 0;
                  p2 = 0;
                } else {
                  m = b[h >> 2] | 0;
                  p2 = +(w2 | 0);
                  t2 = h + 4 | 0;
                  n = b[t2 >> 2] | 0;
                  u2 = h + 8 | 0;
                  o = b[u2 >> 2] | 0;
                  v2 = h;
                  e2 = m;
                  g2 = n;
                  d2 = o;
                  r2 = +((b[i >> 2] | 0) - m | 0) / p2;
                  s2 = +((b[i + 4 >> 2] | 0) - n | 0) / p2;
                  p2 = +((b[i + 8 >> 2] | 0) - o | 0) / p2;
                }
                b[y2 >> 2] = e2;
                o = y2 + 4 | 0;
                b[o >> 2] = g2;
                n = y2 + 8 | 0;
                b[n >> 2] = d2;
                a: do {
                  if ((w2 | 0) < 0) {
                    g2 = 0;
                  } else {
                    l = 0;
                    m = 0;
                    g2 = e2;
                    while (1) {
                      k = +(m >>> 0) + 4294967296 * +(l | 0);
                      A2 = r2 * k + +(g2 | 0);
                      j = s2 * k + +(b[t2 >> 2] | 0);
                      k = p2 * k + +(b[u2 >> 2] | 0);
                      d2 = ~~+zd(+A2);
                      h = ~~+zd(+j);
                      g2 = ~~+zd(+k);
                      A2 = +q(+(+(d2 | 0) - A2));
                      j = +q(+(+(h | 0) - j));
                      k = +q(+(+(g2 | 0) - k));
                      do {
                        if (!(A2 > j & A2 > k)) {
                          i = 0 - d2 | 0;
                          if (j > k) {
                            e2 = i - g2 | 0;
                            break;
                          } else {
                            e2 = h;
                            g2 = i - h | 0;
                            break;
                          }
                        } else {
                          d2 = 0 - (h + g2) | 0;
                          e2 = h;
                        }
                      } while (0);
                      b[y2 >> 2] = d2;
                      b[o >> 2] = e2;
                      b[n >> 2] = g2;
                      _a(y2);
                      g2 = wc(a2, c2, y2, f2 + (m << 3) | 0) | 0;
                      if (g2 | 0) {
                        break a;
                      }
                      if (!((l | 0) < (x2 | 0) | (l | 0) == (x2 | 0) & m >>> 0 < w2 >>> 0)) {
                        g2 = 0;
                        break a;
                      }
                      g2 = ld(m | 0, l | 0, 1, 0) | 0;
                      i = H() | 0;
                      l = i;
                      m = g2;
                      g2 = b[v2 >> 2] | 0;
                    }
                  }
                } while (0);
                y2 = g2;
                T = z2;
                return y2 | 0;
              }
            }
            y2 = g2;
            T = z2;
            return y2 | 0;
          }
          function Cc(a2, b2, c2, d2) {
            a2 = a2 | 0;
            b2 = b2 | 0;
            c2 = c2 | 0;
            d2 = d2 | 0;
            var e2 = 0, f2 = 0, g2 = 0;
            if ((c2 | 0) == 0 & (d2 | 0) == 0) {
              e2 = 0;
              f2 = 1;
              G(e2 | 0);
              return f2 | 0;
            }
            f2 = a2;
            e2 = b2;
            a2 = 1;
            b2 = 0;
            do {
              g2 = (c2 & 1 | 0) == 0 & true;
              a2 = rd((g2 ? 1 : f2) | 0, (g2 ? 0 : e2) | 0, a2 | 0, b2 | 0) | 0;
              b2 = H() | 0;
              c2 = ud(c2 | 0, d2 | 0, 1) | 0;
              d2 = H() | 0;
              f2 = rd(f2 | 0, e2 | 0, f2 | 0, e2 | 0) | 0;
              e2 = H() | 0;
            } while (!((c2 | 0) == 0 & (d2 | 0) == 0));
            G(b2 | 0);
            return a2 | 0;
          }
          function Dc(a2, c2, d2) {
            a2 = a2 | 0;
            c2 = c2 | 0;
            d2 = d2 | 0;
            var f2 = 0, g2 = 0, h = 0, i = 0, j = 0, k = 0, l = 0, m = 0, n = 0, o = 0;
            if (!(ya(c2, d2) | 0)) {
              o = 0;
              return o | 0;
            }
            c2 = xa(c2) | 0;
            f2 = +e[d2 >> 3];
            g2 = +e[d2 + 8 >> 3];
            g2 = c2 & g2 < 0 ? g2 + 6.283185307179586 : g2;
            o = b[a2 >> 2] | 0;
            if ((o | 0) <= 0) {
              o = 0;
              return o | 0;
            }
            n = b[a2 + 4 >> 2] | 0;
            if (c2) {
              c2 = 0;
              m = g2;
              d2 = -1;
              a2 = 0;
              a: while (1) {
                l = a2;
                while (1) {
                  i = +e[n + (l << 4) >> 3];
                  g2 = +e[n + (l << 4) + 8 >> 3];
                  a2 = (d2 + 2 | 0) % (o | 0) | 0;
                  h = +e[n + (a2 << 4) >> 3];
                  j = +e[n + (a2 << 4) + 8 >> 3];
                  if (i > h) {
                    k = i;
                    i = j;
                  } else {
                    k = h;
                    h = i;
                    i = g2;
                    g2 = j;
                  }
                  f2 = f2 == h | f2 == k ? f2 + 2220446049250313e-31 : f2;
                  if (!(f2 < h | f2 > k)) {
                    break;
                  }
                  d2 = l + 1 | 0;
                  if ((d2 | 0) >= (o | 0)) {
                    d2 = 22;
                    break a;
                  } else {
                    a2 = l;
                    l = d2;
                    d2 = a2;
                  }
                }
                j = i < 0 ? i + 6.283185307179586 : i;
                i = g2 < 0 ? g2 + 6.283185307179586 : g2;
                m = j == m | i == m ? m + -2220446049250313e-31 : m;
                k = j + (i - j) * ((f2 - h) / (k - h));
                if ((k < 0 ? k + 6.283185307179586 : k) > m) {
                  c2 = c2 ^ 1;
                }
                a2 = l + 1 | 0;
                if ((a2 | 0) >= (o | 0)) {
                  d2 = 22;
                  break;
                } else {
                  d2 = l;
                }
              }
              if ((d2 | 0) == 22) {
                return c2 | 0;
              }
            } else {
              c2 = 0;
              m = g2;
              d2 = -1;
              a2 = 0;
              b: while (1) {
                l = a2;
                while (1) {
                  i = +e[n + (l << 4) >> 3];
                  g2 = +e[n + (l << 4) + 8 >> 3];
                  a2 = (d2 + 2 | 0) % (o | 0) | 0;
                  h = +e[n + (a2 << 4) >> 3];
                  j = +e[n + (a2 << 4) + 8 >> 3];
                  if (i > h) {
                    k = i;
                    i = j;
                  } else {
                    k = h;
                    h = i;
                    i = g2;
                    g2 = j;
                  }
                  f2 = f2 == h | f2 == k ? f2 + 2220446049250313e-31 : f2;
                  if (!(f2 < h | f2 > k)) {
                    break;
                  }
                  d2 = l + 1 | 0;
                  if ((d2 | 0) >= (o | 0)) {
                    d2 = 22;
                    break b;
                  } else {
                    a2 = l;
                    l = d2;
                    d2 = a2;
                  }
                }
                m = i == m | g2 == m ? m + -2220446049250313e-31 : m;
                if (i + (g2 - i) * ((f2 - h) / (k - h)) > m) {
                  c2 = c2 ^ 1;
                }
                a2 = l + 1 | 0;
                if ((a2 | 0) >= (o | 0)) {
                  d2 = 22;
                  break;
                } else {
                  d2 = l;
                }
              }
              if ((d2 | 0) == 22) {
                return c2 | 0;
              }
            }
            return 0;
          }
          function Ec(a2, c2) {
            a2 = a2 | 0;
            c2 = c2 | 0;
            var d2 = 0, f2 = 0, g2 = 0, h = 0, i = 0, j = 0, k = 0, l = 0, m = 0, n = 0, o = 0, p2 = 0, r2 = 0, s2 = 0, t2 = 0, u2 = 0, v2 = 0;
            r2 = b[a2 >> 2] | 0;
            if (!r2) {
              b[c2 >> 2] = 0;
              b[c2 + 4 >> 2] = 0;
              b[c2 + 8 >> 2] = 0;
              b[c2 + 12 >> 2] = 0;
              b[c2 + 16 >> 2] = 0;
              b[c2 + 20 >> 2] = 0;
              b[c2 + 24 >> 2] = 0;
              b[c2 + 28 >> 2] = 0;
              return;
            }
            s2 = c2 + 8 | 0;
            e[s2 >> 3] = 17976931348623157e292;
            t2 = c2 + 24 | 0;
            e[t2 >> 3] = 17976931348623157e292;
            e[c2 >> 3] = -17976931348623157e292;
            u2 = c2 + 16 | 0;
            e[u2 >> 3] = -17976931348623157e292;
            if ((r2 | 0) <= 0) {
              return;
            }
            o = b[a2 + 4 >> 2] | 0;
            l = 17976931348623157e292;
            m = -17976931348623157e292;
            n = 0;
            a2 = -1;
            h = 17976931348623157e292;
            i = 17976931348623157e292;
            k = -17976931348623157e292;
            f2 = -17976931348623157e292;
            p2 = 0;
            while (1) {
              d2 = +e[o + (p2 << 4) >> 3];
              j = +e[o + (p2 << 4) + 8 >> 3];
              a2 = a2 + 2 | 0;
              g2 = +e[o + (((a2 | 0) == (r2 | 0) ? 0 : a2) << 4) + 8 >> 3];
              if (d2 < h) {
                e[s2 >> 3] = d2;
                h = d2;
              }
              if (j < i) {
                e[t2 >> 3] = j;
                i = j;
              }
              if (d2 > k) {
                e[c2 >> 3] = d2;
              } else {
                d2 = k;
              }
              if (j > f2) {
                e[u2 >> 3] = j;
                f2 = j;
              }
              l = j > 0 & j < l ? j : l;
              m = j < 0 & j > m ? j : m;
              n = n | +q(+(j - g2)) > 3.141592653589793;
              a2 = p2 + 1 | 0;
              if ((a2 | 0) == (r2 | 0)) {
                break;
              } else {
                v2 = p2;
                k = d2;
                p2 = a2;
                a2 = v2;
              }
            }
            if (!n) {
              return;
            }
            e[u2 >> 3] = m;
            e[t2 >> 3] = l;
            return;
          }
          function Fc(a2, c2) {
            a2 = a2 | 0;
            c2 = c2 | 0;
            var d2 = 0, f2 = 0, g2 = 0, h = 0, i = 0, j = 0, k = 0, l = 0, m = 0, n = 0, o = 0, p2 = 0, r2 = 0, s2 = 0, t2 = 0, u2 = 0, v2 = 0, w2 = 0, x2 = 0, y2 = 0, z2 = 0, A2 = 0;
            r2 = b[a2 >> 2] | 0;
            if (r2) {
              s2 = c2 + 8 | 0;
              e[s2 >> 3] = 17976931348623157e292;
              t2 = c2 + 24 | 0;
              e[t2 >> 3] = 17976931348623157e292;
              e[c2 >> 3] = -17976931348623157e292;
              u2 = c2 + 16 | 0;
              e[u2 >> 3] = -17976931348623157e292;
              if ((r2 | 0) > 0) {
                g2 = b[a2 + 4 >> 2] | 0;
                o = 17976931348623157e292;
                p2 = -17976931348623157e292;
                f2 = 0;
                d2 = -1;
                k = 17976931348623157e292;
                l = 17976931348623157e292;
                n = -17976931348623157e292;
                i = -17976931348623157e292;
                v2 = 0;
                while (1) {
                  h = +e[g2 + (v2 << 4) >> 3];
                  m = +e[g2 + (v2 << 4) + 8 >> 3];
                  z2 = d2 + 2 | 0;
                  j = +e[g2 + (((z2 | 0) == (r2 | 0) ? 0 : z2) << 4) + 8 >> 3];
                  if (h < k) {
                    e[s2 >> 3] = h;
                    k = h;
                  }
                  if (m < l) {
                    e[t2 >> 3] = m;
                    l = m;
                  }
                  if (h > n) {
                    e[c2 >> 3] = h;
                  } else {
                    h = n;
                  }
                  if (m > i) {
                    e[u2 >> 3] = m;
                    i = m;
                  }
                  o = m > 0 & m < o ? m : o;
                  p2 = m < 0 & m > p2 ? m : p2;
                  f2 = f2 | +q(+(m - j)) > 3.141592653589793;
                  d2 = v2 + 1 | 0;
                  if ((d2 | 0) == (r2 | 0)) {
                    break;
                  } else {
                    z2 = v2;
                    n = h;
                    v2 = d2;
                    d2 = z2;
                  }
                }
                if (f2) {
                  e[u2 >> 3] = p2;
                  e[t2 >> 3] = o;
                }
              }
            } else {
              b[c2 >> 2] = 0;
              b[c2 + 4 >> 2] = 0;
              b[c2 + 8 >> 2] = 0;
              b[c2 + 12 >> 2] = 0;
              b[c2 + 16 >> 2] = 0;
              b[c2 + 20 >> 2] = 0;
              b[c2 + 24 >> 2] = 0;
              b[c2 + 28 >> 2] = 0;
            }
            z2 = a2 + 8 | 0;
            d2 = b[z2 >> 2] | 0;
            if ((d2 | 0) <= 0) {
              return;
            }
            y2 = a2 + 12 | 0;
            x2 = 0;
            do {
              g2 = b[y2 >> 2] | 0;
              f2 = x2;
              x2 = x2 + 1 | 0;
              t2 = c2 + (x2 << 5) | 0;
              u2 = b[g2 + (f2 << 3) >> 2] | 0;
              if (u2) {
                v2 = c2 + (x2 << 5) + 8 | 0;
                e[v2 >> 3] = 17976931348623157e292;
                a2 = c2 + (x2 << 5) + 24 | 0;
                e[a2 >> 3] = 17976931348623157e292;
                e[t2 >> 3] = -17976931348623157e292;
                w2 = c2 + (x2 << 5) + 16 | 0;
                e[w2 >> 3] = -17976931348623157e292;
                if ((u2 | 0) > 0) {
                  r2 = b[g2 + (f2 << 3) + 4 >> 2] | 0;
                  o = 17976931348623157e292;
                  p2 = -17976931348623157e292;
                  g2 = 0;
                  f2 = -1;
                  s2 = 0;
                  k = 17976931348623157e292;
                  l = 17976931348623157e292;
                  m = -17976931348623157e292;
                  i = -17976931348623157e292;
                  while (1) {
                    h = +e[r2 + (s2 << 4) >> 3];
                    n = +e[r2 + (s2 << 4) + 8 >> 3];
                    f2 = f2 + 2 | 0;
                    j = +e[r2 + (((f2 | 0) == (u2 | 0) ? 0 : f2) << 4) + 8 >> 3];
                    if (h < k) {
                      e[v2 >> 3] = h;
                      k = h;
                    }
                    if (n < l) {
                      e[a2 >> 3] = n;
                      l = n;
                    }
                    if (h > m) {
                      e[t2 >> 3] = h;
                    } else {
                      h = m;
                    }
                    if (n > i) {
                      e[w2 >> 3] = n;
                      i = n;
                    }
                    o = n > 0 & n < o ? n : o;
                    p2 = n < 0 & n > p2 ? n : p2;
                    g2 = g2 | +q(+(n - j)) > 3.141592653589793;
                    f2 = s2 + 1 | 0;
                    if ((f2 | 0) == (u2 | 0)) {
                      break;
                    } else {
                      A2 = s2;
                      s2 = f2;
                      m = h;
                      f2 = A2;
                    }
                  }
                  if (g2) {
                    e[w2 >> 3] = p2;
                    e[a2 >> 3] = o;
                  }
                }
              } else {
                b[t2 >> 2] = 0;
                b[t2 + 4 >> 2] = 0;
                b[t2 + 8 >> 2] = 0;
                b[t2 + 12 >> 2] = 0;
                b[t2 + 16 >> 2] = 0;
                b[t2 + 20 >> 2] = 0;
                b[t2 + 24 >> 2] = 0;
                b[t2 + 28 >> 2] = 0;
                d2 = b[z2 >> 2] | 0;
              }
            } while ((x2 | 0) < (d2 | 0));
            return;
          }
          function Gc(a2, c2, d2) {
            a2 = a2 | 0;
            c2 = c2 | 0;
            d2 = d2 | 0;
            var e2 = 0, f2 = 0, g2 = 0;
            if (!(Dc(a2, c2, d2) | 0)) {
              f2 = 0;
              return f2 | 0;
            }
            f2 = a2 + 8 | 0;
            if ((b[f2 >> 2] | 0) <= 0) {
              f2 = 1;
              return f2 | 0;
            }
            e2 = a2 + 12 | 0;
            a2 = 0;
            while (1) {
              g2 = a2;
              a2 = a2 + 1 | 0;
              if (Dc((b[e2 >> 2] | 0) + (g2 << 3) | 0, c2 + (a2 << 5) | 0, d2) | 0) {
                a2 = 0;
                e2 = 6;
                break;
              }
              if ((a2 | 0) >= (b[f2 >> 2] | 0)) {
                a2 = 1;
                e2 = 6;
                break;
              }
            }
            if ((e2 | 0) == 6) {
              return a2 | 0;
            }
            return 0;
          }
          function Hc() {
            return 8;
          }
          function Ic() {
            return 16;
          }
          function Jc() {
            return 168;
          }
          function Kc() {
            return 8;
          }
          function Lc() {
            return 16;
          }
          function Mc() {
            return 12;
          }
          function Nc() {
            return 8;
          }
          function Oc(a2) {
            a2 = a2 | 0;
            return +(+((b[a2 >> 2] | 0) >>> 0) + 4294967296 * +(b[a2 + 4 >> 2] | 0));
          }
          function Pc(a2) {
            a2 = a2 | 0;
            var b2 = 0, c2 = 0;
            c2 = +e[a2 >> 3];
            b2 = +e[a2 + 8 >> 3];
            return + +r(+(c2 * c2 + b2 * b2));
          }
          function Qc(a2, b2, c2, d2, f2) {
            a2 = a2 | 0;
            b2 = b2 | 0;
            c2 = c2 | 0;
            d2 = d2 | 0;
            f2 = f2 | 0;
            var g2 = 0, h = 0, i = 0, j = 0, k = 0, l = 0, m = 0, n = 0;
            k = +e[a2 >> 3];
            j = +e[b2 >> 3] - k;
            i = +e[a2 + 8 >> 3];
            h = +e[b2 + 8 >> 3] - i;
            m = +e[c2 >> 3];
            g2 = +e[d2 >> 3] - m;
            n = +e[c2 + 8 >> 3];
            l = +e[d2 + 8 >> 3] - n;
            g2 = (g2 * (i - n) - (k - m) * l) / (j * l - h * g2);
            e[f2 >> 3] = k + j * g2;
            e[f2 + 8 >> 3] = i + h * g2;
            return;
          }
          function Rc(a2, b2) {
            a2 = a2 | 0;
            b2 = b2 | 0;
            if (!(+q(+(+e[a2 >> 3] - +e[b2 >> 3])) < 11920928955078125e-23)) {
              b2 = 0;
              return b2 | 0;
            }
            b2 = +q(+(+e[a2 + 8 >> 3] - +e[b2 + 8 >> 3])) < 11920928955078125e-23;
            return b2 | 0;
          }
          function Sc(a2, b2) {
            a2 = a2 | 0;
            b2 = b2 | 0;
            var c2 = 0, d2 = 0, f2 = 0;
            f2 = +e[a2 >> 3] - +e[b2 >> 3];
            d2 = +e[a2 + 8 >> 3] - +e[b2 + 8 >> 3];
            c2 = +e[a2 + 16 >> 3] - +e[b2 + 16 >> 3];
            return +(f2 * f2 + d2 * d2 + c2 * c2);
          }
          function Tc(a2, b2) {
            a2 = a2 | 0;
            b2 = b2 | 0;
            var c2 = 0, d2 = 0, f2 = 0;
            c2 = +e[a2 >> 3];
            d2 = +t(+c2);
            c2 = +u(+c2);
            e[b2 + 16 >> 3] = c2;
            c2 = +e[a2 + 8 >> 3];
            f2 = d2 * +t(+c2);
            e[b2 >> 3] = f2;
            c2 = d2 * +u(+c2);
            e[b2 + 8 >> 3] = c2;
            return;
          }
          function Uc(a2, c2, d2) {
            a2 = a2 | 0;
            c2 = c2 | 0;
            d2 = d2 | 0;
            var e2 = 0, f2 = 0, g2 = 0;
            g2 = T;
            T = T + 16 | 0;
            f2 = g2;
            e2 = xb(a2, c2) | 0;
            if ((d2 + -1 | 0) >>> 0 > 5) {
              f2 = -1;
              T = g2;
              return f2 | 0;
            }
            e2 = (e2 | 0) != 0;
            if ((d2 | 0) == 1 & e2) {
              f2 = -1;
              T = g2;
              return f2 | 0;
            }
            do {
              if (!(Vc(a2, c2, f2) | 0)) {
                if (e2) {
                  e2 = ((b[21936 + (d2 << 2) >> 2] | 0) + 5 - (b[f2 >> 2] | 0) | 0) % 5 | 0;
                  break;
                } else {
                  e2 = ((b[21968 + (d2 << 2) >> 2] | 0) + 6 - (b[f2 >> 2] | 0) | 0) % 6 | 0;
                  break;
                }
              } else {
                e2 = -1;
              }
            } while (0);
            f2 = e2;
            T = g2;
            return f2 | 0;
          }
          function Vc(a2, c2, d2) {
            a2 = a2 | 0;
            c2 = c2 | 0;
            d2 = d2 | 0;
            var e2 = 0, f2 = 0, g2 = 0, h = 0, i = 0, j = 0, k = 0;
            k = T;
            T = T + 32 | 0;
            h = k + 16 | 0;
            i = k;
            e2 = Ob(a2, c2, h) | 0;
            if (e2 | 0) {
              d2 = e2;
              T = k;
              return d2 | 0;
            }
            g2 = tb(a2, c2) | 0;
            j = Fb(a2, c2) | 0;
            qa(g2, i);
            e2 = ra(g2, b[h >> 2] | 0) | 0;
            a: do {
              if (ma(g2) | 0) {
                do {
                  switch (g2 | 0) {
                    case 4: {
                      a2 = 0;
                      break;
                    }
                    case 14: {
                      a2 = 1;
                      break;
                    }
                    case 24: {
                      a2 = 2;
                      break;
                    }
                    case 38: {
                      a2 = 3;
                      break;
                    }
                    case 49: {
                      a2 = 4;
                      break;
                    }
                    case 58: {
                      a2 = 5;
                      break;
                    }
                    case 63: {
                      a2 = 6;
                      break;
                    }
                    case 72: {
                      a2 = 7;
                      break;
                    }
                    case 83: {
                      a2 = 8;
                      break;
                    }
                    case 97: {
                      a2 = 9;
                      break;
                    }
                    case 107: {
                      a2 = 10;
                      break;
                    }
                    case 117: {
                      a2 = 11;
                      break;
                    }
                    default: {
                      e2 = 1;
                      break a;
                    }
                  }
                } while (0);
                f2 = b[22e3 + (a2 * 24 | 0) + 8 >> 2] | 0;
                c2 = b[22e3 + (a2 * 24 | 0) + 16 >> 2] | 0;
                a2 = b[h >> 2] | 0;
                if ((a2 | 0) != (b[i >> 2] | 0)) {
                  i = na(g2) | 0;
                  a2 = b[h >> 2] | 0;
                  if (i | (a2 | 0) == (c2 | 0)) {
                    e2 = (e2 + 1 | 0) % 6 | 0;
                  }
                }
                if ((j | 0) == 3 & (a2 | 0) == (c2 | 0)) {
                  e2 = (e2 + 5 | 0) % 6 | 0;
                  f2 = 22;
                  break;
                }
                if ((j | 0) == 5 & (a2 | 0) == (f2 | 0)) {
                  e2 = (e2 + 1 | 0) % 6 | 0;
                  f2 = 22;
                } else {
                  f2 = 22;
                }
              } else {
                f2 = 22;
              }
            } while (0);
            if ((f2 | 0) == 22) {
              b[d2 >> 2] = e2;
              e2 = 0;
            }
            d2 = e2;
            T = k;
            return d2 | 0;
          }
          function Wc(a2, c2, d2, e2) {
            a2 = a2 | 0;
            c2 = c2 | 0;
            d2 = d2 | 0;
            e2 = e2 | 0;
            var f2 = 0, g2 = 0, h = 0, i = 0, j = 0, k = 0, l = 0, m = 0, n = 0, o = 0, p2 = 0, q2 = 0, r2 = 0, s2 = 0, t2 = 0, u2 = 0;
            u2 = T;
            T = T + 32 | 0;
            t2 = u2 + 24 | 0;
            r2 = u2 + 20 | 0;
            p2 = u2 + 8 | 0;
            o = u2 + 16 | 0;
            n = u2;
            j = (xb(a2, c2) | 0) == 0;
            j = j ? 6 : 5;
            l = vd(a2 | 0, c2 | 0, 52) | 0;
            H() | 0;
            l = l & 15;
            if (j >>> 0 <= d2 >>> 0) {
              e2 = 2;
              T = u2;
              return e2 | 0;
            }
            m = (l | 0) == 0;
            if (!m ? (q2 = wd(7, 0, (l ^ 15) * 3 | 0) | 0, (q2 & a2 | 0) == 0 & ((H() | 0) & c2 | 0) == 0) : 0) {
              f2 = d2;
            } else {
              g2 = 4;
            }
            a: do {
              if ((g2 | 0) == 4) {
                f2 = (xb(a2, c2) | 0) != 0;
                if (((f2 ? 4 : 5) | 0) < (d2 | 0)) {
                  e2 = 1;
                  T = u2;
                  return e2 | 0;
                }
                if (Vc(a2, c2, t2) | 0) {
                  e2 = 1;
                  T = u2;
                  return e2 | 0;
                }
                g2 = (b[t2 >> 2] | 0) + d2 | 0;
                if (f2) {
                  f2 = 22288 + (((g2 | 0) % 5 | 0) << 2) | 0;
                } else {
                  f2 = 22320 + (((g2 | 0) % 6 | 0) << 2) | 0;
                }
                q2 = b[f2 >> 2] | 0;
                if ((q2 | 0) == 7) {
                  e2 = 1;
                  T = u2;
                  return e2 | 0;
                }
                b[r2 >> 2] = 0;
                f2 = ea(a2, c2, q2, r2, p2) | 0;
                do {
                  if (!f2) {
                    i = p2;
                    k = b[i >> 2] | 0;
                    i = b[i + 4 >> 2] | 0;
                    h = i >>> 0 < c2 >>> 0 | (i | 0) == (c2 | 0) & k >>> 0 < a2 >>> 0;
                    g2 = h ? k : a2;
                    h = h ? i : c2;
                    if (!m ? (m = wd(7, 0, (l ^ 15) * 3 | 0) | 0, (k & m | 0) == 0 & (i & (H() | 0) | 0) == 0) : 0) {
                      f2 = d2;
                    } else {
                      i = (d2 + -1 + j | 0) % (j | 0) | 0;
                      f2 = xb(a2, c2) | 0;
                      if ((i | 0) < 0) {
                        I(23313, 23315, 245, 23324);
                      }
                      j = (f2 | 0) != 0;
                      if (((j ? 4 : 5) | 0) < (i | 0)) {
                        I(23313, 23315, 245, 23324);
                      }
                      if (Vc(a2, c2, t2) | 0) {
                        I(23313, 23315, 245, 23324);
                      }
                      f2 = (b[t2 >> 2] | 0) + i | 0;
                      if (j) {
                        f2 = 22288 + (((f2 | 0) % 5 | 0) << 2) | 0;
                      } else {
                        f2 = 22320 + (((f2 | 0) % 6 | 0) << 2) | 0;
                      }
                      i = b[f2 >> 2] | 0;
                      if ((i | 0) == 7) {
                        I(23313, 23315, 245, 23324);
                      }
                      b[o >> 2] = 0;
                      f2 = ea(a2, c2, i, o, n) | 0;
                      if (f2 | 0) {
                        break;
                      }
                      k = n;
                      j = b[k >> 2] | 0;
                      k = b[k + 4 >> 2] | 0;
                      do {
                        if (k >>> 0 < h >>> 0 | (k | 0) == (h | 0) & j >>> 0 < g2 >>> 0) {
                          if (!(xb(j, k) | 0)) {
                            g2 = b[22384 + ((((b[o >> 2] | 0) + (b[22352 + (i << 2) >> 2] | 0) | 0) % 6 | 0) << 2) >> 2] | 0;
                          } else {
                            g2 = fa(j, k, a2, c2) | 0;
                          }
                          f2 = xb(j, k) | 0;
                          if ((g2 + -1 | 0) >>> 0 > 5) {
                            f2 = -1;
                            g2 = j;
                            h = k;
                            break;
                          }
                          f2 = (f2 | 0) != 0;
                          if ((g2 | 0) == 1 & f2) {
                            f2 = -1;
                            g2 = j;
                            h = k;
                            break;
                          }
                          do {
                            if (!(Vc(j, k, t2) | 0)) {
                              if (f2) {
                                f2 = ((b[21936 + (g2 << 2) >> 2] | 0) + 5 - (b[t2 >> 2] | 0) | 0) % 5 | 0;
                                break;
                              } else {
                                f2 = ((b[21968 + (g2 << 2) >> 2] | 0) + 6 - (b[t2 >> 2] | 0) | 0) % 6 | 0;
                                break;
                              }
                            } else {
                              f2 = -1;
                            }
                          } while (0);
                          g2 = j;
                          h = k;
                        } else {
                          f2 = d2;
                        }
                      } while (0);
                      i = p2;
                      k = b[i >> 2] | 0;
                      i = b[i + 4 >> 2] | 0;
                    }
                    if ((g2 | 0) == (k | 0) & (h | 0) == (i | 0)) {
                      j = (xb(k, i) | 0) != 0;
                      if (j) {
                        a2 = fa(k, i, a2, c2) | 0;
                      } else {
                        a2 = b[22384 + ((((b[r2 >> 2] | 0) + (b[22352 + (q2 << 2) >> 2] | 0) | 0) % 6 | 0) << 2) >> 2] | 0;
                      }
                      f2 = xb(k, i) | 0;
                      if ((a2 + -1 | 0) >>> 0 <= 5 ? (s2 = (f2 | 0) != 0, !((a2 | 0) == 1 & s2)) : 0) {
                        do {
                          if (!(Vc(k, i, t2) | 0)) {
                            if (s2) {
                              f2 = ((b[21936 + (a2 << 2) >> 2] | 0) + 5 - (b[t2 >> 2] | 0) | 0) % 5 | 0;
                              break;
                            } else {
                              f2 = ((b[21968 + (a2 << 2) >> 2] | 0) + 6 - (b[t2 >> 2] | 0) | 0) % 6 | 0;
                              break;
                            }
                          } else {
                            f2 = -1;
                          }
                        } while (0);
                      } else {
                        f2 = -1;
                      }
                      f2 = f2 + 1 | 0;
                      f2 = (f2 | 0) == 6 | j & (f2 | 0) == 5 ? 0 : f2;
                    }
                    c2 = h;
                    a2 = g2;
                    break a;
                  }
                } while (0);
                e2 = f2;
                T = u2;
                return e2 | 0;
              }
            } while (0);
            s2 = wd(f2 | 0, 0, 56) | 0;
            t2 = H() | 0 | c2 & -2130706433 | 536870912;
            b[e2 >> 2] = s2 | a2;
            b[e2 + 4 >> 2] = t2;
            e2 = 0;
            T = u2;
            return e2 | 0;
          }
          function Xc(a2, c2, d2) {
            a2 = a2 | 0;
            c2 = c2 | 0;
            d2 = d2 | 0;
            var e2 = 0, f2 = 0, g2 = 0;
            g2 = (xb(a2, c2) | 0) == 0;
            e2 = Wc(a2, c2, 0, d2) | 0;
            f2 = (e2 | 0) == 0;
            if (g2) {
              if (!f2) {
                g2 = e2;
                return g2 | 0;
              }
              e2 = Wc(a2, c2, 1, d2 + 8 | 0) | 0;
              if (e2 | 0) {
                g2 = e2;
                return g2 | 0;
              }
              e2 = Wc(a2, c2, 2, d2 + 16 | 0) | 0;
              if (e2 | 0) {
                g2 = e2;
                return g2 | 0;
              }
              e2 = Wc(a2, c2, 3, d2 + 24 | 0) | 0;
              if (e2 | 0) {
                g2 = e2;
                return g2 | 0;
              }
              e2 = Wc(a2, c2, 4, d2 + 32 | 0) | 0;
              if (!e2) {
                return Wc(a2, c2, 5, d2 + 40 | 0) | 0;
              } else {
                g2 = e2;
                return g2 | 0;
              }
            }
            if (!f2) {
              g2 = e2;
              return g2 | 0;
            }
            e2 = Wc(a2, c2, 1, d2 + 8 | 0) | 0;
            if (e2 | 0) {
              g2 = e2;
              return g2 | 0;
            }
            e2 = Wc(a2, c2, 2, d2 + 16 | 0) | 0;
            if (e2 | 0) {
              g2 = e2;
              return g2 | 0;
            }
            e2 = Wc(a2, c2, 3, d2 + 24 | 0) | 0;
            if (e2 | 0) {
              g2 = e2;
              return g2 | 0;
            }
            e2 = Wc(a2, c2, 4, d2 + 32 | 0) | 0;
            if (e2 | 0) {
              g2 = e2;
              return g2 | 0;
            }
            g2 = d2 + 40 | 0;
            b[g2 >> 2] = 0;
            b[g2 + 4 >> 2] = 0;
            g2 = 0;
            return g2 | 0;
          }
          function Yc(a2, c2, d2) {
            a2 = a2 | 0;
            c2 = c2 | 0;
            d2 = d2 | 0;
            var e2 = 0, f2 = 0, g2 = 0, h = 0, i = 0, j = 0;
            j = T;
            T = T + 192 | 0;
            f2 = j;
            g2 = j + 168 | 0;
            h = vd(a2 | 0, c2 | 0, 56) | 0;
            H() | 0;
            h = h & 7;
            i = c2 & -2130706433 | 134217728;
            e2 = Ob(a2, i, g2) | 0;
            if (e2 | 0) {
              i = e2;
              T = j;
              return i | 0;
            }
            c2 = vd(a2 | 0, c2 | 0, 52) | 0;
            H() | 0;
            c2 = c2 & 15;
            if (!(xb(a2, i) | 0)) {
              qb(g2, c2, h, 1, f2);
            } else {
              mb(g2, c2, h, 1, f2);
            }
            i = f2 + 8 | 0;
            b[d2 >> 2] = b[i >> 2];
            b[d2 + 4 >> 2] = b[i + 4 >> 2];
            b[d2 + 8 >> 2] = b[i + 8 >> 2];
            b[d2 + 12 >> 2] = b[i + 12 >> 2];
            i = 0;
            T = j;
            return i | 0;
          }
          function Zc(a2, c2) {
            a2 = a2 | 0;
            c2 = c2 | 0;
            var d2 = 0, e2 = 0, f2 = 0, g2 = 0;
            f2 = T;
            T = T + 16 | 0;
            d2 = f2;
            if (!(true & (c2 & 2013265920 | 0) == 536870912)) {
              e2 = 0;
              T = f2;
              return e2 | 0;
            }
            e2 = c2 & -2130706433 | 134217728;
            if (!(ub(a2, e2) | 0)) {
              e2 = 0;
              T = f2;
              return e2 | 0;
            }
            g2 = vd(a2 | 0, c2 | 0, 56) | 0;
            H() | 0;
            g2 = (Wc(a2, e2, g2 & 7, d2) | 0) == 0;
            e2 = d2;
            e2 = g2 & ((b[e2 >> 2] | 0) == (a2 | 0) ? (b[e2 + 4 >> 2] | 0) == (c2 | 0) : 0) & 1;
            T = f2;
            return e2 | 0;
          }
          function _c(a2, c2, d2) {
            a2 = a2 | 0;
            c2 = c2 | 0;
            d2 = d2 | 0;
            var e2 = 0;
            if ((c2 | 0) > 0) {
              e2 = kd(c2, 4) | 0;
              b[a2 >> 2] = e2;
              if (!e2) {
                I(23337, 23360, 40, 23374);
              }
            } else {
              b[a2 >> 2] = 0;
            }
            b[a2 + 4 >> 2] = c2;
            b[a2 + 8 >> 2] = 0;
            b[a2 + 12 >> 2] = d2;
            return;
          }
          function $c(a2) {
            a2 = a2 | 0;
            var c2 = 0, d2 = 0, f2 = 0, g2 = 0, h = 0, i = 0, j = 0;
            g2 = a2 + 4 | 0;
            h = a2 + 12 | 0;
            i = a2 + 8 | 0;
            a: while (1) {
              d2 = b[g2 >> 2] | 0;
              c2 = 0;
              while (1) {
                if ((c2 | 0) >= (d2 | 0)) {
                  break a;
                }
                f2 = b[a2 >> 2] | 0;
                j = b[f2 + (c2 << 2) >> 2] | 0;
                if (!j) {
                  c2 = c2 + 1 | 0;
                } else {
                  break;
                }
              }
              c2 = f2 + (~~(+q(+(+s(10, + +(15 - (b[h >> 2] | 0) | 0)) * (+e[j >> 3] + +e[j + 8 >> 3]))) % +(d2 | 0)) >>> 0 << 2) | 0;
              d2 = b[c2 >> 2] | 0;
              b: do {
                if (d2 | 0) {
                  f2 = j + 32 | 0;
                  if ((d2 | 0) == (j | 0)) {
                    b[c2 >> 2] = b[f2 >> 2];
                  } else {
                    d2 = d2 + 32 | 0;
                    c2 = b[d2 >> 2] | 0;
                    if (!c2) {
                      break;
                    }
                    while (1) {
                      if ((c2 | 0) == (j | 0)) {
                        break;
                      }
                      d2 = c2 + 32 | 0;
                      c2 = b[d2 >> 2] | 0;
                      if (!c2) {
                        break b;
                      }
                    }
                    b[d2 >> 2] = b[f2 >> 2];
                  }
                  jd(j);
                  b[i >> 2] = (b[i >> 2] | 0) + -1;
                }
              } while (0);
            }
            jd(b[a2 >> 2] | 0);
            return;
          }
          function ad(a2) {
            a2 = a2 | 0;
            var c2 = 0, d2 = 0, e2 = 0;
            e2 = b[a2 + 4 >> 2] | 0;
            d2 = 0;
            while (1) {
              if ((d2 | 0) >= (e2 | 0)) {
                c2 = 0;
                d2 = 4;
                break;
              }
              c2 = b[(b[a2 >> 2] | 0) + (d2 << 2) >> 2] | 0;
              if (!c2) {
                d2 = d2 + 1 | 0;
              } else {
                d2 = 4;
                break;
              }
            }
            if ((d2 | 0) == 4) {
              return c2 | 0;
            }
            return 0;
          }
          function bd(a2, c2) {
            a2 = a2 | 0;
            c2 = c2 | 0;
            var d2 = 0, f2 = 0, g2 = 0, h = 0;
            d2 = ~~(+q(+(+s(10, + +(15 - (b[a2 + 12 >> 2] | 0) | 0)) * (+e[c2 >> 3] + +e[c2 + 8 >> 3]))) % +(b[a2 + 4 >> 2] | 0)) >>> 0;
            d2 = (b[a2 >> 2] | 0) + (d2 << 2) | 0;
            f2 = b[d2 >> 2] | 0;
            if (!f2) {
              h = 1;
              return h | 0;
            }
            h = c2 + 32 | 0;
            do {
              if ((f2 | 0) != (c2 | 0)) {
                d2 = b[f2 + 32 >> 2] | 0;
                if (!d2) {
                  h = 1;
                  return h | 0;
                }
                g2 = d2;
                while (1) {
                  if ((g2 | 0) == (c2 | 0)) {
                    g2 = 8;
                    break;
                  }
                  d2 = b[g2 + 32 >> 2] | 0;
                  if (!d2) {
                    d2 = 1;
                    g2 = 10;
                    break;
                  } else {
                    f2 = g2;
                    g2 = d2;
                  }
                }
                if ((g2 | 0) == 8) {
                  b[f2 + 32 >> 2] = b[h >> 2];
                  break;
                } else if ((g2 | 0) == 10) {
                  return d2 | 0;
                }
              } else {
                b[d2 >> 2] = b[h >> 2];
              }
            } while (0);
            jd(c2);
            h = a2 + 8 | 0;
            b[h >> 2] = (b[h >> 2] | 0) + -1;
            h = 0;
            return h | 0;
          }
          function cd(a2, c2, d2) {
            a2 = a2 | 0;
            c2 = c2 | 0;
            d2 = d2 | 0;
            var f2 = 0, g2 = 0, h = 0, i = 0;
            h = id(40) | 0;
            if (!h) {
              I(23390, 23360, 98, 23403);
            }
            b[h >> 2] = b[c2 >> 2];
            b[h + 4 >> 2] = b[c2 + 4 >> 2];
            b[h + 8 >> 2] = b[c2 + 8 >> 2];
            b[h + 12 >> 2] = b[c2 + 12 >> 2];
            g2 = h + 16 | 0;
            b[g2 >> 2] = b[d2 >> 2];
            b[g2 + 4 >> 2] = b[d2 + 4 >> 2];
            b[g2 + 8 >> 2] = b[d2 + 8 >> 2];
            b[g2 + 12 >> 2] = b[d2 + 12 >> 2];
            b[h + 32 >> 2] = 0;
            g2 = ~~(+q(+(+s(10, + +(15 - (b[a2 + 12 >> 2] | 0) | 0)) * (+e[c2 >> 3] + +e[c2 + 8 >> 3]))) % +(b[a2 + 4 >> 2] | 0)) >>> 0;
            g2 = (b[a2 >> 2] | 0) + (g2 << 2) | 0;
            f2 = b[g2 >> 2] | 0;
            do {
              if (!f2) {
                b[g2 >> 2] = h;
              } else {
                while (1) {
                  if (_b(f2, c2) | 0 ? _b(f2 + 16 | 0, d2) | 0 : 0) {
                    break;
                  }
                  g2 = b[f2 + 32 >> 2] | 0;
                  f2 = (g2 | 0) == 0 ? f2 : g2;
                  if (!(b[f2 + 32 >> 2] | 0)) {
                    i = 10;
                    break;
                  }
                }
                if ((i | 0) == 10) {
                  b[f2 + 32 >> 2] = h;
                  break;
                }
                jd(h);
                i = f2;
                return i | 0;
              }
            } while (0);
            i = a2 + 8 | 0;
            b[i >> 2] = (b[i >> 2] | 0) + 1;
            i = h;
            return i | 0;
          }
          function dd(a2, c2, d2) {
            a2 = a2 | 0;
            c2 = c2 | 0;
            d2 = d2 | 0;
            var f2 = 0, g2 = 0;
            g2 = ~~(+q(+(+s(10, + +(15 - (b[a2 + 12 >> 2] | 0) | 0)) * (+e[c2 >> 3] + +e[c2 + 8 >> 3]))) % +(b[a2 + 4 >> 2] | 0)) >>> 0;
            g2 = b[(b[a2 >> 2] | 0) + (g2 << 2) >> 2] | 0;
            if (!g2) {
              d2 = 0;
              return d2 | 0;
            }
            if (!d2) {
              a2 = g2;
              while (1) {
                if (_b(a2, c2) | 0) {
                  f2 = 10;
                  break;
                }
                a2 = b[a2 + 32 >> 2] | 0;
                if (!a2) {
                  a2 = 0;
                  f2 = 10;
                  break;
                }
              }
              if ((f2 | 0) == 10) {
                return a2 | 0;
              }
            }
            a2 = g2;
            while (1) {
              if (_b(a2, c2) | 0 ? _b(a2 + 16 | 0, d2) | 0 : 0) {
                f2 = 10;
                break;
              }
              a2 = b[a2 + 32 >> 2] | 0;
              if (!a2) {
                a2 = 0;
                f2 = 10;
                break;
              }
            }
            if ((f2 | 0) == 10) {
              return a2 | 0;
            }
            return 0;
          }
          function ed(a2, c2) {
            a2 = a2 | 0;
            c2 = c2 | 0;
            var d2 = 0;
            d2 = ~~(+q(+(+s(10, + +(15 - (b[a2 + 12 >> 2] | 0) | 0)) * (+e[c2 >> 3] + +e[c2 + 8 >> 3]))) % +(b[a2 + 4 >> 2] | 0)) >>> 0;
            a2 = b[(b[a2 >> 2] | 0) + (d2 << 2) >> 2] | 0;
            if (!a2) {
              d2 = 0;
              return d2 | 0;
            }
            while (1) {
              if (_b(a2, c2) | 0) {
                c2 = 5;
                break;
              }
              a2 = b[a2 + 32 >> 2] | 0;
              if (!a2) {
                a2 = 0;
                c2 = 5;
                break;
              }
            }
            if ((c2 | 0) == 5) {
              return a2 | 0;
            }
            return 0;
          }
          function fd() {
            return 23424;
          }
          function gd(a2) {
            a2 = +a2;
            return + +Cd(+a2);
          }
          function hd(a2) {
            a2 = +a2;
            return ~~+gd(a2) | 0;
          }
          function id(a2) {
            a2 = a2 | 0;
            var c2 = 0, d2 = 0, e2 = 0, f2 = 0, g2 = 0, h = 0, i = 0, j = 0, k = 0, l = 0, m = 0, n = 0, o = 0, p2 = 0, q2 = 0, r2 = 0, s2 = 0, t2 = 0, u2 = 0, v2 = 0, w2 = 0;
            w2 = T;
            T = T + 16 | 0;
            n = w2;
            do {
              if (a2 >>> 0 < 245) {
                k = a2 >>> 0 < 11 ? 16 : a2 + 11 & -8;
                a2 = k >>> 3;
                m = b[5857] | 0;
                d2 = m >>> a2;
                if (d2 & 3 | 0) {
                  c2 = (d2 & 1 ^ 1) + a2 | 0;
                  a2 = 23468 + (c2 << 1 << 2) | 0;
                  d2 = a2 + 8 | 0;
                  e2 = b[d2 >> 2] | 0;
                  f2 = e2 + 8 | 0;
                  g2 = b[f2 >> 2] | 0;
                  if ((g2 | 0) == (a2 | 0)) {
                    b[5857] = m & ~(1 << c2);
                  } else {
                    b[g2 + 12 >> 2] = a2;
                    b[d2 >> 2] = g2;
                  }
                  v2 = c2 << 3;
                  b[e2 + 4 >> 2] = v2 | 3;
                  v2 = e2 + v2 + 4 | 0;
                  b[v2 >> 2] = b[v2 >> 2] | 1;
                  v2 = f2;
                  T = w2;
                  return v2 | 0;
                }
                l = b[5859] | 0;
                if (k >>> 0 > l >>> 0) {
                  if (d2 | 0) {
                    c2 = 2 << a2;
                    c2 = d2 << a2 & (c2 | 0 - c2);
                    c2 = (c2 & 0 - c2) + -1 | 0;
                    i = c2 >>> 12 & 16;
                    c2 = c2 >>> i;
                    d2 = c2 >>> 5 & 8;
                    c2 = c2 >>> d2;
                    g2 = c2 >>> 2 & 4;
                    c2 = c2 >>> g2;
                    a2 = c2 >>> 1 & 2;
                    c2 = c2 >>> a2;
                    e2 = c2 >>> 1 & 1;
                    e2 = (d2 | i | g2 | a2 | e2) + (c2 >>> e2) | 0;
                    c2 = 23468 + (e2 << 1 << 2) | 0;
                    a2 = c2 + 8 | 0;
                    g2 = b[a2 >> 2] | 0;
                    i = g2 + 8 | 0;
                    d2 = b[i >> 2] | 0;
                    if ((d2 | 0) == (c2 | 0)) {
                      a2 = m & ~(1 << e2);
                      b[5857] = a2;
                    } else {
                      b[d2 + 12 >> 2] = c2;
                      b[a2 >> 2] = d2;
                      a2 = m;
                    }
                    v2 = e2 << 3;
                    h = v2 - k | 0;
                    b[g2 + 4 >> 2] = k | 3;
                    f2 = g2 + k | 0;
                    b[f2 + 4 >> 2] = h | 1;
                    b[g2 + v2 >> 2] = h;
                    if (l | 0) {
                      e2 = b[5862] | 0;
                      c2 = l >>> 3;
                      d2 = 23468 + (c2 << 1 << 2) | 0;
                      c2 = 1 << c2;
                      if (!(a2 & c2)) {
                        b[5857] = a2 | c2;
                        c2 = d2;
                        a2 = d2 + 8 | 0;
                      } else {
                        a2 = d2 + 8 | 0;
                        c2 = b[a2 >> 2] | 0;
                      }
                      b[a2 >> 2] = e2;
                      b[c2 + 12 >> 2] = e2;
                      b[e2 + 8 >> 2] = c2;
                      b[e2 + 12 >> 2] = d2;
                    }
                    b[5859] = h;
                    b[5862] = f2;
                    v2 = i;
                    T = w2;
                    return v2 | 0;
                  }
                  g2 = b[5858] | 0;
                  if (g2) {
                    d2 = (g2 & 0 - g2) + -1 | 0;
                    f2 = d2 >>> 12 & 16;
                    d2 = d2 >>> f2;
                    e2 = d2 >>> 5 & 8;
                    d2 = d2 >>> e2;
                    h = d2 >>> 2 & 4;
                    d2 = d2 >>> h;
                    i = d2 >>> 1 & 2;
                    d2 = d2 >>> i;
                    j = d2 >>> 1 & 1;
                    j = b[23732 + ((e2 | f2 | h | i | j) + (d2 >>> j) << 2) >> 2] | 0;
                    d2 = j;
                    i = j;
                    j = (b[j + 4 >> 2] & -8) - k | 0;
                    while (1) {
                      a2 = b[d2 + 16 >> 2] | 0;
                      if (!a2) {
                        a2 = b[d2 + 20 >> 2] | 0;
                        if (!a2) {
                          break;
                        }
                      }
                      h = (b[a2 + 4 >> 2] & -8) - k | 0;
                      f2 = h >>> 0 < j >>> 0;
                      d2 = a2;
                      i = f2 ? a2 : i;
                      j = f2 ? h : j;
                    }
                    h = i + k | 0;
                    if (h >>> 0 > i >>> 0) {
                      f2 = b[i + 24 >> 2] | 0;
                      c2 = b[i + 12 >> 2] | 0;
                      do {
                        if ((c2 | 0) == (i | 0)) {
                          a2 = i + 20 | 0;
                          c2 = b[a2 >> 2] | 0;
                          if (!c2) {
                            a2 = i + 16 | 0;
                            c2 = b[a2 >> 2] | 0;
                            if (!c2) {
                              d2 = 0;
                              break;
                            }
                          }
                          while (1) {
                            e2 = c2 + 20 | 0;
                            d2 = b[e2 >> 2] | 0;
                            if (!d2) {
                              e2 = c2 + 16 | 0;
                              d2 = b[e2 >> 2] | 0;
                              if (!d2) {
                                break;
                              } else {
                                c2 = d2;
                                a2 = e2;
                              }
                            } else {
                              c2 = d2;
                              a2 = e2;
                            }
                          }
                          b[a2 >> 2] = 0;
                          d2 = c2;
                        } else {
                          d2 = b[i + 8 >> 2] | 0;
                          b[d2 + 12 >> 2] = c2;
                          b[c2 + 8 >> 2] = d2;
                          d2 = c2;
                        }
                      } while (0);
                      do {
                        if (f2 | 0) {
                          c2 = b[i + 28 >> 2] | 0;
                          a2 = 23732 + (c2 << 2) | 0;
                          if ((i | 0) == (b[a2 >> 2] | 0)) {
                            b[a2 >> 2] = d2;
                            if (!d2) {
                              b[5858] = g2 & ~(1 << c2);
                              break;
                            }
                          } else {
                            v2 = f2 + 16 | 0;
                            b[((b[v2 >> 2] | 0) == (i | 0) ? v2 : f2 + 20 | 0) >> 2] = d2;
                            if (!d2) {
                              break;
                            }
                          }
                          b[d2 + 24 >> 2] = f2;
                          c2 = b[i + 16 >> 2] | 0;
                          if (c2 | 0) {
                            b[d2 + 16 >> 2] = c2;
                            b[c2 + 24 >> 2] = d2;
                          }
                          c2 = b[i + 20 >> 2] | 0;
                          if (c2 | 0) {
                            b[d2 + 20 >> 2] = c2;
                            b[c2 + 24 >> 2] = d2;
                          }
                        }
                      } while (0);
                      if (j >>> 0 < 16) {
                        v2 = j + k | 0;
                        b[i + 4 >> 2] = v2 | 3;
                        v2 = i + v2 + 4 | 0;
                        b[v2 >> 2] = b[v2 >> 2] | 1;
                      } else {
                        b[i + 4 >> 2] = k | 3;
                        b[h + 4 >> 2] = j | 1;
                        b[h + j >> 2] = j;
                        if (l | 0) {
                          e2 = b[5862] | 0;
                          c2 = l >>> 3;
                          d2 = 23468 + (c2 << 1 << 2) | 0;
                          c2 = 1 << c2;
                          if (!(c2 & m)) {
                            b[5857] = c2 | m;
                            c2 = d2;
                            a2 = d2 + 8 | 0;
                          } else {
                            a2 = d2 + 8 | 0;
                            c2 = b[a2 >> 2] | 0;
                          }
                          b[a2 >> 2] = e2;
                          b[c2 + 12 >> 2] = e2;
                          b[e2 + 8 >> 2] = c2;
                          b[e2 + 12 >> 2] = d2;
                        }
                        b[5859] = j;
                        b[5862] = h;
                      }
                      v2 = i + 8 | 0;
                      T = w2;
                      return v2 | 0;
                    } else {
                      m = k;
                    }
                  } else {
                    m = k;
                  }
                } else {
                  m = k;
                }
              } else if (a2 >>> 0 <= 4294967231) {
                a2 = a2 + 11 | 0;
                k = a2 & -8;
                e2 = b[5858] | 0;
                if (e2) {
                  f2 = 0 - k | 0;
                  a2 = a2 >>> 8;
                  if (a2) {
                    if (k >>> 0 > 16777215) {
                      j = 31;
                    } else {
                      m = (a2 + 1048320 | 0) >>> 16 & 8;
                      q2 = a2 << m;
                      i = (q2 + 520192 | 0) >>> 16 & 4;
                      q2 = q2 << i;
                      j = (q2 + 245760 | 0) >>> 16 & 2;
                      j = 14 - (i | m | j) + (q2 << j >>> 15) | 0;
                      j = k >>> (j + 7 | 0) & 1 | j << 1;
                    }
                  } else {
                    j = 0;
                  }
                  d2 = b[23732 + (j << 2) >> 2] | 0;
                  a: do {
                    if (!d2) {
                      d2 = 0;
                      a2 = 0;
                      q2 = 61;
                    } else {
                      a2 = 0;
                      i = k << ((j | 0) == 31 ? 0 : 25 - (j >>> 1) | 0);
                      g2 = 0;
                      while (1) {
                        h = (b[d2 + 4 >> 2] & -8) - k | 0;
                        if (h >>> 0 < f2 >>> 0) {
                          if (!h) {
                            a2 = d2;
                            f2 = 0;
                            q2 = 65;
                            break a;
                          } else {
                            a2 = d2;
                            f2 = h;
                          }
                        }
                        q2 = b[d2 + 20 >> 2] | 0;
                        d2 = b[d2 + 16 + (i >>> 31 << 2) >> 2] | 0;
                        g2 = (q2 | 0) == 0 | (q2 | 0) == (d2 | 0) ? g2 : q2;
                        if (!d2) {
                          d2 = g2;
                          q2 = 61;
                          break;
                        } else {
                          i = i << 1;
                        }
                      }
                    }
                  } while (0);
                  if ((q2 | 0) == 61) {
                    if ((d2 | 0) == 0 & (a2 | 0) == 0) {
                      a2 = 2 << j;
                      a2 = (a2 | 0 - a2) & e2;
                      if (!a2) {
                        m = k;
                        break;
                      }
                      m = (a2 & 0 - a2) + -1 | 0;
                      h = m >>> 12 & 16;
                      m = m >>> h;
                      g2 = m >>> 5 & 8;
                      m = m >>> g2;
                      i = m >>> 2 & 4;
                      m = m >>> i;
                      j = m >>> 1 & 2;
                      m = m >>> j;
                      d2 = m >>> 1 & 1;
                      a2 = 0;
                      d2 = b[23732 + ((g2 | h | i | j | d2) + (m >>> d2) << 2) >> 2] | 0;
                    }
                    if (!d2) {
                      i = a2;
                      h = f2;
                    } else {
                      q2 = 65;
                    }
                  }
                  if ((q2 | 0) == 65) {
                    g2 = d2;
                    while (1) {
                      m = (b[g2 + 4 >> 2] & -8) - k | 0;
                      d2 = m >>> 0 < f2 >>> 0;
                      f2 = d2 ? m : f2;
                      a2 = d2 ? g2 : a2;
                      d2 = b[g2 + 16 >> 2] | 0;
                      if (!d2) {
                        d2 = b[g2 + 20 >> 2] | 0;
                      }
                      if (!d2) {
                        i = a2;
                        h = f2;
                        break;
                      } else {
                        g2 = d2;
                      }
                    }
                  }
                  if (((i | 0) != 0 ? h >>> 0 < ((b[5859] | 0) - k | 0) >>> 0 : 0) ? (l = i + k | 0, l >>> 0 > i >>> 0) : 0) {
                    g2 = b[i + 24 >> 2] | 0;
                    c2 = b[i + 12 >> 2] | 0;
                    do {
                      if ((c2 | 0) == (i | 0)) {
                        a2 = i + 20 | 0;
                        c2 = b[a2 >> 2] | 0;
                        if (!c2) {
                          a2 = i + 16 | 0;
                          c2 = b[a2 >> 2] | 0;
                          if (!c2) {
                            c2 = 0;
                            break;
                          }
                        }
                        while (1) {
                          f2 = c2 + 20 | 0;
                          d2 = b[f2 >> 2] | 0;
                          if (!d2) {
                            f2 = c2 + 16 | 0;
                            d2 = b[f2 >> 2] | 0;
                            if (!d2) {
                              break;
                            } else {
                              c2 = d2;
                              a2 = f2;
                            }
                          } else {
                            c2 = d2;
                            a2 = f2;
                          }
                        }
                        b[a2 >> 2] = 0;
                      } else {
                        v2 = b[i + 8 >> 2] | 0;
                        b[v2 + 12 >> 2] = c2;
                        b[c2 + 8 >> 2] = v2;
                      }
                    } while (0);
                    do {
                      if (g2) {
                        a2 = b[i + 28 >> 2] | 0;
                        d2 = 23732 + (a2 << 2) | 0;
                        if ((i | 0) == (b[d2 >> 2] | 0)) {
                          b[d2 >> 2] = c2;
                          if (!c2) {
                            e2 = e2 & ~(1 << a2);
                            b[5858] = e2;
                            break;
                          }
                        } else {
                          v2 = g2 + 16 | 0;
                          b[((b[v2 >> 2] | 0) == (i | 0) ? v2 : g2 + 20 | 0) >> 2] = c2;
                          if (!c2) {
                            break;
                          }
                        }
                        b[c2 + 24 >> 2] = g2;
                        a2 = b[i + 16 >> 2] | 0;
                        if (a2 | 0) {
                          b[c2 + 16 >> 2] = a2;
                          b[a2 + 24 >> 2] = c2;
                        }
                        a2 = b[i + 20 >> 2] | 0;
                        if (a2) {
                          b[c2 + 20 >> 2] = a2;
                          b[a2 + 24 >> 2] = c2;
                        }
                      }
                    } while (0);
                    b: do {
                      if (h >>> 0 < 16) {
                        v2 = h + k | 0;
                        b[i + 4 >> 2] = v2 | 3;
                        v2 = i + v2 + 4 | 0;
                        b[v2 >> 2] = b[v2 >> 2] | 1;
                      } else {
                        b[i + 4 >> 2] = k | 3;
                        b[l + 4 >> 2] = h | 1;
                        b[l + h >> 2] = h;
                        c2 = h >>> 3;
                        if (h >>> 0 < 256) {
                          d2 = 23468 + (c2 << 1 << 2) | 0;
                          a2 = b[5857] | 0;
                          c2 = 1 << c2;
                          if (!(a2 & c2)) {
                            b[5857] = a2 | c2;
                            c2 = d2;
                            a2 = d2 + 8 | 0;
                          } else {
                            a2 = d2 + 8 | 0;
                            c2 = b[a2 >> 2] | 0;
                          }
                          b[a2 >> 2] = l;
                          b[c2 + 12 >> 2] = l;
                          b[l + 8 >> 2] = c2;
                          b[l + 12 >> 2] = d2;
                          break;
                        }
                        c2 = h >>> 8;
                        if (c2) {
                          if (h >>> 0 > 16777215) {
                            d2 = 31;
                          } else {
                            u2 = (c2 + 1048320 | 0) >>> 16 & 8;
                            v2 = c2 << u2;
                            t2 = (v2 + 520192 | 0) >>> 16 & 4;
                            v2 = v2 << t2;
                            d2 = (v2 + 245760 | 0) >>> 16 & 2;
                            d2 = 14 - (t2 | u2 | d2) + (v2 << d2 >>> 15) | 0;
                            d2 = h >>> (d2 + 7 | 0) & 1 | d2 << 1;
                          }
                        } else {
                          d2 = 0;
                        }
                        c2 = 23732 + (d2 << 2) | 0;
                        b[l + 28 >> 2] = d2;
                        a2 = l + 16 | 0;
                        b[a2 + 4 >> 2] = 0;
                        b[a2 >> 2] = 0;
                        a2 = 1 << d2;
                        if (!(e2 & a2)) {
                          b[5858] = e2 | a2;
                          b[c2 >> 2] = l;
                          b[l + 24 >> 2] = c2;
                          b[l + 12 >> 2] = l;
                          b[l + 8 >> 2] = l;
                          break;
                        }
                        c2 = b[c2 >> 2] | 0;
                        c: do {
                          if ((b[c2 + 4 >> 2] & -8 | 0) != (h | 0)) {
                            e2 = h << ((d2 | 0) == 31 ? 0 : 25 - (d2 >>> 1) | 0);
                            while (1) {
                              d2 = c2 + 16 + (e2 >>> 31 << 2) | 0;
                              a2 = b[d2 >> 2] | 0;
                              if (!a2) {
                                break;
                              }
                              if ((b[a2 + 4 >> 2] & -8 | 0) == (h | 0)) {
                                c2 = a2;
                                break c;
                              } else {
                                e2 = e2 << 1;
                                c2 = a2;
                              }
                            }
                            b[d2 >> 2] = l;
                            b[l + 24 >> 2] = c2;
                            b[l + 12 >> 2] = l;
                            b[l + 8 >> 2] = l;
                            break b;
                          }
                        } while (0);
                        u2 = c2 + 8 | 0;
                        v2 = b[u2 >> 2] | 0;
                        b[v2 + 12 >> 2] = l;
                        b[u2 >> 2] = l;
                        b[l + 8 >> 2] = v2;
                        b[l + 12 >> 2] = c2;
                        b[l + 24 >> 2] = 0;
                      }
                    } while (0);
                    v2 = i + 8 | 0;
                    T = w2;
                    return v2 | 0;
                  } else {
                    m = k;
                  }
                } else {
                  m = k;
                }
              } else {
                m = -1;
              }
            } while (0);
            d2 = b[5859] | 0;
            if (d2 >>> 0 >= m >>> 0) {
              c2 = d2 - m | 0;
              a2 = b[5862] | 0;
              if (c2 >>> 0 > 15) {
                v2 = a2 + m | 0;
                b[5862] = v2;
                b[5859] = c2;
                b[v2 + 4 >> 2] = c2 | 1;
                b[a2 + d2 >> 2] = c2;
                b[a2 + 4 >> 2] = m | 3;
              } else {
                b[5859] = 0;
                b[5862] = 0;
                b[a2 + 4 >> 2] = d2 | 3;
                v2 = a2 + d2 + 4 | 0;
                b[v2 >> 2] = b[v2 >> 2] | 1;
              }
              v2 = a2 + 8 | 0;
              T = w2;
              return v2 | 0;
            }
            h = b[5860] | 0;
            if (h >>> 0 > m >>> 0) {
              t2 = h - m | 0;
              b[5860] = t2;
              v2 = b[5863] | 0;
              u2 = v2 + m | 0;
              b[5863] = u2;
              b[u2 + 4 >> 2] = t2 | 1;
              b[v2 + 4 >> 2] = m | 3;
              v2 = v2 + 8 | 0;
              T = w2;
              return v2 | 0;
            }
            if (!(b[5975] | 0)) {
              b[5977] = 4096;
              b[5976] = 4096;
              b[5978] = -1;
              b[5979] = -1;
              b[5980] = 0;
              b[5968] = 0;
              b[5975] = n & -16 ^ 1431655768;
              a2 = 4096;
            } else {
              a2 = b[5977] | 0;
            }
            i = m + 48 | 0;
            j = m + 47 | 0;
            g2 = a2 + j | 0;
            f2 = 0 - a2 | 0;
            k = g2 & f2;
            if (k >>> 0 <= m >>> 0) {
              v2 = 0;
              T = w2;
              return v2 | 0;
            }
            a2 = b[5967] | 0;
            if (a2 | 0 ? (l = b[5965] | 0, n = l + k | 0, n >>> 0 <= l >>> 0 | n >>> 0 > a2 >>> 0) : 0) {
              v2 = 0;
              T = w2;
              return v2 | 0;
            }
            d: do {
              if (!(b[5968] & 4)) {
                d2 = b[5863] | 0;
                e: do {
                  if (d2) {
                    e2 = 23876;
                    while (1) {
                      n = b[e2 >> 2] | 0;
                      if (n >>> 0 <= d2 >>> 0 ? (n + (b[e2 + 4 >> 2] | 0) | 0) >>> 0 > d2 >>> 0 : 0) {
                        break;
                      }
                      a2 = b[e2 + 8 >> 2] | 0;
                      if (!a2) {
                        q2 = 128;
                        break e;
                      } else {
                        e2 = a2;
                      }
                    }
                    c2 = g2 - h & f2;
                    if (c2 >>> 0 < 2147483647) {
                      a2 = Dd(c2 | 0) | 0;
                      if ((a2 | 0) == ((b[e2 >> 2] | 0) + (b[e2 + 4 >> 2] | 0) | 0)) {
                        if ((a2 | 0) != (-1 | 0)) {
                          h = c2;
                          g2 = a2;
                          q2 = 145;
                          break d;
                        }
                      } else {
                        e2 = a2;
                        q2 = 136;
                      }
                    } else {
                      c2 = 0;
                    }
                  } else {
                    q2 = 128;
                  }
                } while (0);
                do {
                  if ((q2 | 0) == 128) {
                    d2 = Dd(0) | 0;
                    if ((d2 | 0) != (-1 | 0) ? (c2 = d2, o = b[5976] | 0, p2 = o + -1 | 0, c2 = ((p2 & c2 | 0) == 0 ? 0 : (p2 + c2 & 0 - o) - c2 | 0) + k | 0, o = b[5965] | 0, p2 = c2 + o | 0, c2 >>> 0 > m >>> 0 & c2 >>> 0 < 2147483647) : 0) {
                      n = b[5967] | 0;
                      if (n | 0 ? p2 >>> 0 <= o >>> 0 | p2 >>> 0 > n >>> 0 : 0) {
                        c2 = 0;
                        break;
                      }
                      a2 = Dd(c2 | 0) | 0;
                      if ((a2 | 0) == (d2 | 0)) {
                        h = c2;
                        g2 = d2;
                        q2 = 145;
                        break d;
                      } else {
                        e2 = a2;
                        q2 = 136;
                      }
                    } else {
                      c2 = 0;
                    }
                  }
                } while (0);
                do {
                  if ((q2 | 0) == 136) {
                    d2 = 0 - c2 | 0;
                    if (!(i >>> 0 > c2 >>> 0 & (c2 >>> 0 < 2147483647 & (e2 | 0) != (-1 | 0)))) {
                      if ((e2 | 0) == (-1 | 0)) {
                        c2 = 0;
                        break;
                      } else {
                        h = c2;
                        g2 = e2;
                        q2 = 145;
                        break d;
                      }
                    }
                    a2 = b[5977] | 0;
                    a2 = j - c2 + a2 & 0 - a2;
                    if (a2 >>> 0 >= 2147483647) {
                      h = c2;
                      g2 = e2;
                      q2 = 145;
                      break d;
                    }
                    if ((Dd(a2 | 0) | 0) == (-1 | 0)) {
                      Dd(d2 | 0) | 0;
                      c2 = 0;
                      break;
                    } else {
                      h = a2 + c2 | 0;
                      g2 = e2;
                      q2 = 145;
                      break d;
                    }
                  }
                } while (0);
                b[5968] = b[5968] | 4;
                q2 = 143;
              } else {
                c2 = 0;
                q2 = 143;
              }
            } while (0);
            if (((q2 | 0) == 143 ? k >>> 0 < 2147483647 : 0) ? (t2 = Dd(k | 0) | 0, p2 = Dd(0) | 0, r2 = p2 - t2 | 0, s2 = r2 >>> 0 > (m + 40 | 0) >>> 0, !((t2 | 0) == (-1 | 0) | s2 ^ 1 | t2 >>> 0 < p2 >>> 0 & ((t2 | 0) != (-1 | 0) & (p2 | 0) != (-1 | 0)) ^ 1)) : 0) {
              h = s2 ? r2 : c2;
              g2 = t2;
              q2 = 145;
            }
            if ((q2 | 0) == 145) {
              c2 = (b[5965] | 0) + h | 0;
              b[5965] = c2;
              if (c2 >>> 0 > (b[5966] | 0) >>> 0) {
                b[5966] = c2;
              }
              j = b[5863] | 0;
              f: do {
                if (j) {
                  c2 = 23876;
                  while (1) {
                    a2 = b[c2 >> 2] | 0;
                    d2 = b[c2 + 4 >> 2] | 0;
                    if ((g2 | 0) == (a2 + d2 | 0)) {
                      q2 = 154;
                      break;
                    }
                    e2 = b[c2 + 8 >> 2] | 0;
                    if (!e2) {
                      break;
                    } else {
                      c2 = e2;
                    }
                  }
                  if (((q2 | 0) == 154 ? (u2 = c2 + 4 | 0, (b[c2 + 12 >> 2] & 8 | 0) == 0) : 0) ? g2 >>> 0 > j >>> 0 & a2 >>> 0 <= j >>> 0 : 0) {
                    b[u2 >> 2] = d2 + h;
                    v2 = (b[5860] | 0) + h | 0;
                    t2 = j + 8 | 0;
                    t2 = (t2 & 7 | 0) == 0 ? 0 : 0 - t2 & 7;
                    u2 = j + t2 | 0;
                    t2 = v2 - t2 | 0;
                    b[5863] = u2;
                    b[5860] = t2;
                    b[u2 + 4 >> 2] = t2 | 1;
                    b[j + v2 + 4 >> 2] = 40;
                    b[5864] = b[5979];
                    break;
                  }
                  if (g2 >>> 0 < (b[5861] | 0) >>> 0) {
                    b[5861] = g2;
                  }
                  d2 = g2 + h | 0;
                  c2 = 23876;
                  while (1) {
                    if ((b[c2 >> 2] | 0) == (d2 | 0)) {
                      q2 = 162;
                      break;
                    }
                    a2 = b[c2 + 8 >> 2] | 0;
                    if (!a2) {
                      break;
                    } else {
                      c2 = a2;
                    }
                  }
                  if ((q2 | 0) == 162 ? (b[c2 + 12 >> 2] & 8 | 0) == 0 : 0) {
                    b[c2 >> 2] = g2;
                    l = c2 + 4 | 0;
                    b[l >> 2] = (b[l >> 2] | 0) + h;
                    l = g2 + 8 | 0;
                    l = g2 + ((l & 7 | 0) == 0 ? 0 : 0 - l & 7) | 0;
                    c2 = d2 + 8 | 0;
                    c2 = d2 + ((c2 & 7 | 0) == 0 ? 0 : 0 - c2 & 7) | 0;
                    k = l + m | 0;
                    i = c2 - l - m | 0;
                    b[l + 4 >> 2] = m | 3;
                    g: do {
                      if ((j | 0) == (c2 | 0)) {
                        v2 = (b[5860] | 0) + i | 0;
                        b[5860] = v2;
                        b[5863] = k;
                        b[k + 4 >> 2] = v2 | 1;
                      } else {
                        if ((b[5862] | 0) == (c2 | 0)) {
                          v2 = (b[5859] | 0) + i | 0;
                          b[5859] = v2;
                          b[5862] = k;
                          b[k + 4 >> 2] = v2 | 1;
                          b[k + v2 >> 2] = v2;
                          break;
                        }
                        a2 = b[c2 + 4 >> 2] | 0;
                        if ((a2 & 3 | 0) == 1) {
                          h = a2 & -8;
                          e2 = a2 >>> 3;
                          h: do {
                            if (a2 >>> 0 < 256) {
                              a2 = b[c2 + 8 >> 2] | 0;
                              d2 = b[c2 + 12 >> 2] | 0;
                              if ((d2 | 0) == (a2 | 0)) {
                                b[5857] = b[5857] & ~(1 << e2);
                                break;
                              } else {
                                b[a2 + 12 >> 2] = d2;
                                b[d2 + 8 >> 2] = a2;
                                break;
                              }
                            } else {
                              g2 = b[c2 + 24 >> 2] | 0;
                              a2 = b[c2 + 12 >> 2] | 0;
                              do {
                                if ((a2 | 0) == (c2 | 0)) {
                                  d2 = c2 + 16 | 0;
                                  e2 = d2 + 4 | 0;
                                  a2 = b[e2 >> 2] | 0;
                                  if (!a2) {
                                    a2 = b[d2 >> 2] | 0;
                                    if (!a2) {
                                      a2 = 0;
                                      break;
                                    }
                                  } else {
                                    d2 = e2;
                                  }
                                  while (1) {
                                    f2 = a2 + 20 | 0;
                                    e2 = b[f2 >> 2] | 0;
                                    if (!e2) {
                                      f2 = a2 + 16 | 0;
                                      e2 = b[f2 >> 2] | 0;
                                      if (!e2) {
                                        break;
                                      } else {
                                        a2 = e2;
                                        d2 = f2;
                                      }
                                    } else {
                                      a2 = e2;
                                      d2 = f2;
                                    }
                                  }
                                  b[d2 >> 2] = 0;
                                } else {
                                  v2 = b[c2 + 8 >> 2] | 0;
                                  b[v2 + 12 >> 2] = a2;
                                  b[a2 + 8 >> 2] = v2;
                                }
                              } while (0);
                              if (!g2) {
                                break;
                              }
                              d2 = b[c2 + 28 >> 2] | 0;
                              e2 = 23732 + (d2 << 2) | 0;
                              do {
                                if ((b[e2 >> 2] | 0) != (c2 | 0)) {
                                  v2 = g2 + 16 | 0;
                                  b[((b[v2 >> 2] | 0) == (c2 | 0) ? v2 : g2 + 20 | 0) >> 2] = a2;
                                  if (!a2) {
                                    break h;
                                  }
                                } else {
                                  b[e2 >> 2] = a2;
                                  if (a2 | 0) {
                                    break;
                                  }
                                  b[5858] = b[5858] & ~(1 << d2);
                                  break h;
                                }
                              } while (0);
                              b[a2 + 24 >> 2] = g2;
                              d2 = c2 + 16 | 0;
                              e2 = b[d2 >> 2] | 0;
                              if (e2 | 0) {
                                b[a2 + 16 >> 2] = e2;
                                b[e2 + 24 >> 2] = a2;
                              }
                              d2 = b[d2 + 4 >> 2] | 0;
                              if (!d2) {
                                break;
                              }
                              b[a2 + 20 >> 2] = d2;
                              b[d2 + 24 >> 2] = a2;
                            }
                          } while (0);
                          c2 = c2 + h | 0;
                          f2 = h + i | 0;
                        } else {
                          f2 = i;
                        }
                        c2 = c2 + 4 | 0;
                        b[c2 >> 2] = b[c2 >> 2] & -2;
                        b[k + 4 >> 2] = f2 | 1;
                        b[k + f2 >> 2] = f2;
                        c2 = f2 >>> 3;
                        if (f2 >>> 0 < 256) {
                          d2 = 23468 + (c2 << 1 << 2) | 0;
                          a2 = b[5857] | 0;
                          c2 = 1 << c2;
                          if (!(a2 & c2)) {
                            b[5857] = a2 | c2;
                            c2 = d2;
                            a2 = d2 + 8 | 0;
                          } else {
                            a2 = d2 + 8 | 0;
                            c2 = b[a2 >> 2] | 0;
                          }
                          b[a2 >> 2] = k;
                          b[c2 + 12 >> 2] = k;
                          b[k + 8 >> 2] = c2;
                          b[k + 12 >> 2] = d2;
                          break;
                        }
                        c2 = f2 >>> 8;
                        do {
                          if (!c2) {
                            e2 = 0;
                          } else {
                            if (f2 >>> 0 > 16777215) {
                              e2 = 31;
                              break;
                            }
                            u2 = (c2 + 1048320 | 0) >>> 16 & 8;
                            v2 = c2 << u2;
                            t2 = (v2 + 520192 | 0) >>> 16 & 4;
                            v2 = v2 << t2;
                            e2 = (v2 + 245760 | 0) >>> 16 & 2;
                            e2 = 14 - (t2 | u2 | e2) + (v2 << e2 >>> 15) | 0;
                            e2 = f2 >>> (e2 + 7 | 0) & 1 | e2 << 1;
                          }
                        } while (0);
                        c2 = 23732 + (e2 << 2) | 0;
                        b[k + 28 >> 2] = e2;
                        a2 = k + 16 | 0;
                        b[a2 + 4 >> 2] = 0;
                        b[a2 >> 2] = 0;
                        a2 = b[5858] | 0;
                        d2 = 1 << e2;
                        if (!(a2 & d2)) {
                          b[5858] = a2 | d2;
                          b[c2 >> 2] = k;
                          b[k + 24 >> 2] = c2;
                          b[k + 12 >> 2] = k;
                          b[k + 8 >> 2] = k;
                          break;
                        }
                        c2 = b[c2 >> 2] | 0;
                        i: do {
                          if ((b[c2 + 4 >> 2] & -8 | 0) != (f2 | 0)) {
                            e2 = f2 << ((e2 | 0) == 31 ? 0 : 25 - (e2 >>> 1) | 0);
                            while (1) {
                              d2 = c2 + 16 + (e2 >>> 31 << 2) | 0;
                              a2 = b[d2 >> 2] | 0;
                              if (!a2) {
                                break;
                              }
                              if ((b[a2 + 4 >> 2] & -8 | 0) == (f2 | 0)) {
                                c2 = a2;
                                break i;
                              } else {
                                e2 = e2 << 1;
                                c2 = a2;
                              }
                            }
                            b[d2 >> 2] = k;
                            b[k + 24 >> 2] = c2;
                            b[k + 12 >> 2] = k;
                            b[k + 8 >> 2] = k;
                            break g;
                          }
                        } while (0);
                        u2 = c2 + 8 | 0;
                        v2 = b[u2 >> 2] | 0;
                        b[v2 + 12 >> 2] = k;
                        b[u2 >> 2] = k;
                        b[k + 8 >> 2] = v2;
                        b[k + 12 >> 2] = c2;
                        b[k + 24 >> 2] = 0;
                      }
                    } while (0);
                    v2 = l + 8 | 0;
                    T = w2;
                    return v2 | 0;
                  }
                  c2 = 23876;
                  while (1) {
                    a2 = b[c2 >> 2] | 0;
                    if (a2 >>> 0 <= j >>> 0 ? (v2 = a2 + (b[c2 + 4 >> 2] | 0) | 0, v2 >>> 0 > j >>> 0) : 0) {
                      break;
                    }
                    c2 = b[c2 + 8 >> 2] | 0;
                  }
                  f2 = v2 + -47 | 0;
                  a2 = f2 + 8 | 0;
                  a2 = f2 + ((a2 & 7 | 0) == 0 ? 0 : 0 - a2 & 7) | 0;
                  f2 = j + 16 | 0;
                  a2 = a2 >>> 0 < f2 >>> 0 ? j : a2;
                  c2 = a2 + 8 | 0;
                  d2 = h + -40 | 0;
                  t2 = g2 + 8 | 0;
                  t2 = (t2 & 7 | 0) == 0 ? 0 : 0 - t2 & 7;
                  u2 = g2 + t2 | 0;
                  t2 = d2 - t2 | 0;
                  b[5863] = u2;
                  b[5860] = t2;
                  b[u2 + 4 >> 2] = t2 | 1;
                  b[g2 + d2 + 4 >> 2] = 40;
                  b[5864] = b[5979];
                  d2 = a2 + 4 | 0;
                  b[d2 >> 2] = 27;
                  b[c2 >> 2] = b[5969];
                  b[c2 + 4 >> 2] = b[5970];
                  b[c2 + 8 >> 2] = b[5971];
                  b[c2 + 12 >> 2] = b[5972];
                  b[5969] = g2;
                  b[5970] = h;
                  b[5972] = 0;
                  b[5971] = c2;
                  c2 = a2 + 24 | 0;
                  do {
                    u2 = c2;
                    c2 = c2 + 4 | 0;
                    b[c2 >> 2] = 7;
                  } while ((u2 + 8 | 0) >>> 0 < v2 >>> 0);
                  if ((a2 | 0) != (j | 0)) {
                    g2 = a2 - j | 0;
                    b[d2 >> 2] = b[d2 >> 2] & -2;
                    b[j + 4 >> 2] = g2 | 1;
                    b[a2 >> 2] = g2;
                    c2 = g2 >>> 3;
                    if (g2 >>> 0 < 256) {
                      d2 = 23468 + (c2 << 1 << 2) | 0;
                      a2 = b[5857] | 0;
                      c2 = 1 << c2;
                      if (!(a2 & c2)) {
                        b[5857] = a2 | c2;
                        c2 = d2;
                        a2 = d2 + 8 | 0;
                      } else {
                        a2 = d2 + 8 | 0;
                        c2 = b[a2 >> 2] | 0;
                      }
                      b[a2 >> 2] = j;
                      b[c2 + 12 >> 2] = j;
                      b[j + 8 >> 2] = c2;
                      b[j + 12 >> 2] = d2;
                      break;
                    }
                    c2 = g2 >>> 8;
                    if (c2) {
                      if (g2 >>> 0 > 16777215) {
                        e2 = 31;
                      } else {
                        u2 = (c2 + 1048320 | 0) >>> 16 & 8;
                        v2 = c2 << u2;
                        t2 = (v2 + 520192 | 0) >>> 16 & 4;
                        v2 = v2 << t2;
                        e2 = (v2 + 245760 | 0) >>> 16 & 2;
                        e2 = 14 - (t2 | u2 | e2) + (v2 << e2 >>> 15) | 0;
                        e2 = g2 >>> (e2 + 7 | 0) & 1 | e2 << 1;
                      }
                    } else {
                      e2 = 0;
                    }
                    d2 = 23732 + (e2 << 2) | 0;
                    b[j + 28 >> 2] = e2;
                    b[j + 20 >> 2] = 0;
                    b[f2 >> 2] = 0;
                    c2 = b[5858] | 0;
                    a2 = 1 << e2;
                    if (!(c2 & a2)) {
                      b[5858] = c2 | a2;
                      b[d2 >> 2] = j;
                      b[j + 24 >> 2] = d2;
                      b[j + 12 >> 2] = j;
                      b[j + 8 >> 2] = j;
                      break;
                    }
                    c2 = b[d2 >> 2] | 0;
                    j: do {
                      if ((b[c2 + 4 >> 2] & -8 | 0) != (g2 | 0)) {
                        e2 = g2 << ((e2 | 0) == 31 ? 0 : 25 - (e2 >>> 1) | 0);
                        while (1) {
                          d2 = c2 + 16 + (e2 >>> 31 << 2) | 0;
                          a2 = b[d2 >> 2] | 0;
                          if (!a2) {
                            break;
                          }
                          if ((b[a2 + 4 >> 2] & -8 | 0) == (g2 | 0)) {
                            c2 = a2;
                            break j;
                          } else {
                            e2 = e2 << 1;
                            c2 = a2;
                          }
                        }
                        b[d2 >> 2] = j;
                        b[j + 24 >> 2] = c2;
                        b[j + 12 >> 2] = j;
                        b[j + 8 >> 2] = j;
                        break f;
                      }
                    } while (0);
                    u2 = c2 + 8 | 0;
                    v2 = b[u2 >> 2] | 0;
                    b[v2 + 12 >> 2] = j;
                    b[u2 >> 2] = j;
                    b[j + 8 >> 2] = v2;
                    b[j + 12 >> 2] = c2;
                    b[j + 24 >> 2] = 0;
                  }
                } else {
                  v2 = b[5861] | 0;
                  if ((v2 | 0) == 0 | g2 >>> 0 < v2 >>> 0) {
                    b[5861] = g2;
                  }
                  b[5969] = g2;
                  b[5970] = h;
                  b[5972] = 0;
                  b[5866] = b[5975];
                  b[5865] = -1;
                  b[5870] = 23468;
                  b[5869] = 23468;
                  b[5872] = 23476;
                  b[5871] = 23476;
                  b[5874] = 23484;
                  b[5873] = 23484;
                  b[5876] = 23492;
                  b[5875] = 23492;
                  b[5878] = 23500;
                  b[5877] = 23500;
                  b[5880] = 23508;
                  b[5879] = 23508;
                  b[5882] = 23516;
                  b[5881] = 23516;
                  b[5884] = 23524;
                  b[5883] = 23524;
                  b[5886] = 23532;
                  b[5885] = 23532;
                  b[5888] = 23540;
                  b[5887] = 23540;
                  b[5890] = 23548;
                  b[5889] = 23548;
                  b[5892] = 23556;
                  b[5891] = 23556;
                  b[5894] = 23564;
                  b[5893] = 23564;
                  b[5896] = 23572;
                  b[5895] = 23572;
                  b[5898] = 23580;
                  b[5897] = 23580;
                  b[5900] = 23588;
                  b[5899] = 23588;
                  b[5902] = 23596;
                  b[5901] = 23596;
                  b[5904] = 23604;
                  b[5903] = 23604;
                  b[5906] = 23612;
                  b[5905] = 23612;
                  b[5908] = 23620;
                  b[5907] = 23620;
                  b[5910] = 23628;
                  b[5909] = 23628;
                  b[5912] = 23636;
                  b[5911] = 23636;
                  b[5914] = 23644;
                  b[5913] = 23644;
                  b[5916] = 23652;
                  b[5915] = 23652;
                  b[5918] = 23660;
                  b[5917] = 23660;
                  b[5920] = 23668;
                  b[5919] = 23668;
                  b[5922] = 23676;
                  b[5921] = 23676;
                  b[5924] = 23684;
                  b[5923] = 23684;
                  b[5926] = 23692;
                  b[5925] = 23692;
                  b[5928] = 23700;
                  b[5927] = 23700;
                  b[5930] = 23708;
                  b[5929] = 23708;
                  b[5932] = 23716;
                  b[5931] = 23716;
                  v2 = h + -40 | 0;
                  t2 = g2 + 8 | 0;
                  t2 = (t2 & 7 | 0) == 0 ? 0 : 0 - t2 & 7;
                  u2 = g2 + t2 | 0;
                  t2 = v2 - t2 | 0;
                  b[5863] = u2;
                  b[5860] = t2;
                  b[u2 + 4 >> 2] = t2 | 1;
                  b[g2 + v2 + 4 >> 2] = 40;
                  b[5864] = b[5979];
                }
              } while (0);
              c2 = b[5860] | 0;
              if (c2 >>> 0 > m >>> 0) {
                t2 = c2 - m | 0;
                b[5860] = t2;
                v2 = b[5863] | 0;
                u2 = v2 + m | 0;
                b[5863] = u2;
                b[u2 + 4 >> 2] = t2 | 1;
                b[v2 + 4 >> 2] = m | 3;
                v2 = v2 + 8 | 0;
                T = w2;
                return v2 | 0;
              }
            }
            v2 = fd() | 0;
            b[v2 >> 2] = 12;
            v2 = 0;
            T = w2;
            return v2 | 0;
          }
          function jd(a2) {
            a2 = a2 | 0;
            var c2 = 0, d2 = 0, e2 = 0, f2 = 0, g2 = 0, h = 0, i = 0, j = 0;
            if (!a2) {
              return;
            }
            d2 = a2 + -8 | 0;
            f2 = b[5861] | 0;
            a2 = b[a2 + -4 >> 2] | 0;
            c2 = a2 & -8;
            j = d2 + c2 | 0;
            do {
              if (!(a2 & 1)) {
                e2 = b[d2 >> 2] | 0;
                if (!(a2 & 3)) {
                  return;
                }
                h = d2 + (0 - e2) | 0;
                g2 = e2 + c2 | 0;
                if (h >>> 0 < f2 >>> 0) {
                  return;
                }
                if ((b[5862] | 0) == (h | 0)) {
                  a2 = j + 4 | 0;
                  c2 = b[a2 >> 2] | 0;
                  if ((c2 & 3 | 0) != 3) {
                    i = h;
                    c2 = g2;
                    break;
                  }
                  b[5859] = g2;
                  b[a2 >> 2] = c2 & -2;
                  b[h + 4 >> 2] = g2 | 1;
                  b[h + g2 >> 2] = g2;
                  return;
                }
                d2 = e2 >>> 3;
                if (e2 >>> 0 < 256) {
                  a2 = b[h + 8 >> 2] | 0;
                  c2 = b[h + 12 >> 2] | 0;
                  if ((c2 | 0) == (a2 | 0)) {
                    b[5857] = b[5857] & ~(1 << d2);
                    i = h;
                    c2 = g2;
                    break;
                  } else {
                    b[a2 + 12 >> 2] = c2;
                    b[c2 + 8 >> 2] = a2;
                    i = h;
                    c2 = g2;
                    break;
                  }
                }
                f2 = b[h + 24 >> 2] | 0;
                a2 = b[h + 12 >> 2] | 0;
                do {
                  if ((a2 | 0) == (h | 0)) {
                    c2 = h + 16 | 0;
                    d2 = c2 + 4 | 0;
                    a2 = b[d2 >> 2] | 0;
                    if (!a2) {
                      a2 = b[c2 >> 2] | 0;
                      if (!a2) {
                        a2 = 0;
                        break;
                      }
                    } else {
                      c2 = d2;
                    }
                    while (1) {
                      e2 = a2 + 20 | 0;
                      d2 = b[e2 >> 2] | 0;
                      if (!d2) {
                        e2 = a2 + 16 | 0;
                        d2 = b[e2 >> 2] | 0;
                        if (!d2) {
                          break;
                        } else {
                          a2 = d2;
                          c2 = e2;
                        }
                      } else {
                        a2 = d2;
                        c2 = e2;
                      }
                    }
                    b[c2 >> 2] = 0;
                  } else {
                    i = b[h + 8 >> 2] | 0;
                    b[i + 12 >> 2] = a2;
                    b[a2 + 8 >> 2] = i;
                  }
                } while (0);
                if (f2) {
                  c2 = b[h + 28 >> 2] | 0;
                  d2 = 23732 + (c2 << 2) | 0;
                  if ((b[d2 >> 2] | 0) == (h | 0)) {
                    b[d2 >> 2] = a2;
                    if (!a2) {
                      b[5858] = b[5858] & ~(1 << c2);
                      i = h;
                      c2 = g2;
                      break;
                    }
                  } else {
                    i = f2 + 16 | 0;
                    b[((b[i >> 2] | 0) == (h | 0) ? i : f2 + 20 | 0) >> 2] = a2;
                    if (!a2) {
                      i = h;
                      c2 = g2;
                      break;
                    }
                  }
                  b[a2 + 24 >> 2] = f2;
                  c2 = h + 16 | 0;
                  d2 = b[c2 >> 2] | 0;
                  if (d2 | 0) {
                    b[a2 + 16 >> 2] = d2;
                    b[d2 + 24 >> 2] = a2;
                  }
                  c2 = b[c2 + 4 >> 2] | 0;
                  if (c2) {
                    b[a2 + 20 >> 2] = c2;
                    b[c2 + 24 >> 2] = a2;
                    i = h;
                    c2 = g2;
                  } else {
                    i = h;
                    c2 = g2;
                  }
                } else {
                  i = h;
                  c2 = g2;
                }
              } else {
                i = d2;
                h = d2;
              }
            } while (0);
            if (h >>> 0 >= j >>> 0) {
              return;
            }
            a2 = j + 4 | 0;
            e2 = b[a2 >> 2] | 0;
            if (!(e2 & 1)) {
              return;
            }
            if (!(e2 & 2)) {
              if ((b[5863] | 0) == (j | 0)) {
                j = (b[5860] | 0) + c2 | 0;
                b[5860] = j;
                b[5863] = i;
                b[i + 4 >> 2] = j | 1;
                if ((i | 0) != (b[5862] | 0)) {
                  return;
                }
                b[5862] = 0;
                b[5859] = 0;
                return;
              }
              if ((b[5862] | 0) == (j | 0)) {
                j = (b[5859] | 0) + c2 | 0;
                b[5859] = j;
                b[5862] = h;
                b[i + 4 >> 2] = j | 1;
                b[h + j >> 2] = j;
                return;
              }
              f2 = (e2 & -8) + c2 | 0;
              d2 = e2 >>> 3;
              do {
                if (e2 >>> 0 < 256) {
                  c2 = b[j + 8 >> 2] | 0;
                  a2 = b[j + 12 >> 2] | 0;
                  if ((a2 | 0) == (c2 | 0)) {
                    b[5857] = b[5857] & ~(1 << d2);
                    break;
                  } else {
                    b[c2 + 12 >> 2] = a2;
                    b[a2 + 8 >> 2] = c2;
                    break;
                  }
                } else {
                  g2 = b[j + 24 >> 2] | 0;
                  a2 = b[j + 12 >> 2] | 0;
                  do {
                    if ((a2 | 0) == (j | 0)) {
                      c2 = j + 16 | 0;
                      d2 = c2 + 4 | 0;
                      a2 = b[d2 >> 2] | 0;
                      if (!a2) {
                        a2 = b[c2 >> 2] | 0;
                        if (!a2) {
                          d2 = 0;
                          break;
                        }
                      } else {
                        c2 = d2;
                      }
                      while (1) {
                        e2 = a2 + 20 | 0;
                        d2 = b[e2 >> 2] | 0;
                        if (!d2) {
                          e2 = a2 + 16 | 0;
                          d2 = b[e2 >> 2] | 0;
                          if (!d2) {
                            break;
                          } else {
                            a2 = d2;
                            c2 = e2;
                          }
                        } else {
                          a2 = d2;
                          c2 = e2;
                        }
                      }
                      b[c2 >> 2] = 0;
                      d2 = a2;
                    } else {
                      d2 = b[j + 8 >> 2] | 0;
                      b[d2 + 12 >> 2] = a2;
                      b[a2 + 8 >> 2] = d2;
                      d2 = a2;
                    }
                  } while (0);
                  if (g2 | 0) {
                    a2 = b[j + 28 >> 2] | 0;
                    c2 = 23732 + (a2 << 2) | 0;
                    if ((b[c2 >> 2] | 0) == (j | 0)) {
                      b[c2 >> 2] = d2;
                      if (!d2) {
                        b[5858] = b[5858] & ~(1 << a2);
                        break;
                      }
                    } else {
                      e2 = g2 + 16 | 0;
                      b[((b[e2 >> 2] | 0) == (j | 0) ? e2 : g2 + 20 | 0) >> 2] = d2;
                      if (!d2) {
                        break;
                      }
                    }
                    b[d2 + 24 >> 2] = g2;
                    a2 = j + 16 | 0;
                    c2 = b[a2 >> 2] | 0;
                    if (c2 | 0) {
                      b[d2 + 16 >> 2] = c2;
                      b[c2 + 24 >> 2] = d2;
                    }
                    a2 = b[a2 + 4 >> 2] | 0;
                    if (a2 | 0) {
                      b[d2 + 20 >> 2] = a2;
                      b[a2 + 24 >> 2] = d2;
                    }
                  }
                }
              } while (0);
              b[i + 4 >> 2] = f2 | 1;
              b[h + f2 >> 2] = f2;
              if ((i | 0) == (b[5862] | 0)) {
                b[5859] = f2;
                return;
              }
            } else {
              b[a2 >> 2] = e2 & -2;
              b[i + 4 >> 2] = c2 | 1;
              b[h + c2 >> 2] = c2;
              f2 = c2;
            }
            a2 = f2 >>> 3;
            if (f2 >>> 0 < 256) {
              d2 = 23468 + (a2 << 1 << 2) | 0;
              c2 = b[5857] | 0;
              a2 = 1 << a2;
              if (!(c2 & a2)) {
                b[5857] = c2 | a2;
                a2 = d2;
                c2 = d2 + 8 | 0;
              } else {
                c2 = d2 + 8 | 0;
                a2 = b[c2 >> 2] | 0;
              }
              b[c2 >> 2] = i;
              b[a2 + 12 >> 2] = i;
              b[i + 8 >> 2] = a2;
              b[i + 12 >> 2] = d2;
              return;
            }
            a2 = f2 >>> 8;
            if (a2) {
              if (f2 >>> 0 > 16777215) {
                e2 = 31;
              } else {
                h = (a2 + 1048320 | 0) >>> 16 & 8;
                j = a2 << h;
                g2 = (j + 520192 | 0) >>> 16 & 4;
                j = j << g2;
                e2 = (j + 245760 | 0) >>> 16 & 2;
                e2 = 14 - (g2 | h | e2) + (j << e2 >>> 15) | 0;
                e2 = f2 >>> (e2 + 7 | 0) & 1 | e2 << 1;
              }
            } else {
              e2 = 0;
            }
            a2 = 23732 + (e2 << 2) | 0;
            b[i + 28 >> 2] = e2;
            b[i + 20 >> 2] = 0;
            b[i + 16 >> 2] = 0;
            c2 = b[5858] | 0;
            d2 = 1 << e2;
            a: do {
              if (!(c2 & d2)) {
                b[5858] = c2 | d2;
                b[a2 >> 2] = i;
                b[i + 24 >> 2] = a2;
                b[i + 12 >> 2] = i;
                b[i + 8 >> 2] = i;
              } else {
                a2 = b[a2 >> 2] | 0;
                b: do {
                  if ((b[a2 + 4 >> 2] & -8 | 0) != (f2 | 0)) {
                    e2 = f2 << ((e2 | 0) == 31 ? 0 : 25 - (e2 >>> 1) | 0);
                    while (1) {
                      d2 = a2 + 16 + (e2 >>> 31 << 2) | 0;
                      c2 = b[d2 >> 2] | 0;
                      if (!c2) {
                        break;
                      }
                      if ((b[c2 + 4 >> 2] & -8 | 0) == (f2 | 0)) {
                        a2 = c2;
                        break b;
                      } else {
                        e2 = e2 << 1;
                        a2 = c2;
                      }
                    }
                    b[d2 >> 2] = i;
                    b[i + 24 >> 2] = a2;
                    b[i + 12 >> 2] = i;
                    b[i + 8 >> 2] = i;
                    break a;
                  }
                } while (0);
                h = a2 + 8 | 0;
                j = b[h >> 2] | 0;
                b[j + 12 >> 2] = i;
                b[h >> 2] = i;
                b[i + 8 >> 2] = j;
                b[i + 12 >> 2] = a2;
                b[i + 24 >> 2] = 0;
              }
            } while (0);
            j = (b[5865] | 0) + -1 | 0;
            b[5865] = j;
            if (j | 0) {
              return;
            }
            a2 = 23884;
            while (1) {
              a2 = b[a2 >> 2] | 0;
              if (!a2) {
                break;
              } else {
                a2 = a2 + 8 | 0;
              }
            }
            b[5865] = -1;
            return;
          }
          function kd(a2, c2) {
            a2 = a2 | 0;
            c2 = c2 | 0;
            var d2 = 0;
            if (a2) {
              d2 = B(c2, a2) | 0;
              if ((c2 | a2) >>> 0 > 65535) {
                d2 = ((d2 >>> 0) / (a2 >>> 0) | 0 | 0) == (c2 | 0) ? d2 : -1;
              }
            } else {
              d2 = 0;
            }
            a2 = id(d2) | 0;
            if (!a2) {
              return a2 | 0;
            }
            if (!(b[a2 + -4 >> 2] & 3)) {
              return a2 | 0;
            }
            Bd(a2 | 0, 0, d2 | 0) | 0;
            return a2 | 0;
          }
          function ld(a2, b2, c2, d2) {
            a2 = a2 | 0;
            b2 = b2 | 0;
            c2 = c2 | 0;
            d2 = d2 | 0;
            c2 = a2 + c2 >>> 0;
            return (G(b2 + d2 + (c2 >>> 0 < a2 >>> 0 | 0) >>> 0 | 0), c2 | 0) | 0;
          }
          function md(a2, b2, c2, d2) {
            a2 = a2 | 0;
            b2 = b2 | 0;
            c2 = c2 | 0;
            d2 = d2 | 0;
            d2 = b2 - d2 - (c2 >>> 0 > a2 >>> 0 | 0) >>> 0;
            return (G(d2 | 0), a2 - c2 >>> 0 | 0) | 0;
          }
          function nd(a2) {
            a2 = a2 | 0;
            return (a2 ? 31 - (E(a2 ^ a2 - 1) | 0) | 0 : 32) | 0;
          }
          function od(a2, c2, d2, e2, f2) {
            a2 = a2 | 0;
            c2 = c2 | 0;
            d2 = d2 | 0;
            e2 = e2 | 0;
            f2 = f2 | 0;
            var g2 = 0, h = 0, i = 0, j = 0, k = 0, l = 0, m = 0, n = 0, o = 0, p2 = 0;
            l = a2;
            j = c2;
            k = j;
            h = d2;
            n = e2;
            i = n;
            if (!k) {
              g2 = (f2 | 0) != 0;
              if (!i) {
                if (g2) {
                  b[f2 >> 2] = (l >>> 0) % (h >>> 0);
                  b[f2 + 4 >> 2] = 0;
                }
                n = 0;
                f2 = (l >>> 0) / (h >>> 0) >>> 0;
                return (G(n | 0), f2) | 0;
              } else {
                if (!g2) {
                  n = 0;
                  f2 = 0;
                  return (G(n | 0), f2) | 0;
                }
                b[f2 >> 2] = a2 | 0;
                b[f2 + 4 >> 2] = c2 & 0;
                n = 0;
                f2 = 0;
                return (G(n | 0), f2) | 0;
              }
            }
            g2 = (i | 0) == 0;
            do {
              if (h) {
                if (!g2) {
                  g2 = (E(i | 0) | 0) - (E(k | 0) | 0) | 0;
                  if (g2 >>> 0 <= 31) {
                    m = g2 + 1 | 0;
                    i = 31 - g2 | 0;
                    c2 = g2 - 31 >> 31;
                    h = m;
                    a2 = l >>> (m >>> 0) & c2 | k << i;
                    c2 = k >>> (m >>> 0) & c2;
                    g2 = 0;
                    i = l << i;
                    break;
                  }
                  if (!f2) {
                    n = 0;
                    f2 = 0;
                    return (G(n | 0), f2) | 0;
                  }
                  b[f2 >> 2] = a2 | 0;
                  b[f2 + 4 >> 2] = j | c2 & 0;
                  n = 0;
                  f2 = 0;
                  return (G(n | 0), f2) | 0;
                }
                g2 = h - 1 | 0;
                if (g2 & h | 0) {
                  i = (E(h | 0) | 0) + 33 - (E(k | 0) | 0) | 0;
                  p2 = 64 - i | 0;
                  m = 32 - i | 0;
                  j = m >> 31;
                  o = i - 32 | 0;
                  c2 = o >> 31;
                  h = i;
                  a2 = m - 1 >> 31 & k >>> (o >>> 0) | (k << m | l >>> (i >>> 0)) & c2;
                  c2 = c2 & k >>> (i >>> 0);
                  g2 = l << p2 & j;
                  i = (k << p2 | l >>> (o >>> 0)) & j | l << m & i - 33 >> 31;
                  break;
                }
                if (f2 | 0) {
                  b[f2 >> 2] = g2 & l;
                  b[f2 + 4 >> 2] = 0;
                }
                if ((h | 0) == 1) {
                  o = j | c2 & 0;
                  p2 = a2 | 0 | 0;
                  return (G(o | 0), p2) | 0;
                } else {
                  p2 = nd(h | 0) | 0;
                  o = k >>> (p2 >>> 0) | 0;
                  p2 = k << 32 - p2 | l >>> (p2 >>> 0) | 0;
                  return (G(o | 0), p2) | 0;
                }
              } else {
                if (g2) {
                  if (f2 | 0) {
                    b[f2 >> 2] = (k >>> 0) % (h >>> 0);
                    b[f2 + 4 >> 2] = 0;
                  }
                  o = 0;
                  p2 = (k >>> 0) / (h >>> 0) >>> 0;
                  return (G(o | 0), p2) | 0;
                }
                if (!l) {
                  if (f2 | 0) {
                    b[f2 >> 2] = 0;
                    b[f2 + 4 >> 2] = (k >>> 0) % (i >>> 0);
                  }
                  o = 0;
                  p2 = (k >>> 0) / (i >>> 0) >>> 0;
                  return (G(o | 0), p2) | 0;
                }
                g2 = i - 1 | 0;
                if (!(g2 & i)) {
                  if (f2 | 0) {
                    b[f2 >> 2] = a2 | 0;
                    b[f2 + 4 >> 2] = g2 & k | c2 & 0;
                  }
                  o = 0;
                  p2 = k >>> ((nd(i | 0) | 0) >>> 0);
                  return (G(o | 0), p2) | 0;
                }
                g2 = (E(i | 0) | 0) - (E(k | 0) | 0) | 0;
                if (g2 >>> 0 <= 30) {
                  c2 = g2 + 1 | 0;
                  i = 31 - g2 | 0;
                  h = c2;
                  a2 = k << i | l >>> (c2 >>> 0);
                  c2 = k >>> (c2 >>> 0);
                  g2 = 0;
                  i = l << i;
                  break;
                }
                if (!f2) {
                  o = 0;
                  p2 = 0;
                  return (G(o | 0), p2) | 0;
                }
                b[f2 >> 2] = a2 | 0;
                b[f2 + 4 >> 2] = j | c2 & 0;
                o = 0;
                p2 = 0;
                return (G(o | 0), p2) | 0;
              }
            } while (0);
            if (!h) {
              k = i;
              j = 0;
              i = 0;
            } else {
              m = d2 | 0 | 0;
              l = n | e2 & 0;
              k = ld(m | 0, l | 0, -1, -1) | 0;
              d2 = H() | 0;
              j = i;
              i = 0;
              do {
                e2 = j;
                j = g2 >>> 31 | j << 1;
                g2 = i | g2 << 1;
                e2 = a2 << 1 | e2 >>> 31 | 0;
                n = a2 >>> 31 | c2 << 1 | 0;
                md(k | 0, d2 | 0, e2 | 0, n | 0) | 0;
                p2 = H() | 0;
                o = p2 >> 31 | ((p2 | 0) < 0 ? -1 : 0) << 1;
                i = o & 1;
                a2 = md(e2 | 0, n | 0, o & m | 0, (((p2 | 0) < 0 ? -1 : 0) >> 31 | ((p2 | 0) < 0 ? -1 : 0) << 1) & l | 0) | 0;
                c2 = H() | 0;
                h = h - 1 | 0;
              } while ((h | 0) != 0);
              k = j;
              j = 0;
            }
            h = 0;
            if (f2 | 0) {
              b[f2 >> 2] = a2;
              b[f2 + 4 >> 2] = c2;
            }
            o = (g2 | 0) >>> 31 | (k | h) << 1 | (h << 1 | g2 >>> 31) & 0 | j;
            p2 = (g2 << 1 | 0 >>> 31) & -2 | i;
            return (G(o | 0), p2) | 0;
          }
          function pd(a2, b2, c2, d2) {
            a2 = a2 | 0;
            b2 = b2 | 0;
            c2 = c2 | 0;
            d2 = d2 | 0;
            var e2 = 0, f2 = 0, g2 = 0, h = 0, i = 0, j = 0;
            j = b2 >> 31 | ((b2 | 0) < 0 ? -1 : 0) << 1;
            i = ((b2 | 0) < 0 ? -1 : 0) >> 31 | ((b2 | 0) < 0 ? -1 : 0) << 1;
            f2 = d2 >> 31 | ((d2 | 0) < 0 ? -1 : 0) << 1;
            e2 = ((d2 | 0) < 0 ? -1 : 0) >> 31 | ((d2 | 0) < 0 ? -1 : 0) << 1;
            h = md(j ^ a2 | 0, i ^ b2 | 0, j | 0, i | 0) | 0;
            g2 = H() | 0;
            a2 = f2 ^ j;
            b2 = e2 ^ i;
            return md((od(h, g2, md(f2 ^ c2 | 0, e2 ^ d2 | 0, f2 | 0, e2 | 0) | 0, H() | 0, 0) | 0) ^ a2 | 0, (H() | 0) ^ b2 | 0, a2 | 0, b2 | 0) | 0;
          }
          function qd(a2, b2) {
            a2 = a2 | 0;
            b2 = b2 | 0;
            var c2 = 0, d2 = 0, e2 = 0, f2 = 0;
            f2 = a2 & 65535;
            e2 = b2 & 65535;
            c2 = B(e2, f2) | 0;
            d2 = a2 >>> 16;
            a2 = (c2 >>> 16) + (B(e2, d2) | 0) | 0;
            e2 = b2 >>> 16;
            b2 = B(e2, f2) | 0;
            return (G((a2 >>> 16) + (B(e2, d2) | 0) + (((a2 & 65535) + b2 | 0) >>> 16) | 0), a2 + b2 << 16 | c2 & 65535 | 0) | 0;
          }
          function rd(a2, b2, c2, d2) {
            a2 = a2 | 0;
            b2 = b2 | 0;
            c2 = c2 | 0;
            d2 = d2 | 0;
            var e2 = 0, f2 = 0;
            e2 = a2;
            f2 = c2;
            c2 = qd(e2, f2) | 0;
            a2 = H() | 0;
            return (G((B(b2, f2) | 0) + (B(d2, e2) | 0) + a2 | a2 & 0 | 0), c2 | 0 | 0) | 0;
          }
          function sd(a2, c2, d2, e2) {
            a2 = a2 | 0;
            c2 = c2 | 0;
            d2 = d2 | 0;
            e2 = e2 | 0;
            var f2 = 0, g2 = 0, h = 0, i = 0, j = 0, k = 0;
            f2 = T;
            T = T + 16 | 0;
            i = f2 | 0;
            h = c2 >> 31 | ((c2 | 0) < 0 ? -1 : 0) << 1;
            g2 = ((c2 | 0) < 0 ? -1 : 0) >> 31 | ((c2 | 0) < 0 ? -1 : 0) << 1;
            k = e2 >> 31 | ((e2 | 0) < 0 ? -1 : 0) << 1;
            j = ((e2 | 0) < 0 ? -1 : 0) >> 31 | ((e2 | 0) < 0 ? -1 : 0) << 1;
            a2 = md(h ^ a2 | 0, g2 ^ c2 | 0, h | 0, g2 | 0) | 0;
            c2 = H() | 0;
            od(a2, c2, md(k ^ d2 | 0, j ^ e2 | 0, k | 0, j | 0) | 0, H() | 0, i) | 0;
            e2 = md(b[i >> 2] ^ h | 0, b[i + 4 >> 2] ^ g2 | 0, h | 0, g2 | 0) | 0;
            d2 = H() | 0;
            T = f2;
            return (G(d2 | 0), e2) | 0;
          }
          function td(a2, c2, d2, e2) {
            a2 = a2 | 0;
            c2 = c2 | 0;
            d2 = d2 | 0;
            e2 = e2 | 0;
            var f2 = 0, g2 = 0;
            g2 = T;
            T = T + 16 | 0;
            f2 = g2 | 0;
            od(a2, c2, d2, e2, f2) | 0;
            T = g2;
            return (G(b[f2 + 4 >> 2] | 0), b[f2 >> 2] | 0) | 0;
          }
          function ud(a2, b2, c2) {
            a2 = a2 | 0;
            b2 = b2 | 0;
            c2 = c2 | 0;
            if ((c2 | 0) < 32) {
              G(b2 >> c2 | 0);
              return a2 >>> c2 | (b2 & (1 << c2) - 1) << 32 - c2;
            }
            G(((b2 | 0) < 0 ? -1 : 0) | 0);
            return b2 >> c2 - 32 | 0;
          }
          function vd(a2, b2, c2) {
            a2 = a2 | 0;
            b2 = b2 | 0;
            c2 = c2 | 0;
            if ((c2 | 0) < 32) {
              G(b2 >>> c2 | 0);
              return a2 >>> c2 | (b2 & (1 << c2) - 1) << 32 - c2;
            }
            G(0);
            return b2 >>> c2 - 32 | 0;
          }
          function wd(a2, b2, c2) {
            a2 = a2 | 0;
            b2 = b2 | 0;
            c2 = c2 | 0;
            if ((c2 | 0) < 32) {
              G(b2 << c2 | (a2 & (1 << c2) - 1 << 32 - c2) >>> 32 - c2 | 0);
              return a2 << c2;
            }
            G(a2 << c2 - 32 | 0);
            return 0;
          }
          function xd(a2, b2) {
            a2 = +a2;
            b2 = +b2;
            if (a2 != a2) {
              return +b2;
            }
            if (b2 != b2) {
              return +a2;
            }
            return +D(+a2, +b2);
          }
          function yd(a2, b2) {
            a2 = +a2;
            b2 = +b2;
            if (a2 != a2) {
              return +b2;
            }
            if (b2 != b2) {
              return +a2;
            }
            return +C(+a2, +b2);
          }
          function zd(a2) {
            a2 = +a2;
            return a2 >= 0 ? +p(a2 + 0.5) : +A(a2 - 0.5);
          }
          function Ad(c2, d2, e2) {
            c2 = c2 | 0;
            d2 = d2 | 0;
            e2 = e2 | 0;
            var f2 = 0, g2 = 0, h = 0;
            if ((e2 | 0) >= 8192) {
              L(c2 | 0, d2 | 0, e2 | 0) | 0;
              return c2 | 0;
            }
            h = c2 | 0;
            g2 = c2 + e2 | 0;
            if ((c2 & 3) == (d2 & 3)) {
              while (c2 & 3) {
                if (!e2) {
                  return h | 0;
                }
                a[c2 >> 0] = a[d2 >> 0] | 0;
                c2 = c2 + 1 | 0;
                d2 = d2 + 1 | 0;
                e2 = e2 - 1 | 0;
              }
              e2 = g2 & -4 | 0;
              f2 = e2 - 64 | 0;
              while ((c2 | 0) <= (f2 | 0)) {
                b[c2 >> 2] = b[d2 >> 2];
                b[c2 + 4 >> 2] = b[d2 + 4 >> 2];
                b[c2 + 8 >> 2] = b[d2 + 8 >> 2];
                b[c2 + 12 >> 2] = b[d2 + 12 >> 2];
                b[c2 + 16 >> 2] = b[d2 + 16 >> 2];
                b[c2 + 20 >> 2] = b[d2 + 20 >> 2];
                b[c2 + 24 >> 2] = b[d2 + 24 >> 2];
                b[c2 + 28 >> 2] = b[d2 + 28 >> 2];
                b[c2 + 32 >> 2] = b[d2 + 32 >> 2];
                b[c2 + 36 >> 2] = b[d2 + 36 >> 2];
                b[c2 + 40 >> 2] = b[d2 + 40 >> 2];
                b[c2 + 44 >> 2] = b[d2 + 44 >> 2];
                b[c2 + 48 >> 2] = b[d2 + 48 >> 2];
                b[c2 + 52 >> 2] = b[d2 + 52 >> 2];
                b[c2 + 56 >> 2] = b[d2 + 56 >> 2];
                b[c2 + 60 >> 2] = b[d2 + 60 >> 2];
                c2 = c2 + 64 | 0;
                d2 = d2 + 64 | 0;
              }
              while ((c2 | 0) < (e2 | 0)) {
                b[c2 >> 2] = b[d2 >> 2];
                c2 = c2 + 4 | 0;
                d2 = d2 + 4 | 0;
              }
            } else {
              e2 = g2 - 4 | 0;
              while ((c2 | 0) < (e2 | 0)) {
                a[c2 >> 0] = a[d2 >> 0] | 0;
                a[c2 + 1 >> 0] = a[d2 + 1 >> 0] | 0;
                a[c2 + 2 >> 0] = a[d2 + 2 >> 0] | 0;
                a[c2 + 3 >> 0] = a[d2 + 3 >> 0] | 0;
                c2 = c2 + 4 | 0;
                d2 = d2 + 4 | 0;
              }
            }
            while ((c2 | 0) < (g2 | 0)) {
              a[c2 >> 0] = a[d2 >> 0] | 0;
              c2 = c2 + 1 | 0;
              d2 = d2 + 1 | 0;
            }
            return h | 0;
          }
          function Bd(c2, d2, e2) {
            c2 = c2 | 0;
            d2 = d2 | 0;
            e2 = e2 | 0;
            var f2 = 0, g2 = 0, h = 0, i = 0;
            h = c2 + e2 | 0;
            d2 = d2 & 255;
            if ((e2 | 0) >= 67) {
              while (c2 & 3) {
                a[c2 >> 0] = d2;
                c2 = c2 + 1 | 0;
              }
              f2 = h & -4 | 0;
              i = d2 | d2 << 8 | d2 << 16 | d2 << 24;
              g2 = f2 - 64 | 0;
              while ((c2 | 0) <= (g2 | 0)) {
                b[c2 >> 2] = i;
                b[c2 + 4 >> 2] = i;
                b[c2 + 8 >> 2] = i;
                b[c2 + 12 >> 2] = i;
                b[c2 + 16 >> 2] = i;
                b[c2 + 20 >> 2] = i;
                b[c2 + 24 >> 2] = i;
                b[c2 + 28 >> 2] = i;
                b[c2 + 32 >> 2] = i;
                b[c2 + 36 >> 2] = i;
                b[c2 + 40 >> 2] = i;
                b[c2 + 44 >> 2] = i;
                b[c2 + 48 >> 2] = i;
                b[c2 + 52 >> 2] = i;
                b[c2 + 56 >> 2] = i;
                b[c2 + 60 >> 2] = i;
                c2 = c2 + 64 | 0;
              }
              while ((c2 | 0) < (f2 | 0)) {
                b[c2 >> 2] = i;
                c2 = c2 + 4 | 0;
              }
            }
            while ((c2 | 0) < (h | 0)) {
              a[c2 >> 0] = d2;
              c2 = c2 + 1 | 0;
            }
            return h - e2 | 0;
          }
          function Cd(a2) {
            a2 = +a2;
            return a2 >= 0 ? +p(a2 + 0.5) : +A(a2 - 0.5);
          }
          function Dd(a2) {
            a2 = a2 | 0;
            var c2 = 0, d2 = 0, e2 = 0;
            e2 = K() | 0;
            d2 = b[g >> 2] | 0;
            c2 = d2 + a2 | 0;
            if ((a2 | 0) > 0 & (c2 | 0) < (d2 | 0) | (c2 | 0) < 0) {
              N(c2 | 0) | 0;
              J(12);
              return -1;
            }
            if ((c2 | 0) > (e2 | 0)) {
              if (!(M(c2 | 0) | 0)) {
                J(12);
                return -1;
              }
            }
            b[g >> 2] = c2;
            return d2 | 0;
          }
          return {
            ___divdi3: pd,
            ___muldi3: rd,
            ___remdi3: sd,
            ___uremdi3: td,
            _areNeighborCells: $a,
            _bitshift64Ashr: ud,
            _bitshift64Lshr: vd,
            _bitshift64Shl: wd,
            _calloc: kd,
            _cellAreaKm2: lc,
            _cellAreaM2: mc,
            _cellAreaRads2: kc,
            _cellToBoundary: Qb,
            _cellToCenterChild: Ab,
            _cellToChildPos: Vb,
            _cellToChildren: yb,
            _cellToChildrenSize: wb,
            _cellToLatLng: Pb,
            _cellToLocalIj: xc,
            _cellToParent: vb,
            _cellToVertex: Wc,
            _cellToVertexes: Xc,
            _cellsToDirectedEdge: ab,
            _cellsToLinkedMultiPolygon: la,
            _childPosToCell: Wb,
            _compactCells: Bb,
            _destroyLinkedMultiPolygon: sc,
            _directedEdgeToBoundary: gb,
            _directedEdgeToCells: eb,
            _edgeLengthKm: oc,
            _edgeLengthM: pc,
            _edgeLengthRads: nc,
            _emscripten_replace_memory: W,
            _free: jd,
            _getBaseCellNumber: tb,
            _getDirectedEdgeDestination: cb,
            _getDirectedEdgeOrigin: bb,
            _getHexagonAreaAvgKm2: ec,
            _getHexagonAreaAvgM2: fc,
            _getHexagonEdgeLengthAvgKm: gc,
            _getHexagonEdgeLengthAvgM: hc,
            _getIcosahedronFaces: Sb,
            _getNumCells: ic,
            _getPentagons: Ub,
            _getRes0Cells: wa,
            _getResolution: sb,
            _greatCircleDistanceKm: ac,
            _greatCircleDistanceM: bc,
            _greatCircleDistanceRads: $b,
            _gridDisk: aa,
            _gridDiskDistances: ba,
            _gridDistance: zc,
            _gridPathCells: Bc,
            _gridPathCellsSize: Ac,
            _gridRingUnsafe: ga,
            _i64Add: ld,
            _i64Subtract: md,
            _isPentagon: xb,
            _isResClassIII: Eb,
            _isValidCell: ub,
            _isValidDirectedEdge: db,
            _isValidVertex: Zc,
            _latLngToCell: Mb,
            _llvm_maxnum_f64: xd,
            _llvm_minnum_f64: yd,
            _llvm_round_f64: zd,
            _localIjToCell: yc,
            _malloc: id,
            _maxFaceCount: Rb,
            _maxGridDiskSize: $,
            _maxPolygonToCellsSize: ha,
            _memcpy: Ad,
            _memset: Bd,
            _originToDirectedEdges: fb,
            _pentagonCount: Tb,
            _polygonToCells: ja,
            _readInt64AsDoubleFromPointer: Oc,
            _res0CellCount: va,
            _round: Cd,
            _sbrk: Dd,
            _sizeOfCellBoundary: Jc,
            _sizeOfCoordIJ: Nc,
            _sizeOfGeoLoop: Kc,
            _sizeOfGeoPolygon: Lc,
            _sizeOfH3Index: Hc,
            _sizeOfLatLng: Ic,
            _sizeOfLinkedGeoPolygon: Mc,
            _uncompactCells: Cb,
            _uncompactCellsSize: Db,
            _vertexToLatLng: Yc,
            establishStackSpace: _,
            stackAlloc: X,
            stackRestore: Z,
            stackSave: Y
          };
        })(
          // EMSCRIPTEN_END_ASM
          asmGlobalArg,
          asmLibraryArg,
          buffer
        )
      );
      var ___divdi3 = Module["___divdi3"] = asm["___divdi3"];
      var ___muldi3 = Module["___muldi3"] = asm["___muldi3"];
      var ___remdi3 = Module["___remdi3"] = asm["___remdi3"];
      var ___uremdi3 = Module["___uremdi3"] = asm["___uremdi3"];
      var _areNeighborCells = Module["_areNeighborCells"] = asm["_areNeighborCells"];
      var _bitshift64Ashr = Module["_bitshift64Ashr"] = asm["_bitshift64Ashr"];
      var _bitshift64Lshr = Module["_bitshift64Lshr"] = asm["_bitshift64Lshr"];
      var _bitshift64Shl = Module["_bitshift64Shl"] = asm["_bitshift64Shl"];
      var _calloc = Module["_calloc"] = asm["_calloc"];
      var _cellAreaKm2 = Module["_cellAreaKm2"] = asm["_cellAreaKm2"];
      var _cellAreaM2 = Module["_cellAreaM2"] = asm["_cellAreaM2"];
      var _cellAreaRads2 = Module["_cellAreaRads2"] = asm["_cellAreaRads2"];
      var _cellToBoundary = Module["_cellToBoundary"] = asm["_cellToBoundary"];
      var _cellToCenterChild = Module["_cellToCenterChild"] = asm["_cellToCenterChild"];
      var _cellToChildPos = Module["_cellToChildPos"] = asm["_cellToChildPos"];
      var _cellToChildren = Module["_cellToChildren"] = asm["_cellToChildren"];
      var _cellToChildrenSize = Module["_cellToChildrenSize"] = asm["_cellToChildrenSize"];
      var _cellToLatLng = Module["_cellToLatLng"] = asm["_cellToLatLng"];
      var _cellToLocalIj = Module["_cellToLocalIj"] = asm["_cellToLocalIj"];
      var _cellToParent = Module["_cellToParent"] = asm["_cellToParent"];
      var _cellToVertex = Module["_cellToVertex"] = asm["_cellToVertex"];
      var _cellToVertexes = Module["_cellToVertexes"] = asm["_cellToVertexes"];
      var _cellsToDirectedEdge = Module["_cellsToDirectedEdge"] = asm["_cellsToDirectedEdge"];
      var _cellsToLinkedMultiPolygon = Module["_cellsToLinkedMultiPolygon"] = asm["_cellsToLinkedMultiPolygon"];
      var _childPosToCell = Module["_childPosToCell"] = asm["_childPosToCell"];
      var _compactCells = Module["_compactCells"] = asm["_compactCells"];
      var _destroyLinkedMultiPolygon = Module["_destroyLinkedMultiPolygon"] = asm["_destroyLinkedMultiPolygon"];
      var _directedEdgeToBoundary = Module["_directedEdgeToBoundary"] = asm["_directedEdgeToBoundary"];
      var _directedEdgeToCells = Module["_directedEdgeToCells"] = asm["_directedEdgeToCells"];
      var _edgeLengthKm = Module["_edgeLengthKm"] = asm["_edgeLengthKm"];
      var _edgeLengthM = Module["_edgeLengthM"] = asm["_edgeLengthM"];
      var _edgeLengthRads = Module["_edgeLengthRads"] = asm["_edgeLengthRads"];
      var _emscripten_replace_memory = Module["_emscripten_replace_memory"] = asm["_emscripten_replace_memory"];
      var _free = Module["_free"] = asm["_free"];
      var _getBaseCellNumber = Module["_getBaseCellNumber"] = asm["_getBaseCellNumber"];
      var _getDirectedEdgeDestination = Module["_getDirectedEdgeDestination"] = asm["_getDirectedEdgeDestination"];
      var _getDirectedEdgeOrigin = Module["_getDirectedEdgeOrigin"] = asm["_getDirectedEdgeOrigin"];
      var _getHexagonAreaAvgKm2 = Module["_getHexagonAreaAvgKm2"] = asm["_getHexagonAreaAvgKm2"];
      var _getHexagonAreaAvgM2 = Module["_getHexagonAreaAvgM2"] = asm["_getHexagonAreaAvgM2"];
      var _getHexagonEdgeLengthAvgKm = Module["_getHexagonEdgeLengthAvgKm"] = asm["_getHexagonEdgeLengthAvgKm"];
      var _getHexagonEdgeLengthAvgM = Module["_getHexagonEdgeLengthAvgM"] = asm["_getHexagonEdgeLengthAvgM"];
      var _getIcosahedronFaces = Module["_getIcosahedronFaces"] = asm["_getIcosahedronFaces"];
      var _getNumCells = Module["_getNumCells"] = asm["_getNumCells"];
      var _getPentagons = Module["_getPentagons"] = asm["_getPentagons"];
      var _getRes0Cells = Module["_getRes0Cells"] = asm["_getRes0Cells"];
      var _getResolution = Module["_getResolution"] = asm["_getResolution"];
      var _greatCircleDistanceKm = Module["_greatCircleDistanceKm"] = asm["_greatCircleDistanceKm"];
      var _greatCircleDistanceM = Module["_greatCircleDistanceM"] = asm["_greatCircleDistanceM"];
      var _greatCircleDistanceRads = Module["_greatCircleDistanceRads"] = asm["_greatCircleDistanceRads"];
      var _gridDisk = Module["_gridDisk"] = asm["_gridDisk"];
      var _gridDiskDistances = Module["_gridDiskDistances"] = asm["_gridDiskDistances"];
      var _gridDistance = Module["_gridDistance"] = asm["_gridDistance"];
      var _gridPathCells = Module["_gridPathCells"] = asm["_gridPathCells"];
      var _gridPathCellsSize = Module["_gridPathCellsSize"] = asm["_gridPathCellsSize"];
      var _gridRingUnsafe = Module["_gridRingUnsafe"] = asm["_gridRingUnsafe"];
      var _i64Add = Module["_i64Add"] = asm["_i64Add"];
      var _i64Subtract = Module["_i64Subtract"] = asm["_i64Subtract"];
      var _isPentagon = Module["_isPentagon"] = asm["_isPentagon"];
      var _isResClassIII = Module["_isResClassIII"] = asm["_isResClassIII"];
      var _isValidCell = Module["_isValidCell"] = asm["_isValidCell"];
      var _isValidDirectedEdge = Module["_isValidDirectedEdge"] = asm["_isValidDirectedEdge"];
      var _isValidVertex = Module["_isValidVertex"] = asm["_isValidVertex"];
      var _latLngToCell = Module["_latLngToCell"] = asm["_latLngToCell"];
      var _llvm_maxnum_f64 = Module["_llvm_maxnum_f64"] = asm["_llvm_maxnum_f64"];
      var _llvm_minnum_f64 = Module["_llvm_minnum_f64"] = asm["_llvm_minnum_f64"];
      var _llvm_round_f64 = Module["_llvm_round_f64"] = asm["_llvm_round_f64"];
      var _localIjToCell = Module["_localIjToCell"] = asm["_localIjToCell"];
      var _malloc = Module["_malloc"] = asm["_malloc"];
      var _maxFaceCount = Module["_maxFaceCount"] = asm["_maxFaceCount"];
      var _maxGridDiskSize = Module["_maxGridDiskSize"] = asm["_maxGridDiskSize"];
      var _maxPolygonToCellsSize = Module["_maxPolygonToCellsSize"] = asm["_maxPolygonToCellsSize"];
      var _memcpy = Module["_memcpy"] = asm["_memcpy"];
      var _memset = Module["_memset"] = asm["_memset"];
      var _originToDirectedEdges = Module["_originToDirectedEdges"] = asm["_originToDirectedEdges"];
      var _pentagonCount = Module["_pentagonCount"] = asm["_pentagonCount"];
      var _polygonToCells = Module["_polygonToCells"] = asm["_polygonToCells"];
      var _readInt64AsDoubleFromPointer = Module["_readInt64AsDoubleFromPointer"] = asm["_readInt64AsDoubleFromPointer"];
      var _res0CellCount = Module["_res0CellCount"] = asm["_res0CellCount"];
      var _round = Module["_round"] = asm["_round"];
      var _sbrk = Module["_sbrk"] = asm["_sbrk"];
      var _sizeOfCellBoundary = Module["_sizeOfCellBoundary"] = asm["_sizeOfCellBoundary"];
      var _sizeOfCoordIJ = Module["_sizeOfCoordIJ"] = asm["_sizeOfCoordIJ"];
      var _sizeOfGeoLoop = Module["_sizeOfGeoLoop"] = asm["_sizeOfGeoLoop"];
      var _sizeOfGeoPolygon = Module["_sizeOfGeoPolygon"] = asm["_sizeOfGeoPolygon"];
      var _sizeOfH3Index = Module["_sizeOfH3Index"] = asm["_sizeOfH3Index"];
      var _sizeOfLatLng = Module["_sizeOfLatLng"] = asm["_sizeOfLatLng"];
      var _sizeOfLinkedGeoPolygon = Module["_sizeOfLinkedGeoPolygon"] = asm["_sizeOfLinkedGeoPolygon"];
      var _uncompactCells = Module["_uncompactCells"] = asm["_uncompactCells"];
      var _uncompactCellsSize = Module["_uncompactCellsSize"] = asm["_uncompactCellsSize"];
      var _vertexToLatLng = Module["_vertexToLatLng"] = asm["_vertexToLatLng"];
      var establishStackSpace = Module["establishStackSpace"] = asm["establishStackSpace"];
      var stackAlloc = Module["stackAlloc"] = asm["stackAlloc"];
      var stackRestore = Module["stackRestore"] = asm["stackRestore"];
      var stackSave = Module["stackSave"] = asm["stackSave"];
      Module["asm"] = asm;
      Module["cwrap"] = cwrap;
      Module["setValue"] = setValue;
      Module["getValue"] = getValue;
      if (memoryInitializer) {
        if (!isDataURI(memoryInitializer)) {
          memoryInitializer = locateFile(memoryInitializer);
        }
        {
          addRunDependency("memory initializer");
          var applyMemoryInitializer = function(data) {
            if (data.byteLength) {
              data = new Uint8Array(data);
            }
            HEAPU8.set(data, GLOBAL_BASE);
            if (Module["memoryInitializerRequest"]) {
              delete Module["memoryInitializerRequest"].response;
            }
            removeRunDependency("memory initializer");
          };
          var doBrowserLoad = function() {
            readAsync(memoryInitializer, applyMemoryInitializer, function() {
              throw "could not load memory initializer " + memoryInitializer;
            });
          };
          var memoryInitializerBytes = tryParseAsDataURI(memoryInitializer);
          if (memoryInitializerBytes) {
            applyMemoryInitializer(memoryInitializerBytes.buffer);
          } else if (Module["memoryInitializerRequest"]) {
            var useRequest = function() {
              var request = Module["memoryInitializerRequest"];
              var response = request.response;
              if (request.status !== 200 && request.status !== 0) {
                var data = tryParseAsDataURI(Module["memoryInitializerRequestURL"]);
                if (data) {
                  response = data.buffer;
                } else {
                  console.warn("a problem seems to have happened with Module.memoryInitializerRequest, status: " + request.status + ", retrying " + memoryInitializer);
                  doBrowserLoad();
                  return;
                }
              }
              applyMemoryInitializer(response);
            };
            if (Module["memoryInitializerRequest"].response) {
              setTimeout(useRequest, 0);
            } else {
              Module["memoryInitializerRequest"].addEventListener("load", useRequest);
            }
          } else {
            doBrowserLoad();
          }
        }
      }
      var calledRun;
      dependenciesFulfilled = function runCaller() {
        if (!calledRun) {
          run();
        }
        if (!calledRun) {
          dependenciesFulfilled = runCaller;
        }
      };
      function run(args) {
        args = args || arguments_;
        if (runDependencies > 0) {
          return;
        }
        preRun();
        if (runDependencies > 0) {
          return;
        }
        function doRun() {
          if (calledRun) {
            return;
          }
          calledRun = true;
          if (ABORT) {
            return;
          }
          initRuntime();
          preMain();
          if (Module["onRuntimeInitialized"]) {
            Module["onRuntimeInitialized"]();
          }
          postRun();
        }
        if (Module["setStatus"]) {
          Module["setStatus"]("Running...");
          setTimeout(function() {
            setTimeout(function() {
              Module["setStatus"]("");
            }, 1);
            doRun();
          }, 1);
        } else {
          doRun();
        }
      }
      Module["run"] = run;
      function abort(what) {
        if (Module["onAbort"]) {
          Module["onAbort"](what);
        }
        what += "";
        out(what);
        err(what);
        ABORT = true;
        throw "abort(" + what + "). Build with -s ASSERTIONS=1 for more info.";
      }
      Module["abort"] = abort;
      if (Module["preInit"]) {
        if (typeof Module["preInit"] == "function") {
          Module["preInit"] = [Module["preInit"]];
        }
        while (Module["preInit"].length > 0) {
          Module["preInit"].pop()();
        }
      }
      run();
      return libh32;
    })(typeof libh3 === "object" ? libh3 : {});
    var NUMBER = "number";
    var H3_ERROR = NUMBER;
    var BOOLEAN = NUMBER;
    var H3_LOWER = NUMBER;
    var H3_UPPER = NUMBER;
    var RESOLUTION = NUMBER;
    var POINTER = NUMBER;
    var BINDINGS = [
      // The size functions are inserted via build/sizes.h
      ["sizeOfH3Index", NUMBER],
      ["sizeOfLatLng", NUMBER],
      ["sizeOfCellBoundary", NUMBER],
      ["sizeOfGeoLoop", NUMBER],
      ["sizeOfGeoPolygon", NUMBER],
      ["sizeOfLinkedGeoPolygon", NUMBER],
      ["sizeOfCoordIJ", NUMBER],
      ["readInt64AsDoubleFromPointer", NUMBER],
      // The remaining functions are defined in the core lib in h3Api.h
      ["isValidCell", BOOLEAN, [H3_LOWER, H3_UPPER]],
      ["latLngToCell", H3_ERROR, [NUMBER, NUMBER, RESOLUTION, POINTER]],
      ["cellToLatLng", H3_ERROR, [H3_LOWER, H3_UPPER, POINTER]],
      ["cellToBoundary", H3_ERROR, [H3_LOWER, H3_UPPER, POINTER]],
      ["maxGridDiskSize", H3_ERROR, [NUMBER, POINTER]],
      ["gridDisk", H3_ERROR, [H3_LOWER, H3_UPPER, NUMBER, POINTER]],
      ["gridDiskDistances", H3_ERROR, [H3_LOWER, H3_UPPER, NUMBER, POINTER, POINTER]],
      ["gridRingUnsafe", H3_ERROR, [H3_LOWER, H3_UPPER, NUMBER, POINTER]],
      ["maxPolygonToCellsSize", H3_ERROR, [POINTER, RESOLUTION, NUMBER, POINTER]],
      ["polygonToCells", H3_ERROR, [POINTER, RESOLUTION, NUMBER, POINTER]],
      ["cellsToLinkedMultiPolygon", H3_ERROR, [POINTER, NUMBER, POINTER]],
      ["destroyLinkedMultiPolygon", null, [POINTER]],
      ["compactCells", H3_ERROR, [POINTER, POINTER, NUMBER, NUMBER]],
      ["uncompactCells", H3_ERROR, [POINTER, NUMBER, NUMBER, POINTER, NUMBER, RESOLUTION]],
      ["uncompactCellsSize", H3_ERROR, [POINTER, NUMBER, NUMBER, RESOLUTION, POINTER]],
      ["isPentagon", BOOLEAN, [H3_LOWER, H3_UPPER]],
      ["isResClassIII", BOOLEAN, [H3_LOWER, H3_UPPER]],
      ["getBaseCellNumber", NUMBER, [H3_LOWER, H3_UPPER]],
      ["getResolution", NUMBER, [H3_LOWER, H3_UPPER]],
      ["maxFaceCount", H3_ERROR, [H3_LOWER, H3_UPPER, POINTER]],
      ["getIcosahedronFaces", H3_ERROR, [H3_LOWER, H3_UPPER, POINTER]],
      ["cellToParent", H3_ERROR, [H3_LOWER, H3_UPPER, RESOLUTION, POINTER]],
      ["cellToChildren", H3_ERROR, [H3_LOWER, H3_UPPER, RESOLUTION, POINTER]],
      ["cellToCenterChild", H3_ERROR, [H3_LOWER, H3_UPPER, RESOLUTION, POINTER]],
      ["cellToChildrenSize", H3_ERROR, [H3_LOWER, H3_UPPER, RESOLUTION, POINTER]],
      ["cellToChildPos", H3_ERROR, [H3_LOWER, H3_UPPER, RESOLUTION, POINTER]],
      ["childPosToCell", H3_ERROR, [NUMBER, NUMBER, H3_LOWER, H3_UPPER, RESOLUTION, POINTER]],
      ["areNeighborCells", H3_ERROR, [H3_LOWER, H3_UPPER, H3_LOWER, H3_UPPER, POINTER]],
      ["cellsToDirectedEdge", H3_ERROR, [H3_LOWER, H3_UPPER, H3_LOWER, H3_UPPER, POINTER]],
      ["getDirectedEdgeOrigin", H3_ERROR, [H3_LOWER, H3_UPPER, POINTER]],
      ["getDirectedEdgeDestination", H3_ERROR, [H3_LOWER, H3_UPPER, POINTER]],
      ["isValidDirectedEdge", BOOLEAN, [H3_LOWER, H3_UPPER]],
      ["directedEdgeToCells", H3_ERROR, [H3_LOWER, H3_UPPER, POINTER]],
      ["originToDirectedEdges", H3_ERROR, [H3_LOWER, H3_UPPER, POINTER]],
      ["directedEdgeToBoundary", H3_ERROR, [H3_LOWER, H3_UPPER, POINTER]],
      ["gridDistance", H3_ERROR, [H3_LOWER, H3_UPPER, H3_LOWER, H3_UPPER, POINTER]],
      ["gridPathCells", H3_ERROR, [H3_LOWER, H3_UPPER, H3_LOWER, H3_UPPER, POINTER]],
      ["gridPathCellsSize", H3_ERROR, [H3_LOWER, H3_UPPER, H3_LOWER, H3_UPPER, POINTER]],
      ["cellToLocalIj", H3_ERROR, [H3_LOWER, H3_UPPER, H3_LOWER, H3_UPPER, NUMBER, POINTER]],
      ["localIjToCell", H3_ERROR, [H3_LOWER, H3_UPPER, POINTER, NUMBER, POINTER]],
      ["getHexagonAreaAvgM2", H3_ERROR, [RESOLUTION, POINTER]],
      ["getHexagonAreaAvgKm2", H3_ERROR, [RESOLUTION, POINTER]],
      ["getHexagonEdgeLengthAvgM", H3_ERROR, [RESOLUTION, POINTER]],
      ["getHexagonEdgeLengthAvgKm", H3_ERROR, [RESOLUTION, POINTER]],
      ["greatCircleDistanceM", NUMBER, [POINTER, POINTER]],
      ["greatCircleDistanceKm", NUMBER, [POINTER, POINTER]],
      ["greatCircleDistanceRads", NUMBER, [POINTER, POINTER]],
      ["cellAreaM2", H3_ERROR, [H3_LOWER, H3_UPPER, POINTER]],
      ["cellAreaKm2", H3_ERROR, [H3_LOWER, H3_UPPER, POINTER]],
      ["cellAreaRads2", H3_ERROR, [H3_LOWER, H3_UPPER, POINTER]],
      ["edgeLengthM", H3_ERROR, [H3_LOWER, H3_UPPER, POINTER]],
      ["edgeLengthKm", H3_ERROR, [H3_LOWER, H3_UPPER, POINTER]],
      ["edgeLengthRads", H3_ERROR, [H3_LOWER, H3_UPPER, POINTER]],
      ["getNumCells", H3_ERROR, [RESOLUTION, POINTER]],
      ["getRes0Cells", H3_ERROR, [POINTER]],
      ["res0CellCount", NUMBER],
      ["getPentagons", H3_ERROR, [NUMBER, POINTER]],
      ["pentagonCount", NUMBER],
      ["cellToVertex", H3_ERROR, [H3_LOWER, H3_UPPER, NUMBER, POINTER]],
      ["cellToVertexes", H3_ERROR, [H3_LOWER, H3_UPPER, POINTER]],
      ["vertexToLatLng", H3_ERROR, [H3_LOWER, H3_UPPER, POINTER]],
      ["isValidVertex", BOOLEAN, [H3_LOWER, H3_UPPER]]
    ];
    var E_SUCCESS = 0;
    var E_FAILED = 1;
    var E_DOMAIN = 2;
    var E_LATLNG_DOMAIN = 3;
    var E_RES_DOMAIN = 4;
    var E_CELL_INVALID = 5;
    var E_DIR_EDGE_INVALID = 6;
    var E_UNDIR_EDGE_INVALID = 7;
    var E_VERTEX_INVALID = 8;
    var E_PENTAGON = 9;
    var E_DUPLICATE_INPUT = 10;
    var E_NOT_NEIGHBORS = 11;
    var E_RES_MISMATCH = 12;
    var E_MEMORY_ALLOC = 13;
    var E_MEMORY_BOUNDS = 14;
    var E_OPTION_INVALID = 15;
    var H3_ERROR_MSGS = {};
    H3_ERROR_MSGS[E_SUCCESS] = "Success";
    H3_ERROR_MSGS[E_FAILED] = "The operation failed but a more specific error is not available";
    H3_ERROR_MSGS[E_DOMAIN] = "Argument was outside of acceptable range";
    H3_ERROR_MSGS[E_LATLNG_DOMAIN] = "Latitude or longitude arguments were outside of acceptable range";
    H3_ERROR_MSGS[E_RES_DOMAIN] = "Resolution argument was outside of acceptable range";
    H3_ERROR_MSGS[E_CELL_INVALID] = "Cell argument was not valid";
    H3_ERROR_MSGS[E_DIR_EDGE_INVALID] = "Directed edge argument was not valid";
    H3_ERROR_MSGS[E_UNDIR_EDGE_INVALID] = "Undirected edge argument was not valid";
    H3_ERROR_MSGS[E_VERTEX_INVALID] = "Vertex argument was not valid";
    H3_ERROR_MSGS[E_PENTAGON] = "Pentagon distortion was encountered";
    H3_ERROR_MSGS[E_DUPLICATE_INPUT] = "Duplicate input";
    H3_ERROR_MSGS[E_NOT_NEIGHBORS] = "Cell arguments were not neighbors";
    H3_ERROR_MSGS[E_RES_MISMATCH] = "Cell arguments had incompatible resolutions";
    H3_ERROR_MSGS[E_MEMORY_ALLOC] = "Memory allocation failed";
    H3_ERROR_MSGS[E_MEMORY_BOUNDS] = "Bounds of provided memory were insufficient";
    H3_ERROR_MSGS[E_OPTION_INVALID] = "Mode or flags argument was not valid";
    var E_UNKNOWN_UNIT = 1e3;
    var E_ARRAY_LENGTH = 1001;
    var E_NULL_INDEX = 1002;
    var JS_ERROR_MESSAGES = {};
    JS_ERROR_MESSAGES[E_UNKNOWN_UNIT] = "Unknown unit";
    JS_ERROR_MESSAGES[E_ARRAY_LENGTH] = "Array length out of bounds";
    JS_ERROR_MESSAGES[E_NULL_INDEX] = "Got unexpected null value for H3 index";
    var UNKNOWN_ERROR_MSG = "Unknown error";
    function createError(messages, errCode, meta) {
      var hasValue = meta && "value" in meta;
      var err = new Error((messages[errCode] || UNKNOWN_ERROR_MSG) + " (code: " + errCode + (hasValue ? ", value: " + meta.value : "") + ")");
      err.code = errCode;
      return err;
    }
    function H3LibraryError(errCode, value) {
      var meta = arguments.length === 2 ? {
        value
      } : {};
      return createError(H3_ERROR_MSGS, errCode, meta);
    }
    function JSBindingError(errCode, value) {
      var meta = arguments.length === 2 ? {
        value
      } : {};
      return createError(JS_ERROR_MESSAGES, errCode, meta);
    }
    function throwIfError(errCode) {
      if (errCode !== 0) {
        throw H3LibraryError(errCode);
      }
    }
    var H3 = {};
    BINDINGS.forEach(function bind(def) {
      H3[def[0]] = libh3.cwrap.apply(libh3, def);
    });
    var BASE_16 = 16;
    var UNUSED_UPPER_32_BITS = 0;
    var SZ_INT = 4;
    var SZ_PTR = 4;
    var SZ_DBL = 8;
    var SZ_INT64 = 8;
    var SZ_H3INDEX = H3.sizeOfH3Index();
    var SZ_LATLNG = H3.sizeOfLatLng();
    var SZ_CELLBOUNDARY = H3.sizeOfCellBoundary();
    var SZ_GEOPOLYGON = H3.sizeOfGeoPolygon();
    var SZ_GEOLOOP = H3.sizeOfGeoLoop();
    var SZ_LINKED_GEOPOLYGON = H3.sizeOfLinkedGeoPolygon();
    var SZ_COORDIJ = H3.sizeOfCoordIJ();
    var UNITS = {
      m: "m",
      m2: "m2",
      km: "km",
      km2: "km2",
      rads: "rads",
      rads2: "rads2"
    };
    function validateRes(res) {
      if (typeof res !== "number" || res < 0 || res > 15 || Math.floor(res) !== res) {
        throw H3LibraryError(E_RES_DOMAIN, res);
      }
      return res;
    }
    function validateH3Index(h3Index) {
      if (!h3Index) {
        throw JSBindingError(E_NULL_INDEX);
      }
      return h3Index;
    }
    var MAX_JS_ARRAY_LENGTH = Math.pow(2, 32) - 1;
    function validateArrayLength(length) {
      if (length > MAX_JS_ARRAY_LENGTH) {
        throw JSBindingError(E_ARRAY_LENGTH, length);
      }
      return length;
    }
    var INVALID_HEXIDECIMAL_CHAR = /[^0-9a-fA-F]/;
    function h3IndexToSplitLong(h3Index) {
      if (Array.isArray(h3Index) && h3Index.length === 2 && Number.isInteger(h3Index[0]) && Number.isInteger(h3Index[1])) {
        return h3Index;
      }
      if (typeof h3Index !== "string" || INVALID_HEXIDECIMAL_CHAR.test(h3Index)) {
        return [0, 0];
      }
      var upper = parseInt(h3Index.substring(0, h3Index.length - 8), BASE_16);
      var lower = parseInt(h3Index.substring(h3Index.length - 8), BASE_16);
      return [lower, upper];
    }
    function hexFrom32Bit(num) {
      if (num >= 0) {
        return num.toString(BASE_16);
      }
      num = num & 2147483647;
      var tempStr = zeroPad(8, num.toString(BASE_16));
      var topNum = (parseInt(tempStr[0], BASE_16) + 8).toString(BASE_16);
      tempStr = topNum + tempStr.substring(1);
      return tempStr;
    }
    function splitLongToH3Index(lower, upper) {
      return hexFrom32Bit(upper) + zeroPad(8, hexFrom32Bit(lower));
    }
    function zeroPad(fullLen, numStr) {
      var numZeroes = fullLen - numStr.length;
      var outStr = "";
      for (var i = 0; i < numZeroes; i++) {
        outStr += "0";
      }
      outStr = outStr + numStr;
      return outStr;
    }
    var UPPER_BIT_DIVISOR = Math.pow(2, 32);
    function numberToSplitLong(num) {
      if (typeof num !== "number") {
        return [0, 0];
      }
      return [num | 0, num / UPPER_BIT_DIVISOR | 0];
    }
    function polygonArrayToGeoLoop(polygonArray, geoLoop, isGeoJson) {
      var numVerts = polygonArray.length;
      var geoCoordArray = libh3._calloc(numVerts, SZ_LATLNG);
      var latIndex = isGeoJson ? 1 : 0;
      var lngIndex = isGeoJson ? 0 : 1;
      for (var i = 0; i < numVerts * 2; i += 2) {
        libh3.HEAPF64.set([polygonArray[i / 2][latIndex], polygonArray[i / 2][lngIndex]].map(degsToRads), geoCoordArray / SZ_DBL + i);
      }
      libh3.HEAPU32.set([numVerts, geoCoordArray], geoLoop / SZ_INT);
      return geoLoop;
    }
    function coordinatesToGeoPolygon(coordinates, isGeoJson) {
      var numHoles = coordinates.length - 1;
      var geoPolygon = libh3._calloc(SZ_GEOPOLYGON);
      var geoLoopOffset = 0;
      var numHolesOffset = geoLoopOffset + SZ_GEOLOOP;
      var holesOffset = numHolesOffset + SZ_INT;
      polygonArrayToGeoLoop(coordinates[0], geoPolygon + geoLoopOffset, isGeoJson);
      var holes;
      if (numHoles > 0) {
        holes = libh3._calloc(numHoles, SZ_GEOLOOP);
        for (var i = 0; i < numHoles; i++) {
          polygonArrayToGeoLoop(coordinates[i + 1], holes + SZ_GEOLOOP * i, isGeoJson);
        }
      }
      libh3.setValue(geoPolygon + numHolesOffset, numHoles, "i32");
      libh3.setValue(geoPolygon + holesOffset, holes, "i32");
      return geoPolygon;
    }
    function destroyGeoPolygon(geoPolygon) {
      var geoLoopOffset = 0;
      var numHolesOffset = geoLoopOffset + SZ_GEOLOOP;
      var holesOffset = numHolesOffset + SZ_INT;
      var geoLoopArrayOffset = SZ_INT;
      libh3._free(libh3.getValue(geoPolygon + geoLoopOffset + geoLoopArrayOffset, "i8*"));
      var numHoles = libh3.getValue(geoPolygon + numHolesOffset, "i32");
      if (numHoles > 0) {
        var holes = libh3.getValue(geoPolygon + holesOffset, "i32");
        for (var i = 0; i < numHoles; i++) {
          libh3._free(libh3.getValue(holes + SZ_GEOLOOP * i + geoLoopArrayOffset, "i8*"));
        }
        libh3._free(holes);
      }
      libh3._free(geoPolygon);
    }
    function readH3IndexFromPointer(cAddress, offset) {
      if (offset === void 0) offset = 0;
      var lower = libh3.getValue(cAddress + SZ_H3INDEX * offset, "i32");
      var upper = libh3.getValue(cAddress + SZ_H3INDEX * offset + SZ_INT, "i32");
      return upper ? splitLongToH3Index(lower, upper) : null;
    }
    function readBooleanFromPointer(cAddress, offset) {
      if (offset === void 0) offset = 0;
      var val = libh3.getValue(cAddress + SZ_INT * offset, "i32");
      return Boolean(val);
    }
    function readDoubleFromPointer(cAddress, offset) {
      if (offset === void 0) offset = 0;
      return libh3.getValue(cAddress + SZ_DBL * offset, "double");
    }
    function readInt64AsDoubleFromPointer(cAddress) {
      return H3.readInt64AsDoubleFromPointer(cAddress);
    }
    function storeH3Index(h3Index, cAddress, offset) {
      libh3.HEAPU32.set(h3IndexToSplitLong(h3Index), cAddress / SZ_INT + 2 * offset);
    }
    function readArrayOfH3Indexes(cAddress, maxCount) {
      var out = [];
      for (var i = 0; i < maxCount; i++) {
        var h3Index = readH3IndexFromPointer(cAddress, i);
        if (h3Index !== null) {
          out.push(h3Index);
        }
      }
      return out;
    }
    function storeArrayOfH3Indexes(cAddress, hexagons) {
      var count = hexagons.length;
      for (var i = 0; i < count; i++) {
        storeH3Index(hexagons[i], cAddress, i);
      }
    }
    function storeLatLng(lat, lng) {
      var geoCoord = libh3._calloc(1, SZ_LATLNG);
      libh3.HEAPF64.set([lat, lng].map(degsToRads), geoCoord / SZ_DBL);
      return geoCoord;
    }
    function readSingleCoord(cAddress) {
      return radsToDegs(libh3.getValue(cAddress, "double"));
    }
    function readLatLng(cAddress) {
      return [readSingleCoord(cAddress), readSingleCoord(cAddress + SZ_DBL)];
    }
    function readLatLngGeoJson(cAddress) {
      return [readSingleCoord(cAddress + SZ_DBL), readSingleCoord(cAddress)];
    }
    function readCellBoundary(cellBoundary, geoJsonCoords, closedLoop) {
      var numVerts = libh3.getValue(cellBoundary, "i32");
      var vertsPos = cellBoundary + SZ_DBL;
      var out = [];
      var readCoord = geoJsonCoords ? readLatLngGeoJson : readLatLng;
      for (var i = 0; i < numVerts * 2; i += 2) {
        out.push(readCoord(vertsPos + SZ_DBL * i));
      }
      if (closedLoop) {
        out.push(out[0]);
      }
      return out;
    }
    function readMultiPolygon(polygon, formatAsGeoJson) {
      var output = [];
      var readCoord = formatAsGeoJson ? readLatLngGeoJson : readLatLng;
      var loops;
      var loop;
      var coords;
      var coord;
      while (polygon) {
        output.push(loops = []);
        loop = libh3.getValue(polygon, "i8*");
        while (loop) {
          loops.push(coords = []);
          coord = libh3.getValue(loop, "i8*");
          while (coord) {
            coords.push(readCoord(coord));
            coord = libh3.getValue(coord + SZ_DBL * 2, "i8*");
          }
          if (formatAsGeoJson) {
            coords.push(coords[0]);
          }
          loop = libh3.getValue(loop + SZ_PTR * 2, "i8*");
        }
        polygon = libh3.getValue(polygon + SZ_PTR * 2, "i8*");
      }
      return output;
    }
    function readCoordIJ(cAddress) {
      return {
        i: libh3.getValue(cAddress, "i32"),
        j: libh3.getValue(cAddress + SZ_INT, "i32")
      };
    }
    function storeCoordIJ(cAddress, ref) {
      var i = ref.i;
      var j = ref.j;
      libh3.setValue(cAddress, i, "i32");
      libh3.setValue(cAddress + SZ_INT, j, "i32");
    }
    function readArrayOfPositiveIntegers(cAddress, count) {
      var out = [];
      for (var i = 0; i < count; i++) {
        var int = libh3.getValue(cAddress + SZ_INT * i, "i32");
        if (int >= 0) {
          out.push(int);
        }
      }
      return out;
    }
    function isValidCell(h3Index) {
      var ref = h3IndexToSplitLong(h3Index);
      var lower = ref[0];
      var upper = ref[1];
      return Boolean(H3.isValidCell(lower, upper));
    }
    function isPentagon(h3Index) {
      var ref = h3IndexToSplitLong(h3Index);
      var lower = ref[0];
      var upper = ref[1];
      return Boolean(H3.isPentagon(lower, upper));
    }
    function isResClassIII(h3Index) {
      var ref = h3IndexToSplitLong(h3Index);
      var lower = ref[0];
      var upper = ref[1];
      return Boolean(H3.isResClassIII(lower, upper));
    }
    function getBaseCellNumber(h3Index) {
      var ref = h3IndexToSplitLong(h3Index);
      var lower = ref[0];
      var upper = ref[1];
      return H3.getBaseCellNumber(lower, upper);
    }
    function getIcosahedronFaces(h3Index) {
      var ref = h3IndexToSplitLong(h3Index);
      var lower = ref[0];
      var upper = ref[1];
      var countPtr = libh3._malloc(SZ_INT);
      try {
        throwIfError(H3.maxFaceCount(lower, upper, countPtr));
        var count = libh3.getValue(countPtr, "i32");
        var faces = libh3._malloc(SZ_INT * count);
        try {
          throwIfError(H3.getIcosahedronFaces(lower, upper, faces));
          return readArrayOfPositiveIntegers(faces, count);
        } finally {
          libh3._free(faces);
        }
      } finally {
        libh3._free(countPtr);
      }
    }
    function getResolution(h3Index) {
      var ref = h3IndexToSplitLong(h3Index);
      var lower = ref[0];
      var upper = ref[1];
      if (!H3.isValidCell(lower, upper)) {
        return -1;
      }
      return H3.getResolution(lower, upper);
    }
    function latLngToCell2(lat, lng, res) {
      var latLng = libh3._malloc(SZ_LATLNG);
      libh3.HEAPF64.set([lat, lng].map(degsToRads), latLng / SZ_DBL);
      var h3Index = libh3._malloc(SZ_H3INDEX);
      try {
        throwIfError(H3.latLngToCell(latLng, res, h3Index));
        return validateH3Index(readH3IndexFromPointer(h3Index));
      } finally {
        libh3._free(h3Index);
        libh3._free(latLng);
      }
    }
    function cellToLatLng(h3Index) {
      var latLng = libh3._malloc(SZ_LATLNG);
      var ref = h3IndexToSplitLong(h3Index);
      var lower = ref[0];
      var upper = ref[1];
      try {
        throwIfError(H3.cellToLatLng(lower, upper, latLng));
        return readLatLng(latLng);
      } finally {
        libh3._free(latLng);
      }
    }
    function cellToBoundary(h3Index, formatAsGeoJson) {
      var cellBoundary = libh3._malloc(SZ_CELLBOUNDARY);
      var ref = h3IndexToSplitLong(h3Index);
      var lower = ref[0];
      var upper = ref[1];
      try {
        throwIfError(H3.cellToBoundary(lower, upper, cellBoundary));
        return readCellBoundary(cellBoundary, formatAsGeoJson, formatAsGeoJson);
      } finally {
        libh3._free(cellBoundary);
      }
    }
    function cellToParent(h3Index, res) {
      var ref = h3IndexToSplitLong(h3Index);
      var lower = ref[0];
      var upper = ref[1];
      var parent = libh3._malloc(SZ_H3INDEX);
      try {
        throwIfError(H3.cellToParent(lower, upper, res, parent));
        return validateH3Index(readH3IndexFromPointer(parent));
      } finally {
        libh3._free(parent);
      }
    }
    function cellToChildren(h3Index, res) {
      if (!isValidCell(h3Index)) {
        return [];
      }
      var ref = h3IndexToSplitLong(h3Index);
      var lower = ref[0];
      var upper = ref[1];
      var count = validateArrayLength(cellToChildrenSize(h3Index, res));
      var hexagons = libh3._calloc(count, SZ_H3INDEX);
      try {
        throwIfError(H3.cellToChildren(lower, upper, res, hexagons));
        return readArrayOfH3Indexes(hexagons, count);
      } finally {
        libh3._free(hexagons);
      }
    }
    function cellToChildrenSize(h3Index, res) {
      if (!isValidCell(h3Index)) {
        throw H3LibraryError(E_CELL_INVALID);
      }
      var ref = h3IndexToSplitLong(h3Index);
      var lower = ref[0];
      var upper = ref[1];
      var countPtr = libh3._malloc(SZ_INT64);
      try {
        throwIfError(H3.cellToChildrenSize(lower, upper, res, countPtr));
        return readInt64AsDoubleFromPointer(countPtr);
      } finally {
        libh3._free(countPtr);
      }
    }
    function cellToCenterChild(h3Index, res) {
      var ref = h3IndexToSplitLong(h3Index);
      var lower = ref[0];
      var upper = ref[1];
      var centerChild = libh3._malloc(SZ_H3INDEX);
      try {
        throwIfError(H3.cellToCenterChild(lower, upper, res, centerChild));
        return validateH3Index(readH3IndexFromPointer(centerChild));
      } finally {
        libh3._free(centerChild);
      }
    }
    function cellToChildPos(h3Index, parentRes) {
      var ref = h3IndexToSplitLong(h3Index);
      var lower = ref[0];
      var upper = ref[1];
      var childPos = libh3._malloc(SZ_INT64);
      try {
        throwIfError(H3.cellToChildPos(lower, upper, parentRes, childPos));
        return readInt64AsDoubleFromPointer(childPos);
      } finally {
        libh3._free(childPos);
      }
    }
    function childPosToCell(childPos, h3Index, childRes) {
      var ref = numberToSplitLong(childPos);
      var cpLower = ref[0];
      var cpUpper = ref[1];
      var ref$1 = h3IndexToSplitLong(h3Index);
      var lower = ref$1[0];
      var upper = ref$1[1];
      var child = libh3._malloc(SZ_H3INDEX);
      try {
        throwIfError(H3.childPosToCell(cpLower, cpUpper, lower, upper, childRes, child));
        return validateH3Index(readH3IndexFromPointer(child));
      } finally {
        libh3._free(child);
      }
    }
    function gridDisk(h3Index, ringSize) {
      var ref = h3IndexToSplitLong(h3Index);
      var lower = ref[0];
      var upper = ref[1];
      var countPtr = libh3._malloc(SZ_INT64);
      try {
        throwIfError(H3.maxGridDiskSize(ringSize, countPtr));
        var count = validateArrayLength(readInt64AsDoubleFromPointer(countPtr));
        var hexagons = libh3._calloc(count, SZ_H3INDEX);
        try {
          throwIfError(H3.gridDisk(lower, upper, ringSize, hexagons));
          return readArrayOfH3Indexes(hexagons, count);
        } finally {
          libh3._free(hexagons);
        }
      } finally {
        libh3._free(countPtr);
      }
    }
    function gridDiskDistances(h3Index, ringSize) {
      var ref = h3IndexToSplitLong(h3Index);
      var lower = ref[0];
      var upper = ref[1];
      var countPtr = libh3._malloc(SZ_INT64);
      try {
        throwIfError(H3.maxGridDiskSize(ringSize, countPtr));
        var count = validateArrayLength(readInt64AsDoubleFromPointer(countPtr));
        var kRings = libh3._calloc(count, SZ_H3INDEX);
        var distances = libh3._calloc(count, SZ_INT);
        try {
          throwIfError(H3.gridDiskDistances(lower, upper, ringSize, kRings, distances));
          var out = [];
          for (var i = 0; i < ringSize + 1; i++) {
            out.push([]);
          }
          for (var i$1 = 0; i$1 < count; i$1++) {
            var cell = readH3IndexFromPointer(kRings, i$1);
            var index = libh3.getValue(distances + SZ_INT * i$1, "i32");
            if (cell !== null) {
              out[index].push(cell);
            }
          }
          return out;
        } finally {
          libh3._free(kRings);
          libh3._free(distances);
        }
      } finally {
        libh3._free(countPtr);
      }
    }
    function gridRingUnsafe(h3Index, ringSize) {
      var maxCount = ringSize === 0 ? 1 : 6 * ringSize;
      var hexagons = libh3._calloc(maxCount, SZ_H3INDEX);
      try {
        throwIfError(H3.gridRingUnsafe.apply(H3, h3IndexToSplitLong(h3Index).concat([ringSize], [hexagons])));
        return readArrayOfH3Indexes(hexagons, maxCount);
      } finally {
        libh3._free(hexagons);
      }
    }
    function polygonToCells(coordinates, res, isGeoJson) {
      validateRes(res);
      isGeoJson = Boolean(isGeoJson);
      if (coordinates.length === 0 || coordinates[0].length === 0) {
        return [];
      }
      var polygon = typeof coordinates[0][0] === "number" ? [coordinates] : coordinates;
      var geoPolygon = coordinatesToGeoPolygon(
        // @ts-expect-error - There's no way to convince TS that polygon is now number[][][]
        polygon,
        isGeoJson
      );
      var countPtr = libh3._malloc(SZ_INT64);
      try {
        throwIfError(H3.maxPolygonToCellsSize(geoPolygon, res, 0, countPtr));
        var count = validateArrayLength(readInt64AsDoubleFromPointer(countPtr));
        var hexagons = libh3._calloc(count, SZ_H3INDEX);
        try {
          throwIfError(H3.polygonToCells(geoPolygon, res, 0, hexagons));
          return readArrayOfH3Indexes(hexagons, count);
        } finally {
          libh3._free(hexagons);
        }
      } finally {
        libh3._free(countPtr);
        destroyGeoPolygon(geoPolygon);
      }
    }
    function cellsToMultiPolygon(h3Indexes, formatAsGeoJson) {
      if (!h3Indexes || !h3Indexes.length) {
        return [];
      }
      var indexCount = h3Indexes.length;
      var set = libh3._calloc(indexCount, SZ_H3INDEX);
      storeArrayOfH3Indexes(set, h3Indexes);
      var polygon = libh3._calloc(SZ_LINKED_GEOPOLYGON);
      try {
        throwIfError(H3.cellsToLinkedMultiPolygon(set, indexCount, polygon));
        return readMultiPolygon(polygon, formatAsGeoJson);
      } finally {
        H3.destroyLinkedMultiPolygon(polygon);
        libh3._free(polygon);
        libh3._free(set);
      }
    }
    function compactCells(h3Set) {
      if (!h3Set || !h3Set.length) {
        return [];
      }
      var count = h3Set.length;
      var set = libh3._calloc(count, SZ_H3INDEX);
      storeArrayOfH3Indexes(set, h3Set);
      var compactedSet = libh3._calloc(count, SZ_H3INDEX);
      try {
        throwIfError(H3.compactCells(set, compactedSet, count, UNUSED_UPPER_32_BITS));
        return readArrayOfH3Indexes(compactedSet, count);
      } finally {
        libh3._free(set);
        libh3._free(compactedSet);
      }
    }
    function uncompactCells(compactedSet, res) {
      validateRes(res);
      if (!compactedSet || !compactedSet.length) {
        return [];
      }
      var count = compactedSet.length;
      var set = libh3._calloc(count, SZ_H3INDEX);
      storeArrayOfH3Indexes(set, compactedSet);
      var uncompactCellSizePtr = libh3._malloc(SZ_INT64);
      try {
        throwIfError(H3.uncompactCellsSize(set, count, UNUSED_UPPER_32_BITS, res, uncompactCellSizePtr));
        var uncompactCellSize = validateArrayLength(readInt64AsDoubleFromPointer(uncompactCellSizePtr));
        var uncompactedSet = libh3._calloc(uncompactCellSize, SZ_H3INDEX);
        try {
          throwIfError(H3.uncompactCells(set, count, UNUSED_UPPER_32_BITS, uncompactedSet, uncompactCellSize, UNUSED_UPPER_32_BITS, res));
          return readArrayOfH3Indexes(uncompactedSet, uncompactCellSize);
        } finally {
          libh3._free(set);
          libh3._free(uncompactedSet);
        }
      } finally {
        libh3._free(uncompactCellSizePtr);
      }
    }
    function areNeighborCells(origin, destination) {
      var ref = h3IndexToSplitLong(origin);
      var oLower = ref[0];
      var oUpper = ref[1];
      var ref$1 = h3IndexToSplitLong(destination);
      var dLower = ref$1[0];
      var dUpper = ref$1[1];
      var out = libh3._malloc(SZ_INT);
      try {
        throwIfError(H3.areNeighborCells(oLower, oUpper, dLower, dUpper, out));
        return readBooleanFromPointer(out);
      } finally {
        libh3._free(out);
      }
    }
    function cellsToDirectedEdge(origin, destination) {
      var ref = h3IndexToSplitLong(origin);
      var oLower = ref[0];
      var oUpper = ref[1];
      var ref$1 = h3IndexToSplitLong(destination);
      var dLower = ref$1[0];
      var dUpper = ref$1[1];
      var h3Index = libh3._malloc(SZ_H3INDEX);
      try {
        throwIfError(H3.cellsToDirectedEdge(oLower, oUpper, dLower, dUpper, h3Index));
        return validateH3Index(readH3IndexFromPointer(h3Index));
      } finally {
        libh3._free(h3Index);
      }
    }
    function getDirectedEdgeOrigin(edgeIndex) {
      var ref = h3IndexToSplitLong(edgeIndex);
      var lower = ref[0];
      var upper = ref[1];
      var h3Index = libh3._malloc(SZ_H3INDEX);
      try {
        throwIfError(H3.getDirectedEdgeOrigin(lower, upper, h3Index));
        return validateH3Index(readH3IndexFromPointer(h3Index));
      } finally {
        libh3._free(h3Index);
      }
    }
    function getDirectedEdgeDestination(edgeIndex) {
      var ref = h3IndexToSplitLong(edgeIndex);
      var lower = ref[0];
      var upper = ref[1];
      var h3Index = libh3._malloc(SZ_H3INDEX);
      try {
        throwIfError(H3.getDirectedEdgeDestination(lower, upper, h3Index));
        return validateH3Index(readH3IndexFromPointer(h3Index));
      } finally {
        libh3._free(h3Index);
      }
    }
    function isValidDirectedEdge(edgeIndex) {
      var ref = h3IndexToSplitLong(edgeIndex);
      var lower = ref[0];
      var upper = ref[1];
      return Boolean(H3.isValidDirectedEdge(lower, upper));
    }
    function directedEdgeToCells(edgeIndex) {
      var ref = h3IndexToSplitLong(edgeIndex);
      var lower = ref[0];
      var upper = ref[1];
      var count = 2;
      var hexagons = libh3._calloc(count, SZ_H3INDEX);
      try {
        throwIfError(H3.directedEdgeToCells(lower, upper, hexagons));
        return readArrayOfH3Indexes(hexagons, count);
      } finally {
        libh3._free(hexagons);
      }
    }
    function originToDirectedEdges(h3Index) {
      var ref = h3IndexToSplitLong(h3Index);
      var lower = ref[0];
      var upper = ref[1];
      var count = 6;
      var edges = libh3._calloc(count, SZ_H3INDEX);
      try {
        throwIfError(H3.originToDirectedEdges(lower, upper, edges));
        return readArrayOfH3Indexes(edges, count);
      } finally {
        libh3._free(edges);
      }
    }
    function directedEdgeToBoundary(edgeIndex, formatAsGeoJson) {
      var cellBoundary = libh3._malloc(SZ_CELLBOUNDARY);
      var ref = h3IndexToSplitLong(edgeIndex);
      var lower = ref[0];
      var upper = ref[1];
      try {
        throwIfError(H3.directedEdgeToBoundary(lower, upper, cellBoundary));
        return readCellBoundary(cellBoundary, formatAsGeoJson);
      } finally {
        libh3._free(cellBoundary);
      }
    }
    function gridDistance(origin, destination) {
      var ref = h3IndexToSplitLong(origin);
      var oLower = ref[0];
      var oUpper = ref[1];
      var ref$1 = h3IndexToSplitLong(destination);
      var dLower = ref$1[0];
      var dUpper = ref$1[1];
      var countPtr = libh3._malloc(SZ_INT64);
      try {
        throwIfError(H3.gridDistance(oLower, oUpper, dLower, dUpper, countPtr));
        return readInt64AsDoubleFromPointer(countPtr);
      } finally {
        libh3._free(countPtr);
      }
    }
    function gridPathCells(origin, destination) {
      var ref = h3IndexToSplitLong(origin);
      var oLower = ref[0];
      var oUpper = ref[1];
      var ref$1 = h3IndexToSplitLong(destination);
      var dLower = ref$1[0];
      var dUpper = ref$1[1];
      var countPtr = libh3._malloc(SZ_INT64);
      try {
        throwIfError(H3.gridPathCellsSize(oLower, oUpper, dLower, dUpper, countPtr));
        var count = validateArrayLength(readInt64AsDoubleFromPointer(countPtr));
        var hexagons = libh3._calloc(count, SZ_H3INDEX);
        try {
          H3.gridPathCells(oLower, oUpper, dLower, dUpper, hexagons);
          return readArrayOfH3Indexes(hexagons, count);
        } finally {
          libh3._free(hexagons);
        }
      } finally {
        libh3._free(countPtr);
      }
    }
    var LOCAL_IJ_DEFAULT_MODE = 0;
    function cellToLocalIj(origin, destination) {
      var ij = libh3._malloc(SZ_COORDIJ);
      try {
        throwIfError(H3.cellToLocalIj.apply(H3, h3IndexToSplitLong(origin).concat(h3IndexToSplitLong(destination), [LOCAL_IJ_DEFAULT_MODE], [ij])));
        return readCoordIJ(ij);
      } finally {
        libh3._free(ij);
      }
    }
    function localIjToCell(origin, coords) {
      if (!coords || typeof coords.i !== "number" || typeof coords.j !== "number") {
        throw new Error("Coordinates must be provided as an {i, j} object");
      }
      var ij = libh3._malloc(SZ_COORDIJ);
      var out = libh3._malloc(SZ_H3INDEX);
      storeCoordIJ(ij, coords);
      try {
        throwIfError(H3.localIjToCell.apply(H3, h3IndexToSplitLong(origin).concat([ij], [LOCAL_IJ_DEFAULT_MODE], [out])));
        return validateH3Index(readH3IndexFromPointer(out));
      } finally {
        libh3._free(ij);
        libh3._free(out);
      }
    }
    function greatCircleDistance(latLng1, latLng2, unit) {
      var coord1 = storeLatLng(latLng1[0], latLng1[1]);
      var coord2 = storeLatLng(latLng2[0], latLng2[1]);
      var result;
      switch (unit) {
        case UNITS.m:
          result = H3.greatCircleDistanceM(coord1, coord2);
          break;
        case UNITS.km:
          result = H3.greatCircleDistanceKm(coord1, coord2);
          break;
        case UNITS.rads:
          result = H3.greatCircleDistanceRads(coord1, coord2);
          break;
        default:
          result = null;
      }
      libh3._free(coord1);
      libh3._free(coord2);
      if (result === null) {
        throw JSBindingError(E_UNKNOWN_UNIT, unit);
      }
      return result;
    }
    function cellArea(h3Index, unit) {
      var ref = h3IndexToSplitLong(h3Index);
      var lower = ref[0];
      var upper = ref[1];
      var out = libh3._malloc(SZ_DBL);
      try {
        switch (unit) {
          case UNITS.m2:
            throwIfError(H3.cellAreaM2(lower, upper, out));
            break;
          case UNITS.km2:
            throwIfError(H3.cellAreaKm2(lower, upper, out));
            break;
          case UNITS.rads2:
            throwIfError(H3.cellAreaRads2(lower, upper, out));
            break;
          default:
            throw JSBindingError(E_UNKNOWN_UNIT, unit);
        }
        return readDoubleFromPointer(out);
      } finally {
        libh3._free(out);
      }
    }
    function edgeLength(edge, unit) {
      var ref = h3IndexToSplitLong(edge);
      var lower = ref[0];
      var upper = ref[1];
      var out = libh3._malloc(SZ_DBL);
      try {
        switch (unit) {
          case UNITS.m:
            throwIfError(H3.edgeLengthM(lower, upper, out));
            break;
          case UNITS.km:
            throwIfError(H3.edgeLengthKm(lower, upper, out));
            break;
          case UNITS.rads:
            throwIfError(H3.edgeLengthRads(lower, upper, out));
            break;
          default:
            throw JSBindingError(E_UNKNOWN_UNIT, unit);
        }
        return readDoubleFromPointer(out);
      } finally {
        libh3._free(out);
      }
    }
    function getHexagonAreaAvg(res, unit) {
      validateRes(res);
      var out = libh3._malloc(SZ_DBL);
      try {
        switch (unit) {
          case UNITS.m2:
            throwIfError(H3.getHexagonAreaAvgM2(res, out));
            break;
          case UNITS.km2:
            throwIfError(H3.getHexagonAreaAvgKm2(res, out));
            break;
          default:
            throw JSBindingError(E_UNKNOWN_UNIT, unit);
        }
        return readDoubleFromPointer(out);
      } finally {
        libh3._free(out);
      }
    }
    function getHexagonEdgeLengthAvg(res, unit) {
      validateRes(res);
      var out = libh3._malloc(SZ_DBL);
      try {
        switch (unit) {
          case UNITS.m:
            throwIfError(H3.getHexagonEdgeLengthAvgM(res, out));
            break;
          case UNITS.km:
            throwIfError(H3.getHexagonEdgeLengthAvgKm(res, out));
            break;
          default:
            throw JSBindingError(E_UNKNOWN_UNIT, unit);
        }
        return readDoubleFromPointer(out);
      } finally {
        libh3._free(out);
      }
    }
    function cellToVertex(h3Index, vertexNum) {
      var ref = h3IndexToSplitLong(h3Index);
      var lower = ref[0];
      var upper = ref[1];
      var vertexIndex = libh3._malloc(SZ_H3INDEX);
      try {
        throwIfError(H3.cellToVertex(lower, upper, vertexNum, vertexIndex));
        return validateH3Index(readH3IndexFromPointer(vertexIndex));
      } finally {
        libh3._free(vertexIndex);
      }
    }
    function cellToVertexes(h3Index) {
      var ref = h3IndexToSplitLong(h3Index);
      var lower = ref[0];
      var upper = ref[1];
      var maxNumVertexes = 6;
      var vertexIndexes = libh3._calloc(maxNumVertexes, SZ_H3INDEX);
      try {
        throwIfError(H3.cellToVertexes(lower, upper, vertexIndexes));
        return readArrayOfH3Indexes(vertexIndexes, maxNumVertexes);
      } finally {
        libh3._free(vertexIndexes);
      }
    }
    function vertexToLatLng(h3Index) {
      var latlng = libh3._malloc(SZ_LATLNG);
      var ref = h3IndexToSplitLong(h3Index);
      var lower = ref[0];
      var upper = ref[1];
      try {
        throwIfError(H3.vertexToLatLng(lower, upper, latlng));
        return readLatLng(latlng);
      } finally {
        libh3._free(latlng);
      }
    }
    function isValidVertex(h3Index) {
      var ref = h3IndexToSplitLong(h3Index);
      var lower = ref[0];
      var upper = ref[1];
      return Boolean(H3.isValidVertex(lower, upper));
    }
    function getNumCells(res) {
      validateRes(res);
      var countPtr = libh3._malloc(SZ_INT64);
      try {
        throwIfError(H3.getNumCells(res, countPtr));
        return readInt64AsDoubleFromPointer(countPtr);
      } finally {
        libh3._free(countPtr);
      }
    }
    function getRes0Cells() {
      var count = H3.res0CellCount();
      var hexagons = libh3._malloc(SZ_H3INDEX * count);
      try {
        throwIfError(H3.getRes0Cells(hexagons));
        return readArrayOfH3Indexes(hexagons, count);
      } finally {
        libh3._free(hexagons);
      }
    }
    function getPentagons(res) {
      validateRes(res);
      var count = H3.pentagonCount();
      var hexagons = libh3._malloc(SZ_H3INDEX * count);
      try {
        throwIfError(H3.getPentagons(res, hexagons));
        return readArrayOfH3Indexes(hexagons, count);
      } finally {
        libh3._free(hexagons);
      }
    }
    function degsToRads(deg) {
      return deg * Math.PI / 180;
    }
    function radsToDegs(rad) {
      return rad * 180 / Math.PI;
    }
    exports.UNITS = UNITS;
    exports.h3IndexToSplitLong = h3IndexToSplitLong;
    exports.splitLongToH3Index = splitLongToH3Index;
    exports.isValidCell = isValidCell;
    exports.isPentagon = isPentagon;
    exports.isResClassIII = isResClassIII;
    exports.getBaseCellNumber = getBaseCellNumber;
    exports.getIcosahedronFaces = getIcosahedronFaces;
    exports.getResolution = getResolution;
    exports.latLngToCell = latLngToCell2;
    exports.cellToLatLng = cellToLatLng;
    exports.cellToBoundary = cellToBoundary;
    exports.cellToParent = cellToParent;
    exports.cellToChildren = cellToChildren;
    exports.cellToChildrenSize = cellToChildrenSize;
    exports.cellToCenterChild = cellToCenterChild;
    exports.cellToChildPos = cellToChildPos;
    exports.childPosToCell = childPosToCell;
    exports.gridDisk = gridDisk;
    exports.gridDiskDistances = gridDiskDistances;
    exports.gridRingUnsafe = gridRingUnsafe;
    exports.polygonToCells = polygonToCells;
    exports.cellsToMultiPolygon = cellsToMultiPolygon;
    exports.compactCells = compactCells;
    exports.uncompactCells = uncompactCells;
    exports.areNeighborCells = areNeighborCells;
    exports.cellsToDirectedEdge = cellsToDirectedEdge;
    exports.getDirectedEdgeOrigin = getDirectedEdgeOrigin;
    exports.getDirectedEdgeDestination = getDirectedEdgeDestination;
    exports.isValidDirectedEdge = isValidDirectedEdge;
    exports.directedEdgeToCells = directedEdgeToCells;
    exports.originToDirectedEdges = originToDirectedEdges;
    exports.directedEdgeToBoundary = directedEdgeToBoundary;
    exports.gridDistance = gridDistance;
    exports.gridPathCells = gridPathCells;
    exports.cellToLocalIj = cellToLocalIj;
    exports.localIjToCell = localIjToCell;
    exports.greatCircleDistance = greatCircleDistance;
    exports.cellArea = cellArea;
    exports.edgeLength = edgeLength;
    exports.getHexagonAreaAvg = getHexagonAreaAvg;
    exports.getHexagonEdgeLengthAvg = getHexagonEdgeLengthAvg;
    exports.cellToVertex = cellToVertex;
    exports.cellToVertexes = cellToVertexes;
    exports.vertexToLatLng = vertexToLatLng;
    exports.isValidVertex = isValidVertex;
    exports.getNumCells = getNumCells;
    exports.getRes0Cells = getRes0Cells;
    exports.getPentagons = getPentagons;
    exports.degsToRads = degsToRads;
    exports.radsToDegs = radsToDegs;
  }
});

// h3-entry.mjs
var import_h3_js = __toESM(require_h3_js(), 1);
var export_latLngToCell = import_h3_js.latLngToCell;
return export_latLngToCell;
})();
// ─────────────────────────────────────────────────────────────────────────────

var BAD_CENTROIDS = [
  [39.0119, -98.4842],
  [47.166, 9.5554],
  [42.5462, 1.6016],
  [43.9424, 12.4578],
  [49.815, 6.1296],
  [51.1657, 10.4515],
  [55.378, -3.436],
  [45.9432, 24.9668]
];
var EPS = 0.02;
var MAX_ACCURACY_RADIUS_KM = 200;
function isKnownBadCentroid(lat, lng) {
  return BAD_CENTROIDS.some((b) => Math.abs(lat - b[0]) < EPS && Math.abs(lng - b[1]) < EPS);
}
function validGeoCoord(lat, lng) {
  if (typeof lat !== "number" || typeof lng !== "number") return false;
  if (!isFinite(lat) || !isFinite(lng)) return false;
  if (lat < -90 || lat > 90 || lng < -180 || lng > 180) return false;
  if (lat === 0 && lng === 0) return false;
  if (isKnownBadCentroid(lat, lng)) return false;
  return true;
}
function structurallyValidCoord(lat, lng) {
  if (typeof lat !== "number" || typeof lng !== "number") return false;
  if (!isFinite(lat) || !isFinite(lng)) return false;
  if (lat < -90 || lat > 90 || lng < -180 || lng > 180) return false;
  if (lat === 0 && lng === 0) return false;
  return true;
}
function lookupGeo(reader, ip) {
  if (!ip || typeof ip !== "string") return null;
  let rec;
  try {
    rec = reader.get(ip.trim());
  } catch (_) {
    return null;
  }
  if (!rec || !rec.location) return null;
  /* v55c: salvage a confident COUNTRY when the precise lookup will fail the
   * accuracy/supplemental gates below. MaxMind frequently resolves hosting/
   * datacenter IPs to a correct country with a wide accuracy radius (>gate).
   * Rather than discard that as noGeo, we return a country-only marker so the
   * producer can place an explicitly-approximate country centroid sourced from
   * MaxMind per-IP — more accurate than the static centroid blocklist. Only
   * when iso_code is a real 2-letter code; otherwise fall through to null. */
  const isoCC = rec.country && typeof rec.country.iso_code === "string" && /^[A-Z]{2}$/.test(rec.country.iso_code)
    ? rec.country.iso_code : null;
  const countryMarker = () => isoCC ? { countryOnly: true, cc: isoCC } : null;
  const { latitude: lat, longitude: lng, accuracy_radius: acc } = rec.location;
  const goodAcc = typeof acc === "number" && acc <= MAX_ACCURACY_RADIUS_KM;
  if (goodAcc) {
    if (!structurallyValidCoord(lat, lng)) return null;
  } else {
    if (!validGeoCoord(lat, lng)) return countryMarker();
    const hasCity = !!(rec.city && rec.city.names && rec.city.names.en);
    const hasSubdiv = !!(rec.subdivisions && rec.subdivisions.length);
    if (!hasCity && !hasSubdiv) return countryMarker();
  }
  if (typeof acc === "number" && acc > MAX_ACCURACY_RADIUS_KM) return countryMarker();
  let hexId = null;
  try {
    hexId = __h3_latLngToCell(lat, lng, 4);
  } catch (_) {
    hexId = null;
  }
  return {
    c: [lat, lng],
    cc: rec.country && rec.country.iso_code ? rec.country.iso_code : "",
    city: rec.city && rec.city.names && rec.city.names.en ? rec.city.names.en : "",
    hexId,
    acc: typeof acc === "number" ? acc : null
  };
}
var _readerPromise = null;
async function getReader(env) {
  /* Memoize the Reader so concurrent callers in the same isolate share one
   * R2 fetch + parse. IMPORTANT: do NOT cache a rejected promise. The previous
   * version assigned the IIFE to _readerPromise unconditionally, so a single
   * transient R2 failure (cold-start race, R2 blip, object missing mid-deploy)
   * was cached for the life of the isolate — every later /run and every cron
   * tick re-awaited the same rejection until the isolate recycled, wedging the
   * worker indefinitely. We now clear the cache on failure so the next call
   * retries, while still sharing a successful Reader. */
  if (_readerPromise) return _readerPromise;
  const p = (async () => {
    const obj = await env.GEO_DB.get("GeoLite2-City.mmdb");
    if (!obj) throw new Error("GeoLite2-City.mmdb not found in R2 bucket GEO_DB");
    const ab = await obj.arrayBuffer();
    const buf = Buffer.from(ab);
    return new import_mmdb_lib.Reader(buf);
  })();
  /* Clear the slot if the build rejects, so we don't pin a poisoned promise.
   * The guard (_readerPromise === p) avoids a race where a later successful
   * build has already replaced the slot before this rejection's microtask
   * runs — we only null out our own failed promise, never someone else's. The
   * empty-bodied .catch also marks this rejection as handled on the discarded
   * reference; the original promise `p` still rejects for the awaiting caller. */
  p.catch(() => { if (_readerPromise === p) _readerPromise = null; });
  _readerPromise = p;
  return p;
}
function proxyFetch(env, path) {
  const url = `${env.SELF_PROXY}${path}`;
  if (env.PROXY && typeof env.PROXY.fetch === "function") {
    return env.PROXY.fetch(new Request(url));
  }
  return fetch(url);
}

/* ── Public consensus source (replaces the wallet/forceip IP path) ──────────
 * Anyone Protocol directory authorities (DirPort), hardcoded & open-source in
 * anyone-protocol/ator-protocol  src/app/config/auth_dirs.inc. The consensus
 * each one serves carries every relay's fingerprint AND IP in a single public
 * `r` line — the same document Anon clients download to build circuits. No
 * wallet, no forceip.
 *
 * Kept as a FALLBACK only — see fetchConsensusText below for why the primary
 * path now goes through the producer worker. */
var AUTH_DIRS = [
  "49.13.145.234:9230",  // ATORDAeu
  "5.161.108.187:9230",  // ATORDAuse
  "5.78.90.106:9230",    // ATORDAusw
  "5.161.228.187:9230",  // AnyoneAsh
  "5.78.94.15:9230",     // AnyoneHil
  "95.216.32.105:9230",  // AnyoneHel
  "176.9.29.53:9230"     // AnyoneFal
];
/* Direct-to-authority fetch. PROBLEM (observed live 2026-05): every attempt
 * fails ~instantly with "unreachable" — Cloudflare Workers' fetch does not
 * reliably permit outbound plaintext-http to a raw IP on a nonstandard port
 * (9230). This is the same class of platform restriction that forced
 * anyonemap-worker onto a GitHub mirror (its v393 comment) and that the
 * producer worked around with its hardened _fetchConsensusBytes (which tries
 * https:// variants). Retained here only as a last-ditch fallback in case the
 * producer path is unavailable AND the platform later relaxes. */
async function fetchConsensusDirect() {
  for (const a of AUTH_DIRS) {
    try {
      const res = await fetch(`http://${a}/tor/status-vote/current/consensus`);
      if (res.ok) return await res.text();
    } catch (_) {
    }
  }
  throw new Error("no directory authority reachable (direct)");
}
/* Primary consensus source: the producer worker's /api/consensus route.
 *
 * Why this is the right call rather than hitting authorities directly:
 *   1. Reliability — the producer's _fetchConsensusBytes tries https:// URLs
 *      and is the path proven to work from inside the Workers runtime. The
 *      direct loop (fetchConsensusDirect) is broken by platform fetch limits.
 *   2. Integrity — the producer walks structural validation and, when
 *      env.CONSENSUS_PUBKEY is set there, ed25519 signature verification
 *      BEFORE serving. So this consumer inherits a verified document instead
 *      of trusting whatever a raw DirPort returns over unauthenticated http.
 *      This closes the audit's H2 (enrichment trusted unsigned consensus).
 *   3. Reuse — we already reach the producer via proxyFetch for
 *      /api/relay-registry; consensus uses the identical, working transport
 *      (PROXY service binding when present, else SELF_PROXY over https).
 *
 * The producer returns the raw consensus text/plain on success (the exact
 * format parseConsensus already expects) or a JSON {error} with a 5xx on any
 * failed integrity layer. We surface a 5xx as a thrown error so runSlice's
 * existing catch reports it, then fall back to the direct loop. */
async function fetchConsensusText(env) {
  try {
    const res = await proxyFetch(env, `/api/consensus`);
    if (res.ok) {
      const txt = await res.text();
      /* Guard against a 200 that isn't actually a consensus document (e.g. an
       * HTML error page from an intermediary). A real consensus has `r ` lines;
       * if none are present, treat it as a miss and fall through to fallback. */
      if (txt && /\nr /.test("\n" + txt)) return txt;
      throw new Error("producer /api/consensus returned no relay lines");
    }
    /* Non-2xx from the producer means one of its integrity layers rejected the
     * upstream (502 "upstream unavailable" / "signature did not verify" / etc).
     * Do NOT silently fall back to an UNVERIFIED direct fetch in that case —
     * if the producer refused on signature grounds, bypassing it would
     * reintroduce exactly the trust gap we're closing. Surface the error. */
    let detail = `status ${res.status}`;
    try { const j = await res.json(); if (j && j.error) detail = `${res.status}: ${j.error}`; } catch (_) {}
    throw new Error(`producer /api/consensus ${detail}`);
  } catch (e) {
    /* Network-level failure reaching the producer at all (binding down, DNS,
     * timeout). This is distinct from the producer deliberately rejecting on
     * integrity — here we have no verified source, so the legacy direct loop
     * is a reasonable last resort. It is currently expected to also fail under
     * the platform limit, but trying it preserves the pre-fix behavior exactly
     * and means a future platform change auto-recovers without a redeploy. */
    if (/\/api\/consensus (status 5|5\d\d:)/.test(e.message)) {
      /* Producer reachable but rejected the upstream — propagate, don't bypass. */
      throw e;
    }
    return await fetchConsensusDirect();
  }
}
/* base64 identity -> 40-char uppercase hex fingerprint. A 20-byte fingerprint
 * encodes to 27 b64 chars and needs ONE "=" of padding (pad to a multiple of 4)
 * — verified by round-trip against the ATORDAeu fingerprint. */
function decodeFp(b64id) {
  let s = b64id.replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) s += "=";
  return [...atob(s)].map((c) => c.charCodeAt(0).toString(16).padStart(2, "0")).join("").toUpperCase();
}
function parseConsensus(txt) {
  const map = {};
  for (const line of txt.split("\n")) {
    if (!line.startsWith("r ")) continue;
    const f = line.split(" ");
    let fp;
    try { fp = decodeFp(f[2]); } catch (_) { continue; }
    const ip = f[6];
    if (/^[A-F0-9]{40}$/.test(fp) && ip) map[fp] = ip;
  }
  return map;
}

/* ── Primary IP-map source: the consensus-mirror GitHub repo ────────────────
 * The directory authorities serve consensus only over the ORPort tunnel and
 * return 403 on the plain DirPort — verified live across all 7 authorities, so
 * NEITHER this worker nor the producer's /api/consensus can fetch it directly.
 * A GitHub Action (consensus-mirror repo) runs the real `anon` client, which
 * CAN speak the ORPort tunnel, parses the consensus into a compact
 * { fingerprint(hex) -> IPv4 } JSON map, and commits it. We read that map over
 * plain HTTPS from raw.githubusercontent.com, which Workers reach fine. Same
 * route-around-the-block pattern anyonemap-worker v393 used for bitnodes.
 *
 * Set CONSENSUS_MIRROR_URL to the raw URL of data/consensus-snapshot.json once
 * the mirror repo exists, e.g.:
 *   https://raw.githubusercontent.com/testmodeanyone-bit/anyone-relay-map/main/data/consensus-snapshot.json
 * Overridable via env.CONSENSUS_MIRROR_URL so the repo location isn't hardcoded. */
const CONSENSUS_MIRROR_URL_DEFAULT = "https://raw.githubusercontent.com/testmodeanyone-bit/anyone-relay-map/main/data/consensus-snapshot.json";
const CONSENSUS_SNAPSHOT_MAX_AGE_S = 6 * 60 * 60; // treat a snapshot older than 6h as stale

/* Returns { fp_to_ip } as a plain { HEXFP: "ip" } object, or null on failure.
 * The mirror already did the parsing, so this is just fetch + validate. */
async function fetchIpMapFromMirror(env) {
  const url = (env && env.CONSENSUS_MIRROR_URL) || CONSENSUS_MIRROR_URL_DEFAULT;
  let res;
  try {
    res = await fetch(url, { cf: { cacheTtl: 300, cacheEverything: true } });
  } catch (e) {
    console.warn("[consensus-mirror] fetch threw: " + (e && e.message));
    return null;
  }
  if (!res.ok) {
    console.warn("[consensus-mirror] non-2xx: " + res.status);
    return null;
  }
  let snap;
  try {
    snap = await res.json();
  } catch (_) {
    console.warn("[consensus-mirror] body not JSON");
    return null;
  }
  if (!snap || typeof snap !== "object" || !snap.fp_to_ip || typeof snap.fp_to_ip !== "object") {
    console.warn("[consensus-mirror] snapshot missing fp_to_ip");
    return null;
  }
  /* Staleness check: if the Action has been failing, the committed snapshot
   * ages. We still USE a stale map (a day-old IP map is far better than none —
   * relay IPs are mostly stable), but we log it so ops can notice the mirror
   * stopped updating. */
  if (typeof snap.builtAt === "number") {
    const ageS = Math.floor(Date.now() / 1000) - snap.builtAt;
    if (ageS > CONSENSUS_SNAPSHOT_MAX_AGE_S) {
      console.warn("[consensus-mirror] snapshot stale: " + Math.floor(ageS / 3600) + "h old (mirror Action may be failing)");
    }
  }
  const n = Object.keys(snap.fp_to_ip).length;
  if (n < 1) { console.warn("[consensus-mirror] empty fp_to_ip"); return null; }
  return snap.fp_to_ip;
}

/* Build the fingerprint->IP map, trying sources in order of reliability:
 *   1. GitHub consensus-mirror  (works today; the authorities' 403 doesn't matter)
 *   2. producer /api/consensus  (works only if the producer can reach consensus,
 *      which it currently can't — kept so we auto-recover if upstream policy
 *      changes, and so a verified path is preferred the moment it's available)
 * Returns a { HEXFP: ip } object or throws if every source fails. */
async function fetchIpMap(env) {
  const fromMirror = await fetchIpMapFromMirror(env);
  if (fromMirror) return fromMirror;
  /* Mirror unavailable — fall back to parsing consensus text from the producer
   * (or, failing that, the direct authority loop inside fetchConsensusText). */
  const txt = await fetchConsensusText(env);
  return parseConsensus(txt);
}
/* Negative-cache (tombstone) tuning.
 *
 * The problem this solves: most quarantined relays sit on country-centroid
 * coordinates because the UPSTREAM geolocation couldn't place their IP. MaxMind
 * frequently can't place them either — lookupGeo returns null (a "noGeo"). The
 * pre-fix runSlice wrote NOTHING on a noGeo/noIp, so those relays were re-picked
 * into `todo` on every single run, crowding out genuinely-rescuable relays and
 * pinning the quarantine count. With ~999 centroid_high relays, the slice was
 * mostly re-grinding permanently-unlocatable fingerprints forever.
 *
 * The fix: on a failed lookup we write a tombstone {failed:true, reason, failCount,
 * builtAt}. The todo-builder skips a relay whose tombstone is still "fresh",
 * where freshness grows with failCount (exponential backoff). So a relay that has
 * failed many times is rechecked rarely (data CAN change — an operator fixes
 * geo, MaxMind updates), while the slice fills with relays we haven't recently
 * tried. Successes still use the long 30-day STALE_MS as before. */
const STALE_MS = 30 * 24 * 60 * 60 * 1e3;          // success record freshness
const FAIL_BASE_MS = 6 * 60 * 60 * 1e3;            // first retry no sooner than 6h after a failure
const FAIL_MAX_MS = 30 * 24 * 60 * 60 * 1e3;       // cap backoff at 30 days
/* Backoff window for a tombstone with the given failCount: 6h, 12h, 24h, 48h …
 * doubling each consecutive failure, capped at 30 days. */
function _failBackoffMs(failCount) {
  const n = Math.max(1, failCount | 0);
  const ms = FAIL_BASE_MS * Math.pow(2, n - 1);
  return Math.min(ms, FAIL_MAX_MS);
}

async function runSlice(env, sliceSize, force) {
  const reader = await getReader(env);
  const regResp = await proxyFetch(env, `/api/relay-registry`);
  if (!regResp.ok) return { error: `registry ${regResp.status}` };
  const reg = await regResp.json();
  const relays = reg.relays || {};
  const quarantined = Object.entries(relays).filter(([, r]) => r.geoQuality && String(r.geoQuality).startsWith("quarantined")).map(([fp]) => fp.toUpperCase());
  const now = Date.now();
  const todo = [];
  /* Track the prior tombstone failCount per fp so a repeated failure increments
   * rather than resets it. */
  const priorFail = {};
  let skippedFresh = 0, skippedBackoff = 0;
  for (const fp of quarantined) {
    let cached = null;
    try {
      cached = await env.GEO_ENRICH.get(`geo:${fp}`, { type: "json" });
    } catch (_) {
    }
    if (cached) {
      if (cached.failed) {
        /* Tombstone present — honor exponential backoff before retrying.
         * v56: `force` bypasses backoff. The consensus IP-mirror went live AFTER
         * many of these relays had already accumulated long backoff windows from
         * failing (noIp) when no mirror existed. Their IPs are available now, but
         * the doubling backoff (up to 30d) means the cron only retries ~1/run.
         * A forced drain retries them all once so they enrich immediately; any
         * that still genuinely fail simply re-tombstone and resume normal backoff. */
        if (!force) {
          const wait = _failBackoffMs(cached.failCount);
          if (cached.builtAt && now - cached.builtAt < wait) { skippedBackoff++; continue; }
        }
        /* Backoff elapsed (or forced): eligible for retry; carry failCount forward. */
        priorFail[fp] = cached.failCount | 0;
      } else if (cached.countryOnly === true) {
        /* v55d: country_only record (approximate, country known). Under force we
         * re-evaluate it (MaxMind may now place it precisely, or its country may
         * have changed); otherwise treat it like a fresh result and skip while
         * fresh. Without this, a forced country_only drain could never refresh or
         * upgrade these records — they'd fall to the success-skip below. */
        if (!force && cached.builtAt && now - cached.builtAt <= STALE_MS) { skippedFresh++; continue; }
        /* forced, or stale → fall through and re-evaluate. */
      } else if (Array.isArray(cached.c) && cached.builtAt && now - cached.builtAt <= STALE_MS) {
        /* Fresh PRECISE success record (has real coords) — nothing to do, even
         * under force: re-doing good precise work wastes lookups and can only
         * regress a confident pin. (Tombstones and country_only records ARE
         * reprocessed under force, above — that's the point of a forced drain.) */
        skippedFresh++;
        continue;
      }
      /* else: stale success, or forced non-precise → fall through and re-enrich. */
    }
    todo.push(fp);
    if (todo.length >= sliceSize) break;
  }
  let ipMap;
  try {
    ipMap = await fetchIpMap(env);
  } catch (e) {
    return { error: `consensus fetch failed: ${e.message}` };
  }
  let ok = 0, noIp = 0, noGeo = 0, countryOnly = 0;
  /* Helper: record a failure tombstone so this fp is backed off rather than
   * retried every run. Increments failCount from any prior tombstone. Failures
   * are fire-and-forget on write errors — a missed tombstone just means the
   * relay is retried sooner, which is safe. */
  const writeFail = (fp, reason) => {
    const failCount = (priorFail[fp] | 0) + 1;
    const rec = { failed: true, reason, failCount, builtAt: now };
    /* Validate against the inlined geo-schema before writing (S2). On failure,
     * skip the write rather than poison GEO_ENRICH — a missing tombstone just
     * means the fp is retried sooner, which is safe (same as the prior
     * fire-and-forget .catch() behaviour). */
    const v = _geoValidate(rec, { mode: "strict", context: "write" });
    if (!v.ok) {
      console.warn(`geo-schema reject (tombstone ${fp}): ${v.errors.join("; ")}`);
      return Promise.resolve();
    }
    return env.GEO_ENRICH.put(`geo:${fp}`, JSON.stringify(rec)).catch(() => {});
  };
  for (const fp of todo) {
    const ip = ipMap[fp];
    if (!ip) { noIp++; await writeFail(fp, "noIp"); continue; }
    const geo = lookupGeo(reader, ip);
    if (!geo) { noGeo++; await writeFail(fp, "noGeo"); continue; }
    /* v55c: country-only marker — MaxMind gave a confident country but not a
     * precise-enough location. Write the country_only variant (no coordinate)
     * so the producer sets countryCode + approxLocation:true and centroids it,
     * MaxMind-per-IP-accurate rather than from the static centroid blocklist.
     * NOT a tombstone: we want enrichFromCache to read and apply it, and we want
     * a future run to still be able to upgrade it to a precise SUCCESS. */
    if (geo.countryOnly === true) {
      const rec = { countryOnly: true, cc: geo.cc, builtAt: now };
      const v = _geoValidate(rec, { mode: "strict", context: "write" });
      if (!v.ok) {
        console.warn(`geo-schema reject (country_only ${fp}): ${v.errors.join("; ")}`);
        /* Fall back to a tombstone so the fp at least backs off rather than
         * re-grinding every run. */
        noGeo++; await writeFail(fp, "noGeo"); continue;
      }
      /* Write is fire-and-forget on error (matches writeFail): a transient KV
       * write failure must not throw out of the todo loop and skip the
       * geo:_cursor update below. Only count it as a success once the put
       * resolves; on failure the fp simply isn't counted and is retried next run. */
      try {
        await env.GEO_ENRICH.put(`geo:${fp}`, JSON.stringify(rec));
        countryOnly++;
      } catch (_) {}
      continue;
    }
    const rec = { c: geo.c, cc: geo.cc, city: geo.city, hexId: geo.hexId, builtAt: now };
    /* Validate against the inlined geo-schema before writing (S2). On failure,
     * skip this fp (don't count it as ok) — it'll be retried next run. Better to
     * leave a relay un-enriched than to write a malformed record the producer
     * would then read. */
    const v = _geoValidate(rec, { mode: "strict", context: "write" });
    if (!v.ok) {
      console.warn(`geo-schema reject (success ${fp}): ${v.errors.join("; ")}`);
      noGeo++;
      continue;
    }
    /* Fire-and-forget on write error, same as the country_only and tombstone
     * paths: a transient KV failure must not throw out of the loop and skip the
     * geo:_cursor update below. Count as ok only once the put resolves. */
    try {
      await env.GEO_ENRICH.put(`geo:${fp}`, JSON.stringify(rec));
      ok++;
    } catch (_) {}
  }
  await env.GEO_ENRICH.put("geo:_cursor", JSON.stringify({
    lastRunAt: now,
    quarantinedTotal: quarantined.length,
    processedThisRun: todo.length,
    consensusRelays: Object.keys(ipMap).length,
    ok,
    countryOnly,
    noIp,
    noGeo,
    skippedFresh,
    skippedBackoff,
    source: "consensus"
  }));
  return { quarantinedTotal: quarantined.length, processed: todo.length, consensusRelays: Object.keys(ipMap).length, ok, countryOnly, noIp, noGeo, skippedFresh, skippedBackoff };
}

/* ── auditMismatches: READ-ONLY declared-vs-IP country audit ────────────────
 * Walks every relay in the registry and, for each one that has BOTH a declared
 * country (countryCode) AND a consensus IP that MaxMind can resolve to a
 * country, compares the two. A "mismatch" is a different ISO country code.
 *
 * Writes NOTHING — this is a diagnostic. It does not re-quarantine, does not
 * touch GEO_ENRICH, does not change any relay. (Re-quarantine is a separate,
 * producer-side change; this endpoint exists to measure the problem first.)
 *
 * Note on tiers: the producer NULLS countryCode on quarantined relays, so those
 * have no declared country to compare and are counted under `noDeclared`. The
 * meaningful mismatches surface on `trusted` / `flagged` relays — exactly the
 * un-IP-checked population. Each mismatch row carries the relay's tier so the
 * caller can see where the disagreements cluster.
 *
 * Returns counts plus a capped list of mismatch rows. fp is the relay's own
 * public fingerprint (already public in the registry); no IPs are returned. */
async function auditMismatches(env, opts) {
  opts = opts || {};
  const cap = Math.min(parseInt(opts.limit || 500, 10) || 500, 5000);
  const reader = await getReader(env);
  const regResp = await proxyFetch(env, `/api/relay-registry`);
  if (!regResp.ok) return { error: `registry ${regResp.status}` };
  const reg = await regResp.json();
  const relays = reg.relays || {};
  let ipMap;
  try {
    ipMap = await fetchIpMap(env);
  } catch (e) {
    return { error: `consensus fetch failed: ${e.message}` };
  }

  /* Light country-only lookup: we want the country even when lookupGeo would
   * reject the precise coords (large accuracy radius), because country-level
   * resolution is reliable far more often than city-level. Returns ISO cc or
   * null. */
  const ipCountry = (ip) => {
    if (!ip || typeof ip !== "string") return null;
    let rec;
    try { rec = reader.get(ip.trim()); } catch (_) { return null; }
    return rec && rec.country && rec.country.iso_code ? rec.country.iso_code : null;
  };

  const stats = {
    total: 0, compared: 0, mismatches: 0,
    noDeclared: 0,        // relay has no declared countryCode (e.g. quarantined)
    noIp: 0,              // no consensus IP for this fp
    ipUnresolved: 0,      // had IP but MaxMind gave no country
    byTier: {}            // mismatch counts grouped by current geoQuality tier
  };
  const rows = [];

  for (const fpRaw in relays) {
    if (!/^[A-Fa-f0-9]{6,}$/.test(fpRaw)) continue;
    stats.total++;
    const r = relays[fpRaw] || {};
    const tier = String(r.geoQuality || "unknown");
    const declared = r.countryCode || null;
    if (!declared) { stats.noDeclared++; continue; }
    const fp = fpRaw.toUpperCase();
    const ip = ipMap[fp];
    if (!ip) { stats.noIp++; continue; }
    const ipCc = ipCountry(ip);
    if (!ipCc) { stats.ipUnresolved++; continue; }
    stats.compared++;
    if (ipCc.toUpperCase() !== String(declared).toUpperCase()) {
      stats.mismatches++;
      stats.byTier[tier] = (stats.byTier[tier] | 0) + 1;
      if (rows.length < cap) {
        rows.push({ fp, declared: String(declared).toUpperCase(), ipCountry: ipCc.toUpperCase(), tier });
      }
    }
  }

  /* Second pass: classify each mismatch as a LIKELY GENUINE MISLABEL vs a
   * LIKELY HOSTING ARTIFACT. The signal that distinguished CWPRELAYBRA01 (a
   * real Brazil relay declared as Lithuania) from the 38 benign cases:
   *   - hosting artifact: IP resolves to a major hosting-hub country (operator
   *     in country X renting a server in a DE/US/NL/GB/FR datacenter), OR the
   *     declared->ip country pair appears multiple times (a cluster = a common
   *     hosting route, not an individual error).
   *   - genuine mislabel: IP in a NON-hub country AND the pair is a singleton.
   * This is triage guidance for human review, NOT an action trigger — the
   * override (if built) acts on an explicit allowlist, never on this heuristic
   * automatically. */
  const HOSTING_HUBS = new Set(["US", "DE", "NL", "GB", "FR"]);
  const pairCount = {};
  for (const r of rows) {
    const k = r.declared + ">" + r.ipCountry;
    pairCount[k] = (pairCount[k] | 0) + 1;
  }
  let likelyMislabel = 0, likelyHosting = 0;
  for (const r of rows) {
    const k = r.declared + ">" + r.ipCountry;
    const hubIp = HOSTING_HUBS.has(r.ipCountry);
    const clustered = pairCount[k] > 1;
    r.classification = (!hubIp && !clustered) ? "likely_mislabel" : "likely_hosting";
    if (r.classification === "likely_mislabel") likelyMislabel++; else likelyHosting++;
  }

  return {
    mode: "audit-readonly",
    builtAt: Date.now(),
    stats,
    summary: {
      relaysChecked: stats.compared,
      countryMismatches: stats.mismatches,
      likelyMislabel,       // genuine errors worth correcting (e.g. CWPRELAYBRA01)
      likelyHosting,        // benign: operator in X, server in a hosting hub
      couldNotCheck: { noDeclaredCountry: stats.noDeclared, noConsensusIp: stats.noIp, ipUnresolved: stats.ipUnresolved }
    },
    mismatchCount: stats.mismatches,
    returned: rows.length,
    capped: stats.mismatches > rows.length,
    mismatches: rows
  };
}

/* ── inspectFp: READ-ONLY full MaxMind detail for ONE fingerprint ───────────
 * Diagnostic companion to /audit. Given a single relay fingerprint, returns
 * the full MaxMind resolution of its consensus IP — AS name/number, city,
 * country, coords, accuracy radius — plus its declared geo from the registry,
 * so the two can be compared in detail. This is what turns "it's in BR somehow"
 * into "it's on AS-NNNN (some hosting co) near <city>".
 *
 * Writes NOTHING. The relay's IP is used for the lookup but is NOT returned
 * (only the geo facts MaxMind derives from it). Same token gate as /audit. */
async function inspectFp(env, fpInput) {
  if (!fpInput || !/^[A-Fa-f0-9]{6,}$/.test(fpInput)) {
    return { error: "missing or invalid fp (expected hex fingerprint)" };
  }
  const fp = fpInput.toUpperCase();
  const reader = await getReader(env);
  const regResp = await proxyFetch(env, `/api/relay-registry`);
  if (!regResp.ok) return { error: `registry ${regResp.status}` };
  const reg = await regResp.json();
  const relays = reg.relays || {};
  const regKey = Object.keys(relays).find((k) => k.toUpperCase() === fp);
  const declared = regKey ? {
    countryCode: relays[regKey].countryCode || null,
    countryName: relays[regKey].countryName || null,
    coordinates: Array.isArray(relays[regKey].coordinates) ? relays[regKey].coordinates : null,
    geoQuality: relays[regKey].geoQuality || null
  } : null;

  let ipMap;
  try { ipMap = await fetchIpMap(env); }
  catch (e) { return { error: `consensus fetch failed: ${e.message}` }; }
  const ip = ipMap[fp];
  if (!ip) {
    return { fp, inRegistry: !!regKey, declared, ipResolution: null, note: "no consensus IP for this fp" };
  }

  /* Full MaxMind record (NOT just country, unlike /audit). IP itself not returned. */
  let rec = null;
  try { rec = reader.get(ip.trim()); } catch (_) { rec = null; }
  let ipResolution = null;
  if (rec) {
    const loc = rec.location || {};
    ipResolution = {
      country: rec.country && rec.country.iso_code ? rec.country.iso_code : null,
      countryName: rec.country && rec.country.names ? (rec.country.names.en || null) : null,
      city: rec.city && rec.city.names ? (rec.city.names.en || null) : null,
      subdivision: rec.subdivisions && rec.subdivisions[0] && rec.subdivisions[0].names ? (rec.subdivisions[0].names.en || null) : null,
      coordinates: (typeof loc.latitude === "number" && typeof loc.longitude === "number") ? [loc.latitude, loc.longitude] : null,
      accuracyRadiusKm: typeof loc.accuracy_radius === "number" ? loc.accuracy_radius : null,
      /* AS data only present if the worker has an ASN database loaded; the City
       * db alone won't have it. Surfaced if available, null otherwise. */
      asNumber: rec.autonomous_system_number || (rec.traits && rec.traits.autonomous_system_number) || null,
      asOrg: rec.autonomous_system_organization || (rec.traits && rec.traits.autonomous_system_organization) || null
    };
  }

  const countryMismatch = !!(declared && declared.countryCode && ipResolution && ipResolution.country &&
    declared.countryCode.toUpperCase() !== ipResolution.country.toUpperCase());

  return { fp, inRegistry: !!regKey, declared, ipResolution, countryMismatch };
}

var enrichment_worker_default = {
  async scheduled(event, env, ctx) {
    ctx.waitUntil(runSlice(env, 25).catch((e) => console.warn("[enrich.scheduled]", e)));
  },
  async fetch(req, env) {
    const url = new URL(req.url);
    /* H3 fix: /run triggers runSlice, which does outbound fetches (consensus
     * mirror) and KV writes. Left open, anyone on the internet could spam it to
     * amplify outbound load / burn KV writes. Gate it behind a shared secret.
     *
     * The token is read from env.RUN_TOKEN (set via `wrangler secret put RUN_TOKEN`
     * or the dashboard). The caller supplies it as either:
     *   - ?token=<secret>            (convenient for manual curl)
     *   - Authorization: Bearer <secret>
     *
     * Fail-closed: if RUN_TOKEN is not configured we REFUSE /run (503) rather
     * than leaving it open — the safe default for a write/outbound endpoint. The
     * scheduled() cron path below is unaffected: it calls runSlice directly and
     * never goes through this HTTP auth, so automatic draining keeps working
     * even with no token set. Constant-time-ish compare to avoid trivial timing
     * leaks (tokens are short and this is low-value, but it costs nothing). */
    function timingSafeEqual(a, b) {
      if (typeof a !== "string" || typeof b !== "string") return false;
      if (a.length !== b.length) return false;
      let diff = 0;
      for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
      return diff === 0;
    }
    function isAuthorized(req2, env2) {
      const secret = env2 && env2.RUN_TOKEN;
      if (!secret) return null; // signal "not configured" -> fail closed
      const u = new URL(req2.url);
      const qp = u.searchParams.get("token") || "";
      const hdr = req2.headers.get("authorization") || "";
      const bearer = hdr.toLowerCase().startsWith("bearer ") ? hdr.slice(7) : "";
      return timingSafeEqual(qp, secret) || timingSafeEqual(bearer, secret);
    }

    if (url.pathname === "/debug") {
      /* /debug leaks env var NAMES (allEnvKeys) and binding presence — minor,
       * but gate it behind the same token so recon isn't free. Read-only. */
      const auth = isAuthorized(req, env);
      if (auth === null) return new Response("debug disabled: set RUN_TOKEN secret to enable", { status: 503 });
      if (!auth) return new Response("unauthorized", { status: 401 });
      /* bindingStatus: "<typeof> <present-or-missing>". `present` is the truthy
       * test result; `presentText` describes the present case (defaults to the
       * plain marker). Extracted from four inline ternaries so the status
       * strings live in one place — also removes the repeated literal that the
       * check-dupes guard flagged as a duplicate. Output is byte-identical to
       * the previous inline form. */
      const bindingStatus = (val, present, presentText) =>
        typeof val + (present ? (presentText || " (present)") : " (MISSING)");
      return Response.json({
        ok: true,
        bindings: {
          GEO_DB: bindingStatus(env.GEO_DB, env.GEO_DB),
          GEO_ENRICH: bindingStatus(env.GEO_ENRICH, env.GEO_ENRICH),
          SELF_PROXY: bindingStatus(env.SELF_PROXY, env.SELF_PROXY, " = " + env.SELF_PROXY),
          PROXY: bindingStatus(env.PROXY, env.PROXY && env.PROXY.fetch, " (service binding present)")
        },
        allEnvKeys: Object.keys(env || {})
      });
    }
    if (url.pathname === "/status") {
      /* /status stays public: read-only, no outbound work, just the cursor. */
      let cursor = null;
      try {
        cursor = await env.GEO_ENRICH.get("geo:_cursor", { type: "json" });
      } catch (_) {
      }
      return Response.json({ ok: true, cursor });
    }
    if (url.pathname === "/run") {
      const auth = isAuthorized(req, env);
      if (auth === null) {
        return new Response("/run disabled: set RUN_TOKEN secret (wrangler secret put RUN_TOKEN) to enable manual runs. The scheduled cron still runs automatically.", { status: 503 });
      }
      if (!auth) {
        return new Response("unauthorized: /run requires a valid token (?token= or Authorization: Bearer)", { status: 401 });
      }
      /* v56: ?force=1 bypasses the exponential backoff so a one-shot drain can
       * retry every tombstoned relay now that the consensus IP-mirror is healthy.
       * Forced runs allow a larger slice (cap 300) so the whole ~251 backlog
       * clears in a single pass; normal runs keep the 200 cap. */
      const force = /^(1|true|yes)$/i.test(url.searchParams.get("force") || "");
      const cap = force ? 300 : 200;
      const n = Math.min(parseInt(url.searchParams.get("n") || (force ? "300" : "50"), 10), cap);
      const result = await runSlice(env, n, force);
      return Response.json(Object.assign({ forced: force }, result));
    }
    if (url.pathname === "/audit") {
      /* READ-ONLY declared-vs-IP country audit. Same token gate as /run (it
       * reads the registry + consensus + MaxMind, so gate it to avoid free
       * recon / outbound amplification), but it writes nothing. */
      const auth = isAuthorized(req, env);
      if (auth === null) {
        return new Response("/audit disabled: set RUN_TOKEN secret to enable.", { status: 503 });
      }
      if (!auth) {
        return new Response("unauthorized: /audit requires a valid token (?token= or Authorization: Bearer)", { status: 401 });
      }
      const limit = url.searchParams.get("limit") || "500";
      const result = await auditMismatches(env, { limit });
      return Response.json(result);
    }
    if (url.pathname === "/inspect") {
      /* READ-ONLY single-fp MaxMind detail. Same token gate as /audit/run. */
      const auth = isAuthorized(req, env);
      if (auth === null) {
        return new Response("/inspect disabled: set RUN_TOKEN secret to enable.", { status: 503 });
      }
      if (!auth) {
        return new Response("unauthorized: /inspect requires a valid token (?token= or Authorization: Bearer)", { status: 401 });
      }
      const fp = url.searchParams.get("fp") || "";
      const result = await inspectFp(env, fp);
      return Response.json(result);
    }
    return new Response("enrichment worker: GET /run?n=50 (auth required) or /status", { status: 200 });
  }
};
export {
  enrichment_worker_default as default
};
