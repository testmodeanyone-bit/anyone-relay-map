anyone-relay-map — bitnodes snapshot mirror
This repository exists for one reason: to mirror a Bitcoin node snapshot into a location that the AnyoneMap Cloudflare Worker can actually fetch. The worker fetches data/bitnodes-snapshot.json from this repo via raw.githubusercontent.com and serves it from the /api/bitnodes route after stratified sampling by country.
Why this mirror exists
bitnodes.io is fronted by Cloudflare. The AnyoneMap worker runs on Cloudflare Workers. Cloudflare blocks Workers-to-Workers fetch traffic to other Cloudflare-protected sites unless explicitly allowlisted by the destination's owner — calls return HTTP 530 to the calling Worker. We can't change bitnodes.io's WAF rules, so the mirror routes around the block: GitHub Actions runners are not on Cloudflare's network, so they can fetch bitnodes.io normally. The runner saves the response into this repo, and the AnyoneMap worker fetches from raw.githubusercontent.com — which Cloudflare Workers can reach.
Data sources
The snapshot in data/bitnodes-snapshot.json is populated by one of two paths:

Primary: bitnodes.io mirror. .github/workflows/bitnodes-mirror.yml runs every 30 minutes, fetches https://bitnodes.io/api/v1/snapshots/latest/ with a polite User-Agent, validates the response shape, and commits the result. This produces total_nodes in the ~20,000+ range with full bitnodes metadata.
Fallback: a path that uses Bitcoin DNS seed servers. When the primary path is unavailable for any reason — rate-limit exhaustion, upstream outage, or anything else that makes the bitnodes.io fetch unusable — a separate fallback path populates the snapshot from Bitcoin's public DNS seeds (the same seed.bitcoin.sipa.be / seed.bitnodes.io / dnsseed.bluematt.me set that Bitcoin Core uses to discover initial peers). This produces a smaller snapshot (typically ~100 nodes) with "source": "dns-seeders" and IP-based geolocation rather than bitnodes' richer per-node data.

You can tell which path produced the current snapshot by reading the source field at the top of the JSON: "source": "bitnodes-mirror" for the primary, "source": "dns-seeders" for the fallback. (If the field is absent in older commits, it's a primary-path snapshot from before the fallback was added.)
How the primary mirror works
.github/workflows/bitnodes-mirror.yml on a 30-minute cron:

curl to https://bitnodes.io/api/v1/snapshots/latest/ with a polite User-Agent
Validate the response is JSON with the expected shape and at least 1000 nodes
Commit the result to data/bitnodes-snapshot.json if it differs from the previous version (it always will — bitnodes updates the timestamp field on every snapshot)
Push the commit

The worker then fetches: https://raw.githubusercontent.com/testmodeanyone-bit/anyone-relay-map/main/data/bitnodes-snapshot.json
Operational notes

Cron jitter: GitHub Actions queues cron triggers; expect 5–30 minutes of late firing under load. The worker's 30-min KV refresh with stale-while-revalidate handles this fine.
Upstream errors: if bitnodes.io returns non-200, the workflow skips the commit and exits cleanly. The last-good snapshot remains in the repo and the worker keeps serving it. Missing commits in the history are the signal that something went wrong.
Rate limits: bitnodes.io rate-limits unauthenticated requests to 10/day per IP. GitHub Actions runners share IPs across many projects, so 429 is occasionally possible. The workflow treats 429 as a skipped run, same as any other non-200.
Validation: the workflow refuses to commit a primary-path snapshot with fewer than 1000 nodes — a real Bitcoin network snapshot has ~20,000+. This protects against partial/corrupted responses publishing to consumers. The fallback path uses its own (lower) threshold because DNS seeds return far fewer entries by design.

Triggering manually
The workflow has workflow_dispatch: enabled, so you can also run it on demand from the GitHub Actions tab. Useful right after creating the repo (so the first snapshot lands without waiting for the next cron tick).
Schema
The committed JSON matches bitnodes.io's API response shape, plus an optional source field added by the fallback path:
json{
  "timestamp": 1779120000,
  "total_nodes": 22847,
  "latest_height": 925545,
  "source": "bitnodes-mirror",
  "nodes": {
    "203.0.113.5:8333": [
      70016,
      "/Satoshi:26.0.0/",
      1764082507,
      1033,
      925545,
      "203.0.113.5",
      8333,
      "US",
      40.7128,
      -74.0060,
      0,
      0,
      "DigitalOcean",
      "New York"
    ]
  }
}
Node array field index reference
Each entry in nodes is keyed by "<address>:<port>" and maps to a 14-element array. The index numbers below are load-bearing — the AnyoneMap worker reads several of these by position, and getting one wrong silently corrupts the field's meaning (e.g., reading index 6 as "city" stores the port number 8333 as the city name on every node).
IndexFieldTypeExampleRead by worker?0protocol versionint70016No1user agentstring/Satoshi:26.0.0/Yes (ua)2last seenint1764082507No3services bitmaskint1033No4block heightint925545No5hoststring203.0.113.5No6portint8333No7country codestringUSYes (cc)8latitudefloat40.7128Yes (lat)9longitudefloat-74.0060Yes (lon)10timezone offsetint0No11ASNint0No12organizationstringDigitalOceanYes (org)13citystringNew YorkYes (city)
The worker's scheduled() handler iterates this array, validates that indices 7/8/9 are present, and emits {lat, lon, cc, city, org, ua} objects into the country-bucketed sample. Changing the upstream array order without updating both the worker and this table will break the dashboard silently — the validation only catches missing-or-falsy values, not field-meaning drift. If you add new fields, append them to the end of the array; if you reorder existing ones, audit every consumer first.
Top-level fields
FieldTypeNotestimestampintUnix seconds when the snapshot was generated by the source. Changes every commit.total_nodesintTotal node count in the snapshot.latest_heightintLatest block height observed across the snapshot. May be 0 on the fallback path.sourcestring"bitnodes-mirror" or "dns-seeders". Optional in older commits; assume primary if absent.nodesobjectMap of "<address>:<port>" → 14-element array (see table above).
