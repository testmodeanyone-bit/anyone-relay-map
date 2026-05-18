# anyone-relay-map
ANyone Protocol live relay map — D3.js world map, AnyClip AI, network health score, custom icons.
anyone-relay-map — bitnodes snapshot mirror
This repository exists for one reason: to mirror the public Bitcoin node snapshot from bitnodes.io into a location that the AnyoneMap Cloudflare Worker can actually fetch.
Why this mirror exists
bitnodes.io is fronted by Cloudflare. The AnyoneMap worker runs on Cloudflare Workers. Cloudflare blocks Workers-to-Workers fetch traffic to other Cloudflare-protected sites unless explicitly allowlisted by the destination's owner, returning HTTP 530 to the calling Worker.
We can't change bitnodes.io's WAF rules, so the mirror routes around the block: GitHub Actions runners are not on Cloudflare's network, so they can fetch bitnodes.io normally. The runner saves the response into this repo, and the AnyoneMap worker fetches from raw.githubusercontent.com — which Cloudflare Workers fetch traffic can reach.
How it works
.github/workflows/bitnodes-mirror.yml runs on a 30-minute cron:

curl to https://bitnodes.io/api/v1/snapshots/latest/ with a polite User-Agent
Validate the response is JSON with the expected shape and a plausible number of nodes (>1000)
Commit the result to data/bitnodes-snapshot.json if it differs from the previous version (it always will — bitnodes increments the timestamp field each snapshot)
Push the commit

The worker then fetches:
https://raw.githubusercontent.com/testmodeanyone-bit/anyone-relay-map/main/data/bitnodes-snapshot.json
Operational notes

Cron jitter: GitHub Actions queues cron triggers; expect 5-30 minutes of late firing under load. The worker's 30-min KV refresh with stale-while-revalidate handles this fine.
Upstream errors: if bitnodes.io returns non-200, the workflow skips the commit and exits cleanly. The last-good snapshot remains in the repo and the worker keeps serving it. Missing commits in the history are the signal that something went wrong.
Rate limits: bitnodes.io rate-limits unauthenticated requests to 10/day per IP. GitHub Actions runners share IPs across many projects, so 429 is occasionally possible. The workflow treats 429 as a skipped run, same as any other non-200.
Validation: the workflow refuses to commit a snapshot with fewer than 1000 nodes — a real Bitcoin network snapshot has ~20,000+. This protects against partial/corrupted responses publishing to consumers.

Triggering manually
The workflow has workflow_dispatch: enabled, so you can also run it on demand from the GitHub Actions tab. Useful right after creating the repo (so the first snapshot lands without waiting for the next cron tick).
Schema
The committed JSON matches bitnodes.io's API response shape exactly:
json{
  "timestamp": 1779120000,
  "total_nodes": 22847,
  "latest_height": 925545,
  "nodes": {
    "203.0.113.5:8333": [
      70016,                      // protocol version
      "/Satoshi:26.0.0/",         // user agent
      1764082507,                  // last seen
      1033,                        // services bitmask
      925545,                      // height
      "203.0.113.5",               // host
      8333,                        // port
      "US",                        // country code
      40.7128,                     // latitude
      -74.0060,                    // longitude
      0,                           // timezone offset
      0,                           // ASN
      "DigitalOcean",              // organization
      "New York"                   // city
    ]
  }
}
(Bitnodes' actual array element order is: protocol version, user agent, last seen, services, height, host, port, country code, latitude, longitude, timezone, ASN, organization, city. The AnyoneMap worker reads indices 1, 6, 7, 8, 9, 12 for user agent, country, latitude, longitude, and organization respectively.)
