# beamline

Beamline looks up a PURL, an exact URL, a SHA-256, or uploaded bytes and returns a
hostility level. Hostile answers include at most three findings.
See [API.md](API.md).

One JavaScript file, no npm packages. It runs as `node local.js` or as a
Cloudflare Worker. Hopper and scan sit behind Cloudflare Tunnels and their
URLs come from the environment; the tree does not name a host.

`SCAN_URL` may be a comma-separated list of interchangeable scan workers. One
is asked at a time, favourite first, and the next is reached only when the one
before it refuses or fails — so a sample costs one analysis slot however many
workers are configured. The order is measured rather than configured: each
worker publishes its own timings and beamline ranks on them per size and
package type. `GET /_/routes` shows the order it would use right now.

Beamline raced every healthy worker once and does not any more: a losing arm
cannot be called off across a Worker abort, the Cloudflare edge, and a tunnel,
so it was measured still analysing 77 seconds after it lost. Each worker has
its own circuit breaker, so a sick one leaves the order without taking scanning
down with it.

An analysis stream survives losing its worker. A v1 stream is progress frames
followed by one decision, so until that decision goes out nothing the caller has
read can be contradicted, and Beamline can hand the run to another worker and
carry on — announced as a `resumed` frame, with elapsed times kept monotonic. A
worker that goes silent is treated the same as one that died: silence on a
stream is a failure the transport cannot report. Whoever dropped the stream is
charged for it, and the credit for an analysis is issued when a decision
arrives, not when the worker accepts the request.

## Telemetry

Beamline cannot be scraped: it is stateless and runs in every colo, so a
`/metrics` route would report one isolate's counters in one city. It writes one
datapoint per request to the `beamline_requests` Analytics Engine dataset
instead, read back through the SQL API. The `beamline - edge` dashboard in the
`grafana` repo draws it; the same numbers also land in Workers Logs, where the
Cloudflare dashboard's Query Builder can aggregate them without any of that.

| | |
| --- | --- |
| `blob1` | route: `lookup`, `analyze`, `analyze:verdict`, `other` |
| `blob2` | source — the layer that answered |
| `blob3` | follow policy the answer was filed under |
| `blob4` | scan worker, empty when a beamline layer answered |
| `blob5` | ecosystem, from the caller's PURL |
| `blob6` | HTTP status |
| `double1` | cache layer, `-1` when nothing answered |
| `double2` | milliseconds |

`analyze` and `analyze:verdict` are two clocks on one request and are not
interchangeable. `/v1/analyze` answers with a stream, so `analyze` stops when the
response headers go out — time to first byte, the number a proxy's idle timeout
acts on — while the analysis is still running. `analyze:verdict` is what the run
cost. Every terminal verdict is filed under it, cached or scanned; an
`unavailable` is under neither, because timing it would measure how quickly
beamline gave up rather than how long anything took.

The blobs above are unchanged. What a customer's request adds is an `index`,
and only an index: the org. Analytics Engine samples per index, so without one
a customer doing millions of lookups samples away a customer doing hundreds,
and the quiet one's dashboard draws a graph made of two surviving rows.
Filtering is all anyone does with the org — `WHERE index1 =` is how that is
spelled — so a blob carrying the same value would be a column nothing reads. Our own operational tokens are deliberately
left unindexed — they are not a customer, and filing a precache pass under an
org would put our load in someone's usage graph.

The artifact is still not in the dataset. A PURL is the caller's dependency
list; an opaque 26-character org id is not, and it is only ever read back
filtered to the org that owns it.

The optional Workers KV L1 namespace is titled `beamline` by default. Run
`make kv-create`, then deploy by passing its returned ID as `KV`:

```
KV=<namespace-id> SCAN_URL=… make deploy-cf
```

The deploy recipe turns that ID into the `BEAMLINE_KV` binding for Wrangler.

## Customers

Beamline does not own customers; [dash](https://dash.isotope13.io) does. Dash
writes `tok:<token>` into its own KV namespace when a customer mints or revokes
one, and beamline reads it — nothing here writes it. Pass that namespace's id
as `DASH_KV` to `make deploy-cf` and a bearer token resolves to an org and a
tier, which is what puts a customer's requests in their own usage graph and
puts their requests in their own usage graph. Omit it and beamline is exactly
what it was before customers existed.

Rules delivery is not here. It lives in `iso13/rules`, behind
`updates.isotope13.ai`, reading this same token namespace — a separate Worker
so that streaming tarballs out of a bucket cannot take down the verdict API.

The lookup is cached at the edge for 60 seconds, so that is the revocation
latency: a token deleted in the dashboard keeps working in whichever colos
already hold it, for up to a minute.

`BEAMLINE_TOKEN` is optional client policy: pass it in the environment to
require a bearer token, or omit it to leave the API open. It is separate from
customer tokens, which are always honoured: turning on customer tokens does not
close an open API, and a deployment that sets `BEAMLINE_TOKEN` is still closed
to everyone who is not a customer. `HOPPER_TOKEN` and
`SCAN_TOKEN` are backend credentials; those may still come from the first
non-empty line of `~/.tok/<service>`. The deploy recipe uploads backend
credentials only, so a local token file cannot accidentally turn on client
authentication in production.

```
HOPPER_URL=… SCAN_URL=… node local.js
HOPPER_URL=… SCAN_URL=… make deploy-cf
```

`make stress-test` targets `https://api.isotope13.ai` by default and does not
need `SCAN_URL`; set `BEAMLINE_URL=` explicitly when you want it to start a
local beamline, in which case `SCAN_URL` is required. The stress client uses
`BEAMLINE_TOKEN` when non-empty, otherwise the first non-empty line of
`~/.tok/beamline`. If neither supplies a token, it sends no bearer token.
