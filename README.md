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

The optional Workers KV L1 namespace is titled `beamline` by default. Run
`make kv-create`, then deploy by passing its returned ID as `KV`:

```
KV=<namespace-id> SCAN_URL=… make deploy-cf
```

The deploy recipe turns that ID into the `BEAMLINE_KV` binding for Wrangler.

`BEAMLINE_TOKEN` is optional client policy: pass it in the environment to
require a bearer token, or omit it to leave the API open. `HOPPER_TOKEN` and
`SCAN_TOKEN` are backend credentials; those may still come from the first
non-empty line of `~/.tok/<service>`. The deploy recipe uploads backend
credentials only, so a local token file cannot accidentally turn on client
authentication in production.

```
HOPPER_URL=… SCAN_URL=… node local.js
HOPPER_URL=… SCAN_URL=… make deploy-cf

`make stress-test` targets `https://api.isotope13.ai` by default and does not
need `SCAN_URL`; set `BEAMLINE_URL=` explicitly when you want it to start a
local beamline, in which case `SCAN_URL` is required.
```
