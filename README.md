# beamline

Beamline looks up a PURL, a SHA-256, or uploaded bytes and returns a
hostility level. Hostile answers include at most three findings.
See [API.md](API.md).

One JavaScript file, no npm packages. It runs as `node local.js` or as a
Cloudflare Worker. Hopper and scan sit behind Cloudflare Tunnels and their
URLs come from the environment; the tree does not name a host.

`SCAN_URL` may be a comma-separated list of interchangeable scan workers.
Bloom and analysis are both raced across every healthy one; the first answer wins and the
losing connections are dropped, which cancels their analyses and frees their
slots, so only the winner's result reaches hopper. A flat race costs one
analysis slot per worker per sample — set `SCAN_RACE_DELAY_MS` to stagger the
starts and give a fast worker the chance to answer before the next is asked.
Each worker gets its own circuit breaker, so a sick one drops out of the race
without taking scanning down with it.

The optional Workers KV L1 namespace is titled `beamline` by default. Run
`make kv-create`, then deploy by passing its returned ID as `KV`:

```
KV=<namespace-id> SCAN_URL=… make deploy-cf
```

The deploy recipe turns that ID into the `BEAMLINE_KV` binding for Wrangler.

Three separate tokens, none of them baked into the tree: `BEAMLINE_TOKEN` is
who may call beamline, `HOPPER_TOKEN` and `SCAN_TOKEN` are how beamline calls
its backends. Each is taken from the environment, and otherwise from the first
non-empty line of `~/.tok/<service>` — the file the services themselves are
pointed at with `--token-file`. `make deploy-cf` uploads all three as Worker
secrets from the same source, so a local run and a deployed Worker
authenticate identically, and a token with no value is left alone rather than
uploaded empty. With no `BEAMLINE_TOKEN` anywhere, beamline serves every route
unauthenticated.

```
HOPPER_URL=… SCAN_URL=… node local.js
HOPPER_URL=… SCAN_URL=… make deploy-cf

`make stress-test` targets `https://api.isotope13.ai` by default and does not
need `SCAN_URL`; set `BEAMLINE_URL=` explicitly when you want it to start a
local beamline, in which case `SCAN_URL` is required.
```
