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

```
HOPPER_URL=… SCAN_URL=… node local.js
HOPPER_URL=… SCAN_URL=… make deploy-cf
```
