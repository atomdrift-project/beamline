# beamline

Beamline looks up a PURL, a SHA-256, or uploaded bytes and returns a
hostility level. Hostile answers include at most three findings.
See [API.md](API.md).

One JavaScript file, no npm packages. It runs as `node local.js` or as a
Cloudflare Worker. Hopper and scan URLs come from the environment; the
tree does not name a host.

```
HOPPER_URL=… SCAN_URL=… node local.js
HOPPER_URL=… SCAN_URL=… CF_TUNNEL_ID=… make deploy-cf
```
