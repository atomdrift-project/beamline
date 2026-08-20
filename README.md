# beamline

HTTP lookup for malicious packages and files.

You send a PURL, a SHA-256, or bytes. You get back a level and, if it is
hostile, at most three findings. That is the product. See [API.md](API.md).

```
curl -s https://beamline.example/purl/pkg:npm/left-pad@1.3.0
curl -s https://beamline.example/sha256/2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
curl -s -X POST --data-binary @./pkg.tgz https://beamline.example/
```

```json
{ "sha": "2cf2…", "purl": "pkg:npm/left-pad@1.3.0", "lvl": -1, "eng": "2.7.2" }
```

`lvl` is the tightest false-positive budget at which the sample is hostile.
`-1` means never. A typical gate is `lvl != -1 && lvl <= 50`.

One JavaScript program. No npm packages. Runs as a Cloudflare Worker or
`node local.js`.

## Run

Every backend is an environment variable. Nothing in this tree names a host.

```
HOPPER_URL=http://127.0.0.1:8081 SCAN_URL=http://127.0.0.1:49999 node local.js
```

Point `SCAN_URL` at an `atomscan serve` with `--fetch --interpret --analysis-timeout 1800`.
Point `HOPPER_URL` at a hopper that stores prior envelopes.

Optional: `BEAMLINE_TOKEN` (Bearer; one token or a comma-separated list),
`MAX_BYTES` (16 MiB), `SCAN_TIMEOUT_MS` (1800000), `PORT` (8080).

Lookup waits 1s for hopper, then starts scan without dropping the hopper
fetch. First useful answer (hopper 200 or a scan envelope) is returned;
the loser is aborted. Hopper itself is killed at 15s if it never returns.
JSON lines on stdout: `lookup`, `hedge`, `abort`. Optional:
`HOPPER_HEDGE_MS`, `HOPPER_LOOKUP_MS`.

```
make test
make stress-test    # HOPPER_URL and SCAN_URL required
make deploy-cf      # Worker + tunnel; see below
```

## Cloudflare Worker

A Worker cannot open a socket to a private address. Hopper and scan stay
private. `cloudflared` on a host that can already reach them provides a
Cloudflare Tunnel; the Worker binds to that tunnel as a VPC Network and
fetches through it.

`HOPPER_URL` and `SCAN_URL` are the URLs **as that host would use them** —
private IP or internal DNS. They are never committed. At runtime the Worker
calls `env.TUNNEL.fetch(url)` instead of the public internet.

1. Run `cloudflared` (2025.7 or later) on a machine that can reach hopper
   and scan. Prefer QUIC (`auto` or `quic`); allow outbound UDP 7844.
   HTTP/2-only tunnels break Workers VPC DNS. You do not need a public
   hostname on the tunnel — VPC traffic uses warp-routing, not ingress.
2. Deploy with the tunnel UUID and the two backend URLs:

```
HOPPER_URL=… SCAN_URL=… CF_TUNNEL_ID=… make deploy-cf
```

3. Put the customer token in secrets, not vars:

```
npx wrangler secret put BEAMLINE_TOKEN
```

The Worker account user needs Connectivity Directory Admin to bind a
tunnel. `MAX_BYTES` and `SCAN_TIMEOUT_MS` stay in `wrangler.toml`; they
are not endpoints.
