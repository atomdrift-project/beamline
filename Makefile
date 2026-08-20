SHELL := /bin/sh

# Backends and the Cloudflare Tunnel UUID come from the environment.
# Nothing below bakes a host or address into the tree.
PORT        ?= 8080
N           ?= 6
SAMPLES     ?=
CONCURRENCY ?= 2
DRAIN_S     ?= 5
STRESS_OUT  ?=
BEAMLINE_URL ?=
BEAMLINE_TOKEN ?=

.PHONY: test stress-test deploy-cf

test:
	node --test

# Start a local beamline (unless BEAMLINE_URL is already set or :$(PORT) is up),
# pull new npm / PyPI / crates / Go PURLs, submit them, print latency and bugs.
stress-test:
	@test -n "$(HOPPER_URL)" || { echo "HOPPER_URL is required"; exit 1; }
	@test -n "$(SCAN_URL)" || { echo "SCAN_URL is required"; exit 1; }
	@url="$(BEAMLINE_URL)"; \
	started=""; \
	if [ -z "$$url" ]; then \
	  if node -e "fetch('http://127.0.0.1:$(PORT)/healthz').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))" 2>/dev/null; then \
	    url="http://127.0.0.1:$(PORT)"; \
	    echo "using existing beamline at $$url"; \
	  else \
	    echo "starting beamline on :$(PORT)"; \
	    SCAN_URL="$(SCAN_URL)" HOPPER_URL="$(HOPPER_URL)" PORT="$(PORT)" BEAMLINE_TOKEN="$(BEAMLINE_TOKEN)" \
	      node local.js & started=$$!; \
	    i=0; \
	    while [ $$i -lt 25 ]; do \
	      if node -e "fetch('http://127.0.0.1:$(PORT)/healthz').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))" 2>/dev/null; then \
	        break; \
	      fi; \
	      i=$$((i + 1)); \
	      sleep 0.2; \
	    done; \
	    if ! node -e "fetch('http://127.0.0.1:$(PORT)/healthz').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))" 2>/dev/null; then \
	      kill $$started 2>/dev/null || true; \
	      echo "beamline failed to start on :$(PORT)"; \
	      exit 1; \
	    fi; \
	    url="http://127.0.0.1:$(PORT)"; \
	  fi; \
	fi; \
	set +e; \
	N="$(N)" SAMPLES="$(SAMPLES)" CONCURRENCY="$(CONCURRENCY)" BEAMLINE_URL="$$url" BEAMLINE_TOKEN="$(BEAMLINE_TOKEN)" \
	  SCAN_URL="$(SCAN_URL)" HOPPER_URL="$(HOPPER_URL)" STRESS_OUT="$(STRESS_OUT)" \
	  node stress.js; \
	st=$$?; \
	if [ -n "$$started" ]; then \
	  sleep $(DRAIN_S); \
	  kill $$started 2>/dev/null || true; \
	  wait $$started 2>/dev/null || true; \
	fi; \
	exit $$st

# Publish beamline.js as a Cloudflare Worker. 200s land in caches.default.
# HOPPER_URL and SCAN_URL are the URLs as seen from the cloudflared host
# (private IP or internal DNS). CF_TUNNEL_ID is that tunnel's UUID.
# The Worker calls env.TUNNEL.fetch() so those URLs never leave the tunnel.
# Token: npx wrangler secret put BEAMLINE_TOKEN
deploy-cf:
	@test -n "$(HOPPER_URL)" || { echo "HOPPER_URL is required"; exit 1; }
	@test -n "$(SCAN_URL)" || { echo "SCAN_URL is required"; exit 1; }
	@test -n "$(CF_TUNNEL_ID)" || { echo "CF_TUNNEL_ID is required"; exit 1; }
	@cfg=$$(mktemp ./wrangler.XXXXXX); \
	{ cat wrangler.toml; printf '\n[[vpc_networks]]\nbinding = "TUNNEL"\ntunnel_id = "%s"\nremote = true\n' "$(CF_TUNNEL_ID)"; } > "$$cfg"; \
	npx --yes wrangler deploy --config "$$cfg" \
	  --var "HOPPER_URL:$(HOPPER_URL)" \
	  --var "SCAN_URL:$(SCAN_URL)"; \
	st=$$?; rm -f "$$cfg"; exit $$st
