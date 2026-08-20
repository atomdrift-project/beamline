SHELL := /bin/sh

# Backends and the Cloudflare Tunnel UUID come from the environment.
# Nothing below bakes a host or address into the tree.
# Pinned so a deploy is reproducible and a compromised release upstream cannot
# walk into the deploy path. Bump deliberately.
WRANGLER    ?= wrangler@4.124.0
OXLINT      ?= oxlint@1.79.0

PORT        ?= 8080
N           ?= 6
SAMPLES     ?=
CONCURRENCY ?= 2
DRAIN_S     ?= 5
STRESS_OUT  ?=
BEAMLINE_URL ?=
BEAMLINE_TOKEN ?=
SCAN_RACE_DELAY_MS ?=
SCAN_RETRIES ?=

.PHONY: lint test stress-test deploy-cf

# Parse every file, then oxlint. No lint config is checked in: the defaults
# are the standard, and the tree stays free of npm packages.
lint:
	@for f in beamline.js local.js stress.js beamline.test.js stress.test.js; do \
	  node --check "$$f" || exit 1; \
	done
	npx --yes $(OXLINT) --deny-warnings beamline.js local.js stress.js beamline.test.js stress.test.js

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
	      SCAN_RACE_DELAY_MS="$(SCAN_RACE_DELAY_MS)" SCAN_RETRIES="$(SCAN_RETRIES)" \
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
# HOPPER_URL and SCAN_URL are the public hostnames of the Cloudflare Tunnels
# in front of hopper and scan; the Worker reaches them over ordinary fetch and
# the edge routes into the tunnel. They carry their own authentication.
# SCAN_URL may list several workers, comma-separated, to race them:
#   SCAN_URL=https://scan-a.example,https://scan-b.example make deploy-cf
# Token: npx wrangler secret put BEAMLINE_TOKEN
deploy-cf:
	@test -n "$(HOPPER_URL)" || { echo "HOPPER_URL is required"; exit 1; }
	@test -n "$(SCAN_URL)" || { echo "SCAN_URL is required"; exit 1; }
	npx --yes $(WRANGLER) deploy \
	  --var "HOPPER_URL:$(HOPPER_URL)" \
	  --var "SCAN_URL:$(SCAN_URL)"
