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
POPULAR     ?=
ANALYZE_MISSES ?=
BEAMLINE_URL ?=
BEAMLINE_TOKEN ?=
# Backend credentials. Unset means tok.js reads ~/.tok/<service>, which is
# where the services themselves are pointed by --token-file.
HOPPER_TOKEN ?=
SCAN_TOKEN ?=
# Exported so the deploy-cf recipe can pipe a value into wrangler without it
# ever appearing in a command line, where ps would show it.
export BEAMLINE_TOKEN
export HOPPER_TOKEN
export SCAN_TOKEN
SCAN_RACE_DELAY_MS ?=
SCAN_RETRIES ?=

.PHONY: lint test stress-test pop-test deploy-cf

# Parse every file, then oxlint. No lint config is checked in: the defaults
# are the standard, and the tree stays free of npm packages.
lint:
	@for f in beamline.js local.js stress.js tok.js scripts/route-bench.mjs beamline.test.js stress.test.js; do \
	  node --check "$$f" || exit 1; \
	done
	npx --yes $(OXLINT) --deny-warnings beamline.js local.js stress.js tok.js scripts/route-bench.mjs beamline.test.js stress.test.js

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
	      HOPPER_TOKEN="$(HOPPER_TOKEN)" SCAN_TOKEN="$(SCAN_TOKEN)" \
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
	  SCAN_URL="$(SCAN_URL)" HOPPER_URL="$(HOPPER_URL)" STRESS_OUT="$(STRESS_OUT)" POPULAR="$(POPULAR)" \
	  HOPPER_TOKEN="$(HOPPER_TOKEN)" SCAN_TOKEN="$(SCAN_TOKEN)" ANALYZE_MISSES="$(ANALYZE_MISSES)" \
	  node stress.js; \
	st=$$?; \
	if [ -n "$$started" ]; then \
	  sleep $(DRAIN_S); \
	  kill $$started 2>/dev/null || true; \
	  wait $$started 2>/dev/null || true; \
	fi; \
	exit $$st

# Same harness as stress-test, but against a fixed list of very widely used
# packages instead of whatever the registries published in the last few minutes.
# Two runs are comparable, so the interesting number is how much came back from
# a cache or an index rather than from a fresh analysis.
pop-test:
	@$(MAKE) --no-print-directory stress-test POPULAR=1 ANALYZE_MISSES=1

# Publish beamline.js as a Cloudflare Worker. 200s land in caches.default.
# HOPPER_URL and SCAN_URL are the public hostnames of the Cloudflare Tunnels
# in front of hopper and scan; the Worker reaches them over ordinary fetch and
# the edge routes into the tunnel. They carry their own authentication.
# SCAN_URL may list several workers, comma-separated, to race them:
#   SCAN_URL=https://scan-a.example,https://scan-b.example make deploy-cf
# Tokens, all three separate, uploaded as Worker secrets after the deploy:
#   BEAMLINE_TOKEN   # who may call beamline
#   HOPPER_TOKEN     # beamline -> hopper
#   SCAN_TOKEN       # beamline -> scan
# Each takes the environment if set, otherwise the first non-empty line of
# ~/.tok/<service> — the same file tok.js reads locally, so a deployed Worker
# and a local run authenticate identically. The secrets go up after the deploy
# because `wrangler secret put` needs the Worker to exist; on a first-ever
# deploy that leaves a short window where the new Worker is running without
# them. Nothing is uploaded for a token with no value: the deployed secret is
# left as it is rather than cleared, so a missing file cannot silently drop
# beamline to unauthenticated.
define put_secret
	@if [ -n "$$$(1)" ]; then \
	  echo "$(1): from the environment"; \
	  printf '%s\n' "$$$(1)" | npx --yes $(WRANGLER) secret put $(1); \
	elif [ -s "$$HOME/.tok/$(2)" ]; then \
	  echo "$(1): from ~/.tok/$(2)"; \
	  awk 'NF { gsub(/^[ \t\r]+|[ \t\r]+$$/, ""); print; exit }' "$$HOME/.tok/$(2)" | npx --yes $(WRANGLER) secret put $(1); \
	else \
	  echo "$(1): no value and no ~/.tok/$(2); leaving the deployed secret unchanged"; \
	fi

endef

deploy-cf:
	@test -n "$(HOPPER_URL)" || { echo "HOPPER_URL is required"; exit 1; }
	@test -n "$(SCAN_URL)" || { echo "SCAN_URL is required"; exit 1; }
	npx --yes $(WRANGLER) deploy \
	  --var "HOPPER_URL:$(HOPPER_URL)" \
	  --var "SCAN_URL:$(SCAN_URL)"
	$(call put_secret,BEAMLINE_TOKEN,beamline)
	$(call put_secret,HOPPER_TOKEN,hopper)
	$(call put_secret,SCAN_TOKEN,scan)
