#!/bin/sh
# Start a `postdoc serve` with no hopper on a loopback port, run
# scripts/postdoc-e2e.test.mjs against it through beamline's handler, and
# stop it. Cleave's analysis cache is off, so every analysis is a real one;
# postdoc's verdict index stays on (the digest lookup reads it), so the
# verdicts of what the test analyzes are left in this host's index.
#
#   POSTDOC_BIN    the postdoc binary (default: postdoc on PATH)
#   POSTDOC_PORT   its port (default 49989)
#   POSTDOC_SCANNERS  third-party scanners postdoc runs (default none here;
#                     postdoc's own default, all three, needs them installed)
#   POSTDOC_ARGS   extra global flags, e.g. "--clamav /run/clamd.sock"
#
# The test's own E2E_* variables pass straight through.
set -eu

bin=${POSTDOC_BIN:-postdoc}
port=${POSTDOC_PORT:-49989}
log=$(mktemp)

# Not SCAN_NO_ANALYSIS_CACHE: it also turns off the verdict index.
# shellcheck disable=SC2086 # POSTDOC_ARGS is a flag list, split on purpose
env -u SCAN_HOPPER CLEAVE_SKIP_CACHE=1 CLEAVE_SKIP_YARA_CACHE=0 \
  POSTDOC_SCANNERS="${POSTDOC_SCANNERS:-none}" \
  "$bin" --no-update ${POSTDOC_ARGS:-} serve --bind "127.0.0.1:$port" >"$log" 2>&1 &
pid=$!
trap 'kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true; rm -f "$log"' EXIT INT TERM

# 503 until the model and rules have loaded.
i=0
until curl -fsS "http://127.0.0.1:$port/_/health" >/dev/null 2>&1; do
  if ! kill -0 "$pid" 2>/dev/null; then
    echo "postdoc exited during startup:" >&2
    cat "$log" >&2
    exit 1
  fi
  i=$((i + 1))
  if [ "$i" -ge 600 ]; then
    echo "postdoc was not ready after 10 minutes:" >&2
    tail -20 "$log" >&2
    exit 1
  fi
  sleep 1
done

POSTDOC_URL="http://127.0.0.1:$port" node --test scripts/postdoc-e2e.test.mjs
