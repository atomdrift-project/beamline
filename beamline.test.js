import { createServer } from "node:http";
import { once } from "node:events";
import assert from "node:assert/strict";
import { afterEach, beforeEach, test } from "node:test";
import { handle, _test } from "./beamline.js";

const HELLO = new TextEncoder().encode("hello");
const HELLO_SHA = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";

// Node's fetch stalls a second concurrent request to a backend until the event
// loop wakes (up to ~200ms), which the hedge timings below would otherwise
// race against. local.js does the same while it has work in flight.
setInterval(() => {}, 1).unref();

beforeEach(() => {
  _test.muteLogs(true);
});

afterEach(() => {
  _test.reset();
});

test("scan timeout default is 1800s", () => {
  assert.equal(_test.DEFAULT_SCAN_TIMEOUT_MS, 1_800_000);
});

test("GET /healthz", async () => {
  const res = await handle(new Request("http://beamline/healthz"), {}, {});
  assert.equal(res.status, 200);
  assert.equal((await res.json()).status, "ok");
});

test("BEAMLINE_TOKEN accepts a comma-separated list", () => {
  assert.deepEqual(_test.tokenList("alpha, beta,gamma"), ["alpha", "beta", "gamma"]);
  assert.deepEqual(_test.tokenList("solo"), ["solo"]);
  assert.deepEqual(_test.tokenList(""), []);
});

test("BEAMLINE_TOKEN is required except on /healthz", async () => {
  const env = { BEAMLINE_TOKEN: "alpha,beta" };
  const open = await handle(new Request("http://beamline/healthz"), env, {});
  assert.equal(open.status, 200);

  const denied = await handle(new Request(`http://beamline/lookup?sha256=${HELLO_SHA}`), env, {});
  assert.equal(denied.status, 401);

  const wrong = await handle(
    new Request(`http://beamline/lookup?sha256=${HELLO_SHA}`, { headers: { authorization: "Bearer nope" } }),
    env,
    {},
  );
  assert.equal(wrong.status, 401);
});

test("a caller's token authenticates them to us and goes no further", async () => {
  const backend = await mockBackend({
    bloom: "unknown",
    sample: () => ({ status: 404 }),
    analyze: () => envelope(HELLO_SHA, { eng: "scan" }),
  });
  const env = {
    ...testEnv(backend.url),
    BEAMLINE_TOKEN: "alpha,beta",
    HOPPER_TOKEN: "hopper-secret",
    SCAN_TOKEN: "scan-secret",
  };
  try {
    const res = await handle(
      new Request(`http://beamline/analyze?sha256=${HELLO_SHA}`, {
        method: "POST",
        headers: { authorization: "Bearer beta" },
        body: HELLO,
      }),
      env,
      waitCtx().ctx,
    );
    assert.equal(res.status, 200);
    const sent = backend.auths.filter((a) => a.path !== "/healthz");
    assert.ok(sent.length > 0);
    // The caller's own credential must never leave beamline: holding it lets
    // you ask beamline questions, not reach a scanner or the sample store.
    assert.ok(!sent.some((a) => a.authorization === "Bearer beta"), JSON.stringify(sent));

    const forScan = sent.filter((a) => a.path === "/lookup" || a.path.startsWith("/analyze"));
    const forHopper = sent.filter((a) => a.path.startsWith("/api/"));
    assert.ok(forScan.length > 0 && forHopper.length > 0, JSON.stringify(sent.map((a) => a.path)));
    assert.ok(forScan.every((a) => a.authorization === "Bearer scan-secret"), JSON.stringify(forScan));
    assert.ok(forHopper.every((a) => a.authorization === "Bearer hopper-secret"), JSON.stringify(forHopper));
  } finally {
    await backend.close();
  }
});

test("cache hit short-circuits the scan lookup and hopper", async () => {
  const backend = await mockBackend({
    bloom: "unknown",
    sample: (sha) => ({ status: 200, sha, body: envelope(sha) }),
  });
  const env = testEnv(backend.url);
  const ctx = waitCtx();
  try {
    const first = await handle(new Request(`http://beamline/lookup?sha256=${HELLO_SHA}`), env, ctx.ctx);
    assert.equal(first.status, 200);
    assert.equal(first.headers.get("x-beamline-source"), "hopper");
    await ctx.flush();
    // Whichever cheap source won, the second request must reach none of them.
    const spent = { ...backend.hits };

    const second = await handle(new Request(`http://beamline/lookup?sha256=${HELLO_SHA}`), env, noopCtx());
    assert.equal(second.status, 200);
    assert.equal(second.headers.get("x-beamline-source"), "cache");
    assert.deepEqual(backend.hits, spent);
    assert.equal(backend.hits.analyze, 0);
  } finally {
    await backend.close();
  }
});

test("a stored scan verdict answers before hopper is asked", async () => {
  const backend = await mockBackend({
    bloom: "unknown",
    verdict: () => ({
      sha: HELLO_SHA,
      lvl: 3,
      eng: "2.8.0",
      why: "Postinstall launches a reverse shell.",
      hits: [{ id: "objectives/execution/shell/bash", crit: 5, file: "lib/install.js", desc: "…" }],
    }),
  });
  try {
    const res = await handle(
      new Request(`http://beamline/lookup?sha256=${HELLO_SHA}`),
      testEnv(backend.url),
      noopCtx(),
    );
    assert.equal(res.status, 200);
    assert.equal(res.headers.get("x-beamline-source"), "scan-cache");
    assert.equal(res.headers.get("x-sha256"), HELLO_SHA);
    const body = await res.json();
    // The real verdict, not the lvl:-1 stub a bare filter hit produces.
    assert.equal(body.lvl, 3);
    assert.equal(body.hits.length, 1);
    assert.equal(body.why, "Postinstall launches a reverse shell.");
    // `bloom` is our upstream's business, not part of this API.
    assert.equal(body.bloom, undefined);
    // hopper is raced alongside the index, so it may well be asked; what a
    // stored verdict must never cost is an analysis.
    assert.equal(backend.hits.analyze, 0);
  } finally {
    await backend.close();
  }
});

test("a stored verdict is preferred over the filter's benign stub", async () => {
  const backend = await mockBackend({
    bloom: "skip",
    verdict: () => ({ sha: HELLO_SHA, lvl: 0, eng: "2.8.0" }),
  });
  try {
    const res = await handle(
      new Request(`http://beamline/lookup?sha256=${HELLO_SHA}`),
      testEnv(backend.url),
      noopCtx(),
    );
    const body = await res.json();
    assert.equal(res.headers.get("x-beamline-source"), "scan-cache");
    assert.equal(body.lvl, 0, "an analysis outranks a known-good filter hit");
  } finally {
    await backend.close();
  }
});

test("/_/health answers alongside /healthz", async () => {
  const res = await handle(new Request("http://beamline/_/health"), {}, {});
  assert.equal(res.status, 200);
  assert.deepEqual(await res.json(), { status: "ok" });
});

test("bloom skip never calls hopper", async () => {
  const backend = await mockBackend({
    bloom: "skip",
    sample: () => {
      throw new Error("hopper should not be called");
    },
  });
  const env = testEnv(backend.url);
  try {
    const res = await handle(new Request(`http://beamline/lookup?sha256=${HELLO_SHA}`), env, noopCtx());
    assert.equal(res.status, 200);
    assert.equal(res.headers.get("x-beamline-source"), "bloom");
    const body = await res.json();
    assert.equal(body.lvl, -1);
    assert.equal(body.eng, "beamline");
    assert.equal(body.sha, HELLO_SHA);
    assert.equal(body.ml, undefined);
    assert.equal(body.raw, undefined);
    assert.equal(body.hits, undefined);
    assert.equal(backend.hits.analyze, 0, "a skip must not cost an analysis");
  } finally {
    await backend.close();
  }
});

test("hopper 200 passes the envelope through", async () => {
  const stored = envelope(HELLO_SHA, { prob: 0.42, lvl: 5 });
  const backend = await mockBackend({
    bloom: "unknown",
    sample: () => ({ status: 200, sha: HELLO_SHA, body: stored }),
  });
  const env = testEnv(backend.url);
  try {
    const res = await handle(new Request(`http://beamline/lookup?sha256=${HELLO_SHA}`), env, noopCtx());
    assert.equal(res.status, 200);
    assert.equal(res.headers.get("x-beamline-source"), "hopper");
    assert.equal(res.headers.get("x-sha256"), HELLO_SHA);
    assert.equal(res.headers.get("x-total-ms"), null);
    const body = await res.json();
    assert.equal(body.lvl, 5);
    assert.equal(body.eng, "mock");
    assert.equal(body.sha, HELLO_SHA);
    assert.equal(body.prob, undefined);
    assert.equal(body.ml, undefined);
    assert.equal(body.raw, undefined);
    assert.equal(backend.hits.analyze, 0);
    assert.equal(backend.hits.analyzePurl, 0);
  } finally {
    await backend.close();
  }
});

test("hopper miss with body posts /analyze and stores the artifact on hopper", async () => {
  const scanned = envelope(HELLO_SHA, { prob: 0.9, lvl: 0, eng: "scan" });
  const backend = await mockBackend({
    bloom: "unknown",
    sample: () => ({ status: 404 }),
    analyze: () => scanned,
  });
  const env = testEnv(backend.url);
  const ctx = waitCtx();
  try {
    const res = await handle(
      new Request(`http://beamline/analyze?sha256=${HELLO_SHA}`, { method: "POST", body: HELLO }),
      env,
      ctx.ctx,
    );
    assert.equal(res.status, 200);
    assert.equal(res.headers.get("x-beamline-source"), "scan");
    assert.equal(res.headers.get("x-total-ms"), "17");
    assert.equal((await res.json()).eng, "scan");
    assert.equal(backend.hits.analyze, 1);
    assert.equal(backend.hits.analyzePurl, 0);
    await ctx.flush();
    assert.equal(backend.hits.upload, 1);
    // The verdict is the scan worker's to renew; beamline only contributes the
    // bytes, which are the one thing hopper cannot get anywhere else.
    assert.equal(backend.hits.result, 0);
  } finally {
    await backend.close();
  }
});

test("PURL miss posts /analyze-purl", async () => {
  const sha = HELLO_SHA;
  const scanned = envelope(sha, { eng: "purl-scan" });
  const backend = await mockBackend({
    bloom: "unknown",
    sample: () => ({ status: 404 }),
    analyzePurl: (body) => {
      assert.equal(body.purl, "pkg:npm/left-pad@1.3.0");
      return scanned;
    },
  });
  const env = testEnv(backend.url);
  const ctx = waitCtx();
  try {
    const res = await handle(
      new Request(`http://beamline/analyze?sha256=${HELLO_SHA}&purl=pkg%3Anpm%2Fleft-pad%401.3.0`, { method: "POST" }),
      env,
      ctx.ctx,
    );
    assert.equal(res.status, 200);
    assert.equal(res.headers.get("x-beamline-source"), "scan");
    assert.equal(res.headers.get("x-sha256"), sha);
    assert.equal((await res.json()).purl, "pkg:npm/left-pad@1.3.0");
    assert.equal(backend.hits.analyzePurl, 1);
    assert.equal(backend.hits.analyze, 0);
    await ctx.flush();
    assert.equal(backend.hits.upload, 0);
    assert.equal(backend.hits.result, 0, "the scan worker files the verdict, not beamline");
  } finally {
    await backend.close();
  }
});

const DEAD = "http://127.0.0.1:1";

test("scan down still serves a hopper hit", async () => {
  const stored = envelope(HELLO_SHA, { eng: "hopper-only" });
  const backend = await mockBackend({
    sample: () => ({ status: 200, sha: HELLO_SHA, body: stored }),
  });
  const env = testEnv(backend.url, { SCAN_URL: DEAD });
  try {
    const res = await handle(new Request(`http://beamline/lookup?sha256=${HELLO_SHA}`), env, noopCtx());
    assert.equal(res.status, 200);
    assert.equal(res.headers.get("x-beamline-source"), "hopper");
    assert.equal((await res.json()).eng, "hopper-only");
    assert.equal(backend.hits.analyze, 0);
  } finally {
    await backend.close();
  }
});

test("hopper down still scans posted bytes", async () => {
  const scanned = envelope(HELLO_SHA, { eng: "scan-only" });
  const backend = await mockBackend({ bloom: "unknown", analyze: () => scanned });
  const env = testEnv(backend.url, { HOPPER_URL: DEAD });
  const ctx = waitCtx();
  try {
    const res = await handle(
      new Request(`http://beamline/analyze?sha256=${HELLO_SHA}`, { method: "POST", body: HELLO }),
      env,
      ctx.ctx,
    );
    assert.equal(res.status, 200);
    assert.equal(res.headers.get("x-beamline-source"), "scan");
    assert.equal((await res.json()).eng, "scan-only");
    await ctx.flush();
    assert.equal(backend.hits.sample, 0);
  } finally {
    await backend.close();
  }
});

test("hopper down still scans a PURL", async () => {
  const sha = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
  const scanned = envelope(sha, { eng: "purl-only" });
  const backend = await mockBackend({
    bloom: "unknown",
    analyzePurl: () => scanned,
  });
  const env = testEnv(backend.url, { HOPPER_URL: DEAD });
  try {
    const res = await handle(
      new Request(`http://beamline/analyze?sha256=${HELLO_SHA}&purl=pkg%3Anpm%2Fleft-pad%401.3.0`, { method: "POST" }),
      env,
      waitCtx().ctx,
    );
    assert.equal(res.status, 200);
    assert.equal(res.headers.get("x-beamline-source"), "scan");
    assert.equal(backend.hits.analyzePurl, 1);
  } finally {
    await backend.close();
  }
});

test("hopper down without bytes is 503, not a miss", async () => {
  const backend = await mockBackend({ bloom: "unknown" });
  const env = testEnv(backend.url, { HOPPER_URL: DEAD });
  try {
    const res = await handle(new Request(`http://beamline/lookup?sha256=${HELLO_SHA}`), env, noopCtx());
    assert.equal(res.status, 503);
    assert.equal((await res.json()).error, "unavailable");
    assert.equal(backend.hits.analyze, 0);
  } finally {
    await backend.close();
  }
});

test("PURL hopper miss with scan down is 503, not a miss", async () => {
  const backend = await mockBackend({
    bloom: "unknown",
    sample: () => ({ status: 404 }),
  });
  const env = testEnv(backend.url, { SCAN_URL: DEAD });
  try {
    const res = await handle(
      new Request(`http://beamline/analyze?sha256=${HELLO_SHA}&purl=pkg%3Anpm%2Fleft-pad%401.3.0`, { method: "POST" }),
      env,
      noopCtx(),
    );
    assert.equal(res.status, 503);
    assert.equal((await res.json()).error, "unavailable");
  } finally {
    await backend.close();
  }
});

test("an unavailable lookup does not disable /analyze", async () => {
  const scanned = envelope(HELLO_SHA, { eng: "scan" });
  const backend = await mockBackend({
    bloomStatus: 404,
    sample: () => ({ status: 404 }),
    analyze: () => scanned,
  });
  const env = testEnv(backend.url);
  try {
    const res = await handle(
      new Request(`http://beamline/analyze?sha256=${HELLO_SHA}`, { method: "POST", body: HELLO }),
      env,
      waitCtx().ctx,
    );
    assert.equal(res.status, 200);
    assert.equal(res.headers.get("x-beamline-source"), "scan");
    assert.equal(backend.hits.analyze, 1);
  } finally {
    await backend.close();
  }
});

test("scan down with posted bytes uploads to hopper and waits", async () => {
  let samples = 0;
  const backend = await mockBackend({
    bloom: "unknown",
    sample: (sha) => {
      samples += 1;
      if (samples === 1) return { status: 404 };
      return { status: 200, sha, body: envelope(sha, { eng: "hopper-worker" }) };
    },
  });
  const env = testEnv(backend.url, { SCAN_URL: DEAD });
  try {
    const res = await handle(
      new Request(`http://beamline/analyze?sha256=${HELLO_SHA}`, { method: "POST", body: HELLO }),
      env,
      noopCtx(),
    );
    assert.equal(res.status, 200);
    assert.equal(res.headers.get("x-beamline-source"), "hopper");
    assert.equal((await res.json()).eng, "hopper-worker");
    assert.equal(backend.hits.upload, 1);
    assert.equal(backend.hits.rescan, 1);
    assert.equal(backend.hits.analyze, 0);
  } finally {
    await backend.close();
  }
});

test("scan down on a pending hopper sample waits for the worker", async () => {
  let samples = 0;
  const backend = await mockBackend({
    bloom: "unknown",
    sample: () => {
      samples += 1;
      if (samples === 1) return { status: 204, sha: HELLO_SHA };
      return { status: 200, sha: HELLO_SHA, body: envelope(HELLO_SHA, { eng: "hopper-worker" }) };
    },
  });
  const env = testEnv(backend.url, { SCAN_URL: DEAD });
  try {
    const res = await handle(new Request(`http://beamline/analyze?sha256=${HELLO_SHA}`, { method: "POST" }), env, noopCtx());
    assert.equal(res.status, 200);
    assert.equal(res.headers.get("x-beamline-source"), "hopper");
    assert.equal(backend.hits.upload, 0);
    assert.equal(backend.hits.rescan, 1);
  } finally {
    await backend.close();
  }
});

test("scan down wait timeout returns 202 pending", async () => {
  const backend = await mockBackend({
    bloom: "unknown",
    sample: () => ({ status: 204, sha: HELLO_SHA }),
  });
  const env = testEnv(backend.url, { SCAN_URL: DEAD, SCAN_TIMEOUT_MS: "80" });
  try {
    const res = await handle(new Request(`http://beamline/analyze?sha256=${HELLO_SHA}`, { method: "POST" }), env, noopCtx());
    assert.equal(res.status, 202);
    // Jittered to spread the retry herd; the contract is a whole number of
    // seconds inside the advertised window, not one fixed value.
    const retry = Number(res.headers.get("retry-after"));
    assert.ok(Number.isInteger(retry) && retry >= 3 && retry <= 8, `retry-after ${retry}`);
    assert.deepEqual(await res.json(), { state: "pending" });
  } finally {
    await backend.close();
  }
});

test("unknown route is 404 not found", async () => {
  const res = await handle(new Request("http://beamline/nope"), {}, {});
  assert.equal(res.status, 404);
  assert.equal((await res.json()).error, "not found");
});

test("a known route with the wrong method is 405, not 404", async () => {
  // Dropping the body to analyze a PURL also drops the POST that
  // `--data-binary` was implying, so this is the mistake callers actually make.
  // A 404 would send them looking for a misspelled path.
  const cases = [
    ["http://beamline/analyze", "GET", "POST"],
    ["http://beamline/lookup", "POST", "GET"],
    ["http://beamline/healthz", "POST", "GET"],
    ["http://beamline/_/health", "DELETE", "GET"],
  ];
  for (const [uri, method, allow] of cases) {
    const res = await handle(new Request(uri, { method }), {}, {});
    assert.equal(res.status, 405, `${method} ${uri}`);
    assert.equal(res.headers.get("allow"), allow, `${method} ${uri} must name the method that works`);
    assert.equal((await res.json()).error, "method not allowed");
  }
});

test("the method check on a guarded route runs after the token check", async () => {
  // A 405 tells the caller the route exists. That is fine once they are known
  // to us, but an unauthenticated prod of /analyze must not learn it.
  const res = await handle(new Request("http://beamline/analyze"), { BEAMLINE_TOKEN: "secret" }, {});
  assert.equal(res.status, 401);
  // Health answers before the token check, so its 405 is reachable unauthenticated.
  const health = await handle(new Request("http://beamline/healthz", { method: "POST" }), { BEAMLINE_TOKEN: "secret" }, {});
  assert.equal(health.status, 405);
});

test("query purl is not a route", async () => {
  const res = await handle(new Request("http://beamline/?purl=pkg:npm/left-pad@1.3.0"), {}, {});
  assert.equal(res.status, 404);
});

test("multipart POST is 415", async () => {
  const res = await handle(
    new Request(`http://beamline/analyze?sha256=${HELLO_SHA}`, {
      method: "POST",
      headers: { "content-type": "multipart/form-data; boundary=x" },
      body: "--x--",
    }),
    {},
    {},
  );
  assert.equal(res.status, 415);
  assert.equal((await res.json()).error, "unsupported media type");
});

test("hopper miss without bytes is unknown sample", async () => {
  const backend = await mockBackend({
    bloom: "unknown",
    sample: () => ({ status: 404 }),
  });
  const env = testEnv(backend.url);
  try {
    const res = await handle(new Request(`http://beamline/lookup?sha256=${HELLO_SHA}`), env, noopCtx());
    assert.equal(res.status, 404);
    assert.equal((await res.json()).error, "unknown sample");
    assert.equal(backend.hits.analyze, 0);
  } finally {
    await backend.close();
  }
});

test("hopper hedge defaults", () => {
  assert.equal(_test.HOPPER_HEDGE_MS, 1_000);
  assert.equal(_test.HOPPER_LOOKUP_MS, 15_000);
  assert.equal(_test.HOPPER_RPC_MS, 2_000);
  assert.equal(_test.BREAKER_FAILS, 5);
  assert.equal(_test.numEnv({}, "HOPPER_HEDGE_MS", 1000), 1000);
  assert.equal(_test.numEnv({ HOPPER_HEDGE_MS: "" }, "HOPPER_HEDGE_MS", 1000), 1000);
  assert.equal(_test.numEnv({ HOPPER_HEDGE_MS: "nope" }, "HOPPER_HEDGE_MS", 1000), 1000);
  assert.equal(_test.numEnv({ HOPPER_HEDGE_MS: "-1" }, "HOPPER_HEDGE_MS", 1000), 1000);
  assert.equal(_test.numEnv({ HOPPER_HEDGE_MS: "0" }, "HOPPER_HEDGE_MS", 1000), 0);
  assert.equal(_test.numEnv({ HOPPER_HEDGE_MS: "20" }, "HOPPER_HEDGE_MS", 1000), 20);
});

test("hopper 404 does not wait for the hedge before scanning", async () => {
  const scanned = envelope(HELLO_SHA, { eng: "scan" });
  const backend = await mockBackend({
    bloom: "unknown",
    sample: () => ({ status: 404 }),
    analyze: () => scanned,
  });
  const env = testEnv(backend.url);
  const t0 = Date.now();
  try {
    const res = await handle(
      new Request(`http://beamline/analyze?sha256=${HELLO_SHA}`, { method: "POST", body: HELLO }),
      env,
      waitCtx().ctx,
    );
    assert.equal(res.status, 200);
    assert.equal(res.headers.get("x-beamline-source"), "scan");
    assert.ok(Date.now() - t0 < 500, `waited ${Date.now() - t0}ms for a fast hopper 404`);
  } finally {
    await backend.close();
  }
});

test("slow hopper 200 beats in-flight scan and does not submit", async () => {
  const stored = envelope(HELLO_SHA, { eng: "hopper-late" });
  const scanned = envelope(HELLO_SHA, { eng: "scan-waste" });
  const logs = captureLogs();
  const backend = await mockBackend({
    bloom: "unknown",
    sample: async () => {
      await delay(80);
      return { status: 200, sha: HELLO_SHA, body: stored };
    },
    analyze: async () => {
      await delay(200);
      return scanned;
    },
  });
  const env = testEnv(backend.url, { HOPPER_HEDGE_MS: "20" });
  const ctx = waitCtx();
  _test.muteLogs(false);
  try {
    const res = await handle(
      new Request(`http://beamline/analyze?sha256=${HELLO_SHA}`, { method: "POST", body: HELLO }),
      env,
      ctx.ctx,
    );
    assert.equal(res.status, 200);
    assert.equal(res.headers.get("x-beamline-source"), "hopper");
    assert.equal((await res.json()).eng, "hopper-late");
    await ctx.flush();
    assert.equal(backend.hits.result, 0);
    assert.equal(backend.hits.upload, 0);
    const hedge = logs.rows.find((r) => r.event === "hedge");
    const abort = logs.rows.find((r) => r.event === "abort");
    const lookup = logs.rows.filter((r) => r.event === "lookup").pop();
    assert.ok(hedge, "expected hedge log");
    assert.ok(abort && abort.target.includes("analysis"), JSON.stringify(abort));
    assert.equal(abort && abort.why, "hopper_hit");
    assert.equal(lookup.src, "hopper");
    assert.equal(lookup.hedged, true);
    assert.equal(lookup.status, 200);
  } finally {
    logs.restore();
    await backend.close();
  }
});

test("hedge serves scan if hopper stays silent, then aborts hopper", async () => {
  const scanned = envelope(HELLO_SHA, { eng: "scan-hedge" });
  const logs = captureLogs();
  const backend = await mockBackend({
    bloom: "unknown",
    sample: async () => {
      await delay(120);
      return { status: 200, sha: HELLO_SHA, body: envelope(HELLO_SHA, { eng: "too-late" }) };
    },
    analyze: () => scanned,
  });
  const env = testEnv(backend.url, { HOPPER_HEDGE_MS: "20" });
  const ctx = waitCtx();
  _test.muteLogs(false);
  try {
    const t0 = Date.now();
    const res = await handle(
      new Request(`http://beamline/analyze?sha256=${HELLO_SHA}`, { method: "POST", body: HELLO }),
      env,
      ctx.ctx,
    );
    const ms = Date.now() - t0;
    assert.equal(res.status, 200);
    assert.equal(res.headers.get("x-beamline-source"), "scan");
    assert.equal((await res.json()).eng, "scan-hedge");
    assert.ok(ms < 300, `scan hedge took ${ms}ms; hopper should have been abandoned`);
    await ctx.flush();
    assert.equal(backend.hits.result, 0, "the scan worker files the verdict, not beamline");
    assert.equal(backend.hits.upload, 1);
    const abort = logs.rows.find((r) => r.event === "abort");
    const lookup = logs.rows.filter((r) => r.event === "lookup").pop();
    assert.equal(abort && abort.target, "hopper");
    assert.equal(abort && abort.why, "scan_hit");
    assert.equal(lookup.src, "scan");
    assert.equal(lookup.hedged, true);
  } finally {
    logs.restore();
    await backend.close();
  }
});

test("fast hopper 200 does not hedge or start scan", async () => {
  const logs = captureLogs();
  const backend = await mockBackend({
    bloom: "unknown",
    sample: () => ({ status: 200, sha: HELLO_SHA, body: envelope(HELLO_SHA, { eng: "hopper-fast" }) }),
    analyze: () => envelope(HELLO_SHA, { eng: "scan" }),
  });
  const env = testEnv(backend.url);
  _test.muteLogs(false);
  try {
    const res = await handle(
      new Request(`http://beamline/analyze?sha256=${HELLO_SHA}`, { method: "POST", body: HELLO }),
      env,
      waitCtx().ctx,
    );
    assert.equal(res.status, 200);
    assert.equal(res.headers.get("x-beamline-source"), "hopper");
    assert.equal(backend.hits.analyze, 0);
    assert.equal(backend.hits.analyzePurl, 0);
    assert.ok(!logs.rows.some((r) => r.event === "hedge"));
    assert.ok(!logs.rows.some((r) => r.event === "analyze"), "analysis must not start");
    const lookup = logs.rows.filter((r) => r.event === "lookup").pop();
    assert.equal(lookup.hedged, false);
  } finally {
    logs.restore();
    await backend.close();
  }
});

test("invalid HOPPER_HEDGE_MS uses the default, not zero", async () => {
  const backend = await mockBackend({
    bloom: "unknown",
    sample: async () => {
      await delay(40);
      return { status: 200, sha: HELLO_SHA, body: envelope(HELLO_SHA, { eng: "hopper" }) };
    },
    analyze: () => envelope(HELLO_SHA, { eng: "scan" }),
  });
  const env = testEnv(backend.url, { HOPPER_HEDGE_MS: "nope" });
  try {
    const res = await handle(
      new Request(`http://beamline/analyze?sha256=${HELLO_SHA}`, { method: "POST", body: HELLO }),
      env,
      waitCtx().ctx,
    );
    assert.equal(res.status, 200);
    assert.equal(res.headers.get("x-beamline-source"), "hopper");
    assert.equal(backend.hits.analyze, 0);
  } finally {
    await backend.close();
  }
});

test("hedged PURL: slow hopper 200 beats analyze-purl and does not submit", async () => {
  const sha = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
  const backend = await mockBackend({
    bloom: "unknown",
    sample: async () => {
      await delay(80);
      return { status: 200, sha, body: envelope(sha, { eng: "hopper-purl" }) };
    },
    analyzePurl: async () => {
      await delay(200);
      return envelope(sha, { eng: "scan-purl" });
    },
  });
  const env = testEnv(backend.url, { HOPPER_HEDGE_MS: "20" });
  const ctx = waitCtx();
  try {
    const res = await handle(
      new Request(`http://beamline/analyze?sha256=${HELLO_SHA}&purl=pkg%3Anpm%2Fleft-pad%401.3.0`, { method: "POST" }),
      env,
      ctx.ctx,
    );
    assert.equal(res.status, 200);
    assert.equal(res.headers.get("x-beamline-source"), "hopper");
    assert.equal((await res.json()).eng, "hopper-purl");
    await ctx.flush();
    assert.equal(backend.hits.analyzePurl, 1);
    assert.equal(backend.hits.analyze, 0);
    assert.equal(backend.hits.result, 0);
  } finally {
    await backend.close();
  }
});

test("hedged PURL: scan wins if hopper stays silent", async () => {
  const sha = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
  const backend = await mockBackend({
    bloom: "unknown",
    sample: async () => {
      await delay(200);
      return { status: 200, sha, body: envelope(sha, { eng: "too-late" }) };
    },
    analyzePurl: () => envelope(sha, { eng: "purl-hedge" }),
  });
  const env = testEnv(backend.url, { HOPPER_HEDGE_MS: "20" });
  const ctx = waitCtx();
  try {
    const t0 = Date.now();
    const res = await handle(
      new Request(`http://beamline/analyze?sha256=${HELLO_SHA}&purl=pkg%3Anpm%2Fleft-pad%401.3.0`, { method: "POST" }),
      env,
      ctx.ctx,
    );
    assert.equal(res.status, 200);
    assert.equal(res.headers.get("x-beamline-source"), "scan");
    assert.equal((await res.json()).eng, "purl-hedge");
    assert.ok(Date.now() - t0 < 150);
    await ctx.flush();
    assert.equal(backend.hits.result, 0, "the scan worker files the verdict, not beamline");
    assert.equal(backend.hits.analyze, 0);
  } finally {
    await backend.close();
  }
});

test("SHA GET: slow hopper 200 still wins after hedge started a file fetch", async () => {
  const backend = await mockBackend({
    bloom: "unknown",
    sample: async () => {
      await delay(80);
      return { status: 200, sha: HELLO_SHA, body: envelope(HELLO_SHA, { eng: "hopper-sha" }) };
    },
    analyze: () => envelope(HELLO_SHA, { eng: "scan" }),
  });
  const env = testEnv(backend.url, { HOPPER_HEDGE_MS: "20" });
  const ctx = waitCtx();
  try {
    const res = await handle(new Request(`http://beamline/analyze?sha256=${HELLO_SHA}`, { method: "POST" }), env, ctx.ctx);
    assert.equal(res.status, 200);
    assert.equal(res.headers.get("x-beamline-source"), "hopper");
    assert.equal((await res.json()).eng, "hopper-sha");
    await ctx.flush();
    assert.equal(backend.hits.analyze, 0);
    assert.equal(backend.hits.result, 0);
    assert.ok(backend.hits.file >= 1);
  } finally {
    await backend.close();
  }
});

test("SHA GET: hedge scans hopper bytes if hopper sample stays silent", async () => {
  const backend = await mockBackend({
    bloom: "unknown",
    sample: async () => {
      await delay(200);
      return { status: 200, sha: HELLO_SHA, body: envelope(HELLO_SHA, { eng: "too-late" }) };
    },
    file: HELLO,
    analyze: () => envelope(HELLO_SHA, { eng: "from-file" }),
  });
  const env = testEnv(backend.url, { HOPPER_HEDGE_MS: "20" });
  const ctx = waitCtx();
  try {
    const t0 = Date.now();
    const res = await handle(new Request(`http://beamline/analyze?sha256=${HELLO_SHA}`, { method: "POST" }), env, ctx.ctx);
    assert.equal(res.status, 200);
    assert.equal(res.headers.get("x-beamline-source"), "scan");
    assert.equal((await res.json()).eng, "from-file");
    assert.ok(Date.now() - t0 < 150);
    await ctx.flush();
    assert.equal(backend.hits.file, 1);
    assert.equal(backend.hits.analyze, 1);
    assert.equal(backend.hits.result, 0, "the scan worker files the verdict, not beamline");
  } finally {
    await backend.close();
  }
});

test("slow hopper 404 after hedge still scans and submits", async () => {
  const backend = await mockBackend({
    bloom: "unknown",
    sample: async () => {
      await delay(60);
      return { status: 404 };
    },
    analyze: () => envelope(HELLO_SHA, { eng: "after-404" }),
  });
  const env = testEnv(backend.url, { HOPPER_HEDGE_MS: "20" });
  const ctx = waitCtx();
  try {
    const res = await handle(
      new Request(`http://beamline/analyze?sha256=${HELLO_SHA}`, { method: "POST", body: HELLO }),
      env,
      ctx.ctx,
    );
    assert.equal(res.status, 200);
    assert.equal(res.headers.get("x-beamline-source"), "scan");
    await ctx.flush();
    assert.equal(backend.hits.result, 0, "the scan worker files the verdict, not beamline");
    assert.equal(backend.hits.upload, 1);
  } finally {
    await backend.close();
  }
});

test("slow hopper 204 after hedge does not re-upload when scan wins", async () => {
  const backend = await mockBackend({
    bloom: "unknown",
    sample: async () => {
      await delay(40);
      return { status: 204, sha: HELLO_SHA };
    },
    analyze: async () => {
      await delay(80);
      return envelope(HELLO_SHA, { eng: "scan-204" });
    },
  });
  const env = testEnv(backend.url, { HOPPER_HEDGE_MS: "20" });
  const ctx = waitCtx();
  try {
    const res = await handle(
      new Request(`http://beamline/analyze?sha256=${HELLO_SHA}`, { method: "POST", body: HELLO }),
      env,
      ctx.ctx,
    );
    assert.equal(res.status, 200);
    assert.equal(res.headers.get("x-beamline-source"), "scan");
    await ctx.flush();
    assert.equal(backend.hits.upload, 0);
    assert.equal(backend.hits.result, 0, "the scan worker files the verdict, not beamline");
  } finally {
    await backend.close();
  }
});

test("hedged hopper 204 with scan down still waits for the hopper worker", async () => {
  let samples = 0;
  const backend = await mockBackend({
    bloom: "unknown",
    sample: async () => {
      samples += 1;
      if (samples === 1) {
        await delay(40);
        return { status: 204, sha: HELLO_SHA };
      }
      return { status: 200, sha: HELLO_SHA, body: envelope(HELLO_SHA, { eng: "hopper-worker" }) };
    },
  });
  const env = testEnv(backend.url, { SCAN_URL: DEAD, HOPPER_HEDGE_MS: "20" });
  try {
    const res = await handle(new Request(`http://beamline/analyze?sha256=${HELLO_SHA}`, { method: "POST" }), env, noopCtx());
    assert.equal(res.status, 200);
    assert.equal(res.headers.get("x-beamline-source"), "hopper");
    assert.equal((await res.json()).eng, "hopper-worker");
    assert.equal(backend.hits.rescan, 1);
  } finally {
    await backend.close();
  }
});

test("scan win populates cache; late hopper does not change it", async () => {
  const backend = await mockBackend({
    bloom: "unknown",
    sample: async () => {
      await delay(120);
      return { status: 200, sha: HELLO_SHA, body: envelope(HELLO_SHA, { eng: "too-late" }) };
    },
    analyze: () => envelope(HELLO_SHA, { eng: "scan-cached" }),
  });
  const env = testEnv(backend.url, { HOPPER_HEDGE_MS: "20" });
  const ctx = waitCtx();
  try {
    const first = await handle(
      new Request(`http://beamline/analyze?sha256=${HELLO_SHA}`, { method: "POST", body: HELLO }),
      env,
      ctx.ctx,
    );
    assert.equal(first.headers.get("x-beamline-source"), "scan");
    await ctx.flush();
    const second = await handle(
      new Request(`http://beamline/lookup?sha256=${HELLO_SHA}`),
      env,
      noopCtx(),
    );
    assert.equal(second.status, 200);
    assert.equal(second.headers.get("x-beamline-source"), "cache");
    assert.equal((await second.json()).eng, "scan-cached");
  } finally {
    await backend.close();
  }
});

test("hopper win after hedge populates cache with hopper", async () => {
  const backend = await mockBackend({
    bloom: "unknown",
    sample: async () => {
      await delay(80);
      return { status: 200, sha: HELLO_SHA, body: envelope(HELLO_SHA, { eng: "hopper-cached" }) };
    },
    analyze: async () => {
      await delay(200);
      return envelope(HELLO_SHA, { eng: "scan-waste" });
    },
  });
  const env = testEnv(backend.url, { HOPPER_HEDGE_MS: "20" });
  const ctx = waitCtx();
  try {
    const first = await handle(
      new Request(`http://beamline/analyze?sha256=${HELLO_SHA}`, { method: "POST", body: HELLO }),
      env,
      ctx.ctx,
    );
    assert.equal(first.headers.get("x-beamline-source"), "hopper");
    await ctx.flush();
    const second = await handle(
      new Request(`http://beamline/lookup?sha256=${HELLO_SHA}`),
      env,
      noopCtx(),
    );
    assert.equal(second.headers.get("x-beamline-source"), "cache");
    assert.equal((await second.json()).eng, "hopper-cached");
  } finally {
    await backend.close();
  }
});

test("response is not blocked on the cache write", async () => {
  const backend = await mockBackend({
    bloom: "unknown",
    sample: () => ({ status: 200, sha: HELLO_SHA, body: envelope(HELLO_SHA, { eng: "hopper" }) }),
  });
  const inner = _test.memoryCache();
  const env = {
    ...testEnv(backend.url),
    cache: {
      match: (req) => inner.match(req),
      put: () => new Promise(() => {}),
    },
  };
  try {
    const t0 = Date.now();
    const res = await handle(new Request(`http://beamline/lookup?sha256=${HELLO_SHA}`), env, noopCtx());
    const ms = Date.now() - t0;
    assert.equal(res.status, 200);
    assert.equal(res.headers.get("x-beamline-source"), "hopper");
    assert.ok(ms < 200, `cache put blocked the response for ${ms}ms`);
  } finally {
    await backend.close();
  }
});

test("cache put failure does not fail the lookup", async () => {
  const logs = captureLogs();
  const backend = await mockBackend({
    bloom: "unknown",
    sample: () => ({ status: 200, sha: HELLO_SHA, body: envelope(HELLO_SHA, { eng: "hopper" }) }),
  });
  const inner = _test.memoryCache();
  const env = {
    ...testEnv(backend.url),
    cache: {
      match: (req) => inner.match(req),
      put: async () => {
        throw new Error("cache full");
      },
    },
  };
  const ctx = waitCtx();
  _test.muteLogs(false);
  try {
    const res = await handle(new Request(`http://beamline/lookup?sha256=${HELLO_SHA}`), env, ctx.ctx);
    assert.equal(res.status, 200);
    await ctx.flush();
    assert.ok(logs.rows.some((r) => r.event === "wait_error"));
  } finally {
    logs.restore();
    await backend.close();
  }
});

test("never-returning hopper does not wait out the lookup budget after scan wins", async () => {
  const backend = await mockBackend({
    bloom: "unknown",
    sample: () => new Promise(() => {}),
    analyze: () => envelope(HELLO_SHA, { eng: "scan" }),
  });
  const env = testEnv(backend.url, { HOPPER_HEDGE_MS: "20", HOPPER_LOOKUP_MS: "2000" });
  const ctx = waitCtx();
  try {
    const t0 = Date.now();
    const res = await handle(
      new Request(`http://beamline/analyze?sha256=${HELLO_SHA}`, { method: "POST", body: HELLO }),
      env,
      ctx.ctx,
    );
    const ms = Date.now() - t0;
    assert.equal(res.status, 200);
    assert.equal(res.headers.get("x-beamline-source"), "scan");
    assert.ok(ms < 300, `waited ${ms}ms; hopper abort should not wait for HOPPER_LOOKUP_MS`);
    await ctx.flush();
  } finally {
    await backend.close();
  }
});

test("aborting hopper on scan win does not trip the hopper breaker", async () => {
  let n = 0;
  const backend = await mockBackend({
    bloom: "unknown",
    sample: async (sha) => {
      n += 1;
      if (n <= _test.BREAKER_FAILS) {
        await delay(80);
        return { status: 200, sha, body: envelope(sha, { eng: "too-late" }) };
      }
      return { status: 200, sha, body: envelope(sha, { eng: "still-up" }) };
    },
    analyze: () => envelope(HELLO_SHA, { eng: "scan" }),
  });
  const env = testEnv(backend.url, { HOPPER_HEDGE_MS: "15" });
  try {
    for (let i = 0; i < _test.BREAKER_FAILS; i++) {
      const ctx = waitCtx();
      const res = await handle(
        new Request(`http://beamline/analyze?sha256=${HELLO_SHA}`, { method: "POST", body: HELLO }),
        { ...env, cache: _test.memoryCache() },
        ctx.ctx,
      );
      assert.equal(res.headers.get("x-beamline-source"), "scan");
      await ctx.flush();
    }
    const res = await handle(
      new Request(`http://beamline/lookup?sha256=${HELLO_SHA}`),
      { ...env, cache: _test.memoryCache() },
      noopCtx(),
    );
    assert.equal(res.status, 200);
    assert.equal(res.headers.get("x-beamline-source"), "hopper");
    assert.equal((await res.json()).eng, "still-up");
  } finally {
    await backend.close();
  }
});

test("aborting scan on hopper win does not trip the scan breaker", async () => {
  let n = 0;
  const backend = await mockBackend({
    bloom: "unknown",
    sample: async (sha) => {
      n += 1;
      if (n <= _test.BREAKER_FAILS) {
        await delay(50);
        return { status: 200, sha, body: envelope(sha, { eng: "hopper-late" }) };
      }
      return { status: 404 };
    },
    analyze: async () => {
      await delay(200);
      return envelope(HELLO_SHA, { eng: "scan" });
    },
  });
  const env = testEnv(backend.url, { HOPPER_HEDGE_MS: "15" });
  try {
    for (let i = 0; i < _test.BREAKER_FAILS; i++) {
      const ctx = waitCtx();
      const res = await handle(
        new Request(`http://beamline/analyze?sha256=${HELLO_SHA}`, { method: "POST", body: HELLO }),
        { ...env, cache: _test.memoryCache() },
        ctx.ctx,
      );
      assert.equal(res.headers.get("x-beamline-source"), "hopper");
      await ctx.flush();
    }
    const ctx = waitCtx();
    const res = await handle(
      new Request(`http://beamline/analyze?sha256=${HELLO_SHA}`, { method: "POST", body: HELLO }),
      { ...env, cache: _test.memoryCache() },
      ctx.ctx,
    );
    assert.equal(res.status, 200);
    assert.equal(res.headers.get("x-beamline-source"), "scan");
    await ctx.flush();
  } finally {
    await backend.close();
  }
});

test("hopper lookup timeout trips the breaker", async () => {
  const backend = await mockBackend({
    bloom: "unknown",
    sample: () => new Promise(() => {}),
  });
  const env = testEnv(backend.url, { HOPPER_HEDGE_MS: "5", HOPPER_LOOKUP_MS: "40" });
  try {
    for (let i = 0; i < _test.BREAKER_FAILS; i++) {
      const res = await handle(new Request(`http://beamline/lookup?sha256=${HELLO_SHA}`), env, noopCtx());
      assert.equal(res.status, 503);
    }
    const before = backend.hits.sample;
    const res = await handle(new Request(`http://beamline/lookup?sha256=${HELLO_SHA}`), env, noopCtx());
    assert.equal(res.status, 503);
    assert.equal(backend.hits.sample, before);
  } finally {
    await backend.close();
  }
});

test("client abort during the hedge wait is 499", async () => {
  const backend = await mockBackend({
    bloom: "unknown",
    sample: () => new Promise(() => {}),
    analyze: () => envelope(HELLO_SHA, { eng: "scan" }),
  });
  const env = testEnv(backend.url, { HOPPER_HEDGE_MS: "200" });
  const ac = new AbortController();
  try {
    const p = handle(
      new Request(`http://beamline/analyze?sha256=${HELLO_SHA}`, { method: "POST", body: HELLO, signal: ac.signal }),
      env,
      { waitUntil() {}, signal: ac.signal },
    );
    await delay(30);
    ac.abort();
    const res = await p;
    assert.equal(res.status, 499);
    assert.equal((await res.json()).error, "canceled");
  } finally {
    await backend.close();
  }
});

test("concurrent hedged lookups share one origin fetch", async () => {
  const backend = await mockBackend({
    bloom: "unknown",
    sample: async () => {
      await delay(40);
      return { status: 404 };
    },
    analyze: async () => {
      await delay(30);
      return envelope(HELLO_SHA, { eng: "once" });
    },
  });
  const env = testEnv(backend.url, { HOPPER_HEDGE_MS: "15" });
  try {
    const ctx = waitCtx();
    const [a, b] = await Promise.all([
      handle(new Request(`http://beamline/analyze?sha256=${HELLO_SHA}`, { method: "POST", body: HELLO }), env, ctx.ctx),
      handle(new Request(`http://beamline/analyze?sha256=${HELLO_SHA}`, { method: "POST", body: HELLO }), env, ctx.ctx),
    ]);
    assert.equal(a.status, 200);
    assert.equal(b.status, 200);
    assert.equal(a.headers.get("x-beamline-source"), "scan");
    assert.equal(b.headers.get("x-beamline-source"), "scan");
    assert.equal(backend.hits.sample, 1);
    assert.equal(backend.hits.analyze, 1);
    await ctx.flush();
  } finally {
    await backend.close();
  }
});

test("when both arms finish, hopper 200 wins", async () => {
  const backend = await mockBackend({
    bloom: "unknown",
    sample: () => ({ status: 200, sha: HELLO_SHA, body: envelope(HELLO_SHA, { eng: "hopper" }) }),
    analyze: async () => {
      await delay(80);
      return envelope(HELLO_SHA, { eng: "scan" });
    },
  });
  const env = testEnv(backend.url, { HOPPER_HEDGE_MS: "0" });
  const ctx = waitCtx();
  try {
    const res = await handle(
      new Request(`http://beamline/analyze?sha256=${HELLO_SHA}`, { method: "POST", body: HELLO }),
      env,
      ctx.ctx,
    );
    assert.equal(res.status, 200);
    assert.equal(res.headers.get("x-beamline-source"), "hopper");
    assert.equal((await res.json()).eng, "hopper");
    await ctx.flush();
    assert.equal(backend.hits.result, 0);
  } finally {
    await backend.close();
  }
});

test("scan 415 passes through error and detail, not 404", async () => {
  const backend = await mockBackend({
    bloom: "unknown",
    sample: () => ({ status: 404 }),
    analyze: () => ({
      status: 415,
      body: { error: "unsupported file type", detail: "not a recognized binary" },
      headers: { "x-total-ms": "9" },
    }),
  });
  const env = testEnv(backend.url);
  try {
    const res = await handle(
      new Request(`http://beamline/analyze?sha256=${HELLO_SHA}`, { method: "POST", body: HELLO }),
      env,
      waitCtx().ctx,
    );
    assert.equal(res.status, 415);
    assert.equal(res.headers.get("x-total-ms"), "9");
    assert.deepEqual(await res.json(), {
      error: "unsupported file type",
      detail: "not a recognized binary",
    });
    assert.equal(backend.hits.upload, 0);
    assert.equal(backend.hits.result, 0);
  } finally {
    await backend.close();
  }
});

test("scan 400 on a PURL passes through, not 404", async () => {
  const backend = await mockBackend({
    bloom: "unknown",
    sample: () => ({ status: 404 }),
    analyzePurl: () => ({ status: 400, body: { error: "not a package URL" } }),
  });
  const env = testEnv(backend.url);
  try {
    const res = await handle(new Request(`http://beamline/analyze?sha256=${HELLO_SHA}&purl=not-a-purl`, { method: "POST" }), env, noopCtx());
    assert.equal(res.status, 400);
    assert.equal((await res.json()).error, "not a package URL");
    assert.equal(backend.hits.analyze, 0);
  } finally {
    await backend.close();
  }
});

test("scan 504 without hopper bytes is a timeout, not unavailable", async () => {
  const backend = await mockBackend({
    bloom: "unknown",
    sample: () => ({ status: 404 }),
    analyzePurl: () => ({
      status: 504,
      body: { error: "analysis timeout", timeout_secs: 1800 },
    }),
  });
  const env = testEnv(backend.url);
  try {
    const res = await handle(
      new Request(`http://beamline/analyze?sha256=${HELLO_SHA}&purl=pkg%3Anpm%2Fleft-pad%401.3.0`, { method: "POST" }),
      env,
      noopCtx(),
    );
    assert.equal(res.status, 504);
    assert.deepEqual(await res.json(), { error: "analysis timeout", timeout_secs: 1800 });
  } finally {
    await backend.close();
  }
});

test("scan 429 without hopper bytes passes through", async () => {
  const backend = await mockBackend({
    bloom: "unknown",
    sample: () => ({ status: 404 }),
    analyzePurl: () => ({
      status: 429,
      body: { error: "At capacity (4/4 active analyses)" },
    }),
  });
  const env = testEnv(backend.url);
  try {
    const res = await handle(
      new Request(`http://beamline/analyze?sha256=${HELLO_SHA}&purl=pkg%3Anpm%2Fleft-pad%401.3.0`, { method: "POST" }),
      env,
      noopCtx(),
    );
    assert.equal(res.status, 429);
    assert.equal((await res.json()).error, "At capacity (4/4 active analyses)");
  } finally {
    await backend.close();
  }
});

test("scan down does not wait when hopper rejects the upload", async () => {
  const backend = await mockBackend({
    bloom: "unknown",
    sample: () => ({ status: 404 }),
    uploadStatus: 500,
  });
  const env = testEnv(backend.url, { SCAN_URL: DEAD });
  try {
    const res = await handle(
      new Request(`http://beamline/analyze?sha256=${HELLO_SHA}`, { method: "POST", body: HELLO }),
      env,
      noopCtx(),
    );
    assert.equal(res.status, 503);
    assert.equal(backend.hits.rescan, 0);
  } finally {
    await backend.close();
  }
});

test("hits carry the byte offset and line the match fired on", () => {
  const envl = {
    ml: { lvl: 3, eng: "2.8.0" },
    raw: {
      files: [
        {
          path: "evil.tgz!!lib/install.js",
          traits: [
            { id: "objectives/execution/shell/bash", crit: 5, desc: "Spawns bash" },
            { id: "objectives/exfil", crit: 4, desc: "POSTs env", spans: [[512, 20]] },
          ],
          ctx: [
            { ln: 100, line: 10, n: [{ i: "objectives/execution/shell/bash", o: 109, z: 4 }] },
          ],
        },
      ],
    },
  };
  const view = _test.customerView(envl, HELLO_SHA, "pkg:npm/evil@1.0.0");
  // The note holds the exact byte; the window it sits in names the line.
  assert.equal(view.hits[0].off, 109);
  assert.equal(view.hits[0].line, 10);
  // No note for this one, so its own evidence span locates it — with no line
  // to claim, rather than a guessed one.
  assert.equal(view.hits[1].off, 512);
  assert.equal(view.hits[1].line, undefined);
});

test("an inherited finding is not repeated as its own hit", () => {
  const envl = {
    ml: { lvl: 4, eng: "2.8.0" },
    raw: {
      files: [
        {
          // The archive reports the member's finding a second time, pointing
          // back at it — the same match, without the path or offset.
          path: "evil.tgz",
          traits: [{ id: "objectives/exfil", crit: 4, desc: "POSTs env", from: [{ file: 2 }] }],
        },
        {
          path: "evil.tgz!!lib/install.js",
          traits: [{ id: "objectives/exfil", crit: 4, desc: "POSTs env", spans: [[512, 20]] }],
        },
      ],
    },
  };
  const view = _test.customerView(envl, HELLO_SHA, "pkg:npm/evil@1.0.0");
  assert.equal(view.hits.length, 1, "one match, reported once");
  assert.equal(view.hits[0].file, "lib/install.js", "the member that actually matched");
  assert.equal(view.hits[0].off, 512);
});

test("PURLs normalize so the pkg: prefix and type case are not two keys", () => {
  const canonical = "pkg:npm/left-pad@1.3.0";
  assert.equal(_test.normalizePurl("pkg:npm/left-pad@1.3.0"), canonical);
  assert.equal(_test.normalizePurl("npm/left-pad@1.3.0"), canonical, "pkg: is optional");
  assert.equal(_test.normalizePurl("PKG:NPM/left-pad@1.3.0"), canonical, "scheme and type fold");
  assert.equal(_test.normalizePurl("  npm/left-pad@1.3.0  "), canonical);
  // The name keeps its case: npm grandfathered in mixed-case package names.
  assert.equal(_test.normalizePurl("npm/Left-Pad@1.3.0"), "pkg:npm/Left-Pad@1.3.0");
  // Qualifiers and subpaths ride along untouched.
  assert.equal(
    _test.normalizePurl("generic/x@1?download_url=https://e.test/x.tgz#sub"),
    "pkg:generic/x@1?download_url=https://e.test/x.tgz#sub",
  );
  // Unrecognizable input is scan's call to make, not ours.
  assert.equal(_test.normalizePurl("not-a-purl"), "not-a-purl");
  assert.equal(_test.normalizePurl("   "), "");
});

test("/lookup takes exactly one key", async () => {
  const backend = await mockBackend({ bloom: "unknown", sample: () => ({ status: 404 }) });
  const env = testEnv(backend.url);
  try {
    const both = await handle(
      new Request(`http://beamline/lookup?sha256=${HELLO_SHA}&purl=pkg:npm/x@1`),
      env,
      noopCtx(),
    );
    assert.equal(both.status, 400);
    assert.equal((await both.json()).error, "provide exactly one of sha256 or purl");

    const neither = await handle(new Request("http://beamline/lookup"), env, noopCtx());
    assert.equal(neither.status, 400);

    const bad = await handle(new Request("http://beamline/lookup?sha256=nope"), env, noopCtx());
    assert.equal(bad.status, 400);
    assert.equal((await bad.json()).error, "invalid sha256");

    // The path forms /lookup replaced are gone, not quietly still serving.
    for (const gone of [`http://beamline/sha256/${HELLO_SHA}`, "http://beamline/purl/pkg:npm/x@1"]) {
      const res = await handle(new Request(gone), env, noopCtx());
      assert.equal(res.status, 404, `${gone} should no longer route`);
    }
  } finally {
    await backend.close();
  }
});

test("a PURL asked for two ways shares one cache entry", async () => {
  const backend = await mockBackend({
    bloom: "unknown",
    verdict: () => ({ sha: HELLO_SHA, lvl: -1, eng: "2.8.0" }),
  });
  const env = testEnv(backend.url);
  const ctx = waitCtx();
  try {
    // Canonical, then bare, then bare with the type in caps.
    for (const uri of [
      "http://beamline/lookup?purl=pkg%3Anpm%2Fleft-pad%401.3.0",
      "http://beamline/lookup?purl=npm%2Fleft-pad%401.3.0",
      "http://beamline/lookup?purl=NPM%2Fleft-pad%401.3.0",
    ]) {
      const res = await handle(new Request(uri), env, ctx.ctx);
      assert.equal(res.status, 200);
      // The cache write is deliberately off the response path, so let it land
      // before asking whether the next spelling hits it.
      await ctx.flush();
    }
    assert.equal(backend.hits.bloom, 1, "one spelling reached scan; the rest were cached");
  } finally {
    await backend.close();
  }
});

test("customer view is sha/purl/lvl/eng plus at most three notable hits", () => {
  const envl = {
    ml: { lvl: 3, eng: "2.7.2" },
    llm: { interpretation: "Postinstall launches a reverse shell." },
    raw: {
      v: "8",
      files: [
        {
          path: "evil.tgz!!lib/install.js",
          ident: { name: "evil", version: "1.0.0" },
          traits: [
            { id: "baseline/noise", crit: 2, desc: "ignore" },
            { id: "objectives/execution/shell/bash", crit: 5, desc: "Spawns bash from a npm postinstall hook" },
            { id: "objectives/persist", crit: 4, desc: "Writes a cron entry" },
            { id: "objectives/exfil", crit: 3, desc: "POSTs env to a paste site" },
            { id: "objectives/other", crit: 3, desc: "should not appear" },
          ],
        },
      ],
    },
  };
  const view = _test.customerView(envl, HELLO_SHA, "pkg:npm/evil@1.0.0");
  assert.deepEqual(view, {
    sha: HELLO_SHA,
    purl: "pkg:npm/evil@1.0.0",
    lvl: 3,
    eng: "2.7.2",
    why: "Postinstall launches a reverse shell.",
    hits: [
      {
        id: "objectives/execution/shell/bash",
        crit: 5,
        desc: "Spawns bash from a npm postinstall hook",
        file: "lib/install.js",
        pkg: "pkg:npm/evil@1.0.0",
      },
      {
        id: "objectives/persist",
        crit: 4,
        desc: "Writes a cron entry",
        file: "lib/install.js",
        pkg: "pkg:npm/evil@1.0.0",
      },
      {
        id: "objectives/exfil",
        crit: 3,
        desc: "POSTs env to a paste site",
        file: "lib/install.js",
        pkg: "pkg:npm/evil@1.0.0",
      },
    ],
  });
});

test("clean samples have no hits even if traits are present", () => {
  const view = _test.customerView(
    {
      ml: { lvl: -1, eng: "beamline" },
      raw: { files: [{ path: "a.js", traits: [{ id: "x", crit: 5, desc: "nope" }] }] },
    },
    HELLO_SHA,
    null,
  );
  assert.equal(view.lvl, -1);
  assert.equal(view.hits, undefined);
  assert.equal(view.why, undefined);
});

test("the handler never encodes the body itself", async () => {
  // Cloudflare's edge compresses Worker responses. A Worker that also
  // compresses double-encodes: gzip-in-gzip for a client that asked for gzip,
  // and a gzip body with no Content-Encoding for one that asked for identity.
  const backend = await mockBackend({
    bloom: "unknown",
    sample: () => ({ status: 200, sha: HELLO_SHA, body: envelope(HELLO_SHA, { eng: "plain" }) }),
  });
  const env = testEnv(backend.url);
  try {
    for (const accept of ["gzip", "identity", "gzip, deflate, br"]) {
      const res = await handle(
        new Request(`http://beamline/lookup?sha256=${HELLO_SHA}`, { headers: { "accept-encoding": accept } }),
        { ...env, cache: _test.memoryCache() },
        noopCtx(),
      );
      assert.equal(res.status, 200);
      assert.equal(res.headers.get("content-encoding"), null, `encoded for accept-encoding: ${accept}`);
      // Readable as-is, with no decompression step.
      assert.equal((await res.json()).eng, "plain");
    }
  } finally {
    await backend.close();
  }
});

test("a token-protected reply is private to the client but still cacheable by us", async () => {
  const backend = await mockBackend({
    bloom: "unknown",
    sample: () => ({ status: 200, sha: HELLO_SHA, body: envelope(HELLO_SHA, { eng: "hopper" }) }),
  });
  const inner = _test.memoryCache();
  const stored = [];
  const env = {
    ...testEnv(backend.url),
    BEAMLINE_TOKEN: "alpha",
    cache: {
      match: (req) => inner.match(req),
      put: (req, res) => {
        stored.push(res.headers.get("cache-control"));
        return inner.put(req, res);
      },
    },
  };
  const headers = { authorization: "Bearer alpha" };
  const ctx = waitCtx();
  try {
    const first = await handle(new Request(`http://beamline/lookup?sha256=${HELLO_SHA}`, { headers }), env, ctx.ctx);
    assert.equal(first.status, 200);
    assert.match(first.headers.get("cache-control"), /^private,/);
    await ctx.flush();
    assert.equal(stored.length, 1);
    assert.ok(!stored[0].includes("private"), `stored as ${stored[0]}`);

    const second = await handle(new Request(`http://beamline/lookup?sha256=${HELLO_SHA}`, { headers }), env, noopCtx());
    assert.equal(second.status, 200);
    assert.equal(second.headers.get("x-beamline-source"), "cache");
    assert.equal(backend.hits.sample, 1);
  } finally {
    await backend.close();
  }
});

test("background work is registered on the context the request arrived on", async () => {
  // Regression: dispatch spread the ExecutionContext to attach a request id,
  // which dropped the prototype's waitUntil. Production then served a 100%
  // cache miss rate while every test passed — under Node the put runs anyway,
  // so asserting that the cache eventually filled proves nothing. The invariant
  // that actually broke is that the runtime was *told* to keep the work alive,
  // so that is what this asserts.
  const backend = await mockBackend({
    bloom: "unknown",
    sample: () => ({ status: 200, sha: HELLO_SHA, body: envelope(HELLO_SHA, { eng: "hopper" }) }),
  });
  const host = hostCtx();
  try {
    const res = await handle(
      new Request(`http://beamline/lookup?sha256=${HELLO_SHA}`),
      testEnv(backend.url),
      host.ctx,
    );
    assert.equal(res.status, 200);
    assert.ok(host.registered() > 0, "nothing was handed to waitUntil; background work would be cancelled");
    await host.flush();
  } finally {
    await backend.close();
  }
});

test("a verdict is cached for an hour, and the life is tunable", async () => {
  const mk = async (extra) => {
    const backend = await mockBackend({
      bloom: "unknown",
      sample: () => ({ status: 200, sha: HELLO_SHA, body: envelope(HELLO_SHA, { eng: "hopper" }) }),
    });
    try {
      const env = { ...testEnv(backend.url), ...extra };
      const res = await handle(new Request(`http://beamline/lookup?sha256=${HELLO_SHA}`), env, noopCtx());
      assert.equal(res.status, 200);
      return res.headers.get("cache-control");
    } finally {
      await backend.close();
    }
  };
  // Short by default: while the service is still moving, a wrong verdict must
  // age out of every colo within the hour rather than within the day.
  assert.match(await mk({}), /max-age=3600$/);
  // And raisable without a code change, for when the answers have settled.
  assert.match(await mk({ VERDICT_MAX_AGE: "86400" }), /max-age=86400$/);
});

test("a lookup logs the layer that answered, so cache hits are countable", async () => {
  const backend = await mockBackend({
    bloom: "unknown",
    sample: () => ({ status: 200, sha: HELLO_SHA, body: envelope(HELLO_SHA, { eng: "hopper" }) }),
  });
  const env = testEnv(backend.url);
  const ctx = waitCtx();
  const log = captureLogs();
  _test.muteLogs(false);
  try {
    await handle(new Request(`http://beamline/lookup?sha256=${HELLO_SHA}`), env, ctx.ctx);
    await ctx.flush();
    await handle(new Request(`http://beamline/lookup?sha256=${HELLO_SHA}`), env, noopCtx());
  } finally {
    _test.muteLogs(true);
    log.restore();
    await backend.close();
  }
  const sources = log.rows.filter((r) => r.event === "lookup").map((r) => r.src);
  // The first request pays for the answer, the second is the hit. Both name a
  // source: a hit rate nothing reports is a hit rate nobody knows.
  assert.ok(sources.includes("hopper"), `sources were ${JSON.stringify(sources)}`);
  assert.ok(sources.includes("cache"), `sources were ${JSON.stringify(sources)}`);
});

test("a cached answer is the same answer, on every path that produces one", async () => {
  const stored = () => ({ status: 200, sha: HELLO_SHA, body: envelope(HELLO_SHA, { eng: "hopper" }) });
  const cases = [
    {
      what: "hopper hit, authenticated",
      backend: { bloom: "unknown", sample: stored },
      extra: { BEAMLINE_TOKEN: "alpha" },
      make: () =>
        new Request(`http://beamline/lookup?sha256=${HELLO_SHA}`, { headers: { authorization: "Bearer alpha" } }),
    },
    {
      what: "hopper hit, open deployment",
      backend: { bloom: "unknown", sample: stored },
      extra: {},
      make: () => new Request(`http://beamline/lookup?sha256=${HELLO_SHA}`),
    },
    {
      what: "definite miss, authenticated",
      backend: { bloom: "unknown", sample: () => ({ status: 404 }) },
      extra: { BEAMLINE_TOKEN: "alpha" },
      make: () =>
        new Request(`http://beamline/lookup?sha256=${HELLO_SHA}`, { headers: { authorization: "Bearer alpha" } }),
    },
    {
      what: "purl asked of hopper, authenticated",
      backend: { bloom: "unknown", sample: stored },
      extra: { BEAMLINE_TOKEN: "alpha" },
      make: () =>
        new Request(`http://beamline/lookup?purl=${encodeURIComponent("pkg:gem/rails@8.1.3.1")}`, {
          headers: { authorization: "Bearer alpha" },
        }),
    },
  ];
  for (const c of cases) {
    const backend = await mockBackend(c.backend);
    try {
      await assertSameThroughCache({ ...testEnv(backend.url), ...c.extra }, c.make, c.what);
    } finally {
      await backend.close();
    }
  }
});

test("a reply from cache is as private to the client as a fresh one", async () => {
  // serveHit stores the copy as `public` because Cloudflare will not hold a
  // `private` one. That rewrite must not reach the caller: found in production
  // once the cache started serving, where an authenticated verdict came back
  // marked public — and the zone then restamped max-age to its browser TTL,
  // so a cached answer advertised a different life than a fresh one.
  const backend = await mockBackend({
    bloom: "unknown",
    sample: () => ({ status: 200, sha: HELLO_SHA, body: envelope(HELLO_SHA, { eng: "hopper" }) }),
  });
  const env = { ...testEnv(backend.url), BEAMLINE_TOKEN: "alpha" };
  const headers = { authorization: "Bearer alpha" };
  const ctx = waitCtx();
  try {
    const first = await handle(new Request(`http://beamline/lookup?sha256=${HELLO_SHA}`, { headers }), env, ctx.ctx);
    assert.equal(first.status, 200);
    await ctx.flush();

    const second = await handle(new Request(`http://beamline/lookup?sha256=${HELLO_SHA}`, { headers }), env, noopCtx());
    assert.equal(second.headers.get("x-beamline-source"), "cache");
    assert.equal(second.headers.get("cache-control"), first.headers.get("cache-control"));
    assert.match(second.headers.get("cache-control"), /^private, max-age=3600$/);
  } finally {
    await backend.close();
  }
});

test("an unauthenticated deployment still serves a public cached reply", async () => {
  const backend = await mockBackend({
    bloom: "unknown",
    sample: () => ({ status: 200, sha: HELLO_SHA, body: envelope(HELLO_SHA, { eng: "hopper" }) }),
  });
  const env = testEnv(backend.url);
  const ctx = waitCtx();
  try {
    await handle(new Request(`http://beamline/lookup?sha256=${HELLO_SHA}`), env, ctx.ctx);
    await ctx.flush();
    const second = await handle(new Request(`http://beamline/lookup?sha256=${HELLO_SHA}`), env, noopCtx());
    assert.equal(second.headers.get("x-beamline-source"), "cache");
    assert.match(second.headers.get("cache-control"), /^public, max-age=3600$/);
  } finally {
    await backend.close();
  }
});

test("a definite miss is cached, so a hot unknown sha stops replaying the pipeline", async () => {
  const backend = await mockBackend({ bloom: "unknown", sample: () => ({ status: 404 }) });
  const env = testEnv(backend.url);
  const ctx = waitCtx();
  try {
    const first = await handle(new Request(`http://beamline/lookup?sha256=${HELLO_SHA}`), env, ctx.ctx);
    assert.equal(first.status, 404);
    await ctx.flush();

    const second = await handle(new Request(`http://beamline/lookup?sha256=${HELLO_SHA}`), env, noopCtx());
    assert.equal(second.status, 404);
    assert.equal(second.headers.get("x-beamline-source"), "cache");
    assert.equal((await second.json()).error, "unknown sample");
    assert.equal(backend.hits.bloom, 1);
    assert.equal(backend.hits.sample, 1);
  } finally {
    await backend.close();
  }
});

test("one request id reaches every backend and every log line", async () => {
  const logs = captureLogs();
  const backend = await mockBackend({
    bloom: "unknown",
    sample: () => ({ status: 200, sha: HELLO_SHA, body: envelope(HELLO_SHA) }),
  });
  const env = testEnv(backend.url);
  _test.muteLogs(false);
  try {
    await handle(
      new Request(`http://beamline/lookup?sha256=${HELLO_SHA}`, { headers: { "cf-ray": "abc123-SJC" } }),
      env,
      noopCtx(),
    );
    assert.ok(backend.auths.length > 0);
    assert.ok(
      backend.auths.every((a) => a.rid === "abc123-SJC"),
      JSON.stringify(backend.auths),
    );
    assert.ok(logs.rows.length > 0);
    assert.ok(logs.rows.every((r) => r.rid === "abc123-SJC"), JSON.stringify(logs.rows));
  } finally {
    logs.restore();
    await backend.close();
  }
});

test("a caller's own request id is honored, filtered, and bounded", async () => {
  const backend = await mockBackend({
    bloom: "unknown",
    sample: () => ({ status: 200, sha: HELLO_SHA, body: envelope(HELLO_SHA) }),
  });
  const env = testEnv(backend.url);
  try {
    await handle(
      new Request(`http://beamline/lookup?sha256=${HELLO_SHA}`, {
        headers: { "x-request-id": "mine-42", "cf-ray": "ignored" },
      }),
      env,
      noopCtx(),
    );
    assert.ok(backend.auths.every((a) => a.rid === "mine-42"), JSON.stringify(backend.auths));

    const fresh = await mockBackend({
      bloom: "unknown",
      sample: () => ({ status: 200, sha: HELLO_SHA, body: envelope(HELLO_SHA) }),
    });
    await handle(
      new Request(`http://beamline/lookup?sha256=${HELLO_SHA.replace(/.$/, "a")}`, {
        headers: { "x-request-id": `bad/id@ ${"x".repeat(200)}` },
      }),
      { ...testEnv(fresh.url), cache: _test.memoryCache() },
      noopCtx(),
    );
    const seen = fresh.auths[0].rid;
    assert.match(seen, /^badidx+$/, seen);
    assert.equal(seen.length, 64);
    await fresh.close();
  } finally {
    await backend.close();
  }
});

test("a scan that never reached a verdict is retried until it does", async () => {
  let calls = 0;
  const backend = await mockBackend({
    bloom: "unknown",
    sample: () => ({ status: 404 }),
    analyze: () => {
      calls += 1;
      if (calls === 1) return { status: 503, body: { error: "unavailable" } };
      if (calls === 2) return { status: 429, body: { error: "At capacity (4/4 active analyses)" } };
      if (calls === 3) return { status: 502, body: { error: "bad gateway" } };
      return envelope(HELLO_SHA, { eng: "eventually" });
    },
  });
  const env = testEnv(backend.url);
  const ctx = waitCtx();
  try {
    const res = await handle(new Request(`http://beamline/analyze?sha256=${HELLO_SHA}`, { method: "POST", body: HELLO }), env, ctx.ctx);
    assert.equal(res.status, 200);
    assert.equal(res.headers.get("x-beamline-source"), "scan");
    assert.equal((await res.json()).eng, "eventually");
    assert.equal(calls, 4, "three transient failures, then the answer");
    await ctx.flush();
  } finally {
    await backend.close();
  }
});

test("a rejection is an answer, so it is not retried", async () => {
  const backend = await mockBackend({
    bloom: "unknown",
    sample: () => ({ status: 404 }),
    analyze: () => ({ status: 415, body: { error: "unsupported file type" } }),
  });
  const env = testEnv(backend.url);
  try {
    const res = await handle(
      new Request(`http://beamline/analyze?sha256=${HELLO_SHA}`, { method: "POST", body: HELLO }),
      env,
      waitCtx().ctx,
    );
    assert.equal(res.status, 415);
    assert.equal((await res.json()).error, "unsupported file type");
    assert.equal(backend.hits.analyze, 1, "a verdict must not be asked for twice");
  } finally {
    await backend.close();
  }
});

test("scan reporting its own analysis timeout is not retried", async () => {
  const backend = await mockBackend({
    bloom: "unknown",
    sample: () => ({ status: 404 }),
    analyzePurl: () => ({ status: 504, body: { error: "analysis timeout", timeout_secs: 1800 } }),
  });
  const env = testEnv(backend.url);
  try {
    const res = await handle(
      new Request(`http://beamline/analyze?sha256=${HELLO_SHA}&purl=pkg%3Anpm%2Fleft-pad%401.3.0`, { method: "POST" }),
      env,
      noopCtx(),
    );
    assert.equal(res.status, 504);
    assert.deepEqual(await res.json(), { error: "analysis timeout", timeout_secs: 1800 });
    // Re-running a sample scan already gave up on spends the budget twice.
    assert.equal(backend.hits.analyzePurl, 1);
  } finally {
    await backend.close();
  }
});

test("retries stop once the breaker opens rather than burning attempts", async () => {
  const backend = await mockBackend({
    bloom: "unknown",
    sample: () => ({ status: 404 }),
    analyze: () => ({ status: 500, body: { error: "boom" } }),
    // Refuse the upload so the lookup ends here instead of going on to wait on
    // a hopper worker; this test is only about how often scan is asked.
    uploadStatus: 500,
  });
  const env = testEnv(backend.url, { SCAN_RETRIES: "50" });
  const ctx = waitCtx();
  try {
    const res = await handle(new Request(`http://beamline/analyze?sha256=${HELLO_SHA}`, { method: "POST", body: HELLO }), env, ctx.ctx);
    assert.equal(res.status, 503);
    // BREAKER_FAILS consecutive failures open the circuit; the loop stops there
    // instead of running all 50 attempts against a backend known to be down.
    assert.ok(
      backend.hits.analyze <= _test.BREAKER_FAILS + 1,
      `kept asking an open circuit: ${backend.hits.analyze} calls`,
    );
    await ctx.flush();
  } finally {
    await backend.close();
  }
});

test("concurrent lookups of one sample share a single retry sequence", async () => {
  let calls = 0;
  const backend = await mockBackend({
    bloom: "unknown",
    sample: async () => {
      await delay(20);
      return { status: 404 };
    },
    analyze: async () => {
      calls += 1;
      await delay(20);
      if (calls <= 2) return { status: 503, body: { error: "unavailable" } };
      return envelope(HELLO_SHA, { eng: "shared" });
    },
  });
  const env = testEnv(backend.url);
  const ctx = waitCtx();
  try {
    const answers = await Promise.all(
      Array.from({ length: 5 }, () =>
        handle(new Request(`http://beamline/analyze?sha256=${HELLO_SHA}`, { method: "POST", body: HELLO }), env, ctx.ctx),
      ),
    );
    for (const res of answers) {
      assert.equal(res.status, 200);
      assert.equal((await res.json()).eng, "shared");
    }
    // Five clients, one flight: two failures and one success, not five of each.
    assert.equal(calls, 3, `retries fanned out: ${calls} scan calls`);
    assert.equal(backend.hits.sample, 1);
    await ctx.flush();
  } finally {
    await backend.close();
  }
});

test("the fastest worker wins, the loser is dropped, and hopper is told once", async () => {
  const hopper = await mockBackend({ bloom: "unknown", sample: () => ({ status: 404 }) });
  const fast = await mockBackend({ bloom: "unknown", analyze: () => envelope(HELLO_SHA, { eng: "fast" }) });
  const slow = await mockBackend({
    bloom: "unknown",
    analyze: async () => {
      await delay(400);
      return envelope(HELLO_SHA, { eng: "slow" });
    },
  });
  const env = testEnv(hopper.url, { SCAN_URL: `${slow.url},${fast.url}` });
  const ctx = waitCtx();
  try {
    const t0 = Date.now();
    const res = await handle(new Request(`http://beamline/analyze?sha256=${HELLO_SHA}`, { method: "POST", body: HELLO }), env, ctx.ctx);
    const ms = Date.now() - t0;
    assert.equal(res.status, 200);
    assert.equal((await res.json()).eng, "fast", "the slower worker must not decide the answer");
    assert.ok(ms < 300, `waited ${ms}ms for a loser we should have dropped`);

    await ctx.flush();
    // Both workers ran, but only the winner's verdict is written back.
    assert.equal(slow.hits.analyze, 1);
    assert.equal(fast.hits.analyze, 1);
    assert.equal(hopper.hits.result, 0, "the winning worker files its own verdict; beamline files none");
  } finally {
    await Promise.all([hopper.close(), fast.close(), slow.close()]);
  }
});

test("a PURL lookup races the same way", async () => {
  const hopper = await mockBackend({ bloom: "unknown", sample: () => ({ status: 404 }) });
  const fast = await mockBackend({ bloom: "unknown", analyzePurl: () => envelope(HELLO_SHA, { eng: "fast" }) });
  const slow = await mockBackend({
    bloom: "unknown",
    analyzePurl: async () => {
      await delay(400);
      return envelope(HELLO_SHA, { eng: "slow" });
    },
  });
  const env = testEnv(hopper.url, { SCAN_URL: `${slow.url},${fast.url}` });
  try {
    const t0 = Date.now();
    const res = await handle(new Request(`http://beamline/analyze?sha256=${HELLO_SHA}&purl=pkg%3Anpm%2Fleft-pad%401.3.0`, { method: "POST" }), env, waitCtx().ctx);
    assert.equal(res.status, 200);
    assert.equal((await res.json()).eng, "fast");
    assert.ok(Date.now() - t0 < 300);
  } finally {
    await Promise.all([hopper.close(), fast.close(), slow.close()]);
  }
});

test("a dead worker does not stop the race", async () => {
  const hopper = await mockBackend({ bloom: "unknown", sample: () => ({ status: 404 }) });
  const alive = await mockBackend({ bloom: "unknown", analyze: () => envelope(HELLO_SHA, { eng: "alive" }) });
  const env = testEnv(hopper.url, { SCAN_URL: `${DEAD},${alive.url}` });
  const ctx = waitCtx();
  try {
    const res = await handle(new Request(`http://beamline/analyze?sha256=${HELLO_SHA}`, { method: "POST", body: HELLO }), env, ctx.ctx);
    assert.equal(res.status, 200);
    assert.equal((await res.json()).eng, "alive");
    await ctx.flush();
  } finally {
    await Promise.all([hopper.close(), alive.close()]);
  }
});

test("a stagger lets the first worker answer before the next is asked", async () => {
  const hopper = await mockBackend({ bloom: "unknown", sample: () => ({ status: 404 }) });
  const first = await mockBackend({ bloom: "unknown", analyze: () => envelope(HELLO_SHA, { eng: "first" }) });
  const second = await mockBackend({ bloom: "unknown", analyze: () => envelope(HELLO_SHA, { eng: "second" }) });
  const env = testEnv(hopper.url, {
    SCAN_URL: `${first.url},${second.url}`,
    SCAN_RACE_DELAY_MS: "5000",
  });
  const ctx = waitCtx();
  try {
    const res = await handle(new Request(`http://beamline/analyze?sha256=${HELLO_SHA}`, { method: "POST", body: HELLO }), env, ctx.ctx);
    assert.equal(res.status, 200);
    assert.equal((await res.json()).eng, "first");
    // The second worker was never asked, so the race cost one slot, not two.
    assert.equal(second.hits.analyze, 0);
    await ctx.flush();
  } finally {
    await Promise.all([hopper.close(), first.close(), second.close()]);
  }
});

test("a worker with an open breaker is skipped while the others keep serving", async () => {
  const hopper = await mockBackend({ bloom: "unknown", sample: () => ({ status: 404 }) });
  const sick = await mockBackend({ bloom: "unknown", analyze: () => ({ status: 500, body: { error: "boom" } }) });
  const well = await mockBackend({
    bloom: "unknown",
    // Slow enough that the sick worker's 500 always lands first, so its
    // breaker trips on a fixed count instead of a race.
    analyze: async () => {
      await delay(25);
      return envelope(HELLO_SHA, { eng: "well" });
    },
  });
  const env = testEnv(hopper.url, { SCAN_URL: `${sick.url},${well.url}` });
  try {
    for (let i = 0; i < _test.BREAKER_FAILS + 2; i++) {
      const body = new TextEncoder().encode(`sample-${i}`);
      const res = await handle(
        new Request(`http://beamline/analyze?sha256=${await shaHex(body)}`, { method: "POST", body }),
        { ...env, cache: _test.memoryCache() },
        waitCtx().ctx,
      );
      assert.equal(res.status, 200, `lookup ${i} should still be served by the healthy worker`);
      assert.equal((await res.json()).eng, "well");
    }
    // Once its breaker opened the sick worker stops being asked; the healthy
    // one carries every lookup.
    assert.ok(
      sick.hits.analyze <= _test.BREAKER_FAILS,
      `kept asking a tripped worker: ${sick.hits.analyze} calls`,
    );
    assert.equal(well.hits.analyze, _test.BREAKER_FAILS + 2);
  } finally {
    await Promise.all([hopper.close(), sick.close(), well.close()]);
  }
});

test("a peer's stored verdict is worth waiting out an unknown for", async () => {
  const hopper = await mockBackend({ sample: () => ({ status: 404 }) });
  // Nothing to say, and quick about it.
  const quick = await mockBackend({ bloom: "unknown" });
  // Holds the analysis, and is the slower of the two.
  const holder = await mockBackend({
    bloom: "unknown",
    bloomDelayMs: 60,
    verdict: () => ({ sha: HELLO_SHA, lvl: 2, eng: "2.8.0" }),
    analyze: () => envelope(HELLO_SHA, { eng: "should-not-run" }),
  });
  const env = testEnv(hopper.url, { SCAN_URL: `${quick.url},${holder.url}` });
  try {
    const res = await handle(new Request(`http://beamline/analyze?sha256=${HELLO_SHA}`, { method: "POST", body: HELLO }), env, waitCtx().ctx);
    assert.equal(res.status, 200);
    // A verdict lives only on the worker that ran the analysis, so one peer
    // answering "unknown sample" first must not end the race.
    assert.equal(res.headers.get("x-beamline-source"), "scan-cache");
    assert.equal((await res.json()).lvl, 2);
    assert.equal(holder.hits.analyze, 0, "the stored verdict is the answer");
  } finally {
    await Promise.all([hopper.close(), quick.close(), holder.close()]);
  }
});

test("a definite filter decision still ends the race immediately", async () => {
  const hopper = await mockBackend({ sample: () => ({ status: 404 }) });
  const quick = await mockBackend({ bloom: "skip" });
  const sluggish = await mockBackend({ bloom: "unknown", bloomDelayMs: 400 });
  const env = testEnv(hopper.url, { SCAN_URL: `${sluggish.url},${quick.url}` });
  try {
    const t0 = Date.now();
    const res = await handle(new Request(`http://beamline/analyze?sha256=${HELLO_SHA}`, { method: "POST", body: HELLO }), env, waitCtx().ctx);
    const ms = Date.now() - t0;
    assert.equal(res.headers.get("x-beamline-source"), "bloom");
    assert.ok(ms < 300, `waited ${ms}ms; a skip needs no second opinion`);
  } finally {
    await Promise.all([hopper.close(), quick.close(), sluggish.close()]);
  }
});

test("bloom is raced and the first answer wins, slow worker dropped", async () => {
  const hopper = await mockBackend({ bloom: "unknown", sample: () => ({ status: 404 }) });
  const quick = await mockBackend({ bloom: "skip" });
  const sluggish = await mockBackend({
    bloom: () => "unknown",
    bloomDelayMs: 400,
    analyze: () => envelope(HELLO_SHA, { eng: "should-not-run" }),
  });
  const env = testEnv(hopper.url, { SCAN_URL: `${sluggish.url},${quick.url}` });
  try {
    const t0 = Date.now();
    const res = await handle(new Request(`http://beamline/analyze?sha256=${HELLO_SHA}`, { method: "POST", body: HELLO }), env, waitCtx().ctx);
    const ms = Date.now() - t0;
    assert.equal(res.status, 200);
    // The quick worker said skip first, so that is the answer and nothing is
    // analyzed at all.
    assert.equal(res.headers.get("x-beamline-source"), "bloom");
    assert.equal((await res.json()).lvl, -1);
    assert.ok(ms < 300, `waited ${ms}ms on the slow worker's bloom`);
    assert.equal(sluggish.hits.analyze, 0, "a skip must not cost an analysis");
  } finally {
    await Promise.all([hopper.close(), quick.close(), sluggish.close()]);
  }
});

test("an edge timeout is not retried into the same ceiling", async () => {
  const hopper = await mockBackend({ bloom: "unknown", sample: () => ({ status: 404 }) });
  // What Cloudflare returns when the origin outruns its proxy read timeout.
  const stalled = await mockBackend({ bloom: "unknown", analyze: () => ({ status: 524, body: { error: "origin timeout" } }) });
  const env = testEnv(hopper.url, { SCAN_URL: stalled.url, SCAN_TIMEOUT_MS: "60" });
  const ctx = waitCtx();
  try {
    const res = await handle(new Request(`http://beamline/analyze?sha256=${HELLO_SHA}`, { method: "POST", body: HELLO }), env, ctx.ctx);
    // Straight to the hopper queue instead of a retry storm: pending, not a
    // quarter hour of re-analysis.
    assert.equal(res.status, 202);
    assert.deepEqual(await res.json(), { state: "pending" });
    // Retrying costs a full analysis per worker and hits the same wall.
    assert.equal(stalled.hits.analyze, 1);
    await ctx.flush();
  } finally {
    await Promise.all([hopper.close(), stalled.close()]);
  }
});

test("/analyze needs a key, and a malformed sha is not one", async () => {
  for (const uri of [
    "http://beamline/analyze?sha256=nothex",
    `http://beamline/analyze?sha256=${HELLO_SHA.slice(0, 63)}`,
  ]) {
    const res = await handle(new Request(uri, { method: "POST", body: HELLO }), {}, {});
    assert.equal(res.status, 400, uri);
    assert.equal((await res.json()).error, "invalid sha256");
  }
  for (const uri of ["http://beamline/analyze", "http://beamline/analyze?sha256="]) {
    const res = await handle(new Request(uri, { method: "POST" }), {}, {});
    assert.equal(res.status, 400, uri);
    assert.equal((await res.json()).error, "provide sha256 or purl");
  }
});

test("bytes without a digest are hashed here, and the derived sha reaches scan", async () => {
  let sentName = "";
  const backend = await mockBackend({
    bloom: "unknown",
    sample: () => ({ status: 404 }),
    analyze: (body) => {
      sentName = /filename="([^"]*)"/.exec(body.toString("utf8"))?.[1] || "";
      return envelope(HELLO_SHA, { lvl: -1, eng: "2.7.2" });
    },
  });
  const env = testEnv(backend.url);
  try {
    // No sha256 anywhere in the request: the caller holds the artifact and
    // should not have to hash it to ask about it.
    const res = await handle(
      new Request("http://beamline/analyze", { method: "POST", body: HELLO }),
      env,
      noopCtx(),
    );
    assert.equal(res.status, 200);
    assert.equal((await res.json()).sha, HELLO_SHA, "the derived digest is the key we answer under");
    // Scan requires a digest; this is where it comes from.
    assert.equal(sentName, HELLO_SHA, "scan is handed the derived digest, not a placeholder");
  } finally {
    await backend.close();
  }
});

test("bytes that do not hash to the claimed sha are refused", async () => {
  const backend = await mockBackend({
    bloom: "unknown",
    sample: () => ({ status: 404 }),
    analyze: () => envelope(HELLO_SHA, { eng: "must-not-run" }),
  });
  const env = testEnv(backend.url);
  try {
    // Claiming one artifact's digest while sending another's would file the
    // verdict under the wrong key in beamline, in scan, and in hopper.
    const res = await handle(
      new Request(`http://beamline/analyze?sha256=${HELLO_SHA}`, {
        method: "POST",
        body: new TextEncoder().encode("not hello"),
      }),
      env,
      noopCtx(),
    );
    assert.equal(res.status, 400);
    assert.equal((await res.json()).error, "body does not match sha256");
    assert.equal(backend.hits.analyze, 0, "mismatched bytes must never reach a scanner");
  } finally {
    await backend.close();
  }
});

test("/analyze without a body falls back to fetching the artifact from hopper", async () => {
  const backend = await mockBackend({
    bloom: "unknown",
    sample: () => ({ status: 404 }),
    file: HELLO,
    analyze: () => envelope(HELLO_SHA, { eng: "from-hopper" }),
  });
  const env = testEnv(backend.url);
  const ctx = waitCtx();
  try {
    const res = await handle(
      new Request(`http://beamline/analyze?sha256=${HELLO_SHA}`, { method: "POST" }),
      env,
      ctx.ctx,
    );
    assert.equal(res.status, 200);
    assert.equal((await res.json()).eng, "from-hopper");
    assert.equal(backend.hits.file, 1);
    await ctx.flush();
  } finally {
    await backend.close();
  }
});

test("a purl hint on /analyze reaches the answer", async () => {
  const backend = await mockBackend({
    bloom: "unknown",
    sample: () => ({ status: 404 }),
    analyze: () => envelope(HELLO_SHA, { eng: "hinted" }),
  });
  const env = testEnv(backend.url);
  const ctx = waitCtx();
  try {
    const res = await handle(
      new Request(`http://beamline/analyze?sha256=${HELLO_SHA}&purl=${encodeURIComponent("NPM/left-pad@1.3.0")}`, {
        method: "POST",
        body: HELLO,
      }),
      env,
      ctx.ctx,
    );
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.eng, "hinted");
    // Canonicalized on the way in, the same as /lookup does.
    assert.equal(body.purl, "pkg:npm/left-pad@1.3.0");
    await ctx.flush();
  } finally {
    await backend.close();
  }
});

// The sha a caller must send alongside its bytes.
async function shaHex(bytes) {
  const hash = await crypto.subtle.digest("SHA-256", bytes);
  return [...new Uint8Array(hash)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function captureLogs() {
  const rows = [];
  const orig = console.log;
  console.log = (...args) => {
    const s = args[0];
    // logLine hands Workers an object and Node a serialized line; a helper that
    // knew only one of them would silently capture nothing on the other.
    if (s && typeof s === "object" && !Array.isArray(s)) {
      rows.push(s);
      return;
    }
    if (typeof s === "string" && s.startsWith("{")) {
      try {
        rows.push(JSON.parse(s));
        return;
      } catch {
        // fall through
      }
    }
    orig.apply(console, args);
  };
  return {
    rows,
    restore() {
      console.log = orig;
    },
  };
}

function envelope(sha, ml = {}) {
  return {
    ml: {
      v: "7",
      prob: 0,
      lvl: -1,
      conf: 0,
      version: "mock",
      eng: "mock",
      analyzed_at: "2026-01-01T00:00:00Z",
      files: [],
      ...ml,
    },
    raw: { v: "8", files: [{ sha, type: "js" }] },
  };
}

function testEnv(url, extra = {}) {
  return {
    HOPPER_URL: extra.HOPPER_URL ?? url,
    SCAN_URL: extra.SCAN_URL ?? url,
    HOPPER_POLL_MS: extra.HOPPER_POLL_MS ?? "10",
    SCAN_TIMEOUT_MS: extra.SCAN_TIMEOUT_MS ?? "2000",
    HOPPER_HEDGE_MS: extra.HOPPER_HEDGE_MS,
    HOPPER_LOOKUP_MS: extra.HOPPER_LOOKUP_MS,
    // Retries are real behaviour worth exercising, but not at a real clock:
    // 5ms base keeps a full backoff sequence under a fifth of a second.
    SCAN_RETRIES: extra.SCAN_RETRIES,
    SCAN_RETRY_BASE_MS: extra.SCAN_RETRY_BASE_MS ?? "5",
    SCAN_RACE_DELAY_MS: extra.SCAN_RACE_DELAY_MS,
    cache: extra.cache ?? _test.memoryCache(),
  };
}

function noopCtx() {
  return { waitUntil() {} };
}

// The real ExecutionContext is a class instance: waitUntil lives on the
// prototype and there are no own enumerable properties at all. waitCtx's object
// literal keeps it as an own property, which a spread copies — so only this
// shape catches code that spreads the context and drops the method.
function hostCtx() {
  const jobs = [];
  class ExecutionContextLike {
    waitUntil(p) {
      jobs.push(Promise.resolve(p));
    }
  }
  return {
    ctx: new ExecutionContextLike(),
    registered: () => jobs.length,
    async flush() {
      while (jobs.length) await Promise.all(jobs.splice(0));
    },
  };
}

// Headers a cached answer is allowed to differ on: each describes this
// delivery rather than the verdict being delivered.
const DELIVERY_HEADERS = new Set(["x-beamline-source", "x-beamline-worker", "server-timing", "age", "date"]);

// Runs one request twice and asserts the cached answer is the same answer.
//
// Both cache bugs found in production were divergences between the copy
// beamline stored and the copy a caller gets back — a `public` scope that was
// meant for our cache alone, and before that no stored copy at all. Neither is
// visible to a test that only ever inspects the first response, so this looks
// at the second and compares.
async function assertSameThroughCache(env, make, what) {
  const ctx = waitCtx();
  const fresh = await handle(make(), env, ctx.ctx);
  await ctx.flush();
  const cached = await handle(make(), env, noopCtx());

  assert.equal(cached.headers.get("x-beamline-source"), "cache", `${what}: second request was not a cache hit`);
  assert.equal(cached.status, fresh.status, `${what}: status differs`);
  assert.equal(await cached.clone().text(), await fresh.clone().text(), `${what}: body differs`);
  for (const [k, v] of fresh.headers) {
    if (DELIVERY_HEADERS.has(k.toLowerCase())) continue;
    assert.equal(cached.headers.get(k), v, `${what}: header ${k} differs between a fresh and a cached answer`);
  }
}

function waitCtx() {
  const jobs = [];
  return {
    ctx: {
      waitUntil(p) {
        jobs.push(Promise.resolve(p));
      },
    },
    // Background work registers more background work, so drain until quiet.
    async flush() {
      while (jobs.length) await Promise.all(jobs.splice(0));
    },
  };
}

function mockBackend(opts) {
  const hits = {
    bloom: 0,
    sample: 0,
    file: 0,
    analyze: 0,
    analyzePurl: 0,
    result: 0,
    upload: 0,
    rescan: 0,
    stats: 0,
  };
  const results = [];
  const auths = [];
  const server = createServer(async (req, res) => {
    try {
      const url = new URL(req.url || "/", "http://127.0.0.1");
      auths.push({
        path: url.pathname,
        authorization: req.headers.authorization || "",
        rid: req.headers["x-request-id"] || "",
      });
      const body = await readReq(req);
      if (url.pathname === "/_/stats") {
        hits.stats += 1;
        if (!opts.stats) return send(res, 404, { error: "not found" });
        return send(res, 200, typeof opts.stats === "function" ? opts.stats() : opts.stats);
      }
      if (url.pathname === "/lookup") {
        hits.bloom += 1;
        if (opts.bloomDelayMs) await new Promise((r) => setTimeout(r, opts.bloomDelayMs));
        const decision = typeof opts.bloom === "function" ? opts.bloom(url) : opts.bloom || "unknown";
        const stored = typeof opts.verdict === "function" ? opts.verdict(url) : opts.verdict;
        if (opts.bloomStatus && opts.bloomStatus !== 200 && opts.bloomStatus !== 404) {
          return send(res, opts.bloomStatus, { error: "unavailable" });
        }
        if (stored) {
          return send(res, 200, { ...stored, bloom: decision });
        }
        return send(res, 404, { error: "unknown sample", bloom: decision });
      }
      if (url.pathname.startsWith("/api/sample")) {
        hits.sample += 1;
        const sha = url.pathname.slice("/api/sample/".length) || "";
        const out = await Promise.resolve(opts.sample ? opts.sample(sha, url) : { status: 404 });
        if (out.status === 204) {
          res.writeHead(204, out.sha ? { "x-sha256": out.sha } : {});
          return res.end();
        }
        if (out.status === 200) {
          return send(res, 200, out.body, out.sha ? { "x-sha256": out.sha } : {});
        }
        return send(res, out.status || 404, { error: "not found" });
      }
      if (url.pathname.startsWith("/api/file/")) {
        hits.file += 1;
        if (!opts.file) {
          res.writeHead(404);
          return res.end();
        }
        const sha = url.pathname.slice("/api/file/".length);
        const body = await Promise.resolve(typeof opts.file === "function" ? opts.file(sha) : opts.file);
        if (!body) {
          res.writeHead(404);
          return res.end();
        }
        const buf = Buffer.from(body);
        res.writeHead(200, { "content-type": "application/octet-stream", "content-length": String(buf.length) });
        return res.end(buf);
      }
      if (url.pathname === "/api/upload") {
        hits.upload += 1;
        return send(res, opts.uploadStatus || 200, { ok: true, sha256: HELLO_SHA });
      }
      if (url.pathname.startsWith("/api/rescan/")) {
        hits.rescan += 1;
        return send(res, 200, { status: "queued" });
      }
      if (url.pathname === "/api/result") {
        hits.result += 1;
        results.push(JSON.parse(body.toString("utf8") || "{}"));
        return send(res, 200, { ok: true });
      }
      if (url.pathname === "/analyze-purl") {
        hits.analyzePurl += 1;
        const parsed = JSON.parse(body.toString("utf8") || "{}");
        const out = opts.analyzePurl ? await opts.analyzePurl(parsed) : null;
        return sendAnalyze(res, out);
      }
      if (url.pathname === "/analyze") {
        hits.analyze += 1;
        const out = opts.analyze ? await opts.analyze(body) : null;
        return sendAnalyze(res, out);
      }
      send(res, 404, { error: "not found" });
    } catch (err) {
      send(res, 500, { error: String(err) });
    }
  });
  return listen(server).then(({ url, close }) => ({ url, close, hits, results, auths }));
}

function sendAnalyze(res, out) {
  if (!out) return send(res, 503, { error: "unavailable" });
  if (out.status) return send(res, out.status, out.body || { error: "rejected" }, out.headers || {});
  return send(res, 200, out, { "x-total-ms": "17" });
}

function send(res, status, body, headers = {}) {
  const payload = JSON.stringify(body);
  res.writeHead(status, { "content-type": "application/json", ...headers });
  res.end(payload);
}

function readReq(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

async function listen(server) {
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const { port } = server.address();
  return {
    url: `http://127.0.0.1:${port}`,
    close: () =>
      new Promise((resolve, reject) => {
        if (typeof server.closeAllConnections === "function") server.closeAllConnections();
        server.close((err) => (err ? reject(err) : resolve()));
      }),
  };
}

const ROUTE_CLASS_COUNT = 9; // lookup, four PURL types, four size buckets
function hostOf(u) { return new URL(u).host; }

// --- routing ---------------------------------------------------------------

// Shape of a /_/stats reply, with only the fields routing reads.
function statsFor({ slots = 8, free = 8, inFlight = 0, ms = 1000, bySize = {}, ...rest } = {}) {
  return {
    slots,
    slots_free: free,
    in_flight: inFlight,
    ready: true,
    overloaded: false,
    max_upload_mb: 100,
    avg_job_ms: ms,
    avg_job_ms_by_size: bySize,
    // Enough by default so existing cases stay "informed"; overridden per test.
    avg_job_samples: 50,
    ...rest,
  };
}

test("routing asks the worker its own history says is faster for this size", async () => {
  const hopper = await mockBackend({ bloom: "unknown", sample: () => ({ status: 404 }) });
  // Equal overall, but one is far better at small inputs — which is what a
  // single scalar average would have hidden.
  const small = await mockBackend({
    bloom: "unknown",
    stats: statsFor({ ms: 8000, bySize: { le_1mb: { jobs: 50, avg_ms: 200 } } }),
    analyze: () => envelope(HELLO_SHA, { eng: "small-specialist" }),
  });
  const big = await mockBackend({
    bloom: "unknown",
    stats: statsFor({ ms: 8000, bySize: { le_1mb: { jobs: 50, avg_ms: 9000 } } }),
    analyze: () => envelope(HELLO_SHA, { eng: "big-specialist" }),
  });
  const env = testEnv(hopper.url, { SCAN_URL: `${big.url},${small.url}` });
  const ctx = waitCtx();
  try {
    const res = await handle(
      new Request(`http://beamline/analyze?sha256=${HELLO_SHA}`, { method: "POST", body: HELLO }),
      env,
      ctx.ctx,
    );
    assert.equal(res.status, 200);
    assert.equal((await res.json()).eng, "small-specialist", "size-bucket history was ignored");
    // Hedged, not raced: the favourite answered well inside its own estimate,
    // so the other worker was never asked and spent no slot.
    assert.equal(big.hits.analyze, 0, "the hedge fired even though the favourite was prompt");
    await ctx.flush();
  } finally {
    await Promise.all([hopper.close(), small.close(), big.close()]);
  }
});

test("a saturated worker loses to an idle one with the same service time", async () => {
  const hopper = await mockBackend({ bloom: "unknown", sample: () => ({ status: 404 }) });
  const busy = await mockBackend({
    bloom: "unknown",
    stats: statsFor({ slots: 4, free: 0, inFlight: 8, ms: 1000 }),
    analyze: () => envelope(HELLO_SHA, { eng: "busy" }),
  });
  const idle = await mockBackend({
    bloom: "unknown",
    stats: statsFor({ slots: 4, free: 4, inFlight: 0, ms: 1000 }),
    analyze: () => envelope(HELLO_SHA, { eng: "idle" }),
  });
  const env = testEnv(hopper.url, { SCAN_URL: `${busy.url},${idle.url}` });
  const ctx = waitCtx();
  try {
    const res = await handle(
      new Request(`http://beamline/analyze?sha256=${HELLO_SHA}`, { method: "POST", body: HELLO }),
      env,
      ctx.ctx,
    );
    assert.equal((await res.json()).eng, "idle", "queue depth was ignored");
    await ctx.flush();
  } finally {
    await Promise.all([hopper.close(), busy.close(), idle.close()]);
  }
});

test("a worker that cannot take the upload is not asked at all", async () => {
  const hopper = await mockBackend({ bloom: "unknown", sample: () => ({ status: 404 }) });
  // Would be picked on latency alone; it simply cannot accept the body.
  const tiny = await mockBackend({
    bloom: "unknown",
    stats: statsFor({ ms: 1, max_upload_mb: 0 }),
    analyze: () => envelope(HELLO_SHA, { eng: "too-small" }),
  });
  const roomy = await mockBackend({
    bloom: "unknown",
    stats: statsFor({ ms: 9000 }),
    analyze: () => envelope(HELLO_SHA, { eng: "roomy" }),
  });
  const env = testEnv(hopper.url, { SCAN_URL: `${tiny.url},${roomy.url}` });
  const ctx = waitCtx();
  try {
    const res = await handle(
      new Request(`http://beamline/analyze?sha256=${HELLO_SHA}`, { method: "POST", body: HELLO }),
      env,
      ctx.ctx,
    );
    assert.equal((await res.json()).eng, "roomy");
    assert.equal(tiny.hits.analyze, 0, "an incapable worker was still asked");
    await ctx.flush();
  } finally {
    await Promise.all([hopper.close(), tiny.close(), roomy.close()]);
  }
});

test("an unready worker is skipped even when it looks fastest", async () => {
  const hopper = await mockBackend({ bloom: "unknown", sample: () => ({ status: 404 }) });
  const loading = await mockBackend({
    bloom: "unknown",
    stats: statsFor({ ms: 1, ready: false }),
    analyze: () => envelope(HELLO_SHA, { eng: "loading" }),
  });
  const serving = await mockBackend({
    bloom: "unknown",
    stats: statsFor({ ms: 9000 }),
    analyze: () => envelope(HELLO_SHA, { eng: "serving" }),
  });
  const env = testEnv(hopper.url, { SCAN_URL: `${loading.url},${serving.url}` });
  const ctx = waitCtx();
  try {
    const res = await handle(
      new Request(`http://beamline/analyze?sha256=${HELLO_SHA}`, { method: "POST", body: HELLO }),
      env,
      ctx.ctx,
    );
    assert.equal((await res.json()).eng, "serving");
    assert.equal(loading.hits.analyze, 0);
    await ctx.flush();
  } finally {
    await Promise.all([hopper.close(), loading.close(), serving.close()]);
  }
});

test("with no stats to go on it falls back to racing everyone", async () => {
  const hopper = await mockBackend({ bloom: "unknown", sample: () => ({ status: 404 }) });
  // Neither serves /_/stats. Holding an arm back would be a coin toss with a
  // long delay attached, so the old flat race is the right answer.
  const slow = await mockBackend({
    bloom: "unknown",
    analyze: async () => {
      await delay(300);
      return envelope(HELLO_SHA, { eng: "slow" });
    },
  });
  const fast = await mockBackend({ bloom: "unknown", analyze: () => envelope(HELLO_SHA, { eng: "fast" }) });
  const env = testEnv(hopper.url, { SCAN_URL: `${slow.url},${fast.url}` });
  const ctx = waitCtx();
  try {
    const res = await handle(
      new Request(`http://beamline/analyze?sha256=${HELLO_SHA}`, { method: "POST", body: HELLO }),
      env,
      ctx.ctx,
    );
    assert.equal((await res.json()).eng, "fast", "uninformed routing must still race");
    await ctx.flush();
  } finally {
    await Promise.all([hopper.close(), slow.close(), fast.close()]);
  }
});

test("/_/routes dry-runs the real ranking, per size bucket", async () => {
  const hopper = await mockBackend({ bloom: "unknown" });
  // Fast on small inputs, slow on large ones — the split a scalar average
  // hides, and the reason this view is per-bucket.
  const specialist = await mockBackend({
    stats: statsFor({ ms: 9000, bySize: { le_1mb: { jobs: 40, avg_ms: 200 } } }),
  });
  const steady = await mockBackend({ stats: statsFor({ ms: 3000 }) });
  const env = testEnv(hopper.url, { SCAN_URL: `${specialist.url},${steady.url}` });
  try {
    const res = await handle(new Request("http://beamline/_/routes"), env, waitCtx().ctx);
    assert.equal(res.status, 200);
    const body = await res.json();

    assert.equal(body.routes[0].kind, "lookup", "the index probe is its own cost class");
    assert.equal(body.routes[1].kind, "purl_type", "the PURL path is the common case");
    const small = body.routes.find((r) => r.class === "le_1mb");
    assert.equal(small.dispatch[0].worker, hostOf(specialist.url));
    assert.equal(small.dispatch[0].est_ms, 200);
    assert.equal(small.dispatch[0].delay_ms, 0, "the favourite must go immediately");
    assert.equal(small.dispatch[1].delay_ms, small.hedge_ms, "arm 1 waits one stagger");
    // 3x the favourite's own estimate: the hedge is a stall detector now, so
    // it sits well above the expected time rather than just below it.
    assert.equal(small.hedge_ms, 600);

    // Same fleet, same instant, opposite order — which is the whole point.
    const large = body.routes.find((r) => r.class === "le_128mb");
    assert.equal(large.dispatch[0].worker, hostOf(steady.url));
    assert.equal(body.routes.length, ROUTE_CLASS_COUNT);
  } finally {
    await Promise.all([hopper.close(), specialist.close(), steady.close()]);
  }
});

test("/_/routes says why a worker was excluded", async () => {
  const hopper = await mockBackend({ bloom: "unknown" });
  const loading = await mockBackend({ stats: statsFor({ ms: 1, ready: false }) });
  const serving = await mockBackend({ stats: statsFor({ ms: 3000 }) });
  const env = testEnv(hopper.url, { SCAN_URL: `${loading.url},${serving.url}` });
  try {
    const res = await handle(new Request("http://beamline/_/routes?size=1mb"), env, waitCtx().ctx);
    const body = await res.json();
    assert.equal(body.routes.length, 1, "?size= answers for one bucket");
    assert.equal(body.routes[0].class, "le_1mb");
    const [route] = body.routes;
    assert.deepEqual(
      route.excluded,
      [{ worker: hostOf(loading.url), reason: "not ready" }],
      "an excluded worker must carry its reason, not just vanish",
    );
    assert.equal(route.dispatch.length, 1);
  } finally {
    await Promise.all([hopper.close(), loading.close(), serving.close()]);
  }
});

test("/_/routes rejects a size it cannot parse", async () => {
  const hopper = await mockBackend({ bloom: "unknown" });
  const scan = await mockBackend({ stats: statsFor({}) });
  const env = testEnv(hopper.url, { SCAN_URL: scan.url });
  try {
    const res = await handle(new Request("http://beamline/_/routes?size=huge"), env, waitCtx().ctx);
    assert.equal(res.status, 400);
  } finally {
    await Promise.all([hopper.close(), scan.close()]);
  }
});

test("/_/routes is behind the token gate", async () => {
  const env = { ...testEnv("http://unused"), BEAMLINE_TOKEN: "secret" };
  const res = await handle(new Request("http://beamline/_/routes"), env, waitCtx().ctx);
  assert.equal(res.status, 401, "the route names every worker and its load");
});

test("a full worker is excluded as closed, not ranked as slow", async () => {
  const hopper = await mockBackend({ bloom: "unknown", sample: () => ({ status: 404 }) });
  // Fast on paper, but its next try_acquire_owned() returns 429.
  const full = await mockBackend({
    bloom: "unknown",
    stats: statsFor({ slots: 4, free: 0, inFlight: 4, ms: 100 }),
    analyze: () => envelope(HELLO_SHA, { eng: "full" }),
  });
  const open = await mockBackend({
    bloom: "unknown",
    stats: statsFor({ slots: 4, free: 2, ms: 8000 }),
    analyze: () => envelope(HELLO_SHA, { eng: "open" }),
  });
  const env = testEnv(hopper.url, { SCAN_URL: `${full.url},${open.url}` });
  const ctx = waitCtx();
  try {
    const res = await handle(
      new Request(`http://beamline/analyze?sha256=${HELLO_SHA}`, { method: "POST", body: HELLO }),
      env,
      ctx.ctx,
    );
    assert.equal((await res.json()).eng, "open");
    assert.equal(full.hits.analyze, 0, "dispatching to a full worker buys a 429");
    await ctx.flush();
  } finally {
    await Promise.all([hopper.close(), full.close(), open.close()]);
  }
});

test("occupancy scales the estimate; queue depth is still not added to it", async () => {
  const hopper = await mockBackend({ bloom: "unknown" });
  // 3 of 4 slots busy. scan rejects rather than queues, so the penalty is
  // proportional to how full the worker is — not the queue-drain term a
  // waiting-line model would add, which at this depth would be a whole extra
  // service time or more.
  const busy = await mockBackend({ stats: statsFor({ slots: 4, free: 1, inFlight: 3, ms: 2000 }) });
  const env = testEnv(hopper.url, { SCAN_URL: busy.url });
  try {
    const res = await handle(new Request("http://beamline/_/routes?size=1mb"), env, waitCtx().ctx);
    const body = await res.json();
    // 2000 * (1 + 0.75), not 2000 and not 2000 + ceil(3/4)*2000.
    assert.equal(body.routes[0].dispatch[0].est_ms, 3500);
  } finally {
    await Promise.all([hopper.close(), busy.close()]);
  }
});

test("an idle worker is scored on its latency alone", async () => {
  const hopper = await mockBackend({ bloom: "unknown" });
  const idle = await mockBackend({ stats: statsFor({ slots: 8, free: 8, inFlight: 0, ms: 2000 }) });
  const env = testEnv(hopper.url, { SCAN_URL: idle.url });
  try {
    const res = await handle(new Request("http://beamline/_/routes?size=1mb"), env, waitCtx().ctx);
    const body = await res.json();
    assert.equal(body.routes[0].dispatch[0].est_ms, 2000, "nothing to penalize on an empty worker");
  } finally {
    await Promise.all([hopper.close(), idle.close()]);
  }
});

test("a nearly-full worker loses to a roomier one that is slower on paper", async () => {
  const hopper = await mockBackend({ bloom: "unknown" });
  // The shape observed live: one worker faster but almost out of slots, another
  // slower with most of its capacity free. Latency alone picked the first and
  // then collected its 429s.
  const tight = await mockBackend({ stats: statsFor({ slots: 16, free: 1, inFlight: 15, ms: 10000 }) });
  const roomy = await mockBackend({ stats: statsFor({ slots: 64, free: 44, inFlight: 20, ms: 14000 }) });
  const env = testEnv(hopper.url, { SCAN_URL: `${tight.url},${roomy.url}` });
  try {
    const res = await handle(new Request("http://beamline/_/routes?size=1mb"), env, waitCtx().ctx);
    const [route] = (await res.json()).routes;
    assert.equal(route.dispatch[0].worker, hostOf(roomy.url), "sent work to a worker with one slot left");
    // 14000*(1+20/64)=18375 beats 10000*(1+15/16)=19375: the faster worker
    // loses because it has almost nowhere to put the work.
    assert.equal(route.dispatch[0].est_ms, 18375);
    assert.equal(route.dispatch[1].est_ms, 19375);
  } finally {
    await Promise.all([hopper.close(), tight.close(), roomy.close()]);
  }
});

test("X-Beamline-Pin forces the route the router would not have chosen", async () => {
  const hopper = await mockBackend({ bloom: "unknown", sample: () => ({ status: 404 }) });
  const quick = await mockBackend({
    bloom: "unknown",
    stats: statsFor({ ms: 100 }),
    analyze: () => envelope(HELLO_SHA, { eng: "quick" }),
  });
  const slow = await mockBackend({
    bloom: "unknown",
    stats: statsFor({ ms: 9000 }),
    analyze: () => envelope(HELLO_SHA, { eng: "slow" }),
  });
  const env = testEnv(hopper.url, { SCAN_URL: `${quick.url},${slow.url}` });
  const ctx = waitCtx();
  try {
    const res = await handle(
      new Request(`http://beamline/analyze?sha256=${HELLO_SHA}`, {
        method: "POST",
        body: HELLO,
        headers: { "x-beamline-pin": hostOf(slow.url) },
      }),
      env,
      ctx.ctx,
    );
    assert.equal((await res.json()).eng, "slow", "the pin was ignored");
    assert.equal(quick.hits.analyze, 0, "a pinned run must not also race the favourite");
    await ctx.flush();
  } finally {
    await Promise.all([hopper.close(), quick.close(), slow.close()]);
  }
});

test("a pinned run is never answered from cache", async () => {
  const hopper = await mockBackend({ bloom: "unknown", sample: () => ({ status: 404 }) });
  const a = await mockBackend({
    bloom: "unknown",
    stats: statsFor({ ms: 100 }),
    analyze: () => envelope(HELLO_SHA, { eng: "a" }),
  });
  const b = await mockBackend({
    bloom: "unknown",
    stats: statsFor({ ms: 100 }),
    analyze: () => envelope(HELLO_SHA, { eng: "b" }),
  });
  const env = testEnv(hopper.url, { SCAN_URL: `${a.url},${b.url}` });
  const ask = async (pin) => {
    const ctx = waitCtx();
    const res = await handle(
      new Request(`http://beamline/analyze?sha256=${HELLO_SHA}`, {
        method: "POST",
        body: HELLO,
        headers: pin ? { "x-beamline-pin": pin } : {},
      }),
      env,
      ctx.ctx,
    );
    const body = await res.json();
    await ctx.flush();
    return body;
  };
  try {
    await ask(null); // warms the cache under this key
    const pinned = await ask(hostOf(b.url));
    assert.equal(pinned.eng, "b", "the cached verdict answered instead of the pinned worker");
    assert.ok(b.hits.analyze >= 1, "the pinned worker must actually be timed");
  } finally {
    await Promise.all([hopper.close(), a.close(), b.close()]);
  }
});

test("/_/routes ages stats against a clock read after they are refreshed", async () => {
  const hopper = await mockBackend({ bloom: "unknown" });
  const scan = await mockBackend({ stats: statsFor({ ms: 1000 }) });
  const env = testEnv(hopper.url, { SCAN_URL: scan.url });
  try {
    const res = await handle(new Request("http://beamline/_/routes"), env, waitCtx().ctx);
    const body = await res.json();
    // A freshly polled worker is 0ms old, never -11ms.
    assert.ok(body.workers[0].stats_age_ms >= 0, `negative age: ${body.workers[0].stats_age_ms}`);
  } finally {
    await Promise.all([hopper.close(), scan.close()]);
  }
});

test("a worker that answers /_/stats with no history is not evidence", async () => {
  const hopper = await mockBackend({ bloom: "unknown" });
  // Reachable and healthy, but has completed nothing: avg_job_ms is null.
  const cold = await mockBackend({ stats: statsFor({ ms: null }) });
  const also = await mockBackend({ stats: statsFor({ ms: null }) });
  const env = testEnv(hopper.url, { SCAN_URL: `${cold.url},${also.url}` });
  try {
    const res = await handle(new Request("http://beamline/_/routes?size=none"), env, waitCtx().ctx);
    const [route] = (await res.json()).routes;
    assert.equal(route.informed, false, "a null average is a default, not knowledge");
    assert.equal(route.hedge_ms, 0, "hedging on a made-up estimate serializes a cold fleet");
    assert.equal(route.dispatch[1].delay_ms, 0);
  } finally {
    await Promise.all([hopper.close(), cold.close(), also.close()]);
  }
});

test("an unsized estimate compares workers on one shared job mix", async () => {
  const hopper = await mockBackend({ bloom: "unknown" });
  // Both took the same time per size class. They differ only in what they were
  // fed: `lucky` saw mostly small work, `unlucky` mostly large. A scalar
  // average would call lucky the faster machine; it is the same machine.
  const lucky = await mockBackend({
    stats: statsFor({
      ms: 1200, // scalar, dragged down by an easy mix
      bySize: { le_1mb: { jobs: 90, avg_ms: 1000 }, le_128mb: { jobs: 10, avg_ms: 3000 } },
    }),
  });
  const unlucky = await mockBackend({
    stats: statsFor({
      ms: 2800, // scalar, inflated by a hard mix
      bySize: { le_1mb: { jobs: 10, avg_ms: 1000 }, le_128mb: { jobs: 90, avg_ms: 3000 } },
    }),
  });
  const env = testEnv(hopper.url, { SCAN_URL: `${lucky.url},${unlucky.url}` });
  try {
    const res = await handle(new Request("http://beamline/_/routes?size=none"), env, waitCtx().ctx);
    const [route] = (await res.json()).routes;
    const [a, b] = route.dispatch;
    assert.equal(a.est_ms, b.est_ms, `identical workers scored differently: ${a.est_ms} vs ${b.est_ms}`);
    // Fleet mix is 100 small / 100 large, so a typical job is 2000ms.
    assert.equal(a.est_ms, 2000);
  } finally {
    await Promise.all([hopper.close(), lucky.close(), unlucky.close()]);
  }
});

test("a class a worker has never handled falls back to its own average", async () => {
  const hopper = await mockBackend({ bloom: "unknown" });
  // Only small-file history. Asked about a 128MB artifact it must not be
  // predicted at its small-file speed just because that is all it has done.
  const small = await mockBackend({
    stats: statsFor({ ms: 9000, bySize: { le_1mb: { jobs: 40, avg_ms: 200 } } }),
  });
  const env = testEnv(hopper.url, { SCAN_URL: small.url });
  try {
    const res = await handle(new Request("http://beamline/_/routes?size=128mb"), env, waitCtx().ctx);
    const [route] = (await res.json()).routes;
    assert.equal(route.dispatch[0].est_ms, 9000, "predicted a 128MB job at its small-file speed");
  } finally {
    await Promise.all([hopper.close(), small.close()]);
  }
});

test("429 does not trip the breaker, so a busy worker is asked again", async () => {
  // Enough 429s to open the breaker if they were counted as failures, then a
  // verdict. The worker is healthy throughout — it was only ever full.
  let calls = 0;
  const backend = await mockBackend({
    bloom: "unknown",
    sample: () => ({ status: 404 }),
    analyzePurl: () => {
      calls += 1;
      return calls <= 6
        ? { status: 429, body: { error: "At capacity (4/4 active analyses)" } }
        : envelope(HELLO_SHA, { eng: "recovered" });
    },
  });
  const env = testEnv(backend.url, { SCAN_RETRY_BASE_MS: "1", SCAN_RETRIES: "8" });
  try {
    const res = await handle(
      new Request("http://beamline/analyze?purl=pkg%3Anpm%2Fleft-pad%401.3.0", { method: "POST" }),
      env,
      noopCtx(),
    );
    assert.equal(res.status, 200, "backpressure was mistaken for a broken worker");
    assert.equal((await res.json()).eng, "recovered");
    assert.ok(calls > 6, `gave up after ${calls} attempts`);
  } finally {
    await backend.close();
  }
});

test("a 5xx still trips the breaker", async () => {
  // The regression guard for the change above: real failures must still open it.
  let calls = 0;
  const backend = await mockBackend({
    bloom: "unknown",
    sample: () => ({ status: 404 }),
    analyzePurl: () => {
      calls += 1;
      return { status: 500, body: { error: "boom" } };
    },
  });
  const env = testEnv(backend.url, { SCAN_RETRY_BASE_MS: "1", SCAN_RETRIES: "8" });
  try {
    const res = await handle(
      new Request("http://beamline/analyze?purl=pkg%3Anpm%2Fbroken%401.0.0", { method: "POST" }),
      env,
      noopCtx(),
    );
    assert.equal(res.status, 503);
    // BREAKER_FAILS is 5; the ladder must stop there rather than run all 8.
    assert.ok(calls <= 6, `kept hammering a broken worker: ${calls} attempts`);
  } finally {
    await backend.close();
  }
});

test("Server-Timing reports each raced arm, not just the winner", async () => {
  // hopper answers late; the scan index answers first and wins. Both figures
  // must survive, or the race is unmeasurable from outside.
  const backend = await mockBackend({
    bloom: "skip",
    bloomDelayMs: 20,
    sample: async () => {
      await delay(120);
      return { status: 404 };
    },
  });
  const env = testEnv(backend.url);
  const ctx = waitCtx();
  try {
    const res = await handle(
      new Request(`http://beamline/lookup?sha256=${HELLO_SHA}`),
      env,
      ctx.ctx,
    );
    assert.equal(res.status, 200);
    const t = res.headers.get("server-timing") || "";
    assert.match(t, /scan_index;dur=\d+/, `no scan-index timing: ${t}`);
    assert.match(t, /total;dur=\d+/, `no total: ${t}`);
    await ctx.flush();
  } finally {
    await backend.close();
  }
});

test("a cached reply does not replay the timings of the request that made it", async () => {
  const backend = await mockBackend({ bloom: "skip" });
  const env = testEnv(backend.url);
  const ask = async () => {
    const ctx = waitCtx();
    const res = await handle(new Request(`http://beamline/lookup?sha256=${HELLO_SHA}`), env, ctx.ctx);
    await ctx.flush();
    return res;
  };
  try {
    const first = await ask();
    assert.ok(first.headers.get("server-timing"), "the live reply should be timed");
    const second = await ask();
    if (second.headers.get("x-beamline-source") === "cache") {
      assert.equal(second.headers.get("server-timing"), null, "stale timings served as if fresh");
    }
  } finally {
    await backend.close();
  }
});

test("a pinned analysis is not answered by the cheap sources", async () => {
  // hopper holds a verdict and the index would serve it. Pinning says "measure
  // this worker", so neither may answer.
  const hopper = await mockBackend({
    bloom: "unknown",
    sample: () => ({ status: 200, sha: HELLO_SHA, body: envelope(HELLO_SHA, { eng: "from-hopper" }) }),
  });
  const worker = await mockBackend({
    bloom: "skip",
    verdict: () => envelope(HELLO_SHA, { eng: "from-index" }),
    analyze: () => envelope(HELLO_SHA, { eng: "from-worker" }),
  });
  const env = testEnv(hopper.url, { SCAN_URL: worker.url });
  const ctx = waitCtx();
  try {
    const res = await handle(
      new Request(`http://beamline/analyze?sha256=${HELLO_SHA}`, {
        method: "POST",
        body: HELLO,
        headers: { "x-beamline-pin": hostOf(worker.url) },
      }),
      env,
      ctx.ctx,
    );
    assert.equal((await res.json()).eng, "from-worker", "a pin that an index can answer measures nothing");
    assert.equal(res.headers.get("x-beamline-source"), "scan");
    await ctx.flush();
  } finally {
    await Promise.all([hopper.close(), worker.close()]);
  }
});

test("one unlucky sample does not brand a worker slow", async () => {
  const hopper = await mockBackend({ bloom: "unknown" });
  // Exactly the shape seen live after a restart: the fast worker had finished
  // one large archive, the other had a real history at a mediocre speed.
  const thin = await mockBackend({
    stats: statsFor({ ms: 33757, bySize: {}, avg_job_samples: 1, avg_job_ms_by_type: { pypi: { jobs: 1, avg_ms: 33757 } } }),
  });
  const settled = await mockBackend({
    stats: statsFor({ ms: 3038, bySize: {}, avg_job_samples: 6, avg_job_ms_by_type: { pypi: { jobs: 6, avg_ms: 3038 } } }),
  });
  const env = testEnv(hopper.url, { SCAN_URL: `${thin.url},${settled.url}` });
  try {
    const res = await handle(new Request("http://beamline/_/routes?type=pypi"), env, waitCtx().ctx);
    const [route] = (await res.json()).routes;
    const byWorker = Object.fromEntries(route.dispatch.map((d) => [d.worker, d.est_ms]));
    assert.equal(byWorker[hostOf(thin.url)], 5000, "n=1 was taken as evidence instead of falling back");
    assert.equal(byWorker[hostOf(settled.url)], 3038, "n=6 clears the bar and should be used");
  } finally {
    await Promise.all([hopper.close(), thin.close(), settled.close()]);
  }
});

test("a class average is used once it has enough completions behind it", async () => {
  const hopper = await mockBackend({ bloom: "unknown" });
  const w = await mockBackend({
    stats: statsFor({ ms: 9000, bySize: {}, avg_job_samples: 40, avg_job_ms_by_type: { golang: { jobs: 40, avg_ms: 25000 } } }),
  });
  const env = testEnv(hopper.url, { SCAN_URL: w.url });
  try {
    const golang = await (await handle(new Request("http://beamline/_/routes?type=golang"), env, waitCtx().ctx)).json();
    assert.equal(golang.routes[0].dispatch[0].est_ms, 25000, "a well-sampled class average must win");
    // npm has no history at all here, so it falls back to the blended average.
    const npm = await (await handle(new Request("http://beamline/_/routes?type=npm"), env, waitCtx().ctx)).json();
    assert.equal(npm.routes[0].dispatch[0].est_ms, 9000);
  } finally {
    await Promise.all([hopper.close(), w.close()]);
  }
});

test("an index probe is not predicted from an analysis average", async () => {
  const hopper = await mockBackend({ bloom: "unknown" });
  // Slow to analyze, fast to answer its index — the normal shape, and the two
  // must not be conflated: they differ by three orders of magnitude.
  const w = await mockBackend({
    stats: statsFor({ ms: 40000, avg_lookup_us: 900, lookup_samples: 500 }),
  });
  const env = testEnv(hopper.url, { SCAN_URL: w.url });
  try {
    const lookup = await (await handle(new Request("http://beamline/_/routes?type=lookup"), env, waitCtx().ctx)).json();
    assert.equal(lookup.routes[0].dispatch[0].est_ms, 1, "900us should read as ~1ms, not the 40s analysis average");
    const npm = await (await handle(new Request("http://beamline/_/routes?type=npm"), env, waitCtx().ctx)).json();
    assert.equal(npm.routes[0].dispatch[0].est_ms, 40000, "the analysis class still uses the analysis average");
  } finally {
    await Promise.all([hopper.close(), w.close()]);
  }
});

test("a worker that cannot be polled never outranks one that can", async () => {
  const hopper = await mockBackend({ bloom: "unknown" });
  // No /_/stats at all: it would score UNKNOWN_JOB_MS (5000) and beat an
  // honest 8000ms — being unreachable used to be a promotion.
  const silent = await mockBackend({});
  const honest = await mockBackend({ stats: statsFor({ ms: 8000 }) });
  const env = testEnv(hopper.url, { SCAN_URL: `${silent.url},${honest.url}` });
  try {
    const res = await handle(new Request("http://beamline/_/routes?type=npm"), env, waitCtx().ctx);
    const [route] = (await res.json()).routes;
    assert.equal(route.dispatch[0].worker, hostOf(honest.url), "silence outranked measurement");
    assert.equal(route.dispatch[1].worker, hostOf(silent.url));
  } finally {
    await Promise.all([hopper.close(), silent.close(), honest.close()]);
  }
});

test("a refusal promotes the next worker instead of waiting out its hedge", async () => {
  const hopper = await mockBackend({ bloom: "unknown", sample: () => ({ status: 404 }) });
  // The live shape: the favourite is small and instantly full, the next worker
  // has capacity. Its hedge is long, so waiting it out is the whole bug.
  const full = await mockBackend({
    bloom: "unknown",
    stats: statsFor({ slots: 6, free: 6, ms: 1000 }),
    analyzePurl: () => ({ status: 429, body: { error: "At capacity (6/6 active analyses)" } }),
  });
  const roomy = await mockBackend({
    bloom: "unknown",
    stats: statsFor({ slots: 64, free: 64, ms: 9000 }),
    analyzePurl: () => envelope(HELLO_SHA, { eng: "roomy" }),
  });
  const env = testEnv(hopper.url, {
    SCAN_URL: `${full.url},${roomy.url}`,
    // A hedge far longer than this test may take: if the promotion does not
    // work, the arm waits this out and the assertion below fails on time.
    SCAN_RACE_DELAY_MS: "10000",
    SCAN_RETRY_BASE_MS: "1",
  });
  const ctx = waitCtx();
  const started = Date.now();
  try {
    const res = await handle(
      new Request("http://beamline/analyze?purl=pkg%3Anpm%2Fleft-pad%401.3.0", { method: "POST" }),
      env,
      ctx.ctx,
    );
    assert.equal(res.status, 200);
    assert.equal((await res.json()).eng, "roomy");
    const took = Date.now() - started;
    assert.ok(took < 5000, `waited ${took}ms behind an instant refusal — the hedge was not cut short`);
    await ctx.flush();
  } finally {
    await Promise.all([hopper.close(), full.close(), roomy.close()]);
  }
});

test("a worker that is merely slow still gets its full hedge", async () => {
  const hopper = await mockBackend({ bloom: "unknown", sample: () => ({ status: 404 }) });
  // The counter-case: promotion must trigger on a refusal, not on slowness.
  // This worker answers correctly, just not instantly, and the second arm must
  // stay parked rather than duplicate the work.
  const slow = await mockBackend({
    bloom: "unknown",
    stats: statsFor({ ms: 1000 }),
    analyzePurl: async () => {
      await delay(150);
      return envelope(HELLO_SHA, { eng: "slow-but-fine" });
    },
  });
  const backup = await mockBackend({
    bloom: "unknown",
    stats: statsFor({ ms: 9000 }),
    analyzePurl: () => envelope(HELLO_SHA, { eng: "backup" }),
  });
  const env = testEnv(hopper.url, {
    SCAN_URL: `${slow.url},${backup.url}`,
    SCAN_RACE_DELAY_MS: "3000",
  });
  const ctx = waitCtx();
  try {
    const res = await handle(
      new Request("http://beamline/analyze?purl=pkg%3Anpm%2Fleft-pad%401.3.0", { method: "POST" }),
      env,
      ctx.ctx,
    );
    assert.equal((await res.json()).eng, "slow-but-fine");
    assert.equal(backup.hits.analyzePurl, 0, "a slow worker is not a failed one");
    await ctx.flush();
  } finally {
    await Promise.all([hopper.close(), slow.close(), backup.close()]);
  }
});

test("the estimate prefers a worker's windowed p80 over its lifetime mean", async () => {
  const hopper = await mockBackend({ bloom: "unknown" });
  // Both published. The mean is inflated by an incident the window has already
  // forgotten, which is the whole reason to prefer the window.
  const w = await mockBackend({
    stats: statsFor({
      ms: 200000,
      bySize: {},
      avg_job_ms_by_type: {
        npm: { jobs: 40, avg_ms: 200000, recent: { samples: 40, p80_ms: 9000, mean_ms: 7000 } },
      },
    }),
  });
  // A generous timeout so the ceiling does not clamp: this case is about the
  // 3x rule, and the clamp has its own test below.
  const env = testEnv(hopper.url, { SCAN_URL: w.url, SCAN_TIMEOUT_MS: "600000" });
  try {
    const res = await handle(new Request("http://beamline/_/routes?type=npm"), env, waitCtx().ctx);
    const [route] = (await res.json()).routes;
    assert.equal(route.dispatch[0].est_ms, 9000, "the lifetime mean should not win over a live window");
    // A stall detector, not a race: 3x the estimate, not a fraction of it.
    assert.equal(route.hedge_ms, 27000);
  } finally {
    await Promise.all([hopper.close(), w.close()]);
  }
});

test("a window with too few samples falls back to the mean", async () => {
  const hopper = await mockBackend({ bloom: "unknown" });
  const w = await mockBackend({
    stats: statsFor({
      ms: 5000,
      bySize: {},
      avg_job_ms_by_type: {
        npm: { jobs: 40, avg_ms: 4000, recent: { samples: 2, p80_ms: 90000, mean_ms: 90000 } },
      },
    }),
  });
  const env = testEnv(hopper.url, { SCAN_URL: w.url });
  try {
    const res = await handle(new Request("http://beamline/_/routes?type=npm"), env, waitCtx().ctx);
    const [route] = (await res.json()).routes;
    assert.equal(route.dispatch[0].est_ms, 4000, "two samples are not a distribution");
  } finally {
    await Promise.all([hopper.close(), w.close()]);
  }
});

test("a worker publishing no window still routes on its mean", async () => {
  const hopper = await mockBackend({ bloom: "unknown" });
  // An older scan build: no `recent` anywhere. It must stay routable.
  const old = await mockBackend({
    stats: statsFor({ ms: 6000, bySize: {}, avg_job_ms_by_type: { npm: { jobs: 40, avg_ms: 6000 } } }),
  });
  const env = testEnv(hopper.url, { SCAN_URL: old.url });
  try {
    const res = await handle(new Request("http://beamline/_/routes?type=npm"), env, waitCtx().ctx);
    const [route] = (await res.json()).routes;
    assert.equal(route.dispatch[0].est_ms, 6000);
    assert.equal(route.informed, true);
  } finally {
    await Promise.all([hopper.close(), old.close()]);
  }
});

test("the hedge ceiling scales with the scan timeout, not a fixed 20s", async () => {
  const hopper = await mockBackend({ bloom: "unknown" });
  // A very slow class: 3x its p80 is far past any fixed ceiling, so the clamp
  // is what decides. Tied to SCAN_TIMEOUT_MS it stays in scale with the work.
  const slow = await mockBackend({
    stats: statsFor({
      ms: 400000,
      bySize: {},
      avg_job_ms_by_type: { golang: { jobs: 40, avg_ms: 400000, recent: { samples: 40, p80_ms: 400000 } } },
    }),
  });
  const env = testEnv(hopper.url, { SCAN_URL: slow.url, SCAN_TIMEOUT_MS: "600000" });
  try {
    const res = await handle(new Request("http://beamline/_/routes?type=golang"), env, waitCtx().ctx);
    const [route] = (await res.json()).routes;
    // 3 * 400000 = 1.2M, clamped to half the 600s timeout.
    assert.equal(route.hedge_ms, 300000);
  } finally {
    await Promise.all([hopper.close(), slow.close()]);
  }
});

test("beamline reads the exact shape scan publishes", async () => {
  const hopper = await mockBackend({ bloom: "unknown" });
  // Verbatim from scan's recent_json(): {samples, p80_ms, mean_ms}. This is the
  // other half of the contract test in scan's job_bucket_recent_tests — a
  // rename on either side demotes routing back to lifetime means and nothing
  // else changes, so both sides pin the names.
  const w = await mockBackend({
    stats: {
      slots: 8,
      slots_free: 8,
      in_flight: 0,
      ready: true,
      overloaded: false,
      max_upload_mb: 100,
      avg_job_ms: 999999,
      avg_job_samples: 50,
      recent: { samples: 40, p80_ms: 4200, mean_ms: 3100 },
      recent_lookup: { samples: 500, p80_ms: 2, mean_ms: 1 },
      avg_job_ms_by_type: {
        npm: { jobs: 40, avg_ms: 999999, recent: { samples: 40, p80_ms: 7700, mean_ms: 5000 } },
      },
      avg_job_ms_by_size: {},
    },
  });
  const env = testEnv(hopper.url, { SCAN_URL: w.url, SCAN_TIMEOUT_MS: "600000" });
  try {
    const npm = await (await handle(new Request("http://beamline/_/routes?type=npm"), env, waitCtx().ctx)).json();
    assert.equal(npm.routes[0].dispatch[0].est_ms, 7700, "per-type window not read");

    const look = await (await handle(new Request("http://beamline/_/routes?type=lookup"), env, waitCtx().ctx)).json();
    assert.equal(look.routes[0].dispatch[0].est_ms, 2, "lookup window not read");

    // cargo has no per-type entry, so it falls back to the worker-wide window —
    // not to the 999999ms lifetime mean sitting right beside it.
    const cargo = await (await handle(new Request("http://beamline/_/routes?type=cargo"), env, waitCtx().ctx)).json();
    assert.equal(cargo.routes[0].dispatch[0].est_ms, 4200, "worker-wide window not read");
  } finally {
    await Promise.all([hopper.close(), w.close()]);
  }
});
