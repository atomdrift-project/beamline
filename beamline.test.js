import { createServer } from "node:http";
import { once } from "node:events";
import assert from "node:assert/strict";
import { afterEach, beforeEach, test } from "node:test";
import { handle, _test } from "./beamline.js";

const HELLO = new TextEncoder().encode("hello");
const HELLO_SHA = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";

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

test("TUNNEL.fetch is used for hopper when bound", async () => {
  const seen = [];
  const env = {
    HOPPER_URL: "http://hopper.internal:8081",
    SCAN_URL: "http://scan.internal:49999",
    cache: _test.memoryCache(),
    TUNNEL: {
      fetch(url) {
        const u = String(url);
        seen.push(u);
        const headers = { "content-type": "application/json" };
        if (u.includes("/_/bloom")) {
          return new Response(JSON.stringify({ decision: "unknown" }), { status: 200, headers });
        }
        if (u.includes("/api/sample")) {
          return new Response(JSON.stringify(envelope(HELLO_SHA)), { status: 200, headers });
        }
        return new Response("no", { status: 404 });
      },
    },
  };
  const res = await handle(new Request(`http://beamline/sha256/${HELLO_SHA}`), env, noopCtx());
  assert.equal(res.status, 200);
  assert.equal(res.headers.get("x-beamline-source"), "hopper");
  assert.ok(seen.some((u) => u.startsWith("http://hopper.internal:8081/api/sample/")));
  assert.ok(seen.some((u) => u.startsWith("http://scan.internal:49999/_/bloom")));
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

  const denied = await handle(new Request(`http://beamline/sha256/${HELLO_SHA}`), env, {});
  assert.equal(denied.status, 401);

  const wrong = await handle(
    new Request(`http://beamline/sha256/${HELLO_SHA}`, { headers: { authorization: "Bearer nope" } }),
    env,
    {},
  );
  assert.equal(wrong.status, 401);
});

test("accepted token is forwarded to hopper and scan", async () => {
  const scanned = envelope(HELLO_SHA, { eng: "scan" });
  const backend = await mockBackend({
    bloom: "unknown",
    sample: () => ({ status: 404 }),
    analyze: () => scanned,
  });
  const env = { ...testEnv(backend.url), BEAMLINE_TOKEN: "alpha,beta" };
  try {
    const res = await handle(
      new Request("http://beamline/", {
        method: "POST",
        headers: { authorization: "Bearer beta" },
        body: HELLO,
      }),
      env,
      waitCtx().ctx,
    );
    assert.equal(res.status, 200);
    const sent = backend.auths.map((a) => a.authorization);
    assert.ok(sent.length > 0);
    assert.ok(sent.every((h) => h === "Bearer beta"));
    const paths = backend.auths.map((a) => a.path);
    assert.ok(paths.some((p) => p === "/_/bloom"));
    assert.ok(paths.some((p) => p.startsWith("/api/sample")));
    assert.ok(paths.some((p) => p === "/analyze"));
  } finally {
    await backend.close();
  }
});

test("cache hit short-circuits bloom and hopper", async () => {
  const backend = await mockBackend({
    bloom: "unknown",
    sample: (sha) => ({ status: 200, sha, body: envelope(sha) }),
  });
  const env = testEnv(backend.url);
  const ctx = waitCtx();
  try {
    const first = await handle(new Request(`http://beamline/sha256/${HELLO_SHA}`), env, ctx.ctx);
    assert.equal(first.status, 200);
    assert.equal(first.headers.get("x-beamline-source"), "hopper");
    assert.equal(backend.hits.bloom, 1);
    assert.equal(backend.hits.sample, 1);
    await ctx.flush();

    const second = await handle(new Request(`http://beamline/sha256/${HELLO_SHA}`), env, noopCtx());
    assert.equal(second.status, 200);
    assert.equal(second.headers.get("x-beamline-source"), "cache");
    assert.equal(backend.hits.bloom, 1);
    assert.equal(backend.hits.sample, 1);
    assert.equal(backend.hits.analyze, 0);
  } finally {
    await backend.close();
  }
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
    const res = await handle(new Request(`http://beamline/sha256/${HELLO_SHA}`), env, noopCtx());
    assert.equal(res.status, 200);
    assert.equal(res.headers.get("x-beamline-source"), "bloom");
    const body = await res.json();
    assert.equal(body.lvl, -1);
    assert.equal(body.eng, "beamline");
    assert.equal(body.sha, HELLO_SHA);
    assert.equal(body.ml, undefined);
    assert.equal(body.raw, undefined);
    assert.equal(body.hits, undefined);
    assert.equal(backend.hits.sample, 0);
    assert.equal(backend.hits.analyze, 0);
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
    const res = await handle(new Request(`http://beamline/sha256/${HELLO_SHA}`), env, noopCtx());
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

test("hopper miss with body posts /analyze and submits /api/result", async () => {
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
      new Request("http://beamline/", { method: "POST", body: HELLO }),
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
    assert.equal(backend.hits.result, 1);
    assert.equal(backend.results[0].worker, "beamline");
    assert.equal(backend.results[0].sha256, HELLO_SHA);
  } finally {
    await backend.close();
  }
});

test("PURL miss posts /analyze-purl", async () => {
  const sha = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
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
      new Request("http://beamline/?purl=pkg:npm/left-pad@1.3.0"),
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
    assert.equal(backend.hits.result, 1);
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
    const res = await handle(new Request(`http://beamline/sha256/${HELLO_SHA}`), env, noopCtx());
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
      new Request("http://beamline/", { method: "POST", body: HELLO }),
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
      new Request("http://beamline/?purl=pkg:npm/left-pad@1.3.0"),
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
    const res = await handle(new Request(`http://beamline/sha256/${HELLO_SHA}`), env, noopCtx());
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
      new Request("http://beamline/?purl=pkg:npm/left-pad@1.3.0"),
      env,
      noopCtx(),
    );
    assert.equal(res.status, 503);
    assert.equal((await res.json()).error, "unavailable");
  } finally {
    await backend.close();
  }
});

test("bloom 404 does not disable /analyze", async () => {
  const scanned = envelope(HELLO_SHA, { eng: "scan" });
  const backend = await mockBackend({
    bloomStatus: 404,
    sample: () => ({ status: 404 }),
    analyze: () => scanned,
  });
  const env = testEnv(backend.url);
  try {
    const res = await handle(
      new Request("http://beamline/", { method: "POST", body: HELLO }),
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
      new Request("http://beamline/", { method: "POST", body: HELLO }),
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
    const res = await handle(new Request(`http://beamline/sha256/${HELLO_SHA}`), env, noopCtx());
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
    const res = await handle(new Request(`http://beamline/sha256/${HELLO_SHA}`), env, noopCtx());
    assert.equal(res.status, 202);
    assert.equal(res.headers.get("retry-after"), "5");
    assert.deepEqual(await res.json(), { state: "pending" });
  } finally {
    await backend.close();
  }
});

test("unknown route is 404 not found", async () => {
  const res = await handle(new Request("http://beamline/analyze"), {}, {});
  assert.equal(res.status, 404);
  assert.equal((await res.json()).error, "not found");
});

test("hopper miss without bytes is unknown sample", async () => {
  const backend = await mockBackend({
    bloom: "unknown",
    sample: () => ({ status: 404 }),
  });
  const env = testEnv(backend.url);
  try {
    const res = await handle(new Request(`http://beamline/sha256/${HELLO_SHA}`), env, noopCtx());
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
      new Request("http://beamline/", { method: "POST", body: HELLO }),
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
      new Request("http://beamline/", { method: "POST", body: HELLO }),
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
    assert.equal(abort && abort.target, "scan");
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
      new Request("http://beamline/", { method: "POST", body: HELLO }),
      env,
      ctx.ctx,
    );
    const ms = Date.now() - t0;
    assert.equal(res.status, 200);
    assert.equal(res.headers.get("x-beamline-source"), "scan");
    assert.equal((await res.json()).eng, "scan-hedge");
    assert.ok(ms < 300, `scan hedge took ${ms}ms; hopper should have been abandoned`);
    await ctx.flush();
    assert.equal(backend.hits.result, 1);
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
      new Request("http://beamline/", { method: "POST", body: HELLO }),
      env,
      waitCtx().ctx,
    );
    assert.equal(res.status, 200);
    assert.equal(res.headers.get("x-beamline-source"), "hopper");
    assert.equal(backend.hits.analyze, 0);
    assert.equal(backend.hits.analyzePurl, 0);
    assert.ok(!logs.rows.some((r) => r.event === "hedge"));
    assert.ok(!logs.rows.some((r) => r.event === "abort"));
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
      new Request("http://beamline/", { method: "POST", body: HELLO }),
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
      new Request("http://beamline/?purl=pkg:npm/left-pad@1.3.0"),
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
      new Request("http://beamline/?purl=pkg:npm/left-pad@1.3.0"),
      env,
      ctx.ctx,
    );
    assert.equal(res.status, 200);
    assert.equal(res.headers.get("x-beamline-source"), "scan");
    assert.equal((await res.json()).eng, "purl-hedge");
    assert.ok(Date.now() - t0 < 150);
    await ctx.flush();
    assert.equal(backend.hits.result, 1);
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
    const res = await handle(new Request(`http://beamline/sha256/${HELLO_SHA}`), env, ctx.ctx);
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
    const res = await handle(new Request(`http://beamline/sha256/${HELLO_SHA}`), env, ctx.ctx);
    assert.equal(res.status, 200);
    assert.equal(res.headers.get("x-beamline-source"), "scan");
    assert.equal((await res.json()).eng, "from-file");
    assert.ok(Date.now() - t0 < 150);
    await ctx.flush();
    assert.equal(backend.hits.file, 1);
    assert.equal(backend.hits.analyze, 1);
    assert.equal(backend.hits.result, 1);
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
      new Request("http://beamline/", { method: "POST", body: HELLO }),
      env,
      ctx.ctx,
    );
    assert.equal(res.status, 200);
    assert.equal(res.headers.get("x-beamline-source"), "scan");
    await ctx.flush();
    assert.equal(backend.hits.result, 1);
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
      new Request("http://beamline/", { method: "POST", body: HELLO }),
      env,
      ctx.ctx,
    );
    assert.equal(res.status, 200);
    assert.equal(res.headers.get("x-beamline-source"), "scan");
    await ctx.flush();
    assert.equal(backend.hits.upload, 0);
    assert.equal(backend.hits.result, 1);
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
    const res = await handle(new Request(`http://beamline/sha256/${HELLO_SHA}`), env, noopCtx());
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
      new Request("http://beamline/", { method: "POST", body: HELLO }),
      env,
      ctx.ctx,
    );
    assert.equal(first.headers.get("x-beamline-source"), "scan");
    await ctx.flush();
    const second = await handle(
      new Request(`http://beamline/sha256/${HELLO_SHA}`),
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
      new Request("http://beamline/", { method: "POST", body: HELLO }),
      env,
      ctx.ctx,
    );
    assert.equal(first.headers.get("x-beamline-source"), "hopper");
    await ctx.flush();
    const second = await handle(
      new Request(`http://beamline/sha256/${HELLO_SHA}`),
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
    const res = await handle(new Request(`http://beamline/sha256/${HELLO_SHA}`), env, noopCtx());
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
    const res = await handle(new Request(`http://beamline/sha256/${HELLO_SHA}`), env, ctx.ctx);
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
      new Request("http://beamline/", { method: "POST", body: HELLO }),
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
        new Request("http://beamline/", { method: "POST", body: HELLO }),
        { ...env, cache: _test.memoryCache() },
        ctx.ctx,
      );
      assert.equal(res.headers.get("x-beamline-source"), "scan");
      await ctx.flush();
    }
    const res = await handle(
      new Request(`http://beamline/sha256/${HELLO_SHA}`),
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
        new Request("http://beamline/", { method: "POST", body: HELLO }),
        { ...env, cache: _test.memoryCache() },
        ctx.ctx,
      );
      assert.equal(res.headers.get("x-beamline-source"), "hopper");
      await ctx.flush();
    }
    const ctx = waitCtx();
    const res = await handle(
      new Request("http://beamline/", { method: "POST", body: HELLO }),
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
      const res = await handle(new Request(`http://beamline/sha256/${HELLO_SHA}`), env, noopCtx());
      assert.equal(res.status, 503);
    }
    const before = backend.hits.sample;
    const res = await handle(new Request(`http://beamline/sha256/${HELLO_SHA}`), env, noopCtx());
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
      new Request("http://beamline/", { method: "POST", body: HELLO, signal: ac.signal }),
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
      handle(new Request("http://beamline/", { method: "POST", body: HELLO }), env, ctx.ctx),
      handle(new Request("http://beamline/", { method: "POST", body: HELLO }), env, ctx.ctx),
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
      new Request("http://beamline/", { method: "POST", body: HELLO }),
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
      new Request("http://beamline/", { method: "POST", body: HELLO }),
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
    const res = await handle(new Request("http://beamline/?purl=not-a-purl"), env, noopCtx());
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
      new Request("http://beamline/?purl=pkg:npm/left-pad@1.3.0"),
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
      new Request("http://beamline/?purl=pkg:npm/left-pad@1.3.0"),
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
      new Request("http://beamline/", { method: "POST", body: HELLO }),
      env,
      noopCtx(),
    );
    assert.equal(res.status, 503);
    assert.equal(backend.hits.rescan, 0);
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

test("gzip when the client asks", async () => {
  if (typeof CompressionStream !== "function" || typeof DecompressionStream !== "function") return;
  const stored = envelope(HELLO_SHA, { lvl: -1, eng: "hopper-only" });
  const backend = await mockBackend({
    bloom: "unknown",
    sample: () => ({ status: 200, sha: HELLO_SHA, body: stored }),
  });
  const env = testEnv(backend.url);
  try {
    const res = await handle(
      new Request(`http://beamline/sha256/${HELLO_SHA}`, { headers: { "accept-encoding": "gzip" } }),
      env,
      noopCtx(),
    );
    assert.equal(res.status, 200);
    assert.equal(res.headers.get("content-encoding"), "gzip");
    const body = await new Response(res.body.pipeThrough(new DecompressionStream("gzip"))).json();
    assert.equal(body.eng, "hopper-only");
    assert.equal(body.lvl, -1);
  } finally {
    await backend.close();
  }
});

function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function captureLogs() {
  const rows = [];
  const orig = console.log;
  console.log = (...args) => {
    const s = args[0];
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
    SCAN_TIMEOUT_MS: extra.SCAN_TIMEOUT_MS,
    HOPPER_HEDGE_MS: extra.HOPPER_HEDGE_MS,
    HOPPER_LOOKUP_MS: extra.HOPPER_LOOKUP_MS,
    cache: extra.cache ?? _test.memoryCache(),
  };
}

function noopCtx() {
  return { waitUntil() {} };
}

function waitCtx() {
  const jobs = [];
  return {
    ctx: {
      waitUntil(p) {
        jobs.push(Promise.resolve(p));
      },
    },
    flush() {
      return Promise.all(jobs);
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
  };
  const results = [];
  const auths = [];
  const server = createServer(async (req, res) => {
    try {
      const url = new URL(req.url || "/", "http://127.0.0.1");
      auths.push({ path: url.pathname, authorization: req.headers.authorization || "" });
      const body = await readReq(req);
      if (url.pathname === "/_/bloom") {
        hits.bloom += 1;
        const decision = typeof opts.bloom === "function" ? opts.bloom(url) : opts.bloom || "unknown";
        return send(res, opts.bloomStatus || 200, { decision });
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
        const out = opts.analyze ? await opts.analyze() : null;
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
