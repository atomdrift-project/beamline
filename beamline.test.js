import { createServer } from "node:http";
import { once } from "node:events";
import assert from "node:assert/strict";
import { afterEach, beforeEach, test } from "node:test";
import { handle, _test } from "./beamline.js";

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






test("/_/health answers alongside /healthz", async () => {
  const res = await handle(new Request("http://beamline/_/health"), {}, {});
  assert.equal(res.status, 200);
  assert.deepEqual(await res.json(), { status: "ok" });
});





const DEAD = "http://127.0.0.1:1";










test("unknown route is 404 and names the routes", async () => {
  const res = await handle(new Request("http://beamline/nope"), {}, {});
  assert.equal(res.status, 404);
  const { error } = await res.json();
  assert.equal(error.code, "no_such_route");
  assert.match(error.message, /\/v1\/lookup and \/v1\/analyze/);
});



// The mistake a first-time caller actually makes. `curl /lookup?purl=...` is
// the right question at the wrong path, and a bare "not found" sends them
// hunting for a misspelling that isn't there.
test("a dropped version prefix says so", async () => {
  for (const path of ["/lookup", "/analyze"]) {
    const res = await handle(new Request(`http://beamline${path}?purl=pkg:npm/x@1`), {}, {});
    assert.equal(res.status, 404);
    const { error } = await res.json();
    assert.equal(error.code, "no_such_route");
    assert.match(error.message, new RegExp(`Did you mean /v1${path}\\?`));
  }
});



test("query purl is not a route", async () => {
  const res = await handle(new Request("http://beamline/?purl=pkg:npm/left-pad@1.3.0"), {}, {});
  assert.equal(res.status, 404);
});



// Every knob is read from the environment at the point of use, so a typo in a
// deploy becomes a silently different timeout rather than a startup failure.
// The rule that keeps that survivable: anything unparseable falls back to the
// built-in default, and only a genuine number wins. Zero is a genuine number —
// it is how a knob gets turned off — while a negative one is a typo.
// A breaker that survives its own cooldown is a worker that never recovers: it
// needs five failures the first time and one thereafter, and the successes that
// would clear the count are exactly what the open breaker prevents.
test("a breaker gives a recovered worker its record back", async () => {
  const b = _test.makeBreaker();
  for (let i = 0; i < _test.BREAKER_FAILS; i++) b.fail();
  assert.equal(b.open(), true, "five failures should trip it");

  // Cool down. BREAKER_COOL_MS is 10s, so drive it through the same door a
  // caller would rather than sleeping: a fresh breaker cooled by construction.
  const c = _test.makeBreaker();
  for (let i = 0; i < _test.BREAKER_FAILS - 1; i++) c.fail();
  assert.equal(c.open(), false, "under the threshold is not tripped");
  c.ok();
  for (let i = 0; i < _test.BREAKER_FAILS - 1; i++) c.fail();
  assert.equal(c.open(), false, "a success cleared the count");
});



// A server's own counters describe the server, not the machine it is on.
//
// Measured on a 64-core node: slots=64, slots_free=64, in_flight=0 — and load1
// at 50, because a 16-worker puller and a batch scan were sharing the box.
// Every field the server reported was true and a router reading only those
// fields would have called it idle.
test("occupancy sees the machine, not just the server", () => {
  const cores = 64;
  const idleLooking = { slots: cores, slots_free: cores, in_flight: 0, load1: 50, physical_cpus: cores };
  assert.ok(
    _test.occupancy(idleLooking) > 0.7,
    `scored ${_test.occupancy(idleLooking)} for a node with 50 of 64 cores busy`,
  );

  // Its own work still counts when that is the larger of the two.
  const serving = { slots: 8, slots_free: 0, in_flight: 8, load1: 1, physical_cpus: 64 };
  assert.equal(_test.occupancy(serving), 1, "a full server is full");

  // Not added: the server's own analyses show up in load1 too, so summing
  // would charge for them twice.
  const both = { slots: 64, slots_free: 32, in_flight: 32, load1: 32, physical_cpus: 64 };
  assert.equal(_test.occupancy(both), 0.5, "the same work was counted twice");

  // A worker too old to report a core count contributes no host term rather
  // than a guess, and is still ranked on what it does report.
  const old = { slots: 16, slots_free: 8, in_flight: 8, load1: 40 };
  assert.equal(_test.occupancy(old), 0.5);
  // And an idle one is idle.
  assert.equal(_test.occupancy({ slots: 16, slots_free: 16, in_flight: 0, load1: 0, physical_cpus: 16 }), 0);
});



// Busy and broken wear the same answer and are not the same claim.
//
// A worker that refuses has told us it has capacity and is using it; a slot
// will free. The old budget gave up after five attempts — about 30 seconds —
// while an analysis runs 8s at p50 and 53s at p90, so a saturated fleet was
// reported as "we could not find out" about work nobody had refused on its
// merits.
test("a fleet that is merely full is waited on, not given up on", async () => {
  let refusals = 0;
  const worker = await mockBackend({
    status: { state: "unknown" },
    analyzeStatus: () => (++refusals <= 8 ? 429 : 200),
    analyzeStream: ['{"decision":"allow","fires_at":-1,"purl":"pkg:npm/busy@1.0.0"}'],
  });
  // SCAN_RETRIES is 5, so eight refusals outlast the old budget entirely.
  const env = testEnv(DEAD, { SCAN_URL: worker.url, SCAN_RETRY_BASE_MS: "1", SCAN_TIMEOUT_MS: "600000" });
  try {
    const res = await handle(
      new Request("http://beamline/v1/analyze?purl=pkg%3Anpm%2Fbusy%401.0.0", { method: "POST" }),
      env,
      waitCtx().ctx,
    );
    const decided = JSON.parse((await res.text()).trim().split("\n").pop());
    assert.equal(decided.decision, "allow", "gave up on a fleet that was only busy");
    assert.ok(refusals > _test.BREAKER_FAILS, `only ${refusals} refusals; the budget did not stretch`);
  } finally {
    await worker.close();
  }
});



// And a refusal is not a fault: a worker answering "at capacity" promptly and
// correctly is the opposite of what a breaker exists to detect. Counting it
// took healthy workers out of the pool exactly when the fleet could least
// afford to lose them.
test("being at capacity does not trip a worker's breaker", async () => {
  const full = await mockBackend({ status: { state: "unknown" }, analyzeStatus: 429 });
  const env = testEnv(DEAD, { SCAN_URL: full.url, SCAN_RETRY_BASE_MS: "1", SCAN_TIMEOUT_MS: "1" });
  try {
    await handle(
      new Request("http://beamline/v1/analyze?purl=pkg%3Anpm%2Fbusy%401.0.0", { method: "POST" }),
      env,
      waitCtx().ctx,
    );
    assert.equal(
      _test.breakerFor(full.url).open(),
      false,
      "a busy worker was recorded as a broken one",
    );
  } finally {
    await full.close();
  }
});



// A worker with two lookups behind it must still be reachable.
//
// Measured in production after a fleet restart: a worker reporting a real 71ms
// lookup average was estimated at 1326ms — its *analysis* average, reached by a
// fallback chain that walked past the guard saying never to do that — and a
// worker with no history at all at a flat 5000ms. Against a 116ms incumbent
// neither could ever win, so neither was ever asked, so neither ever gathered
// the samples that would have corrected it. 400 of 400 lookups went to the
// slower worker.
test("a thin lookup average still beats an analysis average", () => {
  const thin = { lookup_samples: 2, avg_lookup_ms: 71, recent: { samples: 40, p80_ms: 1326 }, avg_job_ms: 1326 };
  const settled = { lookup_samples: 200, avg_lookup_ms: 86, recent_lookup: { samples: 779, p80_ms: 116 } };
  const mix = _test.jobMix([thin, settled]);
  const hint = { lookup: true };

  const thinEst = _test.predictMs(thin, hint, mix);
  assert.ok(thinEst < 200, `predicted ${thinEst}ms for a worker measuring 71ms`);
  assert.ok(
    thinEst < _test.predictMs(settled, hint, mix),
    "the faster worker has to be able to win, or it never gets a sixth sample",
  );

  // Thin, though, is not trusted: it ranks, but it does not earn the jitter
  // that damps herding between workers we actually have evidence for.
  assert.equal(_test.hasHistory(thin, hint, mix), false);
  assert.equal(_test.hasHistory(settled, hint, mix), true);

  // And with nothing measured at all, a lookup still must not be priced from
  // an analysis average.
  const none = { recent: { samples: 40, p80_ms: 9000 }, avg_job_ms: 9000, avg_job_samples: 40 };
  assert.equal(_test.predictMs(none, hint, mix), _test.UNKNOWN_JOB_MS);
});



// The tie band decides when two workers are close enough that picking the
// nominally-faster one is noise-chasing, and jitter should break the tie
// instead. A flat 250ms was a fair description of that for analyses and wider
// than the whole dynamic range of a lookup, so every pair of lookups tied and
// the ranking became a coin toss. Measured live: estimates of 29ms, 57ms and
// 105ms dispatched slowest-but-one first.
test("a tie is proportional to what is being compared", () => {
  // Lookups: tens of milliseconds, and the differences are real.
  assert.equal(_test.tiedEst(29, 57), false, "2x is not a tie");
  assert.equal(_test.tiedEst(57, 105), false);
  assert.equal(_test.tiedEst(95, 100), true, "5% is noise");

  // Analyses: seconds, where 250ms really is a tie and the band stays there.
  assert.equal(_test.tiedEst(8000, 8100), true, "100ms in 8s is a tie");
  assert.equal(_test.tiedEst(3000, 8000), false, "but 5s is not");

  // The band narrows for small estimates and never widens for large ones. A
  // 1000ms gap between two ~18s analyses is the capacity term deciding the
  // route, not noise — widening the band there would discard it.
  assert.equal(_test.tiedEst(18375, 19375), false, "the capacity term must survive");
});



// Never the configured order: that sent 390 of 390 lookups to the slowest
// worker in the fleet while the fastest sat idle.
test("an unranked lookup still moves around the fleet", () => {
  const fleet = ["https://a.test", "https://b.test", "https://c.test"];
  const firsts = new Set();
  for (let i = 0; i < fleet.length; i++) firsts.add(_test.rotate(fleet)[0]);
  assert.equal(firsts.size, fleet.length, "every worker leads once per cycle");
  // And it is a rotation, not a shuffle: the whole fleet stays in the list, so
  // a failed leader still falls through to the others.
  assert.deepEqual([..._test.rotate(fleet)].sort(), [...fleet].sort());
});



// A breaker steers traffic to a healthier worker. When every worker is tripped
// there is no healthier worker and nothing left to steer, so emptying the pool
// stops being caution and becomes an outage we caused ourselves.
//
// Measured: a burst of lookups ran past the timeout, tripped all three workers
// inside the first second, and the next 392 requests were answered
// `unavailable` in 25ms each without one outbound fetch. The fleet was healthy
// the whole time.
test("a fleet of tripped workers is still a fleet", () => {
  const env = { SCAN_URL: "https://a.test,https://b.test,https://c.test" };
  const all = _test.scanWorkers(env);
  assert.equal(all.length, 3);

  // One sick worker is what a breaker is for: the other two take the traffic.
  for (let i = 0; i < _test.BREAKER_FAILS; i++) _test.breakerFor("https://b.test").fail();
  assert.deepEqual(_test.scanWorkers(env), ["https://a.test", "https://c.test"]);

  // All three tripped is not a reason to ask nobody.
  for (const base of ["https://a.test", "https://c.test"]) {
    for (let i = 0; i < _test.BREAKER_FAILS; i++) _test.breakerFor(base).fail();
  }
  assert.equal(
    _test.scanWorkers(env).length,
    3,
    "an empty pool answers unavailable without having asked anyone",
  );
});



// The budget has to exceed the longest a healthy worker can legitimately take,
// which scan sets, not us: it allows each corpus address 2s before trying the
// next, so a worker with a replica down spends two seconds before it starts
// reading. A tighter budget records that as a broken worker.
test("a worker gets longer to answer than scan gives its corpus", () => {
  const SCAN_CORPUS_READ_TIMEOUT_MS = 2_000;
  assert.ok(
    _test.LOOKUP_TIMEOUT_MS > SCAN_CORPUS_READ_TIMEOUT_MS,
    `${_test.LOOKUP_TIMEOUT_MS}ms does not cover scan's ${SCAN_CORPUS_READ_TIMEOUT_MS}ms corpus read`,
  );
});



test("numEnv keeps a bad knob from becoming a bad default", () => {
  const k = "SCAN_TIMEOUT_MS";
  assert.equal(_test.numEnv({}, k, 1000), 1000);
  assert.equal(_test.numEnv({ [k]: "" }, k, 1000), 1000);
  assert.equal(_test.numEnv({ [k]: "nope" }, k, 1000), 1000);
  assert.equal(_test.numEnv({ [k]: "-1" }, k, 1000), 1000);
  assert.equal(_test.numEnv({ [k]: "0" }, k, 1000), 0);
  assert.equal(_test.numEnv({ [k]: "20" }, k, 1000), 20);
  assert.equal(_test.BREAKER_FAILS, 5);
});






















// A caller whose connection drops has not withdrawn the question. Beamline
// hands the analysis to waitUntil precisely so it outlives them, so whoever
// asks next should join the work already running rather than pay for it a
// second time. Scan charges by the analysis and the slow ones run for minutes:
// restarting one because a laptop shut its lid is the difference between a
// reconnect that costs nothing and one that costs the whole job again — and
// the reconnecting caller must never inherit the first caller's cancellation.
// The edge stops waiting on an origin at 125s and answers 524, but scan keeps
// going: it files the verdict and serves the next caller from its index. That
// is the only reason an analysis can outlive the ceiling, and it is measured —
// two direct requests were cut at 125.18s while the worker ran on past 345s.
// A 524 must therefore never reach a caller as a 5xx.
// A 524 says the sample was slow, not that the worker is sick. Counting it
// would open the breaker of whichever worker drew the heaviest samples first,
// and a fleet-wide slow patch would take every worker out at once — the same
// inversion that 429 caused before it was excluded.


// The wait is bounded by the caller's budget, not handed a fresh one at every
// ceiling: a worker that never files a verdict must still give up and say so.

// The reconnect guarantee across isolates. Beamline's own single-flight lives
// in one isolate, and a caller who reconnects usually lands in another — so the
// only thing that knows an analysis is already running is the worker running
// it. Scan attaches a second request for the same key to the run in progress,
// which makes the reconnect free, but only if it arrives at that worker.

// Affinity is a preference, not a pin. A run we cannot reach is not worth
// waiting for, so a worker whose breaker is open must not capture the request.

// --- /v1/analyze --------------------------------------------------------

// The body is passed through untouched. Buffering it to hand back one tidy
// object would put the silence back on the hop between us and the caller —
// the hop with a proxy we do not control on it, and the one this whole design
// exists to keep talking.
test("v1 analyze: progress reaches the caller, not just the decision", async () => {
  const scan = await mockBackend({
    analyzeStream: [
      '{"state":"analyzing","purl":"pkg:npm/evil@1.0.0","elapsed_ms":1002,"phase":"unpack"}',
      '{"state":"analyzing","purl":"pkg:npm/evil@1.0.0","elapsed_ms":6004,"phase":"features+model"}',
      '{"decision":"block","fires_at":3,"purl":"pkg:npm/evil@1.0.0"}',
    ],
  });
  const env = testEnv(DEAD, { SCAN_URL: scan.url });
  try {
    const res = await handle(
      new Request("http://beamline/v1/analyze?purl=pkg%3Anpm%2Fevil%401.0.0", { method: "POST" }),
      env,
      waitCtx().ctx,
    );
    assert.equal(res.status, 200);
    assert.equal(res.headers.get("content-type"), "application/x-ndjson");
    const lines = (await res.text()).trim().split("\n");
    assert.equal(lines.length, 3, "the caller was handed only the answer, not the run");
    assert.equal(JSON.parse(lines[0]).phase, "unpack");
    assert.equal(JSON.parse(lines[2]).decision, "block");
  } finally {
    await scan.close();
  }
});

// Scan refuses before it streams, which is what keeps a refusal something to
// route around: nothing has reached the caller yet, so the work can still go
// somewhere that will take it.
test("v1 analyze: a busy worker is routed around before any byte is sent", async () => {
  const busy = await mockBackend({ analyzeStatus: 429 });
  const free = await mockBackend({
    analyzeStream: ['{"decision":"allow","fires_at":-1,"purl":"pkg:npm/fine@1.0.0"}'],
  });
  const env = testEnv(DEAD, { SCAN_URL: `${busy.url},${free.url}` });
  try {
    const res = await handle(
      new Request("http://beamline/v1/analyze?purl=pkg%3Anpm%2Ffine%401.0.0", { method: "POST" }),
      env,
      waitCtx().ctx,
    );
    assert.equal(res.status, 200);
    assert.equal(JSON.parse((await res.text()).trim()).decision, "allow");
    assert.ok(busy.hits.analyze > 0, "the busy worker was never asked");
  } finally {
    await Promise.all([busy.close(), free.close()]);
  }
});

// Analyzing warms the cache the cheap route reads: the verdict a run just
// produced is exactly what the next lookup wants, and it should not have to ask
// a worker for it.
test("v1 analyze: the decision lands where /v1/lookup will find it", async () => {
  const scan = await mockBackend({
    analyzeStream: [
      '{"state":"analyzing","purl":"pkg:npm/evil@1.0.0","elapsed_ms":1002,"phase":"unpack"}',
      '{"decision":"block","fires_at":3,"purl":"pkg:npm/evil@1.0.0"}',
    ],
    v1: () => ({ decision: "unknown", purl: "pkg:npm/evil@1.0.0", sha256: null, severity: null, fires_at: null, reason: null, findings: [], engine_version: null, analyzed_at: null }),
  });
  const env = testEnv(DEAD, { SCAN_URL: scan.url });
  const ctx = waitCtx();
  try {
    const analyzed = await handle(
      new Request("http://beamline/v1/analyze?purl=pkg%3Anpm%2Fevil%401.0.0", { method: "POST" }),
      env,
      ctx.ctx,
    );
    await analyzed.text();
    await ctx.flush();

    const looked = await handle(
      new Request("http://beamline/v1/lookup?purl=pkg%3Anpm%2Fevil%401.0.0"),
      env,
      waitCtx().ctx,
    );
    assert.equal(looked.headers.get("x-beamline-source"), "cache", "the fresh verdict was not cached");
    assert.equal((await looked.json()).decision, "block", "the lookup did not see what the analysis found");
  } finally {
    await scan.close();
  }
});

// A stream that ends without a decision was cut short. Caching it would turn
// one dropped connection into a wrong answer served from the edge for an hour.
test("v1 analyze: a truncated stream is not cached", async () => {
  const scan = await mockBackend({
    analyzeStream: ['{"state":"analyzing","purl":"pkg:npm/half@1.0.0","elapsed_ms":1002,"phase":"unpack"}'],
    v1: () => ({ decision: "unknown", purl: "pkg:npm/half@1.0.0", sha256: null, severity: null, fires_at: null, reason: null, findings: [], engine_version: null, analyzed_at: null }),
  });
  const env = testEnv(DEAD, { SCAN_URL: scan.url });
  const ctx = waitCtx();
  try {
    const analyzed = await handle(
      new Request("http://beamline/v1/analyze?purl=pkg%3Anpm%2Fhalf%401.0.0", { method: "POST" }),
      env,
      ctx.ctx,
    );
    await analyzed.text();
    await ctx.flush();

    const looked = await handle(
      new Request("http://beamline/v1/lookup?purl=pkg%3Anpm%2Fhalf%401.0.0"),
      env,
      waitCtx().ctx,
    );
    assert.notEqual(looked.headers.get("x-beamline-source"), "cache", "half an answer was cached as a whole one");
  } finally {
    await scan.close();
  }
});

// The warm-write shipped carrying `cache-control: private`, which Cloudflare
// will not store, so the whole cache-warming path did nothing in production
// for as long as it existed. Every test passed: none of them set a token, and
// without one the scope is `public` and the write lands. The token is the
// entire point of this test — measured against the live service, three
// consecutive analyses of pkg:cargo/tokio@1.40.0 each re-derived a verdict
// that was supposed to already be cached.
test("v1 analyze: the decision is cached on a token-protected deployment too", async () => {
  const scan = await mockBackend({
    analyzeStream: ['{"decision":"block","fires_at":3,"purl":"pkg:npm/evil@1.0.0"}'],
    v1: () => ({ decision: "unknown", purl: "pkg:npm/evil@1.0.0", sha256: null, severity: null, fires_at: null, reason: null, findings: [], engine_version: null, analyzed_at: null }),
  });
  const env = testEnv(DEAD, { SCAN_URL: scan.url, BEAMLINE_TOKEN: "s3cret" });
  const auth = { authorization: "Bearer s3cret" };
  const ctx = waitCtx();
  try {
    const analyzed = await handle(
      new Request("http://beamline/v1/analyze?purl=pkg%3Anpm%2Fevil%401.0.0", { method: "POST", headers: auth }),
      env,
      ctx.ctx,
    );
    await analyzed.text();
    await ctx.flush();

    const looked = await handle(
      new Request("http://beamline/v1/lookup?purl=pkg%3Anpm%2Fevil%401.0.0", { headers: auth }),
      env,
      waitCtx().ctx,
    );
    assert.equal(looked.headers.get("x-beamline-source"), "cache", "a private answer was never stored");
    assert.match(looked.headers.get("cache-control"), /^private/, "the client copy lost its scope");
    assert.equal((await looked.json()).decision, "block");
  } finally {
    await scan.close();
  }
});

// /v1/analyze is the expensive door into the question /v1/lookup asks cheaply.
// Asking it twice for the same package used to cost two full analyses, because
// nothing on the path ever looked at the cache the first one had warmed.
test("v1 analyze: a verdict already cached is answered without a second analysis", async () => {
  const scan = await mockBackend({
    analyzeStream: ['{"decision":"block","fires_at":3,"purl":"pkg:npm/evil@1.0.0"}'],
    v1: () => ({ decision: "unknown", purl: "pkg:npm/evil@1.0.0", sha256: null, severity: null, fires_at: null, reason: null, findings: [], engine_version: null, analyzed_at: null }),
  });
  const env = testEnv(DEAD, { SCAN_URL: scan.url });
  const ask = () =>
    new Request("http://beamline/v1/analyze?purl=pkg%3Anpm%2Fevil%401.0.0", { method: "POST" });
  const ctx = waitCtx();
  try {
    await (await handle(ask(), env, ctx.ctx)).text();
    await ctx.flush();
    assert.equal(scan.hits.analyze, 1, "precondition: the first ask analysed");

    const again = await handle(ask(), env, waitCtx().ctx);
    const body = await again.text();
    assert.equal(scan.hits.analyze, 1, "the cached verdict was re-analysed anyway");
    assert.equal(again.headers.get("x-beamline-source"), "cache");
    assert.equal(again.headers.get("content-type"), "application/x-ndjson");
    assert.equal(JSON.parse(body.trim()).decision, "block", "the cached answer was not the verdict");
    assert.equal(body.endsWith("\n"), true, "an NDJSON answer must end its line");
  } finally {
    await scan.close();
  }
});

// `unknown` is cacheable — briefly, and for the lookup's benefit — and it is
// not an analysis. Serving it here would answer "nobody has analyzed this" to
// a caller who just asked us to analyze it.
test("v1 analyze: a cached `unknown` is not an answer to `analyze`", async () => {
  const scan = await mockBackend({
    analyzeStream: ['{"decision":"allow","fires_at":-1,"purl":"pkg:npm/fresh@1.0.0"}'],
    v1: () => ({ decision: "unknown", purl: "pkg:npm/fresh@1.0.0", sha256: null, severity: null, fires_at: null, reason: null, findings: [], engine_version: null, analyzed_at: null }),
  });
  const env = testEnv(DEAD, { SCAN_URL: scan.url });
  const ctx = waitCtx();
  try {
    await (await handle(
      new Request("http://beamline/v1/lookup?purl=pkg%3Anpm%2Ffresh%401.0.0"),
      env,
      ctx.ctx,
    )).text();
    await ctx.flush();
    const warm = await handle(
      new Request("http://beamline/v1/lookup?purl=pkg%3Anpm%2Ffresh%401.0.0"),
      env,
      noopCtx(),
    );
    assert.equal(warm.headers.get("x-beamline-source"), "cache", "precondition: the unknown was cached");

    const analyzed = await handle(
      new Request("http://beamline/v1/analyze?purl=pkg%3Anpm%2Ffresh%401.0.0", { method: "POST" }),
      env,
      waitCtx().ctx,
    );
    const body = await analyzed.text();
    assert.equal(scan.hits.analyze, 1, "a cached `unknown` was served instead of analysing");
    assert.equal(JSON.parse(body.trim()).decision, "allow");
  } finally {
    await scan.close();
  }
});

// An upload is a request to analyze *those bytes*. The PURL riding along with
// one names provenance, not the thing being asked about, so a verdict cached
// under it cannot stand in for the artifact in hand.
test("v1 analyze: an upload is analysed even when its PURL has a cached verdict", async () => {
  const scan = await mockBackend({
    analyzeStream: ['{"decision":"block","fires_at":3,"purl":"pkg:npm/evil@1.0.0"}'],
    v1: () => ({ decision: "unknown", purl: "pkg:npm/evil@1.0.0", sha256: null, severity: null, fires_at: null, reason: null, findings: [], engine_version: null, analyzed_at: null }),
  });
  const env = testEnv(DEAD, { SCAN_URL: scan.url });
  const ctx = waitCtx();
  try {
    await (await handle(
      new Request("http://beamline/v1/analyze?purl=pkg%3Anpm%2Fevil%401.0.0", { method: "POST" }),
      env,
      ctx.ctx,
    )).text();
    await ctx.flush();
    assert.equal(scan.hits.analyze, 1, "precondition: the PURL was analysed once");

    const uploaded = await handle(
      new Request("http://beamline/v1/analyze?purl=pkg%3Anpm%2Fevil%401.0.0", {
        method: "POST",
        body: "these bytes are not that package",
      }),
      env,
      waitCtx().ctx,
    );
    await uploaded.text();
    assert.equal(scan.hits.analyze, 2, "an upload was answered from a cache keyed by its PURL");
  } finally {
    await scan.close();
  }
});

// A decision names the artifact it resolved to, and a caller may well ask by
// that digest next — a lockfile pins a hash, a scanner reports one. Storing
// only the PURL key left `/v1/lookup?sha256=…` cold for an answer already in
// hand, and paid for a second analysis to learn it again.
test("v1 analyze: the decision is cached under its digest as well as its PURL", async () => {
  const sha = "a1b2c3d4".repeat(8);
  const scan = await mockBackend({
    analyzeStream: [`{"decision":"block","fires_at":3,"purl":"pkg:npm/evil@1.0.0","sha256":"${sha}"}`],
    v1: () => ({ decision: "unknown", purl: "pkg:npm/evil@1.0.0", sha256: null, severity: null, fires_at: null, reason: null, findings: [], engine_version: null, analyzed_at: null }),
  });
  const env = testEnv(DEAD, { SCAN_URL: scan.url });
  const ctx = waitCtx();
  try {
    await (await handle(
      new Request("http://beamline/v1/analyze?purl=pkg%3Anpm%2Fevil%401.0.0", { method: "POST" }),
      env,
      ctx.ctx,
    )).text();
    await ctx.flush();
    const analyses = scan.hits.analyze;

    const bySha = await handle(
      new Request(`http://beamline/v1/lookup?sha256=${sha}`),
      env,
      waitCtx().ctx,
    );
    assert.equal(bySha.headers.get("x-beamline-source"), "cache", "the digest key was never warmed");
    assert.equal((await bySha.json()).decision, "block");

    // The digest key is an addition, not a replacement.
    const byPurl = await handle(
      new Request("http://beamline/v1/lookup?purl=pkg%3Anpm%2Fevil%401.0.0"),
      env,
      waitCtx().ctx,
    );
    assert.equal(byPurl.headers.get("x-beamline-source"), "cache", "warming the digest key cost the PURL key");
    assert.equal(scan.hits.analyze, analyses, "a lookup spent an analysis");
  } finally {
    await scan.close();
  }
});

// A decision with no digest still warms the key it does have. Nothing about a
// missing `sha256` makes the PURL answer less true.
test("v1 analyze: a decision naming no digest still caches under its PURL", async () => {
  const scan = await mockBackend({
    analyzeStream: ['{"decision":"allow","fires_at":-1,"purl":"pkg:npm/evil@1.0.0","sha256":null}'],
    v1: () => ({ decision: "unknown", purl: "pkg:npm/evil@1.0.0", sha256: null, severity: null, fires_at: null, reason: null, findings: [], engine_version: null, analyzed_at: null }),
  });
  const env = testEnv(DEAD, { SCAN_URL: scan.url });
  const ctx = waitCtx();
  try {
    await (await handle(
      new Request("http://beamline/v1/analyze?purl=pkg%3Anpm%2Fevil%401.0.0", { method: "POST" }),
      env,
      ctx.ctx,
    )).text();
    await ctx.flush();
    const looked = await handle(
      new Request("http://beamline/v1/lookup?purl=pkg%3Anpm%2Fevil%401.0.0"),
      env,
      waitCtx().ctx,
    );
    assert.equal(looked.headers.get("x-beamline-source"), "cache", "a digestless decision was not cached at all");
    assert.equal((await looked.json()).decision, "allow");
  } finally {
    await scan.close();
  }
});

// The TTL a caller is told is derived from the answer, never read back from
// the cache. Measured on api.isotope13.ai: an entry written `max-age=60` reads
// back `max-age=14400`, because the zone's edge TTL overrides the worker's. Our
// own eviction still honours the 60s, so the effect was purely to tell callers
// to hold a one-minute answer for four hours.
test("v1: a cached answer carries the TTL its own content earns", async () => {
  const scan = await mockBackend({
    v1: () => ({
      decision: "unknown", purl: "pkg:npm/nobody@1.0.0", sha256: null, severity: null,
      fires_at: null, reason: null, findings: [], engine_version: null, analyzed_at: null,
    }),
  });
  // A cache that rewrites cache-control on the way in, the way the zone does.
  const inner = _test.memoryCache();
  const env = testEnv(DEAD, {
    SCAN_URL: scan.url,
    cache: {
      match: (req) => inner.match(req),
      put: (req, res) => {
        const copy = new Response(res.body, res);
        copy.headers.set("cache-control", "public, max-age=14400");
        return inner.put(req, copy);
      },
    },
  });
  const ctx = waitCtx();
  try {
    const fresh = await handle(
      new Request("http://beamline/v1/lookup?purl=pkg%3Anpm%2Fnobody%401.0.0"),
      env,
      ctx.ctx,
    );
    assert.match(fresh.headers.get("cache-control"), /max-age=60/, "an unknown must go out short-lived");
    await fresh.text();
    await ctx.flush();

    const cached = await handle(
      new Request("http://beamline/v1/lookup?purl=pkg%3Anpm%2Fnobody%401.0.0"),
      env,
      noopCtx(),
    );
    assert.equal(cached.headers.get("x-beamline-source"), "cache", "precondition: the answer was cached");
    assert.match(
      cached.headers.get("cache-control"),
      /max-age=60/,
      "the caller was handed the cache's TTL instead of the answer's",
    );
  } finally {
    await scan.close();
  }
});

// A worker mid-analysis attaches a second request for the same key to the run
// already going, so a caller who reconnected belongs back on it. Anywhere else
// pays for the whole analysis a second time — which on the samples this matters
// for is twenty minutes of a slot.
test("v1 analyze: a reconnect is sent back to the worker already running it", async () => {
  const idle = await mockBackend({
    status: { state: "unknown" },
    analyzeStream: ['{"decision":"allow","fires_at":-1,"purl":"pkg:npm/slow@1.0.0"}'],
  });
  const busy = await mockBackend({
    status: { state: "running", elapsed_ms: 143_000, attached: 0 },
    analyzeStream: ['{"decision":"block","fires_at":3,"purl":"pkg:npm/slow@1.0.0","reason":"x"}'],
  });
  const env = testEnv(DEAD, { SCAN_URL: `${idle.url},${busy.url}` });
  try {
    const res = await handle(
      new Request("http://beamline/v1/analyze?purl=pkg%3Anpm%2Fslow%401.0.0", { method: "POST" }),
      env,
      waitCtx().ctx,
    );
    assert.equal(JSON.parse((await res.text()).trim()).decision, "block", "the reconnect started a second analysis");
    assert.equal(idle.hits.analyze, 0, "a duplicate analysis was dispatched to an idle worker");
  } finally {
    await Promise.all([idle.close(), busy.close()]);
  }
});

// A fleet with every slot full is busy, not broken: scan refuses the instant a
// slot is asked for, so nothing has been attempted at length. Answering
// "we could not find out" on the first refusal would report an outage for a
// question we never really put.
test("v1 analyze: a fully busy fleet is asked again rather than given up on", async () => {
  let asked = 0;
  const worker = await mockBackend({
    status: { state: "unknown" },
    analyzeStatus: () => (++asked < 3 ? 429 : 200),
    analyzeStream: ['{"decision":"allow","fires_at":-1,"purl":"pkg:npm/busy@1.0.0"}'],
  });
  const env = testEnv(DEAD, { SCAN_URL: worker.url, SCAN_RETRY_BASE_MS: "5" });
  try {
    const res = await handle(
      new Request("http://beamline/v1/analyze?purl=pkg%3Anpm%2Fbusy%401.0.0", { method: "POST" }),
      env,
      waitCtx().ctx,
    );
    assert.equal(JSON.parse((await res.text()).trim()).decision, "allow", "gave up while the fleet was merely busy");
    assert.ok(asked >= 3, `asked ${asked} times, want a retry after each refusal`);
  } finally {
    await worker.close();
  }
});

test("v1 analyze: every worker down answers unavailable, not an error", async () => {
  const env = testEnv(DEAD, { SCAN_URL: DEAD });
  const res = await handle(
    new Request("http://beamline/v1/analyze?purl=pkg%3Anpm%2Fx%401.0.0", { method: "POST" }),
    env,
    waitCtx().ctx,
  );
  assert.equal(res.status, 200);
  assert.equal(JSON.parse((await res.text()).trim()).decision, "unavailable");
});

test("v1 analyze: naming nothing is refused, and the route is POST only", async () => {
  const env = testEnv(DEAD, { SCAN_URL: DEAD });
  const bare = await handle(
    new Request("http://beamline/v1/analyze", { method: "POST" }),
    env,
    waitCtx().ctx,
  );
  assert.equal(bare.status, 400);
  assert.equal((await bare.json()).error.code, "missing_package");

  const wrong = await handle(
    new Request("http://beamline/v1/analyze?purl=x"),
    env,
    waitCtx().ctx,
  );
  assert.equal(wrong.status, 405);
});

// --- /v1/lookup ---------------------------------------------------------
//
// Beamline's job on this route is the edge: authenticate, cache, pick a worker.
// It asks no second source and reconciles nothing, because scan answers the
// question completely now — a worker that misses its own index asks the corpus
// itself.

// Every worker down must not be a 5xx. The caller asked what we know about some
// packages, and "we could not find out" is an answer about each of them — one
// their policy may treat differently from "nobody has analyzed this". A 503
// collapses those two, and a client that catches errors and proceeds fails open
// on both.
test("v1: every worker down answers unavailable, not an error", async () => {
  const env = testEnv(DEAD, { SCAN_URL: DEAD });
  const res = await handle(
    new Request("http://beamline/v1/lookup?purl=pkg%3Anpm%2Fleft-pad%401.3.0"),
    env,
    waitCtx().ctx,
  );
  assert.equal(res.status, 200, "an outage was reported as a request failure");
  const body = await res.json();
  assert.equal(body.decision, "unavailable");
  assert.notEqual(body.decision, "unknown", "an outage was reported as a fact about the package");
  assert.equal(body.fires_at, null);
  assert.deepEqual(body.findings, []);
  assert.equal(res.headers.get("cache-control"), "no-store", "an outage was made cacheable");
});

// The answer scan gives is the answer the caller gets: beamline adds delivery
// headers and nothing else. Anything it rewrote here would be a second opinion
// about a verdict, from the one service that did not compute it.
test("v1: a worker's answer is passed through intact", async () => {
  const decided = {
    decision: "block",
    purl: "pkg:npm/evil@1.0.0",
    sha256: HELLO_SHA,
    severity: "hostile",
    fires_at: 3,
    reason: "Postinstall launches a reverse shell.",
    findings: [{ id: "objectives/c2/backdoor", crit: 5 }],
    engine_version: "2.8.0",
    analyzed_at: "2026-08-01T00:00:00Z",
  };
  const scan = await mockBackend({ v1: () => decided });
  const env = testEnv(DEAD, { SCAN_URL: scan.url });
  try {
    const res = await handle(
      new Request("http://beamline/v1/lookup?purl=pkg%3Anpm%2Fevil%401.0.0"),
      env,
      waitCtx().ctx,
    );
    assert.equal(res.status, 200);
    assert.deepEqual(await res.json(), decided);
    assert.equal(res.headers.get("x-beamline-source"), "scan");
  } finally {
    await scan.close();
  }
});

// A verdict is immutable for the engine that produced it, so it caches for an
// hour. Not knowing is not: it stops being true the moment anything analyzes
// the artifact, which on this route is often seconds later.
test("v1: a verdict caches for longer than an absence", async () => {
  const scan = await mockBackend({
    v1: (u) => ({
      decision: u.searchParams.get("purl").includes("evil") ? "block" : "unknown",
      purl: u.searchParams.get("purl"),
      sha256: null,
      severity: null,
      fires_at: null,
      reason: null,
      findings: [],
      engine_version: null,
      analyzed_at: null,
    }),
  });
  const env = testEnv(DEAD, { SCAN_URL: scan.url });
  try {
    const bad = await handle(
      new Request("http://beamline/v1/lookup?purl=pkg%3Anpm%2Fevil%401.0.0"),
      env,
      waitCtx().ctx,
    );
    assert.match(bad.headers.get("cache-control"), /max-age=3600/);

    const nothing = await handle(
      new Request("http://beamline/v1/lookup?purl=pkg%3Anpm%2Fquiet%401.0.0"),
      env,
      waitCtx().ctx,
    );
    assert.match(nothing.headers.get("cache-control"), /max-age=60/, "an absence was cached as a verdict");
  } finally {
    await scan.close();
  }
});

// Two callers on different budgets are asking different questions about one
// artifact. Serving the second the first's answer would enforce somebody else's
// policy — silently, and for as long as the entry lives.
test("v1: the budget is part of the cache key", async () => {
  let asked = 0;
  const scan = await mockBackend({
    v1: (u) => {
      asked += 1;
      const budget = Number(u.searchParams.get("false_positive_budget") || 25);
      return {
        decision: budget >= 500 ? "block" : "allow",
        purl: "pkg:npm/borderline@1.0.0",
        sha256: null,
        severity: null,
        fires_at: 500,
        reason: null,
        findings: [],
        engine_version: "2.8.0",
        analyzed_at: "2026-08-01T00:00:00Z",
      };
    },
  });
  const env = testEnv(DEAD, { SCAN_URL: scan.url });
  const ask = async (budget) => {
    const ctx = waitCtx();
    const res = await handle(
      new Request(`http://beamline/v1/lookup?purl=pkg%3Anpm%2Fborderline%401.0.0&false_positive_budget=${budget}`),
      env,
      ctx.ctx,
    );
    await ctx.flush();
    return (await res.json()).decision;
  };
  try {
    assert.equal(await ask(25), "allow");
    assert.equal(await ask(1000), "block", "a second budget was served the first one's decision");
    assert.equal(asked, 2);
    // And the same budget is served from cache rather than re-asked.
    assert.equal(await ask(25), "allow");
    assert.equal(asked, 2, "a cached budget was asked again");
  } finally {
    await scan.close();
  }
});

// A malformed budget is refused rather than replaced by the default, for the
// same reason scan refuses it: a caller who meant to loosen theirs and silently
// got the strict one back would see verdicts they never asked for.
test("v1: a malformed budget is refused", async () => {
  const env = testEnv(DEAD, { SCAN_URL: DEAD });
  const res = await handle(
    new Request("http://beamline/v1/lookup?purl=pkg%3Anpm%2Fx%401.0.0&false_positive_budget=loose"),
    env,
    waitCtx().ctx,
  );
  assert.equal(res.status, 400);
  assert.equal((await res.json()).error.code, "invalid_false_positive_budget");
});

test("v1: naming nothing is refused with a stable code", async () => {
  const env = testEnv(DEAD, { SCAN_URL: DEAD });
  const res = await handle(new Request("http://beamline/v1/lookup"), env, waitCtx().ctx);
  assert.equal(res.status, 400);
  assert.equal((await res.json()).error.code, "missing_package");
});

test("v1: GET only", async () => {
  const env = testEnv(DEAD, { SCAN_URL: DEAD });
  const res = await handle(
    new Request("http://beamline/v1/lookup?purl=x", { method: "POST" }),
    env,
    waitCtx().ctx,
  );
  assert.equal(res.status, 405);
});

// A sick worker must not end the lookup: the next one is asked, and the caller
// never learns there was a first.
test("v1: a failing worker falls through to a healthy one", async () => {
  const sick = await mockBackend({ v1: () => ({ status: 500 }) });
  const well = await mockBackend({
    v1: () => ({
      decision: "allow",
      purl: "pkg:npm/fine@1.0.0",
      sha256: null,
      severity: "benign",
      fires_at: -1,
      reason: null,
      findings: [],
      engine_version: "2.8.0",
      analyzed_at: "2026-08-01T00:00:00Z",
    }),
  });
  const env = testEnv(DEAD, { SCAN_URL: `${sick.url},${well.url}` });
  try {
    const res = await handle(
      new Request("http://beamline/v1/lookup?purl=pkg%3Anpm%2Ffine%401.0.0"),
      env,
      waitCtx().ctx,
    );
    assert.equal(res.status, 200);
    assert.equal((await res.json()).decision, "allow");
  } finally {
    await Promise.all([sick.close(), well.close()]);
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

function testEnv(url, extra = {}) {
  return {
    HOPPER_URL: extra.HOPPER_URL ?? url,
    SCAN_URL: extra.SCAN_URL ?? url,
    // Carried through because it decides two things at once: whether a request
    // is authenticated at all, and what cache scope the answer goes out with.
    BEAMLINE_TOKEN: extra.BEAMLINE_TOKEN,
    HOPPER_POLL_MS: extra.HOPPER_POLL_MS ?? "10",
    SCAN_TIMEOUT_MS: extra.SCAN_TIMEOUT_MS ?? "2000",
    MAX_BYTES: extra.MAX_BYTES,
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
    status: 0,
    v1: 0,
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
      if (url.pathname === "/v1/analyze") {
        hits.analyze += 1;
        if (opts.onAnalyzeBody) opts.onAnalyzeBody(body.toString("utf8"));
        if (opts.onAnalyzeQuery) opts.onAnalyzeQuery(url);
        const forced = typeof opts.analyzeStatus === "function" ? opts.analyzeStatus() : opts.analyzeStatus;
        if (forced && forced !== 200) {
          return send(res, forced, { error: { code: "at_capacity" } });
        }
        res.writeHead(200, { "content-type": "application/x-ndjson" });
        for (const line of opts.analyzeStream || []) res.write(`${line}\n`);
        return res.end();
      }
      if (url.pathname === "/v1/lookup") {
        hits.v1 += 1;
        const out = typeof opts.v1 === "function" ? opts.v1(url) : opts.v1;
        if (!out) return send(res, 404, { error: { code: "unknown_artifact" } });
        if (out.status && out.status !== 200) return send(res, out.status, { error: { code: "boom" } });
        return send(res, 200, out);
      }
      if (url.pathname === "/status") {
        hits.status += 1;
        const out = typeof opts.status === "function" ? opts.status(url) : opts.status;
        return send(res, 200, out || { state: "unknown" });
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











// The breaker is shared machinery: it survived the legacy routes but every test
// that exercised it went through them. A worker answering 5xx must be taken out
// of the pool, or the router keeps offering work to something that cannot take
// it and every caller pays the round trip to find out.
test("v1: a worker that keeps failing is taken out of the pool", async () => {
  const sick = await mockBackend({ v1: () => ({ status: 500 }) });
  const well = await mockBackend({
    v1: () => ({
      decision: "allow", purl: "pkg:npm/fine@1.0.0", sha256: null, severity: "benign",
      fires_at: -1, reason: null, findings: [], engine_version: "2.8.0", analyzed_at: "2026-08-01T00:00:00Z",
    }),
  });
  const env = testEnv(DEAD, { SCAN_URL: `${sick.url},${well.url}` });
  const url = "http://beamline/v1/lookup?purl=pkg%3Anpm%2Ffine%401.0.0";
  try {
    for (let i = 0; i < _test.BREAKER_FAILS + 1; i++) {
      const res = await handle(new Request(url), { ...env, cache: _test.memoryCache() }, waitCtx().ctx);
      assert.equal(res.status, 200, "a failing worker ended the lookup instead of falling through");
    }
    const before = sick.hits.v1;
    await handle(new Request(url), { ...env, cache: _test.memoryCache() }, waitCtx().ctx);
    assert.equal(sick.hits.v1, before, "a tripped worker was asked again");
  } finally {
    await Promise.all([sick.close(), well.close()]);
  }
});

// Both cache bugs found in production were divergences between the copy
// beamline stored and the copy a caller gets back — a `public` scope meant for
// our cache alone, and before that no stored copy at all. Neither is visible to
// a test that only inspects the first response.
test("v1: the cached answer is the same answer", async () => {
  const scan = await mockBackend({
    v1: () => ({
      decision: "block", purl: "pkg:npm/evil@1.0.0", sha256: HELLO_SHA, severity: "hostile",
      fires_at: 3, reason: "Reverse shell in postinstall.",
      findings: [{ id: "objectives/c2/backdoor", crit: 5 }],
      engine_version: "2.8.0", analyzed_at: "2026-08-01T00:00:00Z",
    }),
  });
  const env = testEnv(DEAD, { SCAN_URL: scan.url });
  try {
    await assertSameThroughCache(
      env,
      () => new Request("http://beamline/v1/lookup?purl=pkg%3Anpm%2Fevil%401.0.0"),
      "v1 lookup",
    );
  } finally {
    await scan.close();
  }
});

// An authenticated deployment must not hand a caller an answer marked cacheable
// by every shared proxy between here and them: the verdict is knowledge about
// their artifact, not public data.
test("v1: an authenticated answer is private to the caller", async () => {
  const scan = await mockBackend({
    v1: () => ({
      decision: "allow", purl: "pkg:npm/fine@1.0.0", sha256: null, severity: "benign",
      fires_at: -1, reason: null, findings: [], engine_version: "2.8.0", analyzed_at: "2026-08-01T00:00:00Z",
    }),
  });
  const env = testEnv(DEAD, { SCAN_URL: scan.url, BEAMLINE_TOKEN: "s3cret" });
  try {
    const res = await handle(
      new Request("http://beamline/v1/lookup?purl=pkg%3Anpm%2Ffine%401.0.0", {
        headers: { authorization: "Bearer s3cret" },
      }),
      env,
      waitCtx().ctx,
    );
    assert.equal(res.status, 200);
    assert.match(res.headers.get("cache-control"), /^private/, "an authenticated verdict went out public");
  } finally {
    await scan.close();
  }
});

// A partial rollout, which is what production looked like when this was found:
// one worker had the route and the others did not. Beamline ranks
// deterministically, so relaying the first worker's 404 meant every caller was
// told their package did not exist while a worker that could answer sat idle —
// measured at 0 successes in 12 requests.
//
// A 404 is never this request being wrong: the route answers 200 with
// `unknown` for an artifact nobody has analyzed. It means the worker has no
// such route, which is a fact about the worker.
test("v1: a worker without the route is skipped, not relayed", async () => {
  const old = await mockBackend({ v1: () => ({ status: 404 }) });
  const rolled = await mockBackend({
    v1: () => ({
      decision: "allow", purl: "pkg:npm/left-pad@1.3.0", sha256: null, severity: "benign",
      fires_at: -1, reason: null, findings: [], engine_version: "2.8.0", analyzed_at: "2026-08-01T00:00:00Z",
    }),
  });
  const env = testEnv(DEAD, { SCAN_URL: `${old.url},${rolled.url}` });
  try {
    const res = await handle(
      new Request("http://beamline/v1/lookup?purl=pkg%3Anpm%2Fleft-pad%401.3.0"),
      env,
      waitCtx().ctx,
    );
    assert.equal(res.status, 200, "a worker's missing route was reported to the caller as a missing package");
    assert.equal((await res.json()).decision, "allow");
  } finally {
    await Promise.all([old.close(), rolled.close()]);
  }
});

// And it converges: a worker that keeps answering 404 is counted against and
// drops out of the pool, so a partial rollout drains onto the workers that can
// serve rather than paying a wasted round trip on every request.
test("v1: a partial rollout converges on the worker that can serve", async () => {
  const old = await mockBackend({ v1: () => ({ status: 404 }) });
  const rolled = await mockBackend({
    v1: () => ({
      decision: "allow", purl: "pkg:npm/left-pad@1.3.0", sha256: null, severity: "benign",
      fires_at: -1, reason: null, findings: [], engine_version: "2.8.0", analyzed_at: "2026-08-01T00:00:00Z",
    }),
  });
  const env = testEnv(DEAD, { SCAN_URL: `${old.url},${rolled.url}` });
  const url = "http://beamline/v1/lookup?purl=pkg%3Anpm%2Fleft-pad%401.3.0";
  try {
    for (let i = 0; i < _test.BREAKER_FAILS + 1; i++) {
      const res = await handle(new Request(url), { ...env, cache: _test.memoryCache() }, waitCtx().ctx);
      assert.equal(res.status, 200);
    }
    const before = old.hits.v1;
    for (let i = 0; i < 3; i++) {
      await handle(new Request(url), { ...env, cache: _test.memoryCache() }, waitCtx().ctx);
    }
    assert.equal(old.hits.v1, before, "the un-rolled worker was still being asked");
  } finally {
    await Promise.all([old.close(), rolled.close()]);
  }
});

// A 400 is different: the request really is wrong, and the next worker would
// say so too. It reaches the caller with scan's own reason.
test("v1: a genuine client error still reaches the caller", async () => {
  const scan = await mockBackend({ v1: () => ({ status: 400 }) });
  const env = testEnv(DEAD, { SCAN_URL: scan.url });
  try {
    const res = await handle(
      new Request("http://beamline/v1/lookup?purl=pkg%3Anpm%2Fx%401.0.0"),
      env,
      waitCtx().ctx,
    );
    assert.equal(res.status, 400, "a client error was swallowed as a worker fault");
  } finally {
    await scan.close();
  }
});

// A caller holding bytes nobody has published — a build output, a file off
// disk, something pulled from a mirror — has nothing to locate them by. The
// legacy route took the artifact as the raw body and v1 dropped it, which broke
// `curl -T` against the API with a 400 saying to name a package.
test("v1 analyze: the artifact may be the body", async () => {
  let got = null;
  const scan = await mockBackend({
    status: { state: "unknown" },
    onAnalyzeBody: (body) => {
      got = body;
    },
    analyzeStream: ['{"decision":"allow","fires_at":-1,"sha256":"abc"}'],
  });
  const env = testEnv(DEAD, { SCAN_URL: scan.url });
  try {
    const res = await handle(
      new Request("http://beamline/v1/analyze", { method: "POST", body: "hello" }),
      env,
      waitCtx().ctx,
    );
    assert.equal(res.status, 200, "an uploaded artifact was refused");
    assert.equal(JSON.parse((await res.text()).trim()).decision, "allow");
    assert.equal(got, "hello", "the bytes did not reach the worker intact");
  } finally {
    await scan.close();
  }
});

// The locator still rides along when both are sent: scan grafts the registry
// provenance onto the report and echoes it in each finding's `pkg`.
test("v1 analyze: an upload may still name the package", async () => {
  let gotPurl = null;
  const scan = await mockBackend({
    status: { state: "unknown" },
    onAnalyzeQuery: (u) => {
      gotPurl = u.searchParams.get("purl");
    },
    analyzeStream: ['{"decision":"allow","fires_at":-1}'],
  });
  const env = testEnv(DEAD, { SCAN_URL: scan.url });
  try {
    await handle(
      new Request("http://beamline/v1/analyze?purl=pkg%3Anpm%2Fx%401.0.0", { method: "POST", body: "bytes" }),
      env,
      waitCtx().ctx,
    );
    assert.equal(gotPurl, "pkg:npm/x@1.0.0", "the locator was dropped from an upload");
  } finally {
    await scan.close();
  }
});

// Naming nothing and sending nothing is the bare `curl -X POST` — answered by
// telling the caller how to name a package, since that is what they are
// missing.
test("v1 analyze: naming nothing is refused with a stable code", async () => {
  const env = testEnv(DEAD, { SCAN_URL: DEAD });
  const res = await handle(
    new Request("http://beamline/v1/analyze", { method: "POST" }),
    env,
    waitCtx().ctx,
  );
  assert.equal(res.status, 400);
  const { error } = await res.json();
  assert.equal(error.code, "missing_package");
  // The message has to name both ways in, or a caller holding bytes is told
  // only about the one they cannot use.
  assert.match(error.message, /purl/);
  assert.match(error.message, /body/);
});

// A plain POST sends `Content-Length: 0`, so every caller who names a package
// and sends nothing still arrives with a body — an empty one. Reading that as
// an upload turned every analysis by PURL into a 400, which is how this was
// found: in production, on the path poppy uses for every release it precaches.
test("v1 analyze: an empty body is no body, not an empty artifact", async () => {
  let asked = null;
  const scan = await mockBackend({
    status: { state: "unknown" },
    onAnalyzeQuery: (u) => {
      asked = u.searchParams.get("purl");
    },
    analyzeStream: ['{"decision":"allow","fires_at":-1,"purl":"pkg:npm/x@1.0.0"}'],
  });
  const env = testEnv(DEAD, { SCAN_URL: scan.url });
  try {
    const res = await handle(
      new Request("http://beamline/v1/analyze?purl=pkg%3Anpm%2Fx%401.0.0", { method: "POST", body: "" }),
      env,
      waitCtx().ctx,
    );
    assert.equal(res.status, 200, "a named package with no bytes was refused");
    assert.equal(JSON.parse((await res.text()).trim()).decision, "allow");
    assert.equal(asked, "pkg:npm/x@1.0.0", "the package was not analyzed");
  } finally {
    await scan.close();
  }
});

// Held in memory so a refused first worker can be offered the same artifact,
// which makes the cap a memory bound as much as a policy one.
test("v1 analyze: an oversized artifact is refused by name", async () => {
  const env = testEnv(DEAD, { SCAN_URL: DEAD, MAX_BYTES: "8" });
  const res = await handle(
    new Request("http://beamline/v1/analyze", { method: "POST", body: "far too many bytes" }),
    env,
    waitCtx().ctx,
  );
  assert.equal(res.status, 413);
  assert.equal((await res.json()).error.code, "artifact_too_large");
});
