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

test("a worker with no request history for a size is ranked on its idle work", () => {
  const thin = { jobs: 1, avg_ms: 900, recent: { samples: 1, p80_ms: 900, mean_ms: 900 } };
  const settled = (ms) => ({ jobs: 40, avg_ms: ms, recent: { samples: 40, p80_ms: ms, mean_ms: ms } });
  const hint = { bytes: 512 * 1024 };
  // Nothing to go on but idle work: the starved worker still gets a number,
  // which is the whole point - otherwise it is never tried and never measured.
  assert.equal(
    _test.classMs({ avg_job_ms_by_size: { le_1mb: thin }, avg_job_ms_by_size_idle: { le_1mb: settled(4200) } }, hint),
    4200,
  );
  // Real load beats idle where both are settled: idle work runs uncontended.
  assert.equal(
    _test.classMs({ avg_job_ms_by_size: { le_1mb: settled(7000) }, avg_job_ms_by_size_idle: { le_1mb: settled(4200) } }, hint),
    7000,
  );
  // A worker too old to publish an idle series behaves exactly as before.
  assert.equal(_test.classMs({ avg_job_ms_by_size: { le_1mb: settled(7000) } }, hint), 7000);
  assert.equal(_test.classMs({ avg_job_ms_by_size: { le_1mb: thin } }, hint), null);
});
test("a decision is filed under scan's canonical spelling as well as the caller's", () => {
  const body = JSON.stringify({ purl: "pkg:golang/github.com/gofrs/uuid@v4.4.0+incompatible", sha256: "a".repeat(64), status: "analyzed", severity: "benign", fires_at: -1 });
  const locator = { type: "purl", value: "pkg:golang/github.com/gofrs/uuid@v4.4.0+incompatible" };
  const requested = _test.v1CacheAliasPaths("https://b.example", "/v1/lookup?purl=x", locator, body, "all");
  const canonical = _test.v1CacheAliasPaths("https://b.example", "/v1/lookup?purl=x", locator, body, "all", "pkg:golang/github.com/gofrs/uuid@v4.4.0%2Bincompatible");
  const urls = (keys) => keys.map((k) => k.url);
  // The two spellings are one artifact. Without the canonical key the second
  // spelling to arrive buys an analysis the first already paid for.
  const added = urls(canonical).filter((u) => !urls(requested).includes(u));
  assert.equal(added.length, 1);
  assert.match(added[0], /v4\.4\.0%252Bincompatible/);
});

test("a canonical purl that is not a purl is not made into a cache key", () => {
  const body = JSON.stringify({ sha256: "b".repeat(64), status: "analyzed", severity: "benign", fires_at: -1 });
  const locator = { type: "purl", value: "pkg:npm/left-pad@1.3.0" };
  const base = _test.v1CacheAliasPaths("https://b.example", "/v1/lookup?purl=x", locator, body, "all");
  for (const bad of ["", "   ", "not-a-purl", "https://evil.example/x", "pkg:" + "a".repeat(600)]) {
    assert.equal(_test.cleanPurl(bad), null, `rejects ${JSON.stringify(bad)}`);
    const got = _test.v1CacheAliasPaths("https://b.example", "/v1/lookup?purl=x", locator, body, "all", _test.cleanPurl(bad));
    assert.deepEqual(got.map((k) => k.url), base.map((k) => k.url));
  }
  assert.equal(_test.cleanPurl("pkg:golang/x.io/y@v1%2Bz"), "pkg:golang/x.io/y@v1%2Bz");
});
test("scan timeout default is 1800s", () => {
  assert.equal(_test.DEFAULT_SCAN_TIMEOUT_MS, 1_800_000);
});

test("GET /healthz", async () => {
  const res = await handle(new Request("http://beamline/healthz"), {}, {});
  assert.equal(res.status, 200);
  assert.equal((await res.json()).status, "ok");
});

test("GET / serves the public API documentation", async () => {
  const res = await handle(new Request("http://beamline/"), { BEAMLINE_TOKEN: "secret" }, {});
  assert.equal(res.status, 200);
  assert.match(res.headers.get("content-type"), /^text\/html/);
  const body = await res.text();
  assert.match(body, /Beamline API/);
  assert.match(body, /Find 0-day malware in the software supply chain/);
  assert.match(body, /class="hero-points"/);
  assert.match(body, /false_positive_budget/);
  assert.match(body, /open-source <a href="https:\/\/atomdrift\.org\/">Atomdrift project/);
  assert.match(body, /Use cases/);
  assert.match(body, /href="#false-positive-budget"/);
  assert.match(body, /false_positive_budget=25/);
  assert.match(body, /<code>false_positive_budget<\/code>/);
  assert.match(body, /Following references/);
  assert.match(body, /<code>\?follow=<\/code> controls/);
  assert.match(body, /CI systems/);
  assert.match(body, /Transparent proxy integration/);
  assert.match(body, /<code>\?follow=references<\/code>/);
  assert.match(body, /downloads malware later/);
  assert.match(body, /mailto:support@isotope13\.ai/);
  assert.equal((body.match(/class="new-label"/g) || []).length, 3);
  assert.equal((body.match(/class="heading-link"/g) || []).length, (body.match(/<h[123](?:\s|>)/g) || []).length);
  assert.match(body, /href="#lookup-url"/);
  assert.match(body, /href="#content-upload"/);
  assert.match(body, /follow=none/);
  assert.match(body, /Authentication is required/);
  assert.match(body, /Authorization: Bearer/);
  assert.match(body, /class="run-button"/);
  assert.match(body, /class="request"/);
  assert.match(body, /overflow-wrap:anywhere/);
  assert.match(body, /class="route-example"/);
  assert.doesNotMatch(body, /Runnable curl|class="runbar"/);
  assert.match(body, /class="response"/);
  assert.match(body, /class="meanings"/);
  assert.match(body, /<code>status<\/code> describes whether Beamline has an assessment/);
  assert.match(body, /status: "analyzed"/);
  assert.match(body, /only the terminal line containing <code>status<\/code> is the assessment/);
  assert.match(body, /runner\.has-response/);
  assert.match(body, /runner\.hasAttribute\("data-stream"\) \? output\.scrollHeight : 0/);
  assert.match(body, /data-path="\/v1\/lookup\?url=/);
  assert.match(body, /data-path="\/v1\/lookup\?sha256=/);
  assert.match(body, /application\/x-ndjson/);
  assert.match(body, /--code:#f2f2f7/);
  assert.match(body, /grid-template-columns:136px minmax\(0,1fr\)/);
  assert.match(body, /p \{[^}]*max-width:none/);
  assert.doesNotMatch(body, /healthz/);
});

test("GET / describes an open deployment as unauthenticated", async () => {
  const res = await handle(new Request("http://beamline/"), {}, {});
  const body = await res.text();
  assert.match(body, /<strong>Auth<\/strong> Anonymous \/ Bearer Token/);
  assert.doesNotMatch(body, /Authentication is required/);
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



test("the documentation page ignores query parameters", async () => {
  const res = await handle(new Request("http://beamline/?purl=pkg:npm/left-pad@1.3.0"), {}, {});
  assert.equal(res.status, 200);
  assert.match(await res.text(), /Find 0-day malware in the software supply chain/);
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
    assert.equal(decided.status, "analyzed", "gave up on a fleet that was only busy");
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

// A pin selects, or the header is decoration.
//
// It used to be decoration: `pin` bypassed the caches and nothing filtered the
// pool, so a pinned request was routed like any other. Two benchmarks were
// built on it and both silently measured the router against itself — the
// failure is invisible from outside, because a pinned request still returns a
// perfectly good verdict from the wrong worker.
test("a pin selects one worker and nothing else", () => {
  const env = { SCAN_URL: "https://a.test,https://b.test,https://c.test" };
  assert.deepEqual(_test.scanWorkers(env, "b.test"), ["https://b.test"]);

  // A tripped breaker does not override an explicit choice: timing a worker
  // that is currently failing is a reason to pin, not a reason to refuse.
  for (let i = 0; i < _test.BREAKER_FAILS; i++) _test.breakerFor("https://b.test").fail();
  assert.deepEqual(_test.scanWorkers(env, "b.test"), ["https://b.test"]);

  // A name the fleet does not have selects nobody, so the caller is told it
  // asked for something that does not exist rather than served by a stranger.
  assert.deepEqual(_test.scanWorkers(env, "nope.test"), []);
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

// A worker whose corpus is unreachable answers 200 `unavailable`. That is an
// outage, not an answer, and the fleet exists so that one of them failing is
// not all of them failing.
test("v1 lookup: an unavailable worker does not end the search", async () => {
  const outage = await mockBackend({
    // `decision`, not `status`: mockBackend reads a `status` field as an HTTP
    // status override. Both spellings mark an outage to the code under test.
    v1: { decision: "unavailable", cause: "corpus_unreachable", purl: "pkg:npm/app@1.0.0", severity: "unknown", fires_at: null, findings: [] },
  });
  const healthy = await mockBackend({
    // Same reason as above: `decision` is the field a worker answers with, and
    // normalizeV1Row turns allow/block into the `status` the caller reads.
    v1: { decision: "allow", purl: "pkg:npm/app@1.0.0", sha256: "a".repeat(64), severity: "benign", fires_at: -1, findings: [], engine_version: "2.8.0", analyzed_at: "2026-09-01T00:00:00Z" },
  });
  const env = testEnv(DEAD, { SCAN_URL: `${outage.url},${healthy.url}` });
  try {
    const res = await handle(new Request("http://beamline/v1/lookup?purl=pkg%3Anpm%2Fapp%401.0.0"), env, waitCtx().ctx);
    assert.equal(res.status, 200);
    const body = JSON.parse(await res.text());
    assert.equal(body.status, "analyzed", "the second worker's answer is the one relayed");
    assert.equal(outage.hits.v1, 1, "the unavailable worker was asked first");
    assert.ok(healthy.hits.v1 >= 1, "and the search carried on past it");
  } finally {
    await outage.close();
    await healthy.close();
  }
});

// When nobody can find out, scan's own account of the outage is better than
// one invented here: it names the address that failed.
test("v1 lookup: an outage is relayed once the fleet is exhausted", async () => {
  const outage = await mockBackend({
    // `decision`, not `status`: mockBackend reads a `status` field as an HTTP
    // status override. Both spellings mark an outage to the code under test.
    v1: { decision: "unavailable", cause: "corpus_unreachable", purl: "pkg:npm/app@1.0.0", severity: "unknown", fires_at: null, findings: [] },
  });
  const env = testEnv(DEAD, { SCAN_URL: outage.url });
  try {
    const res = await handle(new Request("http://beamline/v1/lookup?purl=pkg%3Anpm%2Fapp%401.0.0"), env, waitCtx().ctx);
    assert.equal(res.status, 200);
    const body = JSON.parse(await res.text());
    assert.equal(body.status, "unavailable");
    assert.equal(body.cause, "corpus_unreachable", "scan's reason, not ours");
  } finally {
    await outage.close();
  }
});
// --- /v1/analyze --------------------------------------------------------

test("v1 analyze: follow is normalized and forwarded", async () => {
  let forwarded;
  const scan = await mockBackend({
    onAnalyzeQuery: (url) => { forwarded = url.searchParams.get("follow"); },
    analyzeStream: ['{"decision":"allow","fires_at":-1,"purl":"pkg:npm/app@1.0.0"}'],
  });
  const env = testEnv(DEAD, { SCAN_URL: scan.url });
  try {
    const res = await handle(
      new Request(
        "http://beamline/v1/analyze?purl=pkg%3Anpm%2Fapp%401.0.0&follow=references&follow=ci-actions",
        { method: "POST" },
      ),
      env,
      waitCtx().ctx,
    );
    assert.equal(res.status, 200);
    await res.text();
    assert.equal(forwarded, "dependencies,references,ci-actions");
  } finally {
    await scan.close();
  }
});

// The default is a statement about what the caller already knows. A PURL is a
// name for something they resolved themselves, so their dependency graph is
// theirs to walk and only what no manifest declares is followed for them. A URL
// is one artifact out of a set a proxy already handed them in full. Bytes name
// nothing at all, so nothing inside them is discoverable anywhere else.
test("v1 analyze: the follow default is decided by how the artifact was named", async () => {
  const cases = [
    ["purl", "http://beamline/v1/analyze?purl=pkg%3Anpm%2Fapp%401.0.0", null, "references"],
    ["url", `http://beamline/v1/analyze?url=${encodeURIComponent("https://cdn.example.test/app.tgz")}`, null, "none"],
    ["upload", "http://beamline/v1/analyze", "bytes nobody published", "all"],
    // A PURL beside an upload names provenance, not the thing being asked
    // about. The bytes are still the question.
    ["upload with provenance", "http://beamline/v1/analyze?purl=pkg%3Anpm%2Fapp%401.0.0", "bytes nobody published", "all"],
  ];
  for (const [label, target, body, expected] of cases) {
    let forwarded;
    const scan = await mockBackend({
      onAnalyzeQuery: (url) => { forwarded = url.searchParams.get("follow"); },
      analyzeStream: ['{"decision":"allow","fires_at":-1,"purl":"pkg:npm/app@1.0.0"}'],
    });
    const env = testEnv(DEAD, { SCAN_URL: scan.url });
    try {
      const res = await handle(new Request(target, { method: "POST", body }), env, waitCtx().ctx);
      assert.equal(res.status, 200, label);
      await res.text();
      assert.equal(forwarded, expected, label);
    } finally {
      await scan.close();
    }
  }
});

// A digest sits with the PURL rather than the URL. Whoever holds one holds it
// because something resolved to it — a lockfile pin, a scanner report — which
// puts them in the same position as the caller who named the package, and an
// answer one of them paid for should serve the other.
test("v1: a digest resolves the same policy as the PURL that answered it", async () => {
  const purl = "pkg:npm/app@1.0.0";
  const scan = await mockBackend({
    analyzeStream: [
      `{"decision":"allow","fires_at":-1,"purl":"${purl}","sha256":"${HELLO_SHA}","engine_version":"2.8.0"}`,
    ],
  });
  const env = testEnv(DEAD, { SCAN_URL: scan.url });
  const ctx = waitCtx();
  try {
    const analyzed = await handle(
      new Request(`http://beamline/v1/analyze?purl=${encodeURIComponent(purl)}`, { method: "POST" }),
      env,
      ctx.ctx,
    );
    await analyzed.text();
    await ctx.flush();

    const byDigest = await handle(new Request(`http://beamline/v1/lookup?sha256=${HELLO_SHA}`), env, noopCtx());
    assert.equal(
      byDigest.headers.get("x-beamline-source"),
      "cache",
      "the digest asked a different question than the PURL that answered it",
    );
    assert.equal((await byDigest.json()).sha256, HELLO_SHA);
  } finally {
    await scan.close();
  }
});

test("v1 analyze: exact URL reaches scan and warms locator aliases", async () => {
  const artifactUrl = "https://cdn.example.test/files/app-1.0.0.tgz";
  const purl = "pkg:npm/app@1.0.0";
  let forwarded;
  const scan = await mockBackend({
    onAnalyzeQuery: (url) => { forwarded = url; },
    analyzeStream: () => [
      `{"decision":"allow","purl":"${purl}","url":"${artifactUrl}","sha256":"${HELLO_SHA}","fires_at":-1,"engine_version":"2.8.0"}`,
    ],
  });
  const env = testEnv(DEAD, { SCAN_URL: scan.url });
  try {
    const ctx = waitCtx();
    const analyzed = await handle(
      new Request(`http://beamline/v1/analyze?url=${encodeURIComponent(artifactUrl)}`, { method: "POST" }),
      env,
      ctx.ctx,
    );
    const decision = JSON.parse((await analyzed.text()).trim().split("\n").pop());
    assert.equal(decision.url, artifactUrl);
    assert.equal(forwarded.searchParams.get("url"), artifactUrl);
    await ctx.flush();

    // Under the policy the URL scan answered, which is `none`. The PURL's own
    // default is a different question and must still be cold.
    const cached = await handle(
      new Request(`http://beamline/v1/lookup?purl=${encodeURIComponent(purl)}&follow=none`),
      env,
      noopCtx(),
    );
    assert.equal(cached.headers.get("x-beamline-source"), "cache");
    assert.equal((await cached.json()).sha256, HELLO_SHA);
    assert.equal(scan.hits.analyze, 1);
  } finally {
    await scan.close();
  }
});

test("v1 analyze: malformed follow policy is rejected at the edge", async () => {
  for (const follow of ["deps", "none,references", ""]) {
    const res = await handle(
      new Request(`http://beamline/v1/analyze?purl=pkg%3Anpm%2Fapp%401.0.0&follow=${encodeURIComponent(follow)}`, {
        method: "POST",
      }),
      testEnv(DEAD),
      waitCtx().ctx,
    );
    assert.equal(res.status, 400);
    assert.equal((await res.json()).error.code, "invalid_follow_policy");
  }
});

// `follow` widens monotonically, so the policies are ordered rather than merely
// distinct: an answer produced under a wider policy looked everywhere a
// narrower one would have and further, so it answers the narrower question —
// with its own findings, since that is what it measured. A caller asking
// `follow=none` about an artifact whose dependency is hostile is told hostile,
// and `findings[].pkg` says which component made it so.
//
// The reverse is the direction that would turn this cache into a false
// negative, and it stays refused.
test("v1 analyze: a wider policy's answer serves a narrower question", async () => {
  const purl = "pkg:npm/app@1.0.0";
  const scan = await mockBackend({
    analyzeStream: (url) => url.searchParams.get("follow") === "none"
      ? [`{"decision":"block","fires_at":3,"purl":"${purl}","engine_version":"test"}`]
      : [`{"decision":"allow","fires_at":-1,"purl":"${purl}","engine_version":"test"}`],
  });
  const env = testEnv(DEAD, { SCAN_URL: scan.url });
  const firstCtx = waitCtx();
  try {
    const first = await handle(
      new Request(`http://beamline/v1/analyze?purl=${encodeURIComponent(purl)}`, { method: "POST" }),
      env,
      firstCtx.ctx,
    );
    await first.text();
    await firstCtx.flush();

    // The default is `references`, which contains `none`, so the narrower
    // question is already answered and costs no second analysis.
    const customCtx = waitCtx();
    const custom = await handle(
      new Request(`http://beamline/v1/analyze?purl=${encodeURIComponent(purl)}&follow=none`, { method: "POST" }),
      env,
      customCtx.ctx,
    );
    const narrow = JSON.parse((await custom.text()).trim());
    await customCtx.flush();
    assert.equal(narrow.status, "analyzed");
    assert.equal(scan.hits.analyze, 1, "a narrower question paid for an analysis a wider entry already answered");
    // Served on the wider policy's evidence, not the narrower policy's. The
    // mock answers `block` for `follow=none` and `allow` for anything else, so
    // the `allow` proves which entry answered.
    assert.equal(narrow.fires_at, -1, "the narrower question was not answered by the wider entry's findings");
    assert.equal(custom.headers.get("X-Beamline-Follow"), "references", "the answering policy was not named");

    // And the reverse never happens: a `follow=none` entry cannot answer the
    // default's question, because it never looked where that question points.
    const noneOnly = testEnv(DEAD, { SCAN_URL: scan.url });
    const seedCtx = waitCtx();
    await (await handle(
      new Request(`http://beamline/v1/analyze?purl=${encodeURIComponent(purl)}&follow=none`, { method: "POST" }),
      noneOnly,
      seedCtx.ctx,
    )).text();
    await seedCtx.flush();
    const before = scan.hits.analyze;
    const wider = await handle(
      new Request(`http://beamline/v1/analyze?purl=${encodeURIComponent(purl)}`, { method: "POST" }),
      noneOnly,
      waitCtx().ctx,
    );
    assert.equal(JSON.parse((await wider.text()).trim()).status, "analyzed");
    assert.equal(scan.hits.analyze, before + 1, "a narrow answer was served for the wider question");
  } finally {
    await scan.close();
  }
});

// The ordering itself, exhaustively, because every cache decision below rests
// on it. A policy is a set of reference kinds; a stored policy answers a
// requested one exactly when its set contains the requested set.
test("follow policies are ordered by containment, narrowest candidate first", () => {
  const { followCandidates } = _test;

  // Every policy answers itself, and answers it first: the exact entry is
  // always preferred to a wider one.
  for (const policy of ["none", "dependencies", "references", "all"]) {
    assert.equal(followCandidates(policy)[0], policy);
  }

  // `none` is answered by everything.
  assert.deepEqual(followCandidates("none"), [
    "none",
    "dependencies",
    "references",
    "dependencies,ci-actions",
    "dependencies,references",
    "all",
    "dependencies,references,ci-actions",
  ]);

  // `all` is answered only by itself and by its long spelling. Two names for
  // one question, and each has to answer the other or a caller's choice of
  // spelling would decide whether they pay for an analysis.
  assert.deepEqual(followCandidates("all"), ["all", "dependencies,references,ci-actions"]);
  assert.deepEqual(followCandidates("dependencies,references,ci-actions"), [
    "dependencies,references,ci-actions",
    "all",
  ]);

  // `dependencies` and `references` are incomparable: neither contains the
  // other, so neither may answer the other.
  assert.ok(!followCandidates("dependencies").includes("references"));
  assert.ok(!followCandidates("references").includes("dependencies"));

  // ci-actions implies dependencies, so its canonical spelling contains
  // `dependencies` and answers it — but not `references`.
  assert.ok(followCandidates("dependencies").includes("dependencies,ci-actions"));
  assert.ok(!followCandidates("references").includes("dependencies,ci-actions"));

  // Nothing answers a question wider than itself.
  for (const policy of FOLLOW_SPELLINGS) {
    for (const candidate of followCandidates(policy)) {
      assert.ok(
        kindsOf(policy).every((kind) => kindsOf(candidate).includes(kind)),
        `${candidate} was offered for ${policy} without containing it`,
      );
    }
  }
});

const FOLLOW_SPELLINGS = [
  "none",
  "dependencies",
  "references",
  "dependencies,ci-actions",
  "dependencies,references",
  "all",
  "dependencies,references,ci-actions",
];

function kindsOf(policy) {
  if (policy === "none") return [];
  if (policy === "all") return ["dependencies", "references", "ci-actions"];
  return policy.split(",");
}

// The same ordering on the free route. A lookup is cheap, but it is the route a
// proxy calls on every install, so a miss it did not have to take is the one
// that shows up as fleet load.
test("v1 lookup: a wider policy's answer serves a narrower question, never the reverse", async () => {
  const purl = "pkg:npm/app@1.0.0";
  // No `status` field: mockBackend reads that as an HTTP status override.
  const decided = {
    decision: "block",
    purl,
    sha256: HELLO_SHA,
    severity: "hostile",
    fires_at: 3,
    findings: [{ id: "objectives/c2/backdoor", crit: 5, pkg: "pkg:npm/dep@2.0.0" }],
    engine_version: "2.8.0",
    analyzed_at: "2026-08-01T00:00:00Z",
  };
  const scan = await mockBackend({ v1: () => decided });
  const env = testEnv(DEAD, { SCAN_URL: scan.url });
  try {
    // Warm the wide entry.
    const seed = waitCtx();
    await (await handle(
      new Request(`http://beamline/v1/lookup?purl=${encodeURIComponent(purl)}&follow=all`),
      env,
      seed.ctx,
    )).json();
    await seed.flush();
    const warmed = scan.hits.v1;

    // The narrow question is answered from it, on its findings — including the
    // finding attributed to a dependency, which is the whole point of saying
    // the wider entry answers with its own evidence.
    const narrow = await handle(
      new Request(`http://beamline/v1/lookup?purl=${encodeURIComponent(purl)}&follow=none`),
      env,
      waitCtx().ctx,
    );
    const body = await narrow.json();
    assert.equal(scan.hits.v1, warmed, "a narrow lookup reached scan with a wider answer in hand");
    assert.equal(narrow.headers.get("X-Beamline-Source"), "cache");
    assert.equal(narrow.headers.get("X-Beamline-Follow"), "all");
    assert.equal(body.fires_at, 3);
    assert.equal(body.findings[0].pkg, "pkg:npm/dep@2.0.0");

    // An exact hit names no other policy: the header is only ever there to say
    // the answer came from a question the caller did not ask.
    const exact = await handle(
      new Request(`http://beamline/v1/lookup?purl=${encodeURIComponent(purl)}&follow=all`),
      env,
      waitCtx().ctx,
    );
    await exact.json();
    assert.equal(exact.headers.get("X-Beamline-Follow"), null);

    // `references` is not contained by `dependencies`, and the entry we hold is
    // `all` — which does contain it — so this must still be served. The sibling
    // check is below.
    const sibling = testEnv(DEAD, { SCAN_URL: scan.url });
    const sibCtx = waitCtx();
    await (await handle(
      new Request(`http://beamline/v1/lookup?purl=${encodeURIComponent(purl)}&follow=dependencies`),
      sibling,
      sibCtx.ctx,
    )).json();
    await sibCtx.flush();
    const afterDeps = scan.hits.v1;
    await (await handle(
      new Request(`http://beamline/v1/lookup?purl=${encodeURIComponent(purl)}&follow=references`),
      sibling,
      waitCtx().ctx,
    )).json();
    assert.equal(
      scan.hits.v1,
      afterDeps + 1,
      "an incomparable sibling policy was served from the other's entry",
    );
  } finally {
    await scan.close();
  }
});

// A miss is cached too, and it is not an answer about a policy — it is a
// statement about the artifact, true only until something analyzes it. This is
// the production failure the ordering above was missing: poppy looks up a
// release nobody holds, which files `unanalyzed` under the default policy, and
// then analyzes it under `follow=all`, which files the verdict under `all`. For
// the 60s the miss stayed cached, every caller asking the default question was
// told the artifact was unanalyzed — a minute after it had been analyzed, and
// with the verdict sitting one candidate further along the same walk. Measured
// against the fleet before this test existed: 60.3s, 60.1s, 22.5s, 13.8s.
test("v1 lookup: a cached miss does not hide a wider policy's verdict", async () => {
  const purl = "pkg:npm/app@1.0.0";
  const decided = {
    decision: "allow",
    purl,
    sha256: HELLO_SHA,
    severity: "benign",
    fires_at: -1,
    engine_version: "2.8.0",
    analyzed_at: "2026-08-01T00:00:00Z",
  };
  // Nothing is held until the analysis runs, which is what files the miss.
  let analyzed = false;
  const scan = await mockBackend({
    v1: () => (analyzed ? decided : { decision: "unanalyzed", purl, sha256: null, severity: null, fires_at: null, reason: null, findings: [], engine_version: null, analyzed_at: null }),
    analyzeStream: () => {
      analyzed = true;
      return [JSON.stringify(decided)];
    },
  });
  const env = testEnv(DEAD, { SCAN_URL: scan.url });
  try {
    // The miss, filed under the policy poppy's lookups name: none at all.
    const miss = waitCtx();
    const missed = await (await handle(
      new Request(`http://beamline/v1/lookup?purl=${encodeURIComponent(purl)}`),
      env,
      miss.ctx,
    )).json();
    await miss.flush();
    assert.equal(missed.status, "unanalyzed");

    // The analysis, under the wider policy the precache pass asks for.
    const run = waitCtx();
    const res = await handle(
      new Request(`http://beamline/v1/analyze?purl=${encodeURIComponent(purl)}&follow=all`, { method: "POST" }),
      env,
      run.ctx,
    );
    assert.equal(res.status, 200);
    await res.text();
    await run.flush();

    // The same bare question again. The miss is a minute from expiring and the
    // verdict is two candidates past it; the verdict is the answer.
    const after = await handle(
      new Request(`http://beamline/v1/lookup?purl=${encodeURIComponent(purl)}`),
      env,
      waitCtx().ctx,
    );
    const body = await after.json();
    assert.equal(body.status, "analyzed", "a cached miss outranked the verdict that answered it");
    assert.equal(after.headers.get("X-Beamline-Source"), "cache");
    assert.equal(after.headers.get("X-Beamline-Follow"), "all");
  } finally {
    await scan.close();
  }
});

// The fallback the rule above must not cost us. An artifact nobody holds is
// still answered from the cached miss rather than from the fleet: that entry is
// why misses are cached at all, and a lookup is the route a proxy calls on
// every install.
test("v1 lookup: a cached miss still answers when nothing wider holds a verdict", async () => {
  const purl = "pkg:npm/app@1.0.0";
  const scan = await mockBackend({
    v1: () => ({ decision: "unanalyzed", purl, sha256: null, severity: null, fires_at: null, reason: null, findings: [], engine_version: null, analyzed_at: null }),
  });
  const env = testEnv(DEAD, { SCAN_URL: scan.url });
  try {
    const seed = waitCtx();
    await (await handle(
      new Request(`http://beamline/v1/lookup?purl=${encodeURIComponent(purl)}`),
      env,
      seed.ctx,
    )).json();
    await seed.flush();
    const asked = scan.hits.v1;

    const again = await handle(
      new Request(`http://beamline/v1/lookup?purl=${encodeURIComponent(purl)}`),
      env,
      waitCtx().ctx,
    );
    const body = await again.json();
    assert.equal(body.status, "unanalyzed");
    assert.equal(again.headers.get("X-Beamline-Source"), "cache");
    // Its own question answered it, so no other policy is named.
    assert.equal(again.headers.get("X-Beamline-Follow"), null);
    assert.equal(scan.hits.v1, asked, "a cached miss stopped being served and the fleet paid for it");
  } finally {
    await scan.close();
  }
});

// The same rule on the expensive route. A miss filed under the narrow policy
// used to end the walk here too, and ending it here does not merely answer
// wrongly — it sends us off to spend the most expensive thing this service
// does on a verdict a wider entry was already holding.
test("v1 analyze: a cached miss does not buy an analysis a wider entry already answers", async () => {
  const purl = "pkg:npm/app@1.0.0";
  const decided = {
    decision: "allow",
    purl,
    sha256: HELLO_SHA,
    severity: "benign",
    fires_at: -1,
    engine_version: "2.8.0",
    analyzed_at: "2026-08-01T00:00:00Z",
  };
  const scan = await mockBackend({
    v1: () => ({ decision: "unanalyzed", purl, sha256: null, severity: null, fires_at: null, reason: null, findings: [], engine_version: null, analyzed_at: null }),
    analyzeStream: [JSON.stringify(decided)],
  });
  const env = testEnv(DEAD, { SCAN_URL: scan.url });
  try {
    // A miss under `none`, then a verdict under `all`.
    const miss = waitCtx();
    await (await handle(
      new Request(`http://beamline/v1/lookup?purl=${encodeURIComponent(purl)}&follow=none`),
      env,
      miss.ctx,
    )).json();
    await miss.flush();

    const run = waitCtx();
    await (await handle(
      new Request(`http://beamline/v1/analyze?purl=${encodeURIComponent(purl)}&follow=all`, { method: "POST" }),
      env,
      run.ctx,
    )).text();
    await run.flush();
    const ran = scan.hits.analyze;

    // Asking to analyze under the narrow policy is answered from the wider
    // entry, without a second run.
    const res = await handle(
      new Request(`http://beamline/v1/analyze?purl=${encodeURIComponent(purl)}&follow=none`, { method: "POST" }),
      env,
      waitCtx().ctx,
    );
    const body = JSON.parse((await res.text()).trim());
    assert.equal(body.severity, "benign");
    assert.equal(res.headers.get("X-Beamline-Source"), "cache");
    assert.equal(res.headers.get("X-Beamline-Follow"), "all");
    assert.equal(scan.hits.analyze, ran, "a cached miss bought an analysis we were already holding");
  } finally {
    await scan.close();
  }
});

// An analysis outlives the request that asked for it. Scan detaches the run
// from the connection that started it, so a caller who gives up at their own
// timeout leaves a verdict that is still coming and that nothing else will
// observe: the cache write fires from the decision line, and the decision line
// is only parsed while somebody is pulling the stream. Left alone, every
// abandoned analysis is bought twice — once by the caller who walked away, and
// again by whoever asks next.
test("v1 analyze: a caller that hangs up still leaves the verdict cached", async () => {
  const purl = "pkg:npm/app@1.0.0";
  let release = () => {};
  const decided = new Promise((resolve) => {
    release = resolve;
  });
  const scan = await mockBackend({
    // A progress frame, then the decision — with the caller's departure in
    // between, which is the whole point of the test.
    analyzeStream: () =>
      (async function* stream() {
        yield `{"state":"analyzing","purl":"${purl}","elapsed_ms":10,"phase":"unpack"}`;
        await decided;
        yield `{"decision":"allow","fires_at":-1,"purl":"${purl}","engine_version":"test"}`;
      })(),
  });
  const env = testEnv(DEAD, { SCAN_URL: scan.url });
  const hungUp = waitCtx();
  try {
    const res = await handle(
      new Request(`http://beamline/v1/analyze?purl=${encodeURIComponent(purl)}`, { method: "POST" }),
      env,
      hungUp.ctx,
    );
    const reader = res.body.getReader();
    const first = await reader.read();
    assert.match(new TextDecoder().decode(first.value), /"state":"analyzing"/);
    // The caller times out. No decision has been sent.
    await reader.cancel();
    // Scan finishes the run it was always going to finish.
    release();
    await hungUp.flush();

    const before = scan.hits.analyze;
    const next = await handle(
      new Request(`http://beamline/v1/analyze?purl=${encodeURIComponent(purl)}`, { method: "POST" }),
      env,
      waitCtx().ctx,
    );
    const body = JSON.parse((await next.text()).trim());
    assert.equal(body.status, "analyzed");
    assert.equal(body.fires_at, -1);
    assert.equal(
      scan.hits.analyze,
      before,
      "the abandoned analysis was not filed; the next caller paid for it again",
    );
    assert.equal(next.headers.get("X-Beamline-Source"), "cache");
  } finally {
    release();
    await scan.close();
  }
});

// An upload has no locator to file an answer under, so there is nothing to
// salvage and no reason to hold the worker's stream open for a caller who has
// gone. The reader is dropped, as it always was.
test("v1 analyze: an abandoned upload is dropped rather than drained", async () => {
  let released = false;
  let release = () => {};
  const decided = new Promise((resolve) => {
    release = () => {
      released = true;
      resolve();
    };
  });
  const scan = await mockBackend({
    analyzeStream: () =>
      (async function* stream() {
        yield '{"state":"analyzing","sha256":"' + HELLO_SHA + '","elapsed_ms":10,"phase":"unpack"}';
        await decided;
        yield '{"decision":"allow","fires_at":-1,"engine_version":"test"}';
      })(),
  });
  const env = testEnv(DEAD, { SCAN_URL: scan.url });
  const ctx = waitCtx();
  try {
    const res = await handle(
      new Request("http://beamline/v1/analyze", { method: "POST", body: "hello" }),
      env,
      ctx.ctx,
    );
    const reader = res.body.getReader();
    await reader.read();
    await reader.cancel();
    await ctx.flush();
    assert.equal(released, false, "an upload's stream was drained with nothing to file it under");
  } finally {
    release();
    await scan.close();
  }
});

// Scan applies the requested selection on top of its own configuration, so the
// policy that produced an answer is scan's to report. Filing under what we
// asked for rather than what it ran is how a fleet ends up with two services
// each holding a defensible default, disagreeing by one reference kind, and
// silently keeping nothing.
test("v1 analyze: the verdict is filed under the policy scan reports it applied", async () => {
  const purl = "pkg:npm/app@1.0.0";
  const verdict = {
    decision: "allow",
    purl,
    sha256: HELLO_SHA,
    severity: "benign",
    fires_at: -1,
    findings: [],
    engine_version: "test",
    analyzed_at: "2026-08-01T00:00:00Z",
  };
  const scan = await mockBackend({
    analyzeStream: [`{"decision":"allow","fires_at":-1,"purl":"${purl}","engine_version":"test"}`],
    analyzeHeaders: { "x-scan-follow": "all" },
    v1: () => verdict,
  });
  const env = testEnv(DEAD, { SCAN_URL: scan.url });
  const ctx = waitCtx();
  try {
    // Asked at the PURL default, which is `references`.
    await (
      await handle(
        new Request(`http://beamline/v1/analyze?purl=${encodeURIComponent(purl)}`, { method: "POST" }),
        env,
        ctx.ctx,
      )
    ).text();
    await ctx.flush();

    // Scan said it ran `all`, so `all` is the question this answer answers —
    // and asking it must not reach a worker. Filed under `references` instead,
    // this lookup would miss: `references` does not contain `all`.
    const before = scan.hits.v1;
    const wide = await handle(
      new Request(`http://beamline/v1/lookup?purl=${encodeURIComponent(purl)}&follow=all`),
      env,
      waitCtx().ctx,
    );
    await wide.json();
    assert.equal(wide.headers.get("X-Beamline-Source"), "cache");
    assert.equal(
      scan.hits.v1,
      before,
      "an answer scan produced at follow=all was filed under the policy we asked for",
    );
  } finally {
    await scan.close();
  }
});

// A worker too old to report its policy, and one that reports something this
// service cannot spell, are the same case: we know only what we resolved, so
// that is what the answer is filed under. An unparseable name is worse than an
// absent one — filed under it, the answer is unreachable by every later
// question — so it is ignored rather than trusted.
test("v1 analyze: an absent or unspellable reported policy falls back to our own", async () => {
  const purl = "pkg:npm/app@1.0.0";
  const verdict = {
    decision: "allow",
    purl,
    sha256: HELLO_SHA,
    severity: "benign",
    fires_at: -1,
    findings: [],
    engine_version: "test",
    analyzed_at: "2026-08-01T00:00:00Z",
  };
  for (const reported of [null, "sideways", "references,nonsense"]) {
    const scan = await mockBackend({
      analyzeStream: [`{"decision":"allow","fires_at":-1,"purl":"${purl}","engine_version":"test"}`],
      analyzeHeaders: reported ? { "x-scan-follow": reported } : undefined,
      v1: () => verdict,
    });
    const env = testEnv(DEAD, { SCAN_URL: scan.url });
    const ctx = waitCtx();
    try {
      await (
        await handle(
          new Request(`http://beamline/v1/analyze?purl=${encodeURIComponent(purl)}`, { method: "POST" }),
          env,
          ctx.ctx,
        )
      ).text();
      await ctx.flush();

      // Filed under `references`, which we resolved ourselves. It answers the
      // question we asked...
      const narrow = await handle(
        new Request(`http://beamline/v1/lookup?purl=${encodeURIComponent(purl)}`),
        env,
        waitCtx().ctx,
      );
      await narrow.json();
      assert.equal(
        narrow.headers.get("X-Beamline-Source"),
        "cache",
        `reported=${reported}: the answer was not filed under the policy we resolved`,
      );

      // ...and not the wider one nobody claimed to have run.
      const before = scan.hits.v1;
      await (
        await handle(
          new Request(`http://beamline/v1/lookup?purl=${encodeURIComponent(purl)}&follow=all`),
          env,
          waitCtx().ctx,
        )
      ).json();
      assert.equal(
        scan.hits.v1,
        before + 1,
        `reported=${reported}: an unclaimed wider policy was answered from cache`,
      );
    } finally {
      await scan.close();
    }
  }
});

// Every answer says how deep it had to go, on one scale, so a dashboard can
// average it and mean something by the number. Work is the largest value rather
// than a value outside the scale: the average is only a cost proxy if the most
// expensive outcome is also the deepest.
test("v1: every source reports the layer that served it", async () => {
  const { CACHE_LAYERS, beamlineSource } = _test;
  const cacheLayer = (source) => CACHE_LAYERS.get(source);
  assert.deepEqual(
    ["cache", "kv", "scan:index", "scan:cached", "scan:bloom", "scan:replica", "scan:primary", "scan:analysis"]
      .map(cacheLayer),
    [0, 1, 2, 2, 3, 4, 5, 6],
  );

  // Nothing answered is not a depth. Numbering it would pull the average
  // toward "cheap" exactly when the fleet cannot be reached.
  assert.equal(cacheLayer("none"), undefined);

  // A worker's index hit and a fresh run are the same route and used to be the
  // same value. They are the two ends of the scale.
  assert.notEqual(cacheLayer(beamlineSource("scan:index")), cacheLayer(beamlineSource("scan:analysis")));

  // An unrecognised source from a half-rolled deployment counts as work. It
  // overstates the bill rather than the hit rate, which is the direction that
  // gets looked at.
  assert.equal(cacheLayer(beamlineSource("something-new")), 6);
  // ...and the pre-split spelling of a held verdict still reads as one.
  assert.equal(cacheLayer(beamlineSource("index")), 2);
});

// The two headers are one fact. Four routes report a source — two lookup
// layers, the analyze cache hit, and the streamed answer — and a depth missing
// from any of them is a hole in the metric exactly where the traffic is.
test("v1: the layer travels with the source on every route that reports one", async () => {
  const purl = "pkg:npm/app@1.0.0";
  const verdict = {
    decision: "allow",
    purl,
    sha256: HELLO_SHA,
    severity: "benign",
    fires_at: -1,
    findings: [],
    engine_version: "test",
    analyzed_at: "2026-08-01T00:00:00Z",
  };
  const scan = await mockBackend({
    v1: () => verdict,
    v1Headers: { "x-scan-source": "scan:index" },
    analyzeStream: [`{"decision":"allow","fires_at":-1,"purl":"${purl}","engine_version":"test"}`],
  });
  const env = testEnv(DEAD, { SCAN_URL: scan.url });
  try {
    // Straight from a worker: the source scan reported, at its own depth.
    const fromWorker = await handle(
      new Request(`http://beamline/v1/lookup?purl=${encodeURIComponent(purl)}`),
      env,
      waitCtx().ctx,
    );
    await fromWorker.json();
    assert.equal(fromWorker.headers.get("X-Beamline-Source"), "scan:index");
    assert.equal(fromWorker.headers.get("X-Cache-Layer"), "2");

    // The same answer a moment later, now held at the edge.
    const warm = waitCtx();
    await (
      await handle(
        new Request(`http://beamline/v1/lookup?purl=${encodeURIComponent(purl)}`),
        env,
        warm.ctx,
      )
    ).json();
    await warm.flush();
    const fromCache = await handle(
      new Request(`http://beamline/v1/lookup?purl=${encodeURIComponent(purl)}`),
      env,
      waitCtx().ctx,
    );
    await fromCache.json();
    assert.equal(fromCache.headers.get("X-Beamline-Source"), "cache");
    assert.equal(fromCache.headers.get("X-Cache-Layer"), "0");

    // And on analyze, which is the route where a layer is worth real money.
    const analyzed = await handle(
      new Request(`http://beamline/v1/analyze?purl=${encodeURIComponent(purl)}`, { method: "POST" }),
      env,
      waitCtx().ctx,
    );
    await analyzed.text();
    assert.equal(
      analyzed.headers.get("X-Cache-Layer"),
      String(_test.CACHE_LAYERS.get(analyzed.headers.get("X-Beamline-Source"))),
      "the analyze route reported a source without its depth",
    );
  } finally {
    await scan.close();
  }
});

// A Worker cannot be scraped, so the metric is written rather than exposed.
// What matters is that the point and the reply cannot disagree: the datapoint is
// read back off the response, so a caller told one thing and a dashboard told
// another is not a state this can reach.
test("v1: every request writes one datapoint carrying what the caller was told", async () => {
  const purl = "pkg:npm/app@1.0.0";
  const points = [];
  const scan = await mockBackend({
    v1: () => ({
      decision: "allow",
      purl,
      sha256: HELLO_SHA,
      severity: "benign",
      fires_at: -1,
      findings: [],
      engine_version: "test",
      analyzed_at: "2026-08-01T00:00:00Z",
    }),
    v1Headers: { "x-scan-source": "scan:index" },
  });
  const env = {
    ...testEnv(DEAD, { SCAN_URL: scan.url }),
    BEAMLINE_AE: { writeDataPoint: (p) => points.push(p) },
  };
  try {
    const res = await handle(
      new Request(`http://beamline/v1/lookup?purl=${encodeURIComponent(purl)}`),
      env,
      waitCtx().ctx,
    );
    await res.json();

    assert.equal(points.length, 1, "a request wrote no datapoint, or wrote more than one");
    const [route, source, follow, worker, eco, status] = points[0].blobs;
    const [layer, ms] = points[0].doubles;
    assert.equal(route, "lookup");
    // The point says exactly what the reply said. Not what the code that
    // produced the answer believed — what went out.
    assert.equal(source, res.headers.get("X-Beamline-Source"));
    assert.equal(String(layer), res.headers.get("X-Cache-Layer"));
    assert.equal(worker, res.headers.get("X-Beamline-Worker") || "");
    assert.equal(follow, res.headers.get("X-Beamline-Follow") || "");
    assert.equal(eco, "npm");
    assert.equal(status, "200");
    assert.ok(ms >= 0 && Number.isFinite(ms), `ms was ${ms}`);

    // No index: the only high-cardinality field would be the caller's PURL, and
    // an analytics dataset is not where a customer's dependency list belongs.
    assert.equal(points[0].indexes, undefined);
    assert.ok(
      !JSON.stringify(points[0]).includes("app@1.0.0"),
      "the datapoint named the caller's package",
    );
  } finally {
    await scan.close();
  }
});

// Nothing answered is not a cheap answer. Recorded as -1 so an average over the
// layer is not dragged toward the edge exactly when the fleet is unreachable.
test("v1: a request nothing answered records no layer rather than a shallow one", async () => {
  const points = [];
  const env = {
    ...testEnv(DEAD, { SCAN_URL: DEAD }),
    BEAMLINE_AE: { writeDataPoint: (p) => points.push(p) },
  };
  const res = await handle(
    new Request("http://beamline/v1/lookup?purl=pkg%3Anpm%2Fapp%401.0.0"),
    env,
    waitCtx().ctx,
  );
  await res.json();
  assert.equal(points.length, 1);
  assert.equal(res.headers.get("X-Beamline-Source"), "none");
  assert.equal(res.headers.get("X-Cache-Layer"), null, "`none` is not a depth");
  assert.equal(points[0].doubles[0], -1);
});

// The binding is absent under `node local.js` and in most tests. A telemetry
// call that throws there would take the request with it.
test("v1: a deployment without the dataset serves requests unchanged", async () => {
  const env = testEnv(DEAD, { SCAN_URL: DEAD });
  assert.equal(env.BEAMLINE_AE, undefined);
  const res = await handle(
    new Request("http://beamline/v1/lookup?purl=pkg%3Anpm%2Fapp%401.0.0"),
    env,
    waitCtx().ctx,
  );
  assert.equal(res.status, 200);
  // And a binding that is present but not callable is ignored the same way.
  const broken = { ...env, BEAMLINE_AE: {} };
  assert.equal(
    (await handle(new Request("http://beamline/v1/lookup?purl=pkg%3Anpm%2Fapp%401.0.0"), broken, waitCtx().ctx)).status,
    200,
  );
});

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
    assert.equal(lines.length, 5, "the caller was handed the annotated run and answer");
    const unpackStarted = JSON.parse(lines[0]);
    const unpackCompleted = JSON.parse(lines[1]);
    const modelStarted = JSON.parse(lines[2]);
    const modelCompleted = JSON.parse(lines[3]);
    assert.equal(unpackStarted.phase, "unpack");
    assert.equal(unpackStarted.phase_state, "started");
    assert.equal(unpackStarted.phase_elapsed_ms, 0);
    assert.equal(unpackStarted.total_elapsed_ms, 1002);
    assert.equal(unpackStarted.request_id.length > 0, true);
    assert.equal(unpackCompleted.phase, "unpack");
    assert.equal(unpackCompleted.phase_state, "completed");
    assert.equal(unpackCompleted.phase_elapsed_ms, 5002);
    assert.equal(modelStarted.phase, "features+model");
    assert.equal(modelStarted.phase_state, "started");
    assert.equal(modelCompleted.phase, "features+model");
    assert.equal(modelCompleted.phase_state, "completed");
    assert.equal(JSON.parse(lines[4]).status, "analyzed");
  } finally {
    await scan.close();
  }
});

// The analysis itself may run for minutes. It belongs to the response stream,
// which keeps the invocation alive while the caller is connected; waitUntil's
// short post-response budget is reserved for filing the completed decision.
test("v1 analyze: waitUntil starts only after the terminal decision", async () => {
  let releaseDecision;
  const held = new Promise((resolve) => { releaseDecision = resolve; });
  let finishStream;
  const streamHeld = new Promise((resolve) => { finishStream = resolve; });
  const scan = await mockBackend({
    analyzeStream: async function* () {
      yield '{"state":"analyzing","purl":"pkg:npm/slow@1.0.0","elapsed_ms":1002,"phase":"unpack"}';
      await held;
      yield '{"decision":"allow","fires_at":-1,"purl":"pkg:npm/slow@1.0.0","engine_version":"test"}';
      await streamHeld;
    },
  });
  const env = testEnv(DEAD, { SCAN_URL: scan.url });
  const ctx = waitCtx();
  try {
    const res = await handle(
      new Request("http://beamline/v1/analyze?purl=pkg%3Anpm%2Fslow%401.0.0", { method: "POST" }),
      env,
      ctx.ctx,
    );
    const reader = res.body.getReader();
    const decoder = new TextDecoder();
    const first = await reader.read();
    assert.match(decoder.decode(first.value, { stream: true }), /"state":"analyzing"/);
    assert.equal(ctx.pending(), 0, "the in-flight analysis was registered as background work");

    releaseDecision();
    let tail = "";
    while (!tail.includes('"status":"analyzed"')) {
      const { value } = await reader.read();
      tail += decoder.decode(value, { stream: true });
    }
    assert.match(tail, /"status":"analyzed"/);
    assert.equal(ctx.pending(), 1, "the completed decision did not schedule its cache write");
    await reader.cancel();
    await ctx.flush();

    const looked = await handle(
      new Request("http://beamline/v1/lookup?purl=pkg%3Anpm%2Fslow%401.0.0"),
      env,
      noopCtx(),
    );
    assert.equal(looked.headers.get("x-beamline-source"), "cache");
    assert.equal((await looked.json()).status, "analyzed");
  } finally {
    releaseDecision();
    finishStream();
    await scan.close();
  }
});

test("v1 analyze: canceling before a decision schedules no cache work", async () => {
  const encoder = new TextEncoder();
  let sourceCanceled = false;
  let completed = 0;
  const source = new ReadableStream({
    start(controller) {
      controller.enqueue(encoder.encode('{"state":"analyzing","elapsed_ms":1002,"phase":"unpack"}\n'));
    },
    cancel() {
      sourceCanceled = true;
    },
  });
  const reader = _test.annotatedV1Stream(
    source,
    25,
    { requestId: "test", locator: { type: "purl", value: "pkg:npm/slow@1.0.0" }, startedAt: Date.now() },
    () => { completed += 1; },
  ).getReader();

  await reader.read();
  await reader.cancel();
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(sourceCanceled, true, "cancel did not propagate to the upstream stream");
  assert.equal(completed, 0, "a canceled stream was treated as complete");
});

test("v1 analyze: an omitted upstream phase is explicit and correlated", async () => {
  const scan = await mockBackend({
    analyzeStream: [
      '{"state":"analyzing","purl":"pkg:npm/slow@1.0.0","elapsed_ms":100,"phase":null}',
      '{"decision":"allow","fires_at":-1,"purl":"pkg:npm/slow@1.0.0"}',
    ],
  });
  const env = testEnv(DEAD, { SCAN_URL: scan.url });
  try {
    const res = await handle(
      new Request("http://beamline/v1/analyze?purl=pkg%3Anpm%2Fslow%401.0.0", { method: "POST" }),
      env,
      waitCtx().ctx,
    );
    const lines = (await res.text()).trim().split("\n").map(JSON.parse);
    assert.equal(lines[0].phase, "unknown");
    assert.equal(lines[0].phase_state, "started");
    assert.equal(lines[1].phase_state, "completed");
    assert.equal(lines[2].status, "analyzed");
    assert.equal("phase" in lines[0], true);
    assert.notEqual(lines[0].phase, null);
  } finally {
    await scan.close();
  }
});

test("v1 analyze: semantic scan phases reach the caller", async () => {
  const scan = await mockBackend({
    analyzeStream: [
      '{"state":"analyzing","purl":"pkg:npm/slow@1.0.0","elapsed_ms":100,"phase":"purl:registry"}',
      '{"state":"analyzing","purl":"pkg:npm/slow@1.0.0","elapsed_ms":500,"phase":"purl:payload"}',
      '{"state":"analyzing","purl":"pkg:npm/slow@1.0.0","elapsed_ms":900,"phase":"fetch+graft"}',
      '{"state":"analyzing","purl":"pkg:npm/slow@1.0.0","elapsed_ms":1200,"phase":"features+model"}',
      '{"decision":"allow","fires_at":-1,"purl":"pkg:npm/slow@1.0.0"}',
    ],
  });
  const env = testEnv(DEAD, { SCAN_URL: scan.url });
  try {
    const res = await handle(
      new Request("http://beamline/v1/analyze?purl=pkg%3Anpm%2Fslow%401.0.0", { method: "POST" }),
      env,
      waitCtx().ctx,
    );
    const phases = (await res.text())
      .trim()
      .split("\n")
      .map(JSON.parse)
      .filter((row) => row.state === "analyzing" && row.phase_state === "started")
      .map((row) => row.phase);
    assert.deepEqual(phases, ["purl:registry", "purl:payload", "fetch+graft", "features+model"]);
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
    assert.equal(JSON.parse((await res.text()).trim()).status, "analyzed");
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
    v1: () => ({ decision: "unanalyzed", purl: "pkg:npm/evil@1.0.0", sha256: null, severity: null, fires_at: null, reason: null, findings: [], engine_version: null, analyzed_at: null }),
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
    assert.equal((await looked.json()).status, "analyzed", "the lookup did not see what the analysis found");
  } finally {
    await scan.close();
  }
});

// A stream that ends without a decision was cut short. Caching it would turn
// one dropped connection into a wrong answer served from the edge for an hour.
test("v1 analyze: a truncated stream is not cached", async () => {
  const scan = await mockBackend({
    analyzeStream: ['{"state":"analyzing","purl":"pkg:npm/half@1.0.0","elapsed_ms":1002,"phase":"unpack"}'],
    v1: () => ({ decision: "unanalyzed", purl: "pkg:npm/half@1.0.0", sha256: null, severity: null, fires_at: null, reason: null, findings: [], engine_version: null, analyzed_at: null }),
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
    assert.equal(ctx.pending(), 0, "a stream with no decision scheduled cache work");
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
    v1: () => ({ decision: "unanalyzed", purl: "pkg:npm/evil@1.0.0", sha256: null, severity: null, fires_at: null, reason: null, findings: [], engine_version: null, analyzed_at: null }),
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
    assert.equal((await looked.json()).status, "analyzed");
  } finally {
    await scan.close();
  }
});

// /v1/analyze is the expensive door into the question /v1/lookup asks cheaply.
// Asking it twice for the same package used to cost two full analyses, because
// nothing on the path ever looked at the cache the first one had warmed.
test("v1 analyze: a verdict already cached is answered without a second analysis", async () => {
  const scan = await mockBackend({
    analyzeStream: ['{"decision":"block","fires_at":3,"purl":"pkg:npm/evil@1.0.0","engine_version":"2.8.0"}'],
    v1: () => ({ decision: "unanalyzed", purl: "pkg:npm/evil@1.0.0", sha256: null, severity: null, fires_at: null, reason: null, findings: [], engine_version: null, analyzed_at: null }),
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
    assert.equal(JSON.parse(body.trim()).status, "analyzed", "the cached answer was not the verdict");
    assert.equal(body.endsWith("\n"), true, "an NDJSON answer must end its line");
  } finally {
    await scan.close();
  }
});

// `unanalyzed` is cacheable — briefly, and for the lookup's benefit — and it is
// not an analysis. Serving it here would answer "nobody has analyzed this" to
// a caller who just asked us to analyze it.
test("v1 analyze: a cached `unanalyzed` is not an answer to `analyze`", async () => {
  const scan = await mockBackend({
    analyzeStream: ['{"decision":"allow","fires_at":-1,"purl":"pkg:npm/fresh@1.0.0"}'],
    v1: () => ({ decision: "unanalyzed", purl: "pkg:npm/fresh@1.0.0", sha256: null, severity: null, fires_at: null, reason: null, findings: [], engine_version: null, analyzed_at: null }),
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
    assert.equal(warm.headers.get("x-beamline-source"), "cache", "precondition: the unanalyzed row was cached");

    const analyzed = await handle(
      new Request("http://beamline/v1/analyze?purl=pkg%3Anpm%2Ffresh%401.0.0", { method: "POST" }),
      env,
      waitCtx().ctx,
    );
    const body = await analyzed.text();
    assert.equal(scan.hits.analyze, 1, "a cached `unanalyzed` was served instead of analysing");
    assert.equal(JSON.parse(body.trim()).status, "analyzed");
  } finally {
    await scan.close();
  }
});

// The guard is `engine_version`, not the spelling of the decision. Nothing an
// engine of ours did not produce may stand in for an analysis, whatever it
// calls itself — which is what makes the rename survivable in either deploy
// order: a worker still saying `unknown` is rejected on the same test that
// rejects `unanalyzed`, rather than being mistaken for a verdict and filed as
// one for ninety days.
test("v1 analyze: a row no engine produced is never a verdict, whatever it is called", async () => {
  for (const decision of ["unanalyzed", "unknown"]) {
    const purl = "pkg:npm/lagging@1.0.0";
    const scan = await mockBackend({
      analyzeStream: [`{"decision":"allow","fires_at":-1,"purl":"${purl}","engine_version":"2.8.0"}`],
      v1: () => ({ decision, purl, sha256: null, severity: null, fires_at: null, reason: null, findings: [], engine_version: null, analyzed_at: null }),
    });
    const env = testEnv(DEAD, { SCAN_URL: scan.url });
    const ctx = waitCtx();
    try {
      await (await handle(new Request(`http://beamline/v1/lookup?purl=${encodeURIComponent(purl)}`), env, ctx.ctx)).text();
      await ctx.flush();
      const warm = await handle(new Request(`http://beamline/v1/lookup?purl=${encodeURIComponent(purl)}`), env, noopCtx());
      assert.equal(warm.headers.get("x-beamline-source"), "cache", `${decision}: precondition: the row was cached`);
      assert.match(warm.headers.get("cache-control"), /max-age=60/, `${decision}: cached on the long clock`);

      const analyzed = await handle(
        new Request(`http://beamline/v1/analyze?purl=${encodeURIComponent(purl)}`, { method: "POST" }),
        env,
        waitCtx().ctx,
      );
      const body = await analyzed.text();
      assert.equal(scan.hits.analyze, 1, `${decision}: served as a verdict instead of analysing`);
      assert.equal(JSON.parse(body.trim()).status, "analyzed", decision);
    } finally {
      await scan.close();
    }
  }
});

// An upload is a request to analyze *those bytes*. The PURL riding along with
// one names provenance, not the thing being asked about, so a verdict cached
// under it cannot stand in for the artifact in hand.
test("v1 analyze: an upload is analysed even when its PURL has a cached verdict", async () => {
  const scan = await mockBackend({
    analyzeStream: ['{"decision":"block","fires_at":3,"purl":"pkg:npm/evil@1.0.0"}'],
    v1: () => ({ decision: "unanalyzed", purl: "pkg:npm/evil@1.0.0", sha256: null, severity: null, fires_at: null, reason: null, findings: [], engine_version: null, analyzed_at: null }),
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
    v1: () => ({ decision: "unanalyzed", purl: "pkg:npm/evil@1.0.0", sha256: null, severity: null, fires_at: null, reason: null, findings: [], engine_version: null, analyzed_at: null }),
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
    assert.equal((await bySha.json()).status, "analyzed");

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
    v1: () => ({ decision: "unanalyzed", purl: "pkg:npm/evil@1.0.0", sha256: null, severity: null, fires_at: null, reason: null, findings: [], engine_version: null, analyzed_at: null }),
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
    assert.equal((await looked.json()).status, "analyzed");
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
      decision: "unanalyzed", purl: "pkg:npm/nobody@1.0.0", sha256: null, severity: null,
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
    assert.match(fresh.headers.get("cache-control"), /max-age=60/, "an unanalyzed row must go out short-lived");
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

// `unknown` was the old scan spelling of `unanalyzed`. Existing L0 and KV
// entries should survive that rename, but a live worker still using it must
// remain visible so the contract probe catches a partial or bad deployment.
test("v1: legacy unknown is normalized only when read from cache", async () => {
  const purl = "pkg:npm/legacy-unknown@1.0.0";
  const stored = new Map();
  const kv = {
    async get(key) { return stored.get(key) || null; },
    async put(key, value) { stored.set(key, value); },
  };
  const scan = await mockBackend({
    v1: () => ({
      decision: "unknown", purl, sha256: null, severity: null, fires_at: null,
      reason: null, findings: [], engine_version: null, analyzed_at: null,
    }),
  });
  const cache = _test.memoryCache();
  const env = testEnv(DEAD, { SCAN_URL: scan.url, BEAMLINE_KV: kv, cache });
  const ctx = waitCtx();
  try {
    const live = await handle(
      new Request(`http://beamline/v1/lookup?purl=${encodeURIComponent(purl)}`),
      env,
      ctx.ctx,
    );
    assert.equal((await live.json()).status, "unknown", "a live contract violation was hidden");
    await ctx.flush();

    const l0 = await handle(
      new Request(`http://beamline/v1/lookup?purl=${encodeURIComponent(purl)}`),
      env,
      noopCtx(),
    );
    assert.equal(l0.headers.get("x-beamline-source"), "cache");
    assert.equal((await l0.json()).status, "unanalyzed");

    assert.ok(
      [...stored.values()].some((value) => JSON.parse(value).status === "unknown"),
      "the migration rewrote stored data instead of normalizing the read",
    );
    const kvEnv = testEnv(DEAD, { SCAN_URL: scan.url, BEAMLINE_KV: kv, cache: _test.memoryCache() });
    const l1 = await handle(
      new Request(`http://beamline/v1/lookup?purl=${encodeURIComponent(purl)}`),
      kvEnv,
      noopCtx(),
    );
    assert.equal(l1.headers.get("x-beamline-source"), "kv");
    assert.equal((await l1.json()).status, "unanalyzed");
  } finally {
    await scan.close();
  }
});

// A lookup that reached a worker has just learned the artifact's identity. The
// next caller who knows only that identity should not have to reach a worker to
// learn the same thing.
test("v1 lookup: an answer from scan is filed under its digest too", async () => {
  const sha = "c3d4e5f6".repeat(8);
  const scan = await mockBackend({
    v1: () => ({
      decision: "block", purl: "pkg:npm/evil@1.0.0", sha256: sha, severity: "malicious",
      fires_at: 3, reason: null, findings: [], engine_version: "2.8.0", analyzed_at: "2026-08-01T00:00:00Z",
    }),
  });
  const cache = _test.memoryCache();
  const env = testEnv(DEAD, { SCAN_URL: scan.url, cache });
  const ctx = waitCtx();
  try {
    await (await handle(
      new Request("http://beamline/v1/lookup?purl=pkg%3Anpm%2Fevil%401.0.0"),
      env,
      ctx.ctx,
    )).text();
    await ctx.flush();

    const byDigest = await handle(
      new Request(`http://beamline/v1/lookup?sha256=${sha}`),
      env,
      noopCtx(),
    );
    assert.equal(byDigest.headers.get("x-beamline-source"), "cache", "the digest door was left shut");
    assert.equal((await byDigest.json()).status, "analyzed");
    assert.equal(scan.hits.v1, 1, "the digest lookup cost a second trip to a worker");
  } finally {
    await scan.close();
  }
});

// Answering /v1/analyze from cache returns before the warm-write ever runs, so
// a warm PURL key used to leave the digest key cold indefinitely — and
// answering those callers never fixed it either.
test("v1 analyze: answering from cache still opens the digest door", async () => {
  const sha = "d4e5f6a7".repeat(8);
  const decision = JSON.stringify({
    decision: "block", purl: "pkg:npm/evil@1.0.0", sha256: sha, severity: "malicious",
    fires_at: 3, reason: null, findings: [], engine_version: "2.8.0", analyzed_at: "2026-08-01T00:00:00Z",
  });
  const cache = _test.memoryCache();
  // The state this exists for: the PURL key warm, the digest key cold. Both at
  // `references`, the policy a PURL with no stated one resolves to.
  await cache.put(
    new Request("http://beamline/v1/lookup?purl=pkg%3Anpm%2Fevil%401.0.0&follow=references"),
    new Response(decision, {
      status: 200,
      headers: { "content-type": "application/json", "cache-control": "public, max-age=3600" },
    }),
  );
  const scan = await mockBackend({ analyzeStream: [decision] });
  const env = testEnv(DEAD, { SCAN_URL: scan.url, cache });
  const ctx = waitCtx();
  try {
    const analyzed = await handle(
      new Request("http://beamline/v1/analyze?purl=pkg%3Anpm%2Fevil%401.0.0", { method: "POST" }),
      env,
      ctx.ctx,
    );
    assert.equal(analyzed.headers.get("x-beamline-source"), "cache", "precondition: it was answered from cache");
    await analyzed.text();
    await ctx.flush();
    assert.equal(scan.hits.analyze, 0, "precondition: no analysis was dispatched");

    const filed = await cache.match(new Request(`http://beamline/v1/lookup?sha256=${sha}&follow=references`));
    assert.ok(filed, "the digest key was left cold by an answer that named the digest");
    assert.equal(JSON.parse(await filed.text()).status, "analyzed");
  } finally {
    await scan.close();
  }
});

// The check before the write is the point. Rewriting a key every time it is read
// would refresh its TTL forever, and an entry that never ages is pinned rather
// than cached — a verdict is allowed to go stale on schedule.
test("v1 analyze: the digest back-fill never refreshes an entry already there", async () => {
  const sha = "e5f6a7b8".repeat(8);
  const decision = JSON.stringify({
    decision: "block", purl: "pkg:npm/evil@1.0.0", sha256: sha, severity: "malicious",
    fires_at: 3, reason: null, findings: [], engine_version: "2.8.0", analyzed_at: "2026-08-01T00:00:00Z",
  });
  const inner = _test.memoryCache();
  let puts = 0;
  const cache = {
    match: (req) => inner.match(req),
    put: (req, res) => {
      puts += 1;
      return inner.put(req, res);
    },
  };
  const key = (q) => new Request(`http://beamline/v1/lookup?${q}`);
  const stored = (body) =>
    new Response(body, {
      status: 200,
      headers: { "content-type": "application/json", "cache-control": "public, max-age=3600" },
    });
  await inner.put(key("purl=pkg%3Anpm%2Fevil%401.0.0&follow=references"), stored(decision));
  await inner.put(key(`sha256=${sha}&follow=references`), stored(decision));

  const scan = await mockBackend({ analyzeStream: [decision] });
  const env = testEnv(DEAD, { SCAN_URL: scan.url, cache });
  try {
    for (let i = 0; i < 3; i++) {
      const ctx = waitCtx();
      const res = await handle(
        new Request("http://beamline/v1/analyze?purl=pkg%3Anpm%2Fevil%401.0.0", { method: "POST" }),
        env,
        ctx.ctx,
      );
      assert.equal(res.headers.get("x-beamline-source"), "cache");
      await res.text();
      await ctx.flush();
    }
    assert.equal(puts, 0, `a cache hit rewrote its own keys ${puts} times, which pins them alive`);
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
    assert.equal(JSON.parse((await res.text()).trim()).status, "analyzed", "the reconnect started a second analysis");
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
    assert.equal(JSON.parse((await res.text()).trim()).status, "analyzed", "gave up while the fleet was merely busy");
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
  assert.equal(JSON.parse((await res.text()).trim()).status, "unavailable");
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
  assert.equal(body.status, "unavailable");
  assert.notEqual(body.status, "unanalyzed", "an outage was reported as a fact about the package");
  assert.equal(body.fires_at, undefined);
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
    const body = await res.json();
    assert.equal(body.status, "analyzed");
    assert.equal(body.purl, decided.purl);
    assert.equal(body.sha256, decided.sha256);
    assert.equal(body.severity, decided.severity);
    assert.equal(body.fires_at, decided.fires_at);
    assert.equal(body.reason, decided.reason);
    assert.deepEqual(body.findings, decided.findings);
    assert.equal(body.engine_version, decided.engine_version);
    assert.equal(body.analyzed_at, decided.analyzed_at);
    assert.equal(res.headers.get("x-beamline-source"), "scan:analysis");
  } finally {
    await scan.close();
  }
});

test("v1: scan source is exposed as the single Beamline source header", async () => {
  const scan = await mockBackend({
    v1: {
      decision: "allow",
      purl: "pkg:npm/replica@1.0.0",
      sha256: HELLO_SHA,
      severity: "benign",
      fires_at: -1,
      reason: null,
      findings: [],
      engine_version: "2.8.0",
      analyzed_at: "2026-08-01T00:00:00Z",
    },
    v1Headers: { "x-scan-source": "scan:replica" },
  });
  const env = testEnv(DEAD, { SCAN_URL: scan.url });
  try {
    const res = await handle(
      new Request("http://beamline/v1/lookup?purl=pkg%3Anpm%2Freplica%401.0.0"),
      env,
      waitCtx().ctx,
    );
    assert.equal(res.headers.get("x-beamline-source"), "scan:replica");
  } finally {
    await scan.close();
  }
});

test("v1: Bloom source is exposed as a derived Beamline source", async () => {
  const scan = await mockBackend({
    v1: {
      decision: "unanalyzed",
      purl: "pkg:npm/bloom@1.0.0",
      sha256: null,
      severity: null,
      fires_at: null,
      reason: null,
      findings: [],
      engine_version: null,
      analyzed_at: null,
    },
    v1Headers: { "x-scan-source": "scan:bloom" },
  });
  const env = testEnv(DEAD, { SCAN_URL: scan.url });
  try {
    const res = await handle(
      new Request("http://beamline/v1/lookup?purl=pkg%3Anpm%2Fbloom%401.0.0"),
      env,
      waitCtx().ctx,
    );
    assert.equal(res.headers.get("x-beamline-source"), "scan:bloom");
  } finally {
    await scan.close();
  }
});

// A verdict is immutable for the engine that produced it, so it caches for an
// hour. Not knowing is not: it stops being true the moment anything analyzes
// the artifact, which on this route is often seconds later.
test("v1: a verdict caches for longer than an absence", async () => {
  const scan = await mockBackend({
    v1: (u) => {
      const analyzed = u.searchParams.get("purl").includes("evil");
      return {
        decision: analyzed ? "block" : "unanalyzed",
        purl: u.searchParams.get("purl"),
        sha256: null,
        severity: null,
        fires_at: null,
        reason: null,
        findings: [],
        // An engine is what makes it a verdict. Absent, this is a record no
        // engine produced — an absence, or a level derived from threat-feed
        // citations — and both age out on the short schedule.
        engine_version: analyzed ? "2.8.0" : null,
        analyzed_at: null,
      };
    },
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

// The document is stored once. Beamline applies each caller's budget to its
// measured fires_at value, and scan never has to produce budget-shaped copies.
test("v1: beamline applies the budget and stores one document", async () => {
  let asked = 0;
  let scanReceivedBudget = false;
  const scan = await mockBackend({
    v1: (u) => {
      asked += 1;
      scanReceivedBudget = u.searchParams.has("false_positive_budget");
      return {
        decision: "allow",
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
    return (await res.json()).severity;
  };
  try {
    assert.equal(await ask(25), "suspicious");
    assert.equal(await ask(1000), "hostile", "beamline did not apply the caller's budget");
    assert.equal(asked, 1, "different budgets caused duplicate origin work");
    assert.equal(scanReceivedBudget, false, "the budget was delegated to scan");
    // And the same document is served from cache rather than re-asked.
    assert.equal(await ask(25), "suspicious");
    assert.equal(asked, 1, "a cached document was asked again");
  } finally {
    await scan.close();
  }
});

test("v1: KV is L1 behind Cache API and still applies the budget", async () => {
  let reads = 0;
  let writes = 0;
  const document = JSON.stringify({
    decision: "allow",
    purl: "pkg:npm/kv@1.0.0",
    sha256: null,
    severity: "suspicious",
    fires_at: 500,
    reason: null,
    findings: [],
    engine_version: "2.8.0",
    analyzed_at: "2026-08-01T00:00:00Z",
  });
  const kv = {
    async get() {
      reads += 1;
      return document;
    },
    async put() {
      writes += 1;
    },
  };
  const env = testEnv(DEAD, { SCAN_URL: DEAD, BEAMLINE_KV: kv });
  const ask = async (budget) => {
    const ctx = waitCtx();
    const res = await handle(
      new Request(`http://beamline/v1/lookup?purl=pkg%3Anpm%2Fkv%401.0.0&false_positive_budget=${budget}`),
      env,
      ctx.ctx,
    );
    await ctx.flush();
    return res;
  };

  const strict = await ask(25);
  assert.equal(strict.headers.get("x-beamline-source"), "kv");
  assert.equal((await strict.json()).severity, "suspicious");
  const loose = await ask(1000);
  assert.equal(loose.headers.get("x-beamline-source"), "cache");
  assert.equal((await loose.json()).severity, "hostile");
  assert.equal(reads, 1, "the L0 cache should shield KV after the first read");
  assert.equal(writes, 0, "a KV read should not refresh the stored value");
});

// Every KV write carries an expiry. Written without one a verdict is stored
// forever, and a key whose spelling stops being read — an engine that moved on,
// a policy nobody asks for — is never reclaimed, because a key nobody reads is
// a key nobody misses.
test("v1: KV writes expire, a verdict on the long clock and an unanalyzed row on the short one", async () => {
  const purl = "pkg:npm/ttl@1.0.0";
  const cases = [
    ["verdict", { decision: "allow", severity: "benign", fires_at: -1, engine_version: "2.8.0" }, 90 * 24 * 60 * 60],
    ["unanalyzed", { decision: "unanalyzed", severity: null, fires_at: null, engine_version: null }, 60],
  ];
  for (const [label, row, expected] of cases) {
    const ttls = [];
    const kv = {
      async get() { return null; },
      async put(_key, _body, options) { ttls.push(options && options.expirationTtl); },
    };
    const scan = await mockBackend({
      v1: () => ({ purl, sha256: HELLO_SHA, reason: null, findings: [], analyzed_at: "2026-08-01T00:00:00Z", ...row }),
    });
    const env = testEnv(DEAD, { SCAN_URL: scan.url, BEAMLINE_KV: kv });
    const ctx = waitCtx();
    try {
      const res = await handle(
        new Request(`http://beamline/v1/lookup?purl=${encodeURIComponent(purl)}`),
        env,
        ctx.ctx,
      );
      assert.equal(res.status, 200, label);
      await res.json();
      await ctx.flush();
      assert.ok(ttls.length > 0, `${label}: nothing reached KV`);
      for (const ttl of ttls) assert.equal(ttl, expected, `${label}: stored without the expected expiry`);
    } finally {
      await scan.close();
    }
  }
});

test("v1: exact URL aliases the URL, PURL, and SHA cache keys within its policy", async () => {
  const artifactUrl = "https://registry.example.test/npm/app/-/app-1.0.0.tgz";
  const purl = "pkg:npm/app@1.0.0";
  let forwarded;
  const scan = await mockBackend({
    v1: (url) => {
      forwarded = url;
      return {
        decision: "allow",
        purl,
        sha256: HELLO_SHA,
        severity: "benign",
        fires_at: -1,
        reason: null,
        findings: [],
        engine_version: "2.8.0",
        analyzed_at: "2026-08-01T00:00:00Z",
      };
    },
  });
  const env = testEnv(DEAD, { SCAN_URL: scan.url });
  try {
    const firstCtx = waitCtx();
    const first = await handle(
      new Request(`http://beamline/v1/lookup?url=${encodeURIComponent(artifactUrl)}`),
      env,
      firstCtx.ctx,
    );
    assert.equal(first.headers.get("x-beamline-source"), "scan:analysis");
    assert.equal((await first.json()).url, artifactUrl);
    assert.equal(forwarded.searchParams.get("url"), artifactUrl);
    await firstCtx.flush();

    // Every name for the artifact, all asking the question the URL lookup
    // answered. A URL resolves to `follow=none`, so that is where the answer is
    // filed under each of them.
    for (const query of [
      `url=${encodeURIComponent(artifactUrl)}&follow=none`,
      `purl=${encodeURIComponent(purl)}&follow=none`,
      `sha256=${HELLO_SHA}&follow=none`,
    ]) {
      const res = await handle(new Request(`http://beamline/v1/lookup?${query}`), env, noopCtx());
      assert.equal(res.status, 200, query);
      assert.equal(res.headers.get("x-beamline-source"), "cache", query);
      const body = await res.json();
      assert.equal(body.sha256, HELLO_SHA, query);
      if (query.startsWith("url=")) assert.equal(body.url, artifactUrl);
      else assert.equal(body.url, undefined);
    }
    assert.equal(scan.hits.v1, 1, "aliases should prevent a second scan lookup");

    // Names alias, policies do not. A PURL with no stated policy asks about the
    // dependency graph's install commands; this answer followed nothing, and
    // serving it there would answer a question nobody got an analysis for.
    const byDefault = await handle(
      new Request(`http://beamline/v1/lookup?purl=${encodeURIComponent(purl)}`),
      env,
      noopCtx(),
    );
    assert.notEqual(
      byDefault.headers.get("x-beamline-source"),
      "cache",
      "a follow=none answer was served to a caller asking the PURL's own question",
    );
  } finally {
    await scan.close();
  }
});

test("v1: URL and PURL cannot be combined, and URLs are validated", async () => {
  const env = testEnv(DEAD, { SCAN_URL: DEAD });
  const mixed = await handle(
    new Request("http://beamline/v1/lookup?purl=pkg%3Anpm%2Fx%401.0.0&url=https%3A%2F%2Fx.test%2Fx"),
    env,
    noopCtx(),
  );
  assert.equal(mixed.status, 400);
  assert.equal((await mixed.json()).error.code, "multiple_locators");

  const invalid = await handle(
    new Request("http://beamline/v1/lookup?url=file%3A%2F%2F%2Ftmp%2Fx"),
    env,
    noopCtx(),
  );
  assert.equal(invalid.status, 400);
  assert.equal((await invalid.json()).error.code, "invalid_url");
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
    assert.equal((await res.json()).status, "analyzed");
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
    BEAMLINE_KV: extra.BEAMLINE_KV,
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
    SCAN_STREAM_IDLE_MS: extra.SCAN_STREAM_IDLE_MS,
    SCAN_STREAM_RESUMES: extra.SCAN_STREAM_RESUMES,
    cache: extra.cache ?? _test.memoryCache(),
  };
}

function noopCtx() {
  return { waitUntil() {} };
}

// Headers a cached answer is allowed to differ on: each describes this
// delivery rather than the verdict being delivered.
const DELIVERY_HEADERS = new Set(["x-beamline-source", "x-cache-layer", "x-beamline-worker", "server-timing", "age", "date"]);

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
    pending() {
      return jobs.length;
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
        res.writeHead(200, { "content-type": "application/x-ndjson", ...opts.analyzeHeaders });
        const lines = typeof opts.analyzeStream === "function" ? opts.analyzeStream(url) : opts.analyzeStream;
        let written = 0;
        for await (const line of lines || []) {
          // A worker that goes away mid-answer: the socket dies with frames
          // still owed, which is what a node being upgraded does to every
          // stream it is holding.
          if (opts.analyzeCut != null && written >= opts.analyzeCut) {
            // Let the 200 and the frames already written reach the client
            // before the socket dies. A worker taken away mid-answer had been
            // answering; without this pause the reset can overtake the headers
            // and the request never gets past dispatch, which is a different
            // failure with a different repair.
            await new Promise((resolve) => setTimeout(resolve, 25));
            return res.destroy();
          }
          res.write(`${line}\n`);
          written += 1;
        }
        return res.end();
      }
      if (url.pathname === "/v1/lookup") {
        hits.v1 += 1;
        const out = typeof opts.v1 === "function" ? opts.v1(url) : opts.v1;
        if (!out) return send(res, 404, { error: { code: "unknown_artifact" } });
        if (out.status && out.status !== 200) return send(res, out.status, { error: { code: "boom" } });
        return send(res, 200, out, opts.v1Headers || {});
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
    // A queue, not a set of arms: the plan is the order workers are tried in.
    assert.ok(small.dispatch.length > 1, "the plan must name the fallbacks too");

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
  const env = testEnv(hopper.url, { SCAN_URL: w.url, SCAN_TIMEOUT_MS: "600000" });
  try {
    const res = await handle(new Request("http://beamline/_/routes?type=npm"), env, waitCtx().ctx);
    const [route] = (await res.json()).routes;
    assert.equal(route.dispatch[0].est_ms, 9000, "the lifetime mean should not win over a live window");
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

// The trap this fallback used to set, measured on the fleet 2026-09-02.
//
// scan-rdu2 published an empty window and a lifetime mean carrying an old
// contended spell. Ranked on that mean it could not outrank a fleet publishing
// 50-57s p80s, so it was asked for nothing, so its window stayed empty, so the
// mean stayed its estimate. Forcing 23 analyses onto it broke the cycle and its
// window came back at 59.7s p80 — an ordinary worker, ruled out for an hour by
// a statistic nobody else was judged by.
test("an empty window is unknown, not slow", async () => {
  const hopper = await mockBackend({ bloom: "unknown" });
  const idle = await mockBackend({
    stats: statsFor({
      ms: 347000,
      bySize: {},
      // Empty at both levels, the way rdu2 published it: nothing in the last
      // hour per type, and nothing overall either.
      recent: { samples: 0, p80_ms: null, mean_ms: null },
      avg_job_ms_by_type: {
        npm: { jobs: 36, avg_ms: 347000, recent: { samples: 0, p80_ms: null, mean_ms: null } },
      },
    }),
  });
  const env = testEnv(hopper.url, { SCAN_URL: idle.url });
  try {
    const res = await handle(new Request("http://beamline/_/routes?type=npm"), env, waitCtx().ctx);
    const [route] = (await res.json()).routes;
    assert.equal(
      route.dispatch[0].est_ms,
      _test.UNKNOWN_JOB_MS,
      "a worker with nothing to say ranks as unknown, and is asked, and can then say something",
    );
    assert.equal(route.informed, false, "an estimate resting on nothing is not an informed one");
  } finally {
    await Promise.all([hopper.close(), idle.close()]);
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
// `unanalyzed` for an artifact nobody has analyzed. It means the worker has no
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
    assert.equal((await res.json()).status, "analyzed");
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
    assert.equal(JSON.parse((await res.text()).trim()).status, "analyzed");
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
    assert.equal(JSON.parse((await res.text()).trim()).status, "analyzed");
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

// A threat-feed-derived level carries a real `decision` but no engine. It is a
// citation, not a measurement, and the two questions that separates it on are
// deliberately asked of the same field.
test("v1 analyze: a feed-derived level is not an answer to `analyze`", async () => {
  const derived = {
    decision: "block",
    purl: "pkg:npm/cited@1.0.0",
    sha256: null,
    severity: "hostile",
    fires_at: 10,
    reason: "Cited as malicious by 2 independent threat intelligence feeds.",
    findings: [{ id: "intel/feed/malicious", crit: 5, file: null, pkg: null, desc: null, off: null, line: null }],
    engine_version: null,
    analyzed_at: null,
  };
  const scan = await mockBackend({
    analyzeStream: ['{"decision":"block","fires_at":2,"purl":"pkg:npm/cited@1.0.0","engine_version":"2.8.0"}'],
    v1: () => derived,
  });
  const env = testEnv(DEAD, { SCAN_URL: scan.url });
  try {
    // Populate the lookup cache with the derived answer, as a lookup would.
    const look = await handle(
      new Request("http://beamline/v1/lookup?purl=pkg%3Anpm%2Fcited%401.0.0"),
      env,
      waitCtx().ctx,
    );
    assert.equal(JSON.parse(await look.text()).status, "analyzed");
    // Derived answers are not verdicts, so they age out on the short schedule.
    assert.match(look.headers.get("cache-control"), /max-age=60/);

    // The gap this level papers over must still close: analyze has to run.
    const ctx = waitCtx();
    const ran = await handle(
      new Request("http://beamline/v1/analyze?purl=pkg%3Anpm%2Fcited%401.0.0", { method: "POST" }),
      env,
      ctx.ctx,
    );
    const body = await ran.text();
    await ctx.flush();
    assert.equal(scan.hits.analyze, 1, "a feed citation stood in for the analysis");
    assert.equal(JSON.parse(body.trim()).fires_at, 2, "the answer was the citation, not the analysis");
  } finally {
    await scan.close();
  }
});

// A scan worker taken away mid-answer.
//
// Everything above this line tests a fleet that fails before it is committed
// to. These test the window after: beamline has sent 200 and is streaming, so
// the status is spent and the only repair left is to find another worker
// without the caller having to know one was lost.

const CUT_FRAME = '{"state":"analyzing","purl":"pkg:npm/cut@1.0.0","elapsed_ms":40,"phase":"unpack"}';
const CUT_DECISION = '{"decision":"allow","fires_at":-1,"purl":"pkg:npm/cut@1.0.0"}';

// Drives one analyze against `SCAN_URL` and returns the parsed NDJSON frames.
async function analyzeFrames(env) {
  const res = await handle(
    new Request("http://beamline/v1/analyze?purl=pkg%3Anpm%2Fcut%401.0.0", { method: "POST" }),
    env,
    waitCtx().ctx,
  );
  assert.equal(res.status, 200);
  return (await res.text()).trim().split("\n").filter(Boolean).map(JSON.parse);
}

test("v1 analyze: a stream cut mid-answer is finished by another worker", async () => {
  _test.reset();
  const dying = await mockBackend({ analyzeStream: [CUT_FRAME, CUT_DECISION], analyzeCut: 1 });
  const healthy = await mockBackend({ analyzeStream: [CUT_FRAME, CUT_DECISION] });
  const env = testEnv(DEAD, { SCAN_URL: `${dying.url},${healthy.url}` });
  try {
    const frames = await analyzeFrames(env);
    assert.equal(frames.at(-1).status, "analyzed", "the caller never got a decision");
    assert.equal(
      frames.some((f) => f.state === "resumed"),
      true,
      "the handover was not announced to the caller",
    );
    assert.equal(healthy.hits.analyze, 1, "the surviving worker was never asked");
  } finally {
    await Promise.all([dying.close(), healthy.close()]);
  }
});

// A worker shut down politely closes its side rather than dropping it, and the
// stream ends with every frame well-formed and no answer among them. Told apart
// by the absence of a decision, not by how the socket died.
test("v1 analyze: a clean close with no decision is a truncation too", async () => {
  _test.reset();
  const quiet = await mockBackend({ analyzeStream: [CUT_FRAME] });
  const healthy = await mockBackend({ analyzeStream: [CUT_FRAME, CUT_DECISION] });
  const env = testEnv(DEAD, { SCAN_URL: `${quiet.url},${healthy.url}` });
  try {
    const frames = await analyzeFrames(env);
    assert.equal(frames.at(-1).status, "analyzed", "an EOF without a decision was taken for an answer");
    assert.equal(healthy.hits.analyze, 1, "the surviving worker was never asked");
  } finally {
    await Promise.all([quiet.close(), healthy.close()]);
  }
});

// A wedged worker is the failure the transport cannot report: the connection is
// open and healthy, and nothing is ever going to arrive on it.
test("v1 analyze: a worker that stops talking is treated as gone", async () => {
  _test.reset();
  let release;
  const held = new Promise((resolve) => {
    release = resolve;
  });
  const stalled = await mockBackend({
    analyzeStream: async function* stall() {
      yield CUT_FRAME;
      await held;
    },
  });
  const healthy = await mockBackend({ analyzeStream: [CUT_FRAME, CUT_DECISION] });
  const env = testEnv(DEAD, {
    SCAN_URL: `${stalled.url},${healthy.url}`,
    SCAN_STREAM_IDLE_MS: "50",
  });
  try {
    const frames = await analyzeFrames(env);
    assert.equal(frames.at(-1).status, "analyzed", "the caller waited out a worker that had stopped talking");
  } finally {
    release();
    await Promise.all([stalled.close(), healthy.close()]);
  }
});

// The 200 only ever proved the worker could be reached and routed to. A node
// being upgraded accepts every request and drops every stream, and crediting
// each of those as a success kept it at the top of the ranking.
test("v1 analyze: dropping a stream is charged to the worker's breaker", async () => {
  _test.reset();
  const dying = await mockBackend({ analyzeStream: [CUT_FRAME, CUT_DECISION], analyzeCut: 1 });
  const healthy = await mockBackend({ analyzeStream: [CUT_FRAME, CUT_DECISION] });
  const env = testEnv(DEAD, { SCAN_URL: `${dying.url},${healthy.url}` });
  try {
    assert.equal(_test.breakerFor(dying.url).open(), false);
    for (let i = 0; i < _test.BREAKER_FAILS; i++) {
      // A fresh cache each time: a cached verdict answers without dispatching,
      // and the point here is what dispatching costs the worker's record.
      const frames = await analyzeFrames({ ...env, cache: _test.memoryCache() });
      assert.equal(frames.at(-1).status, "analyzed");
    }
    assert.equal(_test.breakerFor(dying.url).open(), true, "a worker that drops every stream still looks healthy");
  } finally {
    await Promise.all([dying.close(), healthy.close()]);
  }
});

// A handover must not let the run appear to travel backwards: the replacement
// worker counts from its own zero, and the caller has already been told a later
// time than that.
test("v1 analyze: elapsed time is monotonic across a handover", async () => {
  _test.reset();
  const dying = await mockBackend({
    analyzeStream: ['{"state":"analyzing","purl":"pkg:npm/cut@1.0.0","elapsed_ms":9000,"phase":"unpack"}'],
  });
  const healthy = await mockBackend({
    analyzeStream: ['{"state":"analyzing","purl":"pkg:npm/cut@1.0.0","elapsed_ms":10,"phase":"fetch"}', CUT_DECISION],
  });
  const env = testEnv(DEAD, { SCAN_URL: `${dying.url},${healthy.url}` });
  try {
    const frames = await analyzeFrames(env);
    const elapsed = frames.map((f) => f.total_elapsed_ms).filter((ms) => typeof ms === "number");
    assert.deepEqual(elapsed, [...elapsed].sort((a, b) => a - b), `elapsed went backwards: ${elapsed}`);
  } finally {
    await Promise.all([dying.close(), healthy.close()]);
  }
});

// One pass over the fleet measures our own bookkeeping, not the fleet: a worker
// restarting refuses the connection instantly, so a whole pass can fail in
// milliseconds and answer `unavailable` having spent nothing.
test("v1 lookup: a fleet that failed fast is asked a second time", async () => {
  _test.reset();
  let asked = 0;
  const flapping = await mockBackend({
    v1: () => {
      asked += 1;
      if (asked === 1) return { status: 503 };
      return {
        decision: "allow", purl: "pkg:npm/flap@1.0.0", sha256: null, severity: "benign",
        fires_at: -1, reason: null, findings: [], engine_version: "2.8.0", analyzed_at: "2026-08-01T00:00:00Z",
      };
    },
  });
  const env = testEnv(DEAD, { SCAN_URL: flapping.url });
  try {
    const res = await handle(
      new Request("http://beamline/v1/lookup?purl=pkg%3Anpm%2Fflap%401.0.0"),
      env,
      waitCtx().ctx,
    );
    const body = await res.json();
    assert.equal(body.status, "analyzed", "a fleet that failed fast was never asked again");
    assert.equal(asked, 2);
  } finally {
    await flapping.close();
  }
});

// "We could not find out" collapses two failures a retry policy has to tell
// apart: a slot that will free shortly, and an outage.
test("v1: an outage says whether the fleet was full or unreachable", async () => {
  _test.reset();
  const full = await mockBackend({ analyzeStatus: 429 });
  try {
    const busy = await handle(
      new Request("http://beamline/v1/analyze?purl=pkg%3Anpm%2Fcut%401.0.0", { method: "POST" }),
      testEnv(DEAD, { SCAN_URL: full.url, SCAN_TIMEOUT_MS: "100", SCAN_RETRIES: "1" }),
      waitCtx().ctx,
    );
    assert.equal(JSON.parse(await busy.text()).cause, "saturated");
  } finally {
    await full.close();
  }

  const gone = await handle(
    new Request("http://beamline/v1/lookup?purl=pkg%3Anpm%2Fcut%401.0.0"),
    testEnv(DEAD, { SCAN_URL: DEAD }),
    waitCtx().ctx,
  );
  assert.equal((await gone.json()).cause, "unreachable");
});

// Cancelling the reader settles the read the stream is parked on, which looks
// exactly like an upstream that closed. Telling those apart matters: the second
// deserves another worker, and the first has nobody left to find one for.
test("v1 analyze: a caller hanging up is not a reason to find another worker", async () => {
  _test.reset();
  let resumes = 0;
  const encoder = new TextEncoder();
  const source = new ReadableStream({
    start(controller) {
      controller.enqueue(encoder.encode(`${CUT_FRAME}\n`));
    },
  });
  const reader = _test.annotatedV1Stream(
    source,
    25,
    { requestId: "test", locator: { type: "purl", value: "pkg:npm/cut@1.0.0" }, startedAt: Date.now(), ids: {} },
    null,
    {
      base: DEAD,
      resume: () => {
        resumes += 1;
        return null;
      },
      idleMs: 0,
      limit: 3,
    },
  ).getReader();

  await reader.read();
  const parked = reader.read();
  await new Promise((resolve) => setImmediate(resolve));
  await reader.cancel();
  await parked;
  assert.equal(resumes, 0, "a caller who hung up was given a fresh analysis on another worker");
});

// The last line of a stream usually has no trailing newline, so at EOF the
// decision can still be sitting in the buffer. Judging the stream truncated
// before flushing it threw away a worker's answer, charged that worker a
// failure for having answered, and paid for the same analysis twice.
test("v1 analyze: a decision without a trailing newline is an answer, not a truncation", async () => {
  _test.reset();
  let resumes = 0;
  const encoder = new TextEncoder();
  const source = new ReadableStream({
    start(controller) {
      controller.enqueue(encoder.encode(CUT_DECISION));
      controller.close();
    },
  });
  const reader = _test.annotatedV1Stream(
    source,
    25,
    { requestId: "test", locator: { type: "purl", value: "pkg:npm/cut@1.0.0" }, startedAt: Date.now(), ids: {} },
    null,
    {
      base: DEAD,
      resume: () => {
        resumes += 1;
        return null;
      },
      idleMs: 0,
      limit: 3,
    },
  ).getReader();

  const frames = [];
  for (;;) {
    const { value, done } = await reader.read();
    if (done) break;
    frames.push(JSON.parse(new TextDecoder().decode(value)));
  }
  assert.equal(resumes, 0, "a worker that answered was treated as having vanished");
  assert.equal(frames.at(-1).status, "analyzed");
  assert.equal(_test.breakerFor(DEAD).open(), false);
});

// The slots describe the server; the load describes the box. A pull worker
// beside the server can have every core busy while the server reports every
// slot free, and a router that only ranks on that sends work to a queue.
// Measured: slots_free=48, in_flight=0, load1=23 on 16 cores — and the
// analysis dispatched there waited five minutes to start.
// The pull worker's own jobs are load the box sheds when asked, so they must
// not make it unroutable — only rank it lower. Measured 2026-09-05: 24 idle
// slots on 16 cores held load1 at 20 with nothing interactive in flight, and
// the server was excluded as saturated for hours while its reserve sat empty.
test("sheddable background work is a penalty, not a refusal", () => {
  const box = { ready: true, slots: 48, slots_free: 4, in_flight: 0, physical_cpus: 16, load1: 20 };
  assert.equal(_test.capability({ ...box, background_in_flight: 12 }, null), null, "idle work discounted");
  assert.equal(_test.capability(box, null), "host saturated", "a server that cannot say is judged on the whole load");
  // Foreground load still refuses: twelve idle jobs do not excuse twenty-eight threads.
  assert.equal(_test.capability({ ...box, load1: 30, background_in_flight: 12 }, null), "host saturated");
  // The whole load stays in the ranking, so a quiet box is still preferred.
  assert.ok(_test.occupancy({ ...box, background_in_flight: 12 }) > 1, "ranked as the busy box it is");
  assert.equal(_test.foregroundPressure({ ...box, background_in_flight: 12 }), 0.5);
  assert.equal(_test.foregroundPressure({ ...box, background_in_flight: 40 }), 0, "never negative");
});

test("capability refuses a saturated host whatever its slots say", () => {
  const cores = 16;
  const free = { ready: true, slots: 48, slots_free: 48, in_flight: 0, physical_cpus: cores };
  assert.equal(_test.capability({ ...free, load1: 23 }, null), "host saturated");
  // Busy is a ranking matter, not a refusal, until every core has a runnable thread.
  assert.equal(_test.capability({ ...free, load1: 15 }, null), null);
  // A worker too old to report its cores is judged on its slots alone.
  assert.equal(_test.capability({ ...free, physical_cpus: undefined, load1: 23 }, null), null);
  assert.equal(_test.capability({ ...free, slots_free: 0, load1: 0 }, null), "at capacity");
});
