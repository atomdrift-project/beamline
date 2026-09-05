// Beamline: cache, then a scan worker. Zero deps.
// Cloudflare Worker and `node local.js` share this fetch handler.
//
// There is one backend. Beamline does not reach the corpus itself: a worker
// that cannot answer a lookup from its own index asks the corpus, which keeps
// the credential and the failover in one place instead of two.

import { docsResponse } from "./docs.js";

const SHA_RE = /^[0-9a-f]{64}$/;
const DEFAULT_SCAN_TIMEOUT_MS = 1_800_000;
// How long a worker gets to answer a lookup before we give up on it and hold
// it against its breaker.
//
// It has to exceed the longest a *healthy* worker can legitimately take, or a
// slow answer is recorded as a broken worker. That ceiling is set by scan, not
// here: a worker that cannot answer from its own index asks the corpus, and it
// allows each corpus address 2s (`READ_TIMEOUT` in scan's corpus.rs) before
// moving to the next. So with a replica down, a perfectly healthy worker can
// legitimately spend two seconds before it even starts reading.
//
// 500ms was inherited from an older shape, when beamline read the corpus itself
// and hopper answered in 25-117ms. It was never resized when the worker took
// that job over, which left the budget four times tighter than the work — and a
// brief excursion past it read as a fleet-wide fault. Raise this if scan's
// READ_TIMEOUT rises.
const LOOKUP_TIMEOUT_MS = 3_000;
const BREAKER_FAILS = 5;
const BREAKER_COOL_MS = 10_000;
const MEMORY_CACHE_MAX = 1024;
const HIT_LIMIT = 3;
const HIT_MIN_CRIT = 3;
const SCAN_RETRIES = 5;
// The share of an analysis's own budget that may be spent waiting for a slot.
// Half: a caller who allows thirty minutes for an answer would rather spend
// fifteen of them queueing than be told we could not find out.
const BUSY_BUDGET_SHARE = 0.5;
const SCAN_RETRY_BASE_MS = 1_000;
const SCAN_RETRY_MAX_MS = 30_000;
// One pass over the fleet is not a measurement of it. A worker restarting
// refuses the connection in microseconds, so a fleet caught mid-rollout can
// fail every address in a few milliseconds and answer `unavailable` having
// spent nothing — the same "measured our own bookkeeping, not the fleet"
// mistake scanWorkers() guards against, one layer up.
//
// Retried only while it is cheap. A pass that failed fast failed on
// reachability and is worth repeating; one that burned its timeouts is
// measuring a fleet that genuinely is not answering, and asking again would
// double a latency the caller is already waiting out. So the retry is gated on
// how long the first pass took, not on how many workers it tried.
const LOOKUP_RETRIES = 1;
const LOOKUP_RETRY_BASE_MS = 100;
const LOOKUP_RETRY_MAX_MS = 500;
const LOOKUP_RETRY_DEADLINE_MS = 5_000;
// How long an analyze stream may go without a frame before its worker is taken
// for gone. Scan emits progress while it works, so silence is not patience: it
// is a worker that stopped talking without closing the connection, the one
// failure the transport cannot report on its own. Set well above scan's
// progress cadence so a slow phase is never mistaken for a stall.
//
// Scan tickers every 5s, so 120s was already 24 missed frames — and it still
// fired on healthy workers. Measured: four golang analyses died as
// `terminated` with no decision, on artifacts from 2.7MB to 95.6MB, while
// 133MB and 137MB ones on the same fleet finished. Size and duration explain
// none of it; what the survivors had in common is that they stayed chatty
// (170-242 frames), and what the casualties had in common is a quiet stretch.
// The ticker is a tokio task and the analysis saturates a rayon pool sized to
// every core, so under load the frames stop arriving because nothing is
// scheduling them — not because the worker is gone. Three handovers later the
// caller is dropped and a healthy worker wears three breaker failures.
//
// 300s buys the starved ticker room to land a frame. It is a floor under a
// scheduling artifact, not a judgement about how long an analysis may run:
// a worker that is genuinely gone still costs a caller this long, which is why
// the real repair is on scan's side, keeping the ticker off the pool that
// starves it.
const STREAM_IDLE_MS = 300_000;
// How long a stream may go without changing phase before the caller is handed
// to another worker. Silence is one way a worker can be lost; the other is a
// worker that keeps the ticker going while its analysis sits behind a
// saturated pool — every frame says `analyzing`, the phase never moves, and
// the idle clock above never fires. Measured: `fetch+graft` for 300s and
// `cleave:resources` for 1800s, each on a heartbeat every 5s. Phase names are
// scan's own progress report, so a phase that has not changed in this long is
// a worker that is not going anywhere, whatever its ticker says.
const STREAM_STALL_MS = 600_000;
// How many times one analyze stream may be handed to another worker. A resume
// is cheap when the original survived — scan attaches the retry to the run
// already in progress — but a fleet dying under us has to terminate, not loop.
const STREAM_RESUMES = 3;
// How long beamline keeps reading an analysis whose caller has gone.
//
// The run is already paid for and already happening: scan detaches the
// analysis from the request that started it, so the verdict is coming whether
// or not anyone is still listening. Reading it out is the difference between
// filing it once and making the next caller buy it again. Bounded because a
// stream nobody is waiting for must not outlive the analysis it is watching.
const ORPHAN_BUDGET_MS = 600_000;

// Per isolate, not global: on Workers each isolate counts its own failures and
// loses them when it is recycled, so a backend outage costs BREAKER_FAILS
// requests per live isolate, not five in total.
//
// Duplicate concurrent work is collapsed by scan, which keys a flight per
// artifact and attaches the second caller to the run already going. Beamline
// does not also try: it ran two isolates deep on the same request often enough
// that a per-isolate map caught almost nothing, and the cache is what actually
// removes the repeat.
//
// One breaker per scan worker, keyed by base URL. A single shared breaker would
// let one sick worker disable scanning altogether.
const scanBreakers = new Map();

export default {
  fetch(request, env, ctx) {
    return handle(request, env, ctx);
  },
};

// Responses go out uncompressed. Cloudflare's edge compresses them itself, and
// a Worker that also compresses double-encodes: the body arrives gzipped twice
// when the client asked for gzip, and gzipped with no `Content-Encoding` at all
// when it asked for identity. `node local.js` has no edge in front of it, so it
// does its own compression.
export async function handle(request, env, ctx) {
  const started = Date.now();
  const response = await dispatch(request, env, ctx);
  recordRequest(env, request, response, Date.now() - started);
  return response;
}

// One datapoint per request, written from the response the caller actually got.
//
// A Worker cannot be scraped: it is stateless and spread across every colo, so
// a /metrics route would report one isolate's counters in one city and change
// on every request. Analytics Engine is the shape that fits — the Worker writes
// points, and the SQL API aggregates them where a dashboard can reach them.
//
// Read back off the response rather than threaded down from where the answer
// was decided. The headers are what the caller was told, and a metric that can
// disagree with what the caller saw is worse than no metric: it is the one that
// gets believed. This also means every route is covered by construction —
// there is no second place to remember.
function recordRequest(env, request, response, ms) {
  // Absent locally (`node local.js`) and in tests, and `writeDataPoint` is
  // fire-and-forget: it returns void, never throws, and must not be awaited.
  const ae = env?.BEAMLINE_AE;
  if (typeof ae?.writeDataPoint !== "function" || !response) return;
  const url = new URL(request.url);
  const source = response.headers.get("X-Beamline-Source") || "";
  // Named, not derived from the path: a 404 on /v1/anything would otherwise
  // become a label of its own, and a metric dimension the caller chooses is
  // unbounded by definition.
  const route =
    url.pathname === "/v1/lookup" || url.pathname === "/v1/analyze" ? url.pathname.slice("/v1/".length) : "other";
  // Deliberately no `indexes`. The only high-cardinality field here is the
  // artifact, and a PURL is the caller's dependency list — the same knowledge
  // `cacheScope` marks private on an authenticated deployment. It does not
  // belong in an analytics dataset by default; the ecosystem is enough to tell
  // npm from crates without naming anyone's packages.
  ae.writeDataPoint({
    blobs: [
      route,
      source,
      response.headers.get("X-Beamline-Follow") || "",
      response.headers.get("X-Beamline-Worker") || "",
      purlType(url.searchParams.get("purl") || ""),
      String(response.status),
    ],
    // `layer` carries -1 when nothing answered, matching what poppy records: a
    // request that reached no layer is not a shallow one, and averaging it as
    // zero would report the fleet at its cheapest exactly when it is down.
    //
    // `ms` is time to the response, not to the decision. On a streamed analysis
    // the headers go out first and the verdict arrives later, so this measures
    // what the caller waited before hearing anything — which is the number that
    // decides whether a proxy cuts the connection, and not the cost of the run.
    // `source = scan:analysis` is what separates the two.
    doubles: [CACHE_LAYERS.get(source) ?? -1, ms],
  });
}


async function dispatch(request, env, ctx) {
  // One id for the whole request, logged on every line and sent to scan, so a
  // slow lookup can be followed across both services. A caller
  // may bring its own; it reaches our logs and outbound headers, so it is
  // filtered and bounded first.
  const rid =
    cleanId(request.headers.get("x-request-id")) || cleanId(request.headers.get("cf-ray")) || crypto.randomUUID();
  // X-Beamline-Pin: <host> forces dispatch to one worker and bypasses the
  // cache, so an experiment can time a specific backend on a specific sample.
  // It only restricts a choice beamline was already free to make, but it does
  // spend a scan slot on demand — so it lives behind the token gate with
  // everything else, and is bounded like any other caller-supplied header.
  // ExecutionContext keeps waitUntil on its prototype, bound to itself, so a
  // spread produces an object without it — and every background job would then
  // be an unregistered promise the runtime may cancel the moment the response
  // goes out. That is silent: the helper below simply finds no waitUntil and
  // does nothing, so the cache never populates and nothing says why. Carry it
  // over explicitly, still bound to the context that owns it. Every later
  // { ...ctx } spreads this plain object, where it is an own property.
  const host = ctx;
  ctx = { ...ctx, rid, pin: cleanId(request.headers.get("x-beamline-pin")) || null };
  if (typeof host?.waitUntil === "function") ctx.waitUntil = (p) => host.waitUntil(p);
  if (request.signal && !ctx.signal) ctx.signal = request.signal;

  const url = new URL(request.url);
  // /_/health is the name every service in this stack answers to; /healthz
  // stays because the Makefile and the stress harness probe it.
  if (url.pathname === "/healthz" || url.pathname === "/_/health") {
    if (request.method !== "GET") return methodNotAllowed("GET");
    return json({ status: "ok" }, 200);
  }

  // Documentation is intentionally public even when API routes use the
  // optional client-token gate. A caller should be able to discover how to
  // authenticate before having a token.
  if (url.pathname === "/") {
    if (request.method !== "GET") return methodNotAllowed("GET");
    return docsResponse(Boolean((env.BEAMLINE_TOKEN || "").trim()));
  }

  const allowed = tokenList(env.BEAMLINE_TOKEN);
  if (allowed.length) {
    const bearer = /^Bearer\s+(\S+)/i.exec((request.headers.get("authorization") || "").trim());
    const got = bearer ? bearer[1] : "";
    if (!allowed.some((t) => tokenEq(got, t))) {
      return v1Error(401, "unauthorized", "Send your API key as `Authorization: Bearer <key>`.");
    }
  }

  // Named after the token gate, because a pin spends a scan slot on demand.
  // Reported here rather than as an outage further down: an unservable pin is
  // a typo in the caller's request, and "no_workers" would send whoever wrote
  // it looking at the fleet.
  if (ctx.pin && !scanWorkers(env, ctx.pin).length) {
    return v1Error(400, "unknown_pin", "X-Beamline-Pin names no configured worker.");
  }

  try {
    if (url.pathname === "/v1/analyze") {
      if (request.method !== "POST") return methodNotAllowed("POST");
      return await handleV1Analyze(request, env, ctx, url);
    }
    if (url.pathname === "/v1/lookup") {
      if (request.method !== "GET") return methodNotAllowed("GET");
      return await handleV1Lookup(env, ctx, url);
    }
    if (url.pathname === "/_/routes") {
      if (request.method !== "GET") return methodNotAllowed("GET");
      return await handleRoutes(env, ctx, url);
    }
    // A mistyped path is the first thing a new caller gets wrong, and bare
    // `not found` sends them hunting through the docs for a name they most
    // likely already had right — nearly every miss here is a dropped `/v1`.
    // Name the routes, and when the last segment is one of ours, say so.
    const routes = ["/v1/lookup", "/v1/analyze"];
    const tail = url.pathname.replace(/\/+$/, "");
    const guess = tail && routes.find((r) => r.endsWith(tail));
    return v1Error(
      404,
      "no_such_route",
      guess
        ? `No route ${url.pathname}. Did you mean ${guess}?`
        : `No route ${url.pathname}. This API serves ${routes.join(" and ")}.`,
    );
  } catch (err) {
    if (clientAborted(ctx)) {
      logLine("canceled", { rid: ctx.rid, method: request.method, path: url.pathname });
      return v1Error(499, "canceled", "The client closed the connection.");
    }
    logLine("error", { rid: ctx.rid, method: request.method, path: url.pathname, err: errText(err) });
    return v1Error(500, "internal", "Beamline failed to handle the request.");
  }
}

// How many packages one /v1/lookup URL may name. Matches scan's own cap, so a
// caller is refused here for the same reason and with the same number rather
// than discovering a second, smaller limit one hop in.
const V1_MAX_KEYS = 50;

// How long a v1 answer stays in the edge cache.
//
// Split the way the legacy route splits it, and for the same reason: a verdict
// is immutable for the engine that produced it, while "we hold nothing" becomes
// wrong the moment anything analyzes the artifact. A decision carrying
// `unavailable` is not cached at all — it describes this moment's reachability,
// and storing it would keep an outage alive after it ended.
const V1_VERDICT_MAX_AGE = 3600;
// The largest artifact a caller may hand us directly. A Worker holds an upload
// in memory to be able to offer it to a second worker when the first refuses,
// so this is a memory bound as much as a policy one. Anything bigger belongs in
// a registry, which is what `?purl=` is for.
const V1_MAX_UPLOAD_BYTES = 16 * 1024 * 1024;
const V1_NO_ENGINE_MAX_AGE = 60;
// How long a verdict survives in KV.
//
// L0 holds one for an hour; L1 is what makes the next month cheap, so its
// horizon is measured in months rather than minutes. Bounded all the same.
// Written without a TTL a verdict is stored forever, and a key whose spelling
// stops being read — an engine that moved on, a policy nobody asks for — is
// then never reclaimed and nothing ever notices, because a key nobody reads is
// a key nobody misses.
//
// KV measures expiration from the write and a read does not extend it, so this
// is a ceiling on staleness rather than a sliding window: a verdict is at most
// this old before the next caller pays for a fresh one.
const V1_KV_MAX_AGE = 90 * 24 * 60 * 60;
// KV refuses anything shorter, so a misconfigured horizon must not turn every
// write into a throw.
const KV_MIN_TTL = 60;
const DEFAULT_FALSE_POSITIVE_BUDGET = 25;
const SUSPICIOUS_LEVEL_CEILING = 3000;

// GET /v1/lookup — what we know, at the caller's budget. Never analyzes.
//
// Beamline's whole job here is the edge: authenticate, cache, and pick a worker.
// It does not consult hopper and does not reconcile two sources, because scan
// answers the question completely now — a worker that misses its own index asks
// the corpus itself. One question, one answer, one place that knows how to
// produce it.
async function handleV1Lookup(env, ctx, url) {
  const budgetRaw = url.searchParams.get("false_positive_budget");
  const budget = parseFalsePositiveBudget(budgetRaw);
  const purls = url.searchParams.getAll("purl").map((p) => p.trim()).filter(Boolean);
  const urls = url.searchParams.getAll("url").map((value) => value.trim()).filter(Boolean);
  const sha = (url.searchParams.get("sha256") || "").trim();
  const locators = urls.length ? urls.map((value) => ({ type: "url", value })) : purls.map((value) => ({ type: "purl", value }));

  if (purls.length && urls.length) {
    return v1Error(400, "multiple_locators", "Use ?purl= or ?url=, not both.");
  }
  if (urls.some((value) => !validArtifactUrl(value))) {
    return v1Error(400, "invalid_url", "url must be an absolute http or https URL.");
  }
  if (!sha && !locators.length) {
    return v1Error(400, "missing_package", "Name an artifact with ?purl=, ?url=, or ?sha256=.");
  }
  if (locators.length > V1_MAX_KEYS) {
    return v1Error(
      413,
      "too_many_packages",
      `${locators.length} packages exceeds the limit of ${V1_MAX_KEYS} for a URL.`,
    );
  }
  if (budget === null) {
    return v1Error(
      400,
      "invalid_false_positive_budget",
      `false_positive_budget must be a whole number from 0 to 3000, not ${JSON.stringify(budgetRaw)}.`,
    );
  }
  // Refused rather than quietly replaced by the default: a caller who meant to
  // loosen their budget and got the strict one back would see verdicts they
  // never asked for, with nothing in the response to say why.

  // Which question is being asked about the artifact. `follow` is part of it,
  // so it is part of the key; false_positive_budget is not, because beamline
  // applies it to `fires_at` below and one stored document therefore answers
  // every budget consistently.
  const follow = parseFollow(url.searchParams, urls.length ? "url" : purls.length ? "purl" : "sha256");
  if (follow.error) return v1Error(400, "invalid_follow_policy", follow.error);
  const path = v1CachePath(sha, locators, follow.value);
  const locator = locators.length === 1 ? locators[0] : null;

  const cache = await getCache(env);
  const cacheKey = new Request(`${url.origin}${path}`);
  // `pin` exists to time a specific backend, so it reads no cache at all —
  // not this policy's, and not a wider one's.
  const candidates = ctx.pin ? [] : followCandidates(follow.value);
  const hit = await nearestAnswer(candidates, async (policy) => {
    const found = await cache
      .match(new Request(`${url.origin}${v1CachePath(sha, locators, policy)}`))
      .catch(() => null);
    // Buffered rather than streamed through, because the answer decides both
    // how long the caller may hold it and whether it may answer for another
    // policy at all. Decisions are one small object.
    const document = found ? await found.text().catch(() => null) : null;
    return document ? { document, response: found } : null;
  });
  if (hit) {
    const { document, policy: served } = hit;
    const body = v1BudgetedBody(document, budget, locator, true);
    const res = new Response(body, hit.response);
    setSource(res.headers, "cache");
    // Derived from the answer, never read back from the cache.
    //
    // What comes back is whatever the platform decided to store the directive
    // as, which is not what we asked for: measured on api.isotope13.ai, an
    // entry written `max-age=60` reads back `max-age=14400`, because the zone's
    // edge TTL overrides the worker's. Our own eviction still honours the 60s —
    // an `unanalyzed` really is gone a minute later — but the caller was being
    // told to hold it for four hours, which is exactly the staleness the short
    // TTL exists to prevent.
    res.headers.set("cache-control", clientScope(env, v1MaxAge(document)));
    res.headers.delete("X-Beamline-Worker");
    if (served !== follow.value) res.headers.set("X-Beamline-Follow", served);
    return res;
  }

  if (!ctx.pin) {
    const stored = await nearestAnswer(candidates, async (policy) => {
      const document = await kvGet(env, v1CachePath(sha, locators, policy));
      return document ? { document } : null;
    });
    if (stored) {
      const { document, policy: served } = stored;
      const body = v1BudgetedBody(document, budget, locator, true);
      if (body) {
        const res = v1Body(env, body, 200, null, v1MaxAge(document));
        setSource(res.headers, "kv");
        if (served !== follow.value) res.headers.set("X-Beamline-Follow", served);
        // Warmed under the policy that produced it, never under the one that
        // asked. Every key holds the answer to its own question; filing a wide
        // document at a narrow key would leave the narrow question permanently
        // answered by evidence it never requested, and no later analysis could
        // tell the difference.
        waitUntil(
          ctx,
          cache.put(
            new Request(`${url.origin}${v1CachePath(sha, locators, served)}`),
            storedDocument(document, env),
          ),
        );
        return res;
      }
    }
  }

  return v1Ask(env, ctx, cache, cacheKey, path, sha, locators, budget, follow.value);
}

// Ask the workers in turn until one answers.
//
// Sequential rather than raced, and one worker rather than all of them: a v1
// lookup spends no analysis slot, and since every worker defers to the same
// corpus when it does not know, they now give the same answer. Broadcasting
// would multiply the load behind them to learn nothing.
async function v1Ask(env, ctx, cache, cacheKey, path, sha, locators, budget, follow) {
  const ids = v1LocatorIds(ctx.rid, sha, locators);
  const locator = locators.length === 1 ? locators[0] : null;
  const origin = new URL(cacheKey.url).origin;
  // Scan is asked by locator alone. Its corpus holds one verdict per artifact
  // rather than one per policy, so sending a policy it does not take would only
  // invite it to reject the question. What comes back is filed under the policy
  // this request resolved to, which is the question the caller actually asked.
  const askPath = v1CachePath(sha, locators, null);
  const t0 = Date.now();
  let cause = "unreachable";
  // The last worker that answered `unavailable`. Held rather than returned so
  // the fleet is exhausted first, and relayed only if nobody could do better -
  // scan's own reason for the outage beats one this service invented.
  let outage = null;

  for (let attempt = 0; ; attempt++) {
    const workers = await lookupOrder(env, ctx, scanWorkers(env, ctx.pin), ids);
    if (!workers.length) {
      cause = "no_workers";
      break;
    }

    for (const base of workers) {
      const worker = hostOf(base);
      try {
        const answered = await fetchTimeout(
          `${base}${askPath}`,
          { method: "GET", headers: scanHeaders(env, ctx) },
          LOOKUP_TIMEOUT_MS,
          ctx,
          async (resp) => {
            const body = await resp.text();
            return { status: resp.status, body, source: resp.headers.get("X-Scan-Source") };
          },
        );
        // A 404 is not this request being wrong. This route never answers one
        // for a well-formed query — an artifact nobody has analyzed is a 200
        // carrying `unanalyzed` — so a 404 means the worker has no such route, which
        // is a fact about the worker. Counted against it and tried elsewhere:
        // during a partial rollout that is what drains traffic off the workers
        // that cannot serve yet and onto the ones that can. Relaying it instead
        // told every caller their package did not exist.
        if (answered.status === 404) {
          breakerFor(base).fail();
          logLine("v1_lookup", { src: "scan", status: 404, worker, no_route: true, ...ids });
          continue;
        }
        // Any other 4xx is this request being wrong, which the next worker would
        // also say. Passed through verbatim so the caller reads scan's own reason.
        if (answered.status >= 400 && answered.status < 500) {
          breakerFor(base).ok();
          const source = beamlineSource(answered.source);
          logLine("v1_lookup", { src: source, status: answered.status, worker, ms: Date.now() - t0, ...ids });
          return v1Body(env, answered.body, answered.status, worker, 0, source);
        }
        if (answered.status !== 200) {
          breakerFor(base).fail();
          continue;
        }
        breakerFor(base).ok();
        const source = beamlineSource(answered.source);
        // An outage is not an answer, and this is the one 200 that is not one.
        //
        // `unavailable` says this worker could not reach the corpus just now -
        // not that the artifact is unknown, which is `unanalyzed` and is an
        // answer. Relaying the first one ends the search at the worker least
        // able to serve it while the rest of the fleet is still willing, and the
        // whole point of asking workers in turn is that they do not all fail
        // together. Measured: one worker lost its corpus while three others
        // still had a reachable replica, and every lookup in a run came back
        // `unavailable` because the favourite answered first.
        //
        // The breaker is deliberately not charged. The worker answered, and
        // promptly; it is the corpus behind it that is missing, and the same
        // worker will still analyze perfectly well. Opening its breaker over
        // this would take a healthy analyzer out of the fleet to punish an
        // outage somewhere else.
        if (v1OutageBody(answered.body)) {
          logLine("v1_lookup", { src: source, status: 200, worker, unavailable: true, ms: Date.now() - t0, ...ids });
          outage = { body: answered.body, worker, source };
          continue;
        }
        logLine("v1_lookup", { src: source, status: 200, worker, ms: Date.now() - t0, ...ids });
        const document = v1DocumentBody(answered.body);
        const stored = document || answered.body;
        const body = document ? v1BudgetedBody(document, budget, locator) : (v1BudgetedBody(answered.body, budget, locator) || answered.body);
        const res = v1Body(env, body, 200, worker, v1MaxAge(stored), source);
        if (!v1MaxAge(stored)) return res;
        // The asked-for key and every resolved alias are stored together; the
        // digest the answer names is
        // stored here. A lookup by PURL that reached a worker has just learned
        // the artifact's identity, and the next caller who knows only that
        // identity should not have to reach a worker to learn the same thing.
        // Skipped when they are the same key — a sha lookup has nothing to add.
        waitUntil(ctx, cacheV1Aliases(env, cache, origin, path, locator, stored, follow));
        return res;
      } catch (err) {
        breakerFor(base).fail();
        logLine("v1_lookup", { src: "scan", worker, unreachable: true, err: errText(err), ...ids });
      }
    }

    if (attempt >= LOOKUP_RETRIES || Date.now() - t0 >= LOOKUP_RETRY_DEADLINE_MS) break;
    const wait = backoff(LOOKUP_RETRY_BASE_MS, attempt, LOOKUP_RETRY_MAX_MS);
    logLine("v1_lookup_retry", { attempt: attempt + 1, wait_ms: Math.round(wait), ...ids });
    await sleep(wait, ctx);
  }

  // Nobody could answer. Not a 5xx: the caller asked what we know about some
  // packages, and "we could not find out" is an answer about each of them —
  // one their policy is entitled to treat differently from "nobody has analyzed
  // this". A 503 here collapses those two, and a client that catches errors and
  // proceeds fails open on both.
  // A worker did answer, and what it said was that it could not find out.
  // Its account beats one invented here: it knows which corpus address failed
  // and this service does not, and the caller reading `cause` is reading the
  // reason rather than our guess at it.
  if (outage) {
    logLine("v1_lookup", { src: outage.source, status: 200, worker: outage.worker, unavailable: true, relayed: true, ms: Date.now() - t0, ...ids });
    // Normalized like any other answer. Only the reason is scan's; the shape is
    // this service's to keep, and a caller should not have to read one spelling
    // on an outage and another on a verdict.
    const document = v1DocumentBody(outage.body);
    const body = (document && v1BudgetedBody(document, budget, locator)) || document || outage.body;
    return v1Body(env, body, 200, outage.worker, 0, outage.source);
  }
  logLine("v1_lookup", { src: "none", status: 200, unavailable: true, cause, ms: Date.now() - t0, ...ids });
  const rows = [];
  if (sha && !locators.length) rows.push(v1Unavailable(sha, null, cause));
  for (const item of locators) rows.push(v1Unavailable(locators.length === 1 && sha ? sha : null, item, cause));
  return v1Body(env, JSON.stringify(rows.length === 1 ? rows[0] : rows), 200, null, 0);
}

// A decision we could not reach a worker to make. Carries nothing about the
// artifact: it is a statement about us.
//
// `cause` says which statement. "We could not find out" collapses two failures
// a caller's retry policy has to tell apart: a saturated fleet has the capacity
// and is using it, so a slot frees shortly and asking again is right, while an
// unreachable one is an outage and asking again just adds load to it. We
// already compute the difference on the way here and used to discard it.
// Distinct from `reason`, which explains a verdict about the artifact and stays
// null on a row that carries no verdict at all.
function v1Unavailable(sha, locator, cause = null) {
  const row = {
    status: "unavailable",
    cause,
    purl: locator?.type === "purl" ? locator.value : null,
    sha256: sha || null,
    severity: "unknown",
    fires_at: null,
    reason: null,
    findings: [],
    engine_version: null,
    analyzed_at: null,
  };
  if (locator?.type === "url") row.url = locator.value;
  return compactV1Row(row);
}

// The cache key a v1 decision is stored under.
//
// One builder for every path that touches it: /v1/lookup reads and writes it,
// and /v1/analyze reads it before dispatching and writes it afterwards. These
// were three separate string literals saying the same thing, and a key that
// differs by one character between the writer and the reader is a cache that
// never hits and never says why.
//
// The follow policy is part of the key because it is part of the question. Two
// policies can reach opposite verdicts about one artifact and both be right —
// a package whose own bytes are clean and whose install script is not — so a
// document filed without saying which question it answers is a document that
// will eventually answer the wrong one. Passing no policy builds the path scan
// is asked on, which takes locators only.
function v1CachePath(sha, locators, follow) {
  const query = [];
  if (sha) query.push(`sha256=${encodeURIComponent(sha)}`);
  for (const locator of locators || []) {
    query.push(`${locator.type}=${encodeURIComponent(locator.value)}`);
  }
  if (follow) query.push(`follow=${encodeURIComponent(follow)}`);
  return `/v1/lookup?${query.join("&")}`;
}

// File an answer under its digest as well, when nothing has yet.
//
// A decision names the artifact it resolved to, so an answer one caller's PURL
// paid for can serve the next caller who holds only a hash — a lockfile pin, a
// scanner report. One question answered, both doors open.
//
// Only ever the digest, never the reverse. A digest is the artifact's identity
// and cannot name a different thing; a PURL is a spelling somebody chose, and
// filing an answer under a PURL the caller never typed would hand the next one
// a body written for a different question.
//
// Under the policy that produced it, never the bare digest. A digest names the
// artifact but says nothing about how it was reached, and the default differs
// by how it was reached — so an answer a URL scan paid for is filed at the
// digest under `follow=none`, where only a caller asking that same question
// finds it.
//
// Checked before it is written, and that check is the point: rewriting a key
// every time it is read would refresh its TTL forever, and an entry that never
// ages is pinned rather than cached. A verdict is allowed to go stale on
// schedule.
async function backfillDigestKey(env, cache, origin, body, follow) {
  const sha = v1DecisionSha(body);
  if (!sha) return;
  const maxAge = v1MaxAge(body);
  if (!maxAge) return;
  const path = v1CachePath(sha, [], follow);
  const key = new Request(`${origin}${path}`);
  const existing = await cache.match(key).catch(() => null);
  // Only a decision is worth leaving alone. A miss cached under this digest is
  // the exact thing this write answers, and skipping the write on account of
  // one leaves the digest key saying "nobody has analyzed this" while the
  // locator key beside it holds the verdict.
  if (existing && v1CachedVerdict(await existing.text().catch(() => null))) return;
  await cache.put(
    key,
    storedDocument(body, env),
  );
  await kvPut(env, path, body);
  logLine("v1_cache_backfill", { key: "sha256", sha, follow, max_age: maxAge });
}

// A locator is an alias, not a second document. Once scan resolves a URL or
// PURL to bytes, file the same canonical document under every name we know:
// the request's locator, the resolved PURL (when present), and the SHA-256.
// Full copies are deliberate: a KV read then costs one lookup and does not
// require a redirect lookup or a second consistency window.
//
// Names alias; policies do not. Every path here carries the one policy that
// produced this document, so a URL scan that followed nothing warms the PURL's
// `follow=none` entry and leaves the PURL's own default untouched. Aliasing
// across policies would file a shallow answer where a caller asking the deeper
// question reads, which is the same mistake as filing under a PURL nobody
// typed — one name, two questions.
function v1CacheAliasPaths(origin, requestedPath, locator, body, follow, canonicalPurl) {
  const paths = new Set([requestedPath]);
  if (locator) paths.add(v1CachePath(null, [locator], follow));
  // The normalized spelling of the coordinate that was asked, as scan
  // reported it. Not a PURL somebody else chose - the same one, written the
  // one way the normalizer writes it, which is the only spelling every other
  // spelling can agree on.
  //
  // Without this a cache keyed on the caller's text holds one entry per way
  // of writing a coordinate. Measured: `@v4.4.0+incompatible` and
  // `@v4.4.0%2Bincompatible` are one artifact by sha and were two entries
  // here, so the second spelling to arrive bought an analysis the first had
  // already paid for. Go pseudo-versions make that spelling common.
  if (canonicalPurl) paths.add(v1CachePath(null, [{ type: "purl", value: canonicalPurl }], follow));
  const sha = v1DecisionSha(body);
  if (sha) paths.add(v1CachePath(sha, [], follow));
  let row;
  try {
    row = JSON.parse(body);
  } catch {
    row = null;
  }
  if (row && !Array.isArray(row) && typeof row === "object") {
    if (typeof row.purl === "string" && row.purl.trim()) {
      paths.add(v1CachePath(null, [{ type: "purl", value: row.purl.trim() }], follow));
    }
    if (typeof row.url === "string" && validArtifactUrl(row.url.trim())) {
      paths.add(v1CachePath(null, [{ type: "url", value: row.url.trim() }], follow));
    }
  }
  return [...paths].map((path) => new Request(`${origin}${path}`));
}

async function cacheV1Aliases(env, cache, origin, requestedPath, locator, body, follow, canonicalPurl) {
  const keys = v1CacheAliasPaths(origin, requestedPath, locator, body, follow, canonicalPurl);
  await Promise.all(
    keys.map(async (key) => {
      try {
        await cache.put(key, storedDocument(body, env));
        const parsed = new URL(key.url);
        await kvPut(env, `${parsed.pathname}${parsed.search}`, body);
      } catch (err) {
        logLine("v1_cache_write", { stored: false, key: key.url, err: errText(err) });
      }
    }),
  );
}

// The digest a decision names, when it names a well-formed one.
function v1DecisionSha(body) {
  let row;
  try {
    row = JSON.parse(body);
  } catch {
    return null;
  }
  const sha = row && typeof row === "object" ? row.sha256 : null;
  return typeof sha === "string" && SHA_RE.test(sha) ? sha : null;
}

function parseFalsePositiveBudget(raw) {
  if (raw === null) return DEFAULT_FALSE_POSITIVE_BUDGET;
  const value = String(raw).trim();
  if (!/^\d{1,4}$/.test(value)) return null;
  const budget = Number(value);
  return budget >= 0 && budget <= SUSPICIOUS_LEVEL_CEILING ? budget : null;
}

function validArtifactUrl(value) {
  try {
    const parsed = new URL(value);
    return parsed.protocol === "http:" || parsed.protocol === "https:";
  } catch {
    return false;
  }
}

function v1LocatorIds(rid, sha, locators) {
  const first = locators?.[0];
  return {
    rid,
    sha256: sha || undefined,
    purl: first?.type === "purl" ? first.value : undefined,
    url: first?.type === "url" ? first.value : undefined,
  };
}

// What a caller who names no policy gets, decided by how they named the
// artifact — which is also a statement about what they already know.
//
// A PURL or a digest is a name for something the caller has already resolved.
// They walked a dependency graph to produce it, and they are working through
// that graph package by package, so walking it again underneath each request
// re-analyzes the same subgraph once per package. What their resolution cannot
// show them is an install or download command fetching something no manifest
// declares, so that is the category followed on their behalf.
//
// A URL is an exact artifact, and a caller holding one usually holds the whole
// set: a proxy hands them the resolved download for every dependency it serves.
// Traversal from a caller-supplied URL also reaches addresses we did not
// choose, which is the one case where following is a request to fetch from
// somewhere nobody vetted.
//
// Bytes name nothing. There is no registry resolution behind them and no
// lockfile beside them, so whatever is discoverable inside them is discoverable
// nowhere else, and this is the only place it can be found.
const DEFAULT_FOLLOW = {
  purl: "references",
  sha256: "references",
  url: "none",
  bytes: "all",
};

// Parse which references discovered inside the root artifact should be
// followed. The root itself is always retrieved; this controls only traversal
// after that. Repeated query keys and comma-separated values are equivalent.
//
// Every request resolves to a policy, named or not, because the answer is
// stored under a key that carries it: a request whose policy we could not name
// would be one whose answer we could not file.
function parseFollow(searchParams, kind) {
  const values = searchParams.getAll("follow");
  if (!values.length) return { value: DEFAULT_FOLLOW[kind] };

  const selected = new Set();
  let none = false;
  let all = false;
  let saw = false;
  for (const value of values) {
    for (const raw of value.split(",")) {
      const target = raw.trim();
      if (!target) continue;
      saw = true;
      if (target === "none") none = true;
      else if (target === "all") all = true;
      else if (["dependencies", "references", "ci-actions"].includes(target)) selected.add(target);
      else {
        return {
          error: `Unknown follow target ${JSON.stringify(target)}. Use all, dependencies, references, ci-actions, or none.`,
        };
      }
    }
  }
  if (!saw) return { error: "follow must name all, dependencies, references, ci-actions, or none." };
  if (none && (all || selected.size)) {
    return { error: "follow=none cannot be combined with another follow target." };
  }
  if (none) return { value: "none" };
  if (all) return { value: "all" };
  // CI actions are dependency references with additional CI context. Include
  // dependencies in the canonical spelling so logs and upstream requests make
  // that implication visible.
  if (selected.has("ci-actions")) selected.add("dependencies");
  const order = ["dependencies", "references", "ci-actions"];
  return { value: order.filter((target) => selected.has(target)).join(",") };
}

// Which stored policies may answer this one.
//
// `follow` widens monotonically: an answer produced under a wider policy saw
// every reference a narrower one would have, and more besides. So a wider entry
// answers a narrower question — and it answers with its own findings. A caller
// asking `follow=none` about an artifact whose dependency is hostile is told
// hostile, and `findings[].pkg` names the component that made it so; the
// alternative is re-running an analysis to be told something we already know.
//
// The reverse stays refused. A narrow answer never looked where the wider
// question points, so serving it there would report clean on evidence nobody
// gathered — the one direction that turns a cache into a false negative.
//
// `dependencies` and `references` are incomparable: neither contains the
// other, so neither answers the other, and both answer `none`.
const FOLLOW_KINDS = ["dependencies", "references", "ci-actions"];

// Every canonical spelling parseFollow can produce, narrowest first. `all` and
// the full triple are one question spelled two ways; both are listed because
// both can already be sitting in the cache, and equal sets answer each other.
const FOLLOW_POLICIES = [
  "none",
  "dependencies",
  "references",
  "dependencies,ci-actions",
  "dependencies,references",
  "all",
  "dependencies,references,ci-actions",
];

function followSet(policy) {
  if (policy === "none") return new Set();
  if (policy === "all") return new Set(FOLLOW_KINDS);
  return new Set(String(policy).split(",").map((kind) => kind.trim()).filter(Boolean));
}

// The requested policy first, then every stored policy wide enough to answer
// it, narrowest first. Nearest-answer-first matters: a caller asking
// `follow=none` should not be handed `all`'s verdict while a `dependencies`
// entry — which folded in less that the caller did not ask about — sits beside
// it.
function followCandidates(policy) {
  const want = followSet(policy);
  const wider = FOLLOW_POLICIES.filter((candidate) => {
    if (candidate === policy) return false;
    const kinds = followSet(candidate);
    return kinds.size >= want.size && [...want].every((kind) => kinds.has(kind));
  });
  return [policy, ...wider];
}

// The nearest candidate policy holding an answer, walked narrowest first.
//
// Only a decision may answer for a policy other than the one asked about. A
// stored "we hold nothing" is not evidence a wider walk gathered — it is a
// statement about the artifact at the moment it was written, and a decision
// filed under a wider policy contradicts it, because nothing that has been
// analyzed becomes unanalyzed again.
//
// Letting one end the walk is how a miss hid the analysis that answered it.
// Measured against the fleet: a caller looks up a package nobody holds, which
// files `unanalyzed` under the policy they asked; the precache pass then
// analyzes it under `follow=all`, which files the verdict under `all` and
// leaves that miss standing; and for the whole 60s the miss remains cached,
// every caller asking the default question is told the artifact is unanalyzed
// — 60s after it was analyzed. Under a policy that happened to match, the
// analysis overwrote the miss and none of this was visible.
//
// The miss is still worth keeping at the policy that asked. That entry is what
// spares the fleet a round trip for an artifact nobody has analyzed, which is
// the reason misses are cached at all — so it is held as a fallback and served
// once every wider candidate has come up empty.
//
// load answers with {document, ...} for one policy, or null. Whatever else it
// carries comes back untouched, alongside the policy that answered.
async function nearestAnswer(candidates, load) {
  let fallback = null;
  for (const [index, policy] of candidates.entries()) {
    const found = await load(policy);
    if (!found) continue;
    if (v1CachedVerdict(found.document)) return { ...found, policy };
    // Narrowest first, so index 0 is the policy the caller named. A
    // non-decision at any later candidate answers a question nobody asked.
    if (index === 0) fallback = { ...found, policy };
  }
  return fallback;
}

function v1DocumentBody(body) {
  let row;
  try {
    row = JSON.parse(body);
  } catch {
    return null;
  }
  if (!row || typeof row !== "object") return null;
  if (Array.isArray(row)) {
    if (!row.every((item) => item && typeof item === "object")) return null;
    return JSON.stringify(row.map((item) => canonicalV1Row(item)));
  }
  return JSON.stringify(canonicalV1Row(row));
}

function canonicalV1Row(row) {
  return compactV1Row(normalizeV1Row(row));
}

function v1BudgetedBody(body, budget, locator, legacyCachedUnknown = false) {
  let row;
  try {
    row = JSON.parse(body);
  } catch {
    return null;
  }
  if (!row || typeof row !== "object") return null;
  // `unknown` was scan's old wire name for `unanalyzed`. Translate it only on
  // cache reads so entries written before the rename remain useful. A live
  // worker returning the old name stays visible and fails the v1 contract
  // probe instead of hiding a partial or regressed deployment.
  const normalizedRow = (item) => {
    const normalized = legacyCachedUnknown && item && typeof item === "object" && !Array.isArray(item)
      && (item.decision === "unknown" || item.status === "unknown")
      ? { ...item, status: "unanalyzed", decision: undefined }
      : item;
    return compactV1Row(normalizeV1Row(normalized, budget));
  };
  const rows = Array.isArray(row) ? row.map(normalizedRow) : normalizedRow(row);
  if (!locator || locator.type !== "url") return JSON.stringify(rows);
  const addUrl = (item) => (item && typeof item === "object" && !Array.isArray(item) ? { ...item, url: locator.value } : item);
  return JSON.stringify(Array.isArray(rows) ? rows.map(addUrl) : addUrl(rows));
}

function normalizeV1Row(row, budget = null) {
  if (!row || typeof row !== "object" || Array.isArray(row)) return row;
  const status = row.status || (row.decision === "allow" || row.decision === "block" ? "analyzed" : row.decision);
  const normalized = { ...row, status: status || "unknown" };
  delete normalized.decision;
  if (normalized.status !== "analyzed") {
    normalized.severity = "unknown";
  } else if (Number.isInteger(normalized.fires_at) && budget !== null) {
    normalized.severity = severityForLevel(normalized.fires_at, budget);
  } else if (normalized.severity == null) {
    normalized.severity = "unknown";
  }
  return normalized;
}

function severityForLevel(firesAt, budget) {
  if (firesAt < 0) return "benign";
  if (firesAt <= budget) return "hostile";
  if (firesAt <= SUSPICIOUS_LEVEL_CEILING) return "suspicious";
  return "benign";
}

// Null means the field has no information. Do not make every client pay for
// keys whose only value is null; nested findings use the same sparse shape.
function compactV1Row(value) {
  if (Array.isArray(value)) return value.map(compactV1Row);
  if (!value || typeof value !== "object") return value;
  return Object.fromEntries(
    Object.entries(value)
      .filter(([, item]) => item !== null)
      .map(([key, item]) => [key, compactV1Row(item)]),
  );
}

// KV keys are hashes rather than raw URLs: a batch of PURLs can exceed KV's
// 512-byte key limit, while the lookup path remains the single source of truth
// for both Cache API and KV key identity.
async function kvKey(path) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(path));
  return `v1:${[...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("")}`;
}

async function kvGet(env, path) {
  const kv = env && env.BEAMLINE_KV;
  if (!kv || typeof kv.get !== "function") return null;
  try {
    return await kv.get(await kvKey(path));
  } catch (err) {
    logLine("v1_kv_read", { ok: false, err: errText(err) });
    return null;
  }
}

// Nothing is written without an expiry. `unanalyzed` keeps the short clock it has
// at the edge, because it stops being true the moment anything analyzes the
// artifact; a verdict keeps the long one.
async function kvPut(env, path, body) {
  const kv = env && env.BEAMLINE_KV;
  if (!kv || typeof kv.put !== "function") return;
  const maxAge = v1MaxAge(body);
  const ttl = maxAge === V1_NO_ENGINE_MAX_AGE ? maxAge : numEnv(env, "KV_MAX_AGE", V1_KV_MAX_AGE);
  await kv.put(await kvKey(path), body, { expirationTtl: Math.max(KV_MIN_TTL, Math.round(ttl)) });
}

// A cached body /v1/analyze may answer with, or null.
//
// `unanalyzed` and `unavailable` are both cacheable — briefly, and for the
// lookup's benefit — and neither one is an analysis. Answering /v1/analyze
// with either would tell a caller who just asked us to analyze an artifact
// that nobody has analyzed it. Only a real verdict may stand in for the run.
//
// A threat-feed-derived answer is the third of those, and the one that would be
// easiest to miss: it carries a real `decision`, so it reads as a verdict, but
// no engine produced it. Standing in for the run would mean an artifact nobody
// has analyzed is never analyzed — the caller is told `block` and the gap the
// derived level exists to paper over stays open forever. An engine is what
// separates a measurement from a citation, so that is what is checked.
function v1CachedVerdict(body) {
  let row;
  try {
    row = JSON.parse(body);
  } catch {
    return null;
  }
  if (!row || typeof row !== "object" || Array.isArray(row)) return null;
  if (row.status !== "analyzed" && !(row.decision === "allow" || row.decision === "block")) return null;
  if (!row.engine_version) return null;
  return row;
}

// How long this answer may be cached. A body carrying any `unavailable` is not
// cacheable at all; anything no engine produced is cacheable only briefly.
//
// One marker, because it is one question. A verdict is immutable for the engine
// that produced it, and everything else here is not: `unanalyzed` stops being true
// the moment something analyzes the artifact, and a feed-derived level stops
// being true when the ledger behind it moves. All of them carry a null
// `engine_version`, so testing for the engine subsumes the `unanalyzed` check
// rather than adding to it.
//
// A pre-engine_version verdict lands in the short bucket too. That costs a
// little more traffic and is never wrong, which is the right side to err on.
// Whether a 200 body is an outage rather than an answer. Same shapes
// `v1MaxAge` reads, for the same reason: one locator or several, and any one
// of them unreachable makes the whole reply one this service should not rest
// on - to cache, or to stop asking on.
function v1OutageBody(body) {
  try {
    const row = JSON.parse(body);
    const rows = Array.isArray(row) ? row : [row];
    return rows.some((item) => item?.status === "unavailable" || item?.decision === "unavailable");
  } catch {
    return false;
  }
}

function v1MaxAge(body) {
  try {
    const row = JSON.parse(body);
    const rows = Array.isArray(row) ? row : [row];
    if (rows.some((item) => item?.status === "unavailable" || item?.decision === "unavailable")) return 0;
    if (rows.some((item) => item?.status !== "analyzed" || !item?.engine_version)) return V1_NO_ENGINE_MAX_AGE;
  } catch {
    return V1_NO_ENGINE_MAX_AGE;
  }
  return V1_VERDICT_MAX_AGE;
}

function beamlineSource(source) {
  switch (source) {
    case "cache":
    case "kv":
    case "none":
      return source;
    case "scan:bloom":
    case "scan:index":
    case "scan:cached":
    case "scan:analysis":
    case "scan:replica":
    case "scan:primary":
      return source;
    // Normalize older scan workers during a rolling deployment.
    case "bloom":
      return "scan:bloom";
    case "replica":
      return "scan:replica";
    case "primary":
      return "scan:primary";
    case "index":
      return "scan:index";
    // Anything unrecognised is counted as work, which is the safe direction:
    // an unknown value from a half-rolled deployment inflates the bill rather
    // than the hit rate, and a metric that overstates what a fleet spends gets
    // investigated where one that understates it does not.
    case "scan":
    default:
      return "scan:analysis";
  }
}

// How deep a request had to go before something answered it.
//
// Ordered by what it costs to be answered there, which is why work sits below
// every cache rather than outside the scale: an average over these levels is
// only meaningful if the most expensive outcome is also the largest number.
// `none` is absent rather than numbered — nothing answered, which is a failure
// to reach any layer and not a depth. Counting it as one would pull the average
// toward "cheap" exactly when the fleet is unreachable.
const CACHE_LAYERS = new Map([
  ["cache", 0],          // L0  Workers Cache, this Worker's own edge
  ["kv", 1],             // L1  Workers KV
  ["scan:index", 2],     // L2  the worker's verdict index
  ["scan:cached", 2],    // L2  the worker's analysis cache: same depth, no work
  ["scan:bloom", 3],     // L3  Bloom-derived knowledge
  ["scan:replica", 4],   // L4  hopper's replica
  ["scan:primary", 5],   // L5  hopper's primary
  ["scan:analysis", 6],  // no layer held it; a worker did the work
]);

// Report where an answer came from, and how deep that is.
//
// Set together, always, because they are one fact. Three routes used to set the
// source by hand and a fourth derived it, which is how a header ends up present
// on the paths nobody graphs and missing on the ones they do.
function setSource(headers, source) {
  headers.set("X-Beamline-Source", source);
  const layer = CACHE_LAYERS.get(source);
  if (layer !== undefined) headers.set("X-Cache-Layer", String(layer));
}

function v1Body(env, body, status, worker, maxAge, source) {
  const headers = new Headers({
    "content-type": "application/json",
    "cache-control": clientScope(env, maxAge),
  });
  if (worker) headers.set("X-Beamline-Worker", worker);
  setSource(headers, worker ? beamlineSource(source) : "none");
  return new Response(body, { status, headers });
}

function v1Error(status, code, message) {
  return new Response(JSON.stringify({ error: { code, message } }), {
    status,
    headers: { "content-type": "application/json", "cache-control": "no-store" },
  });
}

// POST /v1/analyze — analyze an artifact and stream the decision back.
//
// The body is passed through untouched, and that is the point. Scan answers
// this route as a sequence — progress while the run is going, then the decision
// — so that a minutes-long analysis never leaves a connection silent long
// enough for something in the middle to conclude it is dead. Buffering here to
// hand back one tidy object would put that silence back on the hop between us
// and the caller, which is the hop we can least afford it on: a proxy we do not
// control sits on it, and the one measured in front of scan cuts at 125s.
//
// Worker choice happens before the first byte. Scan holds its ordinary response
// long enough to refuse — `429 At capacity` arrives before any body — so a
// refusal is still something to route around rather than a decision already
// half-delivered.
async function handleV1Analyze(request, env, ctx, url) {
  const purl = (url.searchParams.get("purl") || "").trim();
  const artifactUrl = (url.searchParams.get("url") || "").trim();
  const budgetRaw = url.searchParams.get("false_positive_budget");
  const budget = parseFalsePositiveBudget(budgetRaw);
  if (purl && artifactUrl) return v1Error(400, "multiple_locators", "Use ?purl= or ?url=, not both.");
  if (artifactUrl && !validArtifactUrl(artifactUrl)) {
    return v1Error(400, "invalid_url", "url must be an absolute http or https URL.");
  }
  const locator = purl ? { type: "purl", value: purl } : artifactUrl ? { type: "url", value: artifactUrl } : null;
  // Two ways to name an artifact, and the artifact itself is one of them. A
  // caller holding bytes nobody has published — a build output, a file off
  // disk, something pulled from a mirror — has nothing to locate them by, and
  // asking them to publish it first in order to find out what it is would be
  // the wrong way round.
  //
  // Which is meant is decided by whether any bytes arrived, not by whether a
  // body exists: a plain POST sends `Content-Length: 0`, so `request.body` is
  // present and empty for every caller who named a package and sent nothing.
  // Reading emptiness as an upload turned all of those into a 400.
  let bytes = null;
  if (request.body) {
    const max = numEnv(env, "MAX_BYTES", V1_MAX_UPLOAD_BYTES);
    let buffered;
    try {
      buffered = await request.arrayBuffer();
    } catch {
      return v1Error(400, "invalid_body", "Could not read the artifact from the request body.");
    }
    if (buffered.byteLength > max) {
      return v1Error(413, "artifact_too_large", `The artifact exceeds the ${max} byte limit.`);
    }
    if (buffered.byteLength > 0) bytes = buffered;
  }
  if (!locator && !bytes) {
    return v1Error(400, "missing_package", "Name an artifact with ?purl=, ?url=, or send it as the body.");
  }
  if (budget === null) {
    return v1Error(
      400,
      "invalid_false_positive_budget",
      `false_positive_budget must be a whole number from 0 to 3000, not ${JSON.stringify(budgetRaw)}.`,
    );
  }
  // Resolved after the body, because how the artifact was named decides the
  // default and an upload is only known to be one once bytes have arrived.
  const follow = parseFollow(url.searchParams, bytes ? "bytes" : locator.type);
  if (follow.error) return v1Error(400, "invalid_follow_policy", follow.error);

  const query = [];
  // The PURL rides along with an upload too: scan grafts the registry
  // provenance onto the report and echoes it in each finding's `pkg`.
  if (locator) query.push(`${locator.type}=${encodeURIComponent(locator.value)}`);
  // Always sent, named or not. The answer is filed under the policy resolved
  // here, so leaving scan to apply a default of its own would file it under a
  // policy that is not the one it was produced with.
  query.push(`follow=${encodeURIComponent(follow.value)}`);
  const path = `/v1/analyze${query.length ? `?${query.join("&")}` : ""}`;
  const ids = {
    rid: ctx.rid,
    ...v1LocatorIds(ctx.rid, null, locator ? [locator] : []),
    bytes: bytes ? bytes.byteLength : undefined,
    follow: follow.value,
  };
  const t0 = Date.now();

  // Already answered?
  //
  // This is the expensive door into the question /v1/lookup asks cheaply, and
  // the two share a cache key precisely so that asking the expensive way twice
  // costs one analysis rather than two. Nothing on this path used to look:
  // measured before this existed, three consecutive analyses of
  // pkg:cargo/tokio@1.40.0 ran 291s, 161s and 116s, each re-deriving a verdict
  // the cache could have returned in one hop.
  //
  // Only for a named package. An upload is a request to analyze *those bytes*,
  // and the PURL riding along with one names provenance rather than the thing
  // being asked about, so it cannot stand in for the artifact. `pin` bypasses,
  // exactly as it does on the lookup: it exists to time a specific backend.
  //
  // A narrower or wider follow policy is a different entry here, not a bypass.
  // It used to be a bypass, which meant the policy this service documents most
  // loudly — `follow=none`, the one the proxy recipe tells every caller to
  // send — was the one policy that could never hit a cache in either direction.
  if (locator && !bytes && !ctx.pin) {
    const cache = await getCache(env);
    // Same ordering the lookup reads under: this policy, then every wider one
    // that already answers it. An analysis is the most expensive thing this
    // service does, so a wider answer already in hand is worth far more here
    // than it is on the lookup.
    const candidates = followCandidates(follow.value);
    // A cached miss must not end this walk either, and here it is the most
    // expensive place it could: a miss filed under the narrow policy would send
    // us off to spend an analysis slot on a verdict a wider entry is already
    // holding.
    let hit = await nearestAnswer(candidates, async (policy) => {
      const found = await cache
        .match(new Request(`${url.origin}${v1CachePath(null, [locator], policy)}`))
        .catch(() => null);
      const text = found ? await found.text().catch(() => null) : null;
      return text ? { document: text, fromCache: true } : null;
    });
    if (!hit) {
      hit = await nearestAnswer(candidates, async (policy) => {
        const text = await kvGet(env, v1CachePath(null, [locator], policy));
        return text ? { document: text, fromCache: false } : null;
      });
    }
    const document = hit ? hit.document : null;
    const served = hit ? hit.policy : follow.value;
    const decided = document ? v1CachedVerdict(document) : null;
    if (decided) {
      // Serving from cache used to warm nothing, because this path returns
      // before the write below ever runs. So a warm PURL key left the digest
      // key cold indefinitely: every caller holding only a hash paid a round
      // trip to learn something we were already holding, and answering them
      // never fixed it either.
      const body = v1BudgetedBody(document, budget, locator);
      // Filed at the digest under the policy that produced it, not the one that
      // asked, for the reason the lookup warms its own key that way.
      waitUntil(ctx, backfillDigestKey(env, cache, url.origin, document, served));
      logLine("v1_analyze", { src: hit.fromCache ? "cache" : "kv", status: 200, artifact_status: decided.status, follow: served, ms: Date.now() - t0, ...ids });
      // Answered in the shape this route always answers in: one NDJSON line,
      // no progress frames because there was no run to report progress about.
      const answered = new Headers({
        "content-type": "application/x-ndjson",
        "cache-control": "no-store",
      });
      if (served !== follow.value) answered.set("X-Beamline-Follow", served);
      setSource(answered, hit.fromCache ? "cache" : "kv");
      return new Response(`${body.trimEnd()}\n`, { status: 200, headers: answered });
    }
    // Why we are about to spend an analysis slot. Without this a cache that
    // never hits and a cache that is never consulted look identical in the
    // logs, which is how the warm-write below went unnoticed.
    logLine("v1_analyze_uncached", { reason: hit ? "not_a_verdict" : "cold", ...ids });
  }

  // Who is already running it, asked once rather than per attempt. A worker
  // mid-analysis attaches a second request for the same key to the run in
  // progress rather than starting another beside it, so a caller who
  // reconnected belongs back on that worker — anywhere else pays for the whole
  // analysis a second time.
  const busy = locator ? await runningWorker(env, ctx, locator, ids) : null;
  const tries = numEnv(env, "SCAN_RETRIES", SCAN_RETRIES);
  const backoffBase = numEnv(env, "SCAN_RETRY_BASE_MS", SCAN_RETRY_BASE_MS);

  // How long to keep offering work to a fleet that is merely full.
  //
  // Busy and broken wear the same answer and are not the same claim. A worker
  // that refuses has told us it has the capacity and is using it: a slot will
  // free, and the only question is whether we are still here when it does. A
  // worker we could not reach has told us nothing of the sort, and retrying it
  // buys nothing.
  //
  // The old budget did not make that distinction, and the numbers say it must:
  // an analysis runs 8s at p50 and 53s at p90, while five attempts expire after
  // ~30s. Beamline gave up on a saturated fleet while every worker was
  // legitimately busy and about to free — reporting "we could not find out"
  // about work nobody had refused on its merits. So a busy fleet is waited on
  // against the same clock the analysis itself is promised, and a broken one
  // keeps the short budget.
  const busyDeadline = t0 + numEnv(env, "SCAN_TIMEOUT_MS", DEFAULT_SCAN_TIMEOUT_MS) * BUSY_BUDGET_SHARE;
  let last = null;
  for (let attempt = 0; ; attempt++) {
    const pass = { busy: 0, broken: 0 };
    last = pass;
    const cacheFollow = locator && !bytes ? follow.value : null;
    const answered = await v1Dispatch(
      env,
      ctx,
      url,
      locator,
      path,
      budget,
      busy,
      ids,
      t0,
      bytes,
      pass,
      cacheFollow,
    );
    if (answered) return answered;
    const stillWorthOffering = pass.busy > 0 && Date.now() < busyDeadline;
    if ((attempt >= tries && !stillWorthOffering) || !scanWorkers(env, ctx.pin).length) break;
    const wait = backoff(backoffBase, attempt, SCAN_RETRY_MAX_MS);
    logLine("v1_analyze_retry", { attempt: attempt + 1, of: tries, wait_ms: Math.round(wait), ...ids });
    await sleep(wait, ctx);
  }

  // Nobody could take it. A decision rather than a 5xx, for the same reason
  // /v1/lookup gives one: the caller asked about a package, and "we could not
  // find out" is an answer about it that their policy may treat differently
  // from "nobody has analyzed this".
  const cause = v1UnavailableCause(env, ctx, last);
  logLine("v1_analyze", { src: "none", status: 200, unavailable: true, cause, ms: Date.now() - t0, ...ids });
  return new Response(`${JSON.stringify(v1Unavailable(null, locator, cause))}\n`, {
    status: 200,
    headers: { "content-type": "application/x-ndjson", "cache-control": "no-store" },
  });
}

// Which failure the fleet just had, in the terms a caller's retry policy needs.
// The tallies are already kept to decide whether another pass is worth making;
// this only stops them being thrown away once it is not.
function v1UnavailableCause(env, ctx, pass) {
  if (!scanWorkers(env, ctx.pin).length) return "no_workers";
  if (!pass || !pass.busy) return "unreachable";
  return pass.broken ? "mixed" : "saturated";
}

// One pass over the fleet. Returns the response, or null when every worker
// refused and the pass is worth making again.
async function v1Dispatch(env, ctx, url, locator, path, budget, busy, ids, t0, bytes, pass, cacheFollow) {
  const workers = scanWorkers(env, ctx.pin);
  const hint = locator?.type === "purl" ? { purl: locator.value } : {};
  let ranked = workers.length ? await rankWorkers(env, ctx, workers, ids, hint) : [];
  if (busy) {
    // A preference, not a pin: a worker whose breaker is open is not in the
    // pool at all, and a run we cannot reach is not worth waiting for.
    const home = ranked.filter((base) => hostOf(base) === busy);
    if (home.length) ranked = [...home, ...ranked.filter((base) => hostOf(base) !== busy)];
  }
  for (const base of ranked) {
    const worker = hostOf(base);
    let upstream;
    try {
      // The query names the package and the body is the artifact, so a request
      // that names one carries no body at all. Nothing here declares a content
      // type: which is meant is decided by what arrives, and a header saying so
      // could only ever disagree with it.
      // Deliberately not `ctx.signal`. Tying this fetch to the caller means a
      // caller who hangs up takes the answer down with them: scan keeps
      // analysing either way, and the verdict is the one thing that stops the
      // next caller paying for the same run. The stream below reads it out on
      // its own clock; `ORPHAN_BUDGET_MS` is what bounds it.
      upstream = await fetch(`${base}${path}`, {
        method: "POST",
        headers: scanHeaders(env, ctx),
        body: bytes,
      });
    } catch {
      if (pass) pass.broken += 1;
      breakerFor(base).fail();
      continue;
    }
    // Full. Somebody else may have room, and scan refuses before it streams so
    // nothing has been sent to the caller yet.
    //
    // Not counted against the breaker: a worker saying "I am at capacity" is
    // answering correctly and promptly, which is the opposite of the fault a
    // breaker exists to detect. Counting it took healthy workers out of the
    // pool exactly when the fleet could least afford to lose them.
    if (upstream.status === 429) {
      if (pass) pass.busy += 1;
      logLine("v1_analyze", { src: "scan", status: 429, worker, busy: true, ...ids });
      continue;
    }
    if (upstream.status >= 500) {
      if (pass) pass.broken += 1;
      breakerFor(base).fail();
      logLine("v1_analyze", { src: "scan", status: upstream.status, worker, retry: true, ...ids });
      continue;
    }
    // As on the lookup: a 404 means this worker has no such route, not that the
    // request was wrong. Counted against it so a partial rollout converges on
    // the workers that can serve.
    if (upstream.status === 404) {
      if (pass) pass.broken += 1;
      breakerFor(base).fail();
      logLine("v1_analyze", { src: "scan", status: 404, worker, no_route: true, ...ids });
      continue;
    }
    if (upstream.status !== 200) {
      // A refusal delivered promptly is a worker working correctly.
      breakerFor(base).ok();
      logLine("v1_analyze", { src: "scan", status: upstream.status, worker, ms: Date.now() - t0, ...ids });
      return new Response(upstream.body, {
        status: upstream.status,
        headers: { "content-type": "application/json", "cache-control": "no-store" },
      });
    }
    // Deliberately not credited here. A 200 on an analyze proves only that the
    // worker took the request; everything it promised is still ahead of it, and
    // a node being upgraded takes every request and finishes none. Crediting
    // the acceptance zeroed the failure count on each of those, so a worker
    // that dropped every stream could never trip its own breaker. The credit is
    // issued when a decision actually arrives, to whichever worker produced it.

    const source = beamlineSource(upstream.headers.get("X-Scan-Source"));
    // Which policy actually produced this answer.
    //
    // Scan applies the requested selection on top of its own configuration, so
    // what it ran is its to report and not ours to assume — and the two have
    // disagreed before. The answer is filed under what was measured; the
    // policy we resolved is only the fallback for a worker too old to say.
    // A name we cannot spell is a name we could never read back: an answer
    // filed under it would be unreachable by every later question, so an
    // unrecognised value is ignored and the policy we resolved stands.
    const reported = upstream.headers.get("X-Scan-Follow");
    const known = FOLLOW_POLICIES.includes(reported);
    const storedFollow = cacheFollow && known ? reported : cacheFollow;
    if (cacheFollow && reported && reported !== cacheFollow) {
      logLine("v1_analyze_follow", { asked: cacheFollow, applied: reported, known: known || undefined, worker, ...ids });
    }
    // How scan spells the coordinate we asked about. Only scan knows: it is
    // the side that runs the normalizer, and it answers in the caller's words
    // by design. Used for filing, never for answering - the body keeps the
    // spelling the caller used, because that is the question they asked.
    const canonicalPurl = locator?.type === "purl" ? cleanPurl(upstream.headers.get("X-Scan-Purl")) : null;
    if (canonicalPurl && canonicalPurl !== locator.value) {
      logLine("v1_purl_canonical", { asked: locator.value, canonical: canonicalPurl, ...ids });
    }
    logLine("v1_analyze", { src: source, status: 200, worker, ms: Date.now() - t0, ...ids });
    // The caller's stream is also the cache observer. Keeping one pipeline
    // means a minutes-long analysis is request work, not a minutes-long
    // waitUntil task. Only after the terminal decision arrives do we hand the
    // bounded Cache API / KV writes to waitUntil.
    const cacheDecision = cacheFollow
      ? (decided) => {
          waitUntil(ctx, cacheV1Decision(env, ctx, url.origin, locator, decided, storedFollow, canonicalPurl));
        }
      : null;
    const streamed = new Headers({
      "content-type": "application/x-ndjson",
      "cache-control": "no-store",
      "X-Beamline-Worker": worker,
    });
    setSource(streamed, source);
    return new Response(
      annotatedV1Stream(
        upstream.body,
        budget,
        { requestId: ctx.rid, locator, startedAt: t0, ids },
        cacheDecision,
        // Only the analyze path resumes. It is the only one that holds a stream
        // long enough for its worker to be taken away mid-answer — a lookup is
        // over in milliseconds, and a failed one is simply retried.
        {
          base,
          resume: (dead) => v1Resume(env, ctx, path, bytes, ids, locator, dead),
          idleMs: numEnv(env, "SCAN_STREAM_IDLE_MS", STREAM_IDLE_MS),
          stallMs: numEnv(env, "SCAN_STREAM_STALL_MS", STREAM_STALL_MS),
          limit: numEnv(env, "SCAN_STREAM_RESUMES", STREAM_RESUMES),
        },
        // Only where there is something to file. An upload has no locator to
        // file an answer under, so reading out a stream nobody is holding
        // would cost the same and keep nothing.
        cacheFollow
          ? {
              register: (promise) => waitUntil(ctx, promise),
              budgetMs: numEnv(env, "SCAN_ORPHAN_MS", ORPHAN_BUDGET_MS),
            }
          : null,
      ),
      {
      status: 200,
      headers: streamed,
      },
    );
  }

  return null;
}

// A replacement upstream for an analyze stream that lost its worker before the
// decision arrived.
//
// Asked in the same order a first dispatch would use, with two departures. The
// worker already running this key goes first: when the original merely blipped
// it is still analyzing, and scan attaches the retry to the run in progress
// rather than starting a second one, so the handover costs an index request
// instead of an analysis. And the worker that just dropped us goes last, since
// it now has a failure against it and nothing in its favour — last rather than
// excluded, because one worker that stumbled still beats no worker at all,
// which is the rule scanWorkers() already follows for the fleet.
//
// A 429 here is not worth waiting on. The caller is mid-stream and holding a
// budget the queueing logic upstream never got to reason about, so a full
// worker is simply skipped in favour of one with room.
async function v1Resume(env, ctx, path, bytes, ids, locator, dead) {
  // An aborted request has nobody left to finish the analysis for, and every
  // fetch below would be made with a signal that is already tripped.
  if (clientAborted(ctx)) return null;
  const workers = scanWorkers(env, ctx.pin);
  if (!workers.length) return null;
  const hint = locator?.type === "purl" ? { purl: locator.value } : {};
  const ranked = await rankWorkers(env, ctx, workers, ids, hint);
  const busy = locator ? await runningWorker(env, ctx, locator, ids) : null;
  const order = [
    ...ranked.filter((base) => busy && hostOf(base) === busy),
    ...ranked.filter((base) => (!busy || hostOf(base) !== busy) && base !== dead),
    ...ranked.filter((base) => (!busy || hostOf(base) !== busy) && base === dead),
  ];

  for (const base of order) {
    const worker = hostOf(base);
    let upstream;
    try {
      upstream = await fetch(`${base}${path}`, {
        method: "POST",
        headers: scanHeaders(env, ctx),
        body: bytes,
        signal: ctx.signal,
      });
    } catch (err) {
      breakerFor(base).fail();
      logLine("v1_analyze_resume", { src: "scan", worker, unreachable: true, err: errText(err), ...ids });
      continue;
    }
    if (upstream.status !== 200 || !upstream.body) {
      if (upstream.status >= 500 || upstream.status === 404) breakerFor(base).fail();
      await drain(upstream);
      logLine("v1_analyze_resume", { src: "scan", status: upstream.status, worker, ...ids });
      continue;
    }
    breakerFor(base).ok();
    logLine("v1_analyze_resume", {
      src: "scan",
      status: 200,
      worker,
      attached: worker === busy || undefined,
      ...ids,
    });
    return { body: upstream.body, base };
  }
  logLine("v1_analyze_resume", { src: "none", unavailable: true, ...ids });
  return null;
}

// Store a completed stream's decision where the cheap route will find it.
// This function starts only after the decision arrives, so waitUntil covers
// bounded cache writes rather than the analysis that produced them.
async function cacheV1Decision(env, ctx, origin, locator, decided, follow, canonicalPurl) {
  const ids = v1LocatorIds(ctx.rid, null, locator ? [locator] : []);
  const document = v1DocumentBody(decided);
  if (!document) {
    logLine("v1_cache_write", { stored: false, reason: "invalid_decision", ...ids });
    return;
  }
  const maxAge = v1MaxAge(document);
  if (!maxAge) {
    logLine("v1_cache_write", { stored: false, reason: "uncacheable", ...ids });
    return;
  }
  const cache = await getCache(env);
  const requestedPath = v1CachePath(null, locator ? [locator] : [], follow);
  await cacheV1Aliases(env, cache, origin, requestedPath, locator, document, follow, canonicalPurl);
  logLine("v1_cache_write", { stored: true, follow, max_age: maxAge, keys: v1CacheAliasPaths(origin, requestedPath, locator, document, follow, canonicalPurl).length, ...ids });
}

// Add phase telemetry to the progress stream without changing the cached
// decision. Scan's older progress frames only carried a nullable phase and a
// total elapsed time, which made a missing phase indistinguishable from a
// stalled run. The Worker owns the request clock, so it can also correlate the
// frames without asking every scan version to learn a new wire format first.
//
// `resume` makes the stream survive losing its worker. It carries the base URL
// currently serving it, how long silence may last before that worker is taken
// for gone, how many handovers are allowed, and a callback that produces a
// replacement body. Omitted, the stream behaves as it always did.
function annotatedV1Stream(stream, budget, meta, onDecision = null, resume = null, orphan = null) {
  const encoder = new TextEncoder();
  let decoder = new TextDecoder();
  let reader = stream.getReader();
  let buffered = "";
  let decisionSeen = false;
  let finished = false;
  let handovers = 0;
  const queued = [];
  // `floor` keeps elapsed times monotonic across a handover: a replacement
  // worker counts from its own zero, and the caller must never watch the run
  // travel backwards.
  const phase = { name: null, startedElapsed: 0, lastElapsed: 0, floor: 0, changedAt: Date.now() };

  const encodeLine = (line) => {
    const annotated = annotatedV1Lines(line, budget, meta, phase);
    // A decision is terminal by contract. Register its short cache write as
    // soon as we observe it: callers are entitled to stop reading immediately
    // after this line and may cancel the stream before an EOF-driven flush.
    if (annotated.decision && !decisionSeen) {
      decisionSeen = true;
      // The worker finished what it took on. Charged to whoever is serving the
      // stream now, which after a handover is not who started it.
      if (resume) breakerFor(resume.base).ok();
      if (onDecision) {
        try {
          onDecision(annotated.decision);
        } catch (err) {
          logLine("v1_cache_write", { stored: false, reason: "schedule_failed", err: errText(err) });
        }
      }
    }
    return annotated.lines.map((row) => encoder.encode(`${row}\n`));
  };

  const push = (line) => {
    for (const encoded of encodeLine(line)) queued.push(encoded);
  };

  // One chunk, or a rejection when the worker stops talking.
  //
  // Silence needs its own clock. A worker that wedges holds the connection open
  // and sends nothing, which the transport reports as a healthy stream with a
  // very patient peer — so without a deadline here the caller waits out a
  // worker that is never going to answer.
  const readChunk = async () => {
    const pending = reader.read();
    if (!resume?.idleMs) return pending;
    // The loser of this race stays pending. Give it a handler now: once the
    // idle clock has won we stop awaiting the read, and a stream that errors
    // after that would otherwise surface only as an unhandled rejection.
    pending.catch(() => {});
    // Two clocks: silence, and a phase that stopped changing. Whichever has
    // less left decides the wait and names the failure.
    const stallLeft = resume.stallMs ? resume.stallMs - (Date.now() - phase.changedAt) : Infinity;
    const [why, waitMs] = stallLeft < resume.idleMs ? ["stalled", Math.max(0, stallLeft)] : ["idle", resume.idleMs];
    let timer;
    try {
      return await Promise.race([
        pending,
        new Promise((_, reject) => {
          timer = setTimeout(() => reject(new Error(why)), waitMs);
        }),
      ]);
    } finally {
      clearTimeout(timer);
    }
  };

  // Hand the caller to another worker, mid-stream. False when nobody took it,
  // and the stream then ends exactly as it would have without this.
  //
  // Safe because a v1 stream is progress frames followed by one terminal
  // decision: until that decision goes out the caller has consumed nothing a
  // different worker could contradict, so the answer is still owed and can
  // still be gone and got. After it, there is nothing left to resume.
  const handover = async (why) => {
    if (decisionSeen || !resume) return false;
    // The worker took the request and did not finish it. Charged here rather
    // than at the 200, which only ever proved we could reach it and route to
    // it: a node being upgraded accepts every request and drops every stream,
    // and crediting each of those as a success kept it top of the ranking while
    // it failed every caller.
    breakerFor(resume.base).fail();
    const spent = handovers >= resume.limit;
    logLine("v1_analyze_stream", {
      worker: hostOf(resume.base),
      why,
      handover: spent ? undefined : handovers + 1,
      exhausted: spent || undefined,
      ...meta.ids,
    });
    if (spent) return false;
    handovers += 1;
    try {
      await reader.cancel();
    } catch {
      // Already dead: cancelling is a courtesy to a live worker, not a step.
    }
    const next = await resume.resume(resume.base);
    if (!next) return false;
    reader = next.body.getReader();
    resume.base = next.base;
    // The dead worker's trailing bytes are half a frame, not a frame, and its
    // clock is not the replacement's.
    decoder = new TextDecoder();
    buffered = "";
    phase.floor = phase.lastElapsed;
    phase.name = null;
    phase.changedAt = Date.now();
    // Announced rather than papered over: the phase sequence restarts here, and
    // a caller watching progress is owed the reason. No `status` field, so a
    // reader looking for the terminal frame passes over it like any other
    // progress line.
    push(
      JSON.stringify({
        state: "resumed",
        worker: hostOf(next.base),
        elapsed_ms: phase.lastElapsed,
        total_elapsed_ms: phase.lastElapsed,
        request_id: meta.requestId,
        ...(meta.locator?.type === "purl" ? { purl: meta.locator.value } : {}),
        ...(meta.locator?.type === "url" ? { url: meta.locator.value } : {}),
      }),
    );
    return true;
  };

  // Read what is left of an abandoned stream, for the decision alone.
  //
  // Feeds `encodeLine` rather than `push`: the annotated lines are discarded
  // — there is no one to hand them to — and the only thing wanted is the
  // `onDecision` call it makes on the way past. No handover is attempted; a
  // worker that dies with nobody waiting takes its run with it, and asking a
  // second worker to redo it would spend a slot on an answer nobody is owed.
  const drainToDecision = async () => {
    const deadline = Date.now() + (orphan?.budgetMs || ORPHAN_BUDGET_MS);
    try {
      while (!decisionSeen && Date.now() < deadline) {
        const result = await readChunk();
        if (result.done) {
          // Same trailing-line flush the read loop does: the decision is
          // routinely the last line and routinely arrives without a newline.
          buffered += decoder.decode();
          if (buffered) {
            encodeLine(buffered);
            buffered = "";
          }
          break;
        }
        buffered += decoder.decode(result.value, { stream: true });
        const lines = buffered.split("\n");
        buffered = lines.pop() ?? "";
        for (const line of lines) {
          encodeLine(line);
          if (decisionSeen) break;
        }
      }
    } catch {
      // The worker stopped talking to a request nobody was reading. There is
      // nothing to file and nobody to tell.
    }
    try {
      await reader.cancel();
    } catch {
      // Already gone.
    }
    logLine("v1_analyze_orphan", { decided: decisionSeen || undefined, ...meta.ids });
  };

  return new ReadableStream({
    async pull(controller) {
      for (;;) {
        if (queued.length) {
          controller.enqueue(queued.shift());
          return;
        }
        if (finished) {
          controller.close();
          return;
        }
        let result;
        try {
          result = await readChunk();
        } catch (err) {
          // The caller hung up: cancel() settles the read we were parked on, and
          // there is no longer anyone to hand over to.
          if (finished) return;
          // Nothing more is coming from this worker. If nobody else will take
          // it the stream ends undecided — which is what the caller has to be
          // allowed to see, since erroring here would be indistinguishable from
          // the truncation we just failed to repair.
          const why = err?.message === "idle" || err?.message === "stalled" ? err.message : "error";
          if (await handover(why)) continue;
          finished = true;
          continue;
        }
        if (finished) return;
        if (result.done) {
          // Flush before judging. A stream's last line often arrives without a
          // trailing newline, so at EOF the remainder is a whole frame still
          // sitting in the buffer — and when that frame is the decision,
          // deciding first threw the answer away and re-ran the analysis
          // somewhere else. Only a stream that died mid-line leaves a partial
          // frame here, and that path discards the buffer on its own.
          buffered += decoder.decode();
          if (buffered) {
            push(buffered);
            buffered = "";
          }
          // A clean close with no decision is a truncation too: a worker taken
          // down between frames shuts its side politely and says nothing.
          if (!decisionSeen && (await handover("eof"))) continue;
          finished = true;
          continue;
        }
        buffered += decoder.decode(result.value, { stream: true });
        const lines = buffered.split("\n");
        buffered = lines.pop() ?? "";
        for (const line of lines) push(line);
      }
    },
    // The caller stopped reading.
    //
    // After the decision that is simply the end of the stream. Before it, the
    // caller has walked away from a run that is still going and whose answer
    // nothing else will observe — `onDecision` fires from `encodeLine`, and
    // `encodeLine` only runs while somebody pulls. Dropping the reader here is
    // what made an abandoned analysis cost a full re-run for whoever asked
    // next. So finish reading it ourselves, on time the caller is no longer
    // waiting on, and let the decision land in the cache as it would have.
    async cancel(reason) {
      finished = true;
      if (!decisionSeen && orphan) {
        orphan.register(drainToDecision());
        return;
      }
      try {
        await reader.cancel(reason);
      } catch {
        // The caller hung up on a worker that had already gone.
      }
    },
  });
}

function annotatedV1Lines(line, budget, meta, phase) {
  let row;
  try {
    row = JSON.parse(line);
  } catch {
    return { lines: [line], decision: null };
  }
  if (!row || typeof row !== "object" || Array.isArray(row)) {
    return { lines: [budgetedV1Line(line, budget, meta.locator)], decision: null };
  }

  const reported = finiteMs(row.elapsed_ms);
  const totalElapsed = reported == null ? phase.lastElapsed : reported + phase.floor;
  if (Number.isFinite(totalElapsed)) phase.lastElapsed = totalElapsed;

  // A decision is the terminal event. Close the last reported phase in its own
  // frame so clients never have to infer completion from the decision shape.
  if (Object.prototype.hasOwnProperty.call(row, "decision")) {
    const done = phaseCompletion(meta, phase);
    return {
      lines: [...(done ? [JSON.stringify(done)] : []), budgetedV1Line(line, budget, meta.locator)],
      decision: line,
    };
  }

  if (row.state !== "analyzing") {
    return { lines: [budgetedV1Line(line, budget, meta.locator)], decision: null };
  }

  const name = typeof row.phase === "string" && row.phase.trim() ? row.phase.trim() : "unknown";
  const elapsed = Number.isFinite(totalElapsed) ? totalElapsed : 0;
  const rows = [];
  if (phase.name && phase.name !== name) {
    const done = phaseCompletion(meta, phase, elapsed);
    if (done) rows.push(JSON.stringify(done));
    phase.name = null;
  }
  if (!phase.name) {
    phase.name = name;
    phase.startedElapsed = elapsed;
    phase.changedAt = Date.now();
    rows.push(JSON.stringify(phaseFrame(row, meta, phase, "started", elapsed)));
  } else {
    rows.push(JSON.stringify(phaseFrame(row, meta, phase, "running", elapsed)));
  }
  return { lines: rows, decision: null };
}

function phaseFrame(row, meta, phase, state, elapsed) {
  const frame = {
    ...row,
    elapsed_ms: elapsed,
    phase: phase.name,
    phase_state: state,
    phase_elapsed_ms: Math.max(0, elapsed - phase.startedElapsed),
    total_elapsed_ms: elapsed,
    phase_started_at: new Date(meta.startedAt + phase.startedElapsed).toISOString(),
    request_id: meta.requestId,
    ...(row.purl == null && meta.locator?.type === "purl" ? { purl: meta.locator.value } : {}),
    ...(row.url == null && meta.locator?.type === "url" ? { url: meta.locator.value } : {}),
  };
  return frame;
}

function phaseCompletion(meta, phase, elapsed = phase.lastElapsed) {
  if (!phase.name) return null;
  const frame = phaseFrame(
    {
      state: "analyzing",
      ...(meta.locator?.type === "purl" ? { purl: meta.locator.value } : {}),
      ...(meta.locator?.type === "url" ? { url: meta.locator.value } : {}),
    },
    meta,
    phase,
    "completed",
    Number.isFinite(elapsed) ? elapsed : phase.startedElapsed,
  );
  phase.name = null;
  return frame;
}

function finiteMs(value) {
  const n = Number(value);
  return Number.isFinite(n) && n >= 0 ? n : null;
}

function budgetedV1Line(line, budget, locator) {
  if (!line.includes('"decision"')) return line;
  const body = v1BudgetedBody(line, budget, locator);
  return body || line;
}

// One worker's answer. An empty `bloom` means it could not give one, so the
// race keeps waiting on whoever is left.
// Which worker is already analyzing this artifact, if any.
//
// A worker mid-analysis attaches a second request for the same key to the run
// in progress rather than starting another, so a caller who reconnected — a new
// isolate, an empty flight table, no memory of the request that was cut — must
// be sent back to it. Beamline's own single-flight cannot do this: it lives in
// one isolate, and the reconnect is very often somewhere else. Only the workers
// know, so they are the ones asked.
//
// Costs one index-speed request per worker, and only on the analyze path — the
// path that is about to spend orders of magnitude more than that. A worker that
// cannot answer is simply not the one running it.
async function runningWorker(env, ctx, input, ids) {
  const workers = scanWorkers(env, ctx.pin);
  const keys = [];
  if (input.sha) keys.push(`sha256=${input.sha}`);
  if (input.type && input.value) keys.push(`${input.type}=${encodeURIComponent(input.value)}`);
  if (!workers.length || !keys.length) return null;
  const path = `/status?${keys.join("&")}`;
  const asked = await Promise.all(workers.map((base) => statusAsk(env, ctx, path, base)));
  const busy = asked.find((a) => a?.state === "running");
  if (busy) {
    logLine("scan_affinity", { worker: busy.worker, elapsed_ms: busy.elapsed_ms, ...ids });
  }
  return busy?.worker || null;
}

async function statusAsk(env, ctx, path, base) {
  const worker = hostOf(base);
  try {
    return await fetchTimeout(
      `${base}${path}`,
      { method: "GET", headers: scanHeaders(env, ctx) },
      LOOKUP_TIMEOUT_MS,
      ctx,
      async (resp) => {
        if (resp.status !== 200) {
          await drain(resp);
          return null;
        }
        const body = await resp.json().catch(() => null);
        if (!body || typeof body !== "object") return null;
        return { worker, state: body.state, elapsed_ms: body.elapsed_ms };
      },
    );
  } catch {
    return null;
  }
}
// A scan that never reached a verdict is worth asking again: a 5xx, a 429 at
// capacity, an edge timeout at 120s, a dropped connection — none of those are
// answers, and a moment later they may not hold. A rejection is an answer
// (bad bytes, unsupported type), so repeating it would only burn a slot.
//
// Retrying is safe because scan de-duplicates by sha and purl across isolates:
// a retry joins the analysis already running rather than starting a second one,
// which is what makes retrying an edge timeout worth doing at all.
// ---------------------------------------------------------------- routing ---
//
// Which scan worker should go first — and only that. One worker is asked at a
// time, and the next is reached only when the one before it refuses or fails.
//
// It used to race: every healthy worker got every sample and the first verdict
// won. That cost a full duplicate analysis per extra worker on a fleet whose
// scarce resource is analysis slots, and the losers could not be called off.
// Measured on one request, galadriel answered pkg:pypi/idna@2.5 in 12.5s while
// interserver kept working on it for another 77s and returned 200. Cancelling
// has to cross a Worker abort, the Cloudflare edge, and a tunnel before scan
// sees a disconnect, and the evidence is that it does not arrive — so a loser
// costs a slot whatever we do about it once it has started.
//
// The remedy that survived is not to start the work: ask the worker most likely
// to finish first, and ask a second one only when the first says no. That makes
// the ranking below the whole of the strategy, which is why it is measured
// rather than configured.

// How long a cached /_/stats reading stays usable. Short enough to follow a
// worker filling up, long enough that routing costs one poll per worker per
// this interval rather than one per request.
const STATS_TTL_MS = 10_000;
// Bound one stats poll. A worker too busy to answer this is, usefully, also a
// worker we should not be sending work to.
const STATS_TIMEOUT_MS = 1_500;
// Used when a worker has no history for a size class yet. Deliberately
// pessimistic-but-plausible: it should not beat a worker with real evidence.
const UNKNOWN_JOB_MS = 5_000;
// Completions a class average needs before it is treated as evidence.
//
// One sample is a story, not a statistic, and the router had no way to tell the
// difference: `hasHistory` accepted any non-null average, so a worker that had
// finished exactly one large archive was ranked as though it were slow at
// everything. Observed live right after a restart — the fleet's *fastest*
// worker was demoted to second on n=1 while another led on n=6. Below this
// threshold the next-broadest evidence is used instead.
const MIN_CLASS_SAMPLES = 5;
// How heavily occupancy counts against a worker's estimate.
//
// scan queues rather than rejects, so a busy worker's cost is a longer wait —
// and a full worker with somebody already queued costs a whole service time
// more than a full worker with nobody. At 1.0 a worker with every slot busy and
// an empty queue is scored as though the work took twice as long; each further
// job in its queue adds another service time on top.
//
// This is the one signal that routes around a saturated worker at all. It used
// to have a partner: scan answered `429 At capacity` and a refusal promoted the
// next arm immediately, so a bad guess corrected itself in milliseconds. A
// queueing worker never refuses, so nothing corrects a bad guess any more —
// which makes it worth ranking on rather than a hint.
//
// Ranking on latency alone had a specific failure: the fleet's *smallest*
// worker was also its fastest, so it won every first-arm dispatch, filled its
// six slots in milliseconds and refused the rest — while a 64-slot worker sat
// with 44 free. Speed and capacity are different questions and the router was
// only asking one.
const CAPACITY_WEIGHT = 1.0;

// How busy a worker is, in units of its own capacity.
//
// Two measures of the same thing, and the larger wins. `in_flight / slots` is
// what this server is doing; `load1 / physical_cpus` is what the machine is
// doing. They are not added, because the server's own analyses appear in both
// and adding would count them twice.
//
// The host term is not defensive programming. A scan host commonly runs the
// pull worker beside the server, and may run an ad-hoc analysis too. Measured
// on a 64-core node: `slots=64 slots_free=64 in_flight=0` while `load1` sat at
// 50, because a 16-worker puller and a batch scan were between them using
// nearly half the box. Every field the server reported was true, and a router
// reading only those fields would have called it idle.
//
// Unknown slots mean an unknown answer, and 0 keeps such a worker ranked on
// latency alone rather than inventing a penalty for it.
function occupancy(stats) {
  const slots = Number(stats?.slots);
  if (!Number.isFinite(slots) || slots <= 0) return 0;
  const running = Number(stats.in_flight ?? slots - (stats.slots_free ?? slots));
  const mine = Number.isFinite(running) ? Math.max(0, running) / slots : 0;
  return Math.max(mine, hostPressure(stats));
}

// What the whole machine is doing, over the cores it really has.
//
// `physical_cpus` rather than the logical count `/_/info` reports: slots are
// sized on physical cores, and using logical would halve the apparent pressure
// on any host with SMT — which is every host where this matters most. A worker
// too old to report it contributes nothing rather than a guess.
// load1 per physical core above which a worker is not offered work at all.
// Below it the same number is a ranking penalty (see `occupancy`); at 1 every
// core already has a runnable thread and a new analysis can only wait.
const HOST_PRESSURE_LIMIT = 1;
function hostPressure(stats) {
  const cpus = Number(stats?.physical_cpus);
  if (!Number.isFinite(cpus) || cpus <= 0) return 0;
  const busy = machineBusy(stats);
  if (!Number.isFinite(busy) || busy <= 0) return 0;
  return busy / cpus;
}

// How much of the machine is working, in cores. `cpu_busy_cores` when scan
// reports it: the kernel's own CPU counters over the last poll interval, which
// mean the same thing on every host. `load1` otherwise, which does not — Linux
// counts threads blocked on disk in it and FreeBSD counts only runnable ones,
// so before this field existed the Linux servers read busier than the FreeBSD
// one for the same work and were the first excluded on every I/O burst.
// Both are thread counts against physical cores, deliberately: SMT siblings
// add contention, not capacity, once every core is fed.
function machineBusy(stats) {
  // `null` is scan saying "not yet" (one poll old, or no counters here) and
  // must not read as zero busy cores: Number(null) is 0.
  const raw = stats?.cpu_busy_cores;
  const measured = raw == null ? Number.NaN : Number(raw);
  if (Number.isFinite(measured) && measured >= 0) return measured;
  const load = Number(stats?.load1);
  return Number.isFinite(load) ? load : 0;
}

// The load a new analysis would actually queue behind: the host's, less one
// runnable thread for each pull-queue job the server reports in
// `background_in_flight`. One thread each is deliberately conservative — an
// analysis fans out on rayon and may hold more — because what matters is that
// the discount is bounded by work the server itself says is sheddable, and a
// server too old to report the field is judged on the whole load, as before.
function foregroundPressure(stats) {
  const cpus = Number(stats?.physical_cpus);
  if (!Number.isFinite(cpus) || cpus <= 0) return 0;
  const busy = machineBusy(stats);
  if (!Number.isFinite(busy) || busy <= 0) return 0;
  const background = Math.max(0, Number(stats.background_in_flight) || 0);
  return Math.max(0, busy - background) / cpus;
}
// Per-isolate stats cache. Isolates are recycled often, which is exactly why
// scan publishes its own history rather than beamline accumulating one: a cold
// isolate gets a warm estimate from the first poll instead of routing blind
// until it has seen enough traffic to learn.
const statsCache = new Map();

// The size buckets scan reports, and their upper bounds. Kept in step with
// SIZE_BUCKETS in scan's src/server/mod.rs.
const SIZE_BUCKETS = [
  ["le_1mb", 1 << 20],
  ["le_16mb", 16 << 20],
  ["le_128mb", 128 << 20],
  ["gt_128mb", Infinity],
];

// PURL types scan keeps separate averages for. Kept in step with
// PURL_TYPE_NAMES in scan's src/server/mod.rs.
const PURL_TYPES = new Set(["cargo", "golang", "npm", "pypi"]);

// The type between `pkg:` and the first `/`, or "other" — matching how scan
// buckets it, so the two agree on which average is being read.
function purlType(purl) {
  const rest = String(purl || "").replace(/^pkg:/i, "");
  const ty = rest.split("/")[0].toLowerCase();
  return PURL_TYPES.has(ty) ? ty : "other";
}

function sizeBucket(bytes) {
  for (const [name, bound] of SIZE_BUCKETS) {
    if (bytes <= bound) return name;
  }
  return "gt_128mb";
}

// One worker's /_/stats, cached. Never throws: a worker that cannot be polled
// is routed on no evidence rather than excluded, because "I could not ask" is
// not the same as "it is unhealthy" — the circuit breaker already owns that.


async function scanStats(env, ctx, base) {
  const now = Date.now();
  const hit = statsCache.get(base);
  if (hit && now - hit.at < STATS_TTL_MS) return hit.stats;
  let stats = null;
  try {
    stats = await fetchTimeout(
      `${base}/_/stats`,
      { method: "GET", headers: scanHeaders(env, ctx) },
      STATS_TIMEOUT_MS,
      // Deliberately not ctx: a caller hanging up should not poison the cache
      // for every later request in this isolate.
      null,
      async (resp) => (resp.ok ? await resp.json() : null),
    );
  } catch {
    stats = null;
  }
  statsCache.set(base, { at: now, stats });
  return stats;
}

// Predicted milliseconds until this worker returns a verdict for an artifact of
// `sizeHint` bytes.
//
// Service time alone, with no queueing term. Scan takes its slot with a
// non-blocking try_acquire_owned() and returns 429 "At capacity" when none is
// free, so a full worker is not slow — it is closed, and capability() excludes
// it. An earlier version of this added `ceil(in_flight/slots) * service` for a
// queue that does not exist, which over-penalized busy workers and oscillated:
// route away, watch the average decay, route back.
//
// Size matters more than a single average admits. The 12.5s/90s split above was
// one worker being slow at *large archives*, not slow in general — a scalar
// average would have branded it slow for every small package too, and sent
// those somewhere worse.
function predictMs(stats, hint, mix) {
  if (!stats) return UNKNOWN_JOB_MS;
  // Order matters. When a class was named but this worker has never done one,
  // the fleet mix is the wrong substitute: it is renormalized over whatever
  // this worker *has* done, so a machine that has only handled small files
  // would be predicted at its small-file speed for a 128MB artifact. Its own
  // blended average is the honest fallback — it at least contains every size it
  // has really seen. The mix is for requests with no class at all.
  const classed = classMs(stats, hint);
  // A lookup never falls back to an analysis average. classMs() says why —
  // "predicting it from an analysis average would be wrong by a factor of a
  // thousand" — and this chain used to walk straight past that guard one line
  // later, into blendedMs(). Measured in production: a worker reporting a real
  // 71ms lookup average was predicted at 1326ms from its analysis history, and
  // a worker with no history at all at UNKNOWN_JOB_MS, against a 116ms
  // incumbent. Neither could ever win, so neither was ever asked, so neither
  // ever gathered the samples that would have corrected it.
  const base = hint?.lookup
    ? (classed ?? UNKNOWN_JOB_MS)
    : (classed ?? (hint == null ? mixedMs(stats, mix) : null) ?? blendedMs(stats) ?? UNKNOWN_JOB_MS);
  // How long the work takes, then how likely this worker is to take it.
  return base * (1 + CAPACITY_WEIGHT * occupancy(stats));
}


// This worker's average for the cost class the request falls in, or null when
// it has never done one.
//
// Bytes give a size class. A PURL gives only its type — but the type is worth
// more than nothing by a wide margin: measured on this fleet, a golang
// pseudo-version (a repository clone) ran 120s while npm tarballs finished in
// single-digit seconds, and every one of them looked identical to a router
// reading one blended average.
// What one `/lookup` costs on this worker: an index probe, near-constant in
// the size of the artifact and three orders of magnitude cheaper than an
// analysis. Reported in microseconds because a healthy probe rounds to 0ms, and
// a routing signal that is always zero is no signal.
function lookupMsOf(stats) {
  if (!stats) return null;
  const windowed = recentMs(stats.recent_lookup);
  if (windowed != null) return windowed;
  // Below the sample floor the number is thin, and it is still used.
  //
  // The floor is there because one job is a story rather than a statistic, and
  // that reasoning holds for an analysis, where the alternative estimate is
  // another analysis measurement. It does not hold here, where the alternative
  // is this worker's *analysis* average or a flat 5000ms — not a cautious
  // estimate but a wrong one, wrong by twenty times, and wrong in the direction
  // that stops the worker ever being asked again. A thin measurement of the
  // right thing beats a confident measurement of the wrong one.
  //
  // hasHistory() still applies the floor, so a thin number ranks but does not
  // earn the jitter that damps herding between workers we actually trust.
  if (stats.avg_lookup_us != null) return stats.avg_lookup_us / 1000;
  return stats.avg_lookup_ms ?? null;
}

// Whether this worker's lookup estimate rests on enough samples to be trusted
// for tie-breaking, as opposed to merely being the best number available.
function lookupIsSettled(stats) {
  if (!stats) return false;
  if (recentMs(stats.recent_lookup) != null) return true;
  return stats.lookup_samples != null && stats.lookup_samples >= MIN_CLASS_SAMPLES;
}

function classMs(stats, hint) {
  if (hint == null) return null;
  // The cheap-source race asks the index, not the analyzer. Predicting it from
  // an analysis average would be wrong by a factor of a thousand.
  if (hint.lookup) return lookupMsOf(stats);
  if (hint.bytes == null) return bucketMs(stats.avg_job_ms_by_type?.[purlType(hint.purl)]);
  const name = sizeBucket(hint.bytes);
  // What this worker charged for this size under real load, and failing that,
  // what it took on the same size on its own time.
  //
  // A worker is only measured on work it was sent, and what it was sent is
  // this router's own doing - so a worker ranked slow is asked for nothing,
  // reports nothing, and stays ranked slow on the evidence of never having
  // been tried. Measured: a 128-slot worker sat at zero jobs for a whole
  // session while a 4-slot one took the whales, and the fleet's fastest
  // server on small work was ranked last on seven archives it happened to be
  // handed once.
  //
  // The idle series is the way out and costs nothing to collect: every worker
  // analyses hopper queue work on capacity it is not selling, drawn from the
  // same queue as every other worker and chosen by nobody's routing. The
  // worker with no traffic produces the most of it, which is exactly backwards
  // from the starvation above.
  //
  // Second rather than first: idle work runs uncontended, so it flatters a
  // busy server. Where this worker has really served this size, that is the
  // better answer; the idle figure is for the case there is no answer at all.
  // An older worker publishes no idle series, and then this is what it was.
  return (
    bucketMs(stats.avg_job_ms_by_size?.[name]) ?? bucketMs(stats.avg_job_ms_by_size_idle?.[name])
  );
}

// One bucket's figure: the window if it is settled, else the lifetime mean.
// Both floor themselves at MIN_CLASS_SAMPLES, so a thin bucket reads as no
// answer rather than a confident wrong one — except an empty one, which reads
// as no answer at all.
function bucketMs(bucket) {
  if (!bucket) return null;
  const windowed = recentMs(bucket.recent);
  if (windowed != null) return windowed;
  return emptyWindow(bucket.recent) ? null : meanMs(bucket);
}

// A worker that publishes a window and has nothing in it — distinct from one
// publishing no window at all, an older build whose mean is the only evidence
// there is. A thin window still describes work happening now, so two samples
// fall back to the mean; an empty one describes an hour of not being asked, and
// its mean is the stale figure the window exists to replace.
//
// Measured 2026-09-02: scan-rdu2 published an empty window over a mean carrying
// an old contended spell — 264-652s per type against a fleet publishing 50-57s.
// Nothing could outrank that, so it was asked for nothing, so its window stayed
// empty and the mean stayed its estimate. That is the trap classMs() warns
// about below, entered through a stale number rather than a missing one.
// Forcing 23 analyses onto it broke the cycle and the window came back at 59.7s.
//
// Unknown ranks at UNKNOWN_JOB_MS, under any real analysis, so such a worker
// goes to the front and fills its window in MIN_CLASS_SAMPLES jobs. That is the
// probe, and it is self-limiting: hasHistory() still reads false, so it ranks
// without earning the jitter kept for workers we trust.
function emptyWindow(recent) {
  return !!recent && recent.samples === 0;
}

// The windowed p80 a worker publishes for this class: what the work usually
// costs, over the last hour, including a bad day.
//
// Preferred over the lifetime mean for two reasons the fleet demonstrated.
// Analysis time is bimodal — seconds for a package, minutes for an archive —
// so a mean lands between the humps and describes almost no real job; measured
// live, mean-based estimates were out by roughly 10x against observed medians.
// And a mean over a sample count keeps reporting an incident long after it
// ends, where an hour-long window forgets on a clock.
function recentMs(recent) {
  if (!recent || recent.p80_ms == null) return null;
  if (recent.samples != null && recent.samples < MIN_CLASS_SAMPLES) return null;
  return recent.p80_ms;
}

// The lifetime mean, for a worker that has not been upgraded to publish a
// window yet. Same sample floor: one job is a story, not a statistic.
function meanMs(bucket) {
  if (!bucket || bucket.avg_ms == null) return null;
  if (bucket.jobs != null && bucket.jobs < MIN_CLASS_SAMPLES) return null;
  return bucket.avg_ms;
}

// The worker's blended average, if it rests on enough completions to mean
// something. Same threshold, same reason.
function blendedMs(stats) {
  const windowed = recentMs(stats.recent);
  if (windowed != null) return windowed;
  // Same rule as bucketMs, and for the same reason: guarding only the per-class
  // path would leave the stale mean to arrive here instead, one line later.
  if (emptyWindow(stats.recent)) return null;
  if (stats.avg_job_ms == null) return null;
  if (stats.avg_job_samples != null && stats.avg_job_samples < MIN_CLASS_SAMPLES) return null;
  return stats.avg_job_ms;
}

// Each worker's per-size averages re-weighted by one shared job mix.
//
// A PURL carries no size, so the obvious estimate is the worker's scalar
// average — but that is weighted by whatever mix of sizes it happened to
// receive, so comparing two scalars compares their workloads as much as their
// speeds. Measured live: one worker won on the scalar while being 45% slower on
// large artifacts and barely faster on small ones, purely because it had been
// fed more small work.
//
// Weighting every worker's buckets by the fleet's own distribution asks the
// comparable question: how long would *this* worker take on a typical job?
// Renormalized over the buckets a worker has actually seen, so a worker with no
// large-file history is judged on the sizes it can speak to rather than being
// credited with a zero.
function mixedMs(stats, mix) {
  if (!mix) return null;
  let weighted = 0;
  let total = 0;
  for (const [name, jobs] of mix) {
    const avg = stats.avg_job_ms_by_size?.[name]?.avg_ms;
    if (avg == null || !jobs) continue;
    weighted += avg * jobs;
    total += jobs;
  }
  return total ? weighted / total : null;
}

// The fleet's job distribution across size buckets: the shared yardstick above.
function jobMix(all) {
  const mix = new Map();
  for (const stats of all) {
    for (const [name, b] of Object.entries(stats?.avg_job_ms_by_size || {})) {
      if (b?.avg_ms != null && b.jobs) mix.set(name, (mix.get(name) || 0) + b.jobs);
    }
  }
  return mix.size ? mix : null;
}

// Does this estimate rest on anything the worker measured?
//
// A worker that answers /_/stats having completed no jobs reports a null
// average, and predictMs falls back to UNKNOWN_JOB_MS for it — a default, not
// evidence. Treating that as knowledge let a cold fleet hedge on a made-up
// number: every worker tied at 5000ms, ranked at random, and the second arm
// held 3750ms behind a coin toss. Answering /_/stats is not the same as having
// something to say.
function hasHistory(stats, hint, mix) {
  if (!stats) return false;
  if (hint?.lookup) return lookupIsSettled(stats);
  if (classMs(stats, hint) != null) return true;
  if (hint == null && mixedMs(stats, mix) != null) return true;
  return blendedMs(stats) != null;
}

// Can this worker answer *correctly*, never mind quickly?
//
// These are not preferences. A worker missing 7z returns a weaker verdict on a
// DMG rather than a slower one — and being weaker, it is also faster, so a
// purely latency-ranked router would actively prefer it.
function capability(stats, sizeHint) {
  if (!stats) return null; // unknown: let the breaker decide, not a guess
  if (stats.ready === false) return "not ready";
  if (stats.overloaded === true) return "overloaded";
  // A machine with more runnable threads than cores queues everything sent
  // to it, whatever its own slot count says. The slots describe the server;
  // the load describes the box the pull worker and any batch scan share with
  // it. Measured: `slots_free=48 in_flight=0` beside `load1=23` on 16 cores,
  // and an analysis dispatched there waited five minutes to start.
  //
  // Judged on foreground load, not the whole of it. The idle worker's jobs
  // are on the box and in load1, and they are the load that leaves when we
  // send work: it stops claiming the moment a request lands and the server
  // keeps a core reserve it cannot touch. Counting them here made a server
  // full of sheddable work unroutable, and nothing could clear that — the
  // worker yields to traffic, and the report kept the traffic away. Three of
  // four servers sat idle on the interactive path that way (2026-09-05).
  // They still rank below a quiet box: `occupancy` keeps the whole load.
  if (foregroundPressure(stats) > HOST_PRESSURE_LIMIT) return "host saturated";
  // Not a slow worker — a closed one. scan's slot acquire is non-blocking and
  // answers 429 rather than queueing, so dispatching here buys a rejection.
  if ((stats.slots_free ?? 1) <= 0) return "at capacity";
  // `!= null`, not truthiness: a worker advertising 0 accepts nothing, and
  // reading that as "no limit" sends it exactly the bodies it will refuse.
  if (sizeHint != null && stats.max_upload_mb != null && sizeHint > stats.max_upload_mb * 1024 * 1024) {
    return `upload limit ${stats.max_upload_mb}MB < ${sizeHint}B`;
  }
  return null;
}

// Order workers best-first, and say how long to hold the second arm.
//
// Ties and near-ties are broken randomly rather than by a stable sort. Always
// sending to the current best is self-reinforcing: everyone piles onto whichever
// worker last looked fastest until it is the slowest, then the fleet flips. A
// little jitter damps that for no measurable loss.
// Two estimates tie when picking the nominally-faster one would be chasing
// noise, and jitter should break the tie instead.
//
// 250ms alone was right for analyses and wrong for lookups: it is 1.4% of an
// 18-second estimate and wider than the entire dynamic range of a lookup, so
// every pair of lookups fell inside it and ranking them degenerated to the coin
// toss meant only for near-equals. Observed live, with estimates of 29ms, 57ms
// and 105ms dispatched slowest-but-one first.
//
// So the fraction *narrows* the band for small estimates and never widens it.
// Taking the larger of the two instead would have made a 1000ms gap between two
// ~18s analyses a tie — and that gap is the capacity term doing its job, which
// is the one thing here that was already working.
const TIE_CEILING_MS = 250;
const TIE_FRACTION = 0.25;
function tiedEst(a, b) {
  return Math.abs(a - b) < Math.min(TIE_CEILING_MS, TIE_FRACTION * Math.min(a, b));
}

// The stats we already hold for a worker, or undefined when we would have to
// go and ask. Distinct from null, which means we asked and it did not answer.
function cachedStats(base) {
  const hit = statsCache.get(base);
  return hit && Date.now() - hit.at < STATS_TTL_MS ? hit.stats : undefined;
}

// Round-robin start, per isolate. Used only when there is nothing measured to
// rank on; the point is merely never to start at the same worker every time.
let lookupTurn = 0;
function rotate(workers) {
  const start = lookupTurn++ % workers.length;
  return [...workers.slice(start), ...workers.slice(0, start)];
}

// Measured, 400 lookups per arm against the live fleet, interleaved so every
// arm saw the same fleet at the same instant. p50 / p90, milliseconds:
//
//   latency+load     47 /  51    rdu 99%
//   latency          49 /  53    rdu 99%
//   p2c              49 /  99    rdu 68% mci 32%
//   least-inflight   55 / 154    rdu 58% mci 25% lax 18%
//   rotate           98 / 160    even thirds
//   config          156 / 173    lax 100%
//
// Two things came out of it. Choosing beats spreading on a fleet whose workers
// differ — rdu answers a lookup in a third of lax's time, so every request
// spread onto a slower worker is latency paid for nothing, and the three
// spreading arms rank last. And least-outstanding is capacity-blind: it sent
// 18% to the slowest worker in the fleet because it happened to have an empty
// queue, which is the classic least-connections failure against unequal
// backends.
//
// The load arm is *unproven*, not rejected. It scaled the estimate by lookup
// concurrency derived from `recent_lookup` over `latency_window_secs`, which is
// 3600 on scan today — a
// half-minute experiment barely moves an hour-long window, so the term
// evaluated to ~0.001 and the two latency arms were the same algorithm. Its 2ms
// edge is noise. Testing it needs a short window on scan's side, or a fleet
// under real analysis load.
// Same order rankPool() produces, and for the same reasons: measurement first,
// jitter to damp herding between workers we have evidence for, and the
// operator's own order when we have none. Jitter without that last guard is a
// coin toss dressed up as a decision — and it makes a worker that should be
// draining out of the pool accumulate its failures at random.
function byEst(ranked) {
  return [...ranked]
    .sort((x, y) => {
      if (!tiedEst(x.est, y.est)) return x.est - y.est;
      if (x.known && y.known) return x.r - y.r;
      return x.i - y.i;
    })
    .map((w) => w.base);
}

// Measured for /analyze too, 20 analyses per arm at 40-way concurrency, which
// is enough to make mci's six slots scarce. p50 / p90, and refusals collected:
//
//   latency            17.7s / 56.2s    0 x 429
//   latency+occupancy  17.8s / 56.4s    0 x 429
//   p2c                26.5s / 57.3s    0 x 429
//   rotate             34.4s / 61.9s    4 x 429
//   config             39.1s / 71.2s    7 x 429
//
// Ranking is worth 55% of the p50, and the arms that rank collected no capacity
// refusals at all while the two that do not collected eleven between them.
//
// But the capacity term is not what earned that. `latency` scores on service
// time alone and ties with the production path exactly, because the hard gate
// in capability() excludes a worker with no free slots before ranking sees it —
// by the time the multiplier would matter, the worker is about to be removed
// anyway. And it cannot reorder anything below that: this fleet's service-time
// predictions span 10-15x (2560, 28415, 39482 in one dispatch), which no
// occupancy factor of 1.x is going to overturn.
//
// So occupancy is kept, unproven either way. It earns its place only when two
// workers are close on service time and differ in load, and a fleet of three
// unequal machines never presents that case. A homogeneous fleet would.
// The order to try workers in for a lookup, at no cost to the lookup.
//
// Ranking is worth having here — measured directly, the fastest worker answered
// a lookup in 95ms and the slowest in 200ms — but rankPool() pays a stats poll
// to learn that, and on a cold isolate one poll costs more than the request it
// is optimizing. So this ranks only when every worker's stats are already in
// hand, and otherwise answers immediately and fetches them behind the response.
// An isolate is unranked for its first lookup and ranked for the next ten
// seconds of them.
//
// What it must never do is take the configured order. That is what it did
// before, and it sent 390 of 390 lookups to the slowest worker in the fleet
// while the fastest sat idle.
async function lookupOrder(env, ctx, workers, ids) {
  if (workers.length < 2) return workers;
  if (!workers.every((base) => cachedStats(base) !== undefined)) {
    waitUntil(ctx, Promise.all(workers.map((base) => scanStats(env, ctx, base))));
    return rotate(workers);
  }
  const mix = jobMix(workers.map((base) => cachedStats(base)));
  const hint = { lookup: true };
  const ranked = workers.map((base, i) => {
    const stats = cachedStats(base);
    return {
      base,
      stats,
      i,
      est: predictMs(stats, hint, mix),
      known: hasHistory(stats, hint, mix),
      r: Math.random(),
    };
  });
  const order = byEst(ranked);
  logLine("lookup_route", { order: order.map(hostOf).join(","), ...ids });
  return order;
}

async function rankPool(env, ctx, workers, hint) {
  const polled = await Promise.all(
    workers.map(async (base, i) => ({ base, i, stats: await scanStats(env, ctx, base) })),
  );
  // One shared yardstick for the whole fleet, so it has to be built from every
  // worker's history before any single worker can be scored against it.
  const mix = jobMix(polled.map((w) => w.stats));
  const scored = polled.map(({ base, i, stats }) => ({
    base,
    stats,
    i,
    est: predictMs(stats, hint, mix),
    known: hasHistory(stats, hint, mix),
    why: capability(stats, hint?.bytes ?? null),
    r: Math.random(),
  }));
  const usable = scored.filter((w) => w.why == null);
  // Everything filtered out means the filter is wrong, or the fleet is. Either
  // way, refusing to dispatch is worse than dispatching on stale information.
  const pool = usable.length ? usable : scored;
  // Near-ties break randomly *only between workers we have evidence for*.
  // Always picking the current best is self-reinforcing — everyone piles onto
  // whichever worker last looked fastest until it is the slowest, then the
  // fleet flips — and jitter damps that. With no evidence there is nothing to
  // damp, and the order the operator configured is a better guess than a coin
  // toss, so ties fall back to it.
  pool.sort((a, b) => {
    // A worker we could not poll ranks behind one we could.
    //
    // This was backwards: an unpollable worker got UNKNOWN_JOB_MS, and 5000ms
    // beats a worker honestly reporting 8000ms — so failing to answer promoted
    // you. Observed live when a fleet was pointed at the wrong hostnames: every
    // request went first to a worker that could not be reached at all. Being
    // unreachable is not proof of illness (the breaker owns that), but it is
    // not evidence of health either, and it must never outrank measurement.
    if ((a.stats == null) !== (b.stats == null)) return a.stats == null ? 1 : -1;
    if (!tiedEst(a.est, b.est)) return a.est - b.est;
    if (a.known && b.known) return a.r - b.r;
    return a.i - b.i;
  });
  // No exploration here on purpose. A previous revision promoted a random
  // non-favourite on 10% of requests, to stop a worker being trapped by a
  // reputation its own starved sample set could never repair. The measurement
  // that motivated it did not survive scrutiny — the worker in question was
  // winning half the fleet's work at the time — so the cost (a tenth of all
  // dispatches sent somewhere the evidence says is slower) bought a fix for a
  // problem never shown to exist. If per-worker averages do turn out to be
  // biased by the routing itself, the honest repair is to make the samples
  // comparable, not to dilute the ranking that reads them.
  // `informed` says the favourite was chosen on measurement rather than on the
  // configured order, which is the difference between a plan worth reading and
  // a coin toss.
  return { pool, excluded: usable.length ? scored.filter((w) => w.why != null) : [], informed: pool[0].known };
}

async function rankWorkers(env, ctx, workers, ids, hint) {
  const ranked = await rankPool(env, ctx, workers, hint);
  logLine("scan_route", {
    order: ranked.pool.map((w) => hostOf(w.base)).join(","),
    est_ms: ranked.pool.map((w) => Math.round(w.est)).join(","),
    excluded: ranked.excluded.length || undefined,
    informed: ranked.informed || undefined,
    size: hint?.bytes ?? undefined,
    type: hint?.purl ? purlType(hint.purl) : undefined,
    ...ids,
  });
  return ranked.pool.map((w) => w.base);
}

// GET /_/routes[?size=<bytes|10mb>] — what the router would do right now.
//
// A dry run of the real ranking, not a description of it: it calls the same
// rankPool() a dispatch calls, so the two cannot drift. Without ?size it
// answers for every size bucket at once, which is the view that shows a worker
// being fast at small packages and slow at large ones — the case a single
// average hides and the reason routing is size-aware at all.
//
// Behind the token gate with everything else: this names every worker and its
// current load.
async function handleRoutes(env, ctx, url) {
  // Three ways to ask, matching the three ways a request arrives: by the PURL
  // itself, by a bare type, or by an upload size. With none of them, answer for
  // every class at once — which is the view that shows one worker leading on
  // npm and another on golang.
  const rawSize = (url.searchParams.get("size") || "").trim();
  const rawType = (url.searchParams.get("type") || "").trim();
  const rawPurl = (url.searchParams.get("purl") || "").trim();
  const size = rawSize && rawSize.toLowerCase() !== "none" ? parseSize(rawSize) : null;
  if (rawSize && rawSize.toLowerCase() !== "none" && size == null) {
    return v1Error(400, "invalid_size", `Could not read ${rawSize} as a size.`);
  }

  const all = urlList(env.SCAN_URL);
  if (!all.length) return v1Error(503, "no_workers", "No SCAN_URL is configured.");
  // scanWorkers() filters tripped workers out before ranking ever sees them,
  // so a breaker-excluded worker would otherwise just vanish from this view
  // with no explanation — which is precisely when an operator is looking.
  const live = all.filter((base) => !breakerFor(base).open());

  let classes;
  if (rawType.toLowerCase() === "lookup") classes = [{ kind: "lookup", name: "lookup", hint: { lookup: true } }];
  else if (rawPurl) classes = [{ kind: "purl_type", name: purlType(rawPurl), hint: { purl: rawPurl } }];
  else if (rawType) classes = [{ kind: "purl_type", name: purlType(`pkg:${rawType}/x`), hint: { purl: `pkg:${rawType}/x` } }];
  else if (size != null) classes = [{ kind: "size", name: sizeBucket(size), bytes: size, hint: { bytes: size } }];
  else if (rawSize) classes = [{ kind: "unsized", name: "unsized", hint: null }];
  else {
    classes = [
      { kind: "lookup", name: "lookup", hint: { lookup: true } },
      ...["npm", "pypi", "cargo", "golang"].map((t) => ({
        kind: "purl_type",
        name: t,
        hint: { purl: `pkg:${t}/x` },
      })),
      ...SIZE_BUCKETS.map(([n, b]) => {
        const bytes = b === Infinity ? (128 << 20) + 1 : b;
        return { kind: "size", name: n, bytes, hint: { bytes } };
      }),
    ];
  }

  const routes = [];
  for (const c of classes) {
    if (!live.length) {
      routes.push({ class: c.name, kind: c.kind, dispatch: [], note: "every worker's breaker is open" });
      continue;
    }
    const ranked = await rankPool(env, ctx, live, c.hint);
    routes.push({
      class: c.name,
      kind: c.kind,
      size_bytes: c.bytes,
      informed: ranked.informed,
      // The order a dispatch would try, favourite first. One worker is asked at
      // a time and the next is reached only when the one before it refuses or
      // fails, so this is a queue rather than a set of arms.
      dispatch: ranked.pool.map((w) => ({
        worker: hostOf(w.base),
        est_ms: Math.round(w.est),
      })),
      excluded: ranked.excluded.map((w) => ({ worker: hostOf(w.base), reason: w.why })),
    });
  }

  // Stamped after ranking, not before: rankPool refreshes the stats cache, so a
  // `now` taken up front is older than the readings it is used to age and every
  // fresh poll reports a negative age.
  const now = Date.now();
  return json(
    {
      stats_ttl_ms: STATS_TTL_MS,
      workers: all.map((base) => {
        const hit = statsCache.get(base);
        return {
          worker: hostOf(base),
          breaker: breakerFor(base).open() ? "open" : "closed",
          stats_age_ms: hit ? now - hit.at : undefined,
          // null means polled and unanswered, which is not the same as never
          // polled — one is a worker in trouble, the other is a cold isolate.
          stats: hit ? hit.stats : undefined,
        };
      }),
      routes,
    },
    200,
  );
}

// Bytes, or a human size like "10mb". Returns null on anything else.
function parseSize(raw) {
  const m = /^(\d+(?:\.\d+)?)\s*(b|kb|mb|gb)?$/i.exec(raw);
  if (!m) return null;
  const scale = { b: 1, kb: 1 << 10, mb: 1 << 20, gb: 1 << 30 }[(m[2] || "b").toLowerCase()];
  const n = Number(m[1]) * scale;
  return Number.isFinite(n) && n >= 0 ? Math.round(n) : null;
}
// Exponential with full jitter, capped: a burst of waiters on the same sample
// spreads out instead of retrying in lockstep.
function backoff(base, attempt, cap) {
  const ceiling = Math.min(base * 2 ** Math.min(attempt, 10), cap);
  return ceiling <= base ? base : base + Math.random() * (ceiling - base);
}

function scanHeaders(env, ctx) {
  return backendHeaders(env.SCAN_TOKEN, ctx);
}

function backendHeaders(token, ctx) {
  const tok = (token || "").trim();
  const headers = { "x-request-id": ctx.rid };
  if (tok) headers.authorization = `Bearer ${tok}`;
  return headers;
}

// A PURL from a backend header, bounded before it can become a cache key.
// Length-capped and ASCII-only: a key is a URL we build, and an unbounded or
// unspellable one is either a request we cannot make or an entry nothing can
// read back. Must look like a PURL, so a confused worker cannot file an
// answer under something that is not a coordinate at all.
function cleanPurl(raw) {
  const value = String(raw || "").trim();
  if (!value || value.length > 512) return null;
  if (!/^pkg:[a-zA-Z0-9.+-]+\/[\x21-\x7e]*$/.test(value)) return null;
  return value;
}

function tokenList(raw) {
  return String(raw || "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
}

function clientAborted(ctx) {
  return !!(ctx && ctx.signal && ctx.signal.aborted);
}

function tokenEq(a, b) {
  if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length) return false;
  let x = 0;
  for (let i = 0; i < a.length; i++) x |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return x === 0;
}

// Scan's lookup answers in the same shape we serve, so the body passes
// through untouched but for `bloom`, which is our upstream's business and not
// part of this API. Never re-derive it through customerView: there is no
// envelope here to derive from.
function verdictResponse(env, verdict, input, maxAge) {
  const view = {};
  for (const [k, v] of Object.entries(verdict)) {
    if (k !== "bloom" && v !== null && v !== undefined) view[k] = v;
  }
  // Benign artifacts routinely carry notable findings, and scan stores them.
  // `hits` is documented as present only when `lvl != -1`, so drop them here
  // the way customerView does on every other path — one artifact must not
  // change shape depending on which layer answered.
  if (view.lvl === -1) delete view.hits;
  if (!view.sha && input.sha) view.sha = input.sha;
  if (!view.purl && input.purl) view.purl = input.purl;
  const headers = {
    "content-type": "application/json",
    "cache-control": `${cacheScope(env)}, max-age=${maxAge}`,
    "x-beamline-source": "scan:analysis",
  };
  if (view.sha) headers["x-sha256"] = view.sha;
  return new Response(JSON.stringify(view), { status: 200, headers });
}

function bloomStub(env, sha, purl) {
  return envelopeResponse(env, { ml: { lvl: -1, eng: "beamline" } }, sha, "scan:bloom", 3600, null, purl);
}

function envelopeResponse(env, envelope, sha, source, maxAge, totalMs, purl) {
  const view = customerView(envelope, sha, purl);
  const headers = {
    "content-type": "application/json",
    "cache-control": `${cacheScope(env)}, max-age=${maxAge}`,
    "x-beamline-source": source,
  };
  if (view.sha) headers["x-sha256"] = view.sha;
  if (totalMs != null && totalMs !== "") headers["x-total-ms"] = String(totalMs);
  return new Response(JSON.stringify(view), { status: 200, headers });
}

// Authenticated answers are private to everything between us and the client.
// Our own cache is a different matter. The scope a client's copy carries is
// restored independently from the copy stored in the edge cache.
// What a v1 answer tells the caller about holding it.
//
// One rule, because it was two: this said `public` with no max-age for an
// uncacheable answer while `v1Body` said `no-store` for the same thing, and a
// bare `public` lets a shared cache keep — on its own heuristics — the one
// answer we meant nobody to keep. Unreachable today, since only a document that
// earned a TTL is ever in the cache to be re-served, which is exactly how two
// spellings of one rule survive long enough to diverge.
function clientScope(env, maxAge) {
  return maxAge ? `${cacheScope(env)}, max-age=${maxAge}` : "no-store";
}

function cacheScope(env) {
  return (env.BEAMLINE_TOKEN || "").trim() ? "private" : "public";
}

function customerView(envelope, sha, purl) {
  const ml = envelope && envelope.ml;
  const out = {};
  const hex = (sha && SHA_RE.test(sha) && sha) || shaFromEnvelope(envelope);
  if (hex) out.sha = hex;
  if (purl) out.purl = purl;
  if (ml && ml.lvl != null) out.lvl = ml.lvl;
  if (ml && ml.eng) out.eng = ml.eng;
  const why = llmWhy(envelope && envelope.llm);
  if (why) out.why = why;
  if (out.lvl !== -1) {
    const hits = topHits(envelope && envelope.raw, purl);
    if (hits.length) out.hits = hits;
  }
  return out;
}

function llmWhy(llm) {
  if (!llm) return "";
  if (typeof llm === "string") return llm.trim();
  const s = llm.interpretation || llm.why || "";
  return typeof s === "string" ? s.trim() : "";
}

function topHits(raw, purl) {
  const files = (raw && (raw.files || raw.fs)) || [];
  const rows = [];
  const seen = new Set();
  for (const f of files) {
    const traits = (f && (f.traits || f.findings)) || [];
    const file = hitFile(f && f.path);
    const ident = identPkg(f);
    for (const t of traits) {
      const crit = Number(t && t.crit);
      const id = t && t.id;
      if (!id || !Number.isFinite(crit) || crit < HIT_MIN_CRIT) continue;
      // Native matches only. A finding with `from` is the same match reported
      // again on an enclosing archive — the member's own copy carries the real
      // path and offset, and we walk every file — or a cross-file composite,
      // which has no single place to point at.
      if (Array.isArray(t.from) && t.from.length) continue;
      const pkg = (t.dep && t.dep.locator) || purl || ident || "";
      const key = `${id}\0${file}\0${pkg}`;
      if (seen.has(key)) continue;
      seen.add(key);
      const hit = { id, crit };
      if (t.desc) hit.desc = t.desc;
      if (file) hit.file = file;
      if (pkg) hit.pkg = pkg;
      const at = hitLocation(f, id, t);
      if (at.off != null) hit.off = at.off;
      if (at.line != null) hit.line = at.line;
      rows.push(hit);
    }
  }
  rows.sort((a, b) => b.crit - a.crit || a.id.localeCompare(b.id));
  return rows.slice(0, HIT_LIMIT);
}

// Where a match fired. The context windows carry a note per match holding its
// exact byte offset; the window's `line` labels its first byte, which is the
// line to quote for a match inside it. Binary windows have no line structure.
// A report whose context was trimmed falls back to the finding's own first
// evidence span, which locates it without naming a line.
function hitLocation(file, id, trait) {
  for (const w of (file && file.ctx) || []) {
    for (const n of (w && w.n) || []) {
      if (n && n.i === id) {
        return { off: num(n.o), line: num(w.line) };
      }
    }
  }
  const span = trait && Array.isArray(trait.spans) && trait.spans[0];
  return { off: Array.isArray(span) ? num(span[0]) : null, line: null };
}

function num(v) {
  return Number.isFinite(Number(v)) ? Number(v) : null;
}

function hitFile(path) {
  if (!path) return "";
  let p = String(path);
  if (p.includes("!!")) p = p.split("!!").pop();
  else if (p.includes("!")) p = p.split("!").pop();
  return p.replace(/^\/+/, "") || "";
}

function identPkg(f) {
  const ident = (f && (f.ident || f.identity)) || {};
  if (!ident.name) return "";
  return ident.version ? `${ident.name}@${ident.version}` : ident.name;
}
function shaFromEnvelope(body) {
  const sha = body?.raw?.files?.[0]?.sha;
  return typeof sha === "string" ? sha.toLowerCase() : "";
}
// Scan is reached over ordinary fetch: each worker sits behind a Cloudflare
// Tunnel with a public hostname, so the edge does the routing.
//
// `read` runs inside the timeout and the client's abort, because a backend
// that sends headers promptly can still stall mid-body. Nothing may touch the
// Response after fetchTimeout returns.
async function fetchTimeout(url, opts, ms, ctx, read) {
  const ac = new AbortController();
  const outer = ctx && ctx.signal;
  if (outer && outer.aborted) {
    throw new DOMException("Aborted", "AbortError");
  }
  const onAbort = () => ac.abort();
  if (outer) outer.addEventListener("abort", onAbort, { once: true });
  const t = setTimeout(() => ac.abort(), ms);
  try {
    return await read(await fetch(url, { ...opts, signal: ac.signal }));
  } finally {
    clearTimeout(t);
    if (outer) outer.removeEventListener("abort", onAbort);
  }
}

// A body nobody reads pins its connection until the collector notices.
async function drain(resp) {
  try {
    await resp.body?.cancel();
  } catch {
    // The peer is gone; the connection is going away with it.
  }
}

async function getCache(env) {
  if (env && env.cache) return env.cache;
  try {
    if (typeof caches !== "undefined" && caches.default) return caches.default;
  } catch {
    // Workers without Cache API, or Node.
  }
  if (!getCache.memory) getCache.memory = memoryCache();
  return getCache.memory;
}

function memoryCache() {
  const map = new Map();
  return {
    async match(req) {
      const id = cacheId(req);
      const row = map.get(id);
      if (!row) return null;
      if (row.exp && Date.now() > row.exp) {
        map.delete(id);
        return null;
      }
      map.delete(id);
      map.set(id, row);
      return new Response(row.body, { status: row.status, headers: row.headers });
    },
    async put(req, res) {
      const cc = res.headers.get("cache-control") || "";
      // Refused here because Cloudflare refuses them there. A stand-in that is
      // more permissive than the real cache proves nothing: the analyze path
      // stored `private` for as long as it existed and every test passed.
      if (/(^|,\s*)(private|no-store|no-cache)\b/.test(cc)) return;
      const m = /max-age=(\d+)/.exec(cc);
      const maxAge = m ? Number(m[1]) : 3600;
      while (map.size >= MEMORY_CACHE_MAX) map.delete(map.keys().next().value);
      map.set(cacheId(req), {
        body: await res.clone().arrayBuffer(),
        status: res.status,
        headers: [...res.headers],
        exp: Date.now() + maxAge * 1000,
      });
    },
  };
}

function cacheId(req) {
  return typeof req === "string" ? req : req.url;
}

// The copy that goes into our cache.
//
// Cloudflare will not store a `private` response, which would silently leave
// every token-protected deployment with no cache at all. Our cache sits behind
// the 401 and every valid token gets the same answer, so the stored copy drops
// the directive that the client's copy keeps.
//
// Every writer goes through here. When only one of them did, the other wrote
// `private` for as long as it existed and Cloudflare dropped all of it.
function storedCopy(res) {
  const copy = res.clone();
  const cc = copy.headers.get("cache-control") || "";
  if (cc.startsWith("private")) copy.headers.set("cache-control", cc.replace("private", "public"));
  return copy;
}

function storedDocument(body, env) {
  const canonical = v1DocumentBody(body) || body;
  return storedCopy(
    new Response(canonical, {
      status: 200,
      headers: {
        "content-type": "application/json",
        "cache-control": `${cacheScope(env)}, max-age=${v1MaxAge(canonical)}`,
      },
    }),
  );
}

function waitUntil(ctx, p) {
  const q = Promise.resolve(p).catch((err) => {
    logLine("wait_error", { err: errText(err) });
  });
  if (ctx && typeof ctx.waitUntil === "function") ctx.waitUntil(q);
}
function numEnv(env, key, fallback) {
  if (!env || env[key] == null || env[key] === "") return fallback;
  const n = Number(env[key]);
  return Number.isFinite(n) && n >= 0 ? n : fallback;
}

function cleanId(s) {
  return String(s || "").replace(/[^A-Za-z0-9._:-]/g, "").slice(0, 64);
}

function errText(err) {
  return String((err && err.message) || err);
}
// Workers Logs indexes the fields of an object handed to console.log, and
// treats a JSON string as one opaque message. `src` is what says whether a
// lookup was served from cache, so it has to go out as a field or the hit rate
// is only reachable by text search. Node has no such indexer and renders an
// object in a form nothing can parse, so `node local.js` keeps the flat line.
const STRUCTURED_LOGS =
  typeof navigator !== "undefined" && navigator.userAgent === "Cloudflare-Workers";

function logLine(event, fields) {
  if (logLine.mute) return;
  try {
    const row = { event };
    for (const k of Object.keys(fields || {})) {
      if (fields[k] !== undefined) row[k] = fields[k];
    }
    console.log(STRUCTURED_LOGS ? row : JSON.stringify(row));
  } catch {
    // Logging must never fail a lookup.
  }
}

function breakerFor(base) {
  let breaker = scanBreakers.get(base);
  if (!breaker) {
    breaker = makeBreaker();
    scanBreakers.set(base, breaker);
  }
  return breaker;
}

// SCAN_URL is one URL or a comma-separated list of interchangeable workers.
function urlList(raw) {
  return tokenList(raw).map(trimSlash).filter(Boolean);
}

// Workers worth asking right now. Empty means every one of them is tripped,
// and the caller should fail fast rather than pile on.
// The workers worth trying, healthiest first.
//
// A tripped breaker steers traffic to a healthier worker. When every worker is
// tripped there is no healthier worker, and the breaker has nothing left to
// steer — so it must not be allowed to empty the pool. Returning nothing here
// meant answering `unavailable` without having asked anyone, which is not a
// measurement of the fleet, only of our own bookkeeping.
//
// This is not hypothetical: a burst of lookups that ran past the timeout tripped
// all three workers within the first second, and the next 392 requests were
// answered `unavailable` in 25ms each without a single outbound fetch. The
// fleet was healthy throughout. Same rule scan's own corpus reader follows for
// the same reason — an address believed to be failing still beats no address.
function scanWorkers(env, pin) {
  const all = urlList(env.SCAN_URL);
  // A pin names one worker and means it. Falling back to another would answer
  // a question nobody asked: the header exists so an experiment can time a
  // chosen backend, and a silent substitution reports that backend's timing for
  // someone else's work. Measured live before this existed — every pinned
  // request went wherever the router liked, and two benchmarks scored the
  // router against itself without either of them noticing.
  //
  // The breaker is deliberately not consulted: a caller naming one worker has
  // already made the choice this filter exists to make for it, and timing a
  // worker that is currently failing is a legitimate thing to want.
  if (pin) return all.filter((base) => hostOf(base) === pin);
  const live = all.filter((base) => !breakerFor(base).open());
  return live.length ? live : all;
}

// Host only: enough to tell workers apart in a log line, without spilling the
// full internal URL into every record.
function hostOf(base) {
  try {
    return new URL(base).host;
  } catch {
    return base;
  }
}

function makeBreaker() {
  let fails = 0;
  let openUntil = 0;
  return {
    ok() {
      fails = 0;
    },
    fail() {
      fails += 1;
      if (fails >= BREAKER_FAILS) openUntil = Date.now() + BREAKER_COOL_MS;
    },
    // Half-open once the cooldown passes: the worker gets one trial, and a
    // success clears its record.
    //
    // Without this the counter survives the cooldown, so a worker that has
    // tripped once needs five failures the first time and exactly one ever
    // after — a hair trigger that no amount of subsequent good behaviour
    // resets, because the successes that would clear it are the ones the open
    // breaker is preventing.
    open() {
      if (Date.now() < openUntil) return true;
      if (fails >= BREAKER_FAILS) fails = BREAKER_FAILS - 1;
      return false;
    },
    reset() {
      fails = 0;
      openUntil = 0;
    },
  };
}

function json(obj, status) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "content-type": "application/json" },
  });
}

// `GET /analyze` is the easy mistake — dropping the body to analyze a PURL also
// drops the POST that `--data-binary` was implying — and a 404 would send the
// caller hunting for a misspelled path instead of a missing flag. RFC 9110
// requires the `Allow` header here; the detail repeats it for anyone reading
// only the body.
function methodNotAllowed(allow) {
  const body = { error: { code: "method_not_allowed", message: `Use ${allow}.` } };
  return new Response(JSON.stringify(body), {
    status: 405,
    headers: { "content-type": "application/json", "cache-control": "no-store", allow },
  });
}

function sleep(ms, ctx) {
  const outer = ctx && ctx.signal;
  if (outer && outer.aborted) return Promise.reject(new DOMException("Aborted", "AbortError"));
  return new Promise((resolve, reject) => {
    const settle = (fn, arg) => {
      clearTimeout(t);
      if (outer) outer.removeEventListener("abort", onAbort);
      fn(arg);
    };
    const onAbort = () => settle(reject, new DOMException("Aborted", "AbortError"));
    const t = setTimeout(() => settle(resolve), ms);
    if (outer) outer.addEventListener("abort", onAbort, { once: true });
  });
}

function trimSlash(s) {
  return String(s || "").replace(/\/+$/, "");
}

export const _test = {
  occupancy,
  capability,
  foregroundPressure,
  machineBusy,
  CACHE_LAYERS,
  beamlineSource,
  followCandidates,
  predictMs,
  hasHistory,
  jobMix,
  UNKNOWN_JOB_MS,
  tiedEst,
  rotate,
  scanWorkers,
  breakerFor,
  bloomStub,
  verdictResponse,
  hitLocation,
  shaFromEnvelope,
  customerView,
  topHits,
  SHA_RE,
  DEFAULT_SCAN_TIMEOUT_MS,
  LOOKUP_TIMEOUT_MS,
  MEMORY_CACHE_MAX,
  BREAKER_FAILS,
  makeBreaker,
  memoryCache,
  annotatedV1Stream,
  tokenEq,
  tokenList,
  classMs,
  cleanPurl,
  v1CacheAliasPaths,
  numEnv,
  reset() {
    scanBreakers.clear();
    getCache.memory = null;
    logLine.mute = false;
  },
  muteLogs(on) {
    logLine.mute = !!on;
  },
};
