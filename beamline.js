// Beamline: cache → scan lookup → hopper, with scan as a hedge. Zero deps.
// Cloudflare Worker and `node local.js` share this fetch handler.
//
// Hopper GET /api/sample can hang. Wait HOPPER_HEDGE_MS for a 200, then start
// scan without cancelling hopper. First useful answer wins. Hopper is aborted
// when we reply, or at HOPPER_LOOKUP_MS, whichever is first.

const SHA_RE = /^[0-9a-f]{64}$/;
const DEFAULT_MAX_BYTES = 16 * 1024 * 1024;
const DEFAULT_SCAN_TIMEOUT_MS = 1_800_000;
const LOOKUP_TIMEOUT_MS = 500;
// What hopper answers for an artifact it holds but has not analyzed: the one
// outcome worth waiting on, because somebody is already producing the answer.
// 204 is the same state from a hopper that predates the 202, and is accepted so
// a mixed-version fleet does not read "queued" as "nothing here".
const HOPPER_QUEUED = 202;
function isQueued(status) {
  return status === HOPPER_QUEUED || status === 204;
}

// How long the analysis arm waits on a silent hopper before starting anyway.
//
// A policy number, not a measurement: hopper's lookups are tightly clustered at
// 25-117ms, so this is not tracking a distribution — it is answering "how long
// is it worth stalling a caller before spending a scan slot". 500ms is roughly
// four times the observed p99, so it fires on genuine silence and nothing else.
// A definite miss does not wait at all; only silence does.
const HOPPER_HEDGE_MS = 500;
const HOPPER_LOOKUP_MS = 15_000;
const HOPPER_RPC_MS = 2_000;
const HEDGE = Symbol("hedge");
const HOPPER_POLL_MS = 500;
const BREAKER_FAILS = 5;
const BREAKER_COOL_MS = 10_000;
const MEMORY_CACHE_MAX = 1024;
const HIT_LIMIT = 3;
const HIT_MIN_CRIT = 3;
const POLL_MAX_MS = 5_000;
const SCAN_RETRIES = 5;
const SCAN_RETRY_BASE_MS = 1_000;
const SCAN_RETRY_MAX_MS = 30_000;
const EDGE_TIMEOUT = 524;
const MISS_MAX_AGE = 60;
// How long a real verdict stays served from our cache. Deliberately short
// while the service is still moving: a verdict that turns out wrong clears
// within the hour rather than sitting in every colo for a day. Raise
// VERDICT_MAX_AGE once the shape of the answers has settled — the cache is
// per-colo and per-key, so a longer life is the whole of the hit rate.
const VERDICT_MAX_AGE = 3600;
const RETRY_AFTER_MIN_S = 3;
const RETRY_AFTER_MAX_S = 8;

// Per isolate, not global: on Workers each isolate counts its own failures and
// loses them when it is recycled, so a backend outage costs BREAKER_FAILS
// requests per live isolate, not five in total. Same for inflight — it collapses
// duplicate work within one isolate; the cache and hopper do it across them.
const hopperBreaker = makeBreaker();
// One breaker per scan worker, keyed by base URL. A single shared breaker would
// let one sick worker disable scanning altogether.
const scanBreakers = new Map();
const inflight = new Map();

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
export function handle(request, env, ctx) {
  return dispatch(request, env, ctx);
}

async function dispatch(request, env, ctx) {
  // One id for the whole request, logged on every line and sent to hopper and
  // scan, so a slow lookup can be followed across all three services. A caller
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

  const allowed = tokenList(env.BEAMLINE_TOKEN);
  if (allowed.length) {
    const bearer = /^Bearer\s+(\S+)/i.exec((request.headers.get("authorization") || "").trim());
    const got = bearer ? bearer[1] : "";
    if (!allowed.some((t) => tokenEq(got, t))) {
      return json({ error: "unauthorized" }, 401);
    }
  }

  try {
    if (url.pathname === "/analyze") {
      if (request.method !== "POST") return methodNotAllowed("POST");
      return await handleAnalyze(request, env, ctx, url);
    }
    if (url.pathname === "/lookup") {
      if (request.method !== "GET") return methodNotAllowed("GET");
      const sha = (url.searchParams.get("sha256") || "").trim();
      const purl = (url.searchParams.get("purl") || "").trim();
      if (!sha && !purl) {
        return json({ error: "provide sha256, purl, or both" }, 400);
      }
      return await lookupKey(env, ctx, url.origin, sha, purl);
    }
    if (url.pathname === "/_/routes") {
      if (request.method !== "GET") return methodNotAllowed("GET");
      return await handleRoutes(env, ctx, url);
    }
    return json({ error: "not found" }, 404);
  } catch (err) {
    if (clientAborted(ctx)) {
      logLine("canceled", { rid: ctx.rid, method: request.method, path: url.pathname });
      return json({ error: "canceled" }, 499);
    }
    logLine("error", { rid: ctx.rid, method: request.method, path: url.pathname, err: errText(err) });
    return json({ error: "internal" }, 500);
  }
}

// Validate and canonicalize one key, then look it up. Shared by /lookup and
// the path aliases so a PURL means the same thing however it arrived.
async function lookupKey(env, ctx, origin, sha, purl) {
  let hex = null;
  if (sha) {
    hex = sha.trim().toLowerCase();
    if (!SHA_RE.test(hex)) return json({ error: "invalid sha256" }, 400);
  }
  // Anything non-empty goes upstream: scan decides what is a PURL.
  const canonical = purl ? normalizePurl(purl) : null;
  if (!hex && !canonical) return json({ error: "missing purl" }, 400);
  // Both are kept when both are given. They are not interchangeable — a digest
  // names exact bytes, a versioned PURL names whatever sample the corpus holds
  // for that release — so carrying both is what lets one answer when the other
  // cannot, and what lets a disagreement between them be noticed at all.
  return lookup(env, ctx, origin, { sha: hex, bytes: null, purl: canonical, analyze: false });
}

// `pkg:` is optional, as it is on scan's own routes, and the scheme and type
// are case-insensitive per the PURL spec. Everything after the type is left
// exactly as sent: npm grandfathered in mixed-case names, so folding the rest
// would merge packages that are genuinely distinct. Scan canonicalizes the
// remainder its own way; this only has to make the two spellings of one key
// agree on the cache entry.
function normalizePurl(raw) {
  const trimmed = String(raw || "").trim();
  if (!trimmed) return "";
  const body = trimmed.replace(/^pkg:/i, "");
  const slash = body.indexOf("/");
  // Nothing recognizable to canonicalize: pass it upstream unchanged rather
  // than rejecting it here. fletch's parser is the authority on what a PURL
  // is, and a second rule in this file would eventually disagree with it.
  if (slash <= 0 || slash === body.length - 1) return trimmed;
  return `pkg:${body.slice(0, slash).toLowerCase()}${body.slice(slash)}`;
}

// POST /analyze?sha256=…&purl=… with the artifact as the raw body.
//
// Both query parameters are optional when a body is present: the digest is
// derived from the bytes. Scan is the tier that requires one, and it gets the
// derived value, so a caller holding an artifact can simply send it. A caller
// that already knows the digest may still send it and have it checked.
// `purl` is a hint that lets scan graft registry provenance onto the report.
//
// The body is optional too. Without it the artifact is fetched from hopper
// instead — correct, but a round trip slower. Sending the bytes is the fast
// path, and the only path that works for something hopper has never seen.
// With no body, a key must be named: there is nothing to derive one from.
//
// The body is read in full before the lookup race starts. Keeping the digest
// in the query string would let the race begin while the upload streams — a
// cached 16MB artifact could answer before its bytes finished arriving — but
// nothing here does that today, and a caller need not hash anything to get an
// answer. Reviving that would mean racing on the claimed digest and landing
// the verification when the body completes.
async function handleAnalyze(request, env, ctx, url) {
  const claimed = (url.searchParams.get("sha256") || "").trim().toLowerCase();
  const purl = normalizePurl(url.searchParams.get("purl") || "");
  if (claimed && !SHA_RE.test(claimed)) return json({ error: "invalid sha256" }, 400);

  const ct = (request.headers.get("content-type") || "").toLowerCase();
  if (ct.includes("multipart/") || ct.includes("application/x-www-form-urlencoded")) {
    return json({ error: "unsupported media type" }, 415);
  }
  const maxBytes = maxBody(env);
  const cl = Number(request.headers.get("content-length"));
  if (Number.isFinite(cl) && cl > maxBytes) return json({ error: "too large" }, 413);

  const body = await request.arrayBuffer();
  if (body.byteLength > maxBytes) return json({ error: "too large" }, 413);
  const bytes = body.byteLength ? body : null;

  // The digest of an upload is derived here, never taken on trust. A verdict
  // filed under a key the caller chose rather than one the bytes produce would
  // poison beamline's cache, every scan worker's cache, and hopper at once, and
  // every later honest lookup for that sha would get the planted answer.
  // Deriving it also means a caller holding the artifact need not hash it
  // first; scan still requires a digest, and this is where that digest comes
  // from. A caller may send one anyway, and it is then a statement about what
  // it believes it uploaded: a mismatch means the body was truncated or
  // altered in flight, which is worth refusing rather than analyzing.
  let sha = claimed;
  if (bytes) {
    sha = await sha256Hex(bytes);
    if (claimed && claimed !== sha) {
      logLine("sha_mismatch", { rid: ctx.rid, sha: claimed, actual: sha, bytes: bytes.byteLength });
      return json({ error: "body does not match sha256" }, 400);
    }
  }
  // With no bytes there is nothing to derive a key from, so one must be named.
  // A sha is what you have once you hold the artifact; a PURL is what you have
  // before you do, and scan resolves it against the registry itself — which is
  // also where the provenance it grafts into the report comes from.
  if (!sha && !purl) return json({ error: "provide sha256 or purl" }, 400);

  return await lookup(env, ctx, url.origin, {
    sha: sha || null,
    bytes,
    purl: purl || null,
    filename: sha || "artifact",
    analyze: true,
  });
}

async function lookup(env, ctx, origin, input) {
  const t0 = Date.now();
  const cacheKey = input.sha
    ? new Request(`${origin}/lookup?sha256=${input.sha}`)
    : new Request(`${origin}/lookup?purl=${encodeURIComponent(input.purl)}`);
  // A read-only lookup and an analysis of the same key are different questions,
  // so they get different flights: an /analyze must never be handed the 404 that
  // an in-flight /lookup is about to produce.
  const flightKey = `${input.analyze ? "analyze" : "lookup"}:${input.sha ? `sha:${input.sha}` : `purl:${input.purl}`}`;
  const cache = await getCache(env);

  // A pinned request measures a specific worker, so it may not be served by
  // the cache or by someone else's in-flight work — either would return an
  // answer the pinned worker never produced, and time nothing. It still
  // populates both on the way out: the verdict is just as true for having been
  // measured.
  let work = ctx.pin ? null : inflight.get(flightKey);
  if (!work) {
    work = (async () => {
      const hit = ctx.pin ? null : await cache.match(cacheKey);
      // A cached verdict serves either question. A cached *miss* only answers
      // the read-only one — analysis is precisely what turns it into a hit.
      if (hit && !(input.analyze && hit.status !== 200)) {
        const res = new Response(hit.body, hit);
        res.headers.set("X-Beamline-Source", "cache");
        // The stored copy is deliberately `public` so Cloudflare will hold it
        // at all — that rewrite is between us and our own cache (see serveHit).
        // The client's copy must carry the scope a fresh answer would, or an
        // authenticated verdict goes out marked cacheable by every browser and
        // shared proxy on the way back. The stored max-age is kept: Cloudflare
        // sends an Age alongside it, which is what makes it mean anything.
        res.headers.set("cache-control", clientScope(env, hit.headers.get("cache-control")));
        // The stored copy names whoever produced it, possibly days ago. Left
        // in place it would be read as this request's routing decision, and
        // every cache hit would be attributed to that worker.
        res.headers.delete("X-Beamline-Worker");
        res.headers.delete("Server-Timing");
        logLine("lookup", { src: "cache", status: hit.status, ms: Date.now() - t0, ...idFields(ctx, input) });
        return res;
      }
      return runLookup(env, ctx, cache, cacheKey, input, t0);
    })();
    if (!ctx.pin) inflight.set(flightKey, work);
    // Runs to completion even if every waiter walks away, so the answer still
    // reaches the cache and hopper for whoever asks next.
    waitUntil(ctx, work.finally(() => { if (!ctx.pin) inflight.delete(flightKey); }));
  }

  // The API is synchronous: a caller waits for its answer. Workers put no
  // wall-clock limit on a request and waiting on a subrequest is not CPU time,
  // so holding costs nothing — while handing back an early 202 would cap the
  // remaining work at the 30s `waitUntil` budget and throw away anything
  // slower. `SCAN_TIMEOUT_MS` is the one budget that bounds a lookup.
  return (await work).clone();
}

// A timer the winner puts out. Without the cancel, every hedge and every hold
// would keep a timer — and its abort listeners — alive for the full duration
// after the race was already decided, one per in-flight request.
function deadline(ms, ctx, token) {
  const ctl = new AbortController();
  const fired = sleep(ms, { ...ctx, signal: mergeAbort(ctx.signal, ctl.signal) }).then(() => token);
  fired.catch(() => {});
  return { fired, cancel: () => ctl.abort() };
}

// Every cheap source is asked at once — hopper's index and every scan worker's
// — and the first non-miss wins, so a slow or dead backend costs nothing but
// its own silence. Analysis is the expensive arm and joins only when it has to:
// after HOPPER_HEDGE_MS, or the moment every cheap source has missed.
async function runLookup(env, ctx, cache, cacheKey, input, t0) {
  const hedgeMs = numEnv(env, "HOPPER_HEDGE_MS", HOPPER_HEDGE_MS);
  const lookupMs = numEnv(env, "HOPPER_LOOKUP_MS", HOPPER_LOOKUP_MS);
  const ids = idFields(ctx, input);

  const hopperCtl = new AbortController();
  const knownCtl = new AbortController();
  // Stamped where each arm settles, win or lose. `timed` puts them on the way
  // out — after serveHit, which clones for the cache first, so a stored verdict
  // never replays one request's timings as if they were the next one's.
  const timing = {};
  const at = () => Date.now() - t0;
  // Async because `settle` is: stamping a promise set the header on nothing and
  // turned every unavailable path into a 500.
  const timed = async (maybe) => {
    const res = await maybe;
    timing.total = at();
    const header = serverTiming(timing);
    if (header) res.headers.set("Server-Timing", header);
    return res;
  };
  // A pinned analysis skips the cheap sources entirely. The point of a pin is
  // to measure one worker on one artifact, and an answer from hopper's index
  // measures neither — it was returning a stored verdict and reporting
  // `source: hopper`, which made the pin useless for the job it exists for.
  // A pinned /lookup still races them: it is not allowed to analyze, so cheap
  // sources are the only thing it has.
  const forced = Boolean(ctx.pin) && input.analyze;
  const hopper = forced
    ? watch(Promise.resolve(null))
    : watch(hopperSample(env, ctx, input, lookupMs, hopperCtl.signal), () => {
        timing.hopper = at();
      });
  const known = forced
    ? watch(Promise.resolve({ verdict: null, bloom: "unknown" }))
    : watch(scanKnown(env, ctx, input, knownCtl.signal), () => {
        timing.index = at();
      });
  const hedge = deadline(hedgeMs, ctx, HEDGE);

  let scan = null;
  let scanCtl = null;
  let hedged = false;
  // The hedge fires once. Without this, a suppressed hedge leaves an
  // already-resolved promise in the wait set and the loop spins on it.
  let hedgeSpent = false;
  // /lookup reports what is already known and stops there; only /analyze may
  // spend a scan slot. Both race the same cheap sources first.
  const analyze = (why) => {
    if (scan || !input.analyze) return;
    hedge.cancel();
    hedged = why === "hedge";
    logLine(why === "hedge" ? "hedge" : "analyze", { ms: Date.now() - t0, why, hedge_ms: hedgeMs, ...ids });
    scanCtl = new AbortController();
    scan = watch(scanLookup(env, ctx, input, scanCtl), () => {
      timing.scan = at();
    });
  };
  // Drop whatever is still in the air, and say what was dropped. Nothing in
  // flight means nothing to report: an instant answer should not log an abort.
  const stop = (why) => {
    hedge.cancel();
    const dropped = [];
    if (!hopper.done) {
      hopperCtl.abort();
      dropped.push("hopper");
    }
    if (!known.done) {
      // Deliberately not aborted. It is a bloom lookup already in flight, and
      // letting it land is the only way to learn what the scan index would have
      // cost when hopper beat it — measured over 13 live lookups, hopper won
      // every one and the index arm's cost was therefore never once observed.
      // Logged out-of-band so it cannot delay the reply.
      waitUntil(
        ctx,
        known.settled.then(() => {
          logLine("lookup_arms", { winner: why, index_ms: timing.index, hopper_ms: timing.hopper, ...ids });
        }),
      );
    }
    if (scan && !scan.done) {
      scanCtl.abort();
      dropped.push("analysis");
    }
    if (dropped.length) {
      logLine("abort", { target: dropped.join(","), why, ms: Date.now() - t0, ...ids });
    }
  };

  for (;;) {
    // A stored verdict is an analysis of these exact bytes; hopper's row is the
    // same thing from the other index. Either outranks a filter's opinion.
    if (hopper.value?.status === 200) {
      stop("hopper_hit");
      return timed(replyHopper(env, ctx, cache, cacheKey, input, hopper.value, t0, hedged));
    }
    if (known.value?.verdict) {
      stop("index_hit");
      const res = verdictResponse(env, known.value.verdict, input, verdictAge(env));
      logLine("lookup", { src: "scan-cache", status: 200, ms: Date.now() - t0, ...ids });
      return timed(serveHit(ctx, cache, cacheKey, res));
    }
    // `skip` is the filter's word for known-good, served as a benign stub.
    if (known.value?.bloom === "skip") {
      stop("bloom_hit");
      const res = bloomStub(env, input.sha, input.purl);
      logLine("lookup", { src: "bloom", status: 200, ms: Date.now() - t0, ...ids });
      return timed(serveHit(ctx, cache, cacheKey, res));
    }
    if (scan?.value?.scanned?.env) {
      stop("scan_hit");
      const pack = scan.value;
      return timed(replyScan(env, ctx, cache, cacheKey, input, hopper.value, pack.bytes, pack.scanned, t0, hedged));
    }

    // Nothing cheap is left to wait on, so stop waiting out the hedge.
    if (hopper.done && known.done) analyze("cheap_sources_missed");

    // A bloom hit on the bad set carries no reason — it is a filter, so all it
    // can say is that this key is in the set. But it says something useful
    // about where the reason lives: a known-bad sample is by definition one the
    // corpus already holds, so hopper can almost certainly explain it, and
    // waiting beats spending a scan slot re-deriving what is already written
    // down. `conflicted` is the same bet — the filters disagree, and a stored
    // verdict settles it better than a fresh scan.
    //
    // Only the hedge is suppressed. If hopper genuinely misses, the branch
    // above still starts the analysis, so this delays that decision rather
    // than removing it.
    const indexSaysBad = known.value?.bloom === "known-bad" || known.value?.bloom === "conflicted";

    const waits = [];
    if (!hopper.done) waits.push(hopper.settled);
    if (!known.done) waits.push(known.settled);
    if (scan && !scan.done) waits.push(scan.settled);
    if (!scan && input.analyze && !hedgeSpent) waits.push(hedge.fired);
    if (!waits.length) break;
    if ((await Promise.race(waits)) === HEDGE) {
      hedgeSpent = true;
      if (!indexSaysBad) analyze("hedge");
    }
  }

  hedge.cancel();
  const failure = hopper.err || known.err || scan?.err;
  if (failure) throw failure;
  const pack = scan?.value;
  return timed(settle(env, ctx, cache, cacheKey, input, hopper.value, pack?.bytes, pack?.scanned, t0, hedged));
}

// A losing arm keeps running after the race is decided, so whatever it ends
// up doing lands here instead of escaping as an unhandled rejection.
function watch(p, onSettle) {
  const w = { done: false };
  const settle = () => {
    w.done = true;
    onSettle?.();
  };
  w.settled = p.then(
    (value) => {
      w.value = value;
      settle();
    },
    (err) => {
      w.err = err;
      settle();
    },
  );
  return w;
}

// Server-Timing for one lookup.
//
// The cheap sources are raced, so response latency is min(hopper, scan-index)
// and neither number is recoverable from it — a fast answer says only that
// *something* was fast. Recording each arm where it settles is the only way to
// see what hopper's index costs versus a scan worker's, which is what decides
// whether racing them is buying anything.
//
// Losing arms are aborted on a win, so a loser's figure is a lower bound: it
// says "still unanswered at N ms", not "took N ms".
function serverTiming(t) {
  const parts = [];
  if (t.hopper != null) parts.push(`hopper;dur=${t.hopper}`);
  if (t.index != null) parts.push(`scan_index;dur=${t.index}`);
  if (t.scan != null) parts.push(`scan_analyze;dur=${t.scan}`);
  if (t.total != null) parts.push(`total;dur=${t.total}`);
  return parts.join(", ");
}

async function scanLookup(env, ctx, input, scanCtl) {
  const scanCtx = { ...ctx, signal: mergeAbort(ctx.signal, scanCtl.signal) };
  const cancelled = { bytes: null, scanned: { cancelled: true } };
  const ids = idFields(ctx, input);
  try {
    // Analysis needs the artifact, and the only sources of it are the caller's
    // upload and a PURL scan can resolve for itself. A digest alone is a
    // lookup key, not an artifact: beamline used to answer one by pulling the
    // bytes out of hopper and pushing them to a worker, which moved the whole
    // artifact twice through this service, capped what could be analyzed at
    // MAX_BYTES, and put a database-backed read on the hot path — to reach
    // bytes the worker can fetch for itself, from a static path that needs no
    // query at all. Lookup by digest is unaffected; only analysis is refused.
    // Analysis needs the artifact, and the only sources of it are the caller's
    // upload and a PURL scan can resolve for itself. A digest alone is a lookup
    // key, not an artifact: answering one meant pulling the bytes out of hopper
    // and pushing them to a worker, moving the whole artifact twice through
    // this service, capping analysis at MAX_BYTES, and putting a
    // database-backed read on the hot path — to reach bytes a worker can fetch
    // for itself from a static path that needs no query at all. Lookup by
    // digest is unaffected; only analysis without bytes or a PURL is refused.
    const bytes = input.bytes || null;
    if (scanCtl.signal.aborted) return cancelled;
    if (bytes) {
      const name = input.filename || input.sha;
      const scanned = await retryScan(env, scanCtx, ids, () =>
        raceScan(
          env,
          scanCtx,
          ids,
          (base, armCtx) => scanBytes(env, armCtx, base, bytes, name),
          { bytes: bytes.byteLength },
        ),
      );
      return { bytes, scanned };
    }
    if (input.purl) {
      const scanned = await retryScan(env, scanCtx, ids, () =>
        raceScan(env, scanCtx, ids, (base, armCtx) => scanPurl(env, armCtx, base, input.purl), {
          purl: input.purl,
        }),
      );
      return { bytes: null, scanned };
    }
    return { bytes: null, scanned: null };
  } catch (err) {
    // Hopper winning the race aborts scan mid-flight; that is not an error.
    if (clientAborted(ctx) || !scanCtl.signal.aborted) throw err;
    return cancelled;
  }
}

function replyHopper(env, ctx, cache, cacheKey, input, hopper, t0, hedged) {
  const res = envelopeResponse(env, hopper.body, hopper.sha, "hopper", verdictAge(env), null, input.purl);
  logLine("lookup", {
    src: "hopper",
    status: 200,
    ms: Date.now() - t0,
    hedged,
    hopper_status: 200,
    ...idFields(ctx, input),
  });
  return serveHit(ctx, cache, cacheKey, res);
}

function replyScan(env, ctx, cache, cacheKey, input, hopper, bytes, scanned, t0, hedged) {
  const sha = input.sha || scanned.sha || shaFromEnvelope(scanned.env);
  const res = envelopeResponse(env, scanned.env, sha, "scan", verdictAge(env), scanned.totalMs, input.purl);
  // Who actually produced this. Without it a client can measure that beamline
  // was slow but not which worker made it so, and work distribution is only
  // visible by reading the logs of a process it does not run.
  if (scanned.worker) res.headers.set("X-Beamline-Worker", scanned.worker);
  logLine("lookup", {
    src: "scan",
    status: 200,
    ms: Date.now() - t0,
    hedged,
    worker: scanned.worker,
    scan_ms: scanned.ms,
    hopper_status: hopper?.status,
    ...idFields(ctx, input),
  });
  // Neither the verdict nor the bytes are ours to file. The scan worker that
  // produced the verdict renews it on hopper itself, and stores the artifact
  // ahead of it — with the registry record and fetch provenance that beamline
  // never sees. Beamline uploading too was duplicate work carrying strictly
  // less information, and it was the only reason this service needed write
  // access to the corpus at all.
  return serveHit(ctx, cache, cacheKey, res);
}

async function settle(env, ctx, cache, cacheKey, input, hopper, bytes, scanned, t0, hedged) {
  if (scanned?.env) return replyScan(env, ctx, cache, cacheKey, input, hopper, bytes, scanned, t0, hedged);

  const note = (src, status, more) =>
    logLine("lookup", {
      src,
      status,
      ms: Date.now() - t0,
      hedged,
      hopper_status: hopper?.status,
      ...more,
      ...idFields(ctx, input),
    });

  // Waiting on hopper's worker is still work being done on the caller's behalf,
  // so a read-only lookup does not do it: it reports what is known and stops.
  const queued = input.analyze ? await waitForQueued(env, ctx, hopper, input) : null;
  if (queued?.env) {
    note("hopper", 200, { queued: true });
    const res = envelopeResponse(env, queued.env, queued.sha, "hopper", verdictAge(env), null, input.purl);
    return serveHit(ctx, cache, cacheKey, res);
  }
  if (queued?.pending) {
    note("hopper", 202);
    return pending();
  }
  if (scanned?.rejected) {
    const res = scanClientResponse(scanned.status || 400, scanned);
    note("scan", res.status);
    return res;
  }
  if (!bytes && hopper == null) {
    note("hopper", 503, { err: "unavailable" });
    return json({ error: "unavailable" }, 503);
  }
  if (scanned?.unavailable) {
    const res =
      scanned.status === 504 || scanned.status === 429
        ? scanClientResponse(scanned.status, scanned)
        : json({ error: "unavailable" }, 503);
    note("scan", res.status);
    return res;
  }
  // A definite miss is an answer. Cache it briefly so a hot unknown sha does
  // not replay bloom, hopper, and scan on every request.
  note("hopper", 404);
  const miss = new Response(JSON.stringify({ error: "unknown sample" }), {
    status: 404,
    headers: { "content-type": "application/json", "cache-control": `${cacheScope(env)}, max-age=${MISS_MAX_AGE}` },
  });
  return serveHit(ctx, cache, cacheKey, miss);
}

// Scan down, or hopper already has the bytes: upload if needed, promote, wait.
// Wait for a verdict hopper is already working on.
//
// Only ever a read. Hopper answers 202 for an artifact it holds but has not
// analyzed, which is the one outcome worth waiting on rather than giving up on
// — somebody is producing the answer and it will appear at this same key. So
// beamline polls until it does.
//
// It waits rather than returning 202 straight away because this is a blocking
// API: a caller asked what a package is, and "ask again later" is a worse
// answer than a slower one. The 202 still exists as the timeout, for the case
// where the budget runs out first.
async function waitForQueued(env, ctx, hopper, input) {
  // Scan being unavailable is not a reason to wait: nothing is working on it.
  if (!isQueued(hopper?.status)) return null;
  const sha = hopper.sha || input.sha || "";
  if (!SHA_RE.test(sha)) return null;

  const budget = numEnv(env, "SCAN_TIMEOUT_MS", DEFAULT_SCAN_TIMEOUT_MS);
  const poll = numEnv(env, "HOPPER_POLL_MS", HOPPER_POLL_MS);
  const deadline = Date.now() + budget;
  for (let attempt = 0; Date.now() < deadline; attempt++) {
    // Jittered, so a burst of waiters on one sample does not poll in lockstep.
    const wait = Math.min(backoff(poll, attempt, POLL_MAX_MS), Math.max(0, deadline - Date.now()));
    if (wait <= 0) break;
    await sleep(wait, ctx);
    if (clientAborted(ctx)) return null;
    const row = await hopperSample(env, ctx, { sha, bytes: null, purl: null });
    if (row?.status === 200) return { env: row.body, sha: row.sha || sha };
    // The breaker opening means hopper stopped answering, not that the answer
    // is slow. Waiting out the budget against a dead dependency helps nobody.
    if (row == null && hopperBreaker.open()) return null;
  }
  return { pending: true };
}

// What scan already holds for this key, raced across every healthy worker: the
// stored verdict when one has it, and the bloom decision either way — a 404
// still carries the filter's opinion, which is what the separate bloom probe
// used to fetch. Never asks scan to analyze; this sits in front of hopper and
// has to stay cheap.
//
// Any definite answer ends the race: a stored verdict, or a filter decision
// that is not "unknown". Only a worker that has neither keeps us waiting —
// unlike the filters, which are published sets every worker loads identically,
// a verdict lives solely on the worker that ran the analysis, so one peer's
// "unknown sample" says nothing about what the others hold. Bounded by
// LOOKUP_TIMEOUT_MS either way.
async function scanKnown(env, ctx, input, cancelSignal) {
  const miss = { verdict: null, bloom: "unknown" };
  const workers = scanWorkers(env);
  if (!workers.length || cancelSignal?.aborted) return miss;
  const ids = idFields(ctx, input);
  // Both keys when we have both. scan checks each against its own filters and
  // merges the answers, so a release the digest missed still decides — one
  // request, not two, and the worker does the merging where the filters live.
  const keys = [];
  if (input.sha) keys.push(`sha256=${input.sha}`);
  if (input.purl) keys.push(`purl=${encodeURIComponent(input.purl)}`);
  const path = `/lookup?${keys.join("&")}`;
  const t0 = Date.now();
  const controls = workers.map(() => new AbortController());
  // Another source answered first: drop every arm still in the air.
  cancelSignal?.addEventListener("abort", () => controls.forEach((c) => c.abort()), { once: true });
  const arms = workers.map((base, i) => watch(lookupAsk(env, ctx, path, base, controls[i])));

  const drop = () => {
    for (const [i, arm] of arms.entries()) {
      if (!arm.done) controls[i].abort();
    }
  };

  for (;;) {
    // A verdict outranks a decision: it is an analysis of these exact bytes,
    // not a filter's opinion of the key.
    const hit = arms.find((arm) => arm.value?.verdict);
    if (hit) {
      drop();
      logLine("lookup_known", {
        src: "verdict",
        worker: hit.value.worker,
        ms: Date.now() - t0,
        raced: workers.length,
        ...ids,
      });
      return { verdict: hit.value.verdict, bloom: hit.value.bloom || "unknown" };
    }
    const decided = arms.find((arm) => arm.value?.bloom && arm.value.bloom !== "unknown");
    if (decided) {
      drop();
      logLine("lookup_known", {
        src: "bloom",
        decision: decided.value.bloom,
        worker: decided.value.worker,
        ms: Date.now() - t0,
        raced: workers.length,
        ...ids,
      });
      return { verdict: null, bloom: decided.value.bloom };
    }
    if (arms.every((arm) => arm.done)) break;
    await Promise.race(arms.filter((arm) => !arm.done).map((arm) => arm.settled));
  }

  if (clientAborted(ctx)) throw new DOMException("Aborted", "AbortError");
  const silent = arms.filter((arm) => !arm.value?.bloom).length;
  logLine("lookup_known", {
    src: "bloom",
    decision: "unknown",
    ms: Date.now() - t0,
    raced: workers.length,
    silent,
    ...ids,
  });
  return miss;
}

// One worker's answer. An empty `bloom` means it could not give one, so the
// race keeps waiting on whoever is left.
async function lookupAsk(env, ctx, path, base, control) {
  const worker = hostOf(base);
  const askCtx = { ...ctx, signal: mergeAbort(ctx.signal, control.signal) };
  try {
    const answer = await fetchTimeout(
      `${base}${path}`,
      { method: "GET", headers: scanHeaders(env, ctx) },
      LOOKUP_TIMEOUT_MS,
      askCtx,
      async (resp) => {
        // 200 is a stored verdict, 404 is "unknown sample" with the filter's
        // decision attached. Anything else is a worker that cannot answer.
        if (resp.status !== 200 && resp.status !== 404) {
          await drain(resp);
          return null;
        }
        const body = await resp.json().catch(() => null);
        if (!body || typeof body !== "object") return null;
        return {
          verdict: resp.status === 200 ? body : null,
          bloom: (typeof body.bloom === "string" && body.bloom) || "unknown",
        };
      },
    );
    return answer ? { worker, ...answer } : { worker, verdict: null, bloom: "" };
  } catch (err) {
    // `ctx`, not `askCtx`: a loser we dropped ourselves is not a client abort.
    if (clientAborted(ctx)) throw err;
    // Dropped because another source answered first. Not a failure, and not
    // worth a line — `abort` already records why the race ended.
    if (control.signal.aborted) return { worker, verdict: null, bloom: "" };
    logLine("lookup_failed", { rid: ctx.rid, worker, err: errText(err) });
    return { worker, verdict: null, bloom: "" };
  }
}

// Ask hopper about this key, and — when the caller gave us both — about the
// other one if the first cannot answer.
//
// Sequential, not raced. The digest is exact: when it hits, the PURL query
// would only confirm what we already know, so the common path costs exactly one
// request and nothing is added to hopper's load. The second query is a genuine
// second chance: the corpus can know release 1.0 without having seen the bytes
// the caller is holding.
//
// The digest stays the identity throughout. A PURL answer describing different
// bytes is not this artifact's verdict and is refused rather than served — and
// that disagreement is worth a log line of its own, because a version whose
// digest has changed under it is exactly the shape of a re-publish.
async function hopperSample(env, ctx, input, timeoutMs, cancelSignal) {
  const first = await hopperSampleKey(env, ctx, input, timeoutMs, cancelSignal, input.sha ? "sha" : "purl");
  if (!input.sha || !input.purl) return first;
  if (first?.status === 200 || first == null) return first;

  const second = await hopperSampleKey(env, ctx, input, timeoutMs, cancelSignal, "purl");
  if (second?.status !== 200) return first ?? second;
  if (second.sha && second.sha !== input.sha) {
    logLine("purl_digest_mismatch", {
      purl: input.purl,
      asked: input.sha,
      found: second.sha,
      rid: ctx?.rid,
    });
    return first;
  }
  return second;
}

async function hopperSampleKey(env, ctx, input, timeoutMs, cancelSignal, key) {
  const base = trimSlash(env.HOPPER_URL);
  if (!base || hopperBreaker.open()) return null;
  const url =
    key === "sha"
      ? `${base}/api/sample/${input.sha}`
      : `${base}/api/sample?purl=${encodeURIComponent(input.purl)}`;
  const ms = timeoutMs == null ? HOPPER_RPC_MS : timeoutMs;
  const fetchCtx = cancelSignal ? { ...ctx, signal: mergeAbort(ctx && ctx.signal, cancelSignal) } : ctx;
  try {
    // The envelope is read here so it stays inside the request timeout, and
    // null — anything but a usable 200, 404, or queued — trips the breaker.
    const got = await fetchTimeout(url, { method: "GET", headers: hopperHeaders(env, ctx) }, ms, fetchCtx, async (resp) => {
      const hex = String(resp.headers.get("x-sha256") || "").trim().toLowerCase();
      const sha = (SHA_RE.test(hex) && hex) || input.sha;
      if (resp.status === 200) {
        const body = await resp.json().catch(() => null);
        return body && { status: 200, sha, body };
      }
      await drain(resp);
      if (resp.status === 404 || isQueued(resp.status)) return { status: resp.status, sha };
      return null;
    });
    if (!got) {
      hopperBreaker.fail();
      return null;
    }
    hopperBreaker.ok();
    return got;
  } catch (err) {
    if (clientAborted(ctx)) throw err;
    if (cancelSignal && cancelSignal.aborted) return null;
    hopperBreaker.fail();
    return null;
  }
}



// A scan that never reached a verdict is worth asking again: a 5xx, a 429 at
// capacity, an edge timeout at 120s, a dropped connection — none of those are
// answers, and a moment later they may not hold. A rejection is an answer
// (bad bytes, unsupported type), so repeating it would only burn a slot.
//
// Only one of these loops runs per sample. `lookup` collapses concurrent
// identical requests into a single flight before this is ever reached, and
// scan de-duplicates by sha and purl across isolates, so a retry joins the
// analysis already running rather than starting a second one — which is what
// makes retrying an edge timeout worth doing at all.
// Every healthy worker gets the same sample and the first real verdict wins.
// The losers are aborted the moment it lands. That abort reliably stops an arm
// that has not dispatched yet; it does NOT reliably stop one already running,
// because the signal has to cross a Worker abort, the Cloudflare edge, and a
// tunnel before scan sees a disconnect, and measurement says it does not arrive
// — a dropped loser was observed analysing for a further 77s and returning 200.
//
// So the saving comes from the stagger, not the abort: an arm still waiting out
// its delay is aborted before it ever asks, and costs its worker nothing. The
// delay is set per request from the favourite's own predicted latency (see
// rankWorkers), and SCAN_RACE_DELAY_MS overrides it — 0 restores the old flat
// race, which costs one analysis slot per worker per sample.
// ---------------------------------------------------------------- routing ---
//
// Which scan worker should go first?
//
// The old answer was "all of them, at once": SCAN_RACE_DELAY_MS defaulted to 0,
// so every arm dispatched immediately and every worker analysed every sample.
// Measured on one request, galadriel answered pkg:pypi/idna@2.5 in 12.5s while
// interserver kept working on it for another 77s — a full duplicate analysis
// per extra worker, on a fleet whose scarce resource is analysis slots.
//
// The fix is not to cancel the losers. Cancellation has to cross a Worker
// abort, the Cloudflare edge, and a tunnel before scan sees a disconnect, and
// the evidence is that it does not arrive. What works regardless of transport
// is to not start the work: `scanArm` aborts during its stagger and reports
// `never_started`, which costs a worker nothing at all.
//
// So the job here is to put the *most likely to finish first* worker in the
// zero-delay slot, and hold the rest behind a delay long enough that they only
// fire when the favourite is genuinely slow. That is a hedged request, and the
// arm machinery already implements it.

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
// scan rejects rather than queues, so a busy worker's real cost is not a longer
// wait — it is the chance of a 429 and a hop to somebody else. At 1.0 a fully
// occupied worker is scored as though the work took twice as long, which is
// roughly what a rejection plus a failover costs now that a refusal promotes
// the next arm immediately.
//
// Ranking on latency alone had a specific failure: the fleet's *smallest*
// worker was also its fastest, so it won every first-arm dispatch, filled its
// six slots in milliseconds and refused the rest — while a 64-slot worker sat
// with 44 free. Speed and capacity are different questions and the router was
// only asking one.
const CAPACITY_WEIGHT = 1.0;

// occupancy is the fraction of a worker's slots in use, clamped to [0,1].
// Unknown slots mean an unknown answer, and 0 keeps such a worker ranked on
// latency alone rather than inventing a penalty for it.
function occupancy(stats) {
  const slots = Number(stats?.slots);
  if (!Number.isFinite(slots) || slots <= 0) return 0;
  const busy = Number(stats.in_flight ?? slots - (stats.slots_free ?? slots));
  if (!Number.isFinite(busy) || busy <= 0) return 0;
  return Math.min(1, busy / slots);
}
// The hedge is a stall detector, not a latency optimizer.
//
// It used to be the latter, and the distinction is the whole design. Racing
// every worker at once wasted a full analysis per request; hedging below the
// expected time fired on roughly half of them, because the estimate is a
// central tendency and half of all jobs exceed it. Neither is what a second
// arm is for now: routing picks the favourite on measured p80, and a refusal
// promotes the next worker immediately, so the only failure a hedge still
// covers is a worker that *accepted* the work and then went quiet.
//
// So it fires late and rarely. A worker past this multiple of its own p80 is
// not slow, it is stuck — and the alternative is waiting out SCAN_TIMEOUT_MS,
// which is thirty minutes.
const HEDGE_FRACTION = 3;
// Ceiling on the hedge delay, as a fraction of the scan timeout rather than a
// bare number. The previous fixed 20s was set when a job took ~5s; once fresh
// analyses reached 100-380s it clamped every hedge to 20s and turned the whole
// mechanism back into the flat race it replaced. Tying it to the timeout keeps
// it in scale with whatever the work actually costs.
const HEDGE_TIMEOUT_SHARE = 0.5;

// Race outcomes per worker, for /_/routes.
//
// Per-isolate and therefore partial: Workers recycles isolates freely, so these
// count one isolate's view since `raceSince`, not the fleet's since boot. That
// is honest for a stress run — which lands on few isolates and reads them right
// after — and useless as a long-run metric. The durable version of these
// numbers is the scan_arm/scan_race log stream.
const raceTally = new Map();
// Stamped on first use, not at module scope: Workers runs global initialization
// with the clock pinned before any I/O, so Date.now() there is not a wall time
// and the window came out as the entire Unix epoch.
let raceSince = null;

function tally(base) {
  raceSince ??= Date.now();
  let t = raceTally.get(base);
  if (!t) {
    t = { started: 0, won: 0, never_started: 0, dropped: 0, failed: 0, timed: 0, ms_total: 0 };
    raceTally.set(base, t);
  }
  return t;
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
  const base = classed ?? (hint == null ? mixedMs(stats, mix) : null) ?? blendedMs(stats) ?? UNKNOWN_JOB_MS;
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
  if (stats.lookup_samples != null && stats.lookup_samples < MIN_CLASS_SAMPLES) return null;
  if (stats.avg_lookup_us != null) return stats.avg_lookup_us / 1000;
  return stats.avg_lookup_ms ?? null;
}

function classMs(stats, hint) {
  if (hint == null) return null;
  // The cheap-source race asks the index, not the analyzer. Predicting it from
  // an analysis average would be wrong by a factor of a thousand.
  if (hint.lookup) return lookupMsOf(stats);
  const bucket =
    hint.bytes != null
      ? stats.avg_job_ms_by_size?.[sizeBucket(hint.bytes)]
      : stats.avg_job_ms_by_type?.[purlType(hint.purl)];
  if (!bucket) return null;
  return recentMs(bucket.recent) ?? meanMs(bucket);
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
  if (hint?.lookup) return lookupMsOf(stats) != null;
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
    if (Math.abs(a.est - b.est) >= 250) return a.est - b.est;
    if (a.known && b.known) return a.r - b.r;
    return a.i - b.i;
  });
  // Holding an arm back is a bet that the favourite is genuinely the fastest.
  // With no stats to bet on, the ranking is arbitrary and the bet is a coin
  // toss with a long delay attached — strictly worse than asking everyone. So
  // evidence buys the hedge: no evidence, flat race, as before.
  // No exploration here on purpose. A previous revision promoted a random
  // non-favourite on 10% of requests, to stop a worker being trapped by a
  // reputation its own starved sample set could never repair. The measurement
  // that motivated it did not survive scrutiny — the worker in question was
  // winning half the fleet's work at the time — so the cost (a tenth of all
  // dispatches sent somewhere the evidence says is slower) bought a fix for a
  // problem never shown to exist. If per-worker averages do turn out to be
  // biased by the routing itself, the honest repair is to make the samples
  // comparable, not to dilute the ranking that reads them.
  const informed = pool[0].known;
  const ceiling = Math.round(numEnv(env, "SCAN_TIMEOUT_MS", DEFAULT_SCAN_TIMEOUT_MS) * HEDGE_TIMEOUT_SHARE);
  const hedge = informed ? Math.min(ceiling, Math.round(pool[0].est * HEDGE_FRACTION)) : 0;
  return { pool, excluded: usable.length ? scored.filter((w) => w.why != null) : [], hedge, informed };
}

async function rankWorkers(env, ctx, workers, ids, hint) {
  const ranked = await rankPool(env, ctx, workers, hint);
  logLine("scan_route", {
    order: ranked.pool.map((w) => hostOf(w.base)).join(","),
    est_ms: ranked.pool.map((w) => Math.round(w.est)).join(","),
    excluded: ranked.excluded.length || undefined,
    hedge_ms: ranked.hedge,
    informed: ranked.informed || undefined,
    size: hint?.bytes ?? undefined,
    type: hint?.purl ? purlType(hint.purl) : undefined,
    ...ids,
  });
  return {
    workers: ranked.pool.map((w) => w.base),
    hedge: ranked.hedge,
    est: new Map(ranked.pool.map((w) => [w.base, Math.round(w.est)])),
  };
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
    return json({ error: "invalid size" }, 400);
  }

  const all = urlList(env.SCAN_URL);
  if (!all.length) return json({ error: "no SCAN_URL configured" }, 503);
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
    const stagger = numEnv(env, "SCAN_RACE_DELAY_MS", ranked.hedge);
    routes.push({
      class: c.name,
      kind: c.kind,
      size_bytes: c.bytes,
      informed: ranked.informed,
      hedge_ms: ranked.hedge,
      // The delay each arm would actually wait. Arm i waits i*stagger, so a
      // third worker is held twice as long as the second — the number an
      // operator wants is this one, not the hedge it was derived from.
      dispatch: ranked.pool.map((w, i) => ({
        worker: hostOf(w.base),
        est_ms: Math.round(w.est),
        delay_ms: i * stagger,
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
      // A stagger that is not the hedge means SCAN_RACE_DELAY_MS is pinning it,
      // which is otherwise invisible and explains a plan that looks wrong.
      scan_race_delay_ms: numEnv(env, "SCAN_RACE_DELAY_MS", null) ?? undefined,
      // Window these cover. Short relative to the run means the isolate was
      // recycled mid-flight and the tallies below undercount.
      race_window_ms: raceSince == null ? undefined : now - raceSince,
      workers: all.map((base) => {
        const hit = statsCache.get(base);
        const t = raceTally.get(base);
        return {
          worker: hostOf(base),
          breaker: breakerFor(base).open() ? "open" : "closed",
          // What this worker was actually asked to do, and how that ended.
          // `never_started` is work the hedge saved; `dropped` is work already
          // running that a faster worker made redundant — the number that says
          // whether racing is costing real capacity.
          race: t
            ? { ...t, avg_ms: t.timed ? Math.round(t.ms_total / t.timed) : undefined, ms_total: undefined, timed: undefined }
            : undefined,
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

async function raceScan(env, ctx, ids, run, hint = null) {
  let available = scanWorkers(env);
  // An experiment pins the route so predicted and actual can be compared for a
  // worker the router would not have chosen — the counterfactual a passive log
  // cannot supply. Deliberately applied after the breaker filter: pinning is
  // for measuring a healthy worker, not for reviving a tripped one.
  if (ctx.pin) {
    available = available.filter((base) => hostOf(base) === ctx.pin);
    if (!available.length) return { unavailable: true, pinned: ctx.pin };
  }
  if (!available.length) return { unavailable: true };
  // Best-first, with a hedge delay derived from the favourite's own estimate.
  // SCAN_RACE_DELAY_MS still wins when set, so an operator can pin the old flat
  // race (0) or a fixed stagger without touching code.
  const ranked = await rankWorkers(env, ctx, available, ids, hint);
  const workers = ranked.workers;
  const estOf = ranked.est;
  const stagger = numEnv(env, "SCAN_RACE_DELAY_MS", ranked.hedge);
  const t0 = Date.now();
  const controls = workers.map(() => new AbortController());
  // One gate per arm, opened when the arm ahead of it gives up. Arm 0 has no
  // delay to shorten, so its gate is never used.
  const gates = workers.map(() => {
    let open = () => {};
    const waited = new Promise((resolve) => {
      open = resolve;
    });
    return { waited, open };
  });
  // Arms start in index order, so releasing "the next one" is releasing the
  // next gate. Starts at 1 because arm 0 is already running.
  let released = 1;
  const promote = () => {
    if (released < gates.length) gates[released++].open();
  };
  const arms = workers.map((base, i) =>
    watch(scanArm(env, ctx, ids, run, base, i * stagger, controls[i], gates[i].waited)),
  );
  // Arms already accounted for, so one settling does not promote twice.
  const counted = new Set();

  const dropLosers = () => {
    const dropped = [];
    for (const [i, arm] of arms.entries()) {
      if (arm.done || controls[i].signal.aborted) continue;
      controls[i].abort();
      dropped.push(hostOf(workers[i]));
    }
    return dropped;
  };

  for (;;) {
    // Any arm that has finished without a verdict releases the next one from
    // its remaining delay.
    for (const [i, arm] of arms.entries()) {
      if (!arm.done || counted.has(i)) continue;
      counted.add(i);
      if (!arm.value?.scanned?.env) promote();
    }
    const won = arms.find((arm) => arm.value?.scanned?.env);
    if (won) {
      const dropped = dropLosers();
      logLine("scan_race", {
        winner: hostOf(won.value.base),
        ms: Date.now() - t0,
        // Prediction beside outcome on one line. Routing that is never scored
        // against reality is a guess wearing arithmetic, and joining two log
        // lines by rid to find out is a thing nobody does twice.
        est_ms: estOf.get(won.value.base),
        pinned: ctx.pin || undefined,
        scan_ms: won.value.scanned.ms,
        raced: workers.length,
        dropped: dropped.length ? dropped.join(",") : undefined,
        ...ids,
      });
      return won.value.scanned;
    }
    if (arms.every((arm) => arm.done)) {
      if (clientAborted(ctx)) throw new DOMException("Aborted", "AbortError");
      const settled = arms.map((arm) => arm.value?.scanned).filter(Boolean);
      // A rejection is a verdict about the sample; prefer it over "nobody could
      // answer", which only says something about the workers.
      const answer =
        settled.find((s) => s.rejected) || settled.find((s) => s.unavailable) || settled[0] || { unavailable: true };
      logLine("scan_race", {
        winner: "",
        ms: Date.now() - t0,
        raced: workers.length,
        outcome: answer.rejected ? "rejected" : "unavailable",
        status: answer.status,
        ...ids,
      });
      return answer;
    }
    await Promise.race(arms.filter((arm) => !arm.done).map((arm) => arm.settled));
  }
}

// One worker's run at the sample, held back by `waitMs` so a staggered race
// need not start everything at once.
async function scanArm(env, ctx, ids, run, base, waitMs, control, release) {
  const armCtx = { ...ctx, signal: mergeAbort(ctx.signal, control.signal) };
  const worker = hostOf(base);
  if (waitMs > 0) {
    try {
      // The stagger is a bet that the worker ahead will answer. The moment it
      // answers "no" that bet is settled, and waiting out the rest of the delay
      // is dead time — which is how a fleet with 44 free slots served 503s
      // while beamline sat out a 20-second hedge behind an instant 429.
      await Promise.race(release ? [sleep(waitMs, armCtx), release] : [sleep(waitMs, armCtx)]);
    } catch {
      tally(base).never_started += 1;
      logLine("scan_arm", { worker, outcome: "never_started", ...ids });
      return { base, scanned: { cancelled: true, worker } };
    }
  }
  if (control.signal.aborted) {
    tally(base).never_started += 1;
    logLine("scan_arm", { worker, outcome: "never_started", ...ids });
    return { base, scanned: { cancelled: true, worker } };
  }
  const t0 = Date.now();
  tally(base).started += 1;
  logLine("scan_arm_start", { worker, held_ms: waitMs || undefined, ...ids });
  let scanned;
  try {
    scanned = await run(base, armCtx);
  } catch (err) {
    // Dropped mid-request because another worker answered first. Report how
    // far behind it was: that margin is the whole picture of which worker is
    // slow, and it is invisible if a loser just disappears.
    if (!control.signal.aborted) throw err;
    tally(base).dropped += 1;
    logLine("scan_arm", { worker, ms: Date.now() - t0, outcome: "dropped", ...ids });
    return { base, scanned: { cancelled: true, worker } };
  }
  const armMs = Date.now() - t0;
  const t = tally(base);
  t.ms_total += armMs;
  t.timed += 1;
  if (scanned?.env) t.won += 1;
  else t.failed += 1;
  logLine("scan_arm", {
    worker,
    ms: armMs,
    scan_ms: scanned?.totalMs,
    status: scanned?.status,
    outcome: scanned?.env ? "answered" : scanned?.rejected ? "rejected" : "unavailable",
    ...ids,
  });
  return { base, scanned };
}

async function retryScan(env, ctx, ids, run) {
  const tries = numEnv(env, "SCAN_RETRIES", SCAN_RETRIES);
  const base = numEnv(env, "SCAN_RETRY_BASE_MS", SCAN_RETRY_BASE_MS);
  for (let attempt = 0; ; attempt++) {
    const scanned = await run();
    if (!scanned?.unavailable || attempt >= tries) return scanned;
    // Two of these are verdicts about the sample rather than accidents, and
    // asking again only spends the budget twice:
    //   - scan's own 504, meaning it gave up on this sample as too slow;
    //   - a 524, meaning the edge stopped waiting. Cloudflare tears the origin
    //     connection down at that point, which scan reads as a client hangup
    //     and cancels on, so a retry restarts the whole analysis on every
    //     worker and walks into the same ceiling. Measured against two live
    //     workers: 125s, 524, retry, 125s, 524.
    if (scanned.body?.timeout_secs != null || scanned.status === EDGE_TIMEOUT) return scanned;
    // Every worker tripped: more attempts would just burn the budget.
    if (!scanWorkers(env).length) return scanned;
    const wait = backoff(base, attempt, SCAN_RETRY_MAX_MS);
    logLine("scan_retry", { attempt: attempt + 1, of: tries, status: scanned.status, wait_ms: Math.round(wait), ...ids });
    await sleep(wait, ctx);
  }
}

async function scanPurl(env, ctx, base, purl) {
  const breaker = breakerFor(base);
  if (breaker.open()) return { unavailable: true, worker: hostOf(base) };
  const timeout = numEnv(env, "SCAN_TIMEOUT_MS", DEFAULT_SCAN_TIMEOUT_MS);
  const start = Date.now();
  try {
    return await fetchTimeout(
      `${base}/analyze-purl`,
      {
        method: "POST",
        headers: { ...scanHeaders(env, ctx), "content-type": "application/json" },
        body: JSON.stringify({ purl }),
      },
      timeout,
      ctx,
      (resp) => readScan(resp, start, breaker, hostOf(base)),
    );
  } catch (err) {
    if (clientAborted(ctx)) throw err;
    breaker.fail();
    return { unavailable: true, worker: hostOf(base) };
  }
}

async function scanBytes(env, ctx, base, bytes, filename) {
  const breaker = breakerFor(base);
  if (breaker.open()) return { unavailable: true, worker: hostOf(base) };
  const timeout = numEnv(env, "SCAN_TIMEOUT_MS", DEFAULT_SCAN_TIMEOUT_MS);
  const start = Date.now();
  try {
    const body = multipart([{ name: "file", filename: filename || "upload.bin", body: new Uint8Array(bytes) }]);
    return await fetchTimeout(
      `${base}/analyze`,
      { method: "POST", headers: { ...scanHeaders(env, ctx), "content-type": body.contentType }, body: body.body },
      timeout,
      ctx,
      (resp) => readScan(resp, start, breaker, hostOf(base)),
    );
  } catch (err) {
    if (clientAborted(ctx)) throw err;
    breaker.fail();
    return { unavailable: true, worker: hostOf(base) };
  }
}

async function readScan(resp, start, breaker, worker) {
  const totalMs = resp.headers.get("x-total-ms");
  let body = null;
  try {
    body = await resp.json();
  } catch {
    body = null;
  }
  const ms = Date.now() - start;
  // Busy, not broken. Unavailable for this arm — so the race moves on and
  // retryScan tries again — but the breaker is left alone in both directions:
  // a 429 is neither a failure to count against this worker nor evidence it is
  // healthy. The next stats poll excludes it by slots_free anyway.
  if (resp.status === 429) {
    return { unavailable: true, busy: true, status: resp.status, body, ms, totalMs, worker };
  }
  if (unreachableStatus(resp.status)) {
    breaker.fail();
    return { unavailable: true, status: resp.status, body, ms, totalMs, worker };
  }
  if (!resp.ok) return { rejected: true, status: resp.status, body, ms, totalMs, worker };
  breaker.ok();
  return { env: body, sha: shaFromEnvelope(body), ms, totalMs, worker };
}

// Exponential with full jitter, capped: a burst of waiters on the same sample
// spreads out instead of polling hopper in lockstep.
function backoff(base, attempt, cap) {
  const ceiling = Math.min(base * 2 ** Math.min(attempt, 10), cap);
  return ceiling <= base ? base : base + Math.random() * (ceiling - base);
}

// Hopper and scan are separate services with separate credentials, so beamline
// holds one token for each. The caller's own token is never forwarded: it
// authenticates them to us and nothing further, so a beamline client cannot
// turn its credential into direct access to a scanner.
function hopperHeaders(env, ctx) {
  return backendHeaders(env.HOPPER_TOKEN, ctx);
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
    "x-beamline-source": "scan-cache",
  };
  if (view.sha) headers["x-sha256"] = view.sha;
  return new Response(JSON.stringify(view), { status: 200, headers });
}

function bloomStub(env, sha, purl) {
  return envelopeResponse(env, { ml: { lvl: -1, eng: "beamline" } }, sha, "bloom", 3600, null, purl);
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
// Our own cache is a different matter — see serveHit.
// The scope a client's copy carries, restoring what serveHit dropped for the
// benefit of our own cache.
function clientScope(env, stored) {
  const age = /max-age=(\d+)/.exec(stored || "");
  return age ? `${cacheScope(env)}, max-age=${age[1]}` : cacheScope(env);
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

function scanClientResponse(status, scanned) {
  const src = scanned.body && typeof scanned.body === "object" ? scanned.body : {};
  const body = {
    error: typeof src.error === "string" ? src.error : status === 504 ? "analysis timeout" : "rejected",
  };
  if (typeof src.detail === "string") body.detail = src.detail;
  if (src.timeout_secs != null) body.timeout_secs = src.timeout_secs;
  const headers = { "content-type": "application/json" };
  if (scanned.totalMs != null && scanned.totalMs !== "") headers["x-total-ms"] = String(scanned.totalMs);
  return new Response(JSON.stringify(body), { status, headers });
}

function shaFromEnvelope(body) {
  const sha = body?.raw?.files?.[0]?.sha;
  return typeof sha === "string" ? sha.toLowerCase() : "";
}

function multipart(fields) {
  // Random enough that no artifact can contain its own boundary by accident.
  const boundary = `----beamline-${crypto.randomUUID()}`;
  const enc = new TextEncoder();
  const chunks = [];
  let len = 0;
  const add = (u8) => {
    chunks.push(u8);
    len += u8.length;
  };
  for (const f of fields) {
    let head = `--${boundary}\r\nContent-Disposition: form-data; name="${f.name}"`;
    if (f.filename) head += `; filename="${safeName(f.filename)}"`;
    head += `\r\nContent-Type: ${f.type || "application/octet-stream"}\r\n\r\n`;
    add(enc.encode(head));
    add(typeof f.body === "string" ? enc.encode(f.body) : f.body);
    add(enc.encode("\r\n"));
  }
  add(enc.encode(`--${boundary}--\r\n`));
  const body = new Uint8Array(len);
  let off = 0;
  for (const c of chunks) {
    body.set(c, off);
    off += c.length;
  }
  return { contentType: `multipart/form-data; boundary=${boundary}`, body };
}

// The filename is how the digest reaches scan, so the bound must not clip one:
// a sha256 is exactly 64 hex characters, and anything shorter here silently
// hands over a truncated key that scan then names its own temp file after.
function safeName(name) {
  return String(name || "upload.bin").replace(/[^A-Za-z0-9_.-]/g, "_").slice(-64) || "upload.bin";
}

async function sha256Hex(buf) {
  const hash = await crypto.subtle.digest("SHA-256", buf instanceof ArrayBuffer ? buf : new Uint8Array(buf));
  return [...new Uint8Array(hash)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

// Hopper and scan are reached over ordinary fetch: each sits behind a
// Cloudflare Tunnel with a public hostname, so the edge does the routing.
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

function serveHit(ctx, cache, cacheKey, res) {
  const copy = res.clone();
  // Cloudflare will not store a `private` response, which would silently leave
  // every token-protected deployment with no cache at all. Our cache sits
  // behind the 401 and every valid token gets the same answer, so the stored
  // copy drops the directive that the client's copy keeps.
  const cc = copy.headers.get("cache-control") || "";
  if (cc.startsWith("private")) copy.headers.set("cache-control", cc.replace("private", "public"));
  // A cache that throws, synchronously or not, must not fail the lookup.
  waitUntil(ctx, Promise.resolve().then(() => cache.put(cacheKey, copy)));
  return res;
}

function waitUntil(ctx, p) {
  const q = Promise.resolve(p).catch((err) => {
    logLine("wait_error", { err: errText(err) });
  });
  if (ctx && typeof ctx.waitUntil === "function") ctx.waitUntil(q);
}

function mergeAbort(a, b) {
  if (!a) return b;
  if (!b) return a;
  const ac = new AbortController();
  if (a.aborted || b.aborted) {
    ac.abort();
    return ac.signal;
  }
  const fwd = () => {
    a.removeEventListener("abort", fwd);
    b.removeEventListener("abort", fwd);
    ac.abort();
  };
  a.addEventListener("abort", fwd, { once: true });
  b.addEventListener("abort", fwd, { once: true });
  return ac.signal;
}

// One place decides how long a verdict lives, so the four paths that can
// produce one cannot drift apart.
function verdictAge(env) {
  return numEnv(env, "VERDICT_MAX_AGE", VERDICT_MAX_AGE);
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

function maxBody(env) {
  return Number(env.MAX_BYTES) || DEFAULT_MAX_BYTES;
}

function idFields(ctx, input) {
  const out = { rid: ctx.rid };
  if (input && input.sha) out.sha = input.sha;
  if (input && input.purl) out.purl = input.purl;
  return out;
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
function scanWorkers(env) {
  return urlList(env.SCAN_URL).filter((base) => !breakerFor(base).open());
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
    open() {
      return Date.now() < openUntil;
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
  return new Response(JSON.stringify({ error: "method not allowed", detail: `use ${allow}` }), {
    status: 405,
    headers: { "content-type": "application/json", allow },
  });
}

// Jittered: a flat Retry-After brings every client parked during an incident
// back in the same second, forever.
function pending() {
  const secs = RETRY_AFTER_MIN_S + Math.floor(Math.random() * (RETRY_AFTER_MAX_S - RETRY_AFTER_MIN_S + 1));
  return new Response(JSON.stringify({ state: "pending" }), {
    status: 202,
    headers: { "content-type": "application/json", "retry-after": String(secs) },
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

// A status that means the backend could not be reached or is broken — the kind
// worth opening a circuit breaker over.
//
// 429 is deliberately NOT here. "At capacity" is a healthy backend applying
// backpressure, and counting it as a failure inverted the intended behaviour:
// five 429s opened a worker's breaker, a saturated fleet tripped all of them at
// once, scanWorkers() went empty, and retryScan gave up — turning "come back in
// a moment" into a hard 503 after the full retry ladder. Measured on the live
// fleet, that path was every one of poppy's analysis failures and ~85-96% of
// the time it spent analyzing.
function unreachableStatus(status) {
  return status >= 500;
}

export const _test = {
  bloomStub,
  verdictResponse,
  normalizePurl,
  hitLocation,
  shaFromEnvelope,
  customerView,
  topHits,
  SHA_RE,
  DEFAULT_SCAN_TIMEOUT_MS,
  HOPPER_HEDGE_MS,
  HOPPER_LOOKUP_MS,
  HOPPER_RPC_MS,
  LOOKUP_TIMEOUT_MS,
  MEMORY_CACHE_MAX,
  BREAKER_FAILS,
  makeBreaker,
  memoryCache,
  tokenEq,
  tokenList,
  numEnv,
  reset() {
    hopperBreaker.reset();
    scanBreakers.clear();
    inflight.clear();
    getCache.memory = null;
    logLine.mute = false;
  },
  muteLogs(on) {
    logLine.mute = !!on;
  },
};
