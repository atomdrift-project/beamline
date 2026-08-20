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
const HOPPER_HEDGE_MS = 1_000;
const HOPPER_LOOKUP_MS = 15_000;
const HOPPER_RPC_MS = 2_000;
const FILE_TIMEOUT_MS = 30_000;
const HEDGE = Symbol("hedge");
const HELD = Symbol("held");
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
const SCAN_RACE_DELAY_MS = 0;
const HOLD_MS = 10_000;
const MISS_MAX_AGE = 60;
const RETRY_AFTER_MIN_S = 3;
const RETRY_AFTER_MAX_S = 8;
const SUBMIT_TRIES = 4;
const SUBMIT_BASE_MS = 500;

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
  ctx = { ...ctx, rid };
  if (request.signal && !ctx.signal) ctx.signal = request.signal;

  const url = new URL(request.url);
  // /_/health is the name every service in this stack answers to; /healthz
  // stays because the Makefile and the stress harness probe it.
  if ((url.pathname === "/healthz" || url.pathname === "/_/health") && request.method === "GET") {
    return json({ status: "ok" }, 200);
  }

  const allowed = tokenList(env.BEAMLINE_TOKEN);
  if (allowed.length) {
    const bearer = /^Bearer\s+(\S+)/i.exec((request.headers.get("authorization") || "").trim());
    const got = bearer ? bearer[1] : "";
    if (!allowed.some((t) => tokenEq(got, t))) {
      return json({ error: "unauthorized" }, 401);
    }
    env = { ...env, BEAMLINE_TOKEN: got };
  }

  try {
    if (request.method === "POST" && url.pathname === "/") {
      return await handlePost(request, env, ctx, url);
    }
    if (request.method === "GET" && url.pathname === "/lookup") {
      const sha = (url.searchParams.get("sha256") || "").trim();
      const purl = (url.searchParams.get("purl") || "").trim();
      if (!!sha === !!purl) {
        return json({ error: "provide exactly one of sha256 or purl" }, 400);
      }
      return await lookupKey(env, ctx, url.origin, sha, purl);
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
  if (sha) {
    const hex = sha.trim().toLowerCase();
    if (!SHA_RE.test(hex)) return json({ error: "invalid sha256" }, 400);
    return lookup(env, ctx, origin, { sha: hex, bytes: null, purl: null });
  }
  // Anything non-empty goes upstream: scan decides what is a PURL.
  const canonical = normalizePurl(purl);
  if (!canonical) return json({ error: "missing purl" }, 400);
  return lookup(env, ctx, origin, { sha: null, bytes: null, purl: canonical });
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

async function handlePost(request, env, ctx, url) {
  const ct = (request.headers.get("content-type") || "").toLowerCase();
  if (ct.includes("multipart/") || ct.includes("application/x-www-form-urlencoded")) {
    return json({ error: "unsupported media type" }, 415);
  }
  const maxBytes = maxBody(env);
  const cl = Number(request.headers.get("content-length"));
  if (Number.isFinite(cl) && cl > maxBytes) return json({ error: "too large" }, 413);
  const bytes = await request.arrayBuffer();
  if (!bytes.byteLength) return json({ error: "empty body" }, 400);
  if (bytes.byteLength > maxBytes) return json({ error: "too large" }, 413);
  const sha = await sha256Hex(bytes);
  return await lookup(env, ctx, url.origin, { sha, bytes, purl: null, filename: "upload.bin" });
}

async function lookup(env, ctx, origin, input) {
  const t0 = Date.now();
  const cacheKey = input.sha
    ? new Request(`${origin}/lookup?sha256=${input.sha}`)
    : new Request(`${origin}/lookup?purl=${encodeURIComponent(input.purl)}`);
  const flightKey = input.sha ? `sha:${input.sha}` : `purl:${input.purl}`;
  const cache = await getCache(env);

  let work = inflight.get(flightKey);
  if (!work) {
    work = (async () => {
      const hit = await cache.match(cacheKey);
      if (hit) {
        const res = new Response(hit.body, hit);
        res.headers.set("X-Beamline-Source", "cache");
        logLine("lookup", { src: "cache", status: hit.status, ms: Date.now() - t0, ...idFields(ctx, input) });
        return res;
      }
      return runLookup(env, ctx, cache, cacheKey, input, t0);
    })();
    inflight.set(flightKey, work);
    // Runs to completion even if every waiter walks away, so the answer still
    // reaches the cache and hopper for whoever asks next.
    waitUntil(ctx, work.finally(() => inflight.delete(flightKey)));
  }

  // A scan may legitimately run for half an hour. A client may not be made to
  // wait for it: past HOLD_MS we hand back 202 and let the work finish.
  const hold = deadline(numEnv(env, "HOLD_MS", HOLD_MS), ctx, HELD);
  let res;
  try {
    res = await Promise.race([work, hold.fired]);
  } finally {
    hold.cancel();
  }
  if (res !== HELD) return res.clone();
  logLine("lookup", { src: "hold", status: 202, ms: Date.now() - t0, ...idFields(ctx, input) });
  return pending();
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

async function runLookup(env, ctx, cache, cacheKey, input, t0) {
  const hedgeMs = numEnv(env, "HOPPER_HEDGE_MS", HOPPER_HEDGE_MS);
  const lookupMs = numEnv(env, "HOPPER_LOOKUP_MS", HOPPER_LOOKUP_MS);
  const ids = idFields(ctx, input);

  // Scan answers "have you already analyzed this" and "does a filter vouch for
  // it" in one round trip. A stored verdict is a real answer with findings, so
  // it beats the hopper hedge outright; a bare `skip` is the filter's word for
  // known-good, which we serve as a benign stub the way we always have.
  const known = await scanKnown(env, ctx, input);
  if (known.verdict) {
    const res = verdictResponse(env, known.verdict, input, 86400);
    logLine("lookup", { src: "scan-cache", status: 200, ms: Date.now() - t0, ...ids });
    return serveHit(ctx, cache, cacheKey, res);
  }
  if (known.bloom === "skip") {
    const res = bloomStub(env, input.sha, input.purl);
    logLine("lookup", { src: "bloom", status: 200, ms: Date.now() - t0, ...ids });
    return serveHit(ctx, cache, cacheKey, res);
  }

  const hopperCtl = new AbortController();
  const hopperP = hopperSample(env, ctx, input, lookupMs, hopperCtl.signal);
  const hedge = deadline(hedgeMs, ctx, HEDGE);
  let hopper;
  try {
    hopper = await Promise.race([hopperP, hedge.fired]);
  } finally {
    hedge.cancel();
  }
  const hedged = hopper === HEDGE;
  if (hedged) {
    hopper = undefined;
    logLine("hedge", { ms: Date.now() - t0, hedge_ms: hedgeMs, ...ids });
  }

  if (hopper?.status === 200) {
    return replyHopper(env, ctx, cache, cacheKey, input, hopper, t0, false);
  }

  const scanCtl = new AbortController();
  const scanP = scanLookup(env, ctx, input, scanCtl);

  if (!hedged) {
    const pack = await scanP;
    return settle(env, ctx, cache, cacheKey, input, hopper, pack.bytes, pack.scanned, t0, false);
  }

  const won = await raceUseful(hopperP, scanP);
  if (won.winner === "hopper") {
    scanCtl.abort();
    waitUntil(ctx, scanP.catch(() => {}));
    logLine("abort", { target: "scan", why: "hopper_hit", ms: Date.now() - t0, ...ids });
    return replyHopper(env, ctx, cache, cacheKey, input, won.hopper, t0, true);
  }
  if (won.winner === "scan") {
    hopperCtl.abort();
    waitUntil(ctx, hopperP.catch(() => {}));
    logLine("abort", { target: "hopper", why: "scan_hit", ms: Date.now() - t0, ...ids });
    return replyScan(env, ctx, cache, cacheKey, input, won.hopper, won.bytes, won.scanned, t0, true);
  }
  return settle(env, ctx, cache, cacheKey, input, won.hopper, won.bytes, won.scanned, t0, true);
}

// Hopper 200 and a scan envelope are the only results the client can use
// immediately. 404/204/errors are not a win; the other arm keeps running.
async function raceUseful(hopperP, scanP) {
  const hopper = watch(hopperP);
  const scan = watch(scanP);
  for (;;) {
    const pack = scan.value;
    const both = { hopper: hopper.value, bytes: pack?.bytes, scanned: pack?.scanned };
    if (hopper.value?.status === 200) return { winner: "hopper", ...both };
    if (pack?.scanned?.env) return { winner: "scan", ...both };
    if (hopper.done && scan.done) {
      if (hopper.err || scan.err) throw hopper.err || scan.err;
      return { winner: "", ...both };
    }
    const wait = [];
    if (!hopper.done) wait.push(hopper.settled);
    if (!scan.done) wait.push(scan.settled);
    await Promise.race(wait);
  }
}

// The losing arm keeps running after raceUseful returns, so whatever it ends
// up doing lands here instead of escaping as an unhandled rejection.
function watch(p) {
  const w = { done: false };
  w.settled = p.then(
    (value) => {
      w.value = value;
      w.done = true;
    },
    (err) => {
      w.err = err;
      w.done = true;
    },
  );
  return w;
}

async function scanLookup(env, ctx, input, scanCtl) {
  const scanCtx = { ...ctx, signal: mergeAbort(ctx.signal, scanCtl.signal) };
  const cancelled = { bytes: null, scanned: { cancelled: true } };
  const ids = idFields(ctx, input);
  try {
    let bytes = input.bytes || null;
    if (!bytes && input.sha) bytes = await hopperFile(env, scanCtx, input.sha);
    if (scanCtl.signal.aborted) return cancelled;
    if (bytes) {
      const name = input.filename || input.sha;
      const scanned = await retryScan(env, scanCtx, ids, () =>
        raceScan(env, scanCtx, ids, (base, armCtx) => scanBytes(env, armCtx, base, bytes, name)),
      );
      return { bytes, scanned };
    }
    if (input.purl) {
      const scanned = await retryScan(env, scanCtx, ids, () =>
        raceScan(env, scanCtx, ids, (base, armCtx) => scanPurl(env, armCtx, base, input.purl)),
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
  const res = envelopeResponse(env, hopper.body, hopper.sha, "hopper", 86400, null, input.purl);
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
  const res = envelopeResponse(env, scanned.env, sha, "scan", 86400, scanned.totalMs, input.purl);
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
  // Background work outlives the reply, so a client hanging up must not cancel
  // it; the write is still bounded by its own timeout and retry count.
  const bg = { ...ctx, signal: undefined };
  waitUntil(ctx, submitHopper(env, bg, sha, bytes, scanned.env, scanned.ms, hopper?.status !== 204));
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

  const queued = await queueAndWait(env, ctx, hopper, input, bytes, scanned);
  if (queued?.env) {
    note("hopper", 200, { queued: true });
    const res = envelopeResponse(env, queued.env, queued.sha, "hopper", 86400, null, input.purl);
    return serveHit(ctx, cache, cacheKey, res);
  }
  if (queued?.failed) {
    note("hopper", 503, { err: "upload" });
    return json({ error: "unavailable" }, 503);
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
async function queueAndWait(env, ctx, hopper, input, bytes, scanned) {
  const shouldWait = scanned?.unavailable || hopper?.status === 204;
  if (!shouldWait) return null;

  let sha = hopper?.sha || input.sha || "";
  if (bytes && hopper?.status !== 204) {
    sha = sha || (await sha256Hex(bytes));
    if (!(await hopperUpload(env, ctx, sha, bytes, input.filename || sha))) {
      return { failed: true };
    }
  }
  if (!sha || !SHA_RE.test(sha)) return null;

  const waited = await waitForHopper(env, ctx, sha);
  if (waited) return waited;
  if (hopper?.status === 204 || bytes) return { pending: true };
  return null;
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
async function scanKnown(env, ctx, input) {
  const miss = { verdict: null, bloom: "unknown" };
  const workers = scanWorkers(env);
  if (!workers.length) return miss;
  const ids = idFields(ctx, input);
  const path = input.sha
    ? `/lookup?sha256=${input.sha}`
    : `/lookup?purl=${encodeURIComponent(input.purl)}`;
  const t0 = Date.now();
  const controls = workers.map(() => new AbortController());
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
      { method: "GET", headers: backendHeaders(env, ctx) },
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
    logLine("lookup_failed", { worker, err: errText(err) });
    return { worker, verdict: null, bloom: "" };
  }
}

async function hopperSample(env, ctx, input, timeoutMs, cancelSignal) {
  const base = trimSlash(env.HOPPER_URL);
  if (!base || hopperBreaker.open()) return null;
  const url = input.sha
    ? `${base}/api/sample/${input.sha}`
    : `${base}/api/sample?purl=${encodeURIComponent(input.purl)}`;
  const ms = timeoutMs == null ? HOPPER_RPC_MS : timeoutMs;
  const fetchCtx = cancelSignal ? { ...ctx, signal: mergeAbort(ctx && ctx.signal, cancelSignal) } : ctx;
  try {
    // The envelope is read here so it stays inside the request timeout, and
    // null — anything but a usable 200, 404, or 204 — trips the breaker.
    const got = await fetchTimeout(url, { method: "GET", headers: backendHeaders(env, ctx) }, ms, fetchCtx, async (resp) => {
      const hex = String(resp.headers.get("x-sha256") || "").trim().toLowerCase();
      const sha = (SHA_RE.test(hex) && hex) || input.sha;
      if (resp.status === 200) {
        const body = await resp.json().catch(() => null);
        return body && { status: 200, sha, body };
      }
      await drain(resp);
      if (resp.status === 404 || resp.status === 204) return { status: resp.status, sha };
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

async function hopperFile(env, ctx, sha) {
  const base = trimSlash(env.HOPPER_URL);
  if (!base || hopperBreaker.open() || !SHA_RE.test(sha)) return null;
  const max = maxBody(env);
  try {
    const buf = await fetchTimeout(
            `${base}/api/file/${sha}`,
      { method: "GET", headers: backendHeaders(env, ctx) },
      FILE_TIMEOUT_MS,
      ctx,
      async (resp) => {
        const len = Number(resp.headers.get("content-length"));
        if (!resp.ok || (Number.isFinite(len) && len > max)) {
          if (unreachableStatus(resp.status)) hopperBreaker.fail();
          await drain(resp);
          return null;
        }
        const bytes = await resp.arrayBuffer();
        return bytes.byteLength > max ? null : bytes;
      },
    );
    if (!buf) return null;
    hopperBreaker.ok();
    // Hopper is a cache, not an authority: only bytes that hash to the key we
    // asked for are worth scanning.
    return (await sha256Hex(buf)) === sha ? buf : null;
  } catch (err) {
    if (clientAborted(ctx)) throw err;
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
// The losers are aborted the moment it lands, which drops their connection; on
// the scan side that releases their attachment, cancels the analysis, and frees
// the slot, so a loser never finishes and never posts a result of its own to
// hopper. Exactly one envelope leaves here, and it is the winner's.
//
// Workers start SCAN_RACE_DELAY_MS apart. At 0, the default, it is a flat race
// and costs one analysis slot per worker per sample; raise it to give a fast
// worker the chance to answer before the next one is ever asked.
async function raceScan(env, ctx, ids, run) {
  const workers = scanWorkers(env);
  if (!workers.length) return { unavailable: true };
  const stagger = numEnv(env, "SCAN_RACE_DELAY_MS", SCAN_RACE_DELAY_MS);
  const t0 = Date.now();
  const controls = workers.map(() => new AbortController());
  const arms = workers.map((base, i) => watch(scanArm(env, ctx, ids, run, base, i * stagger, controls[i])));

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
    const won = arms.find((arm) => arm.value?.scanned?.env);
    if (won) {
      const dropped = dropLosers();
      logLine("scan_race", {
        winner: hostOf(won.value.base),
        ms: Date.now() - t0,
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
async function scanArm(env, ctx, ids, run, base, waitMs, control) {
  const armCtx = { ...ctx, signal: mergeAbort(ctx.signal, control.signal) };
  const worker = hostOf(base);
  if (waitMs > 0) {
    try {
      await sleep(waitMs, armCtx);
    } catch {
      logLine("scan_arm", { worker, outcome: "never_started", ...ids });
      return { base, scanned: { cancelled: true, worker } };
    }
  }
  if (control.signal.aborted) {
    logLine("scan_arm", { worker, outcome: "never_started", ...ids });
    return { base, scanned: { cancelled: true, worker } };
  }
  const t0 = Date.now();
  logLine("scan_arm_start", { worker, held_ms: waitMs || undefined, ...ids });
  const scanned = await run(base, armCtx);
  logLine("scan_arm", {
    worker,
    ms: Date.now() - t0,
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
    // Scan reporting its own analysis timeout is a verdict about the sample:
    // it is too slow. Running it again just spends the budget twice.
    if (scanned.body?.timeout_secs != null) return scanned;
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
        headers: { ...backendHeaders(env, ctx), "content-type": "application/json" },
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
      { method: "POST", headers: { ...backendHeaders(env, ctx), "content-type": body.contentType }, body: body.body },
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
  if (unreachableStatus(resp.status)) {
    breaker.fail();
    return { unavailable: true, status: resp.status, body, ms, totalMs, worker };
  }
  if (!resp.ok) return { rejected: true, status: resp.status, body, ms, totalMs, worker };
  breaker.ok();
  return { env: body, sha: shaFromEnvelope(body), ms, totalMs, worker };
}

async function hopperUpload(env, ctx, sha, bytes, filename) {
  const base = trimSlash(env.HOPPER_URL);
  if (!base || hopperBreaker.open() || !bytes || !SHA_RE.test(sha)) return false;
  const name = safeName(filename || sha);
  const prov = JSON.stringify({
    schema_version: "1.0",
    artifact: { filename: name, sha256: sha, size_bytes: bytes.byteLength },
    fetch: { collector: "beamline", category: "submitted", at: new Date().toISOString() },
  });
  const body = multipart([
    { name: "provenance", type: "application/json", body: prov },
    { name: "file", filename: name, body: new Uint8Array(bytes) },
  ]);
  try {
    const status = await fetchTimeout(
            `${base}/api/upload`,
      { method: "POST", headers: { ...backendHeaders(env, ctx), "content-type": body.contentType }, body: body.body },
      FILE_TIMEOUT_MS,
      ctx,
      readStatus,
    );
    if (unreachableStatus(status)) {
      hopperBreaker.fail();
      return false;
    }
    const ok = status >= 200 && status < 300;
    if (ok) hopperBreaker.ok();
    return ok;
  } catch (err) {
    if (clientAborted(ctx)) throw err;
    hopperBreaker.fail();
    return false;
  }
}

async function hopperRescan(env, ctx, sha) {
  const base = trimSlash(env.HOPPER_URL);
  if (!base || hopperBreaker.open() || !SHA_RE.test(sha)) return;
  try {
    await fetchTimeout(`${base}/api/rescan/${sha}`, { method: "POST", headers: backendHeaders(env, ctx) }, HOPPER_RPC_MS, ctx, readStatus);
  } catch (err) {
    if (clientAborted(ctx)) throw err;
  }
}

async function waitForHopper(env, ctx, sha) {
  if (!sha || !SHA_RE.test(sha)) return null;
  const budget = numEnv(env, "SCAN_TIMEOUT_MS", DEFAULT_SCAN_TIMEOUT_MS);
  const poll = numEnv(env, "HOPPER_POLL_MS", HOPPER_POLL_MS);
  const deadline = Date.now() + budget;
  await hopperRescan(env, ctx, sha);
  for (let attempt = 0; Date.now() < deadline; attempt++) {
    if (clientAborted(ctx)) return null;
    const row = await hopperSample(env, ctx, { sha, bytes: null, purl: null });
    if (row?.status === 200) return { env: row.body, sha: row.sha || sha };
    if (row == null && hopperBreaker.open()) return null;
    const wait = Math.min(backoff(poll, attempt, POLL_MAX_MS), Math.max(0, deadline - Date.now()));
    if (wait <= 0) break;
    await sleep(wait, ctx);
  }
  return null;
}

// Exponential with full jitter, capped: a burst of waiters on the same sample
// spreads out instead of polling hopper in lockstep.
function backoff(base, attempt, cap) {
  const ceiling = Math.min(base * 2 ** Math.min(attempt, 10), cap);
  return ceiling <= base ? base : base + Math.random() * (ceiling - base);
}

async function submitHopper(env, ctx, sha, bytes, envelope, durationMs, needUpload) {
  const base = trimSlash(env.HOPPER_URL);
  if (!base || !sha || !SHA_RE.test(sha)) return;
  try {
    if (needUpload && bytes && !(await hopperUpload(env, ctx, sha, bytes, sha))) return;
    const payload = {
      sha256: sha,
      worker: "beamline",
      duration_ms: durationMs || 0,
      ml: envelope.ml,
      raw: envelope.raw,
    };
    if (envelope.llm) payload.llm = envelope.llm;
    const opts = {
      method: "POST",
      headers: { ...backendHeaders(env, ctx), "content-type": "application/json" },
      body: JSON.stringify(payload),
    };
    // The client already has its answer, but dropping this write costs the
    // next caller a full re-scan, so a busy hopper is worth waiting out.
    for (let attempt = 0; attempt < SUBMIT_TRIES; attempt++) {
      const status = await fetchTimeout(`${base}/api/result`, opts, FILE_TIMEOUT_MS, ctx, readStatus);
      if (!unreachableStatus(status)) return;
      if (attempt + 1 < SUBMIT_TRIES) await sleep(backoff(SUBMIT_BASE_MS, attempt, POLL_MAX_MS), ctx);
    }
    logLine("submit_failed", { rid: ctx.rid, sha });
  } catch {
    // Client already has the answer.
  }
}

function backendHeaders(env, ctx) {
  const tok = (env.BEAMLINE_TOKEN || "").trim();
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

function safeName(name) {
  return String(name || "upload.bin").replace(/[^A-Za-z0-9_.-]/g, "_").slice(-63) || "upload.bin";
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
async function readStatus(resp) {
  await drain(resp);
  return resp.status;
}

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

function logLine(event, fields) {
  if (logLine.mute) return;
  try {
    const row = { event };
    for (const k of Object.keys(fields || {})) {
      if (fields[k] !== undefined) row[k] = fields[k];
    }
    console.log(JSON.stringify(row));
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

function unreachableStatus(status) {
  return status >= 500 || status === 429;
}

export const _test = {
  bloomStub,
  verdictResponse,
  normalizePurl,
  hitLocation,
  normalizePurl,
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
