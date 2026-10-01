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
// Mid-stream refusals a request may take before it is given up on. A refusal
// is a worker with every big-analysis slot busy; the fleet has four workers,
// and each is asked again only once every other one has refused.
const MAX_STREAM_REFUSALS = 8;
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

// ------------------------------------------------------------------ shapes ---
//
// The object bags that travel between the functions below, named once. `stats`
// alone appears in a dozen signatures, and a shape described twice is a shape
// that eventually disagrees with itself.

/**
 * A customer, as the dash namespace records them.
 * @typedef {object} Org
 * @property {string} oid
 * @property {string} tier
 */

/**
 * A bearer token resolved to whoever holds it. `known` decides admission;
 * `org` decides attribution, and the two are deliberately separable.
 * @typedef {object} Caller
 * @property {string} token
 * @property {boolean} known - one of ours, or a live customer token
 * @property {Org|null} org - null for anonymous callers and for our own tokens
 */

/**
 * Beamline's own request context, built by dispatch() over the runtime's.
 * @typedef {object} Ctx
 * @property {string} rid
 * @property {Org|null} org
 * @property {string|null} pin - X-Beamline-Pin: force one worker
 * @property {string|null} filename
 * @property {boolean} refresh
 * @property {(promise: Promise<unknown>) => void} [waitUntil]
 * @property {AbortSignal} [signal]
 */

/**
 * How the caller named the artifact.
 * @typedef {object} Locator
 * @property {"purl"|"url"|"sha256"} type
 * @property {string} value
 */

/**
 * What every log line and outbound request carries, so one request can be
 * followed across both services.
 * @typedef {object} Ids
 * @property {string} rid
 * @property {string} [sha256]
 * @property {string} [purl]
 * @property {string} [url]
 * @property {number} [bytes]
 * @property {string} [follow]
 * @property {boolean} [full]
 */

/**
 * What the router is being asked to find a worker for. An absent field is
 * absent evidence rather than a zero: no `bytes` means the size is unknown,
 * and a null Hint means the request named no cost class at all.
 * @typedef {object} Hint
 * @property {string} [purl]
 * @property {number} [bytes]
 * @property {boolean} [upload] - the caller sent the artifact in the body
 * @property {boolean} [lookup] - an index probe, not an analysis
 */

/**
 * One cost class's timings, as scan publishes them.
 * @typedef {object} Bucket
 * @property {number} [avg_ms] - lifetime mean
 * @property {number} [jobs] - completions behind that mean
 * @property {{p80_ms?: number, samples?: number}} [recent] - the hour window
 */

/**
 * One worker's /_/stats. Every field is optional: an older worker publishes
 * fewer of them, and a missing field means no evidence rather than a zero.
 * @typedef {object} ScanStats
 * @property {boolean} [ready]
 * @property {boolean} [overloaded]
 * @property {number} [slots]
 * @property {number} [slots_free]
 * @property {number} [in_flight]
 * @property {number} [background_in_flight] - cores the pull worker holds
 * @property {number} [physical_cpus]
 * @property {number} [load1]
 * @property {number} [cpu_busy_cores] - preferred over load1; see machineBusy
 * @property {number} [max_upload_mb]
 * @property {{max?: number, in_use?: number}} [whale_slots]
 * @property {number} [avg_job_ms]
 * @property {number} [avg_job_samples]
 * @property {Bucket} [recent]
 * @property {Object<string, Bucket>} [avg_job_ms_by_type]
 * @property {Object<string, Bucket>} [avg_job_ms_by_size]
 * @property {Object<string, Bucket>} [avg_job_ms_by_size_idle] - uncontended
 * @property {number} [avg_lookup_us]
 * @property {number} [avg_lookup_ms]
 * @property {number} [lookup_samples]
 * @property {Bucket} [recent_lookup]
 */

/**
 * A worker scored for one request. Mutable by design: rankPool caps `est` for
 * a starved worker and records that it did so.
 * @typedef {object} RankedWorker
 * @property {string} base - the worker's URL
 * @property {ScanStats|null} stats - null means polled and unanswered
 * @property {number} i - the operator's configured order, the last tiebreak
 * @property {number} est - predicted milliseconds
 * @property {boolean} known - whether `est` rests on anything measured
 * @property {string|null} [why] - why it is unroutable, or null if it is not
 * @property {number} r - jitter, to damp herding between equals
 * @property {boolean} [starved]
 */

/**
 * Everything one analyze pass needs, settled once per request. Only the tally
 * changes between passes, and that travels beside this rather than in it.
 * @typedef {object} Job
 * @property {URL} url
 * @property {Locator|null} locator
 * @property {string} path - the path asked of a worker
 * @property {number} budget - false_positive_budget
 * @property {string|null} busy - host already analyzing this artifact
 * @property {Ids} ids
 * @property {number} t0 - when the request arrived
 * @property {ArrayBuffer|null} bytes - an uploaded artifact
 * @property {boolean} full
 * @property {number|null} sizeHint
 * @property {string|null} cacheFollow - the policy an answer may be filed
 *   under, and null where nothing may be
 */

/**
 * Why the workers declined this pass, read to decide whether another is worth
 * making. Filled in by v1Dispatch as it walks the fleet.
 * @typedef {object} Pass
 * @property {number} busy - refused with capacity in use
 * @property {number} broken - unreachable, or answering with a fault
 */

/**
 * What the annotating stream needs in order to label frames it did not write.
 * @typedef {object} StreamMeta
 * @property {string} requestId
 * @property {Locator|null} locator
 * @property {number} startedAt
 * @property {Ids} ids
 * @property {(outcome: {finisher: string|null, orphaned: boolean}) => void} [settled]
 * @property {boolean} full
 */

/**
 * The phase clock, carried across a handover and mutated in place as frames
 * arrive. `floor` is what keeps elapsed times monotonic when a replacement
 * worker starts counting from its own zero.
 * @typedef {object} Phase
 * @property {string|null} name
 * @property {number} startedElapsed
 * @property {number} lastElapsed
 * @property {number} floor
 * @property {number} changedAt
 */

// The Cloudflare module-worker contract: the runtime imports this module's
// default export and calls `.fetch` on it. It is the one default export in the
// tree, and it is not ours to rename — `handle` beside it is the named entry
// point everything else in this repo imports.
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
/**
 * The one entry point. Both `node local.js` and the Worker call this.
 * @param {Request} request
 * @param {Record<string, unknown>} env - Worker bindings and tunables
 * @param {{waitUntil?: (p: Promise<unknown>) => void, signal?: AbortSignal}} ctx
 * @returns {Promise<Response>}
 */
export async function handle(request, env, ctx) {
  const started = Date.now();
  // Who is calling, resolved once. Two things need it and they must not be
  // able to disagree: dispatch decides what this caller may read, and
  // recordRequest files the datapoint under the org that read it.
  const caller = await identify(request, env);
  const response = await dispatch(request, env, ctx, caller);
  recordRequest(env, request, response, Date.now() - started, caller);
  return response;
}

// A bearer token, resolved to whoever it belongs to.
//
// Three outcomes. A token in BEAMLINE_TOKEN is ours — the stress harness, the
// precache pass, an operator — and is deliberately anonymous: it is not a
// customer, and filing its traffic under an org would put our own load in
// someone's usage graph. A token in the dash namespace is a customer, and
// carries the org and the tier it was minted with. Anything else is neither,
// and whether that is allowed through is the gate's business, not ours.
//
// The namespace is written only by dash and read only here. The cache TTL is
// therefore the revocation latency: a token deleted in the dashboard keeps
// working in whichever colos already hold it, for up to this long.
const TOKEN_CACHE_TTL_S = 60;

/**
 * @param {Request} request
 * @param {Record<string, unknown>} env
 * @returns {Promise<Caller>} never rejects; an unreadable namespace is anonymous
 */
async function identify(request, env) {
  const bearer = /^Bearer\s+(\S+)/i.exec((request.headers.get("authorization") || "").trim());
  const token = bearer ? bearer[1] : "";
  const ours = tokenList(env?.BEAMLINE_TOKEN);
  if (token && ours.some((candidate) => tokenEq(token, candidate))) return { token, known: true, org: null };

  // Shape-checked before it is spent as a key. A token that cannot be one of
  // ours is a scan for an open API, and every one of those would otherwise be
  // a KV read we pay for.
  const kv = env?.DASH_KV;
  if (token && kv && CUSTOMER_TOKEN_RE.test(token)) {
    const raw = await dashRow(kv, token);
    const row = parseJson(raw);
    if (row?.oid) return { token, known: true, org: { oid: String(row.oid), tier: String(row.tier || "free") } };
    // Dash wrote something it should not have. Not retried — it will read the
    // same way next time — and not logged with the token, which is a secret.
    if (raw) logLine("token_row_invalid", { bytes: raw.length });
  }
  return { token, known: false, org: null };
}

// How many times a failed read of the dash namespace is retried, and the
// backoff between. Short: every request from that customer is waiting on it.
const TOKEN_LOOKUP_RETRIES = 2;
const TOKEN_LOOKUP_RETRY_BASE_MS = 50;
const TOKEN_LOOKUP_RETRY_MAX_MS = 500;

// One customer's row from the dash namespace, or null.
//
// A read that fails is retried briefly, because the alternative is a 401 to a
// paying customer for an outage that is ours and probably already over. Once
// the retries are spent, a namespace that cannot be read must still not take
// the API down with it: the caller falls through to the static gate, which on a
// deployment that has one means a 401 and on an open one means service as
// usual.
/**
 * @param {{get: (key: string, opts: object) => Promise<string|null>}} kv
 * @param {string} token
 * @returns {Promise<string|null>} never rejects
 */
async function dashRow(kv, token) {
  for (let attempt = 0; ; attempt++) {
    try {
      return await kv.get(`tok:${token}`, { cacheTtl: TOKEN_CACHE_TTL_S });
    } catch (err) {
      logLine("token_lookup_failed", { attempt, err: errText(err) });
      if (attempt >= TOKEN_LOOKUP_RETRIES) return null;
      await sleep(backoff(TOKEN_LOOKUP_RETRY_BASE_MS, attempt, TOKEN_LOOKUP_RETRY_MAX_MS), null);
    }
  }
}

// What dash mints: `i13_<nuclide>_<26 base32>`. Matched loosely enough to
// survive dash adding a nuclide and tightly enough that an arbitrary header
// never becomes a KV key.
const CUSTOMER_TOKEN_RE = /^i13_[a-z]+[0-9]*_[0-9a-z]{26}$/;

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
/**
 * @param {Record<string, unknown>} env
 * @param {Request} request
 * @param {Response|null} response - what the caller actually got
 * @param {number} ms
 * @param {Caller} [caller]
 * @returns {void}
 */
function recordRequest(env, request, response, ms, caller) {
  if (!response) return;
  const url = new URL(request.url);
  // Named, not derived from the path: a 404 on /v1/anything would otherwise
  // become a label of its own, and a metric dimension the caller chooses is
  // unbounded by definition.
  const route =
    url.pathname === "/v1/lookup" || url.pathname === "/v1/analyze" ? url.pathname.slice("/v1/".length) : "other";
  // `ms` here is time to the response, not to the verdict. On a streamed
  // analysis the headers go out first and the assessment arrives later, so this
  // measures what the caller waited before hearing anything — the number that
  // decides whether a proxy in the middle cuts the connection. What the run
  // cost is ROUTE_VERDICT, written when the assessment goes out.
  writePoint(env, route, response.headers, ecosystemOf(url), response.status, ms, caller?.org?.oid);
}

// The route a completed analysis is filed under, beside the `analyze` point
// that timed its headers.
//
// /v1/analyze answers with a stream: the response is the start of the answer,
// not the answer, and a p90 over `analyze` on this route reports time to first
// byte. That number is worth having — it is the one a proxy's idle timeout acts
// on — but it is not what an analysis costs, and the two cannot share a series
// without one of them being read as the other.
//
// Every terminal verdict is filed here, cached or scanned, so "how long until
// the caller had an answer" is one query and not a union of two. An analysis
// nobody could run is in no row: `unavailable` reports that the fleet could not
// be asked, and timing it would measure how quickly beamline gave up.
const ROUTE_VERDICT = "analyze:verdict";

// An analysis whose caller hung up before it finished.
//
// The run completed and what it cost is worth keeping — it is the same work on
// the same worker — but no caller ever received it, so it does not belong in
// the series that answers how long callers wait. Kept as its own route rather
// than dropped: these are the longest runs the fleet does, and a series that
// silently omits them would understate what analysis costs.
const ROUTE_ORPHAN = "analyze:orphan";

// One datapoint, written the same way wherever it is written from.
//
// Read off the headers that went out rather than threaded down from where the
// answer was decided, because those are what the caller was told: a metric that
// can disagree with what the caller saw is worse than no metric, it is the one
// that gets believed. It also means a new route is covered by construction.
//
// The artifact is still not in here. A PURL is the caller's dependency list —
// the same knowledge `clientScope` marks private on an authenticated deployment
// — and the ecosystem is enough to tell npm from crates without naming
// anyone's packages.
//
// The org is not a blob either. It is an index, and only an index: Analytics
// Engine samples per index, so indexing the org is what stops a customer doing
// millions of lookups from sampling a customer doing hundreds down to nothing
// — without it the quiet customer's dashboard would draw a graph made of one
// or two surviving rows. Filtering is all anyone does with it, `WHERE index1 =`
// is how that is spelled, and a blob carrying the same value would be a column
// nothing reads. So the shape of this dataset is unchanged; it has gained a
// way to be sliced, not a field.
/**
 * @param {Record<string, unknown>} env
 * @param {string} route - a named route, never one derived from the path
 * @param {Headers} headers - the response's, read for X-Beamline-Source
 * @param {string} ecosystem
 * @param {number} status
 * @param {number} ms
 * @param {string} [oid] - the org to index under; omitted leaves it unindexed
 * @returns {void}
 */
function writePoint(env, route, headers, ecosystem, status, ms, oid) {
  // Absent locally (`node local.js`) and in tests, and `writeDataPoint` is
  // fire-and-forget: it returns void, never throws, and must not be awaited.
  const ae = env?.BEAMLINE_AE;
  if (typeof ae?.writeDataPoint !== "function") return;
  const source = headers.get("X-Beamline-Source") || "";
  const org = String(oid || "");
  ae.writeDataPoint({
    blobs: [
      route,
      source,
      headers.get("X-Beamline-Follow") || "",
      headers.get("X-Beamline-Worker") || "",
      ecosystem,
      String(status),
    ],
    // Only when there is an org to file under. An unattributed request — an
    // open deployment, one of our own tokens — is left out rather than
    // gathered under an empty string, which would become the busiest index in
    // the dataset and sample every real customer against it.
    ...(org ? { indexes: [org] } : {}),
    // `layer` carries -1 when nothing answered, matching what poppy records: a
    // request that reached no layer is not a shallow one, and averaging it as
    // zero would report the fleet at its cheapest exactly when it is down.
    doubles: [CACHE_LAYERS.get(source) ?? -1, ms],
  });
}

// Which ecosystem was asked about, from the caller's own query. A bounded set;
// anything else is `other`.
/**
 * @param {URL} url
 * @returns {string} a PURL type scan averages, or `other`
 */
function ecosystemOf(url) {
  return purlType(url.searchParams.get("purl") || "");
}

/**
 * @param {Request} request
 * @param {Record<string, unknown>} env
 * @param {{waitUntil?: (p: Promise<unknown>) => void, signal?: AbortSignal}} host
 *   the runtime's context; beamline builds its own {@link Ctx} over it
 * @param {Caller} caller
 * @returns {Promise<Response>}
 */
async function dispatch(request, env, host, caller) {
  // One id for the whole request, logged on every line and sent to scan, so a
  // slow lookup can be followed across both services. A caller
  // may bring its own; it reaches our logs and outbound headers, so it is
  // filtered and bounded first.
  const rid =
    cleanId(request.headers.get("x-request-id")) || cleanId(request.headers.get("cf-ray")) || crypto.randomUUID();
  const url = new URL(request.url);
  // Forwarded to scan as a header and read there as a name, so it carries no
  // control characters at all, not only line breaks: a NUL or an escape is
  // neither a header nor a name.
  const filename = (request.headers.get("x-filename") || request.headers.get("x-file-name") || "").trim();
  const ctx = {
    ...host,
    rid,
    // The customer this request belongs to, or null for an anonymous caller on
    // an open deployment and for our own operational tokens. Read by the
    // telemetry writes deep in the analyze path.
    org: caller?.org || null,
    // X-Beamline-Pin: <host> forces dispatch to one worker and bypasses the
    // cache, so an experiment can time a specific backend on a specific sample.
    // It only restricts a choice beamline was already free to make, but it does
    // spend a scan slot on demand — so it lives behind the token gate with
    // everything else, and is bounded like any other caller-supplied header.
    pin: cleanId(request.headers.get("x-beamline-pin")) || null,
    // eslint-disable-next-line no-control-regex
    filename: filename && filename.length <= 255 && !/[\x00-\x1f\x7f]/.test(filename) ? filename : null,
    // A refresh is a cache-read policy, not part of an artifact's identity. It
    // therefore bypasses Beamline's Cache API/KV reads while retaining the
    // ordinary canonical key for the result Scan returns and we write back.
    refresh: url.searchParams.get("refresh") === "1",
  };
  // ExecutionContext keeps waitUntil on its prototype, bound to itself, so a
  // spread produces an object without it — and every background job would then
  // be an unregistered promise the runtime may cancel the moment the response
  // goes out. That is silent: the helper below simply finds no waitUntil and
  // does nothing, so the cache never populates and nothing says why. Carry it
  // over explicitly, still bound to the context that owns it. Every later
  // { ...ctx } spreads this plain object, where it is an own property.
  if (typeof host?.waitUntil === "function") ctx.waitUntil = (promise) => host.waitUntil(promise);
  if (request.signal && !ctx.signal) ctx.signal = request.signal;
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

  // identify() has already decided whether this token is one of ours or a
  // customer's. The gate is what that means: a recognized token is always
  // admitted, and an unrecognized one is refused only where the deployment
  // asked for a gate at all. So turning on customer tokens does not close an
  // open API, and a deployment that sets BEAMLINE_TOKEN is still closed to
  // everyone who is not a customer.
  if (!caller?.known && tokenList(env.BEAMLINE_TOKEN).length) {
    return v1Error(401, "unauthorized", "Send your API key as `Authorization: Bearer <key>`.");
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
    if (url.pathname === "/v1/flush") {
      if (request.method !== "POST") return methodNotAllowed("POST");
      return await handleV1Flush(env, ctx, url);
    }
    if (url.pathname === "/_/routes") {
      if (request.method !== "GET") return methodNotAllowed("GET");
      return await handleRoutes(env, ctx, url);
    }
    // A mistyped path is the first thing a new caller gets wrong, and bare
    // `not found` sends them hunting through the docs for a name they most
    // likely already had right — nearly every miss here is a dropped `/v1`.
    // Name the routes, and when the last segment is one of ours, say so.
    const routes = ["/v1/lookup", "/v1/analyze", "/v1/flush"];
    const tail = url.pathname.replace(/\/+$/, "");
    const guess = tail && routes.find((route) => route.endsWith(tail));
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
// How many locators one flush may walk to. The graph is caller-influenced —
// each document names the next — so it is bounded rather than trusted. An
// artifact reaches its digest, its URL and its PURL, which is three; the room
// above that is for a chain of spellings, not for an unbounded crawl.
const V1_FLUSH_MAX_LOCATORS = 16;
// The zone purge API takes at most this many URLs per call.
const CF_PURGE_BATCH = 30;
const CF_PURGE_TIMEOUT_MS = 10000;
// Retries after the first purge call, and the backoff between them. Short: a
// flush answers its caller only once the zone has, so this is their wait.
const CF_PURGE_RETRIES = 3;
const CF_PURGE_RETRY_BASE_MS = 250;
const CF_PURGE_RETRY_MAX_MS = 2_000;

// How long a v1 answer stays in the edge cache.
//
// Split the way the legacy route splits it, and for the same reason: a verdict
// is immutable for the engine that produced it, while "we hold nothing" becomes
// wrong the moment anything analyzes the artifact. A decision carrying
// `unavailable` is not cached at all — it describes this moment's reachability,
// and storing it would keep an outage alive after it ended.
// Seventy-two hours rather than the hour it was. An artifact is immutable — a PURL
// naming a version is the same bytes tomorrow — so the only thing a short TTL
// buys is picking up a re-score from a newer engine, and an hour bought that at
// the price of a KV round trip on almost every repeat ask. Measured over the
// fleet before this changed: L0 answered 0.5% of cached analyses and KV 87%,
// because poppy walks thousands of packages before returning to any one of
// them and the entry had long expired by then. See VERDICT_MAX_AGE, which
// overrides this without a deploy of the code.
const V1_VERDICT_MAX_AGE = 259200;
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
/**
 * @param {Record<string, unknown>} env
 * @param {Ctx} ctx
 * @param {URL} url
 * @returns {Promise<Response>}
 */
async function handleV1Lookup(env, ctx, url) {
  const budgetRaw = url.searchParams.get("false_positive_budget");
  const budget = parseFalsePositiveBudget(budgetRaw);
  const purls = url.searchParams.getAll("purl").map((value) => normalizePurl(value)).filter(Boolean);
  const urls = url.searchParams.getAll("url").map((value) => value.trim()).filter(Boolean);
  const sha = (url.searchParams.get("sha256") || "").trim().toLowerCase();
  const locators = urls.length ? urls.map((value) => ({ type: "url", value })) : purls.map((value) => ({ type: "purl", value }));

  if (purls.length && urls.length) {
    return v1Error(400, "multiple_locators", "Use ?purl= or ?url=, not both.");
  }
  if (urls.some((value) => !validArtifactUrl(value))) {
    return v1Error(400, "invalid_url", "url must be an absolute http or https URL with no credentials in it.");
  }
  if (!sha && !locators.length) {
    return v1Error(400, "missing_package", "Name an artifact with ?purl=, ?url=, or ?sha256=.");
  }
  // Checked here as /v1/analyze and /v1/flush check it. Anything else would be
  // a cache key and a worker request spent on a name no artifact can have.
  if (sha && !SHA_RE.test(sha)) {
    return v1Error(400, "invalid_sha256", "sha256 must be 64 hexadecimal characters.");
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
  const hit = await fullestAnswer(follow.value, candidates, async (policy) => {
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
    res.headers.set("cache-control", clientScope(env, v1MaxAge(env, document)));
    res.headers.delete("X-Beamline-Worker");
    if (served !== follow.value) res.headers.set("X-Beamline-Follow", served);
    return res;
  }

  if (!ctx.pin) {
    const stored = await fullestAnswer(follow.value, candidates, async (policy) => {
      const document = await kvGet(env, v1CachePath(sha, locators, policy));
      return document ? { document } : null;
    });
    if (stored) {
      const { document, policy: served } = stored;
      const body = v1BudgetedBody(document, budget, locator, true);
      if (body) {
        const res = v1Body(env, body, 200, null, v1MaxAge(env, document));
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
            storedDocument(env, document),
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
/**
 * @param {Record<string, unknown>} env
 * @param {Ctx} ctx
 * @param {Cache} cache
 * @param {Request} cacheKey - the asked-for key; its origin files the aliases
 * @param {string} path - the cache path the caller's question resolved to
 * @param {string} sha
 * @param {Locator[]} locators
 * @param {number} budget - false_positive_budget
 * @param {string} follow - the resolved follow policy
 * @returns {Promise<Response>}
 */
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
          logLine("v1_lookup", { src: "scan", status: answered.status, worker, retry: true, ...ids });
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
        // Any one row unreachable makes the whole reply one this service
        // should not rest on, whether one locator was asked or several.
        if (rowsIn(answered.body).some(isOutage)) {
          logLine("v1_lookup", { src: source, status: 200, worker, unavailable: true, ms: Date.now() - t0, ...ids });
          outage = { body: answered.body, worker, source };
          continue;
        }
        logLine("v1_lookup", { src: source, status: 200, worker, ms: Date.now() - t0, ...ids });
        const document = v1DocumentBody(answered.body);
        const stored = document || answered.body;
        const body = document ? v1BudgetedBody(document, budget, locator) : (v1BudgetedBody(answered.body, budget, locator) || answered.body);
        const res = v1Body(env, body, 200, worker, v1MaxAge(env, stored), source);
        if (!v1MaxAge(env, stored)) return res;
        // The asked-for key and every resolved alias are stored together; the
        // digest the answer names is
        // stored here. A lookup by PURL that reached a worker has just learned
        // the artifact's identity, and the next caller who knows only that
        // identity should not have to reach a worker to learn the same thing.
        // Skipped when they are the same key — a sha lookup has nothing to add.
        waitUntil(ctx, cacheV1Aliases(env, cache, origin, path, locator, stored, follow));
        return res;
      } catch (err) {
        // A caller who hung up aborted this fetch; the worker did nothing
        // wrong, and charging its breaker for it takes a healthy worker out
        // of the fleet one impatient client at a time.
        if (clientAborted(ctx)) throw err;
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
/**
 * @param {string|null} sha
 * @param {Locator|null} locator
 * @param {string|null} [cause=null] - no_workers, unreachable, saturated or mixed
 * @returns {object} a compact `unavailable` row
 */
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
/**
 * @param {string|null} sha
 * @param {Locator[]|null} locators
 * @param {string|null} follow - null builds the path scan is asked on
 * @param {boolean} [full=false]
 * @returns {string} `/v1/lookup?…`, the key both cache layers share
 */
function v1CachePath(sha, locators, follow, full = false) {
  const query = [];
  if (sha) query.push(`sha256=${encodeURIComponent(sha)}`);
  for (const locator of locators || []) {
    query.push(`${locator.type}=${encodeURIComponent(locator.value)}`);
  }
  if (follow) query.push(`follow=${encodeURIComponent(follow)}`);
  if (full) query.push("full=1");
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
/**
 * @param {Record<string, unknown>} env
 * @param {Cache} cache
 * @param {string} origin
 * @param {string} body - the decision to file
 * @param {string} follow - the policy that produced it
 * @param {boolean} [full=false]
 * @returns {Promise<void>}
 */
async function backfillDigestKey(env, cache, origin, body, follow, full = false) {
  const sha = v1DecisionSha(body);
  if (!sha) return;
  const maxAge = v1MaxAge(env, body);
  if (!maxAge) return;
  const path = v1CachePath(sha, [], follow, full);
  const key = new Request(`${origin}${path}`);
  // Only a decision is worth leaving alone. A miss cached under this digest is
  // the exact thing this write answers, and skipping the write on account of
  // one leaves the digest key saying "nobody has analyzed this" while the
  // locator key beside it holds the verdict.
  const existing = await cachedText(cache, key);
  if (existing && v1CachedAnalyzeAnswer(existing, full)) return;
  await fileDocument(env, cache, key, path, body);
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
/**
 * @param {string} origin
 * @param {string} requestedPath
 * @param {Locator|null} locator
 * @param {string} body
 * @param {string} follow
 * @param {string|null} canonicalPurl - scan's spelling of the asked PURL
 * @param {boolean} [full=false]
 * @returns {Request[]} one key per name the document answers to
 */
function v1CacheAliasPaths(origin, requestedPath, locator, body, follow, canonicalPurl, full = false) {
  const paths = new Set([requestedPath]);
  if (locator) paths.add(v1CachePath(null, [locator], follow, full));
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
  if (canonicalPurl) paths.add(v1CachePath(null, [{ type: "purl", value: canonicalPurl }], follow, full));
  const sha = v1DecisionSha(body);
  if (sha) paths.add(v1CachePath(sha, [], follow, full));
  const row = parseJson(body);
  if (row && !Array.isArray(row) && typeof row === "object") {
    if (typeof row.purl === "string" && row.purl.trim()) {
      paths.add(v1CachePath(null, [{ type: "purl", value: row.purl.trim() }], follow, full));
    }
    if (typeof row.url === "string" && validArtifactUrl(row.url.trim())) {
      paths.add(v1CachePath(null, [{ type: "url", value: row.url.trim() }], follow, full));
    }
  }
  return [...paths].map((path) => new Request(`${origin}${path}`));
}

// Writes every alias, and answers with how many there were. The count is for
// the log line at the one call site that logs: building the key set a second
// time to count it re-parsed the document and could disagree with what was
// actually written.
/**
 * @param {Record<string, unknown>} env
 * @param {Cache} cache
 * @param {string} origin
 * @param {string} requestedPath
 * @param {Locator|null} locator
 * @param {string} body
 * @param {string} follow
 * @param {string|null} [canonicalPurl]
 * @param {boolean} [full=false]
 * @returns {Promise<number>} how many keys were written
 */
async function cacheV1Aliases(env, cache, origin, requestedPath, locator, body, follow, canonicalPurl, full = false) {
  const keys = v1CacheAliasPaths(origin, requestedPath, locator, body, follow, canonicalPurl, full);
  await Promise.all(
    keys.map((key) => {
      const parsed = new URL(key.url);
      return fileDocument(env, cache, key, `${parsed.pathname}${parsed.search}`, body);
    }),
  );
  return keys.length;
}

// One document into both layers, together and independently.
//
// They used to be written in series inside one try, so an edge write the Cache
// API refused skipped the KV write after it — and KV is the copy that outlives
// the edge by months and serves every other data center. Each failure is now
// its own log line and costs only its own layer.
/**
 * @param {Record<string, unknown>} env
 * @param {Cache} cache
 * @param {Request} key - the edge cache key
 * @param {string} path - the same key as a path, which KV hashes
 * @param {string} body
 * @returns {Promise<void>} never rejects
 */
async function fileDocument(env, cache, key, path, body) {
  const [edge, kv] = await Promise.allSettled([cache.put(key, storedDocument(env, body)), kvPut(env, path, body)]);
  if (edge.status === "rejected") logLine("v1_cache_write", { stored: false, layer: "cache", key: path, err: errText(edge.reason) });
  if (kv.status === "rejected") logLine("v1_cache_write", { stored: false, layer: "kv", key: path, err: errText(kv.reason) });
}

// A stored or streamed body, parsed. Everything here is handed JSON that came
// from a cache, a worker, or a stream line, and every one of them treats text
// that will not parse as text that is not a document — so the judgement is made
// once, here, rather than in a try block per reader, each free to drift.
/**
 * @param {string|null|undefined} text
 * @returns {unknown} the parsed value, or null when it does not parse
 */
function parseJson(text) {
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

// A body's rows, one shape. A single locator is answered with an object and
// several with an array, and every reader below asks the same question of each
// row — so both arrive as a list. A body that will not parse yields one empty
// row, which answers nothing, which is what an unreadable body should say.
/**
 * @param {string} body
 * @returns {unknown[]} every row, an object body as a list of one
 */
function rowsIn(body) {
  const row = parseJson(body);
  return Array.isArray(row) ? row : [row];
}

// The digest a decision names, when it names a well-formed one.
/**
 * @param {string} body
 * @returns {string|null} a well-formed lowercase digest, or null
 */
function v1DecisionSha(body) {
  const row = parseJson(body);
  const sha = row && typeof row === "object" ? (row.sha256 || shaFromEnvelope(row)) : null;
  return typeof sha === "string" && SHA_RE.test(sha) ? sha : null;
}

/**
 * @param {string|null} raw - the query value; null when absent
 * @returns {number|null} the budget, or null when it is not a whole number from 0 to 3000
 */
function parseFalsePositiveBudget(raw) {
  if (raw === null) return DEFAULT_FALSE_POSITIVE_BUDGET;
  const value = String(raw).trim();
  if (!/^\d{1,4}$/.test(value)) return null;
  const budget = Number(value);
  return budget >= 0 && budget <= SUSPICIOUS_LEVEL_CEILING ? budget : null;
}

// An absolute http(s) URL carrying no credentials. A URL is logged, sent to a
// worker, and filed as a key in caches every caller shares, so a password in
// its userinfo would be written to all three; refusing it is the only place
// that can stop that.
/**
 * @param {string} value
 * @returns {boolean}
 */
function validArtifactUrl(value) {
  try {
    const parsed = new URL(value);
    return (parsed.protocol === "http:" || parsed.protocol === "https:") && !parsed.username && !parsed.password;
  } catch {
    return false;
  }
}

/**
 * @param {string} rid
 * @param {string|null} sha
 * @param {Locator[]} [locators] - only the first is named; a batch logs one
 * @returns {Ids}
 */
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
/**
 * @param {URLSearchParams} searchParams
 * @param {"purl"|"url"|"sha256"|"bytes"} kind - how the artifact was named,
 *   which is what decides the default
 * @returns {{value: string}|{error: string}} one or the other, never both
 */
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

/**
 * @param {string} policy - a canonical spelling from parseFollow
 * @returns {Set<string>} the kinds it follows
 */
function followSet(policy) {
  if (policy === "none") return new Set();
  if (policy === "all") return new Set(FOLLOW_KINDS);
  return new Set(String(policy).split(",").map((kind) => kind.trim()).filter(Boolean));
}

// Every stored policy wide enough to answer the question, widest first.
//
// `follow` is a spend control, not a narrowing of the question. It caps what an
// analysis may walk, and a caller who set it low was buying a cheaper run — not
// asking to be told less about an artifact somebody else has already paid to
// walk further. So when several stored answers all answer the question, the
// fullest one wins. Its extra findings are the ones the cheap walk could never
// have reached, `findings[].pkg` names the component each came from, and the
// caller pays nothing for them.
//
// This orders how a decision is chosen, not how the reads are issued; those go
// out together. See fullestAnswer.
/**
 * @param {string} policy
 * @returns {string[]} stored policies that answer it, widest first
 */
function followCandidates(policy) {
  const want = followSet(policy);
  // FOLLOW_POLICIES runs narrowest first, so containment order reversed is
  // widest first.
  return FOLLOW_POLICIES.filter((candidate) => {
    const kinds = followSet(candidate);
    return kinds.size >= want.size && [...want].every((kind) => kinds.has(kind));
  }).reverse();
}

// The fullest candidate policy holding an answer.
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
//
// Every candidate is read at once. They are independent keys, so walking them
// in series bought nothing but their latency added together — measured on the
// fleet, that walk was the difference between /lookup at 314ms and /analyze at
// 163ms, /lookup being the route built to miss and so the one paying for the
// whole walk almost every time.
//
// Reading all of them is also what widest-first requires: which policy answers
// is not known until every key has been looked at, so there is no fast path to
// take. That costs one batch of reads where a hit on the caller's own policy
// used to cost a single read, and buys the fullest answer already paid for.
//
// `asked` is the policy the caller named, and only it may supply the fallback.
// A non-decision — `unanalyzed`, `unavailable` — is a statement about one key at
// one moment rather than evidence any walk gathered, so a wider candidate's
// non-decision answers a question nobody asked.
/**
 * @template {{document: string}} T
 * @param {string} asked - the policy the caller named; only it may fall back
 * @param {string[]} candidates - widest first
 * @param {(policy: string) => Promise<T|null>} load - reads one policy's key
 * @returns {Promise<(T & {policy: string})|null>} whatever `load` returned,
 *   untouched, beside the policy that answered
 */
async function fullestAnswer(asked, candidates, load) {
  if (!candidates.length) return null;

  const found = await Promise.all(candidates.map((policy) => load(policy)));
  let best = null;
  let newest = null;
  for (const [index, hit] of found.entries()) {
    const verdict = hit && v1CachedVerdict(hit.document);
    if (!verdict) continue;
    // Candidates run widest first, so the first decision seen at a given engine
    // is already the fullest one that engine produced. Only a newer engine
    // displaces it.
    if (best && !newerEngine(verdict.engine_version, newest)) continue;
    best = { ...hit, policy: candidates[index] };
    newest = verdict.engine_version;
  }
  if (best) return best;

  const mine = found[candidates.indexOf(asked)];
  return mine ? { ...mine, policy: asked } : null;
}

// Is `a` a newer engine than `b`?
//
// Width picks the fullest answer; this keeps it from picking an archaeological
// one. Nothing else in the walk looks at age, and KV holds a verdict for 90
// days, so without this a `follow=all` entry an old engine wrote outranks a
// verdict minutes old from the engine running now — which is precisely the
// failure that sent `pkg:pypi/ddtrace@3.18.1` out as hostile on engine 2.8.0
// while 2.11.0 had already scored it benign.
//
// Compared segment by segment as numbers, because `2.11.0` orders before
// `2.8.0` under the string comparison a naive version of this would use.
/**
 * @param {string|null|undefined} candidate
 * @param {string|null|undefined} incumbent
 * @returns {boolean} whether `candidate` is the newer engine version
 */
function newerEngine(candidate, incumbent) {
  const left = String(candidate || "").split(".");
  const right = String(incumbent || "").split(".");
  for (let i = 0; i < Math.max(left.length, right.length); i++) {
    const step = (Number.parseInt(left[i], 10) || 0) - (Number.parseInt(right[i], 10) || 0);
    if (step) return step > 0;
  }
  return false;
}

/**
 * @param {string} body
 * @param {boolean} [full=false] - accept only a full envelope
 * @returns {string|null} the canonical document, or null when it is not one
 */
function v1DocumentBody(body, full = false) {
  const row = parseJson(body);
  if (!row || typeof row !== "object") return null;
  if (full) return isFullEnvelope(row) ? JSON.stringify(row) : null;
  if (Array.isArray(row)) {
    if (!row.every((item) => item && typeof item === "object")) return null;
    return JSON.stringify(row.map((item) => canonicalV1Row(item)));
  }
  return JSON.stringify(canonicalV1Row(row));
}

/**
 * @param {object} row
 * @returns {object}
 */
function canonicalV1Row(row) {
  return compactV1Row(normalizeV1Row(row));
}

/**
 * @param {string} body
 * @param {number} budget
 * @param {Locator|null} locator - a URL locator is echoed into each row
 * @param {boolean} [legacyCachedUnknown=false] - translate scan's old `unknown`
 * @returns {string|null} the body as the caller sees it, or null when it does not parse
 */
function v1BudgetedBody(body, budget, locator, legacyCachedUnknown = false) {
  const row = parseJson(body);
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

/**
 * @param {unknown} row
 * @param {number|null} [budget=null] - null keeps the stored severity
 * @returns {unknown} a copy with `status` and `severity` settled; non-objects pass through
 */
function normalizeV1Row(row, budget = null) {
  if (!row || typeof row !== "object" || Array.isArray(row)) return row;
  const status = row.status || (row.decision === "allow" || row.decision === "block" ? "analyzed" : row.decision);
  const normalized = { ...row, status: status || "unknown" };
  delete normalized.decision;
  if (normalized.status !== "analyzed") {
    normalized.severity = "unknown";
  } else if (Number.isInteger(normalized.fires_at) && budget !== null) {
    const level = normalized.fires_at;
    if (level < 0) normalized.severity = "benign";
    else if (level <= budget) normalized.severity = "hostile";
    else if (level <= SUSPICIOUS_LEVEL_CEILING) normalized.severity = "suspicious";
    else normalized.severity = "benign";
  } else if (normalized.severity == null) {
    normalized.severity = "unknown";
  }
  return normalized;
}

// Null means the field has no information. Do not make every client pay for
// keys whose only value is null; nested findings use the same sparse shape.
/**
 * @param {unknown} value
 * @returns {unknown} a copy without null fields, recursively
 */
function compactV1Row(value) {
  if (Array.isArray(value)) return value.map(compactV1Row);
  if (!value || typeof value !== "object") return value;
  return Object.fromEntries(
    Object.entries(value)
      .filter(([, item]) => item !== null)
      .map(([key, item]) => [key, compactV1Row(item)]),
  );
}

// What the edge cache holds under `key`, as text, or null. A read that fails
// is a miss: the layer behind it still answers.
/**
 * @param {Cache} cache
 * @param {Request} key
 * @returns {Promise<string|null>}
 */
async function cachedText(cache, key) {
  const found = await cache.match(key).catch(() => null);
  return found ? await found.text().catch(() => null) : null;
}

// KV keys are hashes rather than raw URLs: a batch of PURLs can exceed KV's
// 512-byte key limit, while the lookup path remains the single source of truth
// for both Cache API and KV key identity.
/**
 * @param {string} path
 * @returns {Promise<string>}
 */
async function kvKey(path) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(path));
  return `v1:${[...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0")).join("")}`;
}

/**
 * @param {Record<string, unknown>} env
 * @param {string} path
 * @returns {Promise<string|null>} never rejects
 */
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

/**
 * @param {Record<string, unknown>} env
 * @param {string} path
 * @returns {Promise<boolean>} whether the delete went through; never rejects
 */
async function kvDelete(env, path) {
  const kv = env && env.BEAMLINE_KV;
  if (!kv || typeof kv.delete !== "function") return false;
  try {
    await kv.delete(await kvKey(path));
    return true;
  } catch (err) {
    logLine("v1_kv_delete", { ok: false, err: errText(err) });
    return false;
  }
}

// Nothing is written without an expiry. `unanalyzed` keeps the short clock it has
// at the edge, because it stops being true the moment anything analyzes the
// artifact; a verdict keeps the long one.
/**
 * @param {Record<string, unknown>} env
 * @param {string} path
 * @param {string} body
 * @returns {Promise<void>}
 */
async function kvPut(env, path, body) {
  const kv = env && env.BEAMLINE_KV;
  if (!kv || typeof kv.put !== "function") return;
  const maxAge = v1MaxAge(env, body);
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
/**
 * @param {string} body
 * @returns {object|null} the row when it is an engine's verdict
 */
function v1CachedVerdict(body) {
  const row = parseJson(body);
  if (!row || typeof row !== "object" || Array.isArray(row)) return null;
  if (row.status !== "analyzed" && !(row.decision === "allow" || row.decision === "block")) return null;
  if (!row.engine_version) return null;
  return row;
}

/**
 * @param {unknown} row
 * @returns {boolean}
 */
function isFullEnvelope(row) {
  return !!row && typeof row === "object" && !Array.isArray(row)
    && !!row.ml && typeof row.ml === "object" && !Array.isArray(row.ml)
    && typeof row.ml.eng === "string" && row.ml.eng.length > 0
    && !!row.raw && typeof row.raw === "object" && !Array.isArray(row.raw);
}

/**
 * @param {string|null} body
 * @param {boolean} [full=false]
 * @returns {object|null} the answer /v1/analyze may serve, or null
 */
function v1CachedAnalyzeAnswer(body, full = false) {
  if (!full) return v1CachedVerdict(body);
  const row = parseJson(body);
  return isFullEnvelope(row) ? row : null;
}

// One row saying the fleet could not find out, in either spelling scan has
// used for it. Named once because two readers ask it — a body carrying one is
// not an answer to relay and not an answer to cache — and a predicate spelled
// out twice is a predicate that eventually says two things.
/**
 * @param {unknown} row
 * @returns {boolean}
 */
function isOutage(row) {
  return row?.status === "unavailable" || row?.decision === "unavailable";
}

// How long this document may be held, in seconds. A body carrying any
// `unavailable` is not cacheable at all; anything no engine produced is
// cacheable only briefly.
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
//
// `env` is read for the verdict age only. The short ages are policy about what
// the document *is* — an absence goes stale the moment anything analyzes the
// artifact, an outage describes only this moment — and neither is a deployment
// choice. How long a settled verdict is worth keeping is.
/**
 * @param {Record<string, unknown>} env
 * @param {string} body
 * @returns {number} seconds; 0 means do not cache
 */
function v1MaxAge(env, body) {
  const rows = rowsIn(body);
  if (rows.some(isOutage)) return 0;
  if (rows.some((item) => !isFullEnvelope(item) && (item?.status !== "analyzed" || !item?.engine_version))) return V1_NO_ENGINE_MAX_AGE;
  return numEnv(env, "VERDICT_MAX_AGE", V1_VERDICT_MAX_AGE);
}

/**
 * @param {string|null} source - X-Scan-Source, or a layer of ours
 * @returns {string} a name CACHE_LAYERS knows
 */
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
/**
 * @param {Headers} headers - set in place
 * @param {string} source
 * @returns {void}
 */
function setSource(headers, source) {
  headers.set("X-Beamline-Source", source);
  const layer = CACHE_LAYERS.get(source);
  if (layer !== undefined) headers.set("X-Cache-Layer", String(layer));
}

/**
 * @param {Record<string, unknown>} env
 * @param {string} body
 * @param {number} status
 * @param {string|null} worker - the host that answered, if any
 * @param {number} maxAge - seconds; 0 is no-store
 * @param {string|null} [source]
 * @returns {Response}
 */
function v1Body(env, body, status, worker, maxAge, source) {
  const headers = new Headers({
    "content-type": "application/json",
    "cache-control": clientScope(env, maxAge),
  });
  if (worker) headers.set("X-Beamline-Worker", worker);
  setSource(headers, worker ? beamlineSource(source) : "none");
  return new Response(body, { status, headers });
}

/**
 * @param {number} status
 * @param {string} code
 * @param {string} message
 * @returns {Response}
 */
function v1Error(status, code, message) {
  return new Response(JSON.stringify({ error: { code, message } }), {
    status,
    headers: { "content-type": "application/json", "cache-control": "no-store" },
  });
}

// POST /v1/flush — forget everything cached about an artifact.
//
// The only operation here that removes rather than writes. Without it a stale
// verdict could be displaced only by landing a newer one on the exact key a
// caller would read, and an artifact does not have one key: it has one per
// follow policy, per `full` variant, and per locator that names it. Correcting
// a single PyPI sdist by hand took four attempts across two wrong keys before
// this existed, and the write that finally worked went through X-Beamline-Pin,
// which is a benchmarking lever rather than an invalidation one.
//
// Children are the point. A verdict names the other ways to reach the artifact
// it describes — the digest it resolved to, the URL it was fetched from, the
// PURL scan normalized it to — and those are separate entries that a flush of
// the caller's own spelling would leave standing, holding exactly the answer
// that was just dropped. So each document is read before it is deleted, the
// locators inside it are queued, and the walk continues until nothing new
// turns up. Bounded, because the graph is caller-influenced.
/**
 * @param {Record<string, unknown>} env
 * @param {Ctx} ctx
 * @param {URL} url
 * @returns {Promise<Response>}
 */
async function handleV1Flush(env, ctx, url) {
  const named = oneLocator(url);
  if (named.error) return named.error;
  if (!named.locator) {
    return v1Error(400, "missing_package", "Name an artifact with ?purl=, ?url=, or ?sha256=.");
  }

  const cache = await getCache(env);
  const seen = new Set();
  const locators = [];
  const keys = [];
  let examined = 0;
  let dropped = 0;
  let edge = 0;
  let kv = 0;
  // Walked a generation at a time. Depth is unavoidable — a child is named by
  // the document its parent was holding, so it cannot be known before that
  // parent is read — but breadth is not: siblings are independent keys, and
  // draining them one at a time would make a flush as many round trips deep as
  // the artifact has spellings.
  let frontier = [named.locator];
  while (frontier.length && seen.size < V1_FLUSH_MAX_LOCATORS) {
    const wave = [];
    for (const locator of frontier) {
      const id = `${locator.type}=${locator.value}`;
      if (seen.has(id) || seen.size >= V1_FLUSH_MAX_LOCATORS) continue;
      seen.add(id);
      wave.push({ locator, id });
    }
    if (!wave.length) break;

    const walked = await Promise.all(wave.map(({ locator }) => dropLocator(env, cache, url.origin, locator)));
    frontier = [];
    for (const [index, result] of walked.entries()) {
      examined += result.examined;
      dropped += result.dropped;
      edge += result.edge;
      kv += result.kv;
      locators.push({ locator: wave[index].id, dropped: result.dropped });
      frontier.push(...result.children);
      keys.push(...result.keys);
    }
  }

  const purge = await purgeZone(env, ctx, keys);
  logLine("v1_flush", { rid: ctx.rid, locators: locators.length, examined, dropped, edge, kv, purge });
  if (purge === "failed") {
    return v1Error(
      502,
      "purge_failed",
      "This data center and KV were cleared, but the zone purge did not go through; other data centers may still hold the old answer. Retry.",
    );
  }
  // One entry per layer a verdict can live in, in the order a lookup reads
  // them. `edge` is this data center's Cache API alone; `zone` is every other
  // data center, reached by URL, so it counts keys purged rather than found.
  const caches = {
    edge: { dropped: edge },
    kv: { dropped: kv },
    zone: { purge, purged: purge === "ok" ? keys.length : 0 },
  };
  return json({ status: "flushed", caches, locators, keys_examined: examined, keys_dropped: dropped }, 200);
}

// The one artifact a request names by ?purl=, ?url= or ?sha256=, null when it
// names none, or the 400 saying why it cannot be read. /v1/analyze and
// /v1/flush take a single locator under the same rules, so the rules are
// written once.
/**
 * @param {URL} url
 * @returns {{locator: Locator|null, error?: undefined}|{error: Response}}
 */
function oneLocator(url) {
  const purl = normalizePurl(url.searchParams.get("purl"));
  const artifactUrl = (url.searchParams.get("url") || "").trim();
  const sha256 = (url.searchParams.get("sha256") || "").trim().toLowerCase();
  if (Number(Boolean(purl)) + Number(Boolean(artifactUrl)) + Number(Boolean(sha256)) > 1) {
    return { error: v1Error(400, "multiple_locators", "Use ?purl=, ?url=, or ?sha256=, not more than one.") };
  }
  if (sha256 && !SHA_RE.test(sha256)) {
    return { error: v1Error(400, "invalid_sha256", "sha256 must be 64 hexadecimal characters.") };
  }
  if (artifactUrl && !validArtifactUrl(artifactUrl)) {
    return { error: v1Error(400, "invalid_url", "url must be an absolute http or https URL with no credentials in it.") };
  }
  if (purl) return { locator: { type: "purl", value: purl } };
  if (artifactUrl) return { locator: { type: "url", value: artifactUrl } };
  if (sha256) return { locator: { type: "sha256", value: sha256 } };
  return { locator: null };
}

// Every data center, not just this one.
//
// cache.delete() removes an entry from the colo that ran the flush and from
// nowhere else: the Cache API does not replicate, so every other colo that has
// served this artifact keeps its own copy for the rest of VERDICT_MAX_AGE. The
// zone purge API is what reaches them. Entries are keyed on ordinary URLs under
// this deployment's origin, so purge-by-URL is enough, and it is the one purge
// shape every plan has. Every examined key is sent, not only those this colo
// held: the colo that matters is the one that answered somebody else.
//
// Unconfigured is not a failure. `node local.js` has no edge cache to purge,
// and a deployment without the secrets is exactly as flushed as it was before
// this existed. The caller can see which it got.
/**
 * @param {Record<string, unknown>} env
 * @param {Ctx} ctx
 * @param {string[]} urls - cache keys to purge in every data center
 * @returns {Promise<"ok"|"failed"|"unconfigured">}
 */
async function purgeZone(env, ctx, urls) {
  const zone = (env.CF_ZONE_ID || "").trim();
  const token = (env.CF_PURGE_TOKEN || "").trim();
  if (!zone || !token) return "unconfigured";
  const batches = [];
  for (let i = 0; i < urls.length; i += CF_PURGE_BATCH) batches.push(urls.slice(i, i + CF_PURGE_BATCH));
  const endpoint = `https://api.cloudflare.com/client/v4/zones/${encodeURIComponent(zone)}/purge_cache`;
  const results = await Promise.all(batches.map((files) => purgeBatch(endpoint, token, files, ctx)));
  return results.every(Boolean) ? "ok" : "failed";
}

// One purge call, retried while the failure is the API's rather than ours.
//
// A network error, a 429 or a 5xx says nothing about the request and is likely
// gone a moment later, and the alternative is telling the caller to retry a
// flush whose local half already happened. Any other refusal — a token without
// the permission, a zone that is not ours — repeats identically, so it is
// reported at once. Bounded short, because the caller is waiting on it.
/**
 * @param {string} endpoint
 * @param {string} token
 * @param {string[]} files - at most CF_PURGE_BATCH URLs
 * @param {Ctx} ctx
 * @returns {Promise<boolean>} whether the zone accepted the purge; never rejects
 */
async function purgeBatch(endpoint, token, files, ctx) {
  for (let attempt = 0; ; attempt++) {
    let retryable = true;
    try {
      const outcome = await fetchTimeout(
        endpoint,
        {
          method: "POST",
          headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
          body: JSON.stringify({ files }),
        },
        CF_PURGE_TIMEOUT_MS,
        ctx,
        async (res) => {
          const body = await res.json().catch(() => null);
          const ok = res.ok && body?.success === true;
          if (!ok) {
            logLine("v1_purge", { rid: ctx.rid, ok: false, status: res.status, attempt, urls: files.length, err: JSON.stringify(body?.errors || []) });
          }
          return { ok, retryable: res.status === 429 || res.status >= 500 };
        },
      );
      if (outcome.ok) return true;
      retryable = outcome.retryable;
    } catch (err) {
      if (clientAborted(ctx)) return false;
      logLine("v1_purge", { rid: ctx.rid, ok: false, attempt, urls: files.length, err: errText(err) });
    }
    if (!retryable || attempt >= CF_PURGE_RETRIES) return false;
    const wait = backoff(CF_PURGE_RETRY_BASE_MS, attempt, CF_PURGE_RETRY_MAX_MS);
    logLine("v1_purge_retry", { rid: ctx.rid, attempt: attempt + 1, wait_ms: Math.round(wait), urls: files.length });
    try {
      await sleep(wait, ctx);
    } catch {
      return false;
    }
  }
}

// Drop every key one locator can be filed under: both `full` shapes of every
// follow policy. Issued together, because they are independent keys and a
// series walk would be fourteen round trips deep for one spelling.
/**
 * @param {Record<string, unknown>} env
 * @param {Cache} cache
 * @param {string} origin
 * @param {Locator} locator
 * @returns {Promise<{examined: number, dropped: number, edge: number,
 *   kv: number, children: Locator[], keys: string[]}>}
 */
async function dropLocator(env, cache, origin, locator) {
  const paths = [];
  for (const policy of FOLLOW_POLICIES) {
    for (const full of [false, true]) {
      paths.push(
        locator.type === "sha256"
          ? v1CachePath(locator.value, [], policy, full)
          : v1CachePath(null, [locator], policy, full),
      );
    }
  }
  const held = await Promise.all(paths.map((path) => dropKey(env, cache, origin, path)));
  const children = [];
  let dropped = 0;
  let edge = 0;
  let kv = 0;
  for (const key of held) {
    edge += Number(key.edge);
    kv += Number(key.kv);
    if (!key.document) continue;
    dropped += 1;
    children.push(...locatorsIn(key.document));
  }
  return { examined: paths.length, dropped, edge, kv, children, keys: paths.map((path) => `${origin}${path}`) };
}

// Drop one key from both layers, returning whatever it held and which layer
// held it.
//
// Read and delete rather than delete alone: the document names the artifact's
// other spellings, and dropping it without looking would strand them. Both
// layers are read, in parallel, because the answer reports each one — a key
// present in both holds the same document in each, so the second read buys
// nothing for the walk, only for the accounting.
/**
 * @param {Record<string, unknown>} env
 * @param {Cache} cache
 * @param {string} origin
 * @param {string} path
 * @returns {Promise<{document: string|null, edge: boolean, kv: boolean}>}
 */
async function dropKey(env, cache, origin, path) {
  const request = new Request(`${origin}${path}`);
  const [cached, stored] = await Promise.all([cachedText(cache, request), kvGet(env, path)]);
  await Promise.all([
    typeof cache.delete === "function" ? cache.delete(request).catch(() => false) : false,
    kvDelete(env, path),
  ]);
  return { document: cached || stored, edge: Boolean(cached), kv: Boolean(stored) };
}

// Every locator a stored answer names, so a flush can reach them too.
/**
 * @param {string} body
 * @returns {Locator[]}
 */
function locatorsIn(body) {
  const out = [];
  for (const item of rowsIn(body)) {
    if (!item || typeof item !== "object") continue;
    const purl = normalizePurl(item.purl);
    if (purl && cleanPurl(purl)) out.push({ type: "purl", value: purl });
    const artifactUrl = String(item.url || "").trim();
    if (validArtifactUrl(artifactUrl)) out.push({ type: "url", value: artifactUrl });
    const sha = String(item.sha256 || "").trim().toLowerCase();
    if (SHA_RE.test(sha)) out.push({ type: "sha256", value: sha });
  }
  return out;
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
/**
 * @param {Request} request
 * @param {Record<string, unknown>} env
 * @param {Ctx} ctx
 * @param {URL} url
 * @returns {Promise<Response>}
 */
async function handleV1Analyze(request, env, ctx, url) {
  const budgetRaw = url.searchParams.get("false_positive_budget");
  const budget = parseFalsePositiveBudget(budgetRaw);
  const full = url.searchParams.get("full") === "1";
  const named = oneLocator(url);
  if (named.error) return named.error;
  const { locator } = named;
  const bySha = locator?.type === "sha256";
  if (bySha && !ctx.refresh) {
    return v1Error(400, "refresh_required", "?sha256= on /v1/analyze requires refresh=1.");
  }
  if (ctx.refresh && !bySha) {
    return v1Error(400, "missing_sha256", "refresh=1 requires ?sha256=.");
  }
  // Locators name a stored artifact, and the artifact itself is another way
  // in. A caller holding bytes nobody has published — a build output, a file off
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
      buffered = await readBounded(request, max);
    } catch {
      return v1Error(400, "invalid_body", "Could not read the artifact from the request body.");
    }
    if (!buffered) {
      return v1Error(413, "artifact_too_large", `The artifact exceeds the ${max} byte limit.`);
    }
    if (buffered.byteLength > 0) bytes = buffered;
  }
  if (!locator && !bytes) {
    return v1Error(400, "missing_package", "Name an artifact with ?purl=, ?url=, or ?sha256=, or send it as the body.");
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
  if (ctx.refresh) query.push("refresh=1");
  if (full) query.push("full=1");
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
    full: full || undefined,
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
  if (locator && !bytes && !ctx.pin && !ctx.refresh) {
    const cache = await getCache(env);
    // Same ordering the lookup reads under: every policy wide enough to answer
    // this one, widest first. An analysis is the most expensive thing this
    // service does, so a fuller answer already in hand is worth even more here
    // than it is on the lookup.
    const candidates = followCandidates(follow.value);
    // A cached miss must not end this walk either, and here it is the most
    // expensive place it could: a miss filed under the narrow policy would send
    // us off to spend an analysis slot on a verdict a wider entry is already
    // holding.
    let hit = await fullestAnswer(follow.value, candidates, async (policy) => {
      const text = await cachedText(cache, new Request(`${url.origin}${v1CachePath(null, [locator], policy, full)}`));
      return text ? { document: text, fromCache: true } : null;
    });
    if (!hit) {
      hit = await fullestAnswer(follow.value, candidates, async (policy) => {
        const text = await kvGet(env, v1CachePath(null, [locator], policy, full));
        return text ? { document: text, fromCache: false } : null;
      });
    }
    const document = hit ? hit.document : null;
    const served = hit ? hit.policy : follow.value;
    const decided = document ? v1CachedAnalyzeAnswer(document, full) : null;
    if (decided) {
      // Serving from cache used to warm nothing, because this path returns
      // before the write below ever runs. So a warm PURL key left the digest
      // key cold indefinitely: every caller holding only a hash paid a round
      // trip to learn something we were already holding, and answering them
      // never fixed it either.
      const body = full ? document : v1BudgetedBody(document, budget, locator);
      // An answer that came from KV warms L0 under the key it was asked for,
      // exactly as the lookup does on its own KV hit.
      //
      // Without this the only write on this path is the digest backfill below,
      // which answers a different caller entirely — the one holding a hash. The
      // locator key that was just read stayed cold, so a client that only ever
      // calls /v1/analyze paid the L1 round trip for the same package in the
      // same colo indefinitely, and L0 looked broken while working perfectly.
      // It was warmed only by accident, when a lookup for the same package
      // happened to come past.
      if (!hit.fromCache) {
        waitUntil(
          ctx,
          cache.put(
            new Request(`${url.origin}${v1CachePath(null, [locator], served, full)}`),
            storedDocument(env, document),
          ),
        );
      }
      // Filed at the digest under the policy that produced it, not the one that
      // asked, for the reason the lookup warms its own key that way.
      waitUntil(ctx, backfillDigestKey(env, cache, url.origin, document, served, full));
      logLine("v1_analyze", { src: hit.fromCache ? "cache" : "kv", status: 200, artifact_status: decided.status, follow: served, ms: Date.now() - t0, ...ids });
      // Answered in the shape this route always answers in: one NDJSON line,
      // no progress frames because there was no run to report progress about.
      const answered = new Headers({
        "content-type": "application/x-ndjson",
        "cache-control": "no-store",
      });
      if (served !== follow.value) answered.set("X-Beamline-Follow", served);
      setSource(answered, hit.fromCache ? "cache" : "kv");
      // A held verdict is whole the moment it goes out, so its two points carry
      // the same time. Written anyway: the series is every answer this route
      // gave, and one missing its cheap half would read as a fleet that only
      // ever scans.
      writePoint(env, ROUTE_VERDICT, answered, ecosystemOf(url), 200, Date.now() - t0, ctx.org?.oid);
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
  //
  // Three round trips that do not depend on each other, taken together: who
  // is already running this package, what it weighs, and how the fleet looks
  // right now. In sequence they cost a worker round trip apiece; measured
  // 2026-09-06 the router's share of a median answer was 600ms.
  const [busy, sizeHint] = await Promise.all([
    locator ? runningWorker(env, ctx, locator, ids) : null,
    locator?.type === "purl" ? registrySize(env, ctx, locator.value, ids) : (bytes ? bytes.byteLength : null),
    Promise.all(scanWorkers(env, ctx.pin).map((base) => scanStats(env, ctx, base))),
  ]);
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
  // Everything a pass needs, settled once. Each attempt asks the same question
  // of a different worker, so the only thing that changes between them is the
  // tally it fills in.
  const job = {
    url,
    locator,
    path,
    budget,
    busy,
    ids,
    t0,
    bytes,
    full,
    sizeHint,
    // Which policy an answer may be filed under, and null where nothing may be:
    // an upload has no locator to file one against.
    cacheFollow: locator && !bytes ? follow.value : null,
  };
  // A pass that never reached a verdict is worth making again: a 5xx, a 429 at
  // capacity, an edge timeout at 120s, a dropped connection — none of those are
  // answers, and a moment later they may not hold. A rejection is an answer
  // (bad bytes, unsupported type), and v1Dispatch returns those rather than
  // null, so repeating one never burns a slot.
  //
  // Retrying is safe because scan de-duplicates by sha and purl across isolates:
  // a retry joins the analysis already running rather than starting a second one,
  // which is what makes retrying an edge timeout worth doing at all.
  let last = null;
  for (let attempt = 0; ; attempt++) {
    const pass = { busy: 0, broken: 0 };
    last = pass;
    const answered = await v1Dispatch(env, ctx, job, pass);
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
  //
  // Which failure it was, in the terms a caller's retry policy needs. The
  // tallies were already kept to decide whether another pass was worth making;
  // this only stops them being thrown away once it is not.
  const cause = !scanWorkers(env, ctx.pin).length
    ? "no_workers"
    : !last?.busy
      ? "unreachable"
      : last.broken
        ? "mixed"
        : "saturated";
  logLine("v1_analyze", { src: "none", status: 200, unavailable: true, cause, ms: Date.now() - t0, ...ids });
  return new Response(`${JSON.stringify(v1Unavailable(null, locator, cause))}\n`, {
    status: 200,
    headers: { "content-type": "application/x-ndjson", "cache-control": "no-store" },
  });
}

// A request body, or null when it is larger than `max`.
//
// Checked as it arrives rather than after it is held. Reading the whole body
// first and measuring it afterwards let any caller make an isolate buffer as
// much as the platform would carry — far past the limit, and past the memory
// the isolate has — before being told no. A declared length over the limit is
// refused without reading at all; an undeclared or understated one is cut off
// at the first chunk that crosses it.
/**
 * @param {Request} request
 * @param {number} max - bytes
 * @returns {Promise<ArrayBuffer|null>} null when the body exceeds `max`
 */
async function readBounded(request, max) {
  const declared = Number(request.headers.get("content-length"));
  if (Number.isFinite(declared) && declared > max) return null;
  const reader = request.body.getReader();
  const chunks = [];
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > max) {
      await reader.cancel().catch(() => {});
      return null;
    }
    chunks.push(value);
  }
  const out = new Uint8Array(size);
  let at = 0;
  for (const chunk of chunks) {
    out.set(chunk, at);
    at += chunk.byteLength;
  }
  return out.buffer;
}

// One pass over the fleet. Returns the response, or null when every worker
// refused and the pass is worth making again.
/**
 * @param {Record<string, unknown>} env
 * @param {Ctx} ctx
 * @param {Job} job
 * @param {Pass} pass - filled in as the fleet is walked
 * @returns {Promise<Response|null>} null when every worker refused and the
 *   pass is worth making again
 */
async function v1Dispatch(env, ctx, job, pass) {
  const { url, locator, path, budget, busy, ids, t0, bytes, cacheFollow, full, sizeHint } = job;
  const workers = scanWorkers(env, ctx.pin);
  const hint = v1Hint(locator, bytes, sizeHint);
  let ranked = workers.length ? await rankWorkers(env, ctx, workers, ids, hint) : [];
  if (busy) {
    // A preference, not a pin: a worker whose breaker is open is not in the
    // pool at all, and a run we cannot reach is not worth waiting for.
    const home = ranked.filter((base) => hostOf(base) === busy);
    if (home.length) ranked = [...home, ...ranked.filter((base) => hostOf(base) !== busy)];
  }
  for (const base of ranked) {
    const worker = hostOf(base);
    lastDispatch.set(base, Date.now());
    noteDispatch(base);
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
      await drain(upstream);
      logLine("v1_analyze", { src: "scan", status: 429, worker, busy: true, ...ids });
      continue;
    }
    if (upstream.status >= 500) {
      if (pass) pass.broken += 1;
      breakerFor(base).fail();
      await drain(upstream);
      logLine("v1_analyze", { src: "scan", status: upstream.status, worker, retry: true, ...ids });
      continue;
    }
    // As on the lookup: a 404 means this worker has no such route, not that the
    // request was wrong. Counted against it so a partial rollout converges on
    // the workers that can serve.
    if (upstream.status === 404) {
      if (pass) pass.broken += 1;
      breakerFor(base).fail();
      await drain(upstream);
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
          waitUntil(ctx, cacheV1Decision(env, ctx, url.origin, locator, decided, storedFollow, canonicalPurl, full));
        }
      : null;
    const streamed = new Headers({
      "content-type": "application/x-ndjson",
      "cache-control": "no-store",
      "X-Beamline-Worker": worker,
    });
    setSource(streamed, source);
    // What the run cost, filed when the assessment goes out rather than now.
    // Called once — the stream registers the first terminal decision and
    // ignores anything after it.
    const settled = ({ finisher, orphaned }) => {
      const took = Date.now() - t0;
      // Credited to whoever produced the decision. After a handover that is not
      // the worker named in the response headers — those went out minutes ago
      // and cannot be corrected — and crediting them would put a stranded run
      // on the record of the box that rescued it. The breaker beside this call
      // already charges the finisher; this is the same rule for the same event.
      const credited = new Headers(streamed);
      if (finisher) credited.set("X-Beamline-Worker", finisher);
      // An abandoned run is filed apart. Its analysis really did take this long
      // and is worth keeping, but nobody was waiting at the end of it, and
      // ROUTE_VERDICT answers "how long until the caller had an answer". Orphans
      // are the longest runs there are — they are the ones whose caller gave up
      // — so folding them in would bias exactly the tail that gets read.
      writePoint(env, orphaned ? ROUTE_ORPHAN : ROUTE_VERDICT, credited, ecosystemOf(url), 200, took, ctx.org?.oid);
      // Also a log line, because Workers Logs is the other place these are read
      // and it indexes the fields it is given. Same numbers, same names.
      logLine("v1_analyze_verdict", {
        src: source,
        worker: finisher || worker,
        orphaned: orphaned || undefined,
        ms: took,
        ...ids,
      });
    };
    return new Response(
      annotatedV1Stream(
        upstream.body,
        budget,
        { requestId: ctx.rid, locator, startedAt: t0, ids, settled, full },
        cacheDecision,
        // Only the analyze path resumes. It is the only one that holds a stream
        // long enough for its worker to be taken away mid-answer — a lookup is
        // over in milliseconds, and a failed one is simply retried.
        {
          base,
          resume: (tried) => v1Resume(env, ctx, job, tried),
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
/**
 * @param {Record<string, unknown>} env
 * @param {Ctx} ctx
 * @param {Job} job
 * @param {Set<string>} tried - workers this stream has already been on
 * @returns {Promise<{body: ReadableStream, base: string}|null>}
 */
async function v1Resume(env, ctx, job, tried) {
  const { path, bytes, ids, locator, sizeHint } = job;
  // An aborted request has nobody left to finish the analysis for, and every
  // fetch below would be made with a signal that is already tripped.
  if (clientAborted(ctx)) return null;
  const workers = scanWorkers(env, ctx.pin);
  if (!workers.length) return null;
  const hint = v1Hint(locator, bytes, sizeHint);
  const [ranked, busy] = await Promise.all([
    rankWorkers(env, ctx, workers, ids, hint),
    locator ? runningWorker(env, ctx, locator, ids) : null,
  ]);
  const order = [
    ...ranked.filter((base) => busy && hostOf(base) === busy),
    ...ranked.filter((base) => (!busy || hostOf(base) !== busy) && !tried.has(base)),
    ...ranked.filter((base) => (!busy || hostOf(base) !== busy) && tried.has(base)),
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
      // As on the lookup: a caller's abort is not the worker's failure.
      if (clientAborted(ctx)) return null;
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
    if (worker !== busy) noteDispatch(base);
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
/**
 * @param {Record<string, unknown>} env
 * @param {Ctx} ctx
 * @param {string} origin
 * @param {Locator|null} locator
 * @param {string} decided - the terminal frame, as scan sent it
 * @param {string} follow - the policy that produced it
 * @param {string|null} canonicalPurl
 * @param {boolean} [full=false]
 * @returns {Promise<void>}
 */
async function cacheV1Decision(env, ctx, origin, locator, decided, follow, canonicalPurl, full = false) {
  const ids = v1LocatorIds(ctx.rid, null, locator ? [locator] : []);
  const document = v1DocumentBody(decided, full);
  if (!document) {
    logLine("v1_cache_write", { stored: false, reason: "invalid_decision", ...ids });
    return;
  }
  const maxAge = v1MaxAge(env, document);
  if (!maxAge) {
    logLine("v1_cache_write", { stored: false, reason: "uncacheable", ...ids });
    return;
  }
  const cache = await getCache(env);
  const requestedPath = v1CachePath(null, locator ? [locator] : [], follow, full);
  const keys = await cacheV1Aliases(env, cache, origin, requestedPath, locator, document, follow, canonicalPurl, full);
  logLine("v1_cache_write", { stored: true, follow, full: full || undefined, max_age: maxAge, keys, ...ids });
}

// Add phase telemetry to the progress stream without changing the cached
// decision. Scan's older progress frames only carried a nullable phase and a
// total elapsed time, which made a missing phase indistinguishable from a
// stalled run. The Worker owns the request clock, so it can also correlate the
// frames without asking every scan version to learn a new wire format first.
//
// `resume` makes the stream survive losing its worker. It carries the base URL
// the stream starts on (read, never written), how long silence may last
// before that worker is taken for gone, how many handovers are allowed, and a
// callback that produces a replacement body. Omitted, the stream behaves as it
// always did.
/**
 * @param {ReadableStream} stream - the worker's NDJSON
 * @param {number} budget - false_positive_budget, applied to each decision
 * @param {StreamMeta} meta
 * @param {((decision: string) => void)|null} [onDecision] - fires once, on the
 *   terminal frame, before the caller can cancel
 * @param {{base: string, resume: (tried: Set<string>) => Promise<{body: ReadableStream, base: string}|null>,
 *          idleMs: number, stallMs: number, limit: number}|null} [resume]
 *   omitted, the stream behaves as it did before handovers existed
 * @param {{register: (p: Promise<unknown>) => void, budgetMs: number}|null} [orphan]
 *   omitted, a stream the caller abandons is simply dropped
 * @returns {ReadableStream}
 */
function annotatedV1Stream(stream, budget, meta, onDecision = null, resume = null, orphan = null) {
  const encoder = new TextEncoder();
  let decoder = new TextDecoder();
  let reader = stream.getReader();
  let buffered = "";
  let decisionSeen = false;
  // Set once the caller has gone and the stream is being read for the decision
  // alone. Carried into the telemetry so an abandoned run is not counted as one
  // somebody waited for.
  let abandoned = false;
  let refused = false;
  let finished = false;
  let handovers = 0;
  let refusals = 0;
  // Every worker this request has already been on. A resume goes to the rest
  // first: two workers refusing in turn used to bounce the request between
  // them while a third with room was never asked.
  const tried = new Set();
  // The worker serving the stream now. Starts as the one dispatched to and moves
  // with each handover; kept here rather than written back into `resume`, which
  // belongs to the caller.
  let serving = resume?.base ?? null;
  // A read that outlived its stall timer. Kept, not dropped: when the stream
  // is read on rather than handed over, the frame it delivers still counts.
  let inflight = null;
  const queued = [];
  // `floor` keeps elapsed times monotonic across a handover: a replacement
  // worker counts from its own zero, and the caller must never watch the run
  // travel backwards.
  const phase = { name: null, startedElapsed: 0, lastElapsed: 0, floor: 0, changedAt: Date.now() };

  const encodeLine = (line) => {
    const annotated = annotatedV1Lines(line, budget, meta, phase);
    if (annotated.refused) refused = true;
    // A decision is terminal by contract. Register its short cache write as
    // soon as we observe it: callers are entitled to stop reading immediately
    // after this line and may cancel the stream before an EOF-driven flush.
    if (annotated.decision && !decisionSeen) {
      decisionSeen = true;
      // The worker finished what it took on. Charged to whoever is serving the
      // stream now, which after a handover is not who started it.
      if (serving) breakerFor(serving).ok();
      // How long the caller waited for an answer, as against the headers this
      // response opened with minutes ago. Telemetry must never take a stream
      // down with it, so it is guarded like the logging around it.
      try {
        meta.settled?.({ finisher: serving ? hostOf(serving) : null, orphaned: abandoned });
      } catch (err) {
        logLine("v1_analyze_verdict", { recorded: false, err: errText(err), ...meta.ids });
      }
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
    const pending = inflight ?? reader.read();
    inflight = null;
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
    } catch (err) {
      if (err?.message === why) inflight = pending;
      throw err;
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
    // it failed every caller. A refusal is the exception: the worker answered
    // promptly and correctly that it had no room for this one.
    // A stalled stream is still talking, so its worker is alive too.
    if (why !== "refused" && why !== "stalled") breakerFor(serving).fail();
    // Refusals have their own budget. One costs milliseconds and says nothing
    // about the request, and three of them spending the handovers left an
    // 11-minute analysis on the fourth worker to be cut at its first stall.
    const used = why === "refused" ? refusals : handovers;
    const limit = why === "refused" ? MAX_STREAM_REFUSALS : resume.limit;
    const spent = used >= limit;
    logLine("v1_analyze_stream", {
      worker: hostOf(serving),
      why,
      handover: spent ? undefined : used + 1,
      exhausted: spent || undefined,
      ...meta.ids,
    });
    if (spent) return false;
    if (why === "refused") refusals += 1;
    else handovers += 1;
    tried.add(serving);
    try {
      await reader.cancel();
    } catch {
      // Already dead: cancelling is a courtesy to a live worker, not a step.
    }
    const next = await resume.resume(tried);
    if (!next) return false;
    reader = next.body.getReader();
    inflight = null;
    serving = next.base;
    // The dead worker's trailing bytes are half a frame, not a frame, and its
    // clock is not the replacement's.
    decoder = new TextDecoder();
    buffered = "";
    refused = false;
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
    abandoned = true;
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
          // Stalled is not silent: frames still arrive, only the phase has not
          // changed. A whale spends longer than that in one phase (an
          // 11-minute `archive:whl` on rdu2 was cut this way, 2026-09-06),
          // so with no handover left the stream is read on and asked again
          // after another stall interval.
          if (why === "stalled" && (!resume || handovers >= resume.limit)) {
            phase.changedAt = Date.now();
            logLine("v1_analyze_stream", { worker: serving ? hostOf(serving) : undefined, why, kept: true, ...meta.ids });
            continue;
          }
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
          if (!decisionSeen && (await handover(refused ? "refused" : "eof"))) continue;
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

/**
 * @param {string} line - one NDJSON frame, without its newline
 * @param {number} budget
 * @param {StreamMeta} meta
 * @param {Phase} phase - advanced in place
 * @returns {{lines: string[], decision: string|null, refused?: boolean}}
 */
function annotatedV1Lines(line, budget, meta, phase) {
  const row = parseJson(line);
  // Not a frame we can read: pass it through as it arrived. budgetedV1Line
  // leaves anything it cannot parse alone, so text that is not JSON at all and
  // JSON that is not an object take the same road out.
  if (!row || typeof row !== "object" || Array.isArray(row)) {
    return { lines: [budgetedV1Line(line, budget, meta.locator)], decision: null };
  }

  // A worker's own clock for this frame, when it sent a usable one.
  const sent = Number(row.elapsed_ms);
  const reported = Number.isFinite(sent) && sent >= 0 ? sent : null;
  const totalElapsed = reported == null ? phase.lastElapsed : reported + phase.floor;
  if (Number.isFinite(totalElapsed)) phase.lastElapsed = totalElapsed;

  // A decision is the terminal event. Close the last reported phase in its own
  // frame so clients never have to infer completion from the decision shape.
  if (Object.prototype.hasOwnProperty.call(row, "decision") || (meta.full && isFullEnvelope(row))) {
    const done = phaseCompletion(meta, phase);
    return {
      lines: [...(done ? [JSON.stringify(done)] : []), budgetedV1Line(line, budget, meta.locator)],
      decision: line,
    };
  }

  if (row.state !== "analyzing") {
    // A worker that took the request and then found every big-analysis slot
    // busy says so and closes without a decision. Not a fault: it answered
    // promptly and correctly, and the caller belongs on a worker with room.
    return { lines: [budgetedV1Line(line, budget, meta.locator)], decision: null, refused: row.state === "refused" };
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

/**
 * @param {object} row - the worker's frame, carried through
 * @param {StreamMeta} meta
 * @param {Phase} phase
 * @param {"started"|"running"|"completed"} state
 * @param {number} elapsed
 * @returns {object}
 */
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

/**
 * Close the phase in flight, and clear it. Null when none was open.
 * @param {StreamMeta} meta
 * @param {Phase} phase - cleared in place
 * @param {number} [elapsed]
 * @returns {object|null}
 */
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

/**
 * @param {string} line
 * @param {number} budget
 * @param {Locator|null} locator
 * @returns {string}
 */
function budgetedV1Line(line, budget, locator) {
  if (!line.includes('"decision"')) return line;
  const body = v1BudgetedBody(line, budget, locator);
  return body || line;
}

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
/**
 * @param {Record<string, unknown>} env
 * @param {Ctx} ctx
 * @param {Locator} input
 * @param {Ids} ids
 * @returns {Promise<string|null>} the host already analyzing this, if any
 */
async function runningWorker(env, ctx, input, ids) {
  const workers = scanWorkers(env, ctx.pin);
  const keys = [];
  if (input.sha) keys.push(`sha256=${input.sha}`);
  if (input.type && input.value) keys.push(`${input.type}=${encodeURIComponent(input.value)}`);
  if (!workers.length || !keys.length) return null;
  const path = `/status?${keys.join("&")}`;
  const asked = await Promise.all(workers.map((base) => statusAsk(env, ctx, path, base)));
  const busy = asked.find((answer) => answer?.state === "running");
  if (busy) {
    logLine("scan_affinity", { worker: busy.worker, elapsed_ms: busy.elapsed_ms, ...ids });
  }
  return busy?.worker || null;
}

/**
 * @param {Record<string, unknown>} env
 * @param {Ctx} ctx
 * @param {string} path
 * @param {string} base
 * @returns {Promise<{worker: string, state: string, elapsed_ms: number}|null>}
 *   never rejects
 */
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
//
// The server's own term is analyses in flight over *cores*, not over slots.
// Slots are sized at three per core, so `in_flight / slots` said a four-core
// box with three analyses running was a quarter busy when every core it had
// was spoken for. Measured at concurrency 8 (2026-09-05): that box won 80% of
// the fleet's dispatches on the strength of its small-package averages, then
// saturated and was excluded, while a 128-core box took 11%. A worker too old
// to report its cores is measured against its slots, as before.
//
// The host term is foreground pressure — machine busy less the cores its pull
// worker holds — because that work leaves when a request lands, and ranking
// on it penalized the two biggest boxes for load that would not be there.
//
// `pending` is what this isolate has sent the worker since those stats were
// polled. Stats are cached for STATS_TTL_MS, and inside that window a worker's
// `in_flight` never moves, so every dispatch in the window went to whichever
// worker looked emptiest at the poll: run 5 (2026-09-06, concurrency 8) sent
// them in runs of four and five and stacked three big wheels on a 4-core box
// in two minutes. Counting our own dispatches is what the next poll will show.
/**
 * @param {ScanStats|null} stats
 * @param {number} [pending=0] - dispatches since those stats were polled
 * @returns {number} busy in units of the worker's own capacity, 0 when unknown
 */
function occupancy(stats, pending = 0) {
  const slots = Number(stats?.slots);
  if (!Number.isFinite(slots) || slots <= 0) return 0;
  const reported = Number(stats.in_flight ?? slots - (stats.slots_free ?? slots));
  const running = (Number.isFinite(reported) ? Math.max(0, reported) : 0) + Math.max(0, pending);
  const cpus = Number(stats.physical_cpus);
  const denominator = Number.isFinite(cpus) && cpus > 0 ? cpus : slots;
  const mine = running / denominator;
  return Math.max(mine, foregroundPressure(stats));
}

// Foreground busy threads per physical core above which a worker is not
// offered work at all. Below it the same number is a ranking penalty (see
// `occupancy`); at 1 every core already has a runnable thread that will not
// yield, and a new analysis can only wait.
//
// `physical_cpus` rather than the logical count `/_/info` reports: slots are
// sized on physical cores, and using logical would halve the apparent pressure
// on any host with SMT — which is every host where this matters most. A worker
// too old to report it contributes no host term rather than a guess.
const HOST_PRESSURE_LIMIT = 1;

// How much of the machine is working, in cores. `cpu_busy_cores` when scan
// reports it: the kernel's own CPU counters over the last poll interval, which
// mean the same thing on every host. `load1` otherwise, which does not — Linux
// counts threads blocked on disk in it and FreeBSD counts only runnable ones,
// so before this field existed the Linux servers read busier than the FreeBSD
// one for the same work and were the first excluded on every I/O burst.
// Both are thread counts against physical cores, deliberately: SMT siblings
// add contention, not capacity, once every core is fed.
/**
 * @param {ScanStats|null} stats
 * @returns {number} cores working, from cpu_busy_cores or load1
 */
function machineBusy(stats) {
  // `null` is scan saying "not yet" (one poll old, or no counters here) and
  // must not read as zero busy cores: Number(null) is 0.
  const raw = stats?.cpu_busy_cores;
  const measured = raw == null ? Number.NaN : Number(raw);
  if (Number.isFinite(measured) && measured >= 0) return measured;
  const load = Number(stats?.load1);
  return Number.isFinite(load) ? load : 0;
}

// The load a new analysis would actually queue behind: the machine's, less
// the cores the server says its pull worker holds (`background_in_flight`).
// That number is bounded by the pull worker's core budget, which is what
// makes subtracting it safe: it can never exceed what is sheddable, and the
// remainder is work that stays when a request lands. A server too old to
// report the field is judged on the whole load, as before.
/**
 * @param {ScanStats|null} stats
 * @returns {number} load per core that stays when a request lands, 0 when
 *   the worker is too old to report its cores
 */
function foregroundPressure(stats) {
  const cpus = Number(stats?.physical_cpus);
  if (!Number.isFinite(cpus) || cpus <= 0) return 0;
  const busy = machineBusy(stats);
  if (!Number.isFinite(busy) || busy <= 0) return 0;
  const background = Math.max(0, Number(stats.background_in_flight) || 0);
  return Math.max(0, busy - background) / cpus;
}
// When a routable worker has received nothing from this isolate for this long,
// it is offered the next dispatch regardless of its rank: one request, to
// give it a sample its own history can be repaired from.
//
// A worker that has been excluded for a while carries the averages of that
// period into the hour after it, ranks last on them, and — with no
// exploration by design — never receives the request that would correct them.
// Measured 2026-09-05: a 16-core server with sixteen free permits took zero of
// 128 analyses at concurrency 8, predicted at 150s from a window spent starved.
// This is exploration tied to starvation, not to a coin: a worker that is
// being used needs none, and one that is not gets exactly one request per
// isolate per five minutes, which is the cheapest evidence there is.
const STARVE_PROBE_MS = 300_000;
const lastDispatch = new Map();
const isolateBorn = Date.now();

// Index into `pool` of the worker to probe, or -1. Never the favourite (it is
// being used), never a worker with no free slot (the probe would be refused),
// and never one this isolate has dispatched to inside the window. `ages` is
// milliseconds since each pool entry was last dispatched to; a worker never
// dispatched to counts from the isolate's birth, so a cold isolate probes
// nobody for its first five minutes rather than everybody at once.
/**
 * @param {RankedWorker[]} pool - favourite first; index 0 is never probed
 * @param {number[]} ages - milliseconds since each entry was dispatched to
 * @returns {number} index into `pool`, or -1
 */
function probeIndex(pool, ages) {
  for (let i = 1; i < pool.length; i++) {
    const candidate = pool[i];
    if (candidate.stats == null) continue;
    if ((candidate.stats.slots_free ?? 1) <= 0) continue;
    if (ages[i] >= STARVE_PROBE_MS) return i;
  }
  return -1;
}

// The estimate a starved worker competes with: its own, unless that is worse
// than the fleet's median, in which case the median. Pure; rankPool applies
// it to workers past STARVE_PROBE_MS.
/**
 * @param {number} own - the starved worker's own estimate
 * @param {number[]} fleetEsts - every estimate we have evidence for
 * @returns {number} the lower of `own` and the fleet median
 */
function starvedEstimate(own, fleetEsts) {
  const known = [...fleetEsts].sort((a, b) => a - b);
  if (known.length < 2) return own;
  return Math.min(own, known[Math.floor(known.length / 2)]);
}

/**
 * @param {string} base
 * @param {number} now
 * @returns {number} milliseconds since this isolate last dispatched to `base`
 */
function dispatchAge(base, now) {
  return now - (lastDispatch.get(base) ?? isolateBorn);
}

// Per-isolate stats cache. Isolates are recycled often, which is exactly why
// scan publishes its own history rather than beamline accumulating one: a cold
// isolate gets a warm estimate from the first poll instead of routing blind
// until it has seen enough traffic to learn.
const statsCache = new Map();
// Stats polls in flight, by worker, so concurrent misses share one.
const statsPolls = new Map();

// When this isolate last dispatched to each worker, newest last. Read by
// `pendingSince` for the occupancy term; see `occupancy`.
const dispatchLog = new Map();

/**
 * @param {string} base
 * @param {number} [now=Date.now()]
 * @returns {void}
 */
function noteDispatch(base, now = Date.now()) {
  const log = dispatchLog.get(base) ?? [];
  log.push(now);
  while (log.length && now - log[0] > STATS_TTL_MS) log.shift();
  dispatchLog.set(base, log);
}

// Dispatches to `base` since its stats were polled at `at`; those before it
// are already in the worker's own `in_flight`.
//
// `>=`, not `>`. `at` is stamped before the poll's own round trip, so a dispatch
// recorded in that same millisecond cannot have reached the worker in time to be
// counted in the `in_flight` it answered with. Under `>` it was counted by
// neither side, and the router read a worker as one slot emptier than it was —
// an undercount, which is the direction that sends more work to a box already
// holding some. The cost of being wrong the other way is one slot of caution.
/**
 * @param {string} base
 * @param {number|null} at - when the stats were polled
 * @param {number} [now]
 * @returns {number} dispatches this isolate made that the worker's own
 *   in_flight cannot yet have counted
 */
function pendingSince(base, at, now = Date.now()) {
  const log = dispatchLog.get(base);
  if (!log || at == null) return 0;
  return log.filter((sentAt) => sentAt >= at && now - sentAt <= STATS_TTL_MS).length;
}

// The size of a package, from its registry, before any worker is asked. pypi
// and npm say it in one small request each; cargo and golang do not, and get
// no hint. Cached by coordinate, since a published artifact never changes.
const sizeCache = new Map();
const SIZE_CACHE_MAX = 4096;
const SIZE_LOOKUP_MS = 1_500;

/**
 * @param {Record<string, unknown>} env
 * @param {Ctx} ctx
 * @param {string} purl
 * @param {Ids} ids
 * @returns {Promise<number|null>} bytes, or null where the registry will
 *   not say; never rejects
 */
async function registrySize(env, ctx, purl, ids) {
  const hit = sizeCache.get(purl);
  if (hit !== undefined) return hit;
  let size = null;
  try {
    size = await registrySizeOf(env, ctx, purl);
  } catch (err) {
    logLine("v1_size_hint", { purl, err: errText(err), ...ids });
  }
  if (sizeCache.size >= SIZE_CACHE_MAX) sizeCache.delete(sizeCache.keys().next().value);
  sizeCache.set(purl, size);
  if (size != null) logLine("v1_size_hint", { purl, bytes: size, ...ids });
  return size;
}

/**
 * @param {string} purl
 * @returns {{type: string, name: string, version: string}|null}
 */
function purlNameVersion(purl) {
  const rest = String(purl || "").replace(/^pkg:/i, "");
  const slash = rest.indexOf("/");
  const at = rest.lastIndexOf("@");
  if (slash < 0 || at <= slash + 1 || at === rest.length - 1) return null;
  try {
    return {
      type: rest.slice(0, slash).toLowerCase(),
      name: decodeURIComponent(rest.slice(slash + 1, at)),
      version: decodeURIComponent(rest.slice(at + 1)),
    };
  } catch {
    return null;
  }
}

/**
 * @param {Record<string, unknown>} env
 * @param {Ctx} ctx
 * @param {string} purl
 * @returns {Promise<number|null>} bytes, or null where the registry will not say
 */
async function registrySizeOf(env, ctx, purl) {
  const parts = purlNameVersion(purl);
  if (!parts) return null;
  const json = async (resp) => (resp.ok ? await resp.json() : (await drain(resp), null));
  if (parts.type === "pypi") {
    const base = (env.PYPI_URL || "https://pypi.org").replace(/\/$/, "");
    const doc = await fetchTimeout(
      `${base}/pypi/${encodeURIComponent(parts.name)}/${encodeURIComponent(parts.version)}/json`,
      { headers: { accept: "application/json" } },
      SIZE_LOOKUP_MS,
      ctx,
      json,
    );
    // The largest file of the release: which one the worker fetches is its
    // decision, and the routing question is only whether this is a whale.
    const sizes = (doc?.urls || []).map((file) => Number(file?.size)).filter((size) => Number.isFinite(size) && size > 0);
    return sizes.length ? Math.max(...sizes) : null;
  }
  if (parts.type === "npm") {
    const base = (env.NPM_REGISTRY_URL || "https://registry.npmjs.org").replace(/\/$/, "");
    // The name is the caller's text, decoded, and is about to become a path.
    // Only the two shapes npm allows get that far — `name` and `@scope/name` —
    // and each segment is encoded, so a `..`, a `?` or a `#` cannot walk the
    // request somewhere on the registry the caller chose instead.
    const segments = parts.name.split("/");
    const shaped = segments.length === 1 || (segments.length === 2 && segments[0].startsWith("@"));
    if (!shaped || segments.some((segment) => !segment || segment === "." || segment === ".." || segment === "@")) return null;
    const name = segments.map((segment) => encodeURIComponent(segment).replace(/^%40/, "@")).join("/");
    const doc = await fetchTimeout(
      `${base}/${name}/${encodeURIComponent(parts.version)}`,
      { headers: { accept: "application/json" } },
      SIZE_LOOKUP_MS,
      ctx,
      json,
    );
    const tarball = doc?.dist?.tarball;
    if (typeof tarball !== "string" || !tarball) return null;
    // A publisher writes this field, so it is an address somebody else chose.
    // Followed only back to the registry it came from: a size hint is not worth
    // letting a package aim this Worker at an arbitrary host. One that does not
    // parse throws, and registrySize files that as no hint.
    if (new URL(tarball).origin !== new URL(base).origin) return null;
    // The packument's `unpackedSize` is the tree, not the tarball the worker
    // downloads; a HEAD on the tarball is the number the worker's lanes use.
    const length = await fetchTimeout(tarball, { method: "HEAD" }, SIZE_LOOKUP_MS, ctx, async (resp) => {
      await drain(resp);
      return resp.ok ? Number(resp.headers.get("content-length")) : Number.NaN;
    });
    return Number.isFinite(length) && length > 0 ? length : null;
  }
  return null;
}

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
/**
 * @param {string} purl
 * @returns {string}
 */
function purlType(purl) {
  const rest = String(purl || "").replace(/^pkg:/i, "");
  const ty = rest.split("/")[0].toLowerCase();
  return PURL_TYPES.has(ty) ? ty : "other";
}

/**
 * @param {number} bytes
 * @returns {string} one of SIZE_BUCKETS' names
 */
function sizeBucket(bytes) {
  for (const [name, bound] of SIZE_BUCKETS) {
    if (bytes <= bound) return name;
  }
  return "gt_128mb";
}

// One worker's /_/stats, cached. Never throws: a worker that cannot be polled
// is routed on no evidence rather than excluded, because "I could not ask" is
// not the same as "it is unhealthy" — the circuit breaker already owns that.

/**
 * @param {Record<string, unknown>} env
 * @param {Ctx} ctx
 * @param {string} base
 * @returns {Promise<ScanStats|null>} null means asked and unanswered, which
 *   is not the same as unhealthy
 */
async function scanStats(env, ctx, base) {
  const now = Date.now();
  const hit = statsCache.get(base);
  if (hit && now - hit.at < STATS_TTL_MS) return hit.stats;
  // One poll per worker at a time. A cold isolate takes a burst of requests
  // that all find the cache empty, and each used to poll every worker itself:
  // the same answer bought once per request, from the workers least able to
  // spare it when the burst is load.
  const pending = statsPolls.get(base);
  if (pending) return pending;
  const poll = (async () => {
    let stats = null;
    try {
      stats = await fetchTimeout(
        `${base}/_/stats`,
        { method: "GET", headers: scanHeaders(env, ctx) },
        STATS_TIMEOUT_MS,
        // Deliberately not ctx: a caller hanging up should not poison the cache
        // for every later request in this isolate.
        null,
        async (resp) => {
          if (resp.ok) return resp.json();
          await drain(resp);
          logLine("scan_stats", { worker: hostOf(base), status: resp.status });
          return null;
        },
      );
    } catch (err) {
      logLine("scan_stats", { worker: hostOf(base), err: errText(err) });
    }
    statsCache.set(base, { at: now, stats });
    statsPolls.delete(base);
    return stats;
  })();
  statsPolls.set(base, poll);
  return poll;
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
/**
 * @param {ScanStats|null} stats
 * @param {Hint|null} hint - null when the request named no cost class
 * @param {Map<string, number>|null} mix - the fleet's job distribution
 * @param {number} [pending=0]
 * @returns {number} milliseconds
 */
function predictMs(stats, hint, mix, pending = 0) {
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
  return base * whaleSlowdown(stats, hint) * (1 + CAPACITY_WEIGHT * occupancy(stats, pending));
}

// scan runs a big analysis on a private pool of `physical_cpus / 4` threads,
// 2 to 16, so the same wheel takes several times longer on a 4-core box than
// on a 128-core one. Ranked on that ratio when the size is known, so whales
// go where the threads are; the same box's own by-size average says the same
// thing once it has enough samples, and this says it from the first one.
const BIG_JOB_BYTES = 8 << 20;
const WHALE_THREADS_MAX = 16;

/**
 * @param {ScanStats|null} stats
 * @param {Hint|null} hint
 * @returns {number} 1 when the artifact is not a whale, else the ratio of
 *   the largest whale pool to this worker's
 */
function whaleSlowdown(stats, hint) {
  if (!(hint?.bytes > BIG_JOB_BYTES)) return 1;
  const cpus = Number(stats?.physical_cpus);
  // A worker too old to report its cores is assumed to have the whole pool,
  // which costs it no penalty rather than inventing one for it.
  if (!Number.isFinite(cpus) || cpus <= 0) return 1;
  return WHALE_THREADS_MAX / Math.min(WHALE_THREADS_MAX, Math.max(2, Math.floor(cpus / 4)));
}

// The routing hint for one request: the package it names and, when known
// before dispatch, how big it is.
/**
 * @param {Locator|null} locator
 * @param {ArrayBuffer|null} bytes
 * @param {number|null} sizeHint
 * @returns {Hint}
 */
function v1Hint(locator, bytes, sizeHint) {
  const hint = locator?.type === "purl" ? { purl: locator.value } : {};
  if (bytes) hint.upload = true;
  if (sizeHint != null) hint.bytes = sizeHint;
  return hint;
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
/**
 * @param {ScanStats|null} stats
 * @returns {number|null} milliseconds, or null with nothing measured
 */
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

/**
 * @param {ScanStats} stats
 * @param {Hint|null} hint
 * @returns {number|null} milliseconds, or null where this worker has never
 *   done one of these
 */
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
/**
 * @param {Bucket|null|undefined} bucket
 * @returns {number|null}
 */
function bucketMs(bucket) {
  if (!bucket) return null;
  const windowed = recentMs(bucket.recent);
  if (windowed != null) return windowed;
  // The lifetime mean, for a worker that has not been upgraded to publish a
  // window yet. Same sample floor: one job is a story, not a statistic.
  if (emptyWindow(bucket.recent) || bucket.avg_ms == null) return null;
  if (bucket.jobs != null && bucket.jobs < MIN_CLASS_SAMPLES) return null;
  return bucket.avg_ms;
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
/**
 * @param {{samples?: number}|null|undefined} recent
 * @returns {boolean} true only for a window that exists and holds nothing
 */
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
/**
 * @param {{p80_ms?: number, samples?: number}|null|undefined} recent
 * @returns {number|null}
 */
function recentMs(recent) {
  if (!recent || recent.p80_ms == null) return null;
  if (recent.samples != null && recent.samples < MIN_CLASS_SAMPLES) return null;
  return recent.p80_ms;
}

// The worker's blended average, if it rests on enough completions to mean
// something. Same threshold, same reason.
/**
 * @param {ScanStats} stats
 * @returns {number|null}
 */
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
/**
 * @param {ScanStats} stats
 * @param {Map<string, number>|null} mix
 * @returns {number|null}
 */
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
/**
 * @param {(ScanStats|null)[]} all
 * @returns {Map<string, number>|null} size bucket to completion count
 */
function jobMix(all) {
  const mix = new Map();
  for (const stats of all) {
    for (const [name, bucket] of Object.entries(stats?.avg_job_ms_by_size || {})) {
      if (bucket?.avg_ms != null && bucket.jobs) mix.set(name, (mix.get(name) || 0) + bucket.jobs);
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
/**
 * @param {ScanStats|null} stats
 * @param {Hint|null} hint
 * @param {Map<string, number>|null} mix
 * @returns {boolean}
 */
function hasHistory(stats, hint, mix) {
  if (!stats) return false;
  // A lookup estimate is trusted for tie-breaking only once it rests on enough
  // samples, as opposed to merely being the best number available.
  if (hint?.lookup) {
    return recentMs(stats.recent_lookup) != null || (stats.lookup_samples != null && stats.lookup_samples >= MIN_CLASS_SAMPLES);
  }
  if (classMs(stats, hint) != null) return true;
  if (hint == null && mixedMs(stats, mix) != null) return true;
  return blendedMs(stats) != null;
}

// Can this worker answer *correctly*, never mind quickly?
//
// These are not preferences. A worker missing 7z returns a weaker verdict on a
// DMG rather than a slower one — and being weaker, it is also faster, so a
// purely latency-ranked router would actively prefer it.
/**
 * @param {ScanStats|null} stats
 * @param {number|null} sizeHint
 * @param {boolean} [upload=false] - whether the caller sent the bytes
 * @returns {string|null} why this worker cannot serve, or null if it can;
 *   null stats means unknown, which the breaker owns rather than this
 */
function capability(stats, sizeHint, upload = false) {
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
  // A big analysis needs one of the worker's whale slots; with every one
  // taken it refuses, so the refusal round trip is skipped here.
  if (sizeHint != null && sizeHint > BIG_JOB_BYTES) {
    const whale = stats.whale_slots;
    if (whale && Number(whale.max) > 0 && Number(whale.in_use) >= Number(whale.max)) return "whale slots full";
  }
  // `!= null`, not truthiness: a worker advertising 0 accepts nothing, and
  // reading that as "no limit" sends it exactly the bodies it will refuse.
  // Only for bytes the caller sends: a package the worker fetches for itself
  // never passes through the upload limit.
  if (upload && sizeHint != null && stats.max_upload_mb != null && sizeHint > stats.max_upload_mb * 1024 * 1024) {
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
/**
 * @param {number} left - milliseconds
 * @param {number} right - milliseconds
 * @returns {boolean}
 */
function tiedEst(left, right) {
  return Math.abs(left - right) < Math.min(TIE_CEILING_MS, TIE_FRACTION * Math.min(left, right));
}

// The stats we already hold for a worker, or undefined when we would have to
// go and ask. Distinct from null, which means we asked and it did not answer.
/**
 * @param {string} base
 * @returns {ScanStats|null|undefined} undefined when the reading is missing or stale
 */
function cachedStats(base) {
  const hit = statsCache.get(base);
  return hit && Date.now() - hit.at < STATS_TTL_MS ? hit.stats : undefined;
}

// Round-robin start, per isolate. Used only when there is nothing measured to
// rank on; the point is merely never to start at the same worker every time.
let lookupTurn = 0;
/**
 * @param {string[]} workers
 * @returns {string[]} a rotated copy
 */
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
/**
 * @param {RankedWorker[]} ranked
 * @returns {string[]} worker base URLs, best first
 */
function byEst(ranked) {
  return [...ranked]
    .sort((a, b) => {
      if (!tiedEst(a.est, b.est)) return a.est - b.est;
      if (a.known && b.known) return a.r - b.r;
      return a.i - b.i;
    })
    .map((worker) => worker.base);
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
/**
 * @param {Record<string, unknown>} env
 * @param {Ctx} ctx
 * @param {string[]} workers
 * @param {Ids} ids
 * @returns {Promise<string[]>} base URLs, best first
 */
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

/**
 * @param {Record<string, unknown>} env
 * @param {Ctx} ctx
 * @param {string[]} workers
 * @param {Hint|null} hint
 * @param {boolean} [probe=false] - allow a starved worker to be promoted
 * @returns {Promise<{pool: RankedWorker[], excluded: RankedWorker[],
 *   informed: boolean, probed: string|undefined, starved: string|undefined}>}
 */
async function rankPool(env, ctx, workers, hint, probe = false) {
  const polled = await Promise.all(
    workers.map(async (base, i) => ({ base, i, stats: await scanStats(env, ctx, base) })),
  );
  // One shared yardstick for the whole fleet, so it has to be built from every
  // worker's history before any single worker can be scored against it.
  const mix = jobMix(polled.map((worker) => worker.stats));
  const scored = polled.map(({ base, i, stats }) => ({
    base,
    stats,
    i,
    est: predictMs(stats, hint, mix, pendingSince(base, statsCache.get(base)?.at ?? null)),
    known: hasHistory(stats, hint, mix),
    why: capability(stats, hint?.bytes ?? null, hint?.upload === true),
    r: Math.random(),
  }));
  // A starved worker's own history is the wrong prior. It ranks on samples
  // from whatever period stopped it being used — an hour of saturation, an
  // exclusion — and with no requests arriving nothing replaces them; measured
  // 2026-09-05 a 128-core server that had just answered its one probe in 3s
  // was still estimated at 23-431s from the hour before and took 1% of a run.
  // So while it is starved its estimate is capped at the fleet's median: it
  // then competes as an ordinary worker, its real samples arrive, and the cap
  // stops applying the moment it is being used again.
  if (probe) {
    const now = Date.now();
    const known = scored.filter((worker) => worker.stats != null && worker.known).map((worker) => worker.est).sort((a, b) => a - b);
    if (known.length > 1) {
      for (const candidate of scored) {
        if (candidate.stats == null || dispatchAge(candidate.base, now) < STARVE_PROBE_MS) continue;
        const capped = starvedEstimate(candidate.est, known);
        if (capped < candidate.est) {
          candidate.est = capped;
          candidate.starved = true;
        }
      }
    }
  }
  const usable = scored.filter((worker) => worker.why == null);
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
  let probed;
  if (probe && pool.length > 1) {
    const now = Date.now();
    const promote = probeIndex(pool, pool.map((worker) => dispatchAge(worker.base, now)));
    if (promote > 0) {
      const [starving] = pool.splice(promote, 1);
      pool.unshift(starving);
      probed = hostOf(starving.base);
    }
  }
  const starved = scored.filter((worker) => worker.starved).map((worker) => hostOf(worker.base));
  return {
    pool,
    excluded: usable.length ? scored.filter((worker) => worker.why != null) : [],
    informed: pool[0].known,
    probed,
    starved: starved.length ? starved.join(",") : undefined,
  };
}

/**
 * @param {Record<string, unknown>} env
 * @param {Ctx} ctx
 * @param {string[]} workers
 * @param {Ids} ids
 * @param {Hint|null} hint
 * @returns {Promise<string[]>} base URLs, best first
 */
async function rankWorkers(env, ctx, workers, ids, hint) {
  const ranked = await rankPool(env, ctx, workers, hint, true);
  logLine("scan_route", {
    order: ranked.pool.map((worker) => hostOf(worker.base)).join(","),
    est_ms: ranked.pool.map((worker) => Math.round(worker.est)).join(","),
    excluded: ranked.excluded.length || undefined,
    informed: ranked.informed || undefined,
    probed: ranked.probed,
    starved: ranked.starved,
    size: hint?.bytes ?? undefined,
    type: hint?.purl ? purlType(hint.purl) : undefined,
    ...ids,
  });
  return ranked.pool.map((worker) => worker.base);
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
/**
 * @param {Record<string, unknown>} env
 * @param {Ctx} ctx
 * @param {URL} url
 * @returns {Promise<Response>}
 */
async function handleRoutes(env, ctx, url) {
  // Three ways to ask, matching the three ways a request arrives: by the PURL
  // itself, by a bare type, or by an upload size. With none of them, answer for
  // every class at once — which is the view that shows one worker leading on
  // npm and another on golang.
  const rawSize = (url.searchParams.get("size") || "").trim();
  const rawType = (url.searchParams.get("type") || "").trim();
  const rawPurl = (url.searchParams.get("purl") || "").trim();
  // Bytes, or a human size like "10mb".
  let size = null;
  if (rawSize && rawSize.toLowerCase() !== "none") {
    const match = /^(\d+(?:\.\d+)?)\s*(b|kb|mb|gb)?$/i.exec(rawSize);
    if (!match) return v1Error(400, "invalid_size", `Could not read ${rawSize} as a size.`);
    const scale = { b: 1, kb: 1 << 10, mb: 1 << 20, gb: 1 << 30 }[(match[2] || "b").toLowerCase()];
    size = Math.round(Number(match[1]) * scale);
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
      ...["npm", "pypi", "cargo", "golang"].map((type) => ({
        kind: "purl_type",
        name: type,
        hint: { purl: `pkg:${type}/x` },
      })),
      ...SIZE_BUCKETS.map(([name, bound]) => {
        const bytes = bound === Infinity ? (128 << 20) + 1 : bound;
        return { kind: "size", name, bytes, hint: { bytes } };
      }),
    ];
  }

  const routes = [];
  for (const costClass of classes) {
    if (!live.length) {
      routes.push({ class: costClass.name, kind: costClass.kind, dispatch: [], note: "every worker's breaker is open" });
      continue;
    }
    const ranked = await rankPool(env, ctx, live, costClass.hint);
    routes.push({
      class: costClass.name,
      kind: costClass.kind,
      size_bytes: costClass.bytes,
      informed: ranked.informed,
      // The order a dispatch would try, favourite first. One worker is asked at
      // a time and the next is reached only when the one before it refuses or
      // fails, so this is a queue rather than a set of arms.
      dispatch: ranked.pool.map((worker) => ({
        worker: hostOf(worker.base),
        est_ms: Math.round(worker.est),
      })),
      excluded: ranked.excluded.map((worker) => ({ worker: hostOf(worker.base), reason: worker.why })),
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

// Exponential with full jitter, capped: a burst of waiters on the same sample
// spreads out instead of retrying in lockstep.
/**
 * @param {number} base - milliseconds
 * @param {number} attempt - zero-based
 * @param {number} cap - milliseconds
 * @returns {number} milliseconds to wait
 */
function backoff(base, attempt, cap) {
  const ceiling = Math.min(base * 2 ** Math.min(attempt, 10), cap);
  return ceiling <= base ? base : base + Math.random() * (ceiling - base);
}

// What every outbound request to a scan worker carries. There is one backend,
// so there is one of these: the indirection this used to have existed for a
// second credential that no longer has a service behind it.
/**
 * @param {Record<string, unknown>} env
 * @param {Ctx} ctx
 * @returns {Record<string, string>}
 */
function scanHeaders(env, ctx) {
  const token = (env.SCAN_TOKEN || "").trim();
  const headers = { "x-request-id": ctx.rid };
  if (token) headers.authorization = `Bearer ${token}`;
  if (ctx.filename) headers["x-filename"] = ctx.filename;
  return headers;
}

// One coordinate, one spelling.
//
// The `pkg:` scheme is required by the PURL spec, and both it and the type are
// case-insensitive there — so `pypi/x@1`, `pkg:pypi/x@1` and `pkg:PyPI/x@1`
// name one artifact. Carried through as typed they were three cache entries:
// measured live, a bare-spelled lookup for a coordinate somebody had already
// asked prefixed missed L0 and KV both and paid a backend round trip for a
// verdict we were already holding. Everything else here has always read a PURL
// prefix-insensitively — purlNameVersion and purlType both strip it — so the
// caller's literal text was the one place a spelling could still fork.
//
// Only the parts the spec calls case-insensitive are folded. Namespace, name
// and version belong to the package manager, and folding those would merge
// coordinates that really are distinct.
//
// Applied where the locator is parsed rather than where the key is built, so
// the canonical spelling is also what reaches scan. A caller who writes `PKG:`
// gets an answer instead of the 400 the raw text used to earn, and the PURL
// echoed back is the canonical one rather than whatever they typed.
/**
 * @param {unknown} raw
 * @returns {string} the canonical spelling, or "" for nothing
 */
function normalizePurl(raw) {
  const value = String(raw || "").trim();
  if (!value) return "";
  const rest = value.replace(/^pkg:/i, "");
  const slash = rest.indexOf("/");
  // Not a coordinate this can canonicalize. Hand it on and let validation say so.
  if (slash < 1) return `pkg:${rest}`;
  return `pkg:${rest.slice(0, slash).toLowerCase()}${rest.slice(slash)}`;
}

// A PURL from a backend header, bounded before it can become a cache key.
// Length-capped and ASCII-only: a key is a URL we build, and an unbounded or
// unspellable one is either a request we cannot make or an entry nothing can
// read back. Must look like a PURL, so a confused worker cannot file an
// answer under something that is not a coordinate at all.
/**
 * @param {unknown} raw
 * @returns {string|null}
 */
function cleanPurl(raw) {
  const value = String(raw || "").trim();
  if (!value || value.length > 512) return null;
  if (!/^pkg:[a-zA-Z0-9.+-]+\/[\x21-\x7e]*$/.test(value)) return null;
  return value;
}

/**
 * @param {unknown} raw - comma-separated
 * @returns {string[]}
 */
function tokenList(raw) {
  return String(raw || "")
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}

/**
 * @param {Ctx|null} ctx
 * @returns {boolean}
 */
function clientAborted(ctx) {
  return !!(ctx && ctx.signal && ctx.signal.aborted);
}

// Constant-time for equal-length strings: a token check that returns early on
// the first wrong character tells an attacker how much of a prefix they have.
/**
 * @param {unknown} left
 * @param {unknown} right
 * @returns {boolean}
 */
function tokenEq(left, right) {
  if (typeof left !== "string" || typeof right !== "string" || left.length !== right.length) return false;
  let differing = 0;
  for (let i = 0; i < left.length; i++) differing |= left.charCodeAt(i) ^ right.charCodeAt(i);
  return differing === 0;
}

// What a v1 answer tells the caller about holding it.
//
// `private` on a deployment with a token, because this header travels: the
// caller's proxy and browser both read it, and a PURL is their dependency list.
// The copy we put in caches.default is marked separately and deliberately
// differently — see storedDocument.
//
// One rule, because it was two: this said `public` with no max-age for an
// uncacheable answer while `v1Body` said `no-store` for the same thing, and a
// bare `public` lets a shared cache keep — on its own heuristics — the one
// answer we meant nobody to keep. Unreachable today, since only a document that
// earned a TTL is ever in the cache to be re-served, which is exactly how two
// spellings of one rule survive long enough to diverge.
/**
 * @param {Record<string, unknown>} env
 * @param {number} maxAge - seconds; 0 is no-store
 * @returns {string} a Cache-Control value
 */
function clientScope(env, maxAge) {
  if (!maxAge) return "no-store";
  return `${(env.BEAMLINE_TOKEN || "").trim() ? "private" : "public"}, max-age=${maxAge}`;
}

/**
 * @param {object|null} envelope - a full scan report
 * @param {string|null} sha
 * @param {string|null} purl
 * @returns {object}
 */
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

/**
 * @param {unknown} llm
 * @returns {string}
 */
function llmWhy(llm) {
  if (!llm) return "";
  if (typeof llm === "string") return llm.trim();
  const text = llm.interpretation || llm.why || "";
  return typeof text === "string" ? text.trim() : "";
}

/**
 * @param {object|null} raw - the report's `raw` section
 * @param {string|null} purl
 * @returns {object[]} at most HIT_LIMIT, most critical first
 */
function topHits(raw, purl) {
  const files = (raw && (raw.files || raw.fs)) || [];
  const rows = [];
  const seen = new Set();
  for (const entry of files) {
    const traits = (entry && (entry.traits || entry.findings)) || [];
    const file = hitFile(entry && entry.path);
    const ident = identPkg(entry);
    for (const trait of traits) {
      const crit = Number(trait && trait.crit);
      const id = trait && trait.id;
      if (!id || !Number.isFinite(crit) || crit < HIT_MIN_CRIT) continue;
      // Native matches only. A finding with `from` is the same match reported
      // again on an enclosing archive — the member's own copy carries the real
      // path and offset, and we walk every file — or a cross-file composite,
      // which has no single place to point at.
      if (Array.isArray(trait.from) && trait.from.length) continue;
      const pkg = (trait.dep && trait.dep.locator) || purl || ident || "";
      const key = `${id}\0${file}\0${pkg}`;
      if (seen.has(key)) continue;
      seen.add(key);
      const hit = { id, crit };
      if (trait.desc) hit.desc = trait.desc;
      if (file) hit.file = file;
      if (pkg) hit.pkg = pkg;
      const at = hitLocation(entry, id, trait);
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
/**
 * @param {object|null} file
 * @param {string} id
 * @param {object|null} trait
 * @returns {{off: number|null, line: number|null}}
 */
function hitLocation(file, id, trait) {
  for (const context of (file && file.ctx) || []) {
    for (const note of (context && context.n) || []) {
      if (note && note.i === id) {
        return { off: num(note.o), line: num(context.line) };
      }
    }
  }
  const span = trait && Array.isArray(trait.spans) && trait.spans[0];
  return { off: Array.isArray(span) ? num(span[0]) : null, line: null };
}

/**
 * @param {unknown} value
 * @returns {number|null}
 */
function num(value) {
  return Number.isFinite(Number(value)) ? Number(value) : null;
}

/**
 * @param {unknown} path
 * @returns {string} the innermost member's path
 */
function hitFile(path) {
  if (!path) return "";
  let inner = String(path);
  if (inner.includes("!!")) inner = inner.split("!!").pop();
  else if (inner.includes("!")) inner = inner.split("!").pop();
  return inner.replace(/^\/+/, "") || "";
}

/**
 * @param {object|null} file
 * @returns {string} `name@version`, or ""
 */
function identPkg(file) {
  const ident = (file && (file.ident || file.identity)) || {};
  if (!ident.name) return "";
  return ident.version ? `${ident.name}@${ident.version}` : ident.name;
}
/**
 * @param {object|null} body
 * @returns {string} lowercase, or ""
 */
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
/**
 * @template T
 * @param {string} url
 * @param {RequestInit} opts
 * @param {number} ms
 * @param {Ctx|null} ctx - null opts out of the caller's abort
 * @param {(resp: Response) => Promise<T>} read - runs inside the timeout;
 *   nothing may touch the Response after this returns
 * @returns {Promise<T>}
 */
async function fetchTimeout(url, opts, ms, ctx, read) {
  const controller = new AbortController();
  const outer = ctx && ctx.signal;
  if (outer && outer.aborted) {
    throw new DOMException("Aborted", "AbortError");
  }
  const onAbort = () => controller.abort();
  if (outer) outer.addEventListener("abort", onAbort, { once: true });
  const timer = setTimeout(() => controller.abort(), ms);
  try {
    return await read(await fetch(url, { ...opts, signal: controller.signal }));
  } finally {
    clearTimeout(timer);
    if (outer) outer.removeEventListener("abort", onAbort);
  }
}

// A body nobody reads pins its connection until the collector notices.
/**
 * @param {Response} resp
 * @returns {Promise<void>} never rejects
 */
async function drain(resp) {
  try {
    await resp.body?.cancel();
  } catch {
    // The peer is gone; the connection is going away with it.
  }
}

/**
 * @param {Record<string, unknown>} env
 * @returns {Promise<Cache>}
 */
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

/**
 * Stands in for caches.default off Cloudflare, refusing exactly what the
 * real one refuses so a test cannot pass on a more permissive stub.
 * @returns {{match: (req: Request|string) => Promise<Response|null>,
 *   delete: (req: Request|string) => Promise<boolean>,
 *   put: (req: Request|string, res: Response) => Promise<void>}}
 */
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
    async delete(req) {
      return map.delete(cacheId(req));
    },
    async put(req, res) {
      const control = res.headers.get("cache-control") || "";
      // Refused here because Cloudflare refuses them there. A stand-in that is
      // more permissive than the real cache proves nothing: the analyze path
      // stored `private` for as long as it existed and every test passed.
      if (/(^|,\s*)(private|no-store|no-cache)\b/.test(control)) return;
      const match = /max-age=(\d+)/.exec(control);
      const maxAge = match ? Number(match[1]) : 3600;
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

/**
 * @param {Request|string} req
 * @returns {string}
 */
function cacheId(req) {
  return typeof req === "string" ? req : req.url;
}

// The copy that goes into caches.default.
//
// `public`, always — including on an authenticated deployment, where the answer
// sent to the caller is `private`. Those are two different headers doing two
// different jobs, and conflating them is what emptied L0: caches.default is a
// shared cache, so a response marked `private` instructs it not to store, and
// `cache.put` duly refuses. Every verdict then lived in KV alone and every
// lookup paid the L1 round trip, on the deployments that have a token — which
// is the deployments that matter.
//
// Marking the stored copy `public` shares it with nobody. The key is the
// artifact's identity, it lives on beamline's own origin, and the token gate in
// dispatch() runs before any route reads the cache — so the only way to this
// entry is through a request that has already authenticated. What must stay
// `private` is the header the caller receives, because that one travels: it is
// read by their proxy and their browser, and a PURL is their dependency list.
// clientScope() still stamps that, and is unchanged.
/**
 * @param {Record<string, unknown>} env
 * @param {string} body
 * @returns {Response}
 */
function storedDocument(env, body) {
  // Full envelopes are already canonical scan output. Running one through the
  // compact decision normalizer would add `status` and `severity`, changing
  // the payload between a fresh response and a cache hit.
  const canonical = v1DocumentBody(body, true) || v1DocumentBody(body) || body;
  return new Response(canonical, {
    status: 200,
    headers: {
      "content-type": "application/json",
      "cache-control": `public, max-age=${v1MaxAge(env, canonical)}`,
    },
  });
}

/**
 * @param {Ctx|null} ctx
 * @param {Promise<unknown>} promise
 * @returns {void}
 */
function waitUntil(ctx, promise) {
  const guarded = Promise.resolve(promise).catch((err) => {
    logLine("wait_error", { err: errText(err) });
  });
  if (ctx && typeof ctx.waitUntil === "function") ctx.waitUntil(guarded);
}
/**
 * @param {Record<string, unknown>} env
 * @param {string} key
 * @param {number} fallback
 * @returns {number} a finite, non-negative value
 */
function numEnv(env, key, fallback) {
  if (!env || env[key] == null || env[key] === "") return fallback;
  const value = Number(env[key]);
  return Number.isFinite(value) && value >= 0 ? value : fallback;
}

/**
 * @param {unknown} raw
 * @returns {string} at most 64 characters of [A-Za-z0-9._:-]
 */
function cleanId(raw) {
  return String(raw || "").replace(/[^A-Za-z0-9._:-]/g, "").slice(0, 64);
}

/**
 * @param {unknown} err
 * @returns {string}
 */
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

/**
 * @param {string} event
 * @param {Record<string, unknown>} [fields]
 * @returns {void} never throws
 */
function logLine(event, fields) {
  if (logLine.mute) return;
  try {
    const row = { event };
    for (const key of Object.keys(fields || {})) {
      if (fields[key] !== undefined) row[key] = fields[key];
    }
    console.log(STRUCTURED_LOGS ? row : JSON.stringify(row));
  } catch {
    // Logging must never fail a lookup.
  }
}

/**
 * @param {string} base
 * @returns {ReturnType<typeof makeBreaker>}
 */
function breakerFor(base) {
  let breaker = scanBreakers.get(base);
  if (!breaker) {
    breaker = makeBreaker();
    scanBreakers.set(base, breaker);
  }
  return breaker;
}

// SCAN_URL is one URL or a comma-separated list of interchangeable workers.
/**
 * @param {unknown} raw - comma-separated
 * @returns {string[]} base URLs without trailing slashes
 */
function urlList(raw) {
  return tokenList(raw).map((base) => base.replace(/\/+$/, "")).filter(Boolean);
}

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
/**
 * @param {Record<string, unknown>} env
 * @param {string|null} pin
 * @returns {string[]}
 */
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
/**
 * @param {string} base
 * @returns {string}
 */
function hostOf(base) {
  try {
    return new URL(base).host;
  } catch {
    return base;
  }
}

/**
 * @returns {{ok: () => void, fail: () => void, open: () => boolean,
 *   reset: () => void}}
 */
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

/**
 * @param {unknown} obj
 * @param {number} status
 * @returns {Response}
 */
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
/**
 * @param {string} allow
 * @returns {Response}
 */
function methodNotAllowed(allow) {
  const body = { error: { code: "method_not_allowed", message: `Use ${allow}.` } };
  return new Response(JSON.stringify(body), {
    status: 405,
    headers: { "content-type": "application/json", "cache-control": "no-store", allow },
  });
}

/**
 * @param {number} ms
 * @param {Ctx|null} ctx - its abort rejects the wait
 * @returns {Promise<void>}
 */
function sleep(ms, ctx) {
  const outer = ctx && ctx.signal;
  if (outer && outer.aborted) return Promise.reject(new DOMException("Aborted", "AbortError"));
  return new Promise((resolve, reject) => {
    const settle = (fn, arg) => {
      clearTimeout(timer);
      if (outer) outer.removeEventListener("abort", onAbort);
      fn(arg);
    };
    const onAbort = () => settle(reject, new DOMException("Aborted", "AbortError"));
    const timer = setTimeout(() => settle(resolve), ms);
    if (outer) outer.addEventListener("abort", onAbort, { once: true });
  });
}

export const _test = {
  occupancy,
  capability,
  noteDispatch,
  pendingSince,
  registrySize,
  purlNameVersion,
  whaleSlowdown,
  BIG_JOB_BYTES,
  foregroundPressure,
  machineBusy,
  probeIndex,
  starvedEstimate,
  STARVE_PROBE_MS,
  CACHE_LAYERS,
  beamlineSource,
  followCandidates,
  v1CachePath,
  kvKey,
  newerEngine,
  normalizePurl,
  locatorsIn,
  predictMs,
  hasHistory,
  jobMix,
  UNKNOWN_JOB_MS,
  tiedEst,
  rotate,
  scanWorkers,
  breakerFor,
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
