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

// Per isolate, not global: on Workers each isolate counts its own failures and
// loses them when it is recycled, so a backend outage costs BREAKER_FAILS
// requests per live isolate, not five in total. Same for inflight — it collapses
// duplicate work within one isolate; the cache does it across them.
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

// GET /v1/lookup — what we know, at the caller's budget. Never analyzes.
//
// Beamline's whole job here is the edge: authenticate, cache, and pick a worker.
// It does not consult hopper and does not reconcile two sources, because scan
// answers the question completely now — a worker that misses its own index asks
// the corpus itself. One question, one answer, one place that knows how to
// produce it.
async function handleV1Lookup(env, ctx, url) {
  const purls = url.searchParams.getAll("purl").map((p) => p.trim()).filter(Boolean);
  const urls = url.searchParams.getAll("url").map((value) => value.trim()).filter(Boolean);
  const sha = (url.searchParams.get("sha256") || "").trim();
  const budgetRaw = url.searchParams.get("false_positive_budget");
  const budget = parseFalsePositiveBudget(budgetRaw);
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
  // Refused rather than quietly replaced by the default: a caller who meant to
  // loosen their budget and got the strict one back would see verdicts they
  // never asked for, with nothing in the response to say why.
  if (budget === null) {
    return v1Error(
      400,
      "invalid_false_positive_budget",
      `false_positive_budget must be a whole number from 0 to 65535, not ${JSON.stringify(budgetRaw)}.`,
    );
  }

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
  const hit = ctx.pin ? null : await cache.match(cacheKey);
  if (hit) {
    // Buffered rather than streamed through, because the answer decides how
    // long the caller may hold it. Decisions are one small object.
    const document = await hit.text();
    const body = v1BudgetedBody(document, budget, locator, true);
    const res = new Response(body, hit);
    res.headers.set("X-Beamline-Source", "cache");
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
    return res;
  }

  if (!ctx.pin) {
    const document = await kvGet(env, path);
    if (document) {
      const body = v1BudgetedBody(document, budget, locator, true);
      if (body) {
        const res = v1Body(env, body, 200, null, v1MaxAge(document));
        res.headers.set("X-Beamline-Source", "kv");
        waitUntil(ctx, cache.put(cacheKey, storedDocument(document, env)));
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
  const workers = await lookupOrder(env, ctx, scanWorkers(env), ids);
  const t0 = Date.now();

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
      logLine("v1_lookup", { src: source, status: 200, worker, ms: Date.now() - t0, ...ids });
      const document = v1DocumentBody(answered.body);
      const stored = document || answered.body;
      const body = document ? v1BudgetedBody(document, budget, locator) : answered.body;
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
    } catch {
      breakerFor(base).fail();
    }
  }

  // Nobody could answer. Not a 5xx: the caller asked what we know about some
  // packages, and "we could not find out" is an answer about each of them —
  // one their policy is entitled to treat differently from "nobody has analyzed
  // this". A 503 here collapses those two, and a client that catches errors and
  // proceeds fails open on both.
  logLine("v1_lookup", { src: "none", status: 200, unavailable: true, ms: Date.now() - t0, ...ids });
  const rows = [];
  if (sha && !locators.length) rows.push(v1Unavailable(sha, null));
  for (const item of locators) rows.push(v1Unavailable(locators.length === 1 && sha ? sha : null, item));
  return v1Body(env, JSON.stringify(rows.length === 1 ? rows[0] : rows), 200, null, 0);
}

// A decision we could not reach a worker to make. Carries nothing about the
// artifact: it is a statement about us.
function v1Unavailable(sha, locator) {
  const row = {
    decision: "unavailable",
    purl: locator?.type === "purl" ? locator.value : null,
    sha256: sha || null,
    severity: null,
    fires_at: null,
    reason: null,
    findings: [],
    engine_version: null,
    analyzed_at: null,
  };
  if (locator?.type === "url") row.url = locator.value;
  return row;
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
  if (await cache.match(key).catch(() => null)) return;
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
function v1CacheAliasPaths(origin, requestedPath, locator, body, follow) {
  const paths = new Set([requestedPath]);
  if (locator) paths.add(v1CachePath(null, [locator], follow));
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

async function cacheV1Aliases(env, cache, origin, requestedPath, locator, body, follow) {
  const keys = v1CacheAliasPaths(origin, requestedPath, locator, body, follow);
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
  if (!/^\d{1,5}$/.test(value)) return null;
  const budget = Number(value);
  return budget <= 65535 ? budget : null;
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
  return applyBudgetToRow(row, DEFAULT_FALSE_POSITIVE_BUDGET);
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
  const budgetRow = (item) => {
    const normalized = legacyCachedUnknown && item && typeof item === "object" && !Array.isArray(item) && item.decision === "unknown"
      ? { ...item, decision: "unanalyzed" }
      : item;
    return applyBudgetToRow(normalized, budget);
  };
  const rows = Array.isArray(row) ? row.map(budgetRow) : budgetRow(row);
  if (!locator || locator.type !== "url") return JSON.stringify(rows);
  const addUrl = (item) => (item && typeof item === "object" && !Array.isArray(item) ? { ...item, url: locator.value } : item);
  return JSON.stringify(Array.isArray(rows) ? rows.map(addUrl) : addUrl(rows));
}

function applyBudgetToRow(row, budget) {
  if (!row || typeof row !== "object" || Array.isArray(row)) return row;
  if (row.engine_version && Number.isInteger(row.fires_at)) {
    return { ...row, decision: row.fires_at >= 0 && row.fires_at <= budget ? "block" : "allow" };
  }
  return row;
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
  const decision = row.decision;
  if (typeof decision !== "string" || decision === "unanalyzed" || decision === "unavailable") return null;
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
function v1MaxAge(body) {
  if (body.includes('"unavailable"')) return 0;
  if (body.includes('"engine_version":null')) return V1_NO_ENGINE_MAX_AGE;
  return V1_VERDICT_MAX_AGE;
}

function beamlineSource(source) {
  switch (source) {
    case "cache":
    case "kv":
    case "none":
      return source;
    case "scan:bloom":
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
    case "scan":
    case "index":
    default:
      return "scan:analysis";
  }
}

function v1Body(env, body, status, worker, maxAge, source) {
  const headers = { "content-type": "application/json" };
  headers["cache-control"] = maxAge
    ? `${cacheScope(env)}, max-age=${maxAge}`
    : "no-store";
  if (worker) headers["X-Beamline-Worker"] = worker;
  headers["X-Beamline-Source"] = worker ? beamlineSource(source) : "none";
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
      `false_positive_budget must be a whole number from 0 to 65535, not ${JSON.stringify(budgetRaw)}.`,
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
    const cachePath = v1CachePath(null, [locator], follow.value);
    const key = new Request(`${url.origin}${cachePath}`);
    const hit = await cache.match(key).catch(() => null);
    let document = hit ? await hit.text().catch(() => null) : null;
    if (!document) document = await kvGet(env, cachePath);
    const decided = document ? v1CachedVerdict(document) : null;
    if (decided) {
      // Serving from cache used to warm nothing, because this path returns
      // before the write below ever runs. So a warm PURL key left the digest
      // key cold indefinitely: every caller holding only a hash paid a round
      // trip to learn something we were already holding, and answering them
      // never fixed it either.
      const body = v1BudgetedBody(document, budget, locator);
      waitUntil(ctx, backfillDigestKey(env, cache, url.origin, document, follow.value));
      logLine("v1_analyze", { src: "cache", status: 200, decision: decided.decision, ms: Date.now() - t0, ...ids });
      // Answered in the shape this route always answers in: one NDJSON line,
      // no progress frames because there was no run to report progress about.
      return new Response(`${body.trimEnd()}\n`, {
        status: 200,
        headers: {
          "content-type": "application/x-ndjson",
          "cache-control": "no-store",
        "X-Beamline-Source": hit ? "cache" : "kv",
        },
      });
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
  for (let attempt = 0; ; attempt++) {
    const pass = { busy: 0, broken: 0 };
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
    if ((attempt >= tries && !stillWorthOffering) || !scanWorkers(env).length) break;
    const wait = backoff(backoffBase, attempt, SCAN_RETRY_MAX_MS);
    logLine("v1_analyze_retry", { attempt: attempt + 1, of: tries, wait_ms: Math.round(wait), ...ids });
    await sleep(wait, ctx);
  }

  // Nobody could take it. A decision rather than a 5xx, for the same reason
  // /v1/lookup gives one: the caller asked about a package, and "we could not
  // find out" is an answer about it that their policy may treat differently
  // from "nobody has analyzed this".
  logLine("v1_analyze", { src: "none", status: 200, unavailable: true, ms: Date.now() - t0, ...ids });
  return new Response(`${JSON.stringify(v1Unavailable(null, locator))}\n`, {
    status: 200,
    headers: { "content-type": "application/x-ndjson", "cache-control": "no-store" },
  });
}

// One pass over the fleet. Returns the response, or null when every worker
// refused and the pass is worth making again.
async function v1Dispatch(env, ctx, url, locator, path, budget, busy, ids, t0, bytes, pass, cacheFollow) {
  const workers = scanWorkers(env);
  const hint = locator?.type === "purl" ? { purl: locator.value } : {};
  let ranked = workers.length ? (await rankWorkers(env, ctx, workers, ids, hint)).workers : [];
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
      upstream = await fetch(`${base}${path}`, {
        method: "POST",
        headers: scanHeaders(env, ctx),
        body: bytes,
        signal: ctx.signal,
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
    breakerFor(base).ok();
    if (upstream.status !== 200) {
      logLine("v1_analyze", { src: "scan", status: upstream.status, worker, ms: Date.now() - t0, ...ids });
      return new Response(upstream.body, {
        status: upstream.status,
        headers: { "content-type": "application/json", "cache-control": "no-store" },
      });
    }

    const source = beamlineSource(upstream.headers.get("X-Scan-Source"));
    logLine("v1_analyze", { src: source, status: 200, worker, ms: Date.now() - t0, ...ids });
    // One copy to the caller, one to be read out of band: a fresh verdict is
    // exactly what the next lookup wants, so analyzing warms the cache the
    // cheap route reads. Teeing rather than buffering keeps the caller's copy
    // flowing while ours is still arriving.
    let out = upstream.body;
    if (cacheFollow) {
      const streams = upstream.body.tee();
      out = streams[0];
      waitUntil(ctx, cacheV1Decision(env, ctx, url.origin, locator, streams[1], cacheFollow));
    }
    return new Response(
      annotatedV1Stream(out, budget, {
        requestId: ctx.rid,
        locator,
        startedAt: t0,
      }),
      {
      status: 200,
      headers: {
        "content-type": "application/x-ndjson",
        "cache-control": "no-store",
        "X-Beamline-Worker": worker,
        "X-Beamline-Source": source,
      },
      },
    );
  }

  return null;
}

// Read the streamed answer out of band and store its decision where the cheap
// route will find it.
//
// The decision is the last line scan sends; everything before it says what the
// run was doing. A stream that ends without one was cut short, and caching a
// truncated answer would turn one dropped connection into a wrong answer served
// from the edge — so nothing is stored unless a decision actually arrived.
async function cacheV1Decision(env, ctx, origin, locator, stream, follow) {
  const ids = v1LocatorIds(ctx.rid, null, locator ? [locator] : []);
  const decided = await lastDecision(stream);
  if (!decided) {
    logLine("v1_cache_write", { stored: false, reason: "no_decision", ...ids });
    return;
  }
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
  await cacheV1Aliases(env, cache, origin, requestedPath, locator, document, follow);
  logLine("v1_cache_write", { stored: true, follow, max_age: maxAge, keys: v1CacheAliasPaths(origin, requestedPath, locator, document, follow).length, ...ids });
}

// Add phase telemetry to the progress stream without changing the cached
// decision. Scan's older progress frames only carried a nullable phase and a
// total elapsed time, which made a missing phase indistinguishable from a
// stalled run. The Worker owns the request clock, so it can also correlate the
// frames without asking every scan version to learn a new wire format first.
function annotatedV1Stream(stream, budget, meta) {
  const decoder = new TextDecoder();
  const encoder = new TextEncoder();
  let buffered = "";
  const phase = { name: null, startedElapsed: 0, lastElapsed: 0 };

  const encodeLine = (line) => {
    const rows = annotatedV1Lines(line, budget, meta, phase);
    return rows.map((row) => encoder.encode(`${row}\n`));
  };

  return stream.pipeThrough(
    new TransformStream({
      transform(chunk, controller) {
        buffered += decoder.decode(chunk, { stream: true });
        const lines = buffered.split("\n");
        buffered = lines.pop() ?? "";
        for (const line of lines) {
          for (const encoded of encodeLine(line)) controller.enqueue(encoded);
        }
      },
      flush(controller) {
        buffered += decoder.decode();
        if (buffered) {
          for (const encoded of encodeLine(buffered)) controller.enqueue(encoded);
        }
      },
    }),
  );
}

function annotatedV1Lines(line, budget, meta, phase) {
  let row;
  try {
    row = JSON.parse(line);
  } catch {
    return [line];
  }
  if (!row || typeof row !== "object" || Array.isArray(row)) {
    return [budgetedV1Line(line, budget, meta.locator)];
  }

  const totalElapsed = finiteMs(row.elapsed_ms) ?? phase.lastElapsed;
  if (Number.isFinite(totalElapsed)) phase.lastElapsed = totalElapsed;

  // A decision is the terminal event. Close the last reported phase in its own
  // frame so clients never have to infer completion from the decision shape.
  if (Object.prototype.hasOwnProperty.call(row, "decision")) {
    const done = phaseCompletion(meta, phase);
    return [...(done ? [JSON.stringify(done)] : []), budgetedV1Line(line, budget, meta.locator)];
  }

  if (row.state !== "analyzing") return [budgetedV1Line(line, budget, meta.locator)];

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
    rows.push(JSON.stringify(phaseFrame(row, meta, phase, "started", elapsed)));
  } else {
    rows.push(JSON.stringify(phaseFrame(row, meta, phase, "running", elapsed)));
  }
  return rows;
}

function phaseFrame(row, meta, phase, state, elapsed) {
  return {
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

// The last line of an NDJSON stream that carries a decision, or null.
async function lastDecision(stream) {
  const reader = stream.getReader();
  const decoder = new TextDecoder();
  let buffered = "";
  let found = null;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (value) buffered += decoder.decode(value, { stream: true });
      // Keep only the tail: progress frames are numerous on a long run and
      // none of them is the answer.
      const lines = buffered.split("\n");
      buffered = lines.pop() ?? "";
      for (const line of lines) {
        if (line.includes('"decision"')) found = line;
      }
      if (done) break;
    }
    if (buffered.includes('"decision"')) found = buffered;
  } catch {
    return null;
  } finally {
    reader.releaseLock();
  }
  return found;
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
  const workers = scanWorkers(env);
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
function hostPressure(stats) {
  const cpus = Number(stats?.physical_cpus);
  const load = Number(stats?.load1);
  if (!Number.isFinite(cpus) || cpus <= 0) return 0;
  if (!Number.isFinite(load) || load <= 0) return 0;
  return load / cpus;
}
// The hedge is a stall detector, not a latency optimizer.
//
// It used to be the latter, and the distinction is the whole design. Racing
// every worker at once wasted a full analysis per request; hedging below the
// expected time fired on roughly half of them, because the estimate is a
// central tendency and half of all jobs exceed it. Neither is what a second
// arm is for now: routing picks the favourite on measured p80, and a refusal
// promotes the next worker immediately, so the only failure a hedge still
// covers is a worker that *accepted* the work and then went quiet — which now
// includes one that accepted it into a queue, since a queued job looks exactly
// like a slow one from here.
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
function clientScope(env, maxAge) {
  return maxAge ? `${cacheScope(env)}, max-age=${maxAge}` : cacheScope(env);
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
  return storedCopy(
    new Response(body, {
      status: 200,
      headers: {
        "content-type": "application/json",
        "cache-control": `${cacheScope(env)}, max-age=${v1MaxAge(body)}`,
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
function scanWorkers(env) {
  const all = urlList(env.SCAN_URL);
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
  // Lets a test wait until a caller has actually joined the shared flight,
  // rather than sleeping and hoping. Timing-based waits here were flaky under a
  // loaded event loop, and a flaky test about cancellation is worse than none.
  flightCount: () => inflight.size,
  tokenEq,
  tokenList,
  numEnv,
  reset() {
    scanBreakers.clear();
    inflight.clear();
    getCache.memory = null;
    logLine.mute = false;
  },
  muteLogs(on) {
    logLine.mute = !!on;
  },
};
