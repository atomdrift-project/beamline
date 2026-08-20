// Beamline: cache → bloom → hopper, with scan as a hedge. Zero dependencies.
// Cloudflare Worker and `node local.js` share this fetch handler.
//
// Hopper GET /api/sample can hang. Wait HOPPER_HEDGE_MS for a 200, then start
// scan without cancelling hopper. First useful answer wins. Hopper is aborted
// when we reply, or at HOPPER_LOOKUP_MS, whichever is first.

const SHA_RE = /^[0-9a-f]{64}$/;
const DEFAULT_MAX_BYTES = 16 * 1024 * 1024;
const DEFAULT_SCAN_TIMEOUT_MS = 1_800_000;
const BLOOM_TIMEOUT_MS = 500;
const HOPPER_HEDGE_MS = 1_000;
const HOPPER_LOOKUP_MS = 15_000;
const HOPPER_RPC_MS = 2_000;
const FILE_TIMEOUT_MS = 30_000;
const HEDGE = Symbol("hedge");
const HOPPER_POLL_MS = 500;
const BREAKER_FAILS = 5;
const BREAKER_COOL_MS = 10_000;
const MEMORY_CACHE_MAX = 1024;
const HIT_LIMIT = 3;
const HIT_MIN_CRIT = 3;

const hopperBreaker = makeBreaker();
const scanBreaker = makeBreaker();
const inflight = new Map();

export default {
  fetch(request, env, ctx) {
    return handle(request, env, ctx);
  },
};

export async function handle(request, env, ctx) {
  return maybeGzip(request, await dispatch(request, env, ctx));
}

async function dispatch(request, env, ctx) {
  ctx = ctx || {};
  if (request.signal && !ctx.signal) ctx = { ...ctx, signal: request.signal };

  const url = new URL(request.url);
  if (url.pathname === "/healthz" && request.method === "GET") {
    return json({ status: "ok" }, 200);
  }

  const allowed = tokenList(env.BEAMLINE_TOKEN);
  if (allowed.length) {
    const got = bearerToken(request);
    if (!allowed.some((t) => tokenEq(got, t))) {
      return json({ error: "unauthorized" }, 401);
    }
    env = { ...env, BEAMLINE_TOKEN: got };
  }

  try {
    if (request.method === "POST" && url.pathname === "/") {
      return await handlePost(request, env, ctx, url);
    }
    if (request.method === "GET" && url.pathname.startsWith("/sha256/")) {
      const sha = url.pathname.slice("/sha256/".length).toLowerCase();
      if (!SHA_RE.test(sha)) return json({ error: "invalid sha256" }, 400);
      return await lookup(env, ctx, url.origin, { sha, bytes: null, purl: null });
    }
    if (request.method === "GET" && (url.pathname.startsWith("/purl/") || url.searchParams.has("purl"))) {
      let purl;
      try {
        purl = url.searchParams.get("purl") || decodeURIComponent(url.pathname.slice("/purl/".length));
      } catch {
        return json({ error: "invalid purl" }, 400);
      }
      if (!purl.trim()) return json({ error: "missing purl" }, 400);
      return await lookup(env, ctx, url.origin, { sha: null, bytes: null, purl: purl.trim() });
    }
    return json({ error: "not found" }, 404);
  } catch (err) {
    if (clientAborted(ctx)) return json({ error: "canceled" }, 499);
    return json({ error: "internal" }, 500);
  }
}

async function handlePost(request, env, ctx, url) {
  const maxBytes = Number(env.MAX_BYTES) || DEFAULT_MAX_BYTES;
  const cl = Number(request.headers.get("content-length"));
  if (Number.isFinite(cl) && cl > maxBytes) return json({ error: "too large" }, 413);
  const { bytes, filename } = await readBody(request, maxBytes);
  if (!bytes) return json({ error: "empty body" }, 400);
  if (bytes.byteLength > maxBytes) return json({ error: "too large" }, 413);
  const sha = await sha256Hex(bytes);
  return await lookup(env, ctx, url.origin, { sha, bytes, purl: null, filename });
}

async function lookup(env, ctx, origin, input) {
  const t0 = Date.now();
  const cacheKey = input.sha
    ? new Request(`${origin}/sha256/${input.sha}`)
    : new Request(`${origin}/purl/${encodeURIComponent(input.purl)}`);
  const flightKey = input.sha ? `sha:${input.sha}` : `purl:${input.purl}`;

  const cache = await getCache(env);
  if (inflight.has(flightKey)) {
    const res = await inflight.get(flightKey);
    return res.clone();
  }
  const p = (async () => {
    const hit = await cache.match(cacheKey);
    if (hit) {
      const res = new Response(hit.body, hit);
      res.headers.set("X-Beamline-Source", "cache");
      logLine("lookup", { src: "cache", status: 200, ms: Date.now() - t0, ...idFields(input) });
      return res;
    }
    return runLookup(env, ctx, cache, cacheKey, input, t0);
  })();
  inflight.set(flightKey, p);
  try {
    const res = await p;
    return res.clone();
  } finally {
    inflight.delete(flightKey);
  }
}

async function runLookup(env, ctx, cache, cacheKey, input, t0) {
  const hedgeMs = numEnv(env, "HOPPER_HEDGE_MS", HOPPER_HEDGE_MS);
  const lookupMs = numEnv(env, "HOPPER_LOOKUP_MS", HOPPER_LOOKUP_MS);
  const ids = idFields(input);

  const bloom = await bloomDecide(env, ctx, input);
  if (bloom === "skip") {
    const res = bloomStub(env, input.sha, input.purl);
    logLine("lookup", { src: "bloom", status: 200, ms: Date.now() - t0, ...ids });
    return serveHit(ctx, cache, cacheKey, res);
  }

  const hopperCtl = new AbortController();
  const hopperP = hopperSample(env, ctx, input, lookupMs, hopperCtl.signal);
  let hopper = await Promise.race([hopperP, sleep(hedgeMs, ctx).then(() => HEDGE)]);
  const hedged = hopper === HEDGE;
  if (hedged) {
    hopper = undefined;
    logLine("hedge", { ms: Date.now() - t0, hedge_ms: hedgeMs, ...ids });
  }

  if (hopper?.status === 200) {
    return replyHopper(env, ctx, cache, cacheKey, input, hopper, t0, { hedged: false });
  }

  const scanCtl = new AbortController();
  const scanP = scanLookup(env, ctx, input, scanCtl);

  if (!hedged) {
    const pack = await scanP;
    return settle(env, ctx, cache, cacheKey, input, hopper, pack.bytes, pack.scanned, t0, { hedged: false });
  }

  const won = await raceUseful(hopperP, scanP);
  if (won.winner === "hopper") {
    scanCtl.abort();
    waitUntil(ctx, scanP.catch(() => {}));
    logLine("abort", { target: "scan", why: "hopper_hit", ms: Date.now() - t0, ...ids });
    return replyHopper(env, ctx, cache, cacheKey, input, won.hopper, t0, { hedged: true });
  }
  if (won.winner === "scan") {
    hopperCtl.abort();
    waitUntil(ctx, hopperP.catch(() => {}));
    logLine("abort", { target: "hopper", why: "scan_hit", ms: Date.now() - t0, ...ids });
    return replyScan(env, ctx, cache, cacheKey, input, won.hopper, won.bytes, won.scanned, t0, { hedged: true });
  }
  return settle(env, ctx, cache, cacheKey, input, won.hopper, won.bytes, won.scanned, t0, { hedged: true });
}

// Hopper 200 and a scan envelope are the only results the client can use
// immediately. 404/204/errors are not a win; the other arm keeps running.
async function raceUseful(hopperP, scanP) {
  let hopper;
  let pack;
  let hopperDone = false;
  let scanDone = false;
  const hp = hopperP.then((v) => {
    hopperDone = true;
    hopper = v;
  });
  const sp = scanP.then((v) => {
    scanDone = true;
    pack = v;
  });
  for (;;) {
    if (hopper?.status === 200) {
      return { winner: "hopper", hopper, bytes: pack && pack.bytes, scanned: pack && pack.scanned };
    }
    if (pack && pack.scanned && pack.scanned.env) {
      return { winner: "scan", hopper, bytes: pack.bytes, scanned: pack.scanned };
    }
    if (hopperDone && scanDone) {
      return { winner: "", hopper, bytes: pack && pack.bytes, scanned: pack && pack.scanned };
    }
    const wait = [];
    if (!hopperDone) wait.push(hp);
    if (!scanDone) wait.push(sp);
    await Promise.race(wait);
  }
}

async function scanLookup(env, ctx, input, scanCtl) {
  const scanCtx = { ...ctx, signal: mergeAbort(ctx && ctx.signal, scanCtl && scanCtl.signal) };
  try {
    let bytes = input.bytes || null;
    if (!bytes && input.sha) bytes = await hopperFile(env, scanCtx, input.sha);
    if (scanCtl && scanCtl.signal.aborted) return { bytes: null, scanned: { cancelled: true } };
    if (bytes) {
      return { bytes, scanned: await scanBytes(env, scanCtx, bytes, input.filename || input.sha) };
    }
    if (input.purl) return { bytes: null, scanned: await scanPurl(env, scanCtx, input.purl) };
    return { bytes: null, scanned: null };
  } catch (err) {
    if (clientAborted(ctx)) throw err;
    if (scanCtl && scanCtl.signal.aborted) return { bytes: null, scanned: { cancelled: true } };
    throw err;
  }
}

async function replyHopper(env, ctx, cache, cacheKey, input, hopper, t0, extra) {
  const res = envelopeResponse(env, await hopper.resp.json(), hopper.sha, "hopper", 86400, null, input.purl);
  logLine("lookup", {
    src: "hopper",
    status: 200,
    ms: Date.now() - t0,
    hedged: !!extra.hedged,
    hopper_status: 200,
    ...idFields(input),
  });
  return serveHit(ctx, cache, cacheKey, res);
}

function replyScan(env, ctx, cache, cacheKey, input, hopper, bytes, scanned, t0, extra) {
  const sha = input.sha || scanned.sha || shaFromEnvelope(scanned.env);
  const res = envelopeResponse(env, scanned.env, sha, "scan", 86400, scanned.totalMs, input.purl);
  logLine("lookup", {
    src: "scan",
    status: 200,
    ms: Date.now() - t0,
    hedged: !!extra.hedged,
    hopper_status: hopper?.status,
    ...idFields(input),
  });
  waitUntil(ctx, submitHopper(env, ctx, sha, bytes, scanned.env, scanned.ms, hopper?.status !== 204));
  return serveHit(ctx, cache, cacheKey, res);
}

async function settle(env, ctx, cache, cacheKey, input, hopper, bytes, scanned, t0, extra) {
  const ids = idFields(input);
  const hedged = !!extra.hedged;
  if (scanned?.env) return replyScan(env, ctx, cache, cacheKey, input, hopper, bytes, scanned, t0, extra);

  const queued = await queueAndWait(env, ctx, hopper, input, bytes, scanned);
  if (queued?.env) {
    const res = envelopeResponse(env, queued.env, queued.sha, "hopper", 86400, null, input.purl);
    logLine("lookup", { src: "hopper", status: 200, ms: Date.now() - t0, queued: true, hedged, hopper_status: hopper?.status, ...ids });
    return serveHit(ctx, cache, cacheKey, res);
  }
  if (queued?.failed) {
    logLine("lookup", { src: "hopper", status: 503, ms: Date.now() - t0, hedged, err: "upload", ...ids });
    return json({ error: "unavailable" }, 503);
  }
  if (queued?.pending) {
    logLine("lookup", { src: "hopper", status: 202, ms: Date.now() - t0, hedged, hopper_status: hopper?.status, ...ids });
    return pending();
  }

  if (scanned?.rejected) {
    const res = scanError(scanned);
    logLine("lookup", { src: "scan", status: res.status, ms: Date.now() - t0, hedged, hopper_status: hopper?.status, ...ids });
    return res;
  }
  if (!bytes && hopper == null) {
    logLine("lookup", { src: "hopper", status: 503, ms: Date.now() - t0, hedged, err: "unavailable", ...ids });
    return json({ error: "unavailable" }, 503);
  }
  if (scanned?.unavailable) {
    const res = scanUnavailable(scanned);
    logLine("lookup", { src: "scan", status: res.status, ms: Date.now() - t0, hedged, hopper_status: hopper?.status, ...ids });
    return res;
  }
  logLine("lookup", { src: "hopper", status: 404, ms: Date.now() - t0, hedged, hopper_status: hopper?.status, ...ids });
  return json({ error: "unknown sample" }, 404);
}

// Scan down, or hopper already has the bytes: upload if needed, promote, wait.
async function queueAndWait(env, ctx, hopper, input, bytes, scanned) {
  const shouldWait = scanned?.unavailable || hopper?.status === 204;
  if (!shouldWait) return null;

  let sha = (hopper?.sha && SHA_RE.test(hopper.sha) && hopper.sha) || input.sha || "";
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

async function bloomDecide(env, ctx, input) {
  const base = trimSlash(env.SCAN_URL);
  if (!base) return "unknown";
  const q = input.sha ? `sha256=${input.sha}` : `purl=${encodeURIComponent(input.purl)}`;
  try {
    const resp = await fetchTimeout(env, `${base}/_/bloom?${q}`, { method: "GET", headers: authHeaders(env) }, BLOOM_TIMEOUT_MS, ctx);
    if (!resp.ok) return "unknown";
    const body = await resp.json();
    return body.decision === "skip" ? "skip" : body.decision || "unknown";
  } catch (err) {
    if (clientAborted(ctx)) throw err;
    return "unknown";
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
    const resp = await fetchTimeout(env, url, { method: "GET", headers: authHeaders(env) }, ms, fetchCtx);
    if (resp.status === 404) {
      hopperBreaker.ok();
      return { status: 404, sha: input.sha, resp };
    }
    if (resp.status === 204) {
      hopperBreaker.ok();
      return { status: 204, sha: resp.headers.get("X-SHA256") || input.sha, resp };
    }
    if (!resp.ok) {
      hopperBreaker.fail();
      return null;
    }
    hopperBreaker.ok();
    return { status: 200, sha: resp.headers.get("X-SHA256") || input.sha, resp };
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
  try {
    const resp = await fetchTimeout(env, `${base}/api/file/${sha}`, { method: "GET", headers: authHeaders(env) }, FILE_TIMEOUT_MS, ctx);
    if (unreachableStatus(resp.status)) {
      hopperBreaker.fail();
      return null;
    }
    if (!resp.ok) return null;
    hopperBreaker.ok();
    const buf = await resp.arrayBuffer();
    const got = await sha256Hex(buf);
    return got === sha ? buf : null;
  } catch (err) {
    if (clientAborted(ctx)) throw err;
    hopperBreaker.fail();
    return null;
  }
}

async function scanPurl(env, ctx, purl) {
  const base = trimSlash(env.SCAN_URL);
  if (!base || scanBreaker.open()) return { unavailable: true };
  const timeout = Number(env.SCAN_TIMEOUT_MS) || DEFAULT_SCAN_TIMEOUT_MS;
  const start = Date.now();
  try {
    const resp = await fetchTimeout(
      env,
      `${base}/analyze-purl`,
      {
        method: "POST",
        headers: { ...authHeaders(env), "content-type": "application/json" },
        body: JSON.stringify({ purl }),
      },
      timeout,
      ctx,
    );
    return await readScan(resp, start);
  } catch (err) {
    if (clientAborted(ctx)) throw err;
    scanBreaker.fail();
    return { unavailable: true };
  }
}

async function scanBytes(env, ctx, bytes, filename) {
  const base = trimSlash(env.SCAN_URL);
  if (!base || scanBreaker.open()) return { unavailable: true };
  const timeout = Number(env.SCAN_TIMEOUT_MS) || DEFAULT_SCAN_TIMEOUT_MS;
  const start = Date.now();
  try {
    const body = multipart([{ name: "file", filename: filename || "upload.bin", body: new Uint8Array(bytes) }]);
    const resp = await fetchTimeout(
      env,
      `${base}/analyze`,
      { method: "POST", headers: { ...authHeaders(env), "content-type": body.contentType }, body: body.body },
      timeout,
      ctx,
    );
    return await readScan(resp, start);
  } catch (err) {
    if (clientAborted(ctx)) throw err;
    scanBreaker.fail();
    return { unavailable: true };
  }
}

async function readScan(resp, start) {
  const totalMs = resp.headers.get("x-total-ms");
  let body = null;
  try {
    body = await resp.json();
  } catch {
    body = null;
  }
  const ms = Date.now() - start;
  if (unreachableStatus(resp.status)) {
    scanBreaker.fail();
    return { unavailable: true, status: resp.status, body, ms, totalMs };
  }
  if (!resp.ok) return { rejected: true, status: resp.status, body, ms, totalMs };
  scanBreaker.ok();
  return { env: body, sha: shaFromEnvelope(body), ms, totalMs };
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
    const resp = await fetchTimeout(
      env,
      `${base}/api/upload`,
      { method: "POST", headers: { ...authHeaders(env), "content-type": body.contentType }, body: body.body },
      FILE_TIMEOUT_MS,
      ctx,
    );
    if (unreachableStatus(resp.status)) {
      hopperBreaker.fail();
      return false;
    }
    if (resp.ok) hopperBreaker.ok();
    return resp.ok;
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
    await fetchTimeout(env, `${base}/api/rescan/${sha}`, { method: "POST", headers: authHeaders(env) }, HOPPER_RPC_MS, ctx);
  } catch (err) {
    if (clientAborted(ctx)) throw err;
  }
}

async function waitForHopper(env, ctx, sha) {
  if (!sha || !SHA_RE.test(sha)) return null;
  const budget = Number(env.SCAN_TIMEOUT_MS) || DEFAULT_SCAN_TIMEOUT_MS;
  const poll = Number(env.HOPPER_POLL_MS) || HOPPER_POLL_MS;
  const deadline = Date.now() + budget;
  await hopperRescan(env, ctx, sha);
  while (Date.now() < deadline) {
    if (ctx && ctx.signal && ctx.signal.aborted) return null;
    const row = await hopperSample(env, ctx, { sha, bytes: null, purl: null });
    if (row?.status === 200) return { env: await row.resp.json(), sha: row.sha || sha };
    if (row == null && hopperBreaker.open()) return null;
    const wait = Math.min(poll, Math.max(0, deadline - Date.now()));
    if (wait <= 0) break;
    await sleep(wait, ctx);
  }
  return null;
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
    await fetchTimeout(
      env,
      `${base}/api/result`,
      {
        method: "POST",
        headers: { ...authHeaders(env), "content-type": "application/json" },
        body: JSON.stringify(payload),
      },
      FILE_TIMEOUT_MS,
      ctx,
    );
  } catch {
    // Client already has the answer.
  }
}

function authHeaders(env) {
  const tok = (env.BEAMLINE_TOKEN || "").trim();
  return tok ? { authorization: `Bearer ${tok}` } : {};
}

function tokenList(raw) {
  return String(raw || "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
}

function bearerToken(request) {
  const got = (request.headers.get("authorization") || "").trim();
  const m = /^Bearer\s+(\S+)/i.exec(got);
  return m ? m[1] : "";
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

function bloomStub(env, sha, purl) {
  return envelopeResponse(env, { ml: { lvl: -1, eng: "beamline" } }, sha, "bloom", 3600, null, purl);
}

function envelopeResponse(env, envelope, sha, source, maxAge, totalMs, purl) {
  const view = customerView(envelope, sha, purl);
  const scope = (env.BEAMLINE_TOKEN || "").trim() ? "private" : "public";
  const headers = {
    "content-type": "application/json",
    "cache-control": `${scope}, max-age=${maxAge}`,
    "x-beamline-source": source,
  };
  if (view.sha) headers["x-sha256"] = view.sha;
  if (totalMs != null && totalMs !== "") headers["x-total-ms"] = String(totalMs);
  return new Response(JSON.stringify(view), { status: 200, headers });
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
      const pkg = (t.dep && t.dep.locator) || purl || ident || "";
      const key = `${id}\0${file}\0${pkg}`;
      if (seen.has(key)) continue;
      seen.add(key);
      const hit = { id, crit };
      if (t.desc) hit.desc = t.desc;
      if (file) hit.file = file;
      if (pkg) hit.pkg = pkg;
      rows.push(hit);
    }
  }
  rows.sort((a, b) => b.crit - a.crit || a.id.localeCompare(b.id));
  return rows.slice(0, HIT_LIMIT);
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

function maybeGzip(request, res) {
  if (typeof CompressionStream !== "function") return res;
  const ae = (request.headers.get("accept-encoding") || "").toLowerCase();
  if (!ae.split(",").some((p) => p.trim().startsWith("gzip"))) return res;
  if (res.headers.get("content-encoding")) return res;
  if (!res.body) return res;
  const headers = new Headers(res.headers);
  headers.set("content-encoding", "gzip");
  headers.delete("content-length");
  headers.append("vary", "accept-encoding");
  return new Response(res.body.pipeThrough(new CompressionStream("gzip")), { status: res.status, headers });
}

function scanError(scanned) {
  return scanClientResponse(scanned.status || 400, scanned);
}

function scanUnavailable(scanned) {
  if (scanned.status === 504) return scanClientResponse(504, scanned);
  if (scanned.status === 429) return scanClientResponse(429, scanned);
  return json({ error: "unavailable" }, 503);
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

async function readBody(request, maxBytes) {
  const ct = (request.headers.get("content-type") || "").toLowerCase();
  if (ct.includes("multipart/form-data")) {
    const form = await request.formData();
    const file = form.get("file") || [...form.values()].find((v) => v && typeof v.arrayBuffer === "function");
    if (!file || typeof file.arrayBuffer !== "function") return { bytes: null, filename: "" };
    const buf = await file.arrayBuffer();
    return { bytes: buf, filename: file.name || "upload.bin" };
  }
  const buf = await request.arrayBuffer();
  if (buf.byteLength > maxBytes) return { bytes: buf, filename: "upload.bin" };
  return { bytes: buf.byteLength ? buf : null, filename: "upload.bin" };
}

function multipart(fields) {
  const boundary = "----beamline-" + Math.random().toString(16).slice(2);
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

async function fetchTimeout(env, url, opts, ms, ctx) {
  const ac = new AbortController();
  const outer = ctx && ctx.signal;
  if (outer && outer.aborted) {
    throw new DOMException("Aborted", "AbortError");
  }
  const onAbort = () => ac.abort();
  if (outer) outer.addEventListener("abort", onAbort, { once: true });
  const t = setTimeout(() => ac.abort(), ms);
  try {
    return await backendFetch(env, url, { ...opts, signal: ac.signal });
  } finally {
    clearTimeout(t);
    if (outer) outer.removeEventListener("abort", onAbort);
  }
}

// Hopper and scan sit on a private network. On Cloudflare, TUNNEL is a
// Workers VPC binding to a Cloudflare Tunnel; fetch then goes through
// that tunnel. Off Cloudflare (node local.js, tests) TUNNEL is absent
// and this is ordinary fetch.
function backendFetch(env, url, opts) {
  const tunnel = env && env.TUNNEL;
  if (tunnel && typeof tunnel.fetch === "function") return tunnel.fetch(url, opts);
  return fetch(url, opts);
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
      return new Response(row.body, { status: 200, headers: row.headers });
    },
    async put(req, res) {
      const cc = res.headers.get("cache-control") || "";
      const m = /max-age=(\d+)/.exec(cc);
      const maxAge = m ? Number(m[1]) : 3600;
      while (map.size >= MEMORY_CACHE_MAX) map.delete(map.keys().next().value);
      map.set(cacheId(req), {
        body: await res.clone().arrayBuffer(),
        headers: [...res.headers],
        exp: Date.now() + maxAge * 1000,
      });
    },
  };
}

function cacheId(req) {
  return typeof req === "string" ? req : req.url;
}

async function putCache(cache, key, res) {
  await cache.put(key, res.clone());
}

function serveHit(ctx, cache, cacheKey, res) {
  waitUntil(ctx, putCache(cache, cacheKey, res.clone()));
  return res;
}

function waitUntil(ctx, p) {
  const q = Promise.resolve(p).catch((err) => {
    logLine("wait_error", { err: String(err && err.message ? err.message : err) });
  });
  if (ctx && typeof ctx.waitUntil === "function") ctx.waitUntil(q);
}

function mergeAbort(a, b) {
  if (!a) return b;
  if (!b) return a;
  const ac = new AbortController();
  const fwd = () => ac.abort();
  if (a.aborted || b.aborted) {
    ac.abort();
    return ac.signal;
  }
  a.addEventListener("abort", fwd, { once: true });
  b.addEventListener("abort", fwd, { once: true });
  return ac.signal;
}

function numEnv(env, key, fallback) {
  if (!env || env[key] == null || env[key] === "") return fallback;
  const n = Number(env[key]);
  return Number.isFinite(n) && n >= 0 ? n : fallback;
}

function idFields(input) {
  const out = {};
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

function pending() {
  return new Response(JSON.stringify({ state: "pending" }), {
    status: 202,
    headers: { "content-type": "application/json", "retry-after": "5" },
  });
}

function sleep(ms, ctx) {
  return new Promise((resolve, reject) => {
    const t = setTimeout(resolve, ms);
    const outer = ctx && ctx.signal;
    if (!outer) return;
    if (outer.aborted) {
      clearTimeout(t);
      reject(new DOMException("Aborted", "AbortError"));
      return;
    }
    outer.addEventListener(
      "abort",
      () => {
        clearTimeout(t);
        reject(new DOMException("Aborted", "AbortError"));
      },
      { once: true },
    );
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
  shaFromEnvelope,
  customerView,
  topHits,
  SHA_RE,
  DEFAULT_SCAN_TIMEOUT_MS,
  HOPPER_HEDGE_MS,
  HOPPER_LOOKUP_MS,
  HOPPER_RPC_MS,
  MEMORY_CACHE_MAX,
  BREAKER_FAILS,
  makeBreaker,
  memoryCache,
  tokenEq,
  tokenList,
  numEnv,
  reset() {
    hopperBreaker.reset();
    scanBreaker.reset();
    inflight.clear();
    getCache.memory = null;
    logLine.mute = false;
  },
  muteLogs(on) {
    logLine.mute = !!on;
  },
};
