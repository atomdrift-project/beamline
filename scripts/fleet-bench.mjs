#!/usr/bin/env node
// fleet-bench — how much can each scan worker analyze, by count and by bytes?
//
// Every worker is pinned and given its own set of releases nobody has analyzed
// yet, all at once. The sets are not the same PURLs, and must not be: scan's
// index and primary are shared, so the second worker to reach a PURL reads the
// first one's verdict back in under a second and times the index instead of
// itself (see route-bench.mjs). What is kept equal instead is what the work is
// made of — each worker gets the same ecosystem mix and the same bytes per
// package, dealt from one pool sorted by size.
//
// Each worker is driven at its own capacity. A fixed concurrency measures
// latency rather than throughput: at 8 in flight, a 384-slot worker and a
// 12-slot one both finish at 8 / latency, and a run of that shape scored the
// whole fleet at 22-32 packages a minute while the largest worker sat 94% idle.
// `auto` sends each worker as many at once as it reports free slots, and gives
// it `waves` times that many, so every worker is busy for about as long.
//
//   node scripts/fleet-bench.mjs                          # auto concurrency, 4 waves
//   node scripts/fleet-bench.mjs --waves 2 --dry-run
//   node scripts/fleet-bench.mjs --per-worker 96          # same count everywhere, each at its own width
//   node scripts/fleet-bench.mjs --concurrency 8 --workers scan-lax.isotope13.ai --file purls.txt
//
// BEAMLINE_URL  base URL  (default https://api.isotope13.ai)
// BEAMLINE_TOKEN bearer   (default: first line of ~/.tok/beamline)
//
// Only analyses scan actually ran on the pinned worker are scored. A verdict
// that arrived from the index — the fleet's pull workers analyze fresh
// releases too, and may get there first — is counted and reported, not timed.
//
// Sizes are the registry's compressed artifact: the npm tarball, the largest
// PyPI file of the release, the .crate, the Go module zip. That is what a
// worker downloads, not what it unpacks.
import { writeFileSync, readFileSync } from "node:fs";
import { request as httpRequest } from "node:http";
import { request as httpsRequest } from "node:https";
import { pathToFileURL } from "node:url";
import { resolve } from "node:path";
import { cleartextRemote, readToken } from "../tok.js";
import { fetchCrates, fetchGo, fetchNpm, fetchPypi } from "../stress.js";

const UA = "beamline-fleet-bench/1.0";
const LOOKUP_BATCH = 50; // V1_MAX_KEYS in beamline.js
const META_WIDTH = 16;
const META_TIMEOUT_MS = 20_000;
const LOOKUP_TIMEOUT_MS = 60_000;
const LOOKUP_ATTEMPTS = 3;
// Past scan's own 30-minute analysis budget, so the server gives up first and
// says why, rather than this client cutting a run that was still going. The
// only clock on an analysis: fetch also cut any stream silent for 300s, which
// is shorter than beamline's own stall window and cut runs it was still owed.
const ANALYZE_TIMEOUT_MS = 35 * 60_000;
// For a worker whose stats did not answer: enough to say something about it.
const FALLBACK_WIDTH = 8;
const MIB = 1 << 20;

const isMain = process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href;
if (isMain) {
  main().catch((err) => {
    process.stderr.write(`${err && err.stack ? err.stack : err}\n`);
    process.exit(1);
  });
}

async function main() {
  const args = process.argv.slice(2);
  const opt = (name, fallback) => {
    const i = args.indexOf(name);
    return i >= 0 && i + 1 < args.length ? args[i + 1] : fallback;
  };
  const concurrency = opt("--concurrency", "auto");
  const waves = Math.max(1, Number(opt("--waves", 4)) || 4);
  // A fixed count per worker instead of `waves` of its own width: more samples
  // from the small workers, at the cost of the large ones finishing early.
  const perWorker = Math.max(0, Number(opt("--per-worker", 0)) || 0);
  const seed = Number(opt("--seed", 1)) || 1;
  const file = opt("--file", "");
  const out = opt("--out", "");
  const only = opt("--workers", "").split(",").map((w) => w.trim()).filter(Boolean);
  const dryRun = args.includes("--dry-run");

  const base = (process.env.BEAMLINE_URL || "https://api.isotope13.ai").replace(/\/+$/, "");
  const token = (process.env.BEAMLINE_TOKEN || "").trim() || readToken("beamline");
  if (token && cleartextRemote(base)) {
    throw new Error(`${base} is plain http to a remote host; refusing to send a bearer token over it. Use https.`);
  }
  const auth = token ? { authorization: `Bearer ${token}` } : {};

  const before = await fleet(base, auth);
  const workers = only.length ? only : before.filter((w) => w.breaker === "closed").map((w) => w.worker);
  const unknown = workers.filter((w) => !before.some((b) => b.worker === w));
  if (unknown.length) throw new Error(`not configured on ${base}: ${unknown.join(", ")}`);
  if (!workers.length) throw new Error("no workers with a closed breaker");
  const widths = workers.map((w) => width(concurrency, before.find((b) => b.worker === w)));
  const want = widths.map((c) => perWorker || c * waves);
  const need = want.reduce((a, n) => a + n, 0);
  log(`beamline ${base}`);
  log(`plan     ${perWorker ? `${perWorker} per worker` : `${waves} waves`} at ${concurrency} concurrency = ${need} analyses, seed ${seed}`);
  for (const w of before.filter((b) => workers.includes(b.worker))) log(`  before ${load(w)}`);

  const candidates = dedupe(file ? fromFile(file) : await fromFeeds(need));
  log(`candidates ${candidates.length} ${tally(candidates, (c) => c.eco)}`);
  const fresh = await unanalyzed(base, auth, candidates);
  log(`unanalyzed ${fresh.length} of ${candidates.length}`);
  const sized = (await pool(fresh, META_WIDTH, async (c) => ({ ...c, bytes: await sizeOf(c.purl) }))).filter(
    (c) => c.bytes > 0,
  );
  log(`sized      ${sized.length} of ${fresh.length} (the rest are dropped: they cannot be scored by bytes)`);

  // Short of releases, every worker loses the same share of its waves, so the
  // run still keeps each one busy for about as long as the others.
  const scale = Math.min(1, sized.length / need);
  const counts = want.map((n) => Math.max(1, Math.floor(n * scale)));
  if (scale < 1) log(`warning: ${sized.length} releases for ${need}; each worker gets ${Math.round(scale * 100)}% of its share`);
  const random = rng(seed);
  const picked = shuffle(sized, random).slice(0, counts.reduce((a, n) => a + n, 0));
  const sets = deal(picked, counts).map((set) => shuffle(set, random));
  for (const [i, set] of sets.entries()) {
    log(`  ${workers[i].padEnd(26)} x${String(widths[i]).padEnd(4)} n=${set.length} ${mib(sum(set))} MiB  ${tally(set, (c) => c.eco)}`);
  }
  if (dryRun) {
    if (out) save(out, { base, workers, widths, sets });
    return;
  }

  const t0 = Date.now();
  // Everything finished so far, so a run stopped early — a worker gone
  // unreachable mid-run holds every other worker's report hostage behind its
  // retries — still reports what it measured.
  const done = [];
  const finish = (rows, after) => {
    const results = workers.map((worker, i) => summarize(worker, widths[i], rows.filter((r) => r.worker === worker), t0));
    process.stdout.write(report(results));
    for (const w of after.filter((a) => workers.includes(a.worker))) process.stdout.write(`after  ${load(w)}\n`);
    if (out) save(out, { base, workers, widths, waves, perWorker, seed, t0, before, after, results, rows });
  };
  for (const signal of ["SIGINT", "SIGTERM"]) {
    process.once(signal, () => {
      log(`${signal}: reporting the ${done.length} analyses finished so far`);
      finish(done, []);
      process.exit(130);
    });
  }
  const rows = (
    await Promise.all(
      workers.map((worker, i) =>
        pool(sets[i], widths[i], async (c) => {
          const r = await analyze(base, auth, c.purl, worker);
          const row = { worker, ...c, ...r, scored: scored(r, worker) };
          done.push(row);
          log(line(row));
          return row;
        }),
      ),
    )
  ).flat();
  finish(rows, await fleet(base, auth).catch(() => []));
}

// What the router sees: every configured worker, its breaker, and its stats.
async function fleet(base, auth) {
  const resp = await fetch(`${base}/_/routes?size=none`, { headers: { ...auth, "user-agent": UA } });
  if (!resp.ok) throw new Error(`/_/routes: HTTP ${resp.status}`);
  return (await resp.json()).workers || [];
}

// How many analyses to keep in flight on one worker. `auto` is the slots it
// says are free — past that scan queues, and a queue adds wait, not work.
function width(concurrency, w) {
  if (concurrency !== "auto") return Math.max(1, Number(concurrency) || FALLBACK_WIDTH);
  const free = w?.stats?.slots_free ?? w?.stats?.slots;
  return free > 0 ? free : FALLBACK_WIDTH;
}

// The load a worker was carrying beside the benchmark. Background work is the
// pull worker on the same host, and a throughput number read without it is
// half a measurement.
function load(w) {
  const s = w.stats || {};
  return `${w.worker} slots=${s.slots ?? "?"} free=${s.slots_free ?? "?"} in_flight=${s.in_flight ?? "?"} background=${s.background_in_flight ?? "?"} whale=${s.whale_slots?.in_use ?? "?"}/${s.whale_slots?.max ?? "?"} cpu=${s.cpu_busy_cores == null ? "?" : s.cpu_busy_cores.toFixed(1)}/${s.physical_cpus ?? "?"}`;
}

async function fromFeeds(need) {
  const feeds = await Promise.allSettled([
    fetchNpm(need),
    fetchPypi(need),
    fetchCrates(need),
    fetchGo(need),
  ]);
  for (const f of feeds) if (f.status === "rejected") log(`feed error: ${f.reason?.message || f.reason}`);
  return feeds.flatMap((f) => (f.status === "fulfilled" ? f.value : []));
}

function fromFile(path) {
  return readFileSync(path, "utf8")
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => l.startsWith("pkg:"))
    .map((purl) => ({ eco: parsePurl(purl)?.type || "other", purl }));
}

// One version per package. The Go index lists every pseudo-version a module
// publishes, and a burst of them is the same code timed a dozen times: one run
// had 113 of its 327 small Go modules from a dozen forks of one project, and
// they set the p90 of every worker alike.
function dedupe(candidates) {
  const seen = new Set();
  return candidates.filter((c) => {
    const p = parsePurl(c.purl);
    const key = p ? `${p.type}/${p.name}` : c.purl;
    return !seen.has(key) && seen.add(key);
  });
}

// Asked of the lookup, which spends no analysis slot. Anything the fleet has a
// verdict for would be an index hit on every worker, so only `unanalyzed`
// survives; `unavailable` is our own failure and says nothing either way.
async function unanalyzed(base, auth, candidates) {
  const batches = [];
  for (let i = 0; i < candidates.length; i += LOOKUP_BATCH) batches.push(candidates.slice(i, i + LOOKUP_BATCH));
  const answers = await pool(batches, 4, async (batch) => {
    const q = batch.map((c) => `purl=${encodeURIComponent(c.purl)}`).join("&");
    // A batch that times out is fifty candidates silently gone, so it is asked
    // again rather than dropped: a lookup spends no analysis slot.
    for (let attempt = 1; attempt <= LOOKUP_ATTEMPTS; attempt++) {
      try {
        const resp = await fetch(`${base}/v1/lookup?${q}`, {
          headers: { ...auth, "user-agent": UA },
          signal: AbortSignal.timeout(LOOKUP_TIMEOUT_MS),
        });
        if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
        const body = await resp.json();
        const list = Array.isArray(body) ? body : [body];
        return batch.filter((_, i) => list[i]?.status === "unanalyzed");
      } catch (err) {
        log(`lookup attempt ${attempt}/${LOOKUP_ATTEMPTS}: ${err.message || err}`);
      }
    }
    return [];
  });
  return answers.flat();
}

/**
 * @param {string} purl
 * @returns {{type: string, name: string, version: string}|null}
 */
function parsePurl(purl) {
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

// The Go module proxy's case encoding: each capital becomes `!` and its
// lowercase, so paths differing only in case stay distinct on any filesystem.
function goEscape(s) {
  return s.replace(/[A-Z]/g, (c) => `!${c.toLowerCase()}`);
}

// The registry's size for the artifact a worker would fetch, or 0 when it
// could not be had.
async function sizeOf(purl) {
  const p = parsePurl(purl);
  if (!p) return 0;
  try {
    switch (p.type) {
      case "npm": {
        const doc = await getJson(`https://registry.npmjs.org/${p.name}/${encodeURIComponent(p.version)}`);
        return doc?.dist?.tarball ? await contentLength(doc.dist.tarball) : 0;
      }
      case "pypi": {
        const doc = await getJson(`https://pypi.org/pypi/${encodeURIComponent(p.name)}/${encodeURIComponent(p.version)}/json`);
        return Math.max(0, ...(doc?.urls || []).map((u) => Number(u?.size) || 0));
      }
      case "cargo":
        return await contentLength(`https://static.crates.io/crates/${p.name}/${p.name}-${p.version}.crate`);
      case "golang":
        return await contentLength(`https://proxy.golang.org/${goEscape(p.name)}/@v/${goEscape(p.version)}.zip`);
      default:
        return 0;
    }
  } catch {
    return 0;
  }
}

async function getJson(url) {
  const resp = await fetch(url, { headers: { "user-agent": UA, accept: "application/json" }, signal: AbortSignal.timeout(META_TIMEOUT_MS) });
  return resp.ok ? resp.json() : null;
}

async function contentLength(url) {
  const head = await fetch(url, { method: "HEAD", headers: { "user-agent": UA }, signal: AbortSignal.timeout(META_TIMEOUT_MS) });
  const length = Number(head.headers.get("content-length"));
  if (head.ok && length > 0) return length;
  // npm's CDN answers HEAD with no length. One byte of a range request carries
  // the total in Content-Range; crates.io ignores ranges, but its HEAD is fine.
  const resp = await fetch(url, { headers: { "user-agent": UA, range: "bytes=0-0" }, signal: AbortSignal.timeout(META_TIMEOUT_MS) });
  await resp.body?.cancel();
  const total = /\/(\d+)$/.exec(resp.headers.get("content-range") || "");
  return total ? Number(total[1]) : 0;
}

// Split into sets of the given sizes with the same ecosystem mix and the same
// bytes per package. Each ecosystem gets a quota in each set proportional to
// the set's size; within those quotas, largest first, each item goes to the
// set whose bytes per slot would be lowest once it is placed. Judged after
// placing, not before: before, every empty set ties and a 32-item set takes
// the same first whale as a 512-item one. And a quota rather than a
// preference, because as a preference the mix decided every choice and bytes
// were only ever a tie-break.
function deal(items, counts) {
  const total = counts.reduce((a, n) => a + n, 0);
  const share = Map.groupBy(items, (c) => c.eco);
  const sets = counts.map((cap) => ({
    cap,
    items: [],
    bytes: 0,
    quota: new Map([...share].map(([eco, of]) => [eco, Math.ceil((cap * of.length) / Math.max(total, items.length))])),
  }));
  const open = (s) => s.items.length < s.cap;
  const load = (s, item) => (s.bytes + item.bytes) / s.cap;
  const lightest = (list, item) => list.reduce((best, s) => (load(s, item) < load(best, item) ? s : best));
  for (const item of items.toSorted((a, b) => b.bytes - a.bytes)) {
    const room = sets.filter(open);
    if (!room.length) break;
    const quota = room.filter((s) => s.quota.get(item.eco) > 0);
    const set = lightest(quota.length ? quota : room, item);
    set.items.push(item);
    set.bytes += item.bytes;
    set.quota.set(item.eco, set.quota.get(item.eco) - 1);
  }
  return sets.map((s) => s.items);
}

// One pinned analysis, timed to its decision. The stream is read to the end:
// the first byte arrives in about a second by design and means nothing here.
async function analyze(base, auth, purl, worker) {
  const start = Date.now();
  try {
    const resp = await post(`${base}/v1/analyze?purl=${encodeURIComponent(purl)}`, {
      ...auth,
      "user-agent": UA,
      accept: "application/x-ndjson",
      "x-beamline-pin": worker,
    });
    const lines = resp.text.split("\n").filter((l) => l.trim());
    let decision = null;
    for (const l of lines) {
      try {
        const frame = JSON.parse(l);
        if (frame && "status" in frame) decision = frame;
      } catch {
        // A torn frame is no decision; the absence is what gets recorded.
      }
    }
    const ok = resp.status >= 200 && resp.status < 300;
    return {
      start,
      ms: Date.now() - start,
      http: resp.status,
      source: resp.headers["x-beamline-source"] || "",
      // Who answered, never who was asked: the two differing is the failure
      // that once let a benchmark score the router against itself.
      answered: resp.headers["x-beamline-worker"] || "",
      status: decision?.status || (ok ? "no_decision" : decision?.error?.code || `http_${resp.status}`),
      cause: decision?.cause || null,
      frames: lines.length,
    };
  } catch (err) {
    return { start, ms: Date.now() - start, http: 0, source: "", answered: "", status: "error", cause: err.code || err.message || String(err), frames: 0 };
  }
}

// A POST read to the end, with no clock but ANALYZE_TIMEOUT_MS. node:http
// rather than fetch, whose body timeout would cut a stream beamline itself
// still considers alive. Each request gets its own connection, so a few
// hundred in flight are not multiplexed onto one that a single reset takes
// down together.
function post(url, headers) {
  const u = new URL(url);
  const send = u.protocol === "http:" ? httpRequest : httpsRequest;
  return new Promise((resolve, reject) => {
    const req = send(u, { method: "POST", headers }, (res) => {
      let text = "";
      res.setEncoding("utf8");
      res.on("data", (chunk) => (text += chunk));
      res.on("end", () => {
        clearTimeout(timer);
        resolve({ status: res.statusCode, headers: res.headers, text });
      });
      res.on("error", reject);
    });
    const timer = setTimeout(() => req.destroy(Object.assign(new Error("analysis timeout"), { code: "TIMEOUT" })), ANALYZE_TIMEOUT_MS);
    req.on("error", (err) => {
      clearTimeout(timer);
      reject(err);
    });
    req.end();
  });
}

function scored(r, worker) {
  return r.http === 200 && r.source === "scan:analysis" && r.status === "analyzed" && r.answered === worker;
}

// Two rates. `sustained` counts what finished while the worker was still
// being fed — up to the last dispatch, after which its in-flight count only
// falls — and is the number to compare workers on. `overall` runs to the last
// scored decision and includes that drain. A worker given no more than one
// wave finished nothing while it was still being fed, so it has no sustained
// rate at all — null, not zero, since its dispatches land a few ms apart.
function summarize(worker, width, rows, t0) {
  const good = rows.filter((r) => r.scored);
  const lastStart = Math.max(t0, ...rows.map((r) => r.start));
  const fed = good.filter((r) => r.start + r.ms <= lastStart);
  const fedS = (lastStart - t0) / 1000;
  const wallS = (Math.max(t0, ...good.map((r) => r.start + r.ms)) - t0) / 1000;
  const ms = good.map((r) => r.ms).toSorted((a, b) => a - b);
  const bytes = sum(good);
  const rate = (n, s) => (s ? (n / s) * 60 : null);
  return {
    worker,
    width,
    n: rows.length,
    scored: good.length,
    bytes,
    wallS,
    perMin: rate(good.length, wallS),
    mibPerMin: rate(bytes / MIB, wallS),
    sustainedPerMin: fed.length ? rate(fed.length, fedS) : null,
    sustainedMibPerMin: fed.length ? rate(sum(fed) / MIB, fedS) : null,
    p50: percentile(ms, 50),
    p90: percentile(ms, 90),
    max: ms.at(-1) ?? null,
    byEco: tally(good, (r) => r.eco),
    sources: tally(rows, (r) => r.source || "-"),
    unscored: tally(rows.filter((r) => !r.scored), (r) => (r.answered && r.answered !== worker ? "strayed" : r.cause ? `${r.status}:${r.cause}` : r.status)),
    failedBytes: sum(rows.filter((r) => !r.scored)),
  };
}

function report(results) {
  const rows = results.map(
    (s) =>
      `${s.worker.padEnd(26)} ${String(s.width).padStart(4)} ${String(s.scored).padStart(4)}/${String(s.n).padEnd(4)} ${mib(s.bytes).padStart(8)} ${num(s.sustainedPerMin).padStart(8)} ${num(s.sustainedMibPerMin).padStart(8)} ${s.wallS.toFixed(0).padStart(6)}s ${num(s.perMin).padStart(8)} ${num(s.mibPerMin).padStart(8)} ${fmt(s.p50).padStart(7)} ${fmt(s.p90).padStart(7)} ${mib(s.failedBytes).padStart(7)}`,
  );
  // Null only when no worker has the figure at all, as with a single wave.
  const total = (key) => (results.some((s) => s[key] != null) ? results.reduce((a, s) => a + (s[key] ?? 0), 0) : null);
  const detail = results.map((s) => `  ${s.worker}\n    eco ${s.byEco}\n    src ${s.sources}\n    not scored ${s.unscored}`);
  return [
    "",
    `${"".padEnd(26)}                             sustained           overall`,
    `${"worker".padEnd(26)} conc scored      MiB  pkg/min  MiB/min   wall  pkg/min  MiB/min     p50     p90  failMiB`,
    ...rows,
    `${"fleet".padEnd(26)} ${String(total("width")).padStart(4)} ${String(total("scored")).padStart(4)}/${String(total("n")).padEnd(4)} ${mib(total("bytes")).padStart(8)} ${num(total("sustainedPerMin")).padStart(8)} ${num(total("sustainedMibPerMin")).padStart(8)}`,
    "",
    "Scored analyses only. Sustained: finished before the worker's last dispatch, over that time.",
    "Overall: to its last scored decision. failMiB: bytes it was given and did not score.",
    ...detail,
    "",
  ].join("\n");
}

function line(r) {
  const tag = r.scored ? "ok " : "-- ";
  return `${tag} ${String(r.ms).padStart(7)}ms ${mib(r.bytes).padStart(8)}MiB ${(r.source || "-").padEnd(14)} ${r.worker.padEnd(26)} ${r.status}${r.cause ? `:${r.cause}` : ""}  ${r.purl}`;
}

async function pool(items, width, fn) {
  const out = Array.from({ length: items.length });
  let next = 0;
  await Promise.all(
    Array.from({ length: Math.min(width, items.length) }, async () => {
      for (let i = next++; i < items.length; i = next++) out[i] = await fn(items[i]);
    }),
  );
  return out;
}

// Seeded so a plan can be repeated. mulberry32, as in route-ab.mjs.
function rng(seed) {
  let state = seed | 0;
  return () => {
    state = (state + 0x6d2b79f5) | 0;
    let mixed = Math.imul(state ^ (state >>> 15), 1 | state);
    mixed = (mixed + Math.imul(mixed ^ (mixed >>> 7), 61 | mixed)) ^ mixed;
    return ((mixed ^ (mixed >>> 14)) >>> 0) / 4294967296;
  };
}

function shuffle(items, random) {
  return items.map((item) => ({ item, key: random() })).toSorted((a, b) => a.key - b.key).map((x) => x.item);
}

function percentile(sorted, p) {
  if (!sorted.length) return null;
  return sorted[Math.min(sorted.length - 1, Math.ceil((p / 100) * sorted.length) - 1)];
}

function tally(rows, key) {
  const counts = {};
  for (const r of rows) counts[key(r)] = (counts[key(r)] || 0) + 1;
  return Object.entries(counts).sort().map(([k, v]) => `${k}=${v}`).join(" ") || "-";
}

function sum(rows) {
  return rows.reduce((a, r) => a + (r.bytes || 0), 0);
}

function mib(bytes) {
  return (bytes / MIB).toFixed(1);
}

function num(v) {
  return v == null ? "-" : v.toFixed(1);
}

function fmt(ms) {
  return ms == null ? "-" : `${(ms / 1000).toFixed(1)}s`;
}

function save(path, data) {
  writeFileSync(path, JSON.stringify(data, null, 2));
  log(`wrote ${path}`);
}

function log(msg) {
  process.stderr.write(`${msg}\n`);
}

export const _test = { deal, dedupe, goEscape, parsePurl, scored, summarize, width };
