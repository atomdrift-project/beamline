#!/usr/bin/env node
// Pull recently published PURLs the same way forager does, then time Beamline.
//
//   N=6 CONCURRENCY=2 BEAMLINE_URL=http://127.0.0.1:8080 node stress.js
//
// Feeds: npm replicate _changes, PyPI updates RSS, crates.io-index commits
// (sparse version lookup), Go module index.

import { pathToFileURL } from "node:url";
import { resolve } from "node:path";
import { readToken } from "./tok.js";

const UA = "beamline-stress/1.0 (+https://github.com/isotope13-dev/forager)";
const DEFAULT_N = 6;
const DEFAULT_CONCURRENCY = 2;
const META_TIMEOUT_MS = 20_000;
const GO_WINDOWS_MS = [3_600_000, 6 * 3_600_000, 24 * 3_600_000, 7 * 24 * 3_600_000];

const n = Math.max(1, Number(process.env.N) || DEFAULT_N);
const samples = Math.max(0, Number(process.env.SAMPLES) || 0);
const concurrency = Math.max(1, Number(process.env.CONCURRENCY) || DEFAULT_CONCURRENCY);
const beamlineUrl = trimSlash(process.env.BEAMLINE_URL);
// Client authentication is opt-in through the environment. Do not discover a
// local beamline token implicitly: an absent value means the API is open.
const token = (process.env.BEAMLINE_TOKEN || "").trim();
const scanToken = (process.env.SCAN_TOKEN || "").trim() || readToken("scan");
const hopperToken = (process.env.HOPPER_TOKEN || "").trim() || readToken("hopper");
// SCAN_URL may list several interchangeable workers; probe the first.
const scanUrl = trimSlash((process.env.SCAN_URL || "").split(",")[0]);
const hopperUrl = trimSlash(process.env.HOPPER_URL);
const outPath = process.env.STRESS_OUT || "";
// Which surface to exercise. v1 is the default because it is the one under
// development and the one a customer will hold; API=legacy still reaches the
// older routes while they exist, so a run can be pointed at either without
// keeping two harnesses in step.
const api = (process.env.API || "v1").trim().toLowerCase() === "legacy" ? "legacy" : "v1";
const popular = process.env.POPULAR === "1";
const analyzeMisses = process.env.ANALYZE_MISSES === "1";
const stressRoute = (process.env.STRESS_ROUTE || "combined").trim().toLowerCase();
const repeat = Math.max(1, Number(process.env.REPEAT) || 1);
const timeoutMs = Number(process.env.SCAN_TIMEOUT_MS) || 1_800_000;

// Five very widely used packages per ecosystem, pinned to the versions that
// were current when this list was written. Hardcoded deliberately: the value of
// this run is that two of them are comparable, so a change in the numbers means
// something changed in beamline — not that npm published a release overnight.
// These are the PURLs a real fleet asks about constantly, so what matters here
// is the cache and index hit rate, not whether an analysis succeeds.
const POPULAR = [
  ["npm", "pkg:npm/axios@1.19.0"],
  ["npm", "pkg:npm/chalk@6.0.0"],
  ["npm", "pkg:npm/express@5.2.1"],
  ["npm", "pkg:npm/lodash@4.18.1"],
  ["npm", "pkg:npm/react@19.2.8"],
  ["pypi", "pkg:pypi/boto3@1.43.75"],
  ["pypi", "pkg:pypi/numpy@2.5.2"],
  ["pypi", "pkg:pypi/requests@2.34.2"],
  ["pypi", "pkg:pypi/setuptools@84.0.0"],
  ["pypi", "pkg:pypi/urllib3@2.7.0"],
  ["cargo", "pkg:cargo/libc@0.2.189"],
  ["cargo", "pkg:cargo/quote@1.0.47"],
  ["cargo", "pkg:cargo/rand@0.10.2"],
  ["cargo", "pkg:cargo/serde@1.0.229"],
  ["cargo", "pkg:cargo/syn@3.0.3"],
  ["golang", "pkg:golang/github.com/sirupsen/logrus@v1.10.1"],
  ["golang", "pkg:golang/github.com/spf13/cobra@v1.10.2"],
  ["golang", "pkg:golang/github.com/stretchr/testify@v1.12.1"],
  ["golang", "pkg:golang/golang.org/x/sys@v0.47.0"],
  ["golang", "pkg:golang/google.golang.org/protobuf@v1.36.12"],
];

// Group the fixed list the way the registry feeds are grouped, so mixJobs
// interleaves ecosystems here exactly as it does for a live run.
function popularJobs() {
  const byEco = new Map();
  for (const [eco, purl] of POPULAR) {
    if (!byEco.has(eco)) byEco.set(eco, []);
    byEco.get(eco).push(job(eco, purl));
  }
  return [...byEco.values()];
}

const isMain = process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href;
if (isMain) {
  main().catch((err) => {
    process.stderr.write(`${err && err.stack ? err.stack : err}\n`);
    process.exit(1);
  });
}

async function main() {
  if (!beamlineUrl) {
    process.stderr.write("BEAMLINE_URL is required\n");
    process.exit(2);
  }
  if (!["combined", "lookup", "analyze", "both"].includes(stressRoute)) {
    process.stderr.write("STRESS_ROUTE must be combined, lookup, analyze, or both\n");
    process.exit(2);
  }

  process.stderr.write(
    `beamline ${beamlineUrl}\nscan     ${scanUrl}\n` +
    (hopperUrl ? `hopper   ${hopperUrl}\n` : "") +
      `${popular ? "popular" : `N=${n}`}${samples ? ` SAMPLES=${samples}` : ""}${repeat > 1 ? ` REPEAT=${repeat}` : ""} concurrency=${concurrency} route=${stressRoute}\n`,
  );
  await pingBackends();
  // Before the volume pass: the shapes it cannot reach, checked once.
  // The combined run checks the v1 contract once before both phases. A
  // route-only analyze pass is often used to finish or repeat a long run, so
  // do not spend another analysis slot on the one-off upload probe there.
  const contract = api === "v1" && stressRoute !== "analyze" ? await contractProbe() : [];

  // POPULAR=1 swaps the live registry feeds for the fixed list above.
  if (popular) {
    const baseJobs = mixJobs(popularJobs(), samples || Infinity);
    const jobs = repeatJobs(baseJobs, repeat);
    process.stderr.write(`submitting ${jobs.length} popular PURLs\n`);
    const before = await raceSnapshot();
    const result = await runRoutes(jobs, []);
    printRace(raceDelta(before, await raceSnapshot()));
    if (outPath) await writeOut(outPath, { scanUrl, hopperUrl, beamlineUrl, ...result, contract });
    process.exit(result.bugs.length || contract.length ? 1 : 0);
  }

  const feeds = await Promise.allSettled([
    named("npm", fetchNpm),
    named("pypi", fetchPypi),
    named("cargo", fetchCrates),
    named("golang", fetchGo),
  ]);

  const groups = [];
  const feedErrors = [];
  for (const r of feeds) {
    if (r.status === "fulfilled") groups.push(r.value.jobs);
    else feedErrors.push(r.reason);
  }
  for (const err of feedErrors) {
    process.stderr.write(`feed error: ${err.message || err}\n`);
  }
  let jobs = mixJobs(groups, samples || Infinity);
  if (!jobs.length) {
    process.stderr.write("no PURLs collected\n");
    process.exit(1);
  }

  process.stderr.write(`submitting ${jobs.length} PURLs\n`);
  const before = await raceSnapshot();
  const result = await runRoutes(jobs, feedErrors);
  printRace(raceDelta(before, await raceSnapshot()));
  if (outPath) await writeOut(outPath, { scanUrl, hopperUrl, beamlineUrl, ...result, contract });
  process.exit(result.bugs.length || contract.length ? 1 : 0);
}

async function runRoutes(jobs, feedErrors) {
  if (stressRoute === "both") {
    process.stderr.write("lookup phase\n");
    const lookupRows = await pool(jobs, concurrency, submitLookup);
    const lookup = summarize(lookupRows);
    printRouteReport("lookup", lookupRows, lookup, feedErrors);

    process.stderr.write("analyze phase\n");
    const analyzeRows = await pool(jobs, concurrency, submitAnalyze);
    const analyze = summarize(analyzeRows);
    printRouteReport("analyze", analyzeRows, analyze, feedErrors);
    return {
      lookup: { rows: lookupRows, summary: lookup },
      analyze: { rows: analyzeRows, summary: analyze },
      bugs: [...lookup.bugs, ...analyze.bugs],
    };
  }

  const rows = await pool(jobs, concurrency, submit);
  const summary = summarize(rows);
  printRouteReport(stressRoute, rows, summary, feedErrors);
  return { rows, summary, bugs: summary.bugs };
}

async function named(eco, fn) {
  const jobs = await fn(n);
  process.stderr.write(`  ${eco}: ${jobs.length}\n`);
  return { eco, jobs };
}

async function pingBackends() {
  const beam = await probe(`${beamlineUrl}/healthz`);
  const scan = scanUrl ? await probe(`${scanUrl}/_/health`) : "skipped";
  const hopper = await probe(`${hopperUrl}/healthz`);
  const hopperAlt = hopper === "ok" ? hopper : await probe(`${hopperUrl}/_/health`);
  if (hopperToken) {
    // /healthz is auth-exempt on hopper, so prove the credential works before a
    // whole run turns into 401s that look like misses.
    const probeSha = "0".repeat(64);
    const auth = { authorization: `Bearer ${hopperToken}` };
    const reach = await probe(`${hopperUrl}/api/sample/${probeSha}`, auth);
    if (reach === "401" || reach === "403") {
      process.stderr.write(`warning: hopper rejected our token (${reach})\n`);
    }
  }
  process.stderr.write(`health   beamline=${beam} scan=${scan} hopper=${hopperAlt}\n`);
  if (beam !== "ok") throw new Error(`beamline healthz: ${beam}`);
  if (scanUrl && scan !== "ok" && scan !== "saturated" && scan !== "degraded") {
    process.stderr.write(`warning: scan health is ${scan}\n`);
  }
  if (scanUrl) {
    try {
      const auth = scanToken ? { authorization: `Bearer ${scanToken}` } : {};
      const info = await get(`${scanUrl}/_/info`, 4000, auth).then((r) => r.json());
      process.stderr.write(`scan     version=${info.version || "?"} slots=${info.slots ?? "?"}\n`);
    } catch {
      // info is optional
    }
    try {
      const ap = await fetch(`${scanUrl}/analyze-purl`, {
        method: "GET",
        headers: { "user-agent": UA },
        signal: AbortSignal.timeout(4000),
      });
      if (ap.status === 404) {
        process.stderr.write("warning: scan has no /analyze-purl — PURL lookups 404 until this worker is upgraded\n");
      }
    } catch {
      // preflight is optional
    }
  }
}

async function probe(url, extra = {}) {
  try {
    const resp = await get(url, 4000, extra);
    if (!resp.ok) return String(resp.status);
    const ct = resp.headers.get("content-type") || "";
    if (ct.includes("json")) {
      const body = await resp.json();
      return body.status || "ok";
    }
    return "ok";
  } catch (err) {
    return err.cause?.code || err.message || "down";
  }
}

async function fetchNpm(limit) {
  const cap = Math.min(10_000, Math.max(100, limit * 50));
  const resp = await get(`https://replicate.npmjs.com/registry/_changes?descending=true&limit=${cap}`, META_TIMEOUT_MS);
  const body = await resp.json();
  const names = parseNpmChanges(body);
  const jobs = [];
  for (const name of names) {
    if (jobs.length >= limit) break;
    try {
      const meta = await get(`https://registry.npmjs.org/${encodeNpmName(name)}`, META_TIMEOUT_MS).then((r) => r.json());
      const version = meta["dist-tags"]?.latest || meta.version;
      if (!version) continue;
      jobs.push(job("npm", npmPurl(meta.name || name, version)));
    } catch {
      // Packument vanished between _changes and fetch.
    }
  }
  return jobs;
}

async function fetchPypi(limit) {
  const xml = await get("https://pypi.org/rss/updates.xml", META_TIMEOUT_MS).then((r) => r.text());
  return parsePypiRss(xml)
    .slice(0, limit)
    .map((p) => job("pypi", pypiPurl(p.name, p.version)));
}

async function fetchCrates(limit) {
  const names = await crateNames(limit);
  const jobs = [];
  for (const name of names) {
    if (jobs.length >= limit) break;
    try {
      const version = await cratesSparseNewestVersion(name);
      if (!version) continue;
      jobs.push(job("cargo", cargoPurl(name, version)));
    } catch {
      // Deleted before we resolved it, same as forager.
    }
  }
  return jobs;
}

async function crateNames(limit) {
  try {
    return await crateNamesFromIndex(limit);
  } catch (err) {
    process.stderr.write(`  cargo index: ${err.message}; falling back to crates.io recent-updates\n`);
    return crateNamesFromApi(limit);
  }
}

async function crateNamesFromIndex(limit) {
  const resp = await get(
    "https://api.github.com/repos/rust-lang/crates.io-index/commits?sha=master&per_page=100",
    META_TIMEOUT_MS,
    { accept: "application/vnd.github+json" },
  );
  const commits = await resp.json();
  if (!Array.isArray(commits)) throw new Error("github commits: unexpected body");
  const names = [];
  const seen = new Set();
  for (const c of commits) {
    const subject = (c.commit && c.commit.message ? c.commit.message : "").split("\n")[0];
    const { name, changed } = parseCratesIndexCommit(subject);
    if (!changed || seen.has(name)) continue;
    seen.add(name);
    names.push(name);
    if (names.length >= limit) break;
  }
  if (!names.length) throw new Error("no crate names in recent commits");
  return names;
}

async function crateNamesFromApi(limit) {
  const resp = await get(`https://crates.io/api/v1/crates?sort=recent-updates&per_page=${Math.min(100, limit)}`, META_TIMEOUT_MS);
  const body = await resp.json();
  return (body.crates || []).map((c) => c.name).filter(Boolean).slice(0, limit);
}

async function cratesSparseNewestVersion(name) {
  const resp = await get(`https://index.crates.io/${cratesSparsePath(name)}`, META_TIMEOUT_MS);
  const text = await resp.text();
  let last = "";
  for (const line of text.split("\n")) {
    const t = line.trim();
    if (t) last = t;
  }
  if (!last) return "";
  const rec = JSON.parse(last);
  return rec.vers || "";
}

async function fetchGo(limit) {
  for (let i = 0; i < GO_WINDOWS_MS.length; i++) {
    const w = GO_WINDOWS_MS[i];
    const since = new Date(Date.now() - w).toISOString();
    const url = `https://index.golang.org/index?since=${encodeURIComponent(since)}&limit=${limit * 4}`;
    const text = await get(url, META_TIMEOUT_MS).then((r) => r.text());
    const rows = parseGoIndex(text);
    if (rows.length >= limit || i === GO_WINDOWS_MS.length - 1) {
      const uniq = [];
      const seen = new Set();
      for (let j = rows.length - 1; j >= 0 && uniq.length < limit; j--) {
        const k = `${rows[j].name}@${rows[j].version}`;
        if (seen.has(k)) continue;
        seen.add(k);
        uniq.push(job("golang", golangPurl(rows[j].name, rows[j].version)));
      }
      return uniq;
    }
  }
  return [];
}

// Ask what is known; if nothing is, ask for the work. The analyze call carries
// the PURL and no bytes, so scan resolves the artifact from the registry itself
// and the provenance it grafts into the report comes from the same fetch.
async function submit(item) {
  if (stressRoute === "lookup") return submitLookup(item);
  if (stressRoute === "analyze") return submitAnalyze(item);
  return api === "v1" ? submitV1(item) : submitLegacy(item);
}

async function submitLookup(item) {
  const path = api === "v1" ? "/v1/lookup" : "/lookup";
  return ask(item, `${beamlineUrl}${path}?purl=${encodeURIComponent(item.purl)}`, "GET");
}

async function submitAnalyze(item) {
  if (api === "v1") {
    return askStream(item, `${beamlineUrl}/v1/analyze?purl=${encodeURIComponent(item.purl)}`);
  }
  return ask(item, `${beamlineUrl}/analyze?purl=${encodeURIComponent(item.purl)}`, "POST");
}

async function submitLegacy(item) {
  const looked = await ask(item, `${beamlineUrl}/lookup?purl=${encodeURIComponent(item.purl)}`, "GET");
  const answered = !analyzeMisses || looked.status !== 404 ? looked : null;
  if (answered) return { ...answered, both: await bothProbe(item, answered) };
  const analyzed = await ask(item, `${beamlineUrl}/analyze?purl=${encodeURIComponent(item.purl)}`, "POST");
  return { ...analyzed, analyzed: true, lookupMs: looked.ms, both: await bothProbe(item, analyzed) };
}

// The v1 shape of the same pass. A lookup that nobody has analyzed answers 200
// with `status: unanalyzed` rather than a 404, so what counts as a miss is a
// field rather than a status — which is the whole point of the contract and
// therefore worth exercising exactly as a client would read it.
async function submitV1(item) {
  const looked = await ask(item, `${beamlineUrl}/v1/lookup?purl=${encodeURIComponent(item.purl)}`, "GET");
  // Only a real verdict counts as known. `unanalyzed` is the miss this pass exists
  // to fill, and `unavailable` is our own failure — treating either as an
  // answer would skip the analysis and report an outage as a cache hit.
  const known = looked.artifactStatus === "analyzed";
  if (!analyzeMisses || known) return { ...looked, both: await bothProbeV1(item, looked) };
  const analyzed = await askStream(item, `${beamlineUrl}/v1/analyze?purl=${encodeURIComponent(item.purl)}`);
  return { ...analyzed, analyzed: true, lookupMs: looked.ms, both: await bothProbeV1(item, analyzed) };
}

// Re-ask with both keys, which is the shape a real client is in after its first
// answer: it now knows the digest as well as the locator. This measures what
// the optimized path is worth, against the same artifact on the same fleet, a
// moment apart — the only comparison that controls for what the corpus holds.
//
// Skipped when the first answer produced no digest; there is nothing to pair.
async function bothProbeV1(item, prior) {
  if (!prior?.sha || !/^[0-9a-f]{64}$/.test(prior.sha)) return null;
  const url = `${beamlineUrl}/v1/lookup?purl=${encodeURIComponent(item.purl)}&sha256=${prior.sha}`;
  const probed = await ask(item, url, "GET");
  return { ms: probed.ms, status: probed.status, source: probed.source };
}

async function bothProbe(item, prior) {
  if (!prior?.sha || !/^[0-9a-f]{64}$/.test(prior.sha)) return null;
  const url = `${beamlineUrl}/lookup?purl=${encodeURIComponent(item.purl)}&sha256=${prior.sha}`;
  const probed = await ask(item, url, "GET");
  return { ms: probed.ms, status: probed.status, source: probed.source };
}

async function ask(item, url, method) {
  const headers = { "accept-encoding": "gzip" };
  if (token) headers.authorization = `Bearer ${token}`;
  const t0 = Date.now();
  try {
    const resp = await get(url, timeoutMs + 10_000, headers, method);
    const ms = Date.now() - t0;
    const body = await readJson(resp);
    // Whether we authenticated decides the scope the answer must carry, and
    // only the caller knows that — so it is passed in rather than read from
    // module state, which would make the check untestable either way.
    const issues =
      api === "v1"
        ? checkV1(resp.status, body, item.purl)
        : checkApi(resp.status, resp.headers, body, item.purl, token ? "private" : "public");
    return row(item, {
      ms,
      status: resp.status,
      artifactStatus: body && body.status,
      source: resp.headers.get("x-beamline-source") || "",
      worker: resp.headers.get("x-beamline-worker") || "",
      sha: (body && (body.sha || body.sha256)) || resp.headers.get("x-sha256") || "",
      encoding: resp.headers.get("content-encoding") || "",
      error: body && body.error,
      detail: body && body.detail,
      state: body && body.state,
      lvl: body && (body.lvl ?? body.fires_at),
      eng: body && (body.eng || body.engine_version),
      hits: body && (body.hits || body.findings) ? (body.hits || body.findings).length : 0,
      issues,
    });
  } catch (err) {
    return row(item, { ms: Date.now() - t0, status: 0, error: err.message || String(err), issues: [err.message || String(err)] });
  }
}

// Read a v1 analysis, which answers as a stream: progress while the run is
// going, then the decision. Timed to the decision rather than the first byte —
// the first byte arrives in about a second by design, and reporting that as the
// latency would flatter every measurement this harness exists to take.
//
// `frames` is what proves the connection was talking. A long analysis that
// reports zero progress frames has gone silent, which is the failure this route
// was built to end, so it is counted rather than assumed.
async function askStream(item, url) {
  const headers = { accept: "application/x-ndjson" };
  if (token) headers.authorization = `Bearer ${token}`;
  const t0 = Date.now();
  try {
    const resp = await get(url, timeoutMs + 10_000, headers, "POST");
    const source = resp.headers.get("x-beamline-source") || "";
    const worker = resp.headers.get("x-beamline-worker") || "";
    if (resp.status !== 200) {
      const body = await readJson(resp).catch(() => null);
      return row(item, {
        ms: Date.now() - t0,
        status: resp.status,
        source,
        worker,
        error: body?.error?.code || body?.error,
        issues: [`analyze status ${resp.status}`],
      });
    }
    let frames = 0;
    let assessment = null;
    let firstMs = 0;
    let requestId = "";
    let lastState = "";
    let lastPhase = "";
    for await (const line of ndjson(resp)) {
      if (!firstMs) firstMs = Date.now() - t0;
      if (line.request_id) requestId = line.request_id;
      if (line.state) lastState = line.state;
      if (line.phase) lastPhase = line.phase;
      if (line.status) {
        assessment = line;
        break;
      }
      frames += 1;
    }
    const ms = Date.now() - t0;
    if (!assessment) {
      // No status line means the stream was cut short, not that the answer
      // was negative. Recorded as a defect: a client that took the last frame
      // for an answer would file a verdict nobody produced.
      return row(item, {
        ms,
        status: 200,
        frames,
        source,
        worker,
        requestId,
        lastState,
        lastPhase,
        issues: ["stream ended with no status"],
      });
    }
    return row(item, {
      ms,
      firstMs,
      frames,
      status: 200,
      source,
      worker,
      requestId,
      lastState,
      lastPhase,
      artifactStatus: assessment.status,
      sha: assessment.sha256 || "",
      lvl: assessment.fires_at,
      eng: assessment.engine_version,
      hits: assessment.findings ? assessment.findings.length : 0,
      issues: checkV1(200, assessment, item.purl),
    });
  } catch (err) {
    return row(item, { ms: Date.now() - t0, status: 0, error: err.message || String(err), issues: [err.message || String(err)] });
  }
}

// Yield each JSON line of a streamed body as it arrives.
async function* ndjson(resp) {
  const decoder = new TextDecoder();
  let buffered = "";
  for await (const chunk of resp.body) {
    buffered += decoder.decode(chunk, { stream: true });
    const lines = buffered.split("\n");
    buffered = lines.pop() ?? "";
    for (const line of lines) {
      const trimmed = line.trim();
      if (trimmed) yield JSON.parse(trimmed);
    }
  }
  const tail = buffered.trim();
  if (tail) yield JSON.parse(tail);
}

async function readJson(resp) {
  const buf = new Uint8Array(await resp.arrayBuffer());
  const bytes = buf.length >= 2 && buf[0] === 0x1f && buf[1] === 0x8b ? await gunzip(buf) : buf;
  return JSON.parse(new TextDecoder().decode(bytes));
}

async function gunzip(u8) {
  const stream = new Blob([u8]).stream().pipeThrough(new DecompressionStream("gzip"));
  return new Uint8Array(await new Response(stream).arrayBuffer());
}

const ALLOWED_200 = new Set(["sha", "purl", "lvl", "eng", "why", "hits"]);
// `off` and `line` are documented hit fields (API.md: "off is the byte offset
// of the match within file, and line its 1-based source line"). They were
// missing here, so every response carrying a located hit — which is the useful
// kind — was reported as an API violation. The harness was stale, not the API.
const ALLOWED_HIT = new Set(["id", "crit", "file", "pkg", "desc", "off", "line"]);
const SOURCES = new Set([
  "cache",
  "kv",
  "scan:bloom",
  "scan:analysis",
  "scan:replica",
  "scan:primary",
  "none",
]);
// Every key a v1 decision carries, and every key it may carry — the contract is
// that the shape never moves, so a field appearing or vanishing is a defect
// rather than a variation.
const V1_FIELDS = new Set(["status", "purl", "url", "sha256", "severity", "fires_at", "reason", "findings", "engine_version", "analyzed_at", "cause"]);
const V1_STATUSES = new Set(["analyzed", "unanalyzed", "unavailable"]);
// Why we could not answer. An outage that does not say is one a caller cannot
// write a retry policy against.
const V1_CAUSES = new Set(["saturated", "mixed", "unreachable", "no_workers"]);
const V1_SEVERITIES = new Set(["benign", "suspicious", "hostile", "unknown"]);
const SHA_RE = /^[0-9a-f]{64}$/;
const DOC_STATUS = new Set([200, 202, 400, 401, 413, 415, 422, 404, 429, 503, 504, 500]);

// A v1 assessment, checked as a client would have to read it.
//
// Null fields are omitted to keep responses small. Presence is meaningful for
// optional evidence fields, so clients must branch on the field itself.
function checkV1(status, body, askedPurl) {
  const issues = [];
  if (status !== 200) return issues;
  if (!body || typeof body !== "object") return ["v1 body is not an object"];
  for (const key of Object.keys(body)) if (!V1_FIELDS.has(key)) issues.push(`v1 unexpected ${key}`);
  if (!("status" in body)) issues.push("v1 missing status");
  if (!("severity" in body)) issues.push("v1 missing severity");
  if (!V1_STATUSES.has(body.status)) issues.push(`v1 status ${JSON.stringify(body.status)}`);
  if (!V1_SEVERITIES.has(body.severity)) {
    issues.push(`v1 severity ${JSON.stringify(body.severity)}`);
  }
  if (!Array.isArray(body.findings)) issues.push("v1 findings is not a list");
  // A status that says nothing was found must not carry a level, and one that
  // could not be reached must carry nothing about the artifact at all: reading
  // anything into either is how a caller ends up treating our outage as
  // evidence about a package.
  if (body.status !== "analyzed") {
    if (body.fires_at != null) issues.push(`${body.status} carried fires_at=${body.fires_at}`);
    if (body.severity !== "unknown") issues.push(`${body.status} carried severity=${body.severity}`);
    if (Array.isArray(body.findings) && body.findings.length) {
      issues.push(`${body.status} carried findings`);
    }
    // Checked when present rather than required: an outage relayed from a
    // worker is still an outage, and an older one has no cause to give.
    if ("cause" in body && !V1_CAUSES.has(body.cause)) {
      issues.push(`unavailable cause ${JSON.stringify(body.cause)}`);
    }
  // Clean results commonly omit a null reason; a severity that asks a caller
  // to act must explain why it crossed that threshold.
  } else if (["suspicious", "hostile"].includes(body.severity)
      && (typeof body.reason !== "string" || !body.reason.trim())) {
    issues.push(`${body.severity} missing reason`);
  }
  if (askedPurl && body.purl && body.purl !== askedPurl) {
    issues.push(`answered about ${body.purl}, asked about ${askedPurl}`);
  }
  return issues;
}

function checkApi(status, headers, body, askedPurl, scope) {
  const issues = [];
  const h = headers && typeof headers.get === "function" ? headers : new Headers(headers || {});
  if (!DOC_STATUS.has(status)) issues.push(`status ${status} not in API.md`);
  if (status === 200) {
    // API.md: "public, max-age=… / private if authenticated". Beamline stores
    // its own copy as public because Cloudflare will not hold a private one,
    // and that rewrite once reached the client: an authenticated verdict came
    // back marked cacheable by every shared cache on the way. A fresh reply
    // and a cached one are the same response here, so both are checked.
    const cc = h.get("cache-control") || "";
    if (scope && !cc.startsWith(scope)) {
      issues.push(`cache-control "${cc || "absent"}" should be ${scope} (${h.get("x-beamline-source") || "?"})`);
    }
    return check200(h, body, askedPurl, issues);
  }
  if (status === 202) {
    if (!body || body.state !== "pending") issues.push("202 needs {state:pending}");
    if (body && body.error) issues.push("202 must not use error");
    if (!h.get("retry-after")) issues.push("202 needs Retry-After");
    return issues;
  }
  if (!body || typeof body.error !== "string" || !body.error) issues.push("error body needs error string");
  if (body && body.error === "") issues.push("empty error");
  return issues;
}

function check200(h, body, askedPurl, issues) {
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    issues.push("200 body must be an object");
    return issues;
  }
  for (const k of Object.keys(body)) {
    if (!ALLOWED_200.has(k)) issues.push(`unexpected field ${k}`);
  }
  if (body.ml || body.raw || body.llm) issues.push("cleave/ml/llm must not appear");
  if (!SHA_RE.test(body.sha || "")) issues.push("sha must be 64 hex");
  const hdrSha = (h.get("x-sha256") || "").toLowerCase();
  if (body.sha && !hdrSha) issues.push("missing X-SHA256");
  if (hdrSha && body.sha && hdrSha !== body.sha) issues.push("X-SHA256 != sha");
  if (body.purl != null) {
    if (typeof body.purl !== "string" || !body.purl) issues.push("purl empty");
    else if (askedPurl && body.purl !== askedPurl) issues.push("purl mismatch");
  }
  if (typeof body.lvl !== "number" || !Number.isFinite(body.lvl)) issues.push("lvl required");
  else if (body.lvl < -1) issues.push("lvl < -1");
  if (body.eng != null && (typeof body.eng !== "string" || body.eng === "")) issues.push("eng empty");
  if (body.why != null && (typeof body.why !== "string" || body.why === "")) issues.push("why empty");
  if (body.lvl === -1 && body.hits != null) issues.push("hits forbidden when lvl=-1");
  if (body.hits != null) {
    if (!Array.isArray(body.hits)) issues.push("hits must be an array");
    else if (body.hits.length > 3) issues.push("hits cap is 3");
    else {
      for (const hit of body.hits) issues.push(...checkHit(hit));
    }
  }
  const src = h.get("x-beamline-source") || "";
  if (src && !SOURCES.has(src)) issues.push(`bad X-Beamline-Source ${src}`);
  const ct = h.get("content-type") || "";
  if (!ct.includes("application/json")) issues.push("Content-Type");
  if (!h.get("cache-control")) issues.push("Cache-Control");
  return issues;
}

function checkHit(hit) {
  const issues = [];
  if (!hit || typeof hit !== "object") return ["hit not object"];
  for (const k of Object.keys(hit)) {
    if (!ALLOWED_HIT.has(k)) issues.push(`hit unexpected ${k}`);
  }
  if (typeof hit.id !== "string" || !hit.id) issues.push("hit.id");
  if (hit.crit !== 3 && hit.crit !== 4 && hit.crit !== 5) issues.push("hit.crit must be 3|4|5");
  for (const k of ["file", "pkg", "desc"]) {
    if (hit[k] != null && (typeof hit[k] !== "string" || hit[k] === "")) issues.push(`hit.${k} empty`);
  }
  // Either may be absent — a binary window carries no line structure — but a
  // present one has to be a real position.
  if (hit.off != null && (!Number.isInteger(hit.off) || hit.off < 0)) issues.push("hit.off not a byte offset");
  if (hit.line != null && (!Number.isInteger(hit.line) || hit.line < 1)) issues.push("hit.line not 1-based");
  return issues;
}

function mixJobs(groups, cap) {
  const out = [];
  for (let i = 0; out.length < cap; i++) {
    let added = false;
    for (const g of groups) {
      if (i < g.length) {
        out.push(g[i]);
        added = true;
        if (out.length >= cap) break;
      }
    }
    if (!added) break;
  }
  return out;
}

function repeatJobs(jobs, times) {
  const out = [];
  for (let i = 0; i < times; i++) out.push(...jobs);
  return out;
}

function row(item, extra) {
  const out = { eco: item.eco, purl: item.purl, ...extra };
  out.kind = classify(out);
  logRow(out);
  return out;
}

function classify(r) {
  if (r.issues && r.issues.length) return "bug";
  if (!r.status) return "bug";
  if (r.status === 200) {
    // v1 answers about the corpus in the body: nothing analyzed is a miss and
    // an outage is not an answer at all, both at 200. Reading only the status
    // here would report an outage as a success, which is the exact confusion
    // the four decisions exist to prevent.
    if (r.artifactStatus === "unanalyzed") return "miss";
    if (r.artifactStatus === "unavailable") return "note";
    return "ok";
  }
  // /lookup is read-only, so a 404 is the correct answer for something nothing
  // has analyzed yet — a fact about the corpus, not a defect. It gets its own
  // bucket because the hit rate is the number this run exists to report.
  if (r.status === 404) return "miss";
  if (r.status === 400) return "bug";
  if (r.status >= 500 && r.status !== 503 && r.status !== 504) return "bug";
  return "note";
}

function logRow(r) {
  const tag = r.kind === "bug" ? "BUG" : r.kind === "note" ? "note" : r.kind === "miss" ? "miss" : "ok ";
  const how = r.analyzed ? " analyzed" : "";
  const src = (r.source || "-").padEnd(6);
  const eco = r.eco.padEnd(6);
  const ms = String(r.ms).padStart(6);
  let extra = r.status === 200 ? `lvl=${r.lvl}` : `${r.status} ${r.error || r.state || ""}`;
  if (r.artifactStatus) extra = `${r.artifactStatus} ${extra}`;
  if (r.frames !== undefined) extra += ` frames=${r.frames}${r.firstMs ? ` first=${r.firstMs}ms` : ""}`;
  if (r.requestId) extra += ` request_id=${r.requestId}`;
  if (r.lastState || r.lastPhase) extra += ` last=${r.lastState || "?"}${r.lastPhase ? `:${r.lastPhase}` : ""}`;
  if (r.sha) extra += ` sha=${String(r.sha).slice(0, 12)}`;
  if (r.issues && r.issues.length) extra += ` [${r.issues.join("; ")}]`;
  process.stderr.write(`${tag} ${ms}ms ${src} ${eco} ${r.purl}  ${extra}${how}\n`);
}

// beamline's per-worker race tallies. Null when the endpoint is absent (an
// older deployment) — reported as unavailable rather than as zero, because
// "no work was cancelled" and "nobody counted" look identical otherwise.
async function raceSnapshot() {
  if (!beamlineUrl) return null;
  try {
    const resp = await get(`${beamlineUrl}/_/routes?size=none`, META_TIMEOUT_MS, token ? { authorization: `Bearer ${token}` } : {});
    if (!resp.ok) return null;
    const body = await readJson(resp);
    const out = new Map();
    for (const w of body?.workers || []) if (w.race) out.set(w.worker, w.race);
    return out;
  } catch {
    return null;
  }
}

// after - before, per worker. An isolate recycled mid-run restarts its counters,
// which shows up as a smaller "after"; treat that worker's window as starting
// from zero and say so, rather than reporting a negative count.
function raceDelta(before, after) {
  if (!after) return null;
  const keys = ["started", "won", "never_started", "dropped", "failed"];
  const rows = [];
  let recycled = false;
  for (const [worker, a] of after) {
    const b = (before && before.get(worker)) || null;
    const reset = b && keys.some((k) => (a[k] || 0) < (b[k] || 0));
    if (reset) recycled = true;
    const d = { worker };
    for (const k of keys) d[k] = (a[k] || 0) - (reset || !b ? 0 : b[k] || 0);
    rows.push(d);
  }
  return { rows, recycled };
}

function printRace(delta) {
  if (!delta) {
    process.stdout.write("\nrace     unavailable (beamline has no /_/routes, or it declined)\n");
    return;
  }
  const tot = delta.rows.reduce(
    (a, r) => ({
      started: a.started + r.started,
      won: a.won + r.won,
      never_started: a.never_started + r.never_started,
      dropped: a.dropped + r.dropped,
    }),
    { started: 0, won: 0, never_started: 0, dropped: 0 },
  );
  // Every arm beamline created: the ones it ran, plus the ones the hedge
  // spared. That total is the denominator for "what fraction was wasted".
  const arms = tot.started + tot.never_started;
  const pct = (x) => (arms ? `${((x / arms) * 100).toFixed(1)}%` : "-");
  process.stdout.write(`\nrace     ${arms} arms for ${tot.won} verdicts\n`);
  process.stdout.write(`  spared by hedge  ${tot.never_started} (${pct(tot.never_started)})  never dispatched\n`);
  process.stdout.write(`  cancelled        ${tot.dropped} (${pct(tot.dropped)})  work started, then beaten\n`);
  if (delta.recycled) {
    process.stdout.write("  note: an isolate was recycled mid-run; these undercount\n");
  }
  process.stdout.write("\nby worker\n");
  for (const r of delta.rows.sort((a, b) => b.won - a.won)) {
    process.stdout.write(
      `  ${r.worker.padEnd(34)} won ${String(r.won).padStart(4)}  ran ${String(r.started).padStart(4)}` +
        `  spared ${String(r.never_started).padStart(4)}  cancelled ${String(r.dropped).padStart(4)}` +
        `  failed ${String(r.failed).padStart(3)}\n`,
    );
  }
}

function summarize(rows) {
  const ok = rows.filter((r) => r.kind === "ok");
  const bugs = rows.filter((r) => r.kind === "bug");
  const notes = rows.filter((r) => r.kind === "note");
  const misses = rows.filter((r) => r.kind === "miss");
  const lat = ok.map((r) => r.ms).sort((a, b) => a - b);
  const bySource = countBy(ok, (r) => r.source || "unknown");
  // What the both-keys path cost, beside what the single key cost.
  const paired = rows.filter((r) => r.both && r.ms != null);
  const bothStats = {
    n: paired.length,
    unsupported: paired.filter((r) => r.both.status === 400).length,
    hit: paired.filter((r) => r.both.status === 200).length,
    single: percentile(paired.map((r) => r.ms).sort((a, b) => a - b), 50),
    both: percentile(paired.map((r) => r.both.ms).sort((a, b) => a - b), 50),
  };
  const served = ok.filter((r) => r.source && r.source.startsWith("scan:") && r.worker);
  const byWorker = countBy(served, (r) => r.worker);
  const workerLatency = {};
  for (const w of Object.keys(byWorker)) {
    const lats = served.filter((r) => r.worker === w).map((r) => r.ms).sort((a, b) => a - b);
    workerLatency[w] = { n: lats.length, p50: percentile(lats, 50), p95: percentile(lats, 95), max: lats[lats.length - 1] };
  }
  const byEco = countBy(rows, (r) => r.eco);
  const byKind = countBy(rows, (r) => r.kind);
  return {
    n: rows.length,
    ok: ok.length,
    bugs,
    notes,
    misses,
    bySource,
    bothStats,
    byWorker,
    workerLatency,
    served: served.length,
    byEco,
    byKind,
    latency: {
      p50: percentile(lat, 50),
      p95: percentile(lat, 95),
      p99: percentile(lat, 99),
      max: lat.length ? lat[lat.length - 1] : null,
      n: lat.length,
    },
  };
}

function printReport(rows, summary, feedErrors) {
  const { latency: L } = summary;
  process.stdout.write("\n");
  const known = summary.ok + summary.misses.length;
  const rate = known ? `${Math.round((summary.ok / known) * 100)}%` : "-";
  process.stdout.write(
    `results  ${summary.ok} hit / ${summary.misses.length} miss / ${summary.bugs.length} bug / ${summary.notes.length} note  (n=${summary.n})\n`,
  );
  process.stdout.write(`hit rate ${rate} of ${known} answered lookups\n`);
  process.stdout.write(`latency  p50=${fmtMs(L.p50)} p95=${fmtMs(L.p95)} p99=${fmtMs(L.p99)} max=${fmtMs(L.max)}  (ok n=${L.n})\n`);
  process.stdout.write(`source   ${fmtMap(summary.bySource)}\n`);
  process.stdout.write(`eco      ${fmtMap(summary.byEco)}\n`);
  const b = summary.bothStats;
  if (b && b.n) {
    process.stdout.write(`\nboth-keys ${b.n} probed  ${b.hit} answered  p50 ${b.both}ms (single key p50 ${b.single}ms)\n`);
    if (b.unsupported) {
      process.stdout.write(`  ${b.unsupported} rejected with 400 — this beamline predates the two-key lookup\n`);
    }
  }
  if (summary.served) {
    process.stdout.write(`\nserved   ${summary.served} of ${summary.ok} by a worker (rest: cache or hopper)\n`);
    for (const [w, c] of Object.entries(summary.byWorker).sort((a, b) => b[1] - a[1])) {
      const l = summary.workerLatency[w];
      const share = ((c / summary.served) * 100).toFixed(1);
      process.stdout.write(
        `  ${w.padEnd(34)} ${String(c).padStart(4)} (${share.padStart(5)}%)  p50 ${l.p50}ms  p95 ${l.p95}ms  max ${l.max}ms\n`,
      );
    }
  }
  if (summary.misses.length) {
    process.stdout.write("misses (nothing has analyzed these yet)\n");
    for (const r of summary.misses) process.stdout.write(`  ${r.purl}\n`);
  }
  if (summary.notes.length) {
    process.stdout.write("notes\n");
    for (const r of summary.notes) process.stdout.write(`  ${r.status} ${r.error || ""}  ${r.purl}\n`);
  }
  if (summary.bugs.length) {
    process.stdout.write("bugs\n");
    for (const r of summary.bugs) {
      process.stdout.write(`  ${r.status} ${r.error || r.state || ""}  ${r.purl}${r.issues && r.issues.length ? "  [" + r.issues.join("; ") + "]" : ""}\n`);
    }
  }
  if (feedErrors.length) process.stdout.write(`feed errors: ${feedErrors.length}\n`);
}

function fmtMs(v) {
  return v == null ? "-" : String(v);
}

function fmtMap(obj) {
  return Object.entries(obj)
    .map(([k, v]) => `${k}=${v}`)
    .join(" ") || "-";
}

// A miss is a valid answer for the read-only lookup route: it means the
// package is not in the corpus yet. Count it as a successful request here,
// while keeping the hit/miss split in the detailed report below.
function routeMetrics(rows) {
  const successful = rows.filter((r) => r.kind === "ok" || r.kind === "miss");
  const latency = rows
    .map((r) => r.ms)
    .filter((ms) => Number.isFinite(ms))
    .sort((a, b) => a - b);
  const byEco = {};
  for (const eco of new Set(rows.map((r) => r.eco))) {
    const group = rows.filter((r) => r.eco === eco);
    const good = group.filter((r) => r.kind === "ok" || r.kind === "miss");
    const lats = group
      .map((r) => r.ms)
      .filter((ms) => Number.isFinite(ms))
      .sort((a, b) => a - b);
    byEco[eco] = {
      n: group.length,
      success: good.length,
      successRate: group.length ? good.length / group.length : 0,
      p90: percentile(lats, 90),
    };
  }
  return {
    n: rows.length,
    success: successful.length,
    successRate: rows.length ? successful.length / rows.length : 0,
    p90: percentile(latency, 90),
    byEco,
  };
}

function printRouteReport(route, rows, summary, feedErrors) {
  const metrics = routeMetrics(rows);
  const pct = (rate) => `${(rate * 100).toFixed(1)}%`;
  process.stdout.write(`\n${route} metrics  success rate ${metrics.success}/${metrics.n} (${pct(metrics.successRate)})  p90 latency ${fmtMs(metrics.p90)}ms\n`);
  for (const [eco, m] of Object.entries(metrics.byEco).sort()) {
    process.stdout.write(`  ${eco.padEnd(6)} ${m.success}/${m.n} (${pct(m.successRate)})  p90 ${fmtMs(m.p90)}ms\n`);
  }
  printReport(rows, summary, feedErrors);
}

function countBy(rows, fn) {
  const out = {};
  for (const r of rows) {
    const k = fn(r);
    out[k] = (out[k] || 0) + 1;
  }
  return out;
}

async function writeOut(path, data) {
  const { writeFile } = await import("node:fs/promises");
  await writeFile(path, JSON.stringify(data, null, 2));
  process.stderr.write(`wrote ${path}\n`);
}

function job(eco, purl) {
  return { eco, purl };
}

function npmPurl(name, version) {
  const n = name.startsWith("@") ? `%40${name.slice(1)}` : name;
  return `pkg:npm/${n}@${version}`;
}

function pypiPurl(name, version) {
  return `pkg:pypi/${name}@${version}`;
}

function cargoPurl(name, version) {
  return `pkg:cargo/${name}@${version}`;
}

function golangPurl(name, version) {
  return `pkg:golang/${name}@${version}`;
}

function encodeNpmName(name) {
  if (name.startsWith("@")) {
    const i = name.indexOf("/");
    if (i > 0) return `${encodeURIComponent(name.slice(0, i))}/${encodeURIComponent(name.slice(i + 1))}`;
  }
  return encodeURIComponent(name);
}

function parseNpmChanges(body) {
  const names = [];
  const seen = new Set();
  for (const r of body.results || []) {
    const id = r.id;
    if (!id || id.startsWith("_") || seen.has(id)) continue;
    seen.add(id);
    names.push(id);
  }
  return names;
}

function parsePypiRss(xml) {
  const flat = String(xml).replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, "$1");
  const items = [];
  const re = /<item>[\s\S]*?<title>([^<]+)<\/title>/g;
  let m;
  while ((m = re.exec(flat))) {
    const parts = m[1].trim().split(/\s+/);
    if (parts.length < 2) continue;
    items.push({ name: parts[0], version: parts.slice(1).join(" ") });
  }
  return items;
}

function parseGoIndex(text) {
  const out = [];
  for (const line of text.split("\n")) {
    if (!line.trim()) continue;
    let e;
    try {
      e = JSON.parse(line);
    } catch {
      continue;
    }
    if (e.Path && e.Version) out.push({ name: e.Path, version: e.Version });
  }
  return out;
}

function parseCratesIndexCommit(subject) {
  const raw = String(subject || "").trim();
  const sep = " crate `";
  const i = raw.indexOf(sep);
  if (i < 0) return { name: "", changed: false };
  const verb = raw.slice(0, i);
  const rest = raw.slice(i + sep.length);
  const end = rest.indexOf("`");
  if (end < 0) return { name: "", changed: false };
  const name = rest.slice(0, end);
  if (!name) return { name: "", changed: false };
  return { name, changed: verb === "Create" || verb === "Update" };
}

function cratesSparsePath(name) {
  const n = String(name || "").toLowerCase();
  switch (n.length) {
    case 0:
      return "";
    case 1:
      return `1/${n}`;
    case 2:
      return `2/${n}`;
    case 3:
      return `3/${n.slice(0, 1)}/${n}`;
    default:
      return `${n.slice(0, 2)}/${n.slice(2, 4)}/${n}`;
  }
}

function percentile(sorted, p) {
  if (!sorted.length) return null;
  const i = Math.min(sorted.length - 1, Math.ceil((p / 100) * sorted.length) - 1);
  return sorted[i];
}

async function pool(items, width, fn) {
  const out = Array.from({ length: items.length });
  let i = 0;
  async function worker() {
    while (i < items.length) {
      const idx = i++;
      out[idx] = await fn(items[idx]);
    }
  }
  await Promise.all(Array.from({ length: Math.min(width, items.length) }, worker));
  return out;
}

async function get(url, ms, extra = {}, method = "GET", body) {
  const headers = { "user-agent": UA, ...extra };
  // Set only when there is one: a GET carrying an explicit `body: undefined` is
  // an invalid fetch init, not an empty request.
  const init = { method, headers, signal: AbortSignal.timeout(ms) };
  if (body !== undefined) init.body = body;
  const resp = await fetch(url, init);
  const local = beamlineUrl && url.startsWith(beamlineUrl);
  if (!local && !resp.ok) {
    const t = await resp.text().catch(() => "");
    throw new Error(`${url} HTTP ${resp.status}${t ? `: ${t.slice(0, 180)}` : ""}`);
  }
  return resp;
}

// The three shapes the per-package pass never reaches, checked once per run.
//
// Every row above asks about one PURL by coordinate. That leaves the list reply,
// the digest-only key, and the whole byte-upload route untested — and the upload
// route is the one that has broken twice: once refusing a `curl -T` for its
// content-type, once answering `empty_artifact` to every bodyless POST because a
// plain POST sends `Content-Length: 0`. Both shipped. Neither would have.
//
// Returns a list of complaints, folded into the run's bugs so a failure here
// exits non-zero like any other.
async function contractProbe() {
  const issues = [];
  const auth = token ? { authorization: `Bearer ${token}` } : {};
  const call = async (path, method = "GET", body, extra = {}) => {
    const resp = await get(`${beamlineUrl}${path}`, timeoutMs + 10_000, { ...auth, ...extra }, method, body);
    return { status: resp.status, body: await readJson(resp) };
  };

  // A list question gets a list answer, in the order asked, each entry naming
  // the package it is about — which is the only way a caller can tell which
  // answer belongs to which of fifty questions.
  const pair = ["pkg:npm/left-pad@1.3.0", "pkg:pypi/requests@2.31.0"];
  try {
    const q = pair.map((p) => `purl=${encodeURIComponent(p)}`).join("&");
    const { status, body } = await call(`/v1/lookup?${q}`);
    if (status !== 200) issues.push(`list lookup: HTTP ${status}`);
    else if (!Array.isArray(body)) issues.push("list lookup: two PURLs did not answer with a list");
    else if (body.length !== pair.length) issues.push(`list lookup: asked ${pair.length}, got ${body.length}`);
    else {
      body.forEach((entry, i) => {
        issues.push(...checkV1(200, entry, pair[i]));
      });
    }
  } catch (e) {
    issues.push(`list lookup: ${e.message || e}`);
  }

  // A spelling the canonicalizer would rewrite. PyPI folds `.` and `_` to `-`
  // per PEP 503, so this is the exact shape that came back answered about a
  // package the caller had not named.
  try {
    const odd = "pkg:pypi/zope.interface@6.1";
    const { status, body } = await call(`/v1/lookup?purl=${encodeURIComponent(odd)}`);
    if (status !== 200) issues.push(`spelling: HTTP ${status}`);
    else issues.push(...checkV1(200, body, odd));
  } catch (e) {
    issues.push(`spelling: ${e.message || e}`);
  }

  // The upload route. A tiny artifact of our own making, so the run neither
  // depends on a registry nor spends a real analysis slot on something large.
  try {
    const artifact = Buffer.from(`stress-probe-${process.pid}-${Date.now()}\n`);
    const resp = await get(`${beamlineUrl}/v1/analyze`, timeoutMs + 10_000, auth, "POST", artifact);
    const status = resp.status;
    if (status !== 200) {
      const body = await readJson(resp).catch(() => null);
      issues.push(`upload: HTTP ${status} ${JSON.stringify(body?.error || body).slice(0, 120)}`);
    } else {
      // v1 analyze streams progress and the final decision as NDJSON. The
      // package pass already reads that shape; the contract probe must do the
      // same instead of trying to parse the whole body as one JSON document.
      let assessment = null;
      for await (const frame of ndjson(resp)) {
        if (frame.status) assessment = frame;
      }
      if (!assessment) {
        issues.push("upload: stream ended with no status");
      } else {
        issues.push(...checkV1(200, assessment, null));
        // Bytes have no coordinate, and the digest is not one: a sha256 in the
        // `purl` field is how the two routes stop agreeing.
        if (assessment.purl != null) issues.push(`upload: answered with purl ${assessment.purl}`);
        if (!/^[0-9a-f]{64}$/.test(assessment.sha256 || "")) issues.push("upload: no sha256");
      }
    }
  } catch (e) {
    issues.push(`upload: ${e.message || e}`);
  }

  // A bodyless POST that names nothing is the caller's mistake, and must say so
  // rather than being read as an empty upload.
  try {
    const { status, body } = await call("/v1/analyze", "POST");
    if (status !== 400) issues.push(`empty POST: HTTP ${status}, expected 400`);
    else if (body?.error?.code !== "missing_package") {
      issues.push(`empty POST: ${JSON.stringify(body?.error?.code)}, expected missing_package`);
    }
  } catch (e) {
    issues.push(`empty POST: ${e.message || e}`);
  }

  process.stderr.write(
    issues.length
      ? `contract ${issues.length} problem(s)\n${issues.map((i) => `  ${i}\n`).join("")}`
      : "contract ok (list, spelling, upload, empty POST)\n",
  );
  return issues;
}

function trimSlash(s) {
  return String(s || "").replace(/\/+$/, "");
}

export const _test = {
  checkV1,
  npmPurl,
  pypiPurl,
  cargoPurl,
  golangPurl,
  parseNpmChanges,
  parsePypiRss,
  parseGoIndex,
  parseCratesIndexCommit,
  cratesSparsePath,
  percentile,
  routeMetrics,
  classify,
  POPULAR,
  popularJobs,
  repeatJobs,
  checkApi,
  mixJobs,
};
