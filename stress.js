#!/usr/bin/env node
// Pull recently published PURLs the same way forager does, then time Beamline.
//
//   N=6 CONCURRENCY=2 BEAMLINE_URL=http://127.0.0.1:8080 node stress.js
//
// Feeds: npm replicate _changes, PyPI updates RSS, crates.io-index commits
// (sparse version lookup), Go module index.

import { pathToFileURL } from "node:url";
import { resolve } from "node:path";

const UA = "beamline-stress/1.0 (+https://github.com/isotope13-dev/forager)";
const DEFAULT_N = 6;
const DEFAULT_CONCURRENCY = 2;
const META_TIMEOUT_MS = 20_000;
const GO_WINDOWS_MS = [3_600_000, 6 * 3_600_000, 24 * 3_600_000, 7 * 24 * 3_600_000];

const n = Math.max(1, Number(process.env.N) || DEFAULT_N);
const samples = Math.max(0, Number(process.env.SAMPLES) || 0);
const concurrency = Math.max(1, Number(process.env.CONCURRENCY) || DEFAULT_CONCURRENCY);
const beamlineUrl = trimSlash(process.env.BEAMLINE_URL);
const token = (process.env.BEAMLINE_TOKEN || "").trim();
// SCAN_URL may list several interchangeable workers; probe the first.
const scanUrl = trimSlash((process.env.SCAN_URL || "").split(",")[0]);
const hopperUrl = trimSlash(process.env.HOPPER_URL);
const outPath = process.env.STRESS_OUT || "";
const timeoutMs = Number(process.env.SCAN_TIMEOUT_MS) || 1_800_000;

const isMain = process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href;
if (isMain) {
  main().catch((err) => {
    process.stderr.write(`${err && err.stack ? err.stack : err}\n`);
    process.exit(1);
  });
}

async function main() {
  if (!beamlineUrl) {
    process.stderr.write("BEAMLINE_URL is required (make stress-test sets it)\n");
    process.exit(2);
  }
  if (!scanUrl || !hopperUrl) {
    process.stderr.write("HOPPER_URL and SCAN_URL are required\n");
    process.exit(2);
  }

  process.stderr.write(`beamline ${beamlineUrl}\nscan     ${scanUrl}\nhopper   ${hopperUrl}\nN=${n}${samples ? ` SAMPLES=${samples}` : ""} concurrency=${concurrency}\n`);
  await pingBackends();

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
  const rows = await pool(jobs, concurrency, submit);
  const summary = summarize(rows);
  printReport(rows, summary, feedErrors);
  if (outPath) await writeOut(outPath, { scanUrl, hopperUrl, beamlineUrl, rows, summary });
  process.exit(summary.bugs.length ? 1 : 0);
}

async function named(eco, fn) {
  const jobs = await fn(n);
  process.stderr.write(`  ${eco}: ${jobs.length}\n`);
  return { eco, jobs };
}

async function pingBackends() {
  const beam = await probe(`${beamlineUrl}/healthz`);
  const scan = await probe(`${scanUrl}/_/health`);
  const hopper = await probe(`${hopperUrl}/healthz`);
  const hopperAlt = hopper === "ok" ? hopper : await probe(`${hopperUrl}/_/health`);
  process.stderr.write(`health   beamline=${beam} scan=${scan} hopper=${hopperAlt}\n`);
  if (beam !== "ok") throw new Error(`beamline healthz: ${beam}`);
  if (scan !== "ok" && scan !== "saturated" && scan !== "degraded") {
    process.stderr.write(`warning: scan health is ${scan}\n`);
  }
  try {
    const info = await get(`${scanUrl}/_/info`, 4000).then((r) => r.json());
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

async function probe(url) {
  try {
    const resp = await get(url, 4000);
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

async function submit(item) {
  const url = `${beamlineUrl}/lookup?purl=${encodeURIComponent(item.purl)}`;
  const headers = { "accept-encoding": "gzip" };
  if (token) headers.authorization = `Bearer ${token}`;
  const t0 = Date.now();
  try {
    const resp = await get(url, timeoutMs + 10_000, headers);
    const ms = Date.now() - t0;
    const body = await readJson(resp);
    const issues = checkApi(resp.status, resp.headers, body, item.purl);
    return row(item, {
      ms,
      status: resp.status,
      source: resp.headers.get("x-beamline-source") || "",
      sha: (body && body.sha) || resp.headers.get("x-sha256") || "",
      encoding: resp.headers.get("content-encoding") || "",
      error: body && body.error,
      detail: body && body.detail,
      state: body && body.state,
      lvl: body && body.lvl,
      eng: body && body.eng,
      hits: body && body.hits ? body.hits.length : 0,
      issues,
    });
  } catch (err) {
    return row(item, { ms: Date.now() - t0, status: 0, error: err.message || String(err), issues: [err.message || String(err)] });
  }
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
const ALLOWED_HIT = new Set(["id", "crit", "file", "pkg", "desc"]);
const SOURCES = new Set(["cache", "scan-cache", "bloom", "hopper", "scan"]);
const SHA_RE = /^[0-9a-f]{64}$/;
const DOC_STATUS = new Set([200, 202, 400, 401, 413, 415, 422, 404, 429, 503, 504, 500]);

function checkApi(status, headers, body, askedPurl) {
  const issues = [];
  const h = headers && typeof headers.get === "function" ? headers : new Headers(headers || {});
  if (!DOC_STATUS.has(status)) issues.push(`status ${status} not in API.md`);
  if (status === 200) return check200(h, body, askedPurl, issues);
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

function row(item, extra) {
  const out = { eco: item.eco, purl: item.purl, ...extra };
  out.kind = classify(out);
  logRow(out);
  return out;
}

function classify(r) {
  if (r.issues && r.issues.length) return "bug";
  if (!r.status) return "bug";
  if (r.status === 200) return "ok";
  if (r.status === 400 || r.status === 404) return "bug";
  if (r.status >= 500 && r.status !== 503 && r.status !== 504) return "bug";
  return "note";
}

function logRow(r) {
  const tag = r.kind === "bug" ? "BUG" : r.kind === "note" ? "note" : "ok ";
  const src = (r.source || "-").padEnd(6);
  const eco = r.eco.padEnd(6);
  const ms = String(r.ms).padStart(6);
  let extra = r.status === 200 ? `lvl=${r.lvl}` : `${r.status} ${r.error || r.state || ""}`;
  if (r.sha) extra += ` sha=${String(r.sha).slice(0, 12)}`;
  if (r.issues && r.issues.length) extra += ` [${r.issues.join("; ")}]`;
  process.stderr.write(`${tag} ${ms}ms ${src} ${eco} ${r.purl}  ${extra}\n`);
}

function summarize(rows) {
  const ok = rows.filter((r) => r.kind === "ok");
  const bugs = rows.filter((r) => r.kind === "bug");
  const notes = rows.filter((r) => r.kind === "note");
  const lat = ok.map((r) => r.ms).sort((a, b) => a - b);
  const bySource = countBy(ok, (r) => r.source || "unknown");
  const byEco = countBy(rows, (r) => r.eco);
  const byKind = countBy(rows, (r) => r.kind);
  return {
    n: rows.length,
    ok: ok.length,
    bugs,
    notes,
    bySource,
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
  process.stdout.write(`results  ${summary.ok} ok / ${summary.bugs.length} bug / ${summary.notes.length} note  (n=${summary.n})\n`);
  process.stdout.write(`latency  p50=${fmtMs(L.p50)} p95=${fmtMs(L.p95)} p99=${fmtMs(L.p99)} max=${fmtMs(L.max)}  (ok n=${L.n})\n`);
  process.stdout.write(`source   ${fmtMap(summary.bySource)}\n`);
  process.stdout.write(`eco      ${fmtMap(summary.byEco)}\n`);
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

async function get(url, ms, extra = {}) {
  const headers = { "user-agent": UA, ...extra };
  const resp = await fetch(url, { headers, signal: AbortSignal.timeout(ms) });
  const local = beamlineUrl && url.startsWith(beamlineUrl);
  if (!local && !resp.ok) {
    const t = await resp.text().catch(() => "");
    throw new Error(`${url} HTTP ${resp.status}${t ? `: ${t.slice(0, 180)}` : ""}`);
  }
  return resp;
}

function trimSlash(s) {
  return String(s || "").replace(/\/+$/, "");
}

export const _test = {
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
  classify,
  checkApi,
  mixJobs,
};
