#!/usr/bin/env node
// route-ab — does the router beat picking a worker at random?
//
// route-bench.mjs asks the same question by timing one PURL on every worker.
// It cannot: the first arm publishes its verdict and every later arm reads it
// back from the index, so no trial is ever all-fresh. See the note there.
//
// Both scripts need `pin` to actually select a worker. It did not until
// 2026-09-02 — a pinned request was routed like any other — so a run from
// before that fix compared the router with itself and its control arm is void.
//
// This trades the paired counterfactual for a corpus that stays clean. Each
// PURL is analysed exactly once, by a worker chosen either at random (control)
// or by the router (treatment), and the two latency distributions are compared.
// Nothing is measured twice, so nothing can be contaminated by a measurement.
//
//   node scripts/route-ab.mjs --file purls.txt [--concurrency 2] [--seed 1]
//
// BEAMLINE  base URL   (default https://poc.api.isotope13.ai)
// TOKEN     bearer     (default: first line of ~/.tok/beamline)
//
// Only analyses scan actually served are scored. A PURL this fleet has already
// seen answers from a cache or an index and times that, not a worker, so feed
// it releases published minutes ago.
//
// Under load the two arms fail differently and the difference is the point.
// capability() drops a worker with no free slots before ranking sees it, so the
// routed arm quietly picks somebody else while the control arm — holding one
// pinned candidate — is refused. Those refusals are the cost of that assignment
// and are counted, not discarded: an arm that is fast only because a third of
// it never ran is not fast.
import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

const BEAMLINE = (process.env.BEAMLINE || "https://poc.api.isotope13.ai").replace(/\/$/, "");
const TOKEN =
  process.env.TOKEN ||
  (() => {
    try {
      return readFileSync(join(homedir(), ".tok", "beamline"), "utf8").split("\n").find((l) => l.trim() && !l.startsWith("#"))?.trim() || "";
    } catch {
      return "";
    }
  })();

const args = process.argv.slice(2);
const flag = (name, fallback) => {
  const i = args.indexOf(name);
  return i >= 0 ? Number(args[i + 1]) : fallback;
};
const concurrency = Math.max(1, flag("--concurrency", 2));
const seed = flag("--seed", 1);
const fileArg = args.indexOf("--file");
const purls = fileArg >= 0
  ? readFileSync(args[fileArg + 1], "utf8").split("\n").map((l) => l.trim()).filter((l) => l && !l.startsWith("#"))
  : args.filter((a) => a.startsWith("pkg:"));

if (!purls.length) {
  console.error("usage: route-ab.mjs <purl>... | --file purls.txt [--concurrency N] [--seed N]");
  process.exit(2);
}

const headers = TOKEN ? { authorization: `Bearer ${TOKEN}` } : {};

// Seeded so a run can be repeated against the same assignment. mulberry32:
// small, uniform enough to split a few dozen PURLs into two arms.
function rng(state) {
  return () => {
    state = (state + 0x6d2b79f5) | 0;
    let t = Math.imul(state ^ (state >>> 15), 1 | state);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

// One timed analysis. `pin` null lets the router choose.
async function analyze(purl, pin) {
  const t0 = Date.now();
  try {
    const res = await fetch(`${BEAMLINE}/v1/analyze?purl=${encodeURIComponent(purl)}`, {
      method: "POST",
      headers: pin ? { ...headers, "x-beamline-pin": pin } : headers,
    });
    const text = await res.text();
    const ms = Date.now() - t0;
    // v1 answers NDJSON: progress frames then one decision. Only the last
    // non-empty line carries a verdict.
    const last = text.trimEnd().split("\n").filter(Boolean).pop() || "";
    let body = {};
    try {
      body = JSON.parse(last);
    } catch {
      body = {};
    }
    return {
      ms,
      status: res.status,
      source: res.headers.get("x-beamline-source"),
      // Always the worker that answered, never the one asked for. Recording
      // the request's own intention is how a silently ignored pin got written
      // up as a measurement of a worker that never saw the job.
      worker: res.headers.get("x-beamline-worker"),
      asked: pin,
      // v1 reports an outage inside a 200 as well as by status, so read both.
      cause: body.cause ?? body.error?.code ?? (body.status === "unavailable" ? "unavailable" : null),
      unavailable: body.status === "unavailable" || res.status >= 400,
      lvl: body.lvl ?? body.fires_at,
    };
  } catch (err) {
    return { ms: Date.now() - t0, status: 0, source: null, worker: pin, error: String(err) };
  }
}

async function pool(items, limit, fn) {
  const out = Array.from({ length: items.length });
  let next = 0;
  await Promise.all(
    Array.from({ length: Math.min(limit, items.length) }, async () => {
      for (let i = next++; i < items.length; i = next++) out[i] = await fn(items[i]);
    }),
  );
  return out;
}

function percentile(sorted, p) {
  if (!sorted.length) return null;
  const i = Math.min(sorted.length - 1, Math.ceil((p / 100) * sorted.length) - 1);
  return sorted[i];
}

// How a set of rows was answered, as `key=count` pairs, or "-" for none.
function tally(rows, key) {
  const counts = {};
  for (const r of rows) counts[key(r)] = (counts[key(r)] || 0) + 1;
  return Object.entries(counts).map(([k, v]) => `${k}=${v}`).join(" ") || "-";
}

function stats(rows) {
  const ms = rows.map((r) => r.ms).sort((a, b) => a - b);
  return {
    n: ms.length,
    p50: percentile(ms, 50),
    p90: percentile(ms, 90),
    mean: ms.length ? Math.round(ms.reduce((a, b) => a + b, 0) / ms.length) : null,
  };
}

const plan = await fetch(`${BEAMLINE}/_/routes?size=none`, { headers }).then((r) => r.json());
const workers = plan.workers.filter((w) => w.breaker === "closed").map((w) => w.worker);
if (!workers.length) {
  console.error("no workers with a closed breaker");
  process.exit(1);
}

const random = rng(seed);
// Alternate arms over a shuffled corpus rather than flipping a coin per PURL,
// so the two arms stay the same size and neither gets the whole of one
// ecosystem: the feeds hand them over grouped.
const shuffled = purls.map((purl) => ({ purl, key: random() })).sort((a, b) => a.key - b.key);
const jobs = shuffled.map(({ purl }, i) => ({
  purl,
  arm: i % 2 === 0 ? "routed" : "random",
  pin: i % 2 === 0 ? null : workers[Math.floor(random() * workers.length)],
}));

console.log(`beamline ${BEAMLINE}`);
console.log(`workers  ${workers.join(", ")}`);
console.log(`${jobs.length} PURLs, concurrency ${concurrency}, seed ${seed}\n`);

const rows = await pool(jobs, concurrency, async (job) => {
  const r = await analyze(job.purl, job.pin);
  console.log(`  ${job.arm.padEnd(6)} ${String(r.ms).padStart(7)}ms ${(r.source || "-").padEnd(14)} ${r.worker || "-"}  ${job.purl}`);
  return { ...job, ...r };
});

// --- scoring -------------------------------------------------------------
const strayed = rows.filter((r) => r.asked && r.worker && r.worker !== r.asked);
if (strayed.length) {
  console.log(`\n${strayed.length}/${rows.filter((r) => r.asked).length} pinned analyses were served by another worker.`);
  console.log("The control arm is not a control. Check that this beamline honours X-Beamline-Pin.");
}

for (const arm of ["routed", "random"]) {
  const mine = rows.filter((r) => r.arm === arm);
  const refused = mine.filter((r) => r.unavailable || r.status === 0);
  const why = tally(refused, (r) => r.cause || `status:${r.status}`);
  console.log(`${arm.padEnd(6)} refused ${refused.length}/${mine.length}  ${why}`);
}

// An outage answers in a second or two and says so inside a 200, wearing the
// same scan:analysis source as a real verdict. Timing one as an analysis is the
// contamination this whole script exists to avoid, so refusals are counted
// above and excluded here.
const scored = rows.filter((r) => r.status === 200 && r.source === "scan:analysis" && !r.unavailable);
console.log(`\n${scored.length}/${rows.length} analyses scan-served and scored`);
console.log(`sources ${tally(rows, (r) => r.source || `status:${r.status}`)}\n`);
if (!scored.length) {
  console.log("Nothing to score: nothing reached a worker. Feed it newer releases.");
  process.exit(0);
}

const routed = stats(scored.filter((r) => r.arm === "routed"));
const control = stats(scored.filter((r) => r.arm === "random"));
const show = (label, s) =>
  console.log(
    s.n ? `${label.padEnd(8)} n=${String(s.n).padStart(3)}  p50 ${s.p50}ms  p90 ${s.p90}ms  mean ${s.mean}ms` : `${label.padEnd(8)} nothing scored`,
  );
show("routed", routed);
show("random", control);
if (routed.n && control.n) {
  const d = control.p50 - routed.p50;
  console.log(`\nrouter is ${d >= 0 ? "faster" : "SLOWER"} than random by ${Math.abs(d)}ms at p50 (${((d / control.p50) * 100).toFixed(1)}%)`);
  console.log("Arms are small; treat a difference under the p50 spread below as noise.");
}

console.log("\nwhere each arm landed");
for (const arm of ["routed", "random"]) {
  const picks = {};
  for (const r of scored.filter((x) => x.arm === arm)) picks[r.worker || "?"] = (picks[r.worker || "?"] || 0) + 1;
  console.log(`  ${arm.padEnd(6)} ${Object.entries(picks).sort((a, b) => b[1] - a[1]).map(([w, c]) => `${w}=${c}`).join(" ") || "-"}`);
}
console.log("\nper-worker service time, both arms pooled");
for (const w of workers) {
  const s = stats(scored.filter((r) => r.worker === w));
  if (s.n) console.log(`  ${w.padEnd(24)} n=${String(s.n).padStart(3)}  p50 ${s.p50}ms  p90 ${s.p90}ms`);
}
