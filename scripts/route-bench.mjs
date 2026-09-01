#!/usr/bin/env node
// route-bench — does the predicted-fastest worker actually win?
//
// For each PURL: read beamline's prediction for every worker, then time that
// PURL on every worker by pinning the route, then let the router choose freely.
// Nothing here trusts the router's own account of itself — the pinned runs are
// the counterfactual that says what the alternatives would have cost.
//
//   node scripts/route-bench.mjs pkg:pypi/idna@3.7 pkg:cargo/serde@1.0.210
//   node scripts/route-bench.mjs --file purls.txt --trials 2
//
// BEAMLINE  base URL          (default https://poc.api.isotope13.ai)
// TOKEN     bearer            (default: first line of ~/.tok/beamline)
//
// Only trials scan actually served are scored: a verdict answered from
// beamline's cache or hopper's index timed the index, not the worker, and
// counting it would make every worker look identically fast.
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
const trials = Number(args[args.indexOf("--trials") + 1]) || 1;
const fileArg = args.indexOf("--file");
const purls = fileArg >= 0
  ? readFileSync(args[fileArg + 1], "utf8").split("\n").map((l) => l.trim()).filter((l) => l && !l.startsWith("#"))
  : args.filter((a) => a.startsWith("pkg:"));

if (!purls.length) {
  console.error("usage: route-bench.mjs <purl>... | --file purls.txt [--trials N]");
  process.exit(2);
}

const headers = TOKEN ? { authorization: `Bearer ${TOKEN}` } : {};

async function routes() {
  const res = await fetch(`${BEAMLINE}/_/routes?size=none`, { headers });
  if (!res.ok) throw new Error(`/_/routes ${res.status}: ${await res.text()}`);
  return res.json();
}

// One timed analysis. `pin` null lets the router choose.
async function trial(purl, pin) {
  const t0 = Date.now();
  const res = await fetch(`${BEAMLINE}/analyze?purl=${encodeURIComponent(purl)}`, {
    method: "POST",
    headers: pin ? { ...headers, "x-beamline-pin": pin } : headers,
  });
  const ms = Date.now() - t0;
  const body = await res.json().catch(() => ({}));
  return { ms, status: res.status, source: res.headers.get("x-beamline-source"), lvl: body.lvl };
}

const plan = await routes();
const workers = plan.workers.filter((w) => w.breaker === "closed").map((w) => w.worker);
const predicted = new Map(plan.routes[0].dispatch.map((d) => [d.worker, d.est_ms]));
for (const w of workers) if (!predicted.has(w)) predicted.set(w, null);

console.log(`beamline ${BEAMLINE}`);
console.log(`workers  ${workers.join(", ")}`);
console.log(`predicted (unsized): ${[...predicted].map(([w, e]) => `${w}=${e ?? "?"}ms`).join("  ")}`);
console.log(`informed=${plan.routes[0].informed}\n`);

const rows = [];
for (const purl of purls) {
  for (let t = 0; t < trials; t++) {
    const timings = new Map();
    for (const w of workers) {
      const r = await trial(purl, w);
      timings.set(w, r);
      console.log(`  ${purl} @${w} ${r.ms}ms status=${r.status} src=${r.source}`);
    }
    const routed = await trial(purl, null);
    console.log(`  ${purl} @routed ${routed.ms}ms status=${routed.status} src=${routed.source}\n`);
    rows.push({ purl, timings, routed });
  }
}

// --- scoring -------------------------------------------------------------
// A trial counts only if every arm was genuinely analyzed by a worker.
const scored = rows.filter((r) => [...r.timings.values()].every((v) => v.source === "scan" && v.status === 200));
console.log(`${scored.length}/${rows.length} trials scan-served and scored\n`);
if (!scored.length) {
  console.log("Nothing to score: every trial was answered from cache or hopper.");
  console.log("Pick releases this fleet has not analyzed yet — poppy's DB knows which.");
  process.exit(0);
}

let pickedBest = 0;
const err = [];
for (const { purl, timings } of scored) {
  const actual = [...timings].sort((a, b) => a[1].ms - b[1].ms);
  const fastest = actual[0][0];
  const favourite = [...predicted].filter(([w]) => timings.has(w)).sort((a, b) => (a[1] ?? Infinity) - (b[1] ?? Infinity))[0][0];
  if (favourite === fastest) pickedBest++;
  for (const [w, r] of timings) {
    const p = predicted.get(w);
    if (p != null) err.push(Math.abs(p - r.ms));
  }
  const spread = actual[actual.length - 1][1].ms - actual[0][1].ms;
  console.log(`${purl}: fastest=${fastest} favourite=${favourite} ${favourite === fastest ? "HIT " : "MISS"} spread=${spread}ms`);
}
const mae = Math.round(err.reduce((a, b) => a + b, 0) / err.length);
console.log(`\nfavourite was fastest: ${pickedBest}/${scored.length}`);
console.log(`mean absolute prediction error: ${mae}ms`);
// The honest null hypothesis: with N workers, picking at random is 1/N.
console.log(`random baseline would be ~${(100 / workers.length).toFixed(0)}%`);
