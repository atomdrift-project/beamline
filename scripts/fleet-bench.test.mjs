import assert from "node:assert/strict";
import { test } from "node:test";
import { _test } from "./fleet-bench.mjs";

const { deal, dedupe, goEscape, parsePurl, scored, summarize, width } = _test;

test("deal gives every set the same ecosystem mix and near-equal bytes", () => {
  const items = [];
  for (let i = 1; i <= 12; i++) items.push({ eco: "npm", purl: `pkg:npm/a${i}@1`, bytes: i * 1000 });
  for (let i = 1; i <= 8; i++) items.push({ eco: "golang", purl: `pkg:golang/x/b${i}@v1`, bytes: i * 50_000 });
  const sets = deal(items, [5, 5, 5, 5]);
  assert.equal(sets.flat().length, items.length);
  for (const set of sets) {
    assert.equal(set.filter((c) => c.eco === "npm").length, 3);
    assert.equal(set.filter((c) => c.eco === "golang").length, 2);
  }
  const totals = sets.map((set) => set.reduce((a, c) => a + c.bytes, 0));
  assert.ok(Math.max(...totals) - Math.min(...totals) <= 50_000 + 3000, `unbalanced: ${totals}`);
});

test("goEscape follows the module proxy's case encoding", () => {
  assert.equal(goEscape("github.com/BurntSushi/toml"), "github.com/!burnt!sushi/toml");
  assert.equal(goEscape("v1.4.0"), "v1.4.0");
});

test("parsePurl decodes scoped npm names", () => {
  assert.deepEqual(parsePurl("pkg:npm/%40babel/core@7.24.0"), { type: "npm", name: "@babel/core", version: "7.24.0" });
  assert.equal(parsePurl("pkg:npm/noversion"), null);
});

test("only a pinned, fresh analysis is scored", () => {
  const ok = { http: 200, source: "scan:analysis", status: "analyzed", answered: "w1" };
  assert.equal(scored(ok, "w1"), true);
  assert.equal(scored({ ...ok, answered: "w2" }, "w1"), false);
  assert.equal(scored({ ...ok, source: "scan:primary" }, "w1"), false);
  assert.equal(scored({ ...ok, status: "unavailable" }, "w1"), false);
});

test("summarize separates the sustained rate from the drain", () => {
  const row = (start, ms, bytes = 1 << 20) => ({ eco: "npm", bytes, start, ms, scored: true, source: "scan:analysis", status: "analyzed", answered: "w1" });
  // Fed until 60s: two finished by then. The last, dispatched at 60s, drains to 120s.
  const rows = [row(0, 30_000), row(0, 60_000), row(60_000, 60_000)];
  rows.push({ ...row(0, 1_000, 9 << 20), scored: false, source: "scan:primary" });
  const s = summarize("w1", 2, rows, 0);
  assert.equal(s.scored, 3);
  assert.equal(s.sustainedPerMin, 2);
  assert.equal(s.sustainedMibPerMin, 2);
  assert.equal(s.wallS, 120);
  assert.equal(s.perMin, 1.5);
  assert.equal(s.failedBytes, 9 << 20);
});

test("deal gives every set the same count even when one artifact dwarfs the rest", () => {
  const items = [{ eco: "golang", purl: "pkg:golang/x/huge@v1", bytes: 200 << 20 }];
  for (let i = 1; i <= 15; i++) items.push({ eco: i % 2 ? "npm" : "pypi", purl: `pkg:npm/s${i}@1`, bytes: i << 10 });
  assert.deepEqual(deal(items, [4, 4, 4, 4]).map((set) => set.length), [4, 4, 4, 4]);
});

test("deal scales each ecosystem's share to the set's size", () => {
  const items = [];
  for (let i = 1; i <= 30; i++) items.push({ eco: i % 5 ? "npm" : "golang", purl: `pkg:npm/p${i}@1`, bytes: i << 10 });
  const [big, small] = deal(items, [20, 10]);
  assert.equal(big.length, 20);
  assert.equal(small.length, 10);
  assert.equal(big.filter((c) => c.eco === "golang").length, 2 * small.filter((c) => c.eco === "golang").length);
});

test("dedupe keeps one version of each package", () => {
  const kept = dedupe([
    { eco: "golang", purl: "pkg:golang/github.com/a/task@v0.0.0-2026-1" },
    { eco: "golang", purl: "pkg:golang/github.com/a/task@v0.0.0-2026-2" },
    { eco: "golang", purl: "pkg:golang/github.com/b/task@v1.0.0" },
    { eco: "npm", purl: "pkg:npm/task@1.0.0" },
  ]);
  assert.deepEqual(kept.map((c) => c.purl), [
    "pkg:golang/github.com/a/task@v0.0.0-2026-1",
    "pkg:golang/github.com/b/task@v1.0.0",
    "pkg:npm/task@1.0.0",
  ]);
});

test("auto width is the worker's free slots, a number is taken as given", () => {
  assert.equal(width("auto", { stats: { slots: 384, slots_free: 128 } }), 128);
  assert.equal(width("auto", { stats: { slots: 48 } }), 48);
  assert.equal(width("auto", { stats: null }), 8);
  assert.equal(width("16", { stats: { slots_free: 128 } }), 16);
});

test("deal sends the largest artifact to the largest set", () => {
  const items = [{ eco: "npm", purl: "pkg:npm/whale@1", bytes: 100 << 20 }];
  for (let i = 1; i <= 35; i++) items.push({ eco: "npm", purl: `pkg:npm/s${i}@1`, bytes: 1 << 20 });
  const [small, big] = deal(items, [4, 32]);
  assert.ok(big.some((c) => c.purl === "pkg:npm/whale@1"));
  assert.equal(small.length + big.length, 36);
});

test("a worker given a single wave has no sustained rate", () => {
  const rows = [0, 1, 2].map((i) => ({ eco: "npm", bytes: 1 << 20, start: i, ms: 10_000, scored: true }));
  const s = summarize("w1", 128, rows, 0);
  assert.equal(s.sustainedPerMin, null);
  assert.ok(s.perMin > 0);
});
