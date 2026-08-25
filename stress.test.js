import assert from "node:assert/strict";
import { test } from "node:test";
import { _test } from "./stress.js";

test("npm PURL encodes a scoped name the way scan expects", () => {
  assert.equal(_test.npmPurl("left-pad", "1.3.0"), "pkg:npm/left-pad@1.3.0");
  assert.equal(_test.npmPurl("@babel/core", "7.24.0"), "pkg:npm/%40babel/core@7.24.0");
});

test("pypi cargo golang PURLs", () => {
  assert.equal(_test.pypiPurl("requests", "2.32.0"), "pkg:pypi/requests@2.32.0");
  assert.equal(_test.cargoPurl("serde", "1.0.203"), "pkg:cargo/serde@1.0.203");
  assert.equal(_test.golangPurl("github.com/BurntSushi/toml", "v1.4.0"), "pkg:golang/github.com/BurntSushi/toml@v1.4.0");
});

test("npm _changes skips design docs and duplicates", () => {
  assert.deepEqual(
    _test.parseNpmChanges({
      results: [{ id: "_design/app" }, { id: "left-pad" }, { id: "left-pad" }, { id: "@scope/pkg" }, { id: "" }],
    }),
    ["left-pad", "@scope/pkg"],
  );
});

test("pypi updates RSS title is name then version", () => {
  const xml = `<?xml version="1.0"?>
    <rss><channel>
      <item><title>requests 2.32.3</title></item>
      <item><title><![CDATA[numpy 2.1.0]]></title></item>
      <item><title>not-a-package</title></item>
    </channel></rss>`;
  assert.deepEqual(_test.parsePypiRss(xml), [
    { name: "requests", version: "2.32.3" },
    { name: "numpy", version: "2.1.0" },
  ]);
});

test("go index is NDJSON Path/Version", () => {
  const text = [
    '{"Path":"github.com/foo/bar","Version":"v1.0.0"}',
    "not json",
    '{"Path":"golang.org/x/sync","Version":"v0.8.0"}',
    "",
  ].join("\n");
  assert.deepEqual(_test.parseGoIndex(text), [
    { name: "github.com/foo/bar", version: "v1.0.0" },
    { name: "golang.org/x/sync", version: "v0.8.0" },
  ]);
});

test("crates index commit subjects match forager", () => {
  const cases = [
    ["Update crate `serde`", "serde", true],
    ["Create crate `oceanfic`", "oceanfic", true],
    ["Delete crate `freak`", "freak", false],
    ["Update crate `some-crate_1.0`", "some-crate_1.0", true],
    ["Reformatting", "", false],
    ["Update crate ``", "", false],
    ["Updating crate `legacy`", "legacy", false],
  ];
  for (const [subject, name, changed] of cases) {
    assert.deepEqual(_test.parseCratesIndexCommit(subject), { name, changed }, subject);
  }
});

test("crates sparse path layout", () => {
  assert.equal(_test.cratesSparsePath("a"), "1/a");
  assert.equal(_test.cratesSparsePath("ab"), "2/ab");
  assert.equal(_test.cratesSparsePath("abc"), "3/a/abc");
  assert.equal(_test.cratesSparsePath("serde"), "se/rd/serde");
  assert.equal(_test.cratesSparsePath("Tokio"), "to/ki/tokio");
});

test("percentile is nearest-rank", () => {
  assert.equal(_test.percentile([], 50), null);
  assert.equal(_test.percentile([10], 95), 10);
  assert.equal(_test.percentile([1, 2, 3, 4], 50), 2);
});

test("route metrics count expected misses as successful requests", () => {
  const metrics = _test.routeMetrics([
    { eco: "npm", kind: "ok", ms: 10 },
    { eco: "npm", kind: "miss", ms: 20 },
    { eco: "pypi", kind: "note", ms: 30 },
    { eco: "pypi", kind: "bug", ms: 40 },
  ]);
  assert.equal(metrics.success, 2);
  assert.equal(metrics.successRate, 0.5);
  assert.equal(metrics.p90, 40);
  assert.deepEqual(metrics.byEco.npm, { n: 2, success: 2, successRate: 1, p90: 20 });
  assert.deepEqual(metrics.byEco.pypi, { n: 2, success: 0, successRate: 0, p90: 40 });
});

test("classify treats a missing envelope as a bug, saturation as a note", () => {
  assert.equal(_test.classify({ status: 200 }), "ok");
  assert.equal(_test.classify({ status: 200, issues: ["sha"] }), "bug");
  assert.equal(_test.classify({ status: 404 }), "miss", "read-only /lookup: a miss is an answer, not a defect");
  assert.equal(_test.classify({ status: 400 }), "bug");
  assert.equal(_test.classify({ status: 500 }), "bug");
  assert.equal(_test.classify({ status: 503 }), "note");
  assert.equal(_test.classify({ status: 504 }), "note");
  assert.equal(_test.classify({ status: 429 }), "note");
  assert.equal(_test.classify({ status: 202 }), "note");
  assert.equal(_test.classify({ status: 415 }), "note");
  assert.equal(_test.classify({ status: 0 }), "bug");
});

test("checkApi accepts a documented 200 and rejects ml/raw and hits on clean", () => {
  const sha = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";
  const headers = {
    get(name) {
      return {
        "x-sha256": sha,
        "x-beamline-source": "scan:primary",
        "content-type": "application/json",
        "cache-control": "public, max-age=86400",
      }[name];
    },
  };
  const clean = { sha, purl: "pkg:npm/left-pad@1.3.0", lvl: -1, eng: "2.7.2" };
  assert.deepEqual(_test.checkApi(200, headers, clean, "pkg:npm/left-pad@1.3.0", "public"), []);
  // An authenticated caller must never be handed a publicly cacheable verdict:
  // beamline stores its own copy as public, and that rewrite once reached the
  // client on every cache hit.
  assert.ok(_test.checkApi(200, headers, clean, "pkg:npm/left-pad@1.3.0", "private").length);
  const priv = { get: (n) => (n === "cache-control" ? "private, max-age=3600" : headers.get(n)) };
  assert.deepEqual(_test.checkApi(200, priv, clean, "pkg:npm/left-pad@1.3.0", "private"), []);
  assert.ok(_test.checkApi(200, headers, { sha, lvl: -1, ml: { lvl: -1 } }, null).length);
  assert.ok(_test.checkApi(200, headers, { sha, lvl: -1, hits: [{ id: "x", crit: 5 }] }, null).length);
  assert.ok(_test.checkApi(200, headers, { sha, lvl: 3, hits: [{ id: "x", crit: 2 }] }, null).length);
  assert.deepEqual(_test.checkApi(202, { get: (n) => (n === "retry-after" ? "5" : "") }, { state: "pending" }, null), []);
  assert.ok(_test.checkApi(202, { get: () => "" }, { error: "pending analysis" }, null).length);
  assert.deepEqual(_test.checkApi(404, { get: () => "" }, { error: "unknown sample" }, null), []);
});

test("mixJobs round-robins ecosystems up to the cap", () => {
  const got = _test.mixJobs(
    [[{ purl: "a" }, { purl: "a2" }], [{ purl: "b" }], [{ purl: "c" }]],
    4,
  );
  assert.deepEqual(
    got.map((j) => j.purl),
    ["a", "b", "c", "a2"],
  );
});

test("the popular list is five pinned PURLs per ecosystem", () => {
  const byEco = new Map();
  for (const [eco, purl] of _test.POPULAR) {
    assert.ok(purl.startsWith(`pkg:${eco === "cargo" ? "cargo" : eco}/`), purl);
    // Pinned, not floating: an unversioned PURL would make two runs
    // incomparable, which is the whole point of this list.
    assert.ok(purl.includes("@"), `${purl} has no version`);
    byEco.set(eco, (byEco.get(eco) || 0) + 1);
  }
  assert.deepEqual([...byEco.keys()].sort(), ["cargo", "golang", "npm", "pypi"]);
  for (const [eco, count] of byEco) assert.equal(count, 5, eco);
  assert.equal(new Set(_test.POPULAR.map(([, p]) => p)).size, _test.POPULAR.length, "no duplicates");
});

test("popular jobs interleave ecosystems", () => {
  const mixed = _test.mixJobs(_test.popularJobs(), Infinity);
  assert.equal(mixed.length, _test.POPULAR.length);
  // Round-robin, so a run spreads load across registries rather than doing all
  // of npm and then all of pypi.
  assert.deepEqual(mixed.slice(0, 4).map((j) => j.eco), ["npm", "pypi", "cargo", "golang"]);
});

test("popular jobs can be repeated to a request count", () => {
  const base = [{ eco: "npm", purl: "a" }, { eco: "pypi", purl: "b" }];
  assert.deepEqual(_test.repeatJobs(base, 2), [...base, ...base]);
});

// The v1 contract as a client has to read it. The shape never moving is the
// whole promise — a caller writes one code path against nine keys — so a field
// that vanishes is a defect the harness must report rather than tolerate.
test("v1 check: a well-formed decision passes", () => {
  const ok = {
    decision: "block",
    purl: "pkg:npm/evil@1.0.0",
    sha256: "a".repeat(64),
    severity: "hostile",
    fires_at: 3,
    reason: "Reverse shell in postinstall.",
    findings: [{ id: "objectives/c2/backdoor", crit: 5 }],
    engine_version: "2.8.0",
    analyzed_at: "2026-08-01T00:00:00Z",
  };
  assert.deepEqual(_test.checkV1(200, ok, "pkg:npm/evil@1.0.0"), []);
});

test("v1 check: a missing key is a defect, not a variation", () => {
  const missing = {
    decision: "allow",
    purl: "pkg:npm/fine@1.0.0",
    sha256: null,
    severity: "benign",
    fires_at: -1,
    findings: [],
    engine_version: "2.8.0",
    analyzed_at: "2026-08-01T00:00:00Z",
  };
  assert.deepEqual(_test.checkV1(200, missing, "pkg:npm/fine@1.0.0"), ["v1 missing reason"]);
});

// An outage must carry nothing about the artifact. A caller that can read a
// severity or a level out of one would eventually branch on it, and would then
// be treating our own failure as evidence about somebody's package.
test("v1 check: an outage may not carry evidence", () => {
  const leaky = {
    decision: "unavailable",
    purl: "pkg:npm/x@1.0.0",
    sha256: null,
    severity: "benign",
    fires_at: -1,
    reason: null,
    findings: [{ id: "x", crit: 4 }],
    engine_version: null,
    analyzed_at: null,
  };
  const issues = _test.checkV1(200, leaky, "pkg:npm/x@1.0.0");
  assert.ok(issues.some((i) => i.includes("fires_at")), issues.join("; "));
  assert.ok(issues.some((i) => i.includes("severity")), issues.join("; "));
  assert.ok(issues.some((i) => i.includes("findings")), issues.join("; "));
});

// A block stops somebody's build. If it cannot say why, the developer it
// stopped has nothing to act on.
test("v1 check: a block must be able to say why", () => {
  const mute = {
    decision: "block",
    purl: "pkg:npm/evil@1.0.0",
    sha256: null,
    severity: "hostile",
    fires_at: 3,
    reason: null,
    findings: [],
    engine_version: "2.8.0",
    analyzed_at: "2026-08-01T00:00:00Z",
  };
  assert.deepEqual(_test.checkV1(200, mute, "pkg:npm/evil@1.0.0"), [
    "block carried neither a reason nor a finding",
  ]);
});

test("v1 check: an answer about a different package is a defect", () => {
  const wrong = {
    decision: "allow",
    purl: "pkg:npm/other@2.0.0",
    sha256: null,
    severity: "benign",
    fires_at: -1,
    reason: null,
    findings: [],
    engine_version: "2.8.0",
    analyzed_at: "2026-08-01T00:00:00Z",
  };
  const issues = _test.checkV1(200, wrong, "pkg:npm/asked@1.0.0");
  assert.equal(issues.length, 1);
  assert.match(issues[0], /answered about/);
});

// A miss is a decision now, not a status: v1 answers 200 for a package nobody
// has analyzed. Classifying on the status alone would count every miss as a
// success and report a hit rate of 100%.
test("v1: a miss and an outage are told apart inside a 200", () => {
  assert.equal(_test.classify({ status: 200, decision: "unknown" }), "miss");
  assert.equal(_test.classify({ status: 200, decision: "unavailable" }), "note");
  assert.equal(_test.classify({ status: 200, decision: "allow" }), "ok");
  assert.equal(_test.classify({ status: 200, decision: "block" }), "ok");
});
