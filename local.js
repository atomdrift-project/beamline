#!/usr/bin/env node
// Local HTTP front for beamline.js — same handler as the Cloudflare Worker.

import { createServer } from "node:http";
import { gzipSync } from "node:zlib";
import { handle } from "./beamline.js";
import { readToken } from "./tok.js";

// Below this, gzip costs more bytes than it saves.
const GZIP_MIN_BYTES = 512;

const PORT = Number(process.env.PORT) || 8080;
const MAX_BYTES = Number(process.env.MAX_BYTES) || 16 * 1024 * 1024;
// Bodies are buffered whole, so MAX_INFLIGHT * MAX_BYTES is this process's
// memory ceiling — 512MB at the defaults. Raise them together, or not at all.
const MAX_INFLIGHT = Number(process.env.MAX_INFLIGHT) || 32;

// Every knob beamline.js reads, so a local run is tunable the same way a
// deployed Worker is. Anything absent falls back to the built-in default.
const TUNABLES = [
  "SCAN_URL",
  "BEAMLINE_TOKEN",
  "MAX_BYTES",
  "SCAN_TIMEOUT_MS",
  "SCAN_TOKEN",
  "SCAN_RETRIES",
  "SCAN_RETRY_BASE_MS",
];

const env = Object.fromEntries(TUNABLES.map((k) => [k, process.env[k] || ""]));

// The client token is deliberately environment-only: if BEAMLINE_TOKEN is not
// passed, the API is open. SCAN_TOKEN still falls back to ~/.tok because it is
// a backend credential, not a policy switch for callers.
env.SCAN_TOKEN ||= readToken("scan");

// Workaround, not design. On Node 26 fetch does not dispatch a second
// concurrent request to a backend until the event loop wakes, costing a hedged
// lookup up to 200ms of dead time on an otherwise idle process. A 1ms tick
// while work is in flight keeps the loop awake. Cloudflare's fetch is
// unaffected, so this stays out of beamline.js.
//
// Delete this once fetch dispatches promptly. To check: park a slow request on
// a backend, fire a second one 20ms later, and compare its round trip against
// the same request over node:net. If they match, the tick is dead weight.
let inflight = 0;
let nudge = null;

function busy(delta) {
  inflight += delta;
  if (inflight > 0 && !nudge) nudge = setInterval(() => {}, 1).unref();
  if (inflight === 0 && nudge) {
    clearInterval(nudge);
    nudge = null;
  }
}

const server = createServer(async (req, res) => {
  // Shed rather than queue: a request we cannot start is cheaper to refuse now
  // than to accept and starve.
  if (inflight >= MAX_INFLIGHT) {
    res.statusCode = 429;
    res.setHeader("content-type", "application/json");
    res.setHeader("retry-after", "1");
    res.end(JSON.stringify({ error: "at capacity" }));
    return;
  }
  busy(1);
  try {
    const url = new URL(req.url || "/", `http://${req.headers.host || "127.0.0.1"}`);
    const buf = await readRequest(req, MAX_BYTES);
    const headers = new Headers();
    for (const [k, v] of Object.entries(req.headers)) {
      if (v == null) continue;
      headers.set(k, Array.isArray(v) ? v.join(", ") : v);
    }
    const request = new Request(url, {
      method: req.method,
      headers,
      body: req.method === "GET" || req.method === "HEAD" ? undefined : buf,
    });
    // A client that hangs up should not leave scan working.
    const ac = new AbortController();
    res.on("close", () => {
      if (!res.writableFinished) ac.abort();
    });
    const ctx = {
      signal: ac.signal,
      waitUntil(p) {
        Promise.resolve(p).catch(() => {});
      },
    };
    const out = await handle(request, env, ctx);
    res.statusCode = out.status;
    out.headers.forEach((v, k) => res.setHeader(k, v));
    // Nothing sits in front of this process, so compression is ours to do.
    // Behind Cloudflare the edge does it and beamline.js stays out of the way.
    let body = Buffer.from(await out.arrayBuffer());
    const accepts = String(req.headers["accept-encoding"] || "")
      .toLowerCase()
      .split(",")
      .some((p) => p.trim().startsWith("gzip"));
    if (accepts && body.length >= GZIP_MIN_BYTES && !res.getHeader("content-encoding")) {
      body = gzipSync(body);
      res.setHeader("content-encoding", "gzip");
      res.appendHeader("vary", "accept-encoding");
    }
    res.setHeader("content-length", String(body.length));
    res.end(body);
  } catch (err) {
    const tooLarge = err && err.code === 413;
    res.statusCode = tooLarge ? 413 : 500;
    res.setHeader("content-type", "application/json");
    res.end(JSON.stringify({ error: tooLarge ? "too large" : "internal" }));
  } finally {
    busy(-1);
  }
});

function readRequest(req, maxBytes) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let n = 0;
    req.on("data", (c) => {
      n += c.length;
      if (n > maxBytes) {
        req.destroy();
        const err = new Error("too large");
        err.code = 413;
        reject(err);
        return;
      }
      chunks.push(c);
    });
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

server.listen(PORT, "127.0.0.1", () => {
  process.stderr.write(`beamline listening on http://127.0.0.1:${PORT}\n`);
});
