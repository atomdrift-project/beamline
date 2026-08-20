#!/usr/bin/env node
// Local HTTP front for beamline.js — same handler as the Cloudflare Worker.

import { createServer } from "node:http";
import { handle } from "./beamline.js";

const PORT = Number(process.env.PORT) || 8080;
const MAX_BYTES = Number(process.env.MAX_BYTES) || 16 * 1024 * 1024;

const env = {
  HOPPER_URL: process.env.HOPPER_URL || "",
  SCAN_URL: process.env.SCAN_URL || "",
  BEAMLINE_TOKEN: process.env.BEAMLINE_TOKEN || "",
  MAX_BYTES: process.env.MAX_BYTES || "",
  SCAN_TIMEOUT_MS: process.env.SCAN_TIMEOUT_MS || "",
};

const server = createServer(async (req, res) => {
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
    const ctx = {
      waitUntil(p) {
        Promise.resolve(p).catch(() => {});
      },
    };
    const out = await handle(request, env, ctx);
    res.statusCode = out.status;
    out.headers.forEach((v, k) => res.setHeader(k, v));
    const body = Buffer.from(await out.arrayBuffer());
    res.end(body);
  } catch (err) {
    const tooLarge = err && err.code === 413;
    res.statusCode = tooLarge ? 413 : 500;
    res.setHeader("content-type", "application/json");
    res.end(JSON.stringify({ error: tooLarge ? "too large" : "internal" }));
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
