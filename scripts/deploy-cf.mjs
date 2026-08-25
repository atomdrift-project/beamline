import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import path from "node:path";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const kv = (process.env.KV || "").trim();
const scanUrl = (process.env.SCAN_URL || "").trim();
const wrangler = (process.env.WRANGLER || "wrangler@4.124.0").trim();

if (!/^[0-9a-f]{32}$/i.test(kv)) {
  console.error("KV must be a 32-character Cloudflare KV namespace ID.");
  process.exit(2);
}
if (!scanUrl) {
  console.error("SCAN_URL is required.");
  process.exit(2);
}

const source = readFileSync(path.join(root, "wrangler.toml"), "utf8");
if (/^\[\[kv_namespaces\]\]/m.test(source)) {
  console.error("wrangler.toml already contains an active KV binding; remove the generated deploy path or use one source of truth.");
  process.exit(2);
}

const tempDir = mkdtempSync(path.join(root, ".wrangler-deploy-"));
const configPath = path.join(tempDir, "wrangler.toml");
const main = path.relative(tempDir, path.join(root, "beamline.js")).replaceAll("\\", "/");
const generated = `${source.trimEnd()}\n\n[[kv_namespaces]]\nbinding = "BEAMLINE_KV"\nid = ${JSON.stringify(kv)}\n`;
writeFileSync(configPath, generated.replace('main = "beamline.js"', `main = ${JSON.stringify(main)}`));

try {
  const deployArgs = ["--yes", wrangler, "deploy", "--config", configPath, "--var", `SCAN_URL:${scanUrl}`];
  if (process.env.DRY_RUN === "1") deployArgs.push("--dry-run");
  const result = spawnSync(
    "npx",
    deployArgs,
    { cwd: root, stdio: "inherit" },
  );
  process.exitCode = result.status ?? 1;
} finally {
  rmSync(tempDir, { recursive: true, force: true });
}
