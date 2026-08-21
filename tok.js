// Off Cloudflare there are no Worker secrets, so a token that is not in the
// environment falls back to the file the services themselves are configured
// from — `--token-file ~/.tok/<service>`. That keeps a local run and the
// stress harness working without pasting secrets onto a command line, and it
// is the same file `make deploy-cf` uploads as a Worker secret, so a local
// beamline and a deployed one authenticate identically.

import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

// The first non-empty line, trimmed. A missing file is normal: the service may
// not require a token.
export function readToken(service) {
  try {
    return (
      readFileSync(join(homedir(), ".tok", service), "utf8")
        .split("\n")
        .map((line) => line.trim())
        .find(Boolean) || ""
    );
  } catch {
    return "";
  }
}
