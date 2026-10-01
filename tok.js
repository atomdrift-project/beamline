// Off Cloudflare there are no Worker secrets, so a token that is not in the
// environment falls back to the file the services themselves are configured
// from — `--token-file ~/.tok/<service>`. That keeps a local run and the
// stress harness working without pasting secrets onto a command line, and it
// is the same file `make deploy-cf` uploads as a Worker secret, so a local
// beamline and a deployed one authenticate identically.

import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

// Whether a bearer token sent to this URL would cross a network in the clear.
// Loopback is the one plain-http destination with nobody in between; anywhere
// else, http hands the credential to every hop. Clients read their token from
// ~/.tok without being asked, so this is checked before one is sent.
/**
 * @param {string} url
 * @returns {boolean} true for http to anything but loopback
 */
export function cleartextRemote(url) {
  try {
    const { protocol, hostname } = new URL(url);
    if (protocol !== "http:") return false;
    return !(hostname === "localhost" || hostname === "[::1]" || /^127\.\d+\.\d+\.\d+$/.test(hostname));
  } catch {
    return false;
  }
}

// The first non-empty line, trimmed. A missing file is normal: the service may
// not require a token.
/**
 * @param {string} service - the basename under ~/.tok
 * @returns {string} the first non-empty line, or "" when there is no such file
 */
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
