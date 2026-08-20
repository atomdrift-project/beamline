# Beamline API

Ask about a package or a file. Get a number, and if it is hostile, a short
list of why. That is the whole interface.

```
GET  /healthz
GET  /sha256/{64hex}
GET  /purl/{purl}          also ?purl=
POST /                     raw bytes, or multipart field `file`
```

Same JSON on every 200. Send `Accept-Encoding: gzip` if you want it compressed.
If `BEAMLINE_TOKEN` is set, send `Authorization: Bearer …` on every route except
`/healthz`.

## 200

Clean:

```json
{
  "sha": "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
  "purl": "pkg:npm/left-pad@1.3.0",
  "lvl": -1,
  "eng": "2.7.2"
}
```

`purl` is omitted when unknown. `eng` is the scanner build — enough to file a
ticket.

Hostile:

```json
{
  "sha": "…",
  "purl": "pkg:npm/evil@1.0.0",
  "lvl": 3,
  "eng": "2.7.2",
  "why": "Postinstall launches a reverse shell.",
  "hits": [
    {
      "id": "objectives/execution/shell/bash",
      "crit": 5,
      "file": "lib/install.js",
      "pkg": "pkg:npm/evil@1.0.0",
      "desc": "Spawns bash from a npm postinstall hook"
    }
  ]
}
```

Empty strings are omitted, not sent.

### `lvl`

The tightest false-positive budget (per 100 million) at which this sample is
hostile. Lower is worse. `-1` means it never fires.

A typical gate is `lvl != -1 && lvl <= 50`. Do not invent a second threshold
from other fields; there aren't any.

### `hits`

Present only when `lvl != -1`. At most three. Only notable or worse
(`crit` 3, 4, or 5).

| field | meaning |
| --- | --- |
| `id` | Stable finding id. Use it as a check id. |
| `crit` | 3 notable, 4 suspicious, 5 hostile. |
| `file` | Path inside the artifact. Nested members are the inner path. |
| `pkg` | Package the finding belongs to (PURL when we have one). |
| `desc` | One line a developer can read. |

### `why`

Optional. One sentence from the interpreter, when we have it. A PR comment.
If it is absent, the hits are the why.

## Headers

```
X-SHA256: …                              same as body.sha
X-Beamline-Source: cache|bloom|hopper|scan
Cache-Control: public, max-age=…         private if you authenticated
Content-Encoding: gzip                   if you asked
Retry-After: 5                           on 202
```

`X-Beamline-Source` is for operators. Do not branch on it.

## Not 200

```json
{ "error": "unknown sample" }
```

`detail` is included only when it adds a chain the status code does not.

| code | meaning |
| --- | --- |
| 202 | Queued. Body is `{"state":"pending"}`. Honor `Retry-After`. |
| 400 | Bad sha256 or PURL. |
| 401 | Bad bearer token. |
| 413 | Body too large. |
| 415 / 422 | We have the bytes and cannot analyze them. |
| 404 | No such route, or this sha is unknown and we have nothing to fetch. |
| 429 / 503 / 504 | Capacity, down, or timed out. |

## Mapping

Semgrep: `check_id=id`, `path=file`, `message=why or desc`, severity from `crit`,
fingerprint `sha+id`, `metadata.package=pkg`, gate on `lvl`.

Chainguard: `GET /sha256/…` or `/purl/…`. `lvl == -1` means ship it.

NetRise: `file` is the nested path; `pkg` is the component; three hits is the cap.
