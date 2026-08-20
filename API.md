# Beamline API

```
GET  /healthz
GET  /sha256/{64hex}
GET  /purl/{purl}
POST /
```

`POST /` is the raw file. Encode the PURL in the path.

If `BEAMLINE_TOKEN` is set, every route except `/healthz` requires
`Authorization: Bearer …`.

## 200

```json
{
  "sha": "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
  "purl": "pkg:npm/left-pad@1.3.0",
  "lvl": -1,
  "eng": "2.7.2"
}
```

`purl` is omitted when unknown. `eng` is the scanner build.

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

Empty strings are omitted.

`lvl` is the tightest false-positive budget per 100 million at which the
sample is hostile. Lower is worse. `-1` never fires. Gate on `lvl`.

`hits` is present only when `lvl != -1`. At most three. `crit` is 3 notable,
4 suspicious, 5 hostile. `id` is stable. `file` is the path inside the
artifact. `pkg` is the component. `desc` is one line.

`why` is one sentence from the interpreter, when we have it.

## Headers

```
X-SHA256: …                              same as body.sha
X-Beamline-Source: cache|bloom|hopper|scan
Cache-Control: public, max-age=…         private if authenticated
Content-Encoding: gzip                   applied by the edge, if requested
Retry-After: 3-8                         on 202, jittered
```

`X-Beamline-Source` is for operators. Do not branch on it.

Every request carries an `X-Request-Id`, taken from `CF-Ray` when present, into
hopper and scan and onto every log line. Send your own to correlate with ours.

## Errors

```json
{ "error": "unknown sample" }
```

`detail` is included only when it adds something the status does not.

| code | |
| --- | --- |
| 202 | `{"state":"pending"}`. Honor `Retry-After`; it is jittered, so do not pin it. The analysis is still running and the retry is usually cheap. |
| 400 | Bad sha256 or PURL. |
| 401 | Bad bearer token. |
| 413 | Too large. |
| 415 | Body we will not accept. |
| 422 | Bytes we cannot analyze. |
| 404 | No such route or sample. |
| 429 | At capacity. |
| 503 | Unavailable. |
| 504 | Timed out. |
