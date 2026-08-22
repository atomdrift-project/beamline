# Beamline API

```
GET  /healthz            (also /_/health)
GET  /lookup?sha256={64hex}
GET  /lookup?purl={purl}
GET  /lookup?purl={purl}&sha256={64hex}  both: the fast path, see below
POST /analyze                            the artifact as the raw body
POST /analyze?purl={purl}                no body: resolved by scan
POST /analyze?purl={purl}&sha256={64hex} no body, and the digest is checked
```

`/lookup` reports what is already known and never spends an analysis slot; a
key nothing holds is a 404. Name at least one key; neither is a 400.

### Sending both keys

If you already know the digest **and** the PURL, send both. It is the fastest
path we offer, and it costs you nothing to use.

The two keys are not interchangeable, which is why both are worth having. A
`sha256` names exact bytes. A versioned `purl` names whatever sample the corpus
holds for that release — usually the same artifact, but not necessarily the one
you are holding. So:

- The digest is asked first, because it is exact. If it answers, that is the
  answer, and the PURL costs nothing — no second query is made.
- If the digest is unknown, the PURL gets a second chance. The corpus can know
  release `1.0` without having seen your particular bytes, and that is a hit you
  would not have got from either key alone.
- If the PURL resolves to a *different* digest than the one you named, that
  answer is refused rather than served. It describes different bytes, and a
  release whose digest has moved under it is worth knowing about rather than
  papering over.

The practical effect is that a caller who knows both never pays for a fetch to
find out whether they agree: we compare the digests from the lookup itself.

`/analyze` is the route that may analyze. Send the artifact as the raw body
and neither key is needed: the digest is computed from the bytes. Send
`sha256` as well and it is checked — a mismatch is a 400, which is how a
truncated upload is caught. The digest is never taken on trust; a verdict
filed under a key the caller chose rather than one the bytes produce would
poison this cache, scan's, and hopper's at once.

The body is optional, but a `purl` is then required: scan resolves it against
the registry itself. A digest alone is not enough to analyze — it is a lookup
key, not an artifact — so `/analyze?sha256=` with no body and no `purl` is a
404, not an analysis. Send the bytes, or send a PURL, or use `/lookup`.

A `multipart/` or `application/x-www-form-urlencoded` body is a 415, checked
before the keys, so send `Content-Type: application/octet-stream`.

`purl` on `/analyze` is both the thing scan resolves when there is no body and
a hint when there is: it lets scan graft registry provenance onto the report,
and it is echoed in each hit's `pkg`.

The `pkg:` prefix is optional and the scheme and type are case-folded, so
`npm/left-pad@1.3.0` and `PKG:NPM/left-pad@1.3.0` are the same key. The rest of
the PURL is left as sent: npm grandfathered in mixed-case names.

Both keys travel as query parameters. A PURL's own grammar carries `?` and
`#`, and in a path segment everything from a raw `?` is parsed as the URL's
query string while a `#subpath` never leaves the client — a qualified PURL
would silently become a different one. `GET /sha256/{64hex}` and
`GET /purl/{purl}` were the earlier spelling of this route, and `POST /` of
the upload; none of the three answer any more.

If `BEAMLINE_TOKEN` is set, every route except the health checks requires
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
      "desc": "Spawns bash from a npm postinstall hook",
      "off": 109,
      "line": 12
    }
  ]
}
```

Empty strings are omitted.

`lvl` is the tightest false-positive budget per 100 million at which the
sample is hostile. Lower is worse. `-1` never fires. Gate on `lvl`.

`hits` is present only when `lvl != -1`. At most three, worst first. `crit` is
3 notable, 4 suspicious, 5 hostile. `id` is stable. `file` is the path inside
the artifact. `pkg` is the component. `desc` is one line.

`off` is the byte offset of the match within `file`, and `line` its 1-based
source line. Either may be absent: a binary carries no line structure, and a
match whose evidence was trimmed from the report has neither.

Only matches native to the file they are reported on appear. An archive
repeats its members' findings on itself; those copies are dropped in favour of
the member's own, which names the real path and offset.

`why` is one sentence from the interpreter, when we have it.

## Headers

```
X-SHA256: …                              same as body.sha
X-Beamline-Source: cache|scan-cache|bloom|hopper|scan
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

A call blocks until the sample has an answer. Analyses run to 30 minutes on the
heaviest packages, and the connection is simply held: there is no duration limit
on a Worker request while the caller stays connected. A caller that disconnects
loses nothing — the analysis keeps running, and reconnecting on the same key
joins the work already in progress rather than starting it again.

| code | |
| --- | --- |
| 202 | `{"state":"pending"}`. Honor `Retry-After`; it is jittered, so do not pin it. Rare: the call blocks while an analysis somebody else already started completes, and only gives up on a 202 when that outruns the request budget. |
| 400 | Bad sha256 or PURL. |
| 401 | Bad bearer token. |
| 413 | Too large. |
| 415 | Body we will not accept. |
| 422 | Bytes we cannot analyze. |
| 404 | No such route or sample. |
| 405 | Right route, wrong method. `Allow` names the one that works: `/lookup` is GET, `/analyze` is POST. |
| 429 | At capacity. |
| 503 | Unavailable. No worker could be reached, and nothing is running on the sample. It does not mean the analysis was slow: a sample that outruns the 125s edge ceiling is waited out rather than failed, because the worker finishes it and files the verdict regardless. |
| 504 | Timed out. |
