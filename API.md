# Beamline API

Two routes. `/v1/lookup` reports what is already known; `/v1/analyze` finds out.

`GET /` serves the API documentation.

```
GET  /v1/lookup?purl={purl}                   free, cacheable, never analyzes
GET  /v1/lookup?url={url}                     exact URL; same cache behavior
GET  /v1/lookup?sha256={64hex}
GET  /v1/lookup?purl=a&purl=b                 up to 50 per URL
POST /v1/analyze?purl={purl}                  answers from cache or spends an
POST /v1/analyze?url={url}                    exact URL; scan fetches and hashes it
POST /v1/analyze                              analysis slot; streams. The
                                              artifact may be the raw body

GET  /healthz    (also /_/health)             liveness; no token required
GET  /_/routes                                the router's own reasoning
```

Only `/v1/analyze` costs anything, and only when the answer is not already
known.

Client authentication is optional. If `BEAMLINE_TOKEN` is set, API routes
require `Authorization: Bearer …`; if it is absent, no client token is checked.
The documentation and health routes are public either way. A client token
authenticates you to us and travels no further; beamline holds separate
credentials for its backends.

## Keys

Both keys travel as query parameters. A PURL's grammar carries `?` and `#`, and
in a path segment everything after a raw `?` is parsed as the URL's query
string — a qualified PURL would silently become a different one.

The `pkg:` prefix is optional and the scheme and type are case-folded, so
`npm/left-pad@1.3.0` and `PKG:NPM/left-pad@1.3.0` are one key. The rest is left
as sent: npm grandfathered in mixed-case names.

An exact `url` is an absolute `http` or `https` URL. Encode it as a query
parameter; scan fetches that URL verbatim and returns the resulting SHA-256.
The URL, resolved PURL when known, and SHA-256 are cache aliases, so later
lookups can use whichever spelling they have.

Send both keys when you know both. The digest is asked first, because it names
exact bytes; the PURL is a second chance, because the corpus can know release
`1.0` without having seen your particular bytes. If the PURL resolves to a
different digest than the one you named, that answer is refused rather than
served — it describes different bytes.

## GET /v1/lookup

```
$ curl 'https://api.atomdrift.com/v1/lookup?purl=npm/left-pad@1.3.0'
{
  "decision": "allow",
  "purl": "npm/left-pad@1.3.0",
  "sha256": "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
  "severity": "benign",
  "fires_at": -1,
  "reason": null,
  "findings": [],
  "engine_version": "2.8.0",
  "analyzed_at": "2026-08-01T00:00:00Z"
}
```

`purl` comes back exactly as you sent it, so a reply can be matched to the
request that asked for it. We canonicalize before looking up — PyPI folds `.`
and `_` to `-`, `pkg:` is optional — but you never have to know that to read
your own answer. `sha256` is the identity; compare it when two spellings must
be proven to be one package.

Repeat `purl` to ask about several. One package answers with one object; a
repeated parameter answers with a list, in the order asked. The shape follows
the question, not the data, so a caller that always asks about one always gets
one.

Over 50 packages is a `413`. There is no batch limit on `/v1/analyze` because it
takes one package.

For an exact URL, use one `url` parameter. The response includes `url` exactly
as sent; it may also include a resolved `purl` and includes `sha256` when the
analysis fetched the artifact successfully.

## POST /v1/analyze

Name a package, or send the artifact itself. A caller holding bytes nobody
has published — a build output, a file off disk, something pulled from a
mirror — has nothing to locate them by, and publishing first in order to find
out what you have is the wrong way round.

To analyze an already-resolved artifact URL, use
`POST /v1/analyze?url=https%3A%2F%2F…`. Scan fetches that exact URL, computes the
SHA-256, and Beamline stores the result under the URL and digest (and under a
PURL when scan supplies one).

```
$ curl -sN -X POST --data-binary @suspect.tgz \
    -H 'Content-Type: application/octet-stream' \
    'https://api.atomdrift.com/v1/analyze'
```

The digest is the identity, so two callers uploading the same artifact share one
analysis exactly as two naming one PURL do. `?purl=` may accompany the bytes:
it is grafted onto the report as registry provenance and echoed in each
finding's `pkg`.

Uploads are capped at 16 MiB — the artifact is held in memory so a worker that
refuses can be offered the same bytes. Anything larger belongs in a registry,
which is what `?purl=` is for. An empty body is `empty_artifact`; one over the
cap is `artifact_too_large`.

The reply is newline-delimited JSON: progress while the run is going, then the
decision. **Read lines until one carries `decision`. That is the answer.**

```
$ curl -sN -X POST \
    'https://api.atomdrift.com/v1/analyze?purl=pypi/tensorflow@2.15.0'
{"state":"analyzing","elapsed_ms":1002,"total_elapsed_ms":1002,"phase":"fetch","phase_state":"started","phase_elapsed_ms":0,"request_id":"…","purl":"pypi/tens…"}
{"state":"analyzing","elapsed_ms":6004,"total_elapsed_ms":6004,"phase":"fetch","phase_state":"completed","phase_elapsed_ms":5002,"request_id":"…","purl":"pypi/tens…"}
{"state":"analyzing","elapsed_ms":6004,"total_elapsed_ms":6004,"phase":"unpack","phase_state":"started","phase_elapsed_ms":0,"request_id":"…","purl":"pypi/tens…"}
{"state":"analyzing","elapsed_ms":11006,"total_elapsed_ms":11006,"phase":"unpack","phase_state":"completed","phase_elapsed_ms":5002,"request_id":"…","purl":"pypi/tens…"}
{"decision":"allow","purl":"pypi/tensorflow@2.15.0","fires_at":-1,…}
```

Progress frames carry `state`, `purl`, `elapsed_ms`, `total_elapsed_ms`, `phase`,
`phase_state`, `phase_elapsed_ms`, `phase_started_at`, and `request_id`. Phase
states are `started`, `running`, and `completed`. When scan does not report a
phase, Beamline uses `phase: "unknown"` rather than emitting a null phase.
Beamline emits a completion frame when a phase changes and immediately before
the decision. These fields are stream telemetry only; they are not stored in
the verdict cache.

For PURL analyses, `purl:registry` identifies registry metadata lookup,
`purl:payload` identifies fetching the initial package payload, and
`purl:registry-document` identifies the registry-document fallback. The later
`fetch+graft` phase is dependency retrieval and grafting, not initial payload
acquisition.

### Following discovered references

The requested artifact is always retrieved and analyzed. `follow` controls
which references discovered *inside* that artifact are also retrieved,
analyzed, and folded into its verdict:

| value | follows |
| --- | --- |
| `none` | Nothing beyond the requested artifact. |
| `dependencies` | Dependencies declared in manifests and lockfiles. |
| `references` | Packages and URLs named by install or download commands. |
| `ci-actions` | Third-party CI actions; also implies `dependencies`. |
| `all` | Every category above. |

Values may be comma-separated or repeated:

```
POST /v1/analyze?purl=…&follow=none
POST /v1/analyze?purl=…&follow=dependencies,references
POST /v1/analyze?purl=…&follow=dependencies&follow=references
```

#### Defaults

Omitting `follow` selects a default from how you named the artifact, on the
principle that we follow what your own resolution cannot show you:

| named by | default | why |
| --- | --- | --- |
| `purl`, `sha256` | `references` | You walked a dependency graph to produce this name, and you are asking about it package by package. What that walk cannot show you is an install or download command fetching something no manifest declares. |
| `url` | `none` | You hold the exact set of URLs already — a proxy resolved every one of them for you. |
| uploaded bytes | `all` | Bytes name nothing. There is no resolution behind them and no lockfile beside them, so whatever is inside them is discoverable nowhere else. |

A PURL sent alongside an upload names provenance, not the artifact in hand, so
an upload keeps the upload default.

An explicit `follow` selection replaces the configured categories after scan
validates it. Scan's depth, size, and fan-out limits still apply.

Verdicts are cached per policy. `follow=none` and `follow=all` are separate
entries for one artifact and neither is served for the other's question, so
asking a non-default policy twice still costs one analysis. `/v1/lookup` takes
`follow` too, and resolves the same defaults — a lookup and an analysis that
name a package the same way read and write the same entry.

Progress frames exist
because a silent connection is one an intermediary will eventually cut, and
because a six-minute analysis and a hung one are otherwise indistinguishable.
Ignore them if you like; they are never the answer.

An analysis that finishes before the first frame is due emits only the decision,
so a fast call is a single JSON object.

**A stream that ends without a decision was cut short, not answered.** Retry it.
Nothing is lost: the worker finishes regardless and files the verdict, so the
retry usually answers from the index in milliseconds. Reconnecting rejoins the
run already in progress rather than starting a second one.

Analyses run to 30 minutes on the heaviest packages. The connection is simply
held.

## The decision

| `decision` | means | typical action |
| --- | --- | --- |
| `allow` | Analyzed. Not hostile at your budget. | proceed |
| `block` | Analyzed. Hostile at your budget. | stop |
| `unanalyzed` | Nobody has analyzed this. Nothing is wrong. | your policy |
| `unavailable` | **We could not answer.** Nothing about it. | your policy |

`unanalyzed` and `unavailable` are deliberately distinct. You may reasonably
install unanalyzed packages while refusing to install anything during an
outage — or the reverse. A partial answer is never an HTTP error: if we can
decide four of five packages, that is a `200` carrying four decisions and one
`unavailable`.

An `unavailable` decision carries `null` for `severity`, `fires_at`,
`engine_version` and `analyzed_at`, and an empty `findings`. It is a statement
about us, not about the artifact; there is nothing in it to read.

## The response object

Every field is always present. Unknown is `null`, empty is `[]`. This applies to
the decision object itself; the objects inside `findings` omit what they do not
know — see [findings](#findings).

| field | type | |
| --- | --- | --- |
| `decision` | string | `allow`, `block`, `unanalyzed`, `unavailable`. |
| `purl` | string\|null | The package, spelled as you asked. |
| `url` | string\|null | The exact URL, spelled as you asked; present for URL requests. |
| `sha256` | string\|null | The exact bytes analyzed. |
| `severity` | string\|null | `benign`, `suspicious`, `hostile`. |
| `fires_at` | int\|null | Tightest budget at which this grades hostile. |
| `reason` | string\|null | One sentence, when we have one. |
| `findings` | array | At most three, worst first. Empty unless one fired. |
| `engine_version` | string\|null | Scanner build that produced it. |
| `analyzed_at` | string\|null | RFC 3339. |

### fires_at and false_positive_budget

Same scale, different things. `fires_at` is **measured**: the tightest
budget, in false positives per 100 million benign files, at which this
artifact grades hostile. Lower is worse. `-1` fires at no budget at all;
`null` means no level applies to the record.

`false_positive_budget` is **chosen**: how many false positives per 100 million
you will tolerate. Pass it as a query parameter on either route.

```
?false_positive_budget=25     the default: strict
?false_positive_budget=1000   looser; catches more, and more false alarms
```

`decision` is `block` when `fires_at` is at or below your budget. Tune against
`fires_at` values you have actually seen. When omitted, beamline uses the
strict default budget of 25.

A budget that is not a whole number from 0 to 65535 is a `400`, never a silent
fall back to the default.

### findings

| field | type | |
| --- | --- | --- |
| `id` | string | Stable trait id, e.g. `objectives/execution/shell/bash`. |
| `crit` | int | 3 notable, 4 suspicious, 5 hostile. |
| `file` | string\|null | Path inside the artifact. |
| `pkg` | string\|null | The component it is about. |
| `desc` | string\|null | One line. |
| `off` | int\|null | Byte offset within `file`. |
| `line` | int\|null | 1-based source line. Text matches only. |

`id` and `crit` are the only fields always present. The rest are **omitted**
when there is nothing to say — `file`, `desc`, `off` and `line` are all absent
when the verdict came from the corpus rather than from a local index, because
the corpus keeps the trait and its criticality and not the detail.

That is the opposite of the rule the enclosing decision object follows, and the
two differ because the questions differ. A decision answers a fixed set of
things, so its nine keys never move and `"engine_version": null` is itself the
answer to "which engine". A finding has no fixed set: how much is known about
one depends on where it came from, and four nulls would be most of the object.
Read a finding's extras with a presence check, not a null check.

Only matches native to the file they are reported on appear. An archive repeats
its members' findings on itself; those copies are dropped in favour of the
member's own.

### Answers nobody measured

Some artifacts have never been analyzed, and outside threat intelligence knows
about them anyway. Rather than answer `unanalyzed` about a package several
independent feeds call malware, we answer with what those feeds say — marked as
what it is.

Such an answer carries `engine_version: null` and `analyzed_at: null` alongside
a real `decision`. **`engine_version` is the field to branch on:** it is present
whenever an engine of ours produced the verdict and absent whenever nothing
did. A finding names the evidence:

```json
{
  "decision": "block",
  "purl": "npm/left-pad@1.3.0",
  "severity": "hostile",
  "fires_at": 10,
  "reason": "Cited as malicious by 2 independent threat intelligence feeds.",
  "findings": [{"id": "intel/feed/malicious", "crit": 5, "desc": "…", "file": null, "pkg": null, "off": null, "line": null}],
  "engine_version": null,
  "analyzed_at": null
}
```

Ids under `intel/` describe where a claim came from rather than what an
artifact does, which is why they are namespaced apart from the analyzer's own
taxonomy. `fires_at` follows how much independent agreement there is: several
unrelated operators reach a tighter level than one, and a feed that publishes
adjudicated reports reaches a tighter one than a detector's prediction. Feeds
that share a corpus count once — two mirrors of one advisory database are one
opinion, not two.

The same evidence annotates artifacts we *have* analyzed. There, `fires_at` is
the tighter of the two: outside citations can only make an answer stricter,
never more permissive, and `engine_version` is present because an engine did
produce the verdict.

`POST /v1/analyze` never answers from a citation alone. An artifact nobody has
analyzed is exactly what that route exists to change, so it runs the analysis
and returns the measured answer.

## Errors

```json
{
  "error": {
    "code": "too_many_packages",
    "message": "51 packages exceeds the limit of 50 for a URL."
  }
}
```

`code` is stable and safe to branch on. `message` is for people and may be
reworded.

| code | status | |
| --- | --- | --- |
| `missing_package` | 400 | Neither `purl`, `url`, nor `sha256`. |
| `multiple_locators` | 400 | `purl` and `url` were supplied together. |
| `invalid_url` | 400 | Not an absolute `http` or `https` URL. |
| `url_with_body` | 400 | An exact URL cannot be combined with uploaded bytes. |
| `invalid_false_positive_budget` | 400 | Not a whole number from 0 to 65535. |
| `invalid_follow_policy` | 400 | Unknown, empty, or contradictory `follow` selection. |
| `invalid_purl` | 400 | Not a package URL. |
| `invalid_sha256` | 400 | Not 64 hexadecimal characters. |
| `too_many_packages` | 413 | Over 50 in one URL. Use several requests. |
| `empty_artifact` | 400 | The uploaded body had no bytes. |
| `artifact_too_large` | 413 | Over the 16 MiB upload cap; use `purl`. |
| `invalid_body` | 400 | The body could not be read. |

Beamline's own refusals, such as an unknown route, answer an error object
without a package-level decision.

| status | |
| --- | --- |
| 200 | A decision, or a list of them. Includes `unanalyzed` and `unavailable`. |
| 400 | Your request. See `code`. |
| 401 | Bad or missing bearer token when `BEAMLINE_TOKEN` is configured. |
| 404 | No such route. |
| 405 | Right route, wrong method. `Allow` names the one that works. |
| 413 | Too many packages. |
| 429 | At capacity. Retry; it is jittered on our side. |

There is no `503` for a package we could not reach a worker for. That is a
`200` carrying `unavailable`.

## Headers

| header | |
| --- | --- |
| `X-Request-Id` | Send your own to correlate with our logs. |
| `X-Beamline-Source` | `cache`, `kv`, `scan:bloom`, `scan:analysis`, `scan:replica`, `scan:primary`, `none`. Operators only. |
| `X-Beamline-Worker` | Which worker answered. For operators. |
| `Cache-Control` | See below. |
| `Content-Type` | `application/json`; `x-ndjson` from `/v1/analyze`. |

`scan:bloom` means the scan server answered from Bloom-derived knowledge;
`scan:analysis` means it answered from a locally held or newly produced
analysis; and `scan:replica` / `scan:primary` mean it obtained the answer from
Hopper's replica or primary. `cache` and `kv` identify Beamline's own edge
layers. `none` means no backend produced an answer.

## Caching

A verdict is immutable for the engine that produced it and is cached for an
hour. Not knowing is cached for a minute — it stops being true the moment
anything analyzes the artifact. `unavailable` is never cached; it describes this
moment's reachability.

The cached document is independent of `false_positive_budget`. Beamline applies
the caller's budget to its `fires_at` value, so two callers on different budgets
share one cached document while receiving the appropriate decision.

The Cache API is L0. When configured, Workers KV is L1: it stores the same small
document behind a hashed key and repopulates L0 on a hit. Every KV write carries
an expiry — 90 days for a verdict, a minute for `unanalyzed` — measured from the
write, and a read does not refresh it. A verdict is therefore at most 90 days
old before the next caller pays for a fresh one; `KV_MAX_AGE` moves that
horizon.

The scope is `private` on an authenticated deployment — a verdict is knowledge
about your artifact, not public data.

A decision produced by `/v1/analyze` populates the lookup cache for that
artifact. URL, PURL, and SHA-256 spellings are stored as aliases of one
question, and `/v1/analyze` reads those same aliases before it dispatches.
Names alias; policies do not — an answer that followed nothing is filed under
every name for the artifact at `follow=none`, and never over the answer to a
question nobody ran an analysis for.

Asking the expensive way twice therefore costs one analysis, not two: the
second call returns the stored verdict as a single NDJSON line carrying
`X-Beamline-Source: cache`, with no progress frames, because there was no run to
report progress about.

Three things never answer from the cache:

- an **upload**, which is a request to analyze *those bytes*. A PURL sent
  alongside one names provenance, not the artifact in hand.
- a cached `unanalyzed` or `unavailable`. Neither is an analysis: the first says
  nobody has analyzed the package, which is what you are asking us to change,
  and the second says we could not find out.
- a request carrying `X-Beamline-Pin`, which exists to time a specific
  backend.

A `follow` policy is not on that list: it is part of the cache key rather than
a reason to skip it. Two policies can reach opposite verdicts about one
artifact and both be right — bytes that are clean, an install script that is
not — so each is stored under the question it answers and served only for it.
