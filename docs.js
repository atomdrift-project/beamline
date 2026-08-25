const DOCS_HTML = String.raw`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="description" content="Beamline API documentation: cached malware lookup and real-time analysis.">
  <title>Beamline API · isotope¹³</title>
  <style>
    @font-face { font-family: Oxanium; src: url("https://atomdrift.org/assets/fonts/Oxanium-Bold.ttf") format("truetype"); font-display: swap; font-weight: 700; }
    :root { --ink:#0d0008; --mid:#4a2040; --light:#8a6080; --paper:#fff; --mist:#fdf5fc; --pink:#ff00cc; --pink-dark:#cc0077; --line:rgba(255,0,204,.22); --code:#190b15; --max:1180px; }
    * { box-sizing:border-box; }
    html { scroll-behavior:smooth; }
    body { margin:0; background:var(--paper); color:var(--ink); font:16px/1.65 Inter,ui-sans-serif,system-ui,-apple-system,sans-serif; -webkit-font-smoothing:antialiased; }
    a { color:inherit; }
    a:focus-visible { outline:3px solid var(--pink); outline-offset:3px; }
    .topbar { align-items:center; border-bottom:1px solid var(--line); display:flex; justify-content:space-between; margin:0 auto; max-width:var(--max); padding:22px 40px; }
    .brand { font-family:Oxanium,ui-sans-serif,sans-serif; font-size:21px; letter-spacing:-.7px; }
    .brand sup { color:var(--pink); font-size:11px; margin-left:1px; }
    .topbar a { color:var(--mid); font-size:13px; text-decoration:none; }
    .topbar a:hover { color:var(--pink-dark); }
    .shell { display:grid; gap:72px; grid-template-columns:190px minmax(0,760px); margin:0 auto; max-width:var(--max); padding:70px 40px 110px; }
    .toc { position:sticky; top:28px; align-self:start; }
    .toc-label,.eyebrow { color:var(--pink-dark); font-size:10px; font-weight:700; letter-spacing:1.8px; text-transform:uppercase; }
    .toc-label { margin-bottom:15px; }
    .toc a { border-left:1px solid var(--line); color:var(--mid); display:block; font-size:13px; padding:5px 0 5px 14px; text-decoration:none; }
    .toc a:hover { border-color:var(--pink); color:var(--pink-dark); }
    .content { min-width:0; }
    h1,h2,h3 { font-family:Oxanium,ui-sans-serif,sans-serif; font-weight:700; letter-spacing:-1.5px; line-height:1.1; }
    h1 { font-size:clamp(38px,6vw,62px); margin:14px 0 18px; }
    h2 { border-top:1px solid var(--line); font-size:29px; margin:78px 0 20px; padding-top:22px; }
    h3 { font-size:19px; letter-spacing:-.7px; margin:36px 0 10px; }
    p { color:var(--mid); margin:0 0 18px; max-width:710px; }
    .lead { font-size:19px; line-height:1.6; max-width:620px; }
    .eyebrow { margin-bottom:8px; }
    .facts { display:flex; flex-wrap:wrap; gap:9px; margin:28px 0 42px; }
    .fact { background:var(--mist); border:1px solid var(--line); color:var(--mid); font-size:12px; padding:7px 10px; }
    .fact strong { color:var(--ink); font-weight:600; }
    .endpoint-table { border-collapse:collapse; margin:22px 0 0; width:100%; }
    .endpoint-table th,.endpoint-table td { border-bottom:1px solid var(--line); padding:12px 8px 12px 0; text-align:left; vertical-align:top; }
    .endpoint-table th { color:var(--light); font-size:11px; letter-spacing:1px; text-transform:uppercase; }
    .endpoint-table td:first-child { color:var(--pink-dark); font-family:ui-monospace,SFMono-Regular,Menlo,monospace; font-size:13px; white-space:nowrap; }
    .endpoint-table td:last-child { color:var(--mid); font-size:14px; }
    code,pre { font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace; }
    code { color:var(--pink-dark); font-size:.92em; }
    pre { background:var(--code); border-left:3px solid var(--pink); color:#ffeaf9; font-size:12px; line-height:1.65; margin:18px 0 24px; overflow-x:auto; padding:18px 20px; tab-size:2; }
    .note { background:var(--mist); border-left:3px solid var(--pink); color:var(--mid); margin:20px 0; padding:14px 17px; }
    .note strong { color:var(--ink); }
    .steps { counter-reset:step; list-style:none; margin:18px 0 22px; padding:0; }
    .steps li { counter-increment:step; margin:12px 0; padding-left:32px; position:relative; }
    .steps li::before { color:var(--pink-dark); content:counter(step); font-family:Oxanium,sans-serif; left:0; position:absolute; top:1px; }
    .muted { color:var(--light); font-size:14px; }
    .footer { border-top:1px solid var(--line); margin-top:78px; padding-top:24px; }
    @media (max-width:800px) { .topbar { padding:18px 22px; } .shell { display:block; padding:46px 22px 80px; } .toc { margin-bottom:52px; position:static; } .toc a { display:inline-block; margin:0 18px 4px 0; padding:0 0 0 10px; } h2 { margin-top:58px; } }
  </style>
</head>
<body>
  <header class="topbar">
    <div class="brand">isotope<sup>¹³</sup> / beamline</div>
    <a href="https://lab.atomdrift.org/">Browse sample data →</a>
  </header>
  <div class="shell">
    <aside class="toc" aria-label="Contents">
      <div class="toc-label">On this page</div>
      <a href="#start">Start here</a><a href="#lookup">Lookup</a><a href="#analyze">Analyze</a><a href="#follow">Following</a><a href="#response">Response</a><a href="#proxy">Transparent proxy</a><a href="#errors">Errors</a><a href="#support">Support</a>
    </aside>
    <main class="content">
      <section id="start">
        <div class="eyebrow">Beamline API · isotope¹³</div>
        <h1>Lookup what we know.<br>Analyze what we don’t.</h1>
        <p class="lead">A small API for malware analysis. Lookups are cheap and cacheable. Analysis is blocking, streaming, and retryable.</p>
        <div class="facts"><span class="fact"><strong>Endpoint</strong> https://api.isotope13.ai</span><span class="fact"><strong>Auth</strong> optional Bearer token</span><span class="fact"><strong>Formats</strong> JSON + NDJSON</span></div>
        <table class="endpoint-table" aria-label="Endpoint summary"><thead><tr><th>Method</th><th>Route</th><th>Use it for</th></tr></thead><tbody>
          <tr><td>GET</td><td>/v1/lookup</td><td>Ask whether an artifact is already known.</td></tr>
          <tr><td>POST</td><td>/v1/analyze</td><td>Analyze a PURL, exact URL, or uploaded bytes.</td></tr>
          <tr><td>GET</td><td>/healthz</td><td>Check liveness. No authentication.</td></tr>
        </tbody></table>
        <div class="note"><strong>Authentication is optional.</strong> Set <code>BEAMLINE_TOKEN</code> on the Worker to require <code>Authorization: Bearer …</code>. Leave it unset for an open API.</div>
      </section>

      <section id="lookup"><h2>Lookup</h2>
        <p><code>GET /v1/lookup</code> never analyzes. It checks the edge cache, Workers KV, and the scan fleet, in that order. Ask with a PURL, an exact URL, or a SHA-256.</p>
        <h3>PURL</h3><pre><code>curl -sS \
  "https://api.isotope13.ai/v1/lookup?purl=pkg%3Anpm%2Faxios%401.19.0"</code></pre>
        <h3>Exact URL</h3><pre><code>curl -sS \
  "https://api.isotope13.ai/v1/lookup?url=https%3A%2F%2Fregistry.npmjs.org%2Faxios%2F-%2Faxios-1.19.0.tgz"</code></pre>
        <h3>SHA-256</h3><pre><code>curl -sS \
  "https://api.isotope13.ai/v1/lookup?sha256=dd46efaa38534ef67370ac3ebc6151e4cf475fdb4bb68f8e2003b432d11d92c2"</code></pre>
        <p class="muted">URL-encode PURLs and URLs. Repeat <code>purl</code> for up to 50 packages; one question returns one object, many questions return a list.</p>
      </section>

      <section id="analyze"><h2>Analyze</h2>
        <p><code>POST /v1/analyze</code> streams newline-delimited JSON. Read lines until one contains <code>decision</code>. A fast analysis may return only that final object.</p>
        <h3>PURL</h3><pre><code>curl -sN -X POST \
  "https://api.isotope13.ai/v1/analyze?purl=pkg%3Acargo%2Ftokio%401.40.0"</code></pre>
        <h3>Exact URL</h3><pre><code>curl -sN -X POST \
  "https://api.isotope13.ai/v1/analyze?url=https%3A%2F%2Fexample.com%2Fsample.tgz&amp;follow=none"</code></pre>
        <p>The URL is fetched verbatim. Beamline records the URL, the resolved PURL when known, and the resulting SHA-256 as cache aliases.</p>
        <h3>Upload bytes</h3><pre><code>curl -sN -X POST \
  --data-binary @sample.tgz \
  -H "Content-Type: application/octet-stream" \
  "https://api.isotope13.ai/v1/analyze"</code></pre>
        <p>Archives, binaries, and source are accepted. The default upload limit is 16 MiB.</p>
      </section>

      <section id="follow"><h2>Following discovered references</h2>
        <p><code>follow</code> controls retrieval of dependencies and references found inside the requested artifact. It does not change how the requested artifact is fetched.</p>
        <table class="endpoint-table" aria-label="Follow policy values"><thead><tr><th>Value</th><th>Retrieves</th></tr></thead><tbody>
          <tr><td>none</td><td>Only the requested artifact.</td></tr><tr><td>dependencies</td><td>Dependencies in manifests and lockfiles.</td></tr><tr><td>references</td><td>Packages and URLs named by install or download commands.</td></tr><tr><td>ci-actions</td><td>Third-party CI actions; also implies dependencies.</td></tr><tr><td>all</td><td>Every category above.</td></tr>
        </tbody></table>
        <pre><code>curl -sN -X POST \
  "https://api.isotope13.ai/v1/analyze?url=https%3A%2F%2Fexample.com%2Fsample.tgz&amp;follow=none"</code></pre>
        <p>Omitting <code>follow</code> uses the deployment policy. An explicit follow policy bypasses the shared canonical verdict cache and is not written over it.</p>
      </section>

      <section id="response"><h2>Response</h2>
        <pre><code>{
  "decision": "allow",
  "purl": "pkg:npm/axios@1.19.0",
  "url": null,
  "sha256": "a511049fdaec40a320368b3ee965079b3e14481f82d052584f746bbdc3f01ede",
  "severity": "benign",
  "fires_at": -1,
  "reason": null,
  "findings": [],
  "engine_version": "2.8.0",
  "analyzed_at": "2026-08-23T11:48:00Z"
}</code></pre>
        <p><code>allow</code> is not hostile at your budget. <code>block</code> is hostile. <code>unknown</code> means nobody has analyzed it. <code>unavailable</code> means Beamline could not answer; it says nothing about the artifact.</p>
        <p><code>fires_at</code> is the tightest false-positive budget at which the artifact is hostile, measured per 100 million benign files. <code>-1</code> never fires. The default <code>false_positive_budget</code> is 25; pass a different whole number from 0 to 65535 on either route.</p>
        <p>For uploads and PURL analysis, intermediate lines carry progress. They are telemetry, not verdicts. Retry if a stream ends without a decision.</p>
      </section>

      <section id="proxy"><h2>Transparent proxy integration</h2>
        <p>If Beamline sits behind a proxy that observes package downloads, keep the integration narrow. Three rules prevent most privacy mistakes:</p>
        <ol class="steps"><li><strong>Use <code>url</code>.</strong> Pass the exact URL already resolved by the proxy. Beamline fetches that URL and returns the digest.</li><li><strong>Set <code>follow=none</code>.</strong> Analyze the downloaded artifact only. Traversing its dependency graph can fetch additional URLs.</li><li><strong>Whitelist domains.</strong> Only send URLs from domains you explicitly approve. Do not forward arbitrary user-supplied URLs.</li></ol>
        <pre><code>curl -sN -X POST \
  "https://api.isotope13.ai/v1/analyze?url=${"${EXACT_URL}"}&amp;follow=none"</code></pre>
        <p class="muted">Preserve the returned <code>sha256</code> and cache the result on your side too.</p>
      </section>

      <section id="errors"><h2>Errors</h2>
        <p>Errors are JSON with a stable <code>error.code</code> and a human-readable message.</p>
        <pre><code>{ "error": { "code": "invalid_url", "message": "url must be an absolute http or https URL." } }</code></pre>
        <p><code>400</code> means the request is wrong. <code>413</code> means too many packages or an oversized upload. <code>429</code> means capacity is temporarily full; retry with backoff. A package-level outage is a <code>200</code> with <code>decision: "unavailable"</code>.</p>
      </section>

      <section id="support" class="footer"><h2>Support</h2><p>Beamline is a work in progress. Questions and sharp edges belong at <a href="mailto:t@isotope13.ai">t@isotope13.ai</a>.</p><p class="muted"><a href="https://github.com/atomdrift-project/beamline">Source on GitHub</a> · <a href="https://lab.atomdrift.org/">Sample data</a></p></section>
    </main>
  </div>
</body>
</html>`;

export function docsResponse() {
  return new Response(DOCS_HTML, {
    status: 200,
    headers: {
      "content-type": "text/html; charset=utf-8",
      "cache-control": "public, max-age=300",
      "content-security-policy": "default-src 'self' https://atomdrift.org; style-src 'unsafe-inline' https://atomdrift.org; font-src https://atomdrift.org; img-src 'none'; base-uri 'none'; form-action 'none'",
      "x-content-type-options": "nosniff",
    },
  });
}
