function docsHtml(authRequired) {
  return String.raw`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="description" content="Beamline is an API for finding 0-day malware in the software supply chain, with a false-positive policy you control.">
  <title>Beamline API · software supply-chain malware detection · isotope¹³</title>
  <style>
    @font-face { font-family: Oxanium; src: url("https://atomdrift.org/assets/fonts/Oxanium-Bold.ttf") format("truetype"); font-display: swap; font-weight: 700; }
    :root { --ink:#0d0008; --mid:#4a2040; --light:#6e6e73; --paper:#fff; --mist:#fdf5fc; --pink:#ff00cc; --pink-dark:#9f005f; --line:rgba(255,0,204,.22); --code:#f2f2f7; --code-ink:#1d1d1f; --code-muted:#6e6e73; --max:1180px; }
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
    .shell { display:grid; gap:clamp(36px,4vw,52px); grid-template-columns:136px minmax(0,1fr); margin:0 auto; max-width:var(--max); padding:70px 40px 110px; }
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
    section[id],h3[id] { scroll-margin-top:24px; }
    .heading-link { color:inherit; display:inline-block; text-decoration:none; }
    .heading-link::after { color:var(--pink-dark); content:"#"; font:600 .55em/1 ui-monospace,SFMono-Regular,Menlo,monospace; margin-left:.45em; opacity:0; }
    .heading-link:hover::after,.heading-link:focus-visible::after { opacity:1; }
    .new-label { background:var(--mist); border:1px solid var(--pink); border-radius:999px; color:var(--pink-dark); display:inline-block; font:700 10px/1 Inter,ui-sans-serif,system-ui,sans-serif; letter-spacing:.8px; margin-left:8px; padding:4px 7px 3px; text-transform:uppercase; vertical-align:.25em; }
    p { color:var(--mid); margin:0 0 18px; max-width:none; }
    .lead { font-size:19px; line-height:1.6; max-width:820px; }
    .eyebrow { margin-bottom:8px; }
    .facts { display:flex; flex-wrap:wrap; gap:9px; margin:28px 0 42px; }
    .fact { background:var(--mist); border:1px solid var(--line); color:var(--mid); font-size:12px; overflow-wrap:anywhere; padding:7px 10px; }
    .fact strong { color:var(--ink); font-weight:600; }
    .hero-points { display:grid; gap:24px; grid-template-columns:repeat(3,minmax(0,1fr)); margin:34px 0 42px; }
    .hero-point { border-top:2px solid var(--pink); padding-top:11px; }
    .hero-point-title { color:var(--ink); display:block; font-size:14px; font-weight:700; }
    .hero-point p { font-size:14px; line-height:1.5; margin:6px 0 0; }
    .endpoint-table { border-collapse:collapse; margin:22px 0 0; width:100%; }
    .endpoint-table th,.endpoint-table td { border-bottom:1px solid var(--line); padding:12px 8px 12px 0; text-align:left; vertical-align:top; }
    .endpoint-table th { color:var(--light); font-size:11px; letter-spacing:1px; text-transform:uppercase; }
    .endpoint-table td:first-child { color:var(--pink-dark); font-family:ui-monospace,SFMono-Regular,Menlo,monospace; font-size:13px; white-space:nowrap; }
    .endpoint-table td:last-child { color:var(--mid); font-size:14px; }
    .endpoint-table + p { margin-top:18px; }
    .route-example { color:var(--code-muted); font-size:12px; margin:-2px 0 10px; overflow-wrap:anywhere; }
    .route-example code { color:var(--code-ink); white-space:normal; }
    code,pre { font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace; }
    code { color:var(--pink-dark); font-size:.92em; }
    pre { background:var(--code); border:1px solid #d1d1d6; border-left:3px solid var(--pink); border-radius:7px; color:var(--code-ink); font-size:12px; line-height:1.65; margin:18px 0 24px; overflow-x:auto; padding:18px 20px; tab-size:2; }
    pre code { color:inherit; }
    .runner { margin:18px 0 26px; }
    .request { align-items:start; background:var(--code); border:1px solid #d1d1d6; border-left:3px solid var(--pink); border-radius:8px; display:grid; grid-template-columns:minmax(0,1fr) auto; overflow:hidden; }
    .request pre { border:0; border-radius:0; grid-column:1; grid-row:1; margin:0; min-width:0; overflow-wrap:anywhere; padding:18px 8px 18px 20px; white-space:pre-wrap; }
    .run-button { background:var(--pink-dark); border:0; border-radius:6px; color:#fff; cursor:pointer; font:600 13px/1.2 Inter,ui-sans-serif,system-ui,sans-serif; grid-column:2; grid-row:1; margin:9px; min-height:44px; min-width:64px; padding:10px 16px; }
    .run-button:hover { background:#760046; }
    .run-button:disabled { cursor:wait; opacity:.55; }
    .run-button:focus-visible { outline:3px solid var(--pink); outline-offset:2px; }
    .response { background:#fff; border:1px solid #d1d1d6; border-radius:8px; display:none; margin-top:10px; overflow:hidden; }
    .runner.has-response .response { display:block; }
    .response-head { align-items:center; color:var(--code-muted); display:flex; font-size:11px; font-weight:600; justify-content:space-between; letter-spacing:.8px; padding:10px 16px 0; text-transform:uppercase; }
    .response-state { color:var(--pink-dark); font-weight:500; letter-spacing:0; text-transform:none; }
    .run-output { background:#fff; border:0; color:var(--code-ink); display:block; font-size:12px; margin:0; max-height:300px; overflow:auto; padding:12px 16px 16px; white-space:pre-wrap; }
    .run-output[data-state="error"] { border-left:3px solid #b00020; }
    .file-picker { align-items:center; display:flex; flex-wrap:wrap; gap:10px; grid-column:1 / -1; padding:12px 16px; }
    .file-picker input { color:var(--code-ink); font-size:13px; max-width:100%; }
    .file-picker label { color:var(--code-muted); font-size:12px; }
    .note { background:var(--mist); border-left:3px solid var(--pink); color:var(--mid); margin:20px 0; padding:14px 17px; }
    .note strong { color:var(--ink); }
    .steps { counter-reset:step; list-style:none; margin:18px 0 22px; padding:0; }
    .steps li { counter-increment:step; margin:12px 0; padding-left:32px; position:relative; }
    .steps li::before { color:var(--pink-dark); content:counter(step); font-family:Oxanium,sans-serif; left:0; position:absolute; top:1px; }
    .meanings { margin:0 0 18px; padding-left:22px; }
    .meanings li { color:var(--mid); margin:8px 0; }
    .meanings li::marker { color:var(--pink-dark); }
    .muted { color:var(--light); font-size:14px; }
    .footer { border-top:1px solid var(--line); margin-top:78px; padding-top:24px; }
    @media (max-width:800px) {
      .topbar { align-items:flex-start; gap:12px; padding:18px 20px; }
      .topbar a { font-size:12px; text-align:right; }
      .shell { display:block; padding:42px 20px 72px; }
      .toc { margin-bottom:48px; position:static; }
      .toc a { display:inline-block; margin:0 16px 8px 0; padding:0 0 0 10px; }
      h1 { font-size:clamp(36px,11vw,52px); }
      h2 { font-size:26px; margin-top:58px; }
      .lead { font-size:18px; }
      .hero-points { grid-template-columns:1fr; gap:22px; }
      .endpoint-table { display:block; overflow-x:auto; }
      .endpoint-table th,.endpoint-table td { min-width:120px; }
      .route-example { margin-bottom:9px; }
      pre { font-size:12px; padding:15px; }
      .request pre { padding:15px 6px 15px 15px; }
      .file-picker { align-items:flex-start; flex-direction:column; }
      .file-picker input { font-size:12px; }
    }
  </style>
</head>
<body>
  <header class="topbar">
    <div class="brand">isotope<sup>13</sup> / beamline</div>
    <a href="https://lab.atomdrift.org/">Browse sample data →</a>
  </header>
  <div class="shell">
    <aside class="toc" aria-label="Contents">
      <div class="toc-label">On this page</div>
      <a href="#start">Start here</a><a href="#lookup">Lookup</a><a href="#analyze">Analyze</a><a href="#false-positive-budget">False-positive budget</a><a href="#follow">Following references</a><a href="#response">Response</a><a href="#use-cases">Use cases</a><a href="#errors">Errors</a><a href="#support">Support</a>
    </aside>
    <main class="content">
      <section id="start">
        <div class="eyebrow">Supply-chain malware detection API</div>
        <h1><a class="heading-link" href="#start">Find 0-day malware in the software supply chain.</a></h1>
        <p class="lead">Beamline is an API for finding 0-day malware in the software supply chain. Calls wait for an assessment and may be retried.</p>
        <div class="hero-points" aria-label="Why Beamline">
          <article class="hero-point"><strong class="hero-point-title">Your false-positive policy</strong><p>Set <code>false_positive_budget</code> to match your risk tolerance, then use the measured <code>fires_at</code> level for any additional policy.</p></article>
          <article class="hero-point"><strong class="hero-point-title">Built for what is not known yet</strong><p>Analyze packages, exact downloads, and uploaded artifacts—not just files that already appear on a threat list.</p></article>
          <article class="hero-point"><strong class="hero-point-title">Open-source foundation</strong><p>Beamline is based on the open-source <a href="https://atomdrift.org/">Atomdrift project</a>.</p></article>
        </div>
        <div class="facts"><span class="fact"><strong>Endpoint</strong> https://api.isotope13.ai</span><span class="fact"><strong>Auth</strong> Anonymous / Bearer Token</span><span class="fact"><strong>Formats</strong> JSON + NDJSON</span></div>
        <table class="endpoint-table" aria-label="Endpoint summary"><thead><tr><th>Method</th><th>Route</th><th>Use it for</th></tr></thead><tbody>
          <tr><td>GET</td><td>/v1/lookup</td><td>Ask whether an artifact is already known.</td></tr>
          <tr><td>POST</td><td>/v1/analyze</td><td>Analyze a PURL, exact URL, or uploaded bytes.</td></tr>
        </tbody></table>
        ${authRequired ? '<div class="note"><strong>Authentication is required.</strong> Send your key as <code>Authorization: Bearer …</code>.</div>' : ""}
      </section>

      <section id="lookup"><h2><a class="heading-link" href="#lookup">Lookup</a></h2>
        <p><code>GET /v1/lookup</code> returns what we already know. It never starts an analysis. Ask with a <a href="https://github.com/package-url/purl-spec">PURL</a>, an exact URL, or a SHA-256.</p>
        <h3 id="lookup-purl"><a class="heading-link" href="#lookup-purl">PURL</a></h3>
        <div class="route-example"><code>GET /v1/lookup?purl=…</code></div>
        <div class="runner" data-runner data-method="GET" data-path="/v1/lookup?purl=pkg%3Anpm%2Faxios%401.19.0">
          <div class="request"><button class="run-button" type="button" aria-label="Run PURL lookup example">Run</button><pre><code>curl -sS \
  "https://api.isotope13.ai/v1/lookup?purl=pkg%3Anpm%2Faxios%401.19.0"</code></pre></div>
          <div class="response"><div class="response-head"><span>Response</span><span class="response-state">Ready</span></div><pre class="run-output" aria-live="polite"></pre></div>
        </div>
        <p class="muted">URL-encode PURLs. Repeat <code>purl</code> for up to 50 packages. One PURL returns an object; several return a list.</p>
        <h3 id="lookup-url"><a class="heading-link" href="#lookup-url">Exact URL <span class="new-label">New</span></a></h3>
        <div class="route-example"><code>GET /v1/lookup?url=…</code></div>
        <div class="runner" data-runner data-method="GET" data-path="/v1/lookup?url=https%3A%2F%2Fregistry.npmjs.org%2Faxios%2F-%2Faxios-1.19.0.tgz">
          <div class="request"><button class="run-button" type="button" aria-label="Run exact URL lookup example">Run</button><pre><code>curl -sS \
  "https://api.isotope13.ai/v1/lookup?url=https%3A%2F%2Fregistry.npmjs.org%2Faxios%2F-%2Faxios-1.19.0.tgz"</code></pre></div>
          <div class="response"><div class="response-head"><span>Response</span><span class="response-state">Ready</span></div><pre class="run-output" aria-live="polite"></pre></div>
        </div>
        <p class="muted">URL-encode the <code>url</code> query parameter value.</p>
        <h3 id="lookup-sha256"><a class="heading-link" href="#lookup-sha256">SHA-256</a></h3>
        <div class="route-example"><code>GET /v1/lookup?sha256=…</code></div>
        <div class="runner" data-runner data-method="GET" data-path="/v1/lookup?sha256=dd46efaa38534ef67370ac3ebc6151e4cf475fdb4bb68f8e2003b432d11d92c2">
          <div class="request"><button class="run-button" type="button" aria-label="Run SHA-256 lookup example">Run</button><pre><code>curl -sS \
  "https://api.isotope13.ai/v1/lookup?sha256=dd46efaa38534ef67370ac3ebc6151e4cf475fdb4bb68f8e2003b432d11d92c2"</code></pre></div>
          <div class="response"><div class="response-head"><span>Response</span><span class="response-state">Ready</span></div><pre class="run-output" aria-live="polite"></pre></div>
        </div>
      </section>

      <section id="analyze"><h2><a class="heading-link" href="#analyze">Analyze</a></h2>
        <p><code>POST /v1/analyze</code> streams newline-delimited JSON until an assessment arrives. Complex samples may take minutes. Retrying the same PURL or URL reuses an analysis already in progress.</p>
        <h3 id="analyze-purl"><a class="heading-link" href="#analyze-purl">PURL</a></h3>
        <div class="route-example"><code>POST /v1/analyze?purl=…</code></div>
        <div class="runner" data-runner data-method="POST" data-stream data-path="/v1/analyze?purl=pkg%3Acargo%2Ftokio%401.40.0">
          <div class="request"><button class="run-button" type="button" aria-label="Run PURL analysis example">Run</button><pre><code>curl -sN -X POST \
  "https://api.isotope13.ai/v1/analyze?purl=pkg%3Acargo%2Ftokio%401.40.0"</code></pre></div>
          <div class="response"><div class="response-head"><span>Response</span><span class="response-state">Ready</span></div><pre class="run-output" aria-live="polite"></pre></div>
        </div>
        <h3 id="analyze-url"><a class="heading-link" href="#analyze-url">Exact URL <span class="new-label">New</span></a></h3>
        <div class="route-example"><code>POST /v1/analyze?url=…</code></div>
        <div class="runner" data-runner data-method="POST" data-stream data-path="/v1/analyze?url=https%3A%2F%2Fregistry.npmjs.org%2Faxios%2F-%2Faxios-1.19.0.tgz">
          <div class="request"><button class="run-button" type="button" aria-label="Run exact URL analysis example">Run</button><pre><code>curl -sN -X POST \
  "https://api.isotope13.ai/v1/analyze?url=https%3A%2F%2Fregistry.npmjs.org%2Faxios%2F-%2Faxios-1.19.0.tgz"</code></pre></div>
          <div class="response"><div class="response-head"><span>Response</span><span class="response-state">Ready</span></div><pre class="run-output" aria-live="polite"></pre></div>
        </div>
        <p>Beamline fetches the exact URL and returns its SHA-256. The response includes a PURL when one is known.</p>
        <h3 id="content-upload"><a class="heading-link" href="#content-upload">Upload bytes</a></h3>
        <div class="route-example"><code>POST /v1/analyze</code></div>
        <div class="runner" data-runner data-method="POST" data-stream data-upload data-path="/v1/analyze">
          <div class="request"><button class="run-button" type="button" aria-label="Run content upload example">Run</button><pre><code>curl -sN -X POST \
  --data-binary @sample.tgz \
  -H "Content-Type: application/octet-stream" \
  "https://api.isotope13.ai/v1/analyze"</code></pre>
          <div class="file-picker"><label for="beamline-file">Choose a local sample</label><input id="beamline-file" type="file"></div></div>
          <div class="response"><div class="response-head"><span>Response</span><span class="response-state">Ready</span></div><pre class="run-output" aria-live="polite"></pre></div>
        </div>
        <p>Archives, binaries, and source are accepted. The default upload limit is 16 MiB.</p>
      </section>

      <section id="false-positive-budget"><h2><a class="heading-link" href="#false-positive-budget">False-positive budget</a></h2>
        <p><code>false_positive_budget</code> sets the false-positive rate you accept, measured per 100 million benign files. It defaults to 25 and controls the returned <code>severity</code>. We recommend choosing 1–250; values through 3000 are accepted because 3000 is the suspicious ceiling.</p>
        <pre><code>GET /v1/lookup?purl=…&amp;false_positive_budget=25
POST /v1/analyze?url=…&amp;false_positive_budget=250</code></pre>
        <table class="endpoint-table" aria-label="False-positive budget examples"><thead><tr><th>Value</th><th>Behavior</th></tr></thead><tbody>
          <tr><td>0</td><td>Block only when <code>fires_at</code> is 0.</td></tr><tr><td>25</td><td>Block when <code>fires_at</code> is 0–25. Default.</td></tr><tr><td>250</td><td>Recommended upper end; block when <code>fires_at</code> is 0–250.</td></tr>
        </tbody></table>
        <p>Use a whole number from 0 to 3000. We recommend 1 to 250. The response field <code>fires_at</code> is the tightest budget at which the artifact is hostile. Severity is <code>hostile</code> at or below the requested budget, <code>suspicious</code> above it through 3000, and <code>benign</code> above 3000 or at <code>-1</code>.</p>
      </section>

      <section id="follow"><h2><a class="heading-link" href="#follow">Following references <span class="new-label">New</span></a></h2>
        <p><code>?follow=</code> controls what Beamline retrieves from inside the requested artifact. The artifact itself is always analyzed.</p>
        <table class="endpoint-table" aria-label="Follow policy values and defaults"><thead><tr><th>Value</th><th>Retrieves</th><th>Default for</th></tr></thead><tbody>
          <tr><td>none</td><td>Nothing else.</td><td>URL</td></tr><tr><td>dependencies</td><td>Dependencies in manifests and lockfiles.</td><td>—</td></tr><tr><td>references</td><td>Packages and URLs in install or download commands.</td><td>PURL, SHA-256</td></tr><tr><td>ci-actions</td><td>Third-party CI actions and their dependencies.</td><td>—</td></tr><tr><td>all</td><td>Everything above.</td><td>Upload</td></tr>
        </tbody></table>
        <pre><code>curl -sN -X POST \
  "https://api.isotope13.ai/v1/analyze?purl=pkg%3Anpm%2Faxios%401.19.0&amp;follow=all"</code></pre>
        <p>Omit <code>?follow=</code> to use the default above.</p>
      </section>

      <section id="response"><h2><a class="heading-link" href="#response">Response</a></h2>
        <pre><code>{
  "status": "analyzed",
  "purl": "pkg:npm/axios@1.19.0",
  "sha256": "a511049fdaec40a320368b3ee965079b3e14481f82d052584f746bbdc3f01ede",
  "severity": "benign",
  "fires_at": -1,
  "findings": [],
  "engine_version": "2.8.0",
  "analyzed_at": "2026-08-23T11:48:00Z"
}</code></pre>
        <p><code>status</code> describes whether Beamline has an assessment; <code>severity</code> describes that assessment. A response is factual and does not choose whether your system should proceed. Fields with no value are omitted to save bandwidth:</p>
        <ul class="meanings">
          <li><code>status: "analyzed"</code> means <code>severity</code> was derived from <code>fires_at</code> and the requested budget.</li>
          <li><code>status: "unanalyzed"</code> means nobody has analyzed the artifact; severity is <code>unknown</code>.</li>
          <li><code>status: "unavailable"</code> means Beamline could not answer; severity is <code>unknown</code>.</li>
        </ul>
        <p>For streaming analysis, only the terminal line containing <code>status</code> is the assessment. Other lines report progress. Retry if the stream ends without one.</p>
      </section>

      <section id="use-cases"><h2><a class="heading-link" href="#use-cases">Use cases</a></h2>
        <section aria-labelledby="ci-systems"><h3 id="ci-systems"><a class="heading-link" href="#ci-systems">CI systems</a></h3>
          <p>Use <code>POST /v1/analyze</code> when a job needs a fresh assessment. Name registry dependencies with <code>purl</code>. Upload local build outputs.</p>
          <p>Wait for the terminal line containing <code>status</code>, then apply your policy to <code>severity</code> and <code>fires_at</code>:</p>
          <table class="endpoint-table" aria-label="CI actions by status"><thead><tr><th>Status</th><th>CI action</th></tr></thead><tbody>
            <tr><td>analyzed</td><td>Compare <code>fires_at</code> with your budget.</td></tr><tr><td>unanalyzed</td><td>Apply your unknown-artifact policy.</td></tr><tr><td>unavailable</td><td>Retry with backoff or apply your outage policy.</td></tr>
          </tbody></table>
          <p class="muted">A stream that ends before a status is not an answer. Retry it. Keep the returned <code>sha256</code> with the build record.</p>
        </section>

        <section aria-labelledby="transparent-proxy"><h3 id="transparent-proxy"><a class="heading-link" href="#transparent-proxy">Transparent proxy integration</a></h3>
          <p>Keep proxy integrations narrow:</p>
          <ol class="steps"><li><strong>Use <code>?url=</code>.</strong> Send the exact URL already resolved by the proxy.</li><li><strong>Choose <code>?follow=</code>.</strong> Use <code>?follow=none</code> when the proxy sees every download. If it sees only a subset of commands, such as curl or npm, consider <code>?follow=references</code>. Beamline will also analyze packages and URLs named by install or download commands, which can catch a package that downloads malware later.</li><li><strong>Whitelist domains.</strong> For privacy reasons, never forward arbitrary user-supplied URLs or URLs containing credentials or private query data.</li></ol>
          <pre><code>curl -sN -X POST --get \
  --data-urlencode "url=${"${EXACT_URL}"}" \
  --data "follow=none" \
  "https://api.isotope13.ai/v1/analyze"</code></pre>
          <p class="muted">Keep the returned <code>sha256</code> and cache the result too.</p>
        </section>
      </section>

      <section id="errors"><h2><a class="heading-link" href="#errors">Errors</a></h2>
        <p>Errors are JSON with a stable <code>error.code</code> and a human-readable message.</p>
        <pre><code>{
  "error": {
    "code": "invalid_url",
    "message": "url must be an absolute http or https URL."
  }
}</code></pre>
        <p><code>400</code> means the request is invalid. <code>401</code> means a bearer token is required or invalid. <code>413</code> means too many packages or an oversized upload. <code>429</code> means capacity is temporarily full; retry with backoff. If Beamline cannot answer about an artifact, it returns <code>200</code> with <code>status: "unavailable"</code>.</p>
      </section>

      <section id="support" class="footer"><h2><a class="heading-link" href="#support">Support</a></h2><p>Need help? Have a suggestion? Reach out to <a href="mailto:support@isotope13.ai">support@isotope13.ai</a>.</p><p class="muted"><a href="https://github.com/atomdrift-project/beamline">Source on GitHub</a> · <a href="https://github.com/atomdrift-project/beamline/blob/main/API.md">Full API reference</a> · <a href="https://lab.atomdrift.org/">Sample data</a></p></section>
    </main>
  </div>
  <script>
  (() => {
    const runners = document.querySelectorAll("[data-runner]");

    function show(output, text, state) {
      const runner = output.closest("[data-runner]");
      const status = runner && runner.querySelector(".response-state");
      output.textContent = text;
      output.dataset.state = state || "";
      if (runner) runner.classList.add("has-response");
      if (status) status.textContent = state === "error" ? "Error" : state === "running" ? "Running" : "Complete";
      output.scrollTop = runner && runner.hasAttribute("data-stream") ? output.scrollHeight : 0;
    }

    function prettyJson(text) {
      try {
        return JSON.stringify(JSON.parse(text), null, 2);
      } catch {
        return text;
      }
    }

    async function run(runner, button) {
      const output = runner.querySelector(".run-output");
      const upload = runner.hasAttribute("data-upload");
      const stream = runner.hasAttribute("data-stream");
      const headers = { accept: stream ? "application/x-ndjson" : "application/json" };
      let body;

      if (upload) {
        const input = runner.querySelector("input[type=file]");
        const file = input && input.files[0];
        if (!file) {
          show(output, "Choose a file first.", "error");
          return;
        }
        body = file;
        headers["content-type"] = file.type || "application/octet-stream";
      }

      button.disabled = true;
      button.textContent = "Running…";
      show(output, "Connecting…", "running");

      try {
        const response = await fetch(runner.dataset.path, {
          method: runner.dataset.method || "GET",
          headers,
          body,
        });
        const text = await readResponse(response, stream, output);
        if (!response.ok) {
          show(output, "HTTP " + response.status + "\n" + text, "error");
        }
      } catch (error) {
        show(output, error && error.message ? error.message : String(error), "error");
      } finally {
        button.disabled = false;
        button.textContent = "Run";
      }
    }

    async function readResponse(response, stream, output) {
      if (!stream || !response.body) {
        const text = await response.text();
        const formatted = prettyJson(text);
        show(output, formatted, response.ok ? "done" : "error");
        return formatted;
      }

      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      let pending = "";
      const received = [];
      while (true) {
        const next = await reader.read();
        if (next.done) break;
        pending += decoder.decode(next.value, { stream: true });
        const lines = pending.split("\n");
        pending = lines.pop() || "";
        for (const line of lines) {
          if (line.trim()) received.push(prettyJson(line));
        }
        if (received.length) {
          show(output, received.join("\n\n"), response.ok ? "running" : "error");
        }
      }
      pending += decoder.decode();
      if (pending.trim()) received.push(prettyJson(pending));
      const formatted = received.join("\n\n") || "The stream ended without a response.";
      show(output, formatted, response.ok ? "done" : "error");
      return formatted;
    }

    for (const runner of runners) {
      const button = runner.querySelector(".run-button");
      button.addEventListener("click", () => run(runner, button));
    }
  })();
  </script>
</body>
</html>`;
}

export function docsResponse(authRequired = false) {
  return new Response(docsHtml(authRequired), {
    status: 200,
    headers: {
      "content-type": "text/html; charset=utf-8",
      "cache-control": "public, max-age=300",
      "content-security-policy": "default-src 'self' https://atomdrift.org; style-src 'unsafe-inline' https://atomdrift.org; script-src 'unsafe-inline'; connect-src 'self'; font-src https://atomdrift.org; img-src 'none'; base-uri 'none'; form-action 'none'",
      "x-content-type-options": "nosniff",
    },
  });
}
