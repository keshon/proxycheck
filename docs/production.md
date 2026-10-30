# Production deployment

## Build and trust boundary

Build with Go 1.26.10 or a newer patched supported toolchain. The checking
transport verifies TLS certificate chains and hostnames using the system trust
store and requires TLS 1.2 or later. There is no insecure-TLS switch.

HTTP proxy credentials still travel to an `http://` proxy without proxy-hop
encryption; use HTTPS proxies or an appropriate trusted network when that matters.
Target HTTPS verification does not encrypt a plain HTTP proxy's CONNECT headers.

Checks establish configured HTTP assertions. They do not certify a proxy as safe
or anonymous. `ip_comparison` reports `same`, `different`, or `unknown` based on
validated IP observations; no forwarded-header/anonymity label is inferred.
YouTube metadata/image checks do not establish video playback or account access.

## HTTP API access

The default listener is `127.0.0.1:8080`. Without a token, handlers accept only
loopback clients. Set `PROXYCHECK_API_TOKEN` to a randomly generated secret of at
least 32 characters to require authentication. The token is read from the
environment, not a command-line argument, query parameter or checked-in file.

Non-loopback listeners refuse to start without that token. All `/v1/*` calls
then require `Authorization: Bearer <token>`; `/healthz` is unauthenticated.
Configure a TLS reverse proxy or a protected private transport before sending
tokens across a network. Do not rely on loopback trust when placing an unauthenticated
reverse proxy in front of the API: configure the token at the backend too.

There is no CORS support. Requests with a browser `Origin` header are rejected.
`POST /v1/check` requires `Content-Type: application/json`. Unknown fields,
trailing JSON, invalid timeouts and malformed proxy endpoints are rejected.
The entire batch is validated before streaming, so malformed inputs cannot
silently disappear from otherwise successful output.

## Network policy

API proxy destinations are public-only by default. Literal and resolved
addresses are checked; private, loopback, link-local, shared, documentation and
selected special-use/transition ranges are rejected. Every DNS answer must pass.
The dialer connects to a checked literal address, avoiding a second DNS lookup
between validation and connection. This applies to HTTP, HTTPS and SOCKS proxies.

`-allow-private-proxies` explicitly permits private endpoints for trusted
environments. This expands the server's reachable network surface; use it only
when the deployment's access controls and network policy permit it.

Inline API specs are disabled. `-allow-inline-specs` permits inline specs with
public IP literal targets; named targets belong in operator-installed YAML
presets. Presets are trusted configuration. A remote proxy's routing/DNS is
outside the local dialer's control: restrict egress at the host and at controlled
proxies where internal destinations must never be reachable.

## Resource limits

| Resource | Limit |
| --- | --- |
| Request JSON | 1 MiB |
| Proxy entries per batch | 1000 |
| Active check requests | 4 |
| Workers per request | Default 32; maximum 64 |
| Workers shared across the API | 64 |
| Whole API batch | 2 minutes |
| Dial timeout | Default 8s; maximum 30s |
| TLS handshake | Default 6s; maximum 30s |
| Per-proxy preset timeout | Default 20s; maximum 60s |
| Requests per preset | 16, plus an optional IP probe |
| Body scan | Default 256 KiB; can grow to `min_download`, maximum 1 MiB |
| Response headers | 64 KiB |
| Incoming headers | 32 KiB; 10s header timeout |
| Request body upload | 15s read deadline |
| Stream write deadline | 2 minutes |

Busy admission returns 429 with `Retry-After`. There is no unbounded pending-job
queue. These caps bound application work, not total inbound TCP connections;
apply connection/rate limits at the reverse proxy or firewall for public use.

Interrupted reads fail. Body-marker checks need a complete response within the
scan cap; minimum-download-only checks intentionally allow a bounded prefix.
Large response bodies are not accumulated beyond the configured cap plus one
byte used to detect overflow.

When a stream consumer fails, remaining work is canceled. A timed-out or
disconnected stream can end early; consumers should account for how many records
were received rather than infer completion from EOF alone.

## Credential handling and CLI automation

Passwords are masked in normal result output and never included by the API.
Usernames remain visible; protect output when usernames themselves contain secrets.
Masked proxy URLs are rejected when re-ingested. Use original input, or opt into
`-include-credentials` on the CLI to preserve passwords. That opt-in applies to
text and JSON output and may expose passwords on the terminal as well as in
redirected files; protect the destination using file permissions/ACLs.

Sink writes, serialization and flush failures stop the CLI with an error.
Individual failed proxy checks remain data results and do not alone fail a run.

## GitHub Pages

The landing page is static HTML/CSS/JavaScript. It has relative asset paths and
no backend, package installation, login requirement, framework or external font
dependency. It works both at a domain root and under `/proxycheck/`.

1. In the repository's **Settings → Pages**, select **GitHub Actions** as source.
2. Commit/push the site and workflow changes to `main`, or run the GitHub Pages
   workflow manually from `main`.
3. The workflow checks the site, creates `site/dist`, uploads that allowlisted
   artifact, and deploys through the `github-pages` environment.

The artifact contains only `index.html`, `styles.css`, `script.js`, `favicon.svg`
and `.nojekyll`. Go sources, proxy lists and audit files are excluded. GitHub Pages hosts the landing only;
it does not run the proxy checking API. The workflow follows
[GitHub's custom Pages workflow](https://docs.github.com/en/pages/getting-started-with-github-pages/using-custom-workflows-with-github-pages).
