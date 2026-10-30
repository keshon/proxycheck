# proxycheck

Check proxies against target-specific YAML presets from a CLI or streaming HTTP
API. Results include request outcomes, timings and failure classes.

Built-in presets cover a basic HTTPS request, exit-IP comparison, YouTube
metadata and image delivery, and Telegram Bot API access. Custom presets use the
same engine.

Passing a check means its configured HTTP assertions passed. It does not
establish that a proxy is anonymous or suitable for every request. TLS peers
are verified using the system trust store. See [scope](#scope) and
[production deployment](docs/production.md).

## Build and run

The module requires Go 1.26.10 or later. Keep the build toolchain patched;
updating source alone does not patch an existing binary.

```sh
git clone https://github.com/keshon/proxycheck.git
cd proxycheck
go build -o proxycheck ./cmd/proxycheck
./proxycheck presets
./proxycheck run -p basic proxies.txt
```

On Windows, build with `go build -o proxycheck.exe ./cmd/proxycheck` and run
`.\proxycheck.exe presets`. Subsequent examples use `proxycheck` as the executable
name; use `./proxycheck` on Unix or `.\proxycheck.exe` on Windows unless the
binary is on PATH.

Create `proxies.txt` with one proxy per line. The addresses below are reserved
documentation examples, not working proxies:

```text
192.0.2.10:8080
socks5://198.51.100.20:1080
http://user:password@192.0.2.30:3128
```

## Inputs

Supply files, directories, or `-` for stdin. With no paths, input is read from
stdin. Directory traversal is recursive. Blank lines and comment lines beginning
with `#` are skipped; the first whitespace-delimited token on each other line
is parsed as a proxy. Canonically identical proxy URLs are deduplicated.

Accepted forms:

```text
host:port
scheme://host:port
scheme://user:password@host:port
user:password@host:port
[2001:db8::1]:8080
```

Schemes are `http`, `https`, `socks4` and `socks5`. Bare addresses default to
`http`; the SOCKS4 implementation uses SOCKS4a for hostnames. IPv6 literals must
be bracketed. Proxy passwords are masked in result output.
SOCKS4 supports USERID only; password authentication is rejected rather than ignored.

## CLI

Put flags before positional input paths. Run `proxycheck run -h` for help.

| Flag | Default | Purpose |
| --- | --- | --- |
| `-p`, `-preset` | `basic` | Preset name |
| `-c` | `100` | Worker concurrency, from 1 to 256 |
| `-timeout` | `8s` | Dial timeout, not total duration of the preset |
| `-f`, `-format` | `text` | Data format: `text` or `json` |
| `-json` | false | Shorthand for JSON output |
| `-progress` | `auto` | Live display: `auto`, `list`, `bar`, `none` |
| `-ok-only` | false | Keep only passing results in data output |
| `-presets-dir` | User config directory | Custom YAML preset directory |
| `-include-credentials` | false | Include original passwords in output; sensitive opt-in |

```sh
# Target-specific checks
proxycheck run -p youtube proxies.txt

# Save passing proxies; progress goes to stderr
proxycheck run -p youtube --ok-only ./proxies > youtube-ok.txt

# Emit NDJSON for a pipeline
proxycheck run -p basic -json proxies.txt | jq -r 'select(.ok).proxy'

# Request a scrolling progress display while saving data
proxycheck run -p telegram -progress list ./proxies > results.txt

# Read from stdin, with no live display
cat proxies.txt | proxycheck run -p basic -progress none -json
```

### Output and progress

With stdout attached to a terminal and no explicit format/progress flags, the
CLI prints its interactive result table, counter and summary to stdout.
Otherwise, data goes to stdout and progress/summary go to stderr.

- `text`: one `proxy-url # result details` line per result.
- `json`: one JSON object per line (NDJSON), not a single JSON array.
- `-progress list`: print results as they finish.
- `-progress bar`: draw an updating counter/bar.
- `-progress none`: suppress live progress; retain the summary.
- `auto`: use a bar when stdout is redirected and stderr is a terminal;
  otherwise no live display.

Results arrive in completion order. `-ok-only` filters saved data; a separate
live display still counts all checks. A failed proxy check is a result, not by
itself a nonzero CLI exit. Invocation/setup errors, cancellation, and failed
output writes/flushes exit nonzero and stop remaining work.

Annotated text output can be reused as input **for proxies without passwords**:

```sh
proxycheck run -p basic --ok-only proxies.txt > basic-ok.txt
proxycheck run -p youtube basic-ok.txt > youtube-results.txt
```

Authenticated output contains `***` instead of the original password. The parser
rejects those masked lines instead of silently using the wrong credential. JSON
output also redacts passwords. Keep original input, or explicitly opt into a
credential-preserving export:

```sh
# POSIX example: create output readable only by its owner
umask 077
proxycheck run -p basic --ok-only -include-credentials proxies.txt > private-results.txt
```

That output contains plaintext passwords. Keep it private; the HTTP API never
includes passwords. On Windows, use a destination protected by appropriate ACLs.

### Result fields

NDJSON includes `proxy`, `check`, `ok`, `total_ms` and `checked_at`, plus optional
`error_class`, `error`, `connect_ms`, `ttfb_ms`, `exit_ip`, `ip_comparison` and `steps`.
Timings are best-effort measurements; zero/missing phase timings do not prove
that no network activity occurred. The source schema is
[`pkg/check/result.go`](pkg/check/result.go).

| Failure class | Current interpretation |
| --- | --- |
| `timeout` | A network operation or check exceeded its deadline |
| `refused` | The OS reports an actively refused connection |
| `dns` | DNS resolution failed |
| `tls` | A classified TLS failure, including certificate verification failure |
| `protocol` | Proxy/protocol failure or another unclassified transport error |
| `target_block` | Rejected status such as 403/429/451, missing required marker, or present block marker |
| `assertion` | Another expected status/header/download condition failed |
| `input` | The request/spec could not be constructed |

`target_block` is a response heuristic. It does not prove that the exit IP was
the cause, or that retrying with another proxy will succeed.

## Presets

`proxycheck presets` lists the resolved preset set, including custom overrides.

| Preset | Configured check |
| --- | --- |
| `basic` | Fetch `https://api.ipify.org` and require HTTP 200 |
| `anonymity` | Fetch an exit-IP echo and compare it with a directly detected origin IP |
| `youtube` | Fetch YouTube oEmbed metadata and at least 8192 bytes from its image CDN |
| `telegram` | Request Telegram's Bot API endpoint with configured assertions |

The YouTube preset does not verify video playback. Exit-IP comparison does not
inspect forwarded-origin headers or establish anonymity. `ip_comparison` is
`same`, `different`, or `unknown` relative to a validated direct origin-IP
observation. Legacy `anonymity` labels are no longer emitted.

Custom presets are `*.yaml` files in the directory selected by `-presets-dir`,
then `PROXYCHECK_PRESETS`, then Go's `os.UserConfigDir()` plus `proxycheck/presets`:

- Linux: `$XDG_CONFIG_HOME/proxycheck/presets`, or `~/.config/proxycheck/presets`.
- macOS: `~/Library/Application Support/proxycheck/presets`.
- Windows: `%AppData%\proxycheck\presets`.

A custom preset with the same `name` overrides a built-in. Missing directories
are skipped. YAML supports a duration string and request assertions:

```yaml
name: my-service
description: Check a response marker from my service.
timeout: 15s
requests:
  - url: https://example.com/health
    expect:
      status: [200]
      body_contains: ["ready"]
```

Available assertions: `status`, `body_contains`, `body_absent`, `header`
(header-name to substring map), and `min_download` (bytes). Requests default to
GET. Redirects are not followed. An empty status list accepts any 2xx response.
An optional `exit_ip_probe` names a plain-text IP echo URL, fetched once and
validated as an IP address. Specs are limited to 16 requests, a 60-second total
check timeout, and at most 1 MiB of `min_download`. YAML rejects unknown fields
and multiple documents. Custom presets are trusted operator configuration.

Responses are scanned up to 256 KiB, or a larger configured `min_download` up
to 1 MiB. Interrupted reads fail. Body-marker assertions require a complete
response within that scan limit; minimum-download-only checks may intentionally
sample a bounded prefix of a larger response.

## HTTP API

Use the API with trusted clients on a private interface:

```sh
proxycheck serve -addr 127.0.0.1:8080
```

```sh
curl -sN http://127.0.0.1:8080/v1/check \
  -H 'Content-Type: application/json' \
  -d '{"preset":"youtube","proxies":["192.0.2.10:8080","socks5://198.51.100.20:1080"]}'
```

- `GET /v1/presets`: JSON array of preset names and descriptions.
- `POST /v1/check`: stream NDJSON results as valid proxies finish.
- `GET /healthz`: HTTP 200 health response.

The POST body takes `preset`, `proxies`, optional `concurrency` (default 32,
maximum 64), and `dial_timeout` such as `"3s"` (maximum 30s). `Content-Type:
application/json` is required; unknown fields, trailing JSON and any malformed
proxy reject the whole batch before checking starts. Accepted proxies produce
one record each, including duplicates, unless the stream is interrupted.

The server binds to `127.0.0.1:8080` by default. Non-loopback listeners require
`PROXYCHECK_API_TOKEN` with at least 32 characters. When configured, send it in
`Authorization: Bearer <token>` for all `/v1/*` calls. Use TLS termination before
transmitting bearer tokens over an untrusted network.

API limits: 1 MiB request bodies, 1000 proxies per batch, four active check
requests, 64 workers shared across the server, and two minutes per batch. Busy
admission returns HTTP 429. Malformed input returns 400, oversized input 413,
and unsupported content type 415. See [production deployment](docs/production.md)
for network policy and resource bounds.

Proxy destinations must resolve entirely to public addresses, checked and
pinned at dial time. `-allow-private-proxies` explicitly permits private/loopback
proxy endpoints for trusted deployments. Inline `spec` requests are disabled;
`-allow-inline-specs` enables specs whose targets are public IP literals only.
Use operator-installed YAML presets for named targets. JSON spec timeouts accept
strings such as `"15s"` and legacy numeric nanoseconds. Browser-origin requests
are rejected; this is a machine-to-machine API, not a browser checking service.

## Scope

- Results describe the configured HTTP requests and assertions, not every
  target, protocol, media player or application flow.
- Exit-IP comparison does not detect forwarded-origin headers or prove anonymity.
- `target_block` is a response heuristic, not proof that a specific exit IP
  caused the rejection.
- Default output masks passwords; use the original input or explicit credential
  export when credentials must be reused.
- A canceled or disconnected stream may end before every result is delivered.
- Public API deployments need TLS termination, rate limits and network egress
  policy appropriate to their environment, in addition to built-in controls.

The tool does not scrape proxies, serve a rotating pool, schedule rescans, or
provide a checking GUI.

## Development

[Package layout and checks](docs/development.md) ·
[Landing page source](site/index.html) · [MIT license](LICENSE)
