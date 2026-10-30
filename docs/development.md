# Development

## Package map

| Path | Responsibility |
| --- | --- |
| `pkg/check/` | Proxy parsing, HTTP/SOCKS dialers, spec evaluation, worker pool and result schema |
| `internal/presets/` | Embedded YAML presets and user directory overrides |
| `internal/cli/` | Input loading, output sinks, progress displays and direct origin-IP lookup |
| `internal/server/` | HTTP handlers and streaming NDJSON adapter |
| `internal/commands/` | `run`, `serve`, and `presets` commands and CLI flags |
| `cmd/proxycheck/` | Registry dispatch and signal cancellation |
| `site/` | Static landing page; no proxy checks run in the visitor's browser |

Target-specific behavior belongs in specs; the checking engine operates on
`check.Spec`. Both the CLI and API call that engine.

Commands implement the [github.com/keshon/command](https://github.com/keshon/command)
`Command` interface (`Name`, `Description`, `Run`) and are registered in
`command.Registry`. `main` dispatches by name and builds usage from the registry.
CLI flag parsing stays in each command. Commands use `command.Apply` for
panic-recovery middleware; recovery in a command does not recover panics in an
independent goroutine. The same command interface can support another adapter
without changing the check engine.

## Checks

Run from the repository root using a patched Go toolchain:

```sh
go build ./...
go test ./...
go vet ./...
go test -race ./...
go run golang.org/x/vuln/cmd/govulncheck@latest ./...
```

The race detector requires platform support and a suitable C toolchain.
govulncheck needs network access to its vulnerability database. Review findings
in addition to process status, particularly when consuming JSON output.

Network tests use loopback fixtures for TLS, HTTP CONNECT, SOCKS4/SOCKS5, body
errors, cancellation, API validation/admission and failed output sinks.

GitHub Actions runs build/test/race/vet on Windows and Linux, a vulnerability
scan, and the static site's interaction/structure checks. Those hosted runs are
separate from checks performed locally.

## Landing page

The page is plain HTML/CSS/JavaScript with local assets and no build step. From
the repository root:

```sh
python -m http.server 4178 --bind 127.0.0.1 --directory site
```

Open `http://127.0.0.1:4178/`. Interactive examples are illustrative; they make
no proxy connections. The README is the canonical usage reference; the site
summarizes the same capabilities and links back to it.

For static interaction and GitHub Pages path checks:

```sh
node --check site/script.js
node site/check.mjs
node site/prepare.mjs
```

`site/prepare.mjs` copies an allowlist into `site/dist`; that directory is the
Pages artifact. See [production deployment](production.md#github-pages) for
repository settings and workflow behavior. No Go server is deployed to Pages.
