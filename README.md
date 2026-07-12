# proxycheck

A small Go tool that does one thing well: **answer "does this proxy work for this
target, and how well?"** — with an honest, machine-readable result.

It is preset-based. "Can YouTube work through this proxy" is not a special mode
baked into the engine; it's just one *check preset* — a declarative YAML spec.
`basic`, `anonymity`, `youtube`, and `telegram` ship built in, and you add your
own by dropping a YAML file in a directory. The core engine knows nothing about
any specific target.

## Why it's shaped this way

The valuable output isn't `alive: true/false`. It's the **error class**:

| ok | error_class | meaning |
|----|-------------|---------|
| ✓  | —           | works for this target |
| ✗  | `timeout`   | proxy unreachable / too slow |
| ✗  | `refused`   | nothing listening |
| ✗  | `dns`       | host didn't resolve |
| ✗  | `tls`       | TLS handshake failed |
| ✗  | `protocol`  | not a valid proxy / auth rejected |
| ✗  | `target_block` | proxy is **alive** but the target rejected its exit IP (403/451/geo-block/missing marker) |
| ✗  | `assertion` | reached the target, but the response wasn't what the preset requires |

"Dead proxy" vs "live proxy that YouTube blocks" are different facts. Collapsing
them into a boolean is exactly what makes generic proxy checkers useless for
targeted work.

## Install / build

```sh
go build -o proxycheck ./cmd/proxycheck
```

## Use — three surfaces, one engine

**CLI (interactive):** on a terminal you get a colored table with a live counter.
```sh
proxycheck run -p youtube proxies.txt
```

**CLI (saving / piping):** two independent knobs — the **data** format written
to stdout, and the **progress** display drawn on stderr.
```sh
proxycheck run -p youtube ./proxies > working.txt              # text data + progress bar
proxycheck run -p youtube -progress list ./proxies > working.txt   # watch results scroll
proxycheck run -p basic -json proxies.txt | jq -r 'select(.ok).proxy'
```

Paths may be files *or* directories (directories are walked recursively).

### Output: data format (`-f`, `--format`) vs. progress (`--progress`)

These are separate concerns, which is what lets you save a clean file *and*
watch progress at the same time without the two fighting over one stream.

**Data → stdout** (`-f text|json`, default `text`; `-json` is shorthand):

| format | what it is |
|--------|-----------|
| `text` *(default)* | `address # info` per line — **round-trips** as input |
| `json` | one JSON object per line (NDJSON) |

```
socks5://68.71.243.14:4145 # ok connect=1969ms ttfb=2456ms total=2456ms exit=5.6.7.8 anonymous
http://183.109.79.187:80 # fail protocol: unexpected EOF
```
The proxy is the first token, so a saved `text` file feeds straight back in.

**Progress → stderr** (`--progress list|bar|none`, default `auto`):

| mode | what it shows |
|------|---------------|
| `list` | one decorated result line as each completes (like the table) |
| `bar`  | a single self-updating progress bar |
| `none` | nothing live — just the final summary |
| `auto` *(default)* | `bar` when you're saving stdout to a file, else `none` |

The run summary always goes to stderr, so a redirected stdout stays a clean data
file. On a terminal with no `-format`/`-progress` override you simply get the
interactive table. Add `--ok-only` to keep only passing proxies in the file (the
live view still shows everything).

**HTTP API (inside a bigger system):** streams NDJSON as each proxy finishes.
```sh
proxycheck serve -addr :8080
```
```sh
curl -sN localhost:8080/v1/check \
  -d '{"preset":"youtube","proxies":["1.2.3.4:8080","socks5://5.6.7.8:1080"]}'
# GET /v1/presets lists available checks
```

The API is deliberately thin: no job queue, no database, no scheduler. The
caller owns persistence and scheduling — this endpoint just checks and streams.

## Recipes

```sh
# Quick reachability sweep of one file, on your terminal (interactive table)
proxycheck run -p basic proxies.txt

# Find proxies that reach YouTube, save the working ones to a file, watch a bar
proxycheck run -p youtube --ok-only ./proxies > youtube-ok.txt

# Watch each result scroll by while still saving a clean file
proxycheck run -p telegram -progress list ./proxies > telegram.txt

# See exit IPs and anonymity for a list, as JSON, pull the elite/anonymous ones
proxycheck run -p anonymity -json proxies.txt | jq -r 'select(.anonymity=="anonymous").proxy'

# Fast, aggressive sweep: 500 workers, 3s dial timeout
proxycheck run -p basic -c 500 -timeout 3s ./proxies > alive.txt

# Read every file under a directory (recursive), dedup, check
proxycheck run -p basic ./proxies

# Round-trip: text output feeds straight back in as input
proxycheck run -p basic --ok-only proxies.txt > alive.txt
proxycheck run -p youtube alive.txt > youtube-ok.txt

# Pipe a list in on stdin
cat *.txt | proxycheck run -p basic -json | jq -r 'select(.ok).proxy'

# Use your own presets directory (overrides built-ins by name)
proxycheck run -p my-service -presets-dir ./my-presets proxies.txt

# Silent data-only run for a script (nothing live, summary to stderr)
proxycheck run -p basic -progress none proxies.txt > out.txt 2>/dev/null
```

## Presets

Four built-ins ship in the binary (`proxycheck presets` lists them):

| preset | question it answers |
|--------|--------------------|
| `basic` | Is this a working proxy at all? (reachability only, fast) |
| `anonymity` | What is the exit IP, and does it hide my origin? |
| `youtube` | Can it reach YouTube's API + media CDN from this exit IP? |
| `telegram` | Can it reach Telegram's Bot API (a censorship target)? |

A preset is just a spec like:

```yaml
name: youtube
description: Proxy can reach YouTube and fetch video metadata from this exit IP.
timeout: 15s
requests:
  # oEmbed is a small, stable JSON API — unlike the watch page it does NOT vary
  # by User-Agent or consent state, so the marker check is deterministic.
  - url: "https://www.youtube.com/oembed?url=https://www.youtube.com/watch?v=jNQXAC9IVRw&format=json"
    expect:
      status: [200]
      body_contains: ['"author_name"']
  - url: https://i.ytimg.com/vi/jNQXAC9IVRw/hqdefault.jpg
    expect:
      min_download: 8192                   # throughput probe: actually moves bytes
```

Assertions available per request: `status`, `body_contains`, `body_absent`,
`header`, `min_download`. A spec may also set `exit_ip_probe` (a plain-text IP
echo URL) to capture the exit IP and classify anonymity against your origin IP.

> **On checking "does YouTube work":** the requests run with a browser
> User-Agent, and the check verifies youtube.com is reachable and serving video
> metadata from the proxy's exit IP, plus that the image CDN moves bytes. It does
> **not** prove video *playback* — that goes through `googlevideo.com` with
> signed URLs and the player pipeline, which no single HTTP GET can validate.
> Don't scrape the watch page for markers like `"videoDetails"`: YouTube serves
> bot/consent-gated clients a stripped page without them, so the check fails even
> for working proxies.

Add your own presets in `$XDG_CONFIG/proxycheck/presets/*.yaml` (or point at any
directory with `-presets-dir`, or set `PROXYCHECK_PRESETS`). A user preset with
the same `name:` overrides the built-in.

## Supported proxy inputs

Pass any mix of **files and directories** (directories are read recursively), or
pipe a list on stdin. Each line is one proxy in any of these shapes:

`host:port`, `scheme://host:port`, `scheme://user:pass@host:port`, and
`user:pass@host:port`. Schemes: `http`, `https`, `socks4` (SOCKS4a), `socks5`.
Bare `host:port` defaults to `http`. Lines may carry trailing annotations
(`ip:port # 2.5s`) — the first token wins, so `text`-format output re-ingests
cleanly. Duplicates across all sources are removed.

## Deliberately out of scope

No proxy scraping, no rotation/pool serving, no rescan daemon, no persistence,
no GUI. Each of those is a separate tool that *consumes* this one's NDJSON.

## Layout

```
pkg/check/          engine — parse, dial (http/socks4/socks5), spec eval, pool. No target knowledge.
internal/presets/   embedded YAML specs + user-override loader
internal/cli/        input reader, table + JSONL writers
internal/server/     POST /v1/check (NDJSON stream), GET /v1/presets
internal/commands/   run / serve / presets as command.Command, in a registry
cmd/proxycheck/      thin main: builds the registry and dispatches by name
```

Subcommands implement the [github.com/keshon/command](https://github.com/keshon/command)
`Command` interface (`Name`/`Description`/`Run`) and live in a `command.Registry`;
`main` just dispatches by name and prints usage straight from the registry. Each
command is wrapped with panic-recovery middleware via `command.Apply`. Flag
parsing stays inside each command, so the same command types could be driven from
another transport (Discord, HTTP, a worker) without touching the check engine.
