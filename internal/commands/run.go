package commands

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/keshon/command"
	"github.com/keshon/proxycheck/internal/cli"
	"github.com/keshon/proxycheck/internal/presets"
	"github.com/keshon/proxycheck/pkg/check"
)

// runCmd checks proxies against a preset.
type runCmd struct{}

func (*runCmd) Name() string { return "run" }
func (*runCmd) Description() string {
	return "check proxies against a preset (files or dirs; stdin if none)"
}

func (*runCmd) Run(ctx context.Context, inv *command.Invocation) error {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	fs.Usage = func() { runUsage(fs.Output()) }
	var (
		presetName  = fs.String("preset", "basic", "preset name")
		conc        = fs.Int("c", 100, "concurrency")
		timeout     = fs.Duration("timeout", 8*time.Second, "per-proxy dial timeout")
		format      = fs.String("format", "text", "output format: text|json")
		jsonShort   = fs.Bool("json", false, "shorthand for -format json")
		progress    = fs.String("progress", "auto", "terminal display: auto|list|bar|none")
		okOnly      = fs.Bool("ok-only", false, "only output passing proxies")
		presetsDir  = fs.String("presets-dir", presetDirDefault(), "user presets directory")
		credentials = fs.Bool("include-credentials", false, "include original proxy passwords in output (sensitive)")
	)
	fs.StringVar(presetName, "p", "basic", "preset name (shorthand)")
	fs.StringVar(format, "f", "text", "output format (shorthand)")
	if err := fs.Parse(inv.Args); err != nil {
		return err
	}
	set := setFlags(fs)
	if *conc < 1 || *conc > check.MaxConcurrency {
		return fmt.Errorf("concurrency must be between 1 and %d", check.MaxConcurrency)
	}
	if *timeout <= 0 || *timeout > 30*time.Second {
		return fmt.Errorf("dial timeout must be between 0 and 30s")
	}

	resolvedFormat, err := resolveFormat(*format, *jsonShort)
	if err != nil {
		return err
	}
	resolvedProgress, err := resolveProgress(*progress)
	if err != nil {
		return err
	}

	presetSet, err := presets.Load(existingDir(*presetsDir))
	if err != nil {
		return err
	}
	spec, ok := presetSet.Get(*presetName)
	if !ok {
		return fmt.Errorf("unknown preset %q (have: %v)", *presetName, presetSet.Names())
	}

	proxies, parseErrs, err := cli.LoadProxies(fs.Args())
	if err != nil {
		return err
	}
	for _, e := range parseErrs {
		fmt.Fprintln(os.Stderr, "skip:", e)
	}
	if len(proxies) == 0 {
		return fmt.Errorf("no valid proxies to check")
	}

	// IP comparison needs a direct origin observation only for probe presets.
	localIP := ""
	if spec.ExitIPProbe != "" {
		localIP = cli.DetectLocalIP(ctx)
	}

	w := buildWriter(resolvedFormat, resolvedProgress, *okOnly, len(proxies),
		set["progress"], set["format"] || set["f"] || set["json"])

	opts := check.Options{Concurrency: *conc, DialTimeout: *timeout, LocalIP: localIP, IncludeCredentials: *credentials}
	err = check.Run(ctx, proxies, spec, opts, func(res check.Result) error { w.Write(res); return w.Err() })
	w.Summary()
	if err != nil {
		return err
	}
	return w.Err()
}

func runUsage(w io.Writer) {
	fmt.Fprint(w, `usage: proxycheck run [flags] [paths...]

Check each proxy against a preset. paths may be files or directories (read
recursively); reads stdin when no paths are given.

flags:
  -p, -preset   preset name (default "basic")
  -c            concurrency (default 100)
  -timeout      per-proxy dial timeout, e.g. 8s
  -f, -format   data written to stdout: text|json (default text)
                  text — "address # info" per line; round-trips as input
                  json — one JSON object per line (NDJSON)
  -json         shorthand for -format json
  -progress     terminal display on stderr while checking: auto|list|bar|none
                  list — one result line as it completes (like the table)
                  bar  — a single updating progress bar
                  none — nothing live, just a final summary
                  auto — bar when saving stdout to a file, else none (default)
  -ok-only      only write proxies that passed (the live view still shows all)
  -presets-dir  directory of user *.yaml presets (overrides built-ins by name)
  -include-credentials  include passwords in output; sensitive, explicit opt-in

On a terminal with no -format/-progress override you get an interactive table.
`)
}

// setFlags returns the set of flag names the user explicitly passed.
func setFlags(fs *flag.FlagSet) map[string]bool {
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
	return set
}

// resolveFormat validates -format and folds in the -json shorthand.
func resolveFormat(format string, jsonShort bool) (string, error) {
	if jsonShort {
		format = "json"
	}
	switch format {
	case "text", "json":
		return format, nil
	default:
		return "", fmt.Errorf("unknown format %q (want text|json)", format)
	}
}

// resolveProgress validates the -progress value ("auto" is resolved later, once
// we know whether stdout is a terminal).
func resolveProgress(p string) (string, error) {
	switch p {
	case "auto", "list", "bar", "none":
		return p, nil
	default:
		return "", fmt.Errorf("unknown progress %q (want auto|list|bar|none)", p)
	}
}

// buildWriter assembles the output writer. The two concerns are independent: the
// data sink (text/json) goes to stdout; the progress display goes to stderr.
//
//   - Pure interactive (stdout is a terminal) with no explicit format/progress
//     override gets the classic colored table on stdout — the terminal *is* the
//     output, so there's no separate file to keep clean.
//   - Otherwise the data goes to stdout and a progress display to stderr. This
//     is the "saving to a file" case the -progress flag is for.
func buildWriter(format, progress string, okOnly bool, expected int, progressSet, formatSet bool) cli.Writer {
	stdoutTTY := isTTY(os.Stdout)
	stderrTTY := isTTY(os.Stderr)

	if stdoutTTY && !progressSet && !formatSet {
		return cli.NewHuman(os.Stdout, stderrTTY, okOnly, expected)
	}

	var sink cli.Writer
	if format == "json" {
		sink = cli.NewJSONSink(os.Stdout, okOnly)
	} else {
		sink = cli.NewTextSink(os.Stdout, okOnly)
	}

	// Resolve "auto": a bar when we're saving stdout to a file and stderr is a
	// terminal to draw on; nothing otherwise.
	if progress == "auto" {
		if !stdoutTTY && stderrTTY {
			progress = "bar"
		} else {
			progress = "none"
		}
	}

	var display cli.Writer
	switch progress {
	case "list":
		display = cli.NewHuman(os.Stderr, stderrTTY, false, expected)
	case "bar":
		display = cli.NewBarDisplay(os.Stderr, expected)
	default: // none
		display = cli.NewNoneDisplay(os.Stderr)
	}
	return cli.NewCombo(sink, display)
}
