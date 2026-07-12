// Package commands adapts proxycheck's subcommands to the transport-agnostic
// github.com/keshon/command core: each subcommand implements command.Command,
// they're stored in a command.Registry, and main dispatches by name. Flag
// parsing stays inside each command (a CLI-adapter concern), so the same
// command types could later be driven from another transport without change.
package commands

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/keshon/command"
)

// Build registers every subcommand and returns the registry. Each command is
// wrapped with panic-recovery middleware so a bug surfaces as a clean CLI error
// instead of a stack dump — a good example of a cross-cutting concern living in
// middleware rather than in each command.
func Build() *command.Registry {
	r := command.NewRegistry()
	for _, c := range []command.Command{
		&runCmd{},
		&serveCmd{},
		&presetsCmd{},
	} {
		r.Register(command.Apply(c, recoverMiddleware))
	}
	return r
}

// recoverMiddleware turns a panic in a command into a returned error, keeping
// the command's Name/Description intact (command.Wrap delegates them).
func recoverMiddleware(next command.Command) command.Command {
	return command.Wrap(next, func(ctx context.Context, inv *command.Invocation) (err error) {
		defer func() {
			if r := recover(); r != nil {
				err = fmt.Errorf("%s: panic: %v", next.Name(), r)
			}
		}()
		return next.Run(ctx, inv)
	})
}

// Usage prints the top-level help, listing commands straight from the registry
// so a newly registered command shows up automatically.
func Usage(w io.Writer, reg *command.Registry) {
	fmt.Fprint(w, "proxycheck — validate proxies against declarative check presets\n\n")
	fmt.Fprint(w, "usage: proxycheck <command> [flags] [args]\n\n")
	fmt.Fprintln(w, "commands:")
	for _, c := range reg.GetAll() {
		fmt.Fprintf(w, "  %-9s %s\n", c.Name(), c.Description())
	}
	fmt.Fprint(w, "\nrun 'proxycheck <command> -h' for a command's flags.\n")
}

// --- shared helpers used across commands ---

// presetDirDefault is the conventional user preset location.
func presetDirDefault() string {
	if v := os.Getenv("PROXYCHECK_PRESETS"); v != "" {
		return v
	}
	if home, err := os.UserConfigDir(); err == nil {
		return filepath.Join(home, "proxycheck", "presets")
	}
	return ""
}

// existingDir returns dir if it exists, else "" so presets.Load skips it.
func existingDir(dir string) string {
	if dir == "" {
		return ""
	}
	if fi, err := os.Stat(dir); err == nil && fi.IsDir() {
		return dir
	}
	return ""
}

// isTTY reports whether f is a character device (an interactive terminal).
func isTTY(f *os.File) bool {
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}
