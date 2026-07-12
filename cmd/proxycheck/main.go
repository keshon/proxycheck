// Command proxycheck validates proxies against declarative check presets.
//
//	proxycheck run -p youtube proxies.txt        # interactive table (or text/json when saving)
//	proxycheck run -p basic -json proxies.txt | jq -r 'select(.ok).proxy'
//	proxycheck presets                           # list available checks
//	proxycheck serve -addr :8080                 # POST /v1/check streams NDJSON
//
// Subcommands are command.Command implementations dispatched through a
// command.Registry (see internal/commands).
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/keshon/command"
	"github.com/keshon/proxycheck/internal/commands"
)

func main() {
	reg := commands.Build()

	if len(os.Args) < 2 {
		commands.Usage(os.Stderr, reg)
		os.Exit(2)
	}

	switch os.Args[1] {
	case "-h", "--help", "help":
		commands.Usage(os.Stdout, reg)
		return
	}

	cmd := reg.Get(os.Args[1])
	if cmd == nil {
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", os.Args[1])
		commands.Usage(os.Stderr, reg)
		os.Exit(2)
	}

	// Signals cancel the root context so in-flight checks and the server stop cleanly.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := cmd.Run(ctx, &command.Invocation{Args: os.Args[2:]}); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
