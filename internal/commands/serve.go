package commands

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/keshon/command"
	"github.com/keshon/proxycheck/internal/cli"
	"github.com/keshon/proxycheck/internal/presets"
	"github.com/keshon/proxycheck/internal/server"
)

// serveCmd runs the HTTP check API.
type serveCmd struct{}

func (*serveCmd) Name() string        { return "serve" }
func (*serveCmd) Description() string { return "run the HTTP check API" }

func (*serveCmd) Run(ctx context.Context, inv *command.Invocation) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	var (
		addr       = fs.String("addr", ":8080", "listen address")
		presetsDir = fs.String("presets-dir", presetDirDefault(), "user presets directory")
	)
	if err := fs.Parse(inv.Args); err != nil {
		return err
	}
	set, err := presets.Load(existingDir(*presetsDir))
	if err != nil {
		return err
	}
	localIP := cli.DetectLocalIP(ctx)

	srv := server.New(set, localIP)
	fmt.Fprintf(os.Stderr, "proxycheck serving on %s (presets: %v)\n", *addr, set.Names())
	if err := server.ListenAndServe(ctx, *addr, srv.Handler()); err != nil {
		if ctx.Err() != nil {
			return nil // clean shutdown via signal
		}
		return err
	}
	return nil
}
