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
		addr         = fs.String("addr", "127.0.0.1:8080", "listen address; public listeners require PROXYCHECK_API_TOKEN")
		presetsDir   = fs.String("presets-dir", presetDirDefault(), "user presets directory")
		allowPrivate = fs.Bool("allow-private-proxies", false, "allow private/loopback proxy destinations (trusted networks only)")
		allowInline  = fs.Bool("allow-inline-specs", false, "allow inline specs with public IP literal targets")
	)
	if err := fs.Parse(inv.Args); err != nil {
		return err
	}
	token := os.Getenv("PROXYCHECK_API_TOKEN")
	if err := server.ValidateListenAddress(*addr, token); err != nil {
		return err
	}
	set, err := presets.Load(existingDir(*presetsDir))
	if err != nil {
		return err
	}
	localIP := cli.DetectLocalIP(ctx)

	srv := server.New(set, localIP, server.Config{Token: token, AllowPrivateProxies: *allowPrivate, AllowInlineSpecs: *allowInline})
	fmt.Fprintf(os.Stderr, "proxycheck serving on %s (presets: %v)\n", *addr, set.Names())
	if err := server.ListenAndServe(ctx, *addr, srv.Handler()); err != nil {
		if ctx.Err() != nil {
			return nil // clean shutdown via signal
		}
		return err
	}
	return nil
}
