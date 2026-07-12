package commands

import (
	"context"
	"flag"
	"fmt"

	"github.com/keshon/command"
	"github.com/keshon/proxycheck/internal/presets"
)

// presetsCmd lists available check presets.
type presetsCmd struct{}

func (*presetsCmd) Name() string        { return "presets" }
func (*presetsCmd) Description() string { return "list available check presets" }

func (*presetsCmd) Run(_ context.Context, inv *command.Invocation) error {
	fs := flag.NewFlagSet("presets", flag.ExitOnError)
	presetsDir := fs.String("presets-dir", presetDirDefault(), "user presets directory")
	if err := fs.Parse(inv.Args); err != nil {
		return err
	}
	set, err := presets.Load(existingDir(*presetsDir))
	if err != nil {
		return err
	}
	fmt.Print(set.Describe())
	return nil
}
