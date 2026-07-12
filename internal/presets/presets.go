// Package presets loads named check specs. Built-in presets are embedded in the
// binary; a user directory can add or override them by name. The core check
// engine knows nothing about any specific target — everything target-specific
// lives here as data.
package presets

import (
	"embed"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/keshon/proxycheck/pkg/check"
)

//go:embed data/*.yaml
var builtin embed.FS

// Set is a resolved collection of specs keyed by name.
type Set struct {
	specs map[string]check.Spec
}

// Load reads all embedded presets, then overlays any *.yaml in userDir (a user
// spec with the same name wins). Pass "" for userDir to skip overrides.
func Load(userDir string) (*Set, error) {
	s := &Set{specs: make(map[string]check.Spec)}

	entries, err := builtin.ReadDir("data")
	if err != nil {
		return nil, fmt.Errorf("read embedded presets: %w", err)
	}
	for _, e := range entries {
		data, err := builtin.ReadFile("data/" + e.Name())
		if err != nil {
			return nil, err
		}
		spec, err := check.ParseSpec(data)
		if err != nil {
			return nil, fmt.Errorf("builtin preset %s: %w", e.Name(), err)
		}
		s.specs[spec.Name] = spec
	}

	if userDir != "" {
		if err := s.overlay(userDir); err != nil {
			return nil, err
		}
	}
	return s, nil
}

func (s *Set) overlay(dir string) error {
	matches, err := filepath.Glob(filepath.Join(dir, "*.yaml"))
	if err != nil {
		return err
	}
	for _, path := range matches {
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read user preset %s: %w", path, err)
		}
		spec, err := check.ParseSpec(data)
		if err != nil {
			return fmt.Errorf("user preset %s: %w", path, err)
		}
		s.specs[spec.Name] = spec
	}
	return nil
}

// Get returns the named spec.
func (s *Set) Get(name string) (check.Spec, bool) {
	spec, ok := s.specs[name]
	return spec, ok
}

// Names returns preset names sorted alphabetically.
func (s *Set) Names() []string {
	names := make([]string, 0, len(s.specs))
	for n := range s.specs {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// All returns every spec, sorted by name.
func (s *Set) All() []check.Spec {
	specs := make([]check.Spec, 0, len(s.specs))
	for _, n := range s.Names() {
		specs = append(specs, s.specs[n])
	}
	return specs
}

// Describe returns a "name — description" line per preset, for CLI listing.
func (s *Set) Describe() string {
	var b strings.Builder
	for _, spec := range s.All() {
		fmt.Fprintf(&b, "%-12s %s\n", spec.Name, spec.Description)
	}
	return b.String()
}
