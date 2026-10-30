package presets

import (
	"os"
	"path/filepath"
	"testing"
)

func TestBuiltinsAndUserOverride(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "override.yaml"), []byte("name: basic\ndescription: custom\ntimeout: 3s\nrequests:\n  - url: https://example.com/\n"), 0600); err != nil {
		t.Fatal(err)
	}
	set, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(set.Names()) != 4 {
		t.Fatal(set.Names())
	}
	spec, ok := set.Get("basic")
	if !ok || spec.Description != "custom" || spec.Timeout.Seconds() != 3 {
		t.Fatalf("override lost: %+v", spec)
	}
	if err := os.WriteFile(filepath.Join(dir, "bad.yaml"), []byte("name: invalid\nrequests:\n  - url: file:///etc/passwd\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(dir); err == nil {
		t.Fatal("invalid preset accepted")
	}
}
