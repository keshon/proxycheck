package commands

import (
	"context"
	"fmt"
	"github.com/keshon/command"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCLIOutputFailureAndCredentialExport(t *testing.T) {
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "ok") }))
	defer proxy.Close()
	dir := t.TempDir()
	preset := filepath.Join(dir, "test.yaml")
	input := filepath.Join(dir, "input.list")
	if err := os.WriteFile(preset, []byte("name: test\nrequests:\n  - url: http://target.invalid/\n"), 0600); err != nil {
		t.Fatal(err)
	}
	proxyURL := strings.Replace(proxy.URL, "http://", "http://user:secret@", 1)
	if err := os.WriteFile(input, []byte(proxyURL+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	original := os.Stdout
	defer func() { os.Stdout = original }()
	for _, include := range []bool{false, true} {
		output, err := os.CreateTemp(dir, "output-")
		if err != nil {
			t.Fatal(err)
		}
		os.Stdout = output
		args := []string{"-p", "test", "-presets-dir", dir, "-progress", "none", "-format", "text"}
		if include {
			args = append(args, "-include-credentials")
		}
		args = append(args, input)
		err = (&runCmd{}).Run(context.Background(), &command.Invocation{Args: args})
		output.Close()
		if err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(output.Name())
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(data), ":secret@") != include {
			t.Fatalf("credential export mismatch: %s", data)
		}
	}
	closed, err := os.CreateTemp(dir, "closed-")
	if err != nil {
		t.Fatal(err)
	}
	closed.Close()
	os.Stdout = closed
	err = (&runCmd{}).Run(context.Background(), &command.Invocation{Args: []string{"-p", "test", "-presets-dir", dir, "-format", "json", "-progress", "none", input}})
	if err == nil {
		t.Fatal("CLI succeeded after output file failed")
	}
}

func TestCLIRejectsOutOfRangeOptions(t *testing.T) {
	for _, args := range [][]string{{"-c", "1000000"}, {"-c", "-1"}, {"-timeout", "-1s"}} {
		if err := (&runCmd{}).Run(context.Background(), &command.Invocation{Args: args}); err == nil {
			t.Fatal("unsafe flags accepted")
		}
	}
}

func TestServeRejectsPublicUnauthenticatedAndWeakToken(t *testing.T) {
	t.Setenv("PROXYCHECK_API_TOKEN", "")
	if err := (&serveCmd{}).Run(context.Background(), &command.Invocation{Args: []string{"-addr", ":8080"}}); err == nil {
		t.Fatal("public unauthenticated listener accepted")
	}
	t.Setenv("PROXYCHECK_API_TOKEN", "weak")
	if err := (&serveCmd{}).Run(context.Background(), &command.Invocation{}); err == nil {
		t.Fatal("weak configured token accepted")
	}
}
