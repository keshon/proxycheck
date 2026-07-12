package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/keshon/proxycheck/pkg/check"
)

func TestExpandPathsDirectoryRecursive(t *testing.T) {
	root := t.TempDir()
	sub := filepath.Join(root, "sub")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	write := func(p, s string) {
		if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(root, "a.txt"), "http://1.1.1.1:80\n")
	write(filepath.Join(root, "b.txt"), "socks5://2.2.2.2:1080\n")
	write(filepath.Join(sub, "c.txt"), "http://1.1.1.1:80\n# comment\nsocks4://3.3.3.3:4145\n")

	proxies, parseErrs, err := LoadProxies([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	if len(parseErrs) != 0 {
		t.Errorf("unexpected parse errors: %v", parseErrs)
	}
	// 3 unique proxies (the duplicate 1.1.1.1 across a.txt and c.txt is deduped).
	if len(proxies) != 3 {
		t.Fatalf("got %d proxies, want 3: %v", len(proxies), proxies)
	}
}

// TestTextLineRoundTrip proves text output is re-ingestable: the first token of
// an "address # info" line parses back to the same proxy.
func TestTextLineRoundTrip(t *testing.T) {
	orig, _ := check.ParseProxy("socks5://9.8.7.6:1080")
	line := textLine(check.Result{Proxy: orig.String(), OK: true, ConnectMS: 12, TotalMS: 34})

	// Simulate the input reader taking the first whitespace token.
	got, err := check.ParseProxy(firstToken(line))
	if err != nil {
		t.Fatalf("re-parse failed for %q: %v", line, err)
	}
	if got.String() != orig.String() {
		t.Errorf("round-trip mismatch: %q -> %q", orig, got)
	}
}

func firstToken(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] == ' ' || s[i] == '\t' {
			return s[:i]
		}
	}
	return s
}
