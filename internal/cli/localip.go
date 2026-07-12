package cli

import (
	"context"
	"io"
	"net/http"
	"strings"
	"time"
)

// DetectLocalIP fetches the origin's public IP directly (no proxy). It powers
// anonymity classification: a proxy whose exit IP equals this is not hiding you.
// Returns "" on any failure — anonymity then reports "unknown", which is honest.
func DetectLocalIP(ctx context.Context) string {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.ipify.org", nil)
	if err != nil {
		return ""
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 64))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}
