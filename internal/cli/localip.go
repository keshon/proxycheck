package cli

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"time"
)

// DetectLocalIP directly observes the origin IP, without environment proxies.
// Any failed request, non-2xx status, truncated body or invalid address is unknown.
func DetectLocalIP(ctx context.Context) string {
	tr := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, TLSHandshakeTimeout: 5 * time.Second, MaxResponseHeaderBytes: 64 << 10}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return detectLocalIP(ctx, client, "https://api.ipify.org")
}

func detectLocalIP(ctx context.Context, client *http.Client, endpoint string) string {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return ""
	}
	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return ""
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 129))
	if err != nil || len(body) > 128 {
		return ""
	}
	ip, err := netip.ParseAddr(strings.TrimSpace(string(body)))
	if err != nil || ip.Zone() != "" {
		return ""
	}
	return ip.Unmap().String()
}
