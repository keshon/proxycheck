package check

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestSpecValidationLimits(t *testing.T) {
	for _, change := range []func(*Spec){func(s *Spec) { s.Timeout = MaxCheckTimeout + time.Second }, func(s *Spec) { s.Timeout = -1 }, func(s *Spec) { s.Requests[0].URL = "file:///etc/passwd" }, func(s *Spec) { s.ExitIPProbe = "%" }, func(s *Spec) { s.Requests[0].URL = "https://user:secret@example.com" }, func(s *Spec) { s.Requests[0].Expect.MinDownload = MaxResponseBytes + 1 }, func(s *Spec) { s.Requests[0].Expect.MinDownload = -1 }, func(s *Spec) { s.Requests[0].Expect.Status = []int{999} }, func(s *Spec) { s.Requests = make([]Request, MaxRequests+1) }} {
		s := plainSpec()
		change(&s)
		if s.Validate() == nil {
			t.Fatalf("invalid spec accepted: %+v", s)
		}
	}
	var spec Spec
	for _, duration := range []string{`"15s"`, `15000000000`} {
		if err := json.Unmarshal([]byte(`{"name":"x","timeout":`+duration+`,"requests":[{"url":"https://example.com"}]}`), &spec); err != nil || spec.Timeout != 15*time.Second {
			t.Fatalf("duration %s: %v %+v", duration, err, spec)
		}
	}
	if err := json.Unmarshal([]byte(`{"name":"x","typo":true}`), &spec); err == nil {
		t.Fatal("unknown JSON field accepted")
	}
	if _, err := ParseSpec([]byte("name: x\nrequests:\n  - url: https://example.com\nunknown: true")); err == nil {
		t.Fatal("unknown YAML field accepted")
	}
}
func TestProxyValidationAndRedaction(t *testing.T) {
	for _, raw := range []string{"http://host:0", "http://host:65536", "http://host:80/path", "http://host:80?q=x", "http://host:80#x", "http://user:%1B@host:80", "http://user:***@host:80", "socks4://user:password@host:1080"} {
		if _, err := ParseProxy(raw); err == nil {
			t.Errorf("accepted %q", raw)
		}
	}
	_, err := ParseProxy("http://user:my-secret@bad:invalid")
	if err == nil || strings.Contains(err.Error(), "my-secret") {
		t.Fatal("parse failure leaked credentials")
	}
	p, err := ParseProxy("http://u%40name:secret@host:80")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(p.Redacted(), "secret") || !strings.Contains(p.Redacted(), "u%40name") {
		t.Fatalf("unsafe redaction: %s", p.Redacted())
	}
}
