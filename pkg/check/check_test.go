package check

import "testing"

func TestParseProxy(t *testing.T) {
	cases := []struct {
		in         string
		wantScheme Scheme
		wantAddr   string
		wantUser   string
		wantPass   string
		wantErr    bool
	}{
		{in: "1.2.3.4:8080", wantScheme: HTTP, wantAddr: "1.2.3.4:8080"},
		{in: "http://1.2.3.4:8080", wantScheme: HTTP, wantAddr: "1.2.3.4:8080"},
		{in: "socks5://5.6.7.8:1080", wantScheme: SOCKS5, wantAddr: "5.6.7.8:1080"},
		{in: "socks4://9.9.9.9:4145", wantScheme: SOCKS4, wantAddr: "9.9.9.9:4145"},
		{in: "user:pass@1.2.3.4:3128", wantScheme: HTTP, wantAddr: "1.2.3.4:3128", wantUser: "user", wantPass: "pass"},
		{in: "socks5://u:p@1.2.3.4:1080", wantScheme: SOCKS5, wantAddr: "1.2.3.4:1080", wantUser: "u", wantPass: "p"},
		{in: "[2001:db8::1]:1080", wantScheme: HTTP, wantAddr: "[2001:db8::1]:1080"},
		{in: "", wantErr: true},
		{in: "1.2.3.4", wantErr: true},        // no port
		{in: "ftp://1.2.3.4:21", wantErr: true}, // unknown scheme
	}
	for _, c := range cases {
		p, err := ParseProxy(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("ParseProxy(%q): expected error, got %+v", c.in, p)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseProxy(%q): unexpected error: %v", c.in, err)
			continue
		}
		if p.Scheme != c.wantScheme || p.Address() != c.wantAddr || p.Username != c.wantUser || p.Password != c.wantPass {
			t.Errorf("ParseProxy(%q) = %s/%s user=%q pass=%q; want %s/%s user=%q pass=%q",
				c.in, p.Scheme, p.Address(), p.Username, p.Password,
				c.wantScheme, c.wantAddr, c.wantUser, c.wantPass)
		}
	}
}

func TestRedacted(t *testing.T) {
	p, _ := ParseProxy("socks5://user:secret@1.2.3.4:1080")
	if got := p.Redacted(); got != "socks5://user:***@1.2.3.4:1080" {
		t.Errorf("Redacted() = %q", got)
	}
}

func TestExpectStatusOK(t *testing.T) {
	if !(Expect{}).statusOK(200) {
		t.Error("empty status rule should accept 200")
	}
	if (Expect{}).statusOK(403) {
		t.Error("empty status rule should reject 403")
	}
	if !(Expect{Status: []int{403}}).statusOK(403) {
		t.Error("explicit 403 should be accepted")
	}
}

func TestClassifyAnonymity(t *testing.T) {
	if got := classifyAnonymity("", ""); got != AnonUnknown {
		t.Errorf("no data => %q, want unknown", got)
	}
	if got := classifyAnonymity("5.6.7.8", "1.2.3.4"); got != AnonAnonymous {
		t.Errorf("differing IPs => %q, want anonymous", got)
	}
	if got := classifyAnonymity("1.2.3.4", "1.2.3.4"); got != AnonTransparent {
		t.Errorf("same IP => %q, want transparent", got)
	}
}

func TestParseSpec(t *testing.T) {
	spec, err := ParseSpec([]byte(`
name: demo
description: test
timeout: 9s
requests:
  - url: https://example.com
    expect:
      status: [200, 204]
      body_contains: ["ok"]
`))
	if err != nil {
		t.Fatalf("ParseSpec: %v", err)
	}
	if spec.Timeout.Seconds() != 9 {
		t.Errorf("timeout = %v, want 9s", spec.Timeout)
	}
	if len(spec.Requests) != 1 || spec.Requests[0].Expect.Status[1] != 204 {
		t.Errorf("bad requests: %+v", spec.Requests)
	}
}

func TestParseSpecInvalid(t *testing.T) {
	if _, err := ParseSpec([]byte(`description: no name`)); err == nil {
		t.Error("spec without name should fail validation")
	}
}

// TestParseSpecProbeOnly: the anonymity preset has an exit_ip_probe and NO
// requests. That must be valid (the probe is the whole check).
func TestParseSpecProbeOnly(t *testing.T) {
	spec, err := ParseSpec([]byte(`
name: anonymity
exit_ip_probe: https://api.ipify.org
`))
	if err != nil {
		t.Fatalf("probe-only spec should be valid: %v", err)
	}
	if spec.ExitIPProbe == "" || len(spec.Requests) != 0 {
		t.Errorf("unexpected shape: probe=%q requests=%d", spec.ExitIPProbe, len(spec.Requests))
	}
}
