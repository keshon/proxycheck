package check

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// Scheme is the wire protocol a proxy speaks.
type Scheme string

const (
	HTTP   Scheme = "http"
	HTTPS  Scheme = "https"
	SOCKS4 Scheme = "socks4"
	SOCKS5 Scheme = "socks5"
)

// knownSchemes is the set we can dial. Order matters only for docs.
var knownSchemes = []Scheme{HTTP, HTTPS, SOCKS4, SOCKS5}

// Proxy is a single parsed proxy endpoint. It carries no check state — a Proxy
// is immutable input, a Result is output. That separation is deliberate: the
// old design bolted per-target fields onto the proxy struct and never recovered.
type Proxy struct {
	Scheme   Scheme
	Host     string
	Port     string
	Username string
	Password string

	// Raw is the original line as supplied, preserved for output so users can
	// grep their input against results without normalization surprises.
	Raw string
}

// ParseProxy accepts the shapes people actually paste:
//
//	host:port
//	scheme://host:port
//	scheme://user:pass@host:port
//	user:pass@host:port
//
// A missing scheme defaults to http, which is what bare ip:port lists mean in
// practice. IPv6 hosts must be bracketed per RFC 3986 (e.g. [::1]:1080).
func ParseProxy(raw string) (Proxy, error) {
	s := strings.TrimSpace(raw)
	if len(s) > 4096 {
		return Proxy{}, fmt.Errorf("proxy URL exceeds 4096 bytes")
	}
	if s == "" {
		return Proxy{}, fmt.Errorf("empty proxy string")
	}

	scheme := HTTP
	rest := s
	if i := strings.Index(s, "://"); i >= 0 {
		got := Scheme(strings.ToLower(s[:i]))
		if !isKnownScheme(got) {
			return Proxy{}, fmt.Errorf("unknown proxy scheme (want one of %s)", schemeList())
		}
		scheme = got
		rest = s[i+3:]
	}

	// url.Parse gives us robust user:pass@host:port splitting (incl. bracketed
	// IPv6 and percent-encoded credentials) for free.
	u, err := url.Parse(string(scheme) + "://" + rest)
	if err != nil {
		return Proxy{}, fmt.Errorf("malformed proxy URL")
	}

	host := u.Hostname()
	port := u.Port()
	if host == "" {
		return Proxy{}, fmt.Errorf("proxy URL has no host")
	}
	if port == "" {
		return Proxy{}, fmt.Errorf("proxy URL has no port")
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return Proxy{}, fmt.Errorf("invalid proxy port, path, query or fragment")
	}

	p := Proxy{
		Scheme:   scheme,
		Host:     host,
		Port:     port,
		Username: u.User.Username(),
		Raw:      s,
	}
	if pw, ok := u.User.Password(); ok {
		p.Password = pw
	}
	if strings.IndexFunc(p.Username+p.Password+host, func(r rune) bool { return r < 32 || r == 127 }) >= 0 {
		return Proxy{}, fmt.Errorf("proxy contains invalid control characters")
	}
	if p.Password == "***" {
		return Proxy{}, fmt.Errorf("redacted proxy password cannot be reused; use the original input or an explicit credential export")
	}
	if p.Scheme == SOCKS4 && p.Password != "" {
		return Proxy{}, fmt.Errorf("SOCKS4 supports USERID, not password authentication")
	}
	return p, nil
}

// Address is the host:port form used by dialers.
func (p Proxy) Address() string {
	return net.JoinHostPort(p.Host, p.Port)
}

// URL renders the canonical scheme://[user:pass@]host:port form.
func (p Proxy) URL() *url.URL {
	u := &url.URL{Scheme: string(p.Scheme), Host: p.Address()}
	if p.Username != "" || p.Password != "" {
		u.User = url.UserPassword(p.Username, p.Password)
	}
	return u
}

// String is the canonical URL text, credentials included. Callers logging to
// shared sinks should prefer Redacted.
func (p Proxy) String() string {
	return p.URL().String()
}

// Redacted masks the password. Usernames remain visible in logs and API output.
func (p Proxy) Redacted() string {
	if p.Password == "" {
		return p.String()
	}
	// Build directly rather than through url.URL, whose encoder would escape the
	// mask characters (*** -> %2A%2A%2A).
	return fmt.Sprintf("%s://%s:***@%s", p.Scheme, url.User(p.Username).String(), p.Address())
}

func isKnownScheme(s Scheme) bool {
	for _, k := range knownSchemes {
		if k == s {
			return true
		}
	}
	return false
}

func schemeList() string {
	parts := make([]string, len(knownSchemes))
	for i, s := range knownSchemes {
		parts[i] = string(s)
	}
	return strings.Join(parts, ", ")
}
