package check

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	xproxy "golang.org/x/net/proxy"
)

var zeroTime time.Time

// transportFor builds an http.Transport that routes every request through the
// given proxy. One transport per proxy, never shared: connection pools would
// otherwise leak state between checks and skew timings.
//
// dialTimeout bounds the TCP/handshake to the proxy itself.
func transportFor(p Proxy, dialTimeout, tlsTimeout time.Duration) (*http.Transport, error) {
	base := &net.Dialer{Timeout: dialTimeout}

	tr := &http.Transport{
		TLSHandshakeTimeout: tlsTimeout,
		DisableKeepAlives:   true, // each check is independent; no pooling across proxies
		// We are validating sketchy third-party proxies, not asserting the
		// target's cert chain end-to-end through them. Skip verify so a MITM
		// proxy still lets us observe reachability; assertions catch bad bodies.
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	switch p.Scheme {
	case HTTP, HTTPS:
		tr.Proxy = http.ProxyURL(p.URL())
		tr.DialContext = base.DialContext

	case SOCKS5:
		var auth *xproxy.Auth
		if p.Username != "" || p.Password != "" {
			auth = &xproxy.Auth{User: p.Username, Password: p.Password}
		}
		d, err := xproxy.SOCKS5("tcp", p.Address(), auth, base)
		if err != nil {
			return nil, fmt.Errorf("socks5 dialer: %w", err)
		}
		cd, ok := d.(xproxy.ContextDialer)
		if !ok {
			return nil, errors.New("socks5 dialer lacks context support")
		}
		tr.DialContext = cd.DialContext

	case SOCKS4:
		d := &socks4Dialer{proxyAddr: p.Address(), username: p.Username, forward: base}
		tr.DialContext = d.DialContext

	default:
		return nil, fmt.Errorf("unsupported scheme %q", p.Scheme)
	}

	return tr, nil
}

// classifyDialError maps a low-level dial/transport error to an ErrorClass so
// callers can tell a dead proxy from a live-but-blocked one. Order matters:
// timeout is checked before refused because a wrapped timeout can also satisfy
// coarser checks.
func classifyDialError(err error) ErrorClass {
	if err == nil {
		return ErrNone
	}

	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return ErrTimeout
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return ErrTimeout
	}

	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return ErrDNS
	}

	var tlsErr *tls.RecordHeaderError
	if errors.As(err, &tlsErr) {
		return ErrTLS
	}
	if _, ok := err.(*tls.CertificateVerificationError); ok {
		return ErrTLS
	}

	var opErr *net.OpError
	if errors.As(err, &opErr) {
		// "connection refused" surfaces as a syscall error inside OpError.
		if opErr.Err != nil {
			return ErrRefused
		}
	}

	// SOCKS/HTTP-proxy protocol errors carry our own or x/net's messages.
	return ErrProtocol
}
