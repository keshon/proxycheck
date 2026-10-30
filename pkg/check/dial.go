package check

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"runtime"
	"syscall"
	"time"

	xproxy "golang.org/x/net/proxy"
)

var zeroTime time.Time

// transportFor builds an http.Transport that routes every request through the
// given proxy. One transport per proxy, never shared: connection pools would
// otherwise leak state between checks and skew timings.
//
// dialTimeout bounds the TCP/handshake to the proxy itself.
func transportFor(p Proxy, dialTimeout, tlsTimeout time.Duration, publicOnly bool) (*http.Transport, error) {
	base := &net.Dialer{Timeout: dialTimeout}
	var forward interface {
		proxyDialer
		xproxy.Dialer
	} = base
	if publicOnly {
		forward = &publicDialer{base: base}
	}

	tr := &http.Transport{
		TLSHandshakeTimeout:    tlsTimeout,
		DisableKeepAlives:      true, // each check is independent; no pooling across proxies
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12},
		MaxResponseHeaderBytes: 64 << 10,
	}

	switch p.Scheme {
	case HTTP, HTTPS:
		tr.Proxy = http.ProxyURL(p.URL())
		tr.DialContext = forward.DialContext

	case SOCKS5:
		var auth *xproxy.Auth
		if p.Username != "" || p.Password != "" {
			auth = &xproxy.Auth{User: p.Username, Password: p.Password}
		}
		d, err := xproxy.SOCKS5("tcp", p.Address(), auth, forward)
		if err != nil {
			return nil, fmt.Errorf("socks5 dialer: %w", err)
		}
		cd, ok := d.(xproxy.ContextDialer)
		if !ok {
			return nil, errors.New("socks5 dialer lacks context support")
		}
		tr.DialContext = cd.DialContext

	case SOCKS4:
		d := &socks4Dialer{proxyAddr: p.Address(), username: p.Username, forward: forward}
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
	if errors.Is(err, ErrProxyPolicy) {
		return ErrInput
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
	var certificateErr *tls.CertificateVerificationError
	var unknownAuthority x509.UnknownAuthorityError
	var hostnameErr x509.HostnameError
	if errors.As(err, &certificateErr) || errors.As(err, &unknownAuthority) || errors.As(err, &hostnameErr) {
		return ErrTLS
	}

	// Winsock uses WSAECONNREFUSED (10061), not Go's synthetic Windows
	// syscall.ECONNREFUSED value. Match the actual OS cause on both platforms.
	if errors.Is(err, syscall.ECONNREFUSED) || (runtime.GOOS == "windows" && errors.Is(err, syscall.Errno(10061))) {
		return ErrRefused
	}

	// SOCKS/HTTP-proxy protocol errors carry our own or x/net's messages.
	return ErrProtocol
}
