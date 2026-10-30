package check

import (
	"bufio"
	"context"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func proxyFixture(t *testing.T, h http.HandlerFunc) (Proxy, *httptest.Server) {
	t.Helper()
	s := httptest.NewServer(h)
	t.Cleanup(s.Close)
	p, err := ParseProxy(s.URL)
	if err != nil {
		t.Fatal(err)
	}
	return p, s
}
func plainSpec() Spec {
	return Spec{Name: "test", Requests: []Request{{URL: "http://target.invalid/"}}}
}

func TestTLSVerification(t *testing.T) {
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "expected-marker") }))
	defer target.Close()
	p, _ := proxyFixture(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "CONNECT" {
			http.Error(w, "CONNECT required", 400)
			return
		}
		up, err := net.DialTimeout("tcp", strings.TrimPrefix(target.URL, "https://"), time.Second)
		if err != nil {
			http.Error(w, "dial", 502)
			return
		}
		down, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			up.Close()
			return
		}
		fmt.Fprint(down, "HTTP/1.1 200 Connection Established\r\n\r\n")
		go func() { defer down.Close(); defer up.Close(); io.Copy(up, down) }()
		io.Copy(down, up)
		down.Close()
	})
	spec := Spec{Name: "tls", Requests: []Request{{URL: target.URL, Expect: Expect{BodyContains: []string{"expected-marker"}}}}}
	res := Check(context.Background(), p, spec, Options{})
	if res.OK || res.ErrorClass != ErrTLS {
		t.Fatalf("untrusted certificate accepted/misclassified: %+v", res)
	}
	// A trusted target still works through the same CONNECT tunnel.
	tr, err := transportFor(p, time.Second, time.Second, false)
	if err != nil {
		t.Fatal(err)
	}
	defer tr.CloseIdleConnections()
	roots := x509.NewCertPool()
	roots.AddCert(target.Certificate())
	tr.TLSClientConfig.RootCAs = roots
	step, _, _ := runStep(context.Background(), &http.Client{Transport: tr}, spec.Requests[0])
	if !step.OK {
		t.Fatalf("trusted request failed: %+v", step)
	}
}

func TestExitProbeSingleValidatedResponse(t *testing.T) {
	for _, c := range []struct {
		name, body string
		status     int
		ok         bool
	}{{"valid", "::ffff:198.51.100.9\n", 200, true}, {"html", "<html>blocked</html>", 200, false}, {"forbidden", "198.51.100.9", 403, false}, {"oversize", strings.Repeat("x", defaultBodyCap+1), 200, false}} {
		t.Run(c.name, func(t *testing.T) {
			var calls atomic.Int32
			p, _ := proxyFixture(t, func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				w.WriteHeader(c.status)
				fmt.Fprint(w, c.body)
			})
			res := Check(context.Background(), p, Spec{Name: "ip", ExitIPProbe: "http://probe.invalid/"}, Options{LocalIP: "192.0.2.1"})
			if res.OK != c.ok || calls.Load() != 1 {
				t.Fatalf("result=%+v calls=%d", res, calls.Load())
			}
			if c.ok {
				if res.ExitIP != "198.51.100.9" || res.IPComparison != IPDifferent || res.Anonymity != "" {
					t.Fatalf("misleading IP observation: %+v", res)
				}
			} else if res.ExitIP != "" || res.IPComparison != "" {
				t.Fatalf("invalid IP emitted: %+v", res)
			}
		})
	}
}

func TestResponseReadFailuresAndLimits(t *testing.T) {
	t.Run("truncated", func(t *testing.T) {
		p, _ := proxyFixture(t, func(w http.ResponseWriter, r *http.Request) {
			c, _, _ := w.(http.Hijacker).Hijack()
			fmt.Fprint(c, "HTTP/1.1 200 OK\r\nContent-Length: 100\r\nConnection: close\r\n\r\nok")
			c.Close()
		})
		spec := plainSpec()
		spec.Requests[0].Expect.BodyContains = []string{"ok"}
		res := Check(context.Background(), p, spec, Options{})
		if res.OK {
			t.Fatal("truncated response passed")
		}
	})
	t.Run("marker-beyond-cap", func(t *testing.T) {
		p, _ := proxyFixture(t, func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, strings.Repeat("x", defaultBodyCap)+"blocked")
		})
		spec := plainSpec()
		spec.Requests[0].Expect.BodyAbsent = []string{"blocked"}
		res := Check(context.Background(), p, spec, Options{})
		if res.OK {
			t.Fatal("unscanned body treated as absent marker")
		}
	})
	t.Run("bounded-download-sample", func(t *testing.T) {
		p, _ := proxyFixture(t, func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, strings.Repeat("x", defaultBodyCap+128)) })
		spec := plainSpec()
		spec.Requests[0].Expect.MinDownload = 8192
		res := Check(context.Background(), p, spec, Options{})
		if !res.OK || res.Steps[0].Bytes != defaultBodyCap {
			t.Fatalf("sample failed: %+v", res)
		}
	})
}

func TestCredentialsRequireExplicitOptIn(t *testing.T) {
	p, _ := proxyFixture(t, func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "ok") })
	p.Username = "test"
	p.Password = "secret"
	res := Check(context.Background(), p, plainSpec(), Options{})
	if !res.OK || strings.Contains(res.Proxy, "secret") {
		t.Fatalf("credential leak: %+v", res)
	}
	if _, err := ParseProxy(res.Proxy); err == nil {
		t.Fatal("redacted output silently reused")
	}
	res = Check(context.Background(), p, plainSpec(), Options{IncludeCredentials: true})
	got, err := ParseProxy(res.Proxy)
	if err != nil || got.Password != "secret" || !res.OK {
		t.Fatal("explicit credential export did not round-trip")
	}
}

func TestErrorClassification(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	listener.Close()
	conn, err := net.DialTimeout("tcp", address, time.Second)
	if conn != nil {
		conn.Close()
		t.Fatal("closed port unexpectedly connected")
	}
	if got := classifyDialError(err); got != ErrRefused {
		t.Fatalf("actual OS refusal misclassified: %v => %q", err, got)
	}
	for _, c := range []struct {
		err  error
		want ErrorClass
	}{{fmt.Errorf("wrapped: %w", syscall.ECONNREFUSED), ErrRefused}, {&net.OpError{Op: "read", Net: "tcp", Err: io.EOF}, ErrProtocol}, {fmt.Errorf("wrapped: %w", context.DeadlineExceeded), ErrTimeout}, {&net.DNSError{Err: "missing", Name: "test"}, ErrDNS}, {&tlsErrorFixture{}, ErrProtocol}, {ErrProxyPolicy, ErrInput}} {
		if got := classifyDialError(c.err); got != c.want {
			t.Errorf("%v => %q, want %q", c.err, got, c.want)
		}
	}
}

type tlsErrorFixture struct{}

func (*tlsErrorFixture) Error() string { return "other protocol error" }

func TestPublicProxyPolicy(t *testing.T) {
	for _, raw := range []string{"127.0.0.1", "::1", "10.1.2.3", "169.254.169.254", "100.64.0.1", "192.0.2.1", "::ffff:127.0.0.1", "64:ff9b::7f00:1", "2001:db8::1", "fe80::1%zone"} {
		if IsPublicIP(netip.MustParseAddr(raw)) {
			t.Errorf("allowed %s", raw)
		}
	}
	if !IsPublicIP(netip.MustParseAddr("8.8.8.8")) {
		t.Fatal("public address rejected")
	}
	var calls atomic.Int32
	p, s := proxyFixture(t, func(w http.ResponseWriter, r *http.Request) { calls.Add(1); fmt.Fprint(w, "ok") })
	for _, host := range []string{p.Host, "localhost"} {
		p.Host = host
		res := Check(context.Background(), p, plainSpec(), Options{PublicProxiesOnly: true})
		if res.OK || res.ErrorClass != ErrInput {
			t.Fatalf("policy bypass %q: %+v", host, res)
		}
	}
	_ = s
	if calls.Load() != 0 {
		t.Fatal("private endpoint was contacted")
	}
}

func TestRunStopsOnEmitterFailureAndCancellation(t *testing.T) {
	p, _ := proxyFixture(t, func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "ok") })
	sentinel := errors.New("sink failed")
	var count atomic.Int32
	err := Run(context.Background(), []Proxy{p, p, p}, plainSpec(), Options{Concurrency: 1}, func(Result) error { count.Add(1); return sentinel })
	if !errors.Is(err, sentinel) || count.Load() != 1 {
		t.Fatalf("err=%v count=%d", err, count.Load())
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err = Run(ctx, []Proxy{p}, plainSpec(), Options{}, func(Result) error { t.Fatal("emitted after cancellation"); return nil })
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation lost: %v", err)
	}
}

type pipeDialer struct{ conn net.Conn }

func (d pipeDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	return d.conn, nil
}
func TestSOCKS4Cancellation(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	d := socks4Dialer{proxyAddr: "unused:1", forward: pipeDialer{client}}
	done := make(chan error, 1)
	go func() { _, err := d.DialContext(ctx, "tcp", "example.com:80"); done <- err }()
	request := make([]byte, 1024)
	if _, err := server.Read(request); err != nil {
		t.Fatal(err)
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("got %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("SOCKS4 handshake ignored cancellation")
	}
}

func TestSOCKS4aHandshake(t *testing.T) {
	for _, target := range []string{"example.com:80", "192.0.2.1:443"} {
		t.Run(target, func(t *testing.T) {
			client, server := net.Pipe()
			defer server.Close()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			d := socks4Dialer{proxyAddr: "unused:1", username: "user", forward: pipeDialer{client}}
			done := make(chan error, 1)
			go func() {
				conn, err := d.DialContext(ctx, "tcp", target)
				if conn != nil {
					conn.Close()
				}
				done <- err
			}()
			request := make([]byte, 1024)
			n, err := server.Read(request)
			if err != nil {
				t.Fatal(err)
			}
			if n < 9 || request[0] != 4 || request[1] != 1 {
				t.Fatalf("bad handshake: %v", request[:n])
			}
			if strings.HasPrefix(target, "example") && !strings.Contains(string(request[:n]), "example.com\x00") {
				t.Fatal("hostname missing")
			}
			server.Write([]byte{0, 0x5a, 0, 0, 0, 0, 0, 0})
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestSOCKS5AuthenticatedTunnel(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	finished := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			finished <- err
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(3 * time.Second))
		fail := func(err error) { finished <- err }
		header := make([]byte, 2)
		if _, err := io.ReadFull(conn, header); err != nil {
			fail(err)
			return
		}
		methods := make([]byte, int(header[1]))
		if _, err := io.ReadFull(conn, methods); err != nil {
			fail(err)
			return
		}
		if header[0] != 5 {
			fail(fmt.Errorf("bad SOCKS version"))
			return
		}
		conn.Write([]byte{5, 2})
		if _, err := io.ReadFull(conn, header); err != nil {
			fail(err)
			return
		}
		user := make([]byte, int(header[1]))
		io.ReadFull(conn, user)
		size := make([]byte, 1)
		io.ReadFull(conn, size)
		password := make([]byte, int(size[0]))
		io.ReadFull(conn, password)
		if string(user) != "user" || string(password) != "secret" {
			fail(fmt.Errorf("bad credentials"))
			return
		}
		conn.Write([]byte{1, 0})
		request := make([]byte, 4)
		if _, err := io.ReadFull(conn, request); err != nil {
			fail(err)
			return
		}
		if request[3] != 3 {
			fail(fmt.Errorf("expected remote DNS hostname"))
			return
		}
		io.ReadFull(conn, size)
		host := make([]byte, int(size[0]))
		io.ReadFull(conn, host)
		port := make([]byte, 2)
		io.ReadFull(conn, port)
		if string(host) != "target.invalid" || binary.BigEndian.Uint16(port) != 80 {
			fail(fmt.Errorf("bad target"))
			return
		}
		conn.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0})
		req, err := http.ReadRequest(bufio.NewReader(conn))
		if err != nil {
			fail(err)
			return
		}
		req.Body.Close()
		_, err = fmt.Fprint(conn, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
		finished <- err
	}()
	p, err := ParseProxy("socks5://user:secret@" + listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	res := Check(context.Background(), p, plainSpec(), Options{})
	if !res.OK {
		t.Fatalf("SOCKS5 check: %+v", res)
	}
	if err := <-finished; err != nil {
		t.Fatal(err)
	}
}
