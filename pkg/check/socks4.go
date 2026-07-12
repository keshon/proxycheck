package check

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
)

// socks4Dialer implements SOCKS4a (hostname-capable) CONNECT. We roll our own
// because the stdlib and x/net cover SOCKS5 but not 4, and pulling a whole
// dependency for ~60 lines of a fixed wire format isn't worth it.
type socks4Dialer struct {
	proxyAddr string
	username  string // SOCKS4 USERID field; empty is fine
	forward   proxyDialer
}

// proxyDialer is the minimal dial surface we need from an upstream dialer.
type proxyDialer interface {
	DialContext(ctx context.Context, network, addr string) (net.Conn, error)
}

func (d *socks4Dialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, fmt.Errorf("socks4: unsupported network %q", network)
	}

	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("socks4: bad target %q: %w", addr, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return nil, fmt.Errorf("socks4: bad port %q", portStr)
	}

	conn, err := d.forward.DialContext(ctx, "tcp", d.proxyAddr)
	if err != nil {
		return nil, err
	}

	// Propagate context deadline to the socket so a hung handshake still times out.
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}

	if err := d.handshake(conn, host, port); err != nil {
		conn.Close()
		return nil, err
	}
	// Clear the handshake deadline; the caller (http.Transport) manages its own.
	_ = conn.SetDeadline(zeroTime)
	return conn, nil
}

func (d *socks4Dialer) handshake(conn net.Conn, host string, port int) error {
	req := []byte{0x04, 0x01, byte(port >> 8), byte(port)}

	ip4 := ipv4(host)
	if ip4 != nil {
		req = append(req, ip4...)
		req = append(req, []byte(d.username)...)
		req = append(req, 0x00)
	} else {
		// SOCKS4a: 0.0.0.x sentinel IP, then USERID NUL, then hostname NUL.
		req = append(req, 0x00, 0x00, 0x00, 0x01)
		req = append(req, []byte(d.username)...)
		req = append(req, 0x00)
		req = append(req, []byte(host)...)
		req = append(req, 0x00)
	}

	if _, err := conn.Write(req); err != nil {
		return fmt.Errorf("socks4: write request: %w", err)
	}

	var reply [8]byte
	if _, err := io.ReadFull(conn, reply[:]); err != nil {
		return fmt.Errorf("socks4: read reply: %w", err)
	}
	if reply[0] != 0x00 {
		return fmt.Errorf("socks4: bad reply version 0x%02x", reply[0])
	}
	switch reply[1] {
	case 0x5a: // request granted
		return nil
	case 0x5b:
		return errors.New("socks4: request rejected or failed")
	case 0x5c:
		return errors.New("socks4: rejected, no identd on client")
	case 0x5d:
		return errors.New("socks4: rejected, identd auth failed")
	default:
		return fmt.Errorf("socks4: unknown reply code 0x%02x", reply[1])
	}
}

// ipv4 returns the 4-byte form of host if it is an IPv4 literal, else nil.
func ipv4(host string) net.IP {
	ip := net.ParseIP(host)
	if ip == nil {
		return nil
	}
	return ip.To4()
}
