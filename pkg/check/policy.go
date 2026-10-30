package check

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
)

var ErrProxyPolicy = errors.New("proxy destination is not public")

var reservedNetworks = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"), netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"), netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("::/96"), netip.MustParsePrefix("64:ff9b::/96"),
	netip.MustParsePrefix("64:ff9b:1::/48"), netip.MustParsePrefix("100::/64"),
	netip.MustParsePrefix("2001::/23"), netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("2002::/16"), netip.MustParsePrefix("3fff::/20"),
}

func IsPublicIP(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.IsValid() || ip.Zone() != "" || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return false
	}
	for _, prefix := range reservedNetworks {
		if prefix.Contains(ip) {
			return false
		}
	}
	return true
}

// publicDialer checks every DNS answer, then dials a checked literal address.
// The OS never re-resolves the hostname between policy checking and connection.
type publicDialer struct{ base *net.Dialer }

func (d *publicDialer) Dial(network, address string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, address)
}
func (d *publicDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	var ips []netip.Addr
	if ip, parseErr := netip.ParseAddr(host); parseErr == nil {
		ips = []netip.Addr{ip}
	} else {
		ips, err = net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		if err != nil {
			return nil, err
		}
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("%w: no addresses", ErrProxyPolicy)
	}
	for _, ip := range ips {
		if !IsPublicIP(ip) {
			return nil, ErrProxyPolicy
		}
	}
	for _, ip := range ips {
		conn, e := d.base.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		if e == nil {
			return conn, nil
		}
		err = e
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
	}
	return nil, err
}
