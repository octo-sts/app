// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package provider

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/chainguard-dev/terraform-infra-common/pkg/httpmetrics"
)

// The issuer comes from an unverified bearer token, and the discovery
// document it serves names the jwks_uri, so every outbound OIDC request
// goes to an address the caller chose. These transports refuse to connect
// to addresses no real issuer uses (GHSA-vr42-fr6r-3fj3). The check runs on
// the resolved IP at dial time, so it also covers DNS names that resolve to
// such an address and redirects to one.
var (
	// guardedTransport is used for every non-loopback issuer.
	guardedTransport = newGuardedTransport(http.ProxyFromEnvironment, false)

	// loopbackTransport is used only when the issuer itself is a loopback
	// http issuer (local development and tests), which oidcvalidate already
	// restricts to localhost, 127.0.0.1 and ::1.
	loopbackTransport = newGuardedTransport(http.ProxyFromEnvironment, true)
)

// errBlockedAddress is returned when a request targets a refused address.
var errBlockedAddress = errors.New("refusing to connect to a non-routable OIDC address")

// blockPrivate additionally refuses private and shared (CGNAT) addresses.
// It is off by default because self-hosted deployments often trust
// in-cluster issuers on private addresses.
var blockPrivate atomic.Bool

// BlockPrivateIPs sets whether OIDC discovery and key fetches may connect to
// private (RFC 1918, fc00::/7) and shared (100.64.0.0/10) addresses. Set it
// once at startup from OCTOSTS_OIDC_BLOCK_PRIVATE_IPS.
func BlockPrivateIPs(enabled bool) {
	blockPrivate.Store(enabled)
}

var (
	// alwaysBlocked are cloud metadata and host-agent addresses that the
	// category checks below do not cover.
	alwaysBlocked = []netip.Prefix{
		netip.MustParsePrefix("fd00:ec2::254/128"),  // AWS IMDS over IPv6
		netip.MustParsePrefix("100.100.100.200/32"), // Alibaba Cloud metadata
		netip.MustParsePrefix("168.63.129.16/32"),   // Azure WireServer
	}

	sharedAddressSpace = netip.MustParsePrefix("100.64.0.0/10") // RFC 6598 (CGNAT)
	nat64              = netip.MustParsePrefix("64:ff9b::/96")  // RFC 6052
	sixToFour          = netip.MustParsePrefix("2002::/16")     // RFC 3056
)

func newGuardedTransport(proxy func(*http.Request) (*url.URL, error), allowLoopback bool) http.RoundTripper {
	// proxies records the dial address of every proxy guardedProxy has handed
	// a request to. The operator configured those, and guardedProxy has
	// already checked the request's target, so dialing them is not checked.
	// Otherwise a loopback sidecar proxy, or a proxy on a private address
	// with BlockPrivateIPs on, would be refused.
	var proxies sync.Map
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.Proxy = guardedProxy(proxy, allowLoopback, &proxies)
	guarded := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
		Control: func(_, address string, _ syscall.RawConn) error {
			return checkDialAddress(address, allowLoopback)
		},
	}
	direct := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	}
	t.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		if _, ok := proxies.Load(address); ok {
			return direct.DialContext(ctx, network, address)
		}
		return guarded.DialContext(ctx, network, address)
	}
	return httpmetrics.WrapTransport(t)
}

// guardedProxy wraps proxy so a proxied request is checked before it is
// handed off. Through a proxy the dialer only ever sees the proxy's address,
// so without this the proxy would connect to whatever host the caller chose.
// The target is resolved here and every address checked. A name that does not
// resolve locally is refused rather than passed to the proxy to resolve.
// The proxy resolves the name again, so this narrows the gap rather than
// closing it against a DNS answer that changes in between.
//
// The proxy's own dial address is recorded in proxies, if non-nil, so the
// dialer can tell a proxy connection from a direct one.
func guardedProxy(proxy func(*http.Request) (*url.URL, error), allowLoopback bool, proxies *sync.Map) func(*http.Request) (*url.URL, error) {
	return func(req *http.Request) (*url.URL, error) {
		proxyURL, err := proxy(req)
		if err != nil || proxyURL == nil {
			return proxyURL, err
		}
		if err := checkHost(req.Context(), req.URL.Hostname(), allowLoopback); err != nil {
			return nil, err
		}
		if proxies != nil {
			proxies.Store(proxyDialAddress(proxyURL), struct{}{})
		}
		return proxyURL, nil
	}
}

// proxyDialAddress returns the host:port net/http dials for proxyURL, filling
// in the scheme's default port the same way net/http does.
func proxyDialAddress(proxyURL *url.URL) string {
	port := proxyURL.Port()
	if port == "" {
		switch proxyURL.Scheme {
		case "https":
			port = "443"
		case "socks5", "socks5h":
			port = "1080"
		default:
			port = "80"
		}
	}
	return net.JoinHostPort(proxyURL.Hostname(), port)
}

// checkHost resolves host, unless it is already an IP, and checks every
// address it resolves to.
func checkHost(ctx context.Context, host string, allowLoopback bool) error {
	if ip, err := netip.ParseAddr(host); err == nil {
		return checkIP(ip, allowLoopback)
	}
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return fmt.Errorf("%w: resolving %q: %w", errBlockedAddress, host, err)
	}
	for _, ip := range addrs {
		if err := checkIP(ip, allowLoopback); err != nil {
			return err
		}
	}
	return nil
}

// checkDialAddress checks the resolved host:port a dial is about to use.
func checkDialAddress(address string, allowLoopback bool) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("%w: %q", errBlockedAddress, address)
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return fmt.Errorf("%w: %q", errBlockedAddress, address)
	}
	return checkIP(ip, allowLoopback)
}

// checkIP refuses link-local (including the cloud metadata service at
// 169.254.169.254), unspecified and multicast addresses, the cloud metadata
// addresses in alwaysBlocked, and loopback unless allowLoopback is set. With
// BlockPrivateIPs enabled it also refuses private and shared addresses. An
// IPv4 address embedded in a NAT64 or 6to4 address is checked by the same
// rules, so it cannot be used to reach one of these.
func checkIP(ip netip.Addr, allowLoopback bool) error {
	ip = ip.Unmap()
	if v4, ok := embeddedIPv4(ip); ok {
		if err := checkIP(v4, allowLoopback); err != nil {
			return err
		}
	}
	for _, p := range alwaysBlocked {
		if p.Contains(ip) {
			return fmt.Errorf("%w: %s", errBlockedAddress, ip)
		}
	}
	switch {
	case ip.IsLoopback() && allowLoopback:
		return nil
	case ip.IsLoopback(),
		ip.IsLinkLocalUnicast(),
		ip.IsLinkLocalMulticast(),
		ip.IsInterfaceLocalMulticast(),
		ip.IsMulticast(),
		ip.IsUnspecified():
		return fmt.Errorf("%w: %s", errBlockedAddress, ip)
	}
	if blockPrivate.Load() && (ip.IsPrivate() || sharedAddressSpace.Contains(ip)) {
		return fmt.Errorf("%w: %s (OCTOSTS_OIDC_BLOCK_PRIVATE_IPS)", errBlockedAddress, ip)
	}
	return nil
}

// embeddedIPv4 returns the IPv4 address carried in a NAT64 (64:ff9b::/96) or
// 6to4 (2002::/16) address.
func embeddedIPv4(ip netip.Addr) (netip.Addr, bool) {
	if !ip.Is6() {
		return netip.Addr{}, false
	}
	b := ip.As16()
	switch {
	case nat64.Contains(ip):
		return netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]}), true
	case sixToFour.Contains(ip):
		return netip.AddrFrom4([4]byte{b[2], b[3], b[4], b[5]}), true
	}
	return netip.Addr{}, false
}

// isLoopbackHost reports whether host is one of the loopback names
// oidcvalidate accepts for plain-http issuers.
func isLoopbackHost(host string) bool {
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}

// isLoopbackIssuer reports whether issuer is a plain-http loopback issuer.
// oidcvalidate.IsValidIssuer only accepts http for these hosts.
func isLoopbackIssuer(issuer string) bool {
	u, err := url.Parse(issuer)
	return err == nil && u.Scheme == "http" && isLoopbackHost(u.Hostname())
}

// validateJWKSURI checks the jwks_uri from issuer's discovery document. It
// must be an absolute https URL without userinfo. Plain http is accepted
// only for a loopback jwks_uri served by a loopback http issuer.
func validateJWKSURI(issuer, jwksURI string) error {
	u, err := url.Parse(jwksURI)
	if err != nil || u.Host == "" {
		return fmt.Errorf("invalid jwks_uri %q", jwksURI)
	}
	if u.User != nil {
		return fmt.Errorf("jwks_uri %q must not contain userinfo", jwksURI)
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		if isLoopbackIssuer(issuer) && isLoopbackHost(u.Hostname()) {
			return nil
		}
	}
	return fmt.Errorf("jwks_uri %q must use https", jwksURI)
}
