// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package provider

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sync"
	"syscall"
	"time"

	"github.com/chainguard-dev/terraform-infra-common/pkg/httpmetrics"
)

// dialTimeout bounds how long a single discovery connection may spend in
// connect(2). Discovery targets are attacker-influenced, so a target that
// accepts packets but never completes the handshake must not pin a request.
const dialTimeout = 5 * time.Second

// errNonPublicAddress is returned when a discovery connection resolves to an
// address that is not on the public internet.
var errNonPublicAddress = errors.New("refusing to dial non-public address")

// reservedPrefixes are ranges that are not routable on the public internet but
// which netip's classifiers do not already cover. Cloud instance metadata
// services live in the link-local range, which IsLinkLocalUnicast catches.
var reservedPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),       // "this network" (RFC 1122)
	netip.MustParsePrefix("100.64.0.0/10"),   // carrier-grade NAT (RFC 6598)
	netip.MustParsePrefix("192.0.0.0/24"),    // IETF protocol assignments
	netip.MustParsePrefix("192.0.2.0/24"),    // TEST-NET-1
	netip.MustParsePrefix("198.18.0.0/15"),   // benchmarking (RFC 2544)
	netip.MustParsePrefix("198.51.100.0/24"), // TEST-NET-2
	netip.MustParsePrefix("203.0.113.0/24"),  // TEST-NET-3
	netip.MustParsePrefix("240.0.0.0/4"),     // reserved (RFC 1112)
	netip.MustParsePrefix("100::/64"),        // discard-only (RFC 6666)
	netip.MustParsePrefix("2001:db8::/32"),   // documentation (RFC 3849)
}

// isPublicAddress reports whether addr is routable on the public internet.
//
// IPv4-mapped IPv6 addresses are unmapped first so that, for example,
// ::ffff:10.0.0.1 is classified as the private address it really is.
func isPublicAddress(addr netip.Addr) bool {
	addr = addr.Unmap()
	if !addr.IsValid() {
		return false
	}
	// IsPrivate covers RFC 1918 (IPv4) and RFC 4193 unique local (IPv6).
	if addr.IsLoopback() || addr.IsPrivate() || addr.IsUnspecified() ||
		addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() ||
		addr.IsInterfaceLocalMulticast() || addr.IsMulticast() {
		return false
	}
	for _, p := range reservedPrefixes {
		if p.Contains(addr) {
			return false
		}
	}
	return true
}

// newRestrictedDialer returns a dialer that refuses to open a connection to an
// address that is not on the public internet.
//
// The check runs in Control, which the runtime calls after name resolution and
// immediately before connect(2), on the concrete address being dialed. That
// placement matters: validating the issuer string alone cannot see where a
// hostname actually points, and a name that resolves differently between
// validation and dial (DNS rebinding) would slip past a string check.
//
// allowLoopback relaxes the rule for loopback destinations only. It is set
// solely for issuers that are themselves explicitly loopback, preserving the
// local-development and test carve-out that oidcvalidate.IsValidIssuer makes.
func newRestrictedDialer(allowLoopback bool) *net.Dialer {
	return &net.Dialer{
		Timeout:   dialTimeout,
		KeepAlive: 30 * time.Second,
		Control: func(_, address string, _ syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return fmt.Errorf("parsing dial address %q: %w", address, err)
			}
			addr, err := netip.ParseAddr(host)
			if err != nil {
				return fmt.Errorf("parsing dial address %q: %w", host, err)
			}
			if allowLoopback && addr.Unmap().IsLoopback() {
				return nil
			}
			if !isPublicAddress(addr) {
				return fmt.Errorf("%w: %s", errNonPublicAddress, addr)
			}
			return nil
		},
	}
}

// newDiscoveryTransport builds the RoundTripper used for OIDC discovery and,
// because the constructed provider retains this client, for the JWKS fetches
// that follow. A discovery document that points its jwks_uri at an internal
// address is therefore refused on the same terms as the issuer itself.
func newDiscoveryTransport(allowLoopback bool) http.RoundTripper {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.DialContext = newRestrictedDialer(allowLoopback).DialContext
	return httpmetrics.WrapTransport(t)
}

// Transports are built once and shared so that connection pooling still
// applies across discovery requests.
var (
	strictTransport   = sync.OnceValue(func() http.RoundTripper { return newDiscoveryTransport(false) })
	loopbackTransport = sync.OnceValue(func() http.RoundTripper { return newDiscoveryTransport(true) })
)

// discoveryTransport returns the transport to use for the given issuer.
func discoveryTransport(issuer string) http.RoundTripper {
	if isLoopbackIssuer(issuer) {
		return loopbackTransport()
	}
	return strictTransport()
}

// isLoopbackIssuer reports whether the issuer explicitly names a loopback host.
// This mirrors the carve-out in oidcvalidate.IsValidIssuer, which permits plain
// HTTP for localhost, 127.0.0.1 and ::1 so that local development and tests can
// run against a server on the loopback interface.
//
// A hostname that merely resolves to loopback is deliberately not covered: only
// an issuer that says loopback on its face gets the relaxed treatment.
func isLoopbackIssuer(issuer string) bool {
	u, err := url.Parse(issuer)
	if err != nil {
		return false
	}
	host := u.Hostname()
	if host == "localhost" {
		return true
	}
	addr, err := netip.ParseAddr(host)
	return err == nil && addr.Unmap().IsLoopback()
}
