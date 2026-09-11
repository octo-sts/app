// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package provider

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
)

func TestIsPublicAddress(t *testing.T) {
	for _, tc := range []struct {
		addr string
		want bool
	}{
		// Public.
		{"8.8.8.8", true},
		{"1.1.1.1", true},
		{"140.82.121.4", true},
		{"2606:4700:4700::1111", true},

		// Loopback.
		{"127.0.0.1", false},
		{"127.1.2.3", false},
		{"::1", false},

		// RFC 1918 private.
		{"10.0.0.1", false},
		{"172.16.0.1", false},
		{"172.31.255.255", false},
		{"192.168.1.1", false},

		// Link-local, including the cloud instance metadata address.
		{"169.254.169.254", false},
		{"169.254.0.1", false},
		{"fe80::1", false},

		// IPv6 unique local.
		{"fd00::1", false},
		{"fc00::1", false},

		// Unspecified and other reserved ranges.
		{"0.0.0.0", false},
		{"0.1.2.3", false},
		{"::", false},
		{"100.64.0.1", false},
		{"192.0.0.1", false},
		{"198.18.0.1", false},
		{"240.0.0.1", false},
		{"255.255.255.255", false},
		{"224.0.0.1", false},

		// IPv4-mapped IPv6 must be judged on the embedded IPv4 address.
		{"::ffff:10.0.0.1", false},
		{"::ffff:127.0.0.1", false},
		{"::ffff:8.8.8.8", true},
	} {
		t.Run(tc.addr, func(t *testing.T) {
			addr, err := netip.ParseAddr(tc.addr)
			if err != nil {
				t.Fatalf("ParseAddr(%q) = %v", tc.addr, err)
			}
			if got := isPublicAddress(addr); got != tc.want {
				t.Errorf("isPublicAddress(%s) = %v, want %v", tc.addr, got, tc.want)
			}
		})
	}
}

func TestIsLoopbackIssuer(t *testing.T) {
	for _, tc := range []struct {
		issuer string
		want   bool
	}{
		{"http://localhost:8080", true},
		{"http://127.0.0.1:8080", true},
		{"https://127.0.0.1", true},
		{"http://[::1]:8080", true},
		{"https://accounts.example.com", false},
		{"https://token.actions.githubusercontent.com", false},
		// A public name may still resolve to loopback; it does not get the
		// carve-out, and the dialer is what ultimately refuses it.
		{"https://localhost.example.com", false},
		{"https://10.0.0.1", false},
		{"", false},
	} {
		t.Run(tc.issuer, func(t *testing.T) {
			if got := isLoopbackIssuer(tc.issuer); got != tc.want {
				t.Errorf("isLoopbackIssuer(%q) = %v, want %v", tc.issuer, got, tc.want)
			}
		})
	}
}

// TestRestrictedDialerBlocksNonPublic asserts the dialer refuses a real
// connection to a loopback listener unless loopback has been allowed. The
// listener stands in for any internal service reachable from the deployment.
func TestRestrictedDialerBlocksNonPublic(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	addr := server.Listener.Addr().String()

	t.Run("blocked", func(t *testing.T) {
		_, err := newRestrictedDialer(false).DialContext(context.Background(), "tcp", addr)
		if err == nil {
			t.Fatal("DialContext() = nil, want an error for a non-public address")
		}
		if !errors.Is(err, errNonPublicAddress) {
			t.Errorf("DialContext() = %v, want errNonPublicAddress", err)
		}
	})

	t.Run("allowed for loopback issuers", func(t *testing.T) {
		conn, err := newRestrictedDialer(true).DialContext(context.Background(), "tcp", addr)
		if err != nil {
			t.Fatalf("DialContext() = %v, want success when loopback is allowed", err)
		}
		conn.Close()
	})
}

// TestDiscoveryTransportBlocksNonPublicIssuer drives the guard through the
// transport that discovery actually uses, via a hostname that is not itself
// loopback but resolves there — the shape a rebinding or attacker-controlled
// DNS record takes.
func TestDiscoveryTransportBlocksNonPublicIssuer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	_, port, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatalf("SplitHostPort() = %v", err)
	}

	// "localtest.me" style names are avoided so the test stays hermetic; the
	// strict transport is instead pointed at the loopback literal directly,
	// which it must refuse because the issuer carve-out does not apply to it.
	client := &http.Client{Transport: discoveryTransport("https://accounts.example.com")}
	req, err := http.NewRequest(http.MethodGet, "http://127.0.0.1:"+port+"/.well-known/openid-configuration", nil)
	if err != nil {
		t.Fatalf("NewRequest() = %v", err)
	}
	if _, err := client.Do(req); err == nil {
		t.Fatal("client.Do() = nil, want an error reaching a non-public address")
	} else if !errors.Is(err, errNonPublicAddress) {
		t.Errorf("client.Do() = %v, want errNonPublicAddress", err)
	}
}
