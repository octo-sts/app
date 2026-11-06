// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package provider

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
)

func TestValidateJWKSURI(t *testing.T) {
	for _, tc := range []struct {
		issuer, jwks string
		ok           bool
	}{
		{"https://token.actions.githubusercontent.com", "https://token.actions.githubusercontent.com/.well-known/jwks", true},
		// A different host is fine: Google serves its keys from googleapis.com.
		{"https://accounts.google.com", "https://www.googleapis.com/oauth2/v3/certs", true},
		{"http://127.0.0.1:8080", "http://127.0.0.1:8080/jwks", true},
		{"http://localhost:8080", "http://localhost:9090/jwks", true},

		// Plain http is refused for a public issuer.
		{"https://issuer.example.com", "http://169.254.169.254/computeMetadata/v1/", false},
		{"https://issuer.example.com", "http://internal.example.com/jwks", false},
		// A loopback issuer must not point jwks_uri off the machine over http.
		{"http://127.0.0.1:8080", "http://169.254.169.254/latest/meta-data/", false},
		{"https://issuer.example.com", "https://user:pass@issuer.example.com/jwks", false},
		{"https://issuer.example.com", "file:///etc/passwd", false},
		{"https://issuer.example.com", "gopher://issuer.example.com/", false},
		{"https://issuer.example.com", "/jwks", false},
		{"https://issuer.example.com", "", false},
	} {
		err := validateJWKSURI(tc.issuer, tc.jwks)
		if (err == nil) != tc.ok {
			t.Errorf("validateJWKSURI(%q, %q) = %v, want ok=%v", tc.issuer, tc.jwks, err, tc.ok)
		}
	}
}

func TestCheckDialAddress(t *testing.T) {
	for _, tc := range []struct {
		addr          string
		allowLoopback bool
		ok            bool
	}{
		{"140.82.112.3:443", false, true},
		{"[2606:4700::1111]:443", false, true},
		// Private ranges stay reachable for self-hosted, in-cluster issuers.
		{"10.0.0.5:443", false, true},
		{"127.0.0.1:8080", true, true},
		{"[::1]:8080", true, true},

		{"169.254.169.254:80", false, false},
		{"169.254.169.254:80", true, false},
		{"[::ffff:169.254.169.254]:80", false, false},
		{"[fe80::1]:80", false, false},
		{"127.0.0.1:8080", false, false},
		{"[::1]:8080", false, false},
		{"0.0.0.0:80", false, false},
		{"224.0.0.1:80", false, false},
		{"not-an-ip:80", false, false},

		// Cloud metadata addresses outside the link-local range.
		{"[fd00:ec2::254]:80", false, false},
		{"100.100.100.200:80", false, false},
		{"168.63.129.16:80", false, false},

		// NAT64 and 6to4 are checked by the IPv4 address they carry, so a
		// public address through NAT64 (IPv6-only hosts) still works.
		{"[64:ff9b::a9fe:a9fe]:80", false, false}, // 169.254.169.254
		{"[64:ff9b::7f00:1]:80", false, false},    // 127.0.0.1
		{"[2002:a9fe:a9fe::1]:80", false, false},  // 169.254.169.254
		{"[64:ff9b::8c52:7003]:443", false, true}, // 140.82.112.3
		{"[2002:8c52:7003::1]:443", false, true},  // 140.82.112.3
	} {
		err := checkDialAddress(tc.addr, tc.allowLoopback)
		if (err == nil) != tc.ok {
			t.Errorf("checkDialAddress(%q, %v) = %v, want ok=%v", tc.addr, tc.allowLoopback, err, tc.ok)
		}
	}
}

func TestCheckDialAddressBlockPrivateIPs(t *testing.T) {
	BlockPrivateIPs(true)
	t.Cleanup(func() { BlockPrivateIPs(false) })

	for _, tc := range []struct {
		addr string
		ok   bool
	}{
		{"140.82.112.3:443", true},
		{"[2606:4700::1111]:443", true},
		// Loopback issuers keep working for local development.
		{"127.0.0.1:8080", true},

		{"10.0.0.5:443", false},
		{"172.16.0.1:443", false},
		{"192.168.1.1:443", false},
		{"100.64.0.1:443", false}, // CGNAT, not covered by IsPrivate
		{"[fd12:3456::1]:443", false},
		{"[::ffff:10.0.0.5]:443", false},
		{"[64:ff9b::a00:5]:443", false}, // NAT64 of 10.0.0.5
	} {
		err := checkDialAddress(tc.addr, true)
		if (err == nil) != tc.ok {
			t.Errorf("checkDialAddress(%q) with private block = %v, want ok=%v", tc.addr, err, tc.ok)
		}
	}
}

// TestGuardedProxyChecksTarget covers the proxy path: through a proxy the dial
// check only sees the proxy's address, so the target must be checked before
// the request is handed off.
func TestGuardedProxyChecksTarget(t *testing.T) {
	proxyURL, err := url.Parse("http://proxy.internal:3128")
	if err != nil {
		t.Fatal(err)
	}
	viaProxy := guardedProxy(func(*http.Request) (*url.URL, error) { return proxyURL, nil }, false, nil)

	for _, tc := range []struct {
		target string
		ok     bool
	}{
		{"https://140.82.112.3/.well-known/openid-configuration", true},
		{"http://169.254.169.254/computeMetadata/v1/", false},
		{"http://[fd00:ec2::254]/latest/meta-data/", false},
		{"http://127.0.0.1:8080/", false},
		// A name that doesn't resolve is refused, not left to the proxy.
		{"https://does-not-resolve.invalid/jwks", false},
	} {
		req, err := http.NewRequest(http.MethodGet, tc.target, nil)
		if err != nil {
			t.Fatal(err)
		}
		got, err := viaProxy(req)
		if tc.ok && (err != nil || got != proxyURL) {
			t.Errorf("proxy(%q) = (%v, %v), want the proxy", tc.target, got, err)
		}
		if !tc.ok && (err == nil || !errors.Is(err, errBlockedAddress)) {
			t.Errorf("proxy(%q) = (%v, %v), want errBlockedAddress", tc.target, got, err)
		}
	}

	// With no proxy configured, nothing is resolved here: the dial check
	// handles it.
	direct := guardedProxy(func(*http.Request) (*url.URL, error) { return nil, nil }, false, nil)
	req, err := http.NewRequest(http.MethodGet, "https://does-not-resolve.invalid/jwks", nil)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := direct(req); got != nil || err != nil {
		t.Errorf("direct proxy func = (%v, %v), want (nil, nil)", got, err)
	}
}

// TestGuardedTransportThroughLoopbackProxy covers an operator-configured proxy
// on an address the dial check would refuse, such as a loopback sidecar. The
// transport must still reach the proxy for an allowed target, with and without
// BlockPrivateIPs, and must still refuse a disallowed target before the proxy
// sees it. The fake proxy answers plain-http proxy requests itself, so the
// test needs no network.
func TestGuardedTransportThroughLoopbackProxy(t *testing.T) {
	var hits atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.URL.Host != "140.82.112.3" {
			t.Errorf("proxy got a request for %q, want 140.82.112.3", r.URL.Host)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer proxy.Close()
	proxyURL, err := url.Parse(proxy.URL)
	if err != nil {
		t.Fatal(err)
	}
	rt := newGuardedTransport(http.ProxyURL(proxyURL), false)

	for _, block := range []bool{false, true} {
		BlockPrivateIPs(block)
		req, err := http.NewRequest(http.MethodGet, "http://140.82.112.3/jwks", nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := rt.RoundTrip(req)
		if err != nil {
			t.Fatalf("BlockPrivateIPs(%v): request through loopback proxy: %v", block, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("BlockPrivateIPs(%v): status = %d, want 200", block, resp.StatusCode)
		}
	}
	BlockPrivateIPs(false)
	if got := hits.Load(); got != 2 {
		t.Errorf("proxy saw %d requests, want 2", got)
	}

	req, err := http.NewRequest(http.MethodGet, "http://169.254.169.254/computeMetadata/v1/", nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp, err := rt.RoundTrip(req); err == nil {
		resp.Body.Close()
		t.Fatal("request for the metadata service went through the proxy")
	} else if !errors.Is(err, errBlockedAddress) {
		t.Errorf("err = %v, want errBlockedAddress", err)
	}
	if got := hits.Load(); got != 2 {
		t.Errorf("proxy saw %d requests after a refused target, want 2", got)
	}
}

func TestProxyDialAddress(t *testing.T) {
	for in, want := range map[string]string{
		"http://127.0.0.1:3128":      "127.0.0.1:3128",
		"http://proxy.internal":      "proxy.internal:80",
		"https://proxy.internal":     "proxy.internal:443",
		"socks5://10.0.0.1":          "10.0.0.1:1080",
		"http://[::1]:3128":          "[::1]:3128",
		"http://user:pw@proxy:8080/": "proxy:8080",
	} {
		u, err := url.Parse(in)
		if err != nil {
			t.Fatal(err)
		}
		if got := proxyDialAddress(u); got != want {
			t.Errorf("proxyDialAddress(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestGuardedTransportRefusesLoopback proves the dial-time check is wired in:
// a non-loopback issuer's transport must not reach a loopback server even
// though nothing about the URL itself is rejected.
func TestGuardedTransportRefusesLoopback(t *testing.T) {
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
	}))
	defer server.Close()

	req, err := http.NewRequest(http.MethodGet, server.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := guardedTransport.RoundTrip(req)
	if err == nil {
		resp.Body.Close()
		t.Fatal("guardedTransport reached a loopback server")
	}
	if !errors.Is(err, errBlockedAddress) {
		t.Errorf("err = %v, want errBlockedAddress", err)
	}
	if hits.Load() != 0 {
		t.Errorf("server saw %d requests, want 0", hits.Load())
	}

	resp, err = loopbackTransport.RoundTrip(req.Clone(context.Background()))
	if err != nil {
		t.Fatalf("loopbackTransport: %v", err)
	}
	resp.Body.Close()
}

// TestGetRejectsUnsafeJWKSURI covers GHSA-vr42-fr6r-3fj3: discovery must fail,
// and nothing be cached, when the discovery document points jwks_uri at an
// address the issuer checks would never allow.
func TestGetRejectsUnsafeJWKSURI(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		issuerURL := "http://" + r.Host
		w.Write([]byte(`{"issuer":"` + issuerURL + `","jwks_uri":"http://169.254.169.254/computeMetadata/v1/"}`))
	}))
	defer server.Close()

	if _, err := Get(context.Background(), server.URL); err == nil {
		t.Fatal("Get accepted a provider whose jwks_uri targets the metadata service")
	}
	if _, ok := providers.Get(server.URL); ok {
		t.Error("provider with an unsafe jwks_uri was cached")
	}
}
