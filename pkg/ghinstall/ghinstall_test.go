// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package ghinstall

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"hash/fnv"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bradleyfalzon/ghinstallation/v2"
	jwt "github.com/golang-jwt/jwt/v4"
	"github.com/google/go-github/v84/github"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestGet(t *testing.T) {
	ctx := context.Background()
	installID := int64(42)

	atr := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/app/installations":
			json.NewEncoder(w).Encode([]github.Installation{{
				ID: github.Ptr(installID),
				Account: &github.User{
					Login: github.Ptr("my-org"),
				},
			}})
		default:
			w.WriteHeader(http.StatusNotImplemented)
			fmt.Fprintf(w, "%s %s not implemented\n", r.Method, r.URL.Path)
		}
	}))

	mgr, err := New(atr)
	if err != nil {
		t.Fatalf("New() = %v", err)
	}

	gotATR, gotID, err := mgr.Get(ctx, "my-org", "my-org/repo", "my-identity")
	if err != nil {
		t.Fatalf("Get() = %v", err)
	}
	if gotATR != atr {
		t.Error("Get() returned unexpected AppsTransport")
	}
	if gotID != installID {
		t.Errorf("install ID: got = %d, wanted = %d", gotID, installID)
	}
}

func TestGetCached(t *testing.T) {
	ctx := context.Background()
	installID := int64(99)
	calls := 0

	atr := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/app/installations":
			calls++
			json.NewEncoder(w).Encode([]github.Installation{{
				ID: github.Ptr(installID),
				Account: &github.User{
					Login: github.Ptr("cached-org"),
				},
			}})
		default:
			w.WriteHeader(http.StatusNotImplemented)
		}
	}))

	mgr, err := New(atr)
	if err != nil {
		t.Fatalf("New() = %v", err)
	}

	// First call populates the cache.
	if _, _, err := mgr.Get(ctx, "cached-org", "cached-org/repo", "my-identity"); err != nil {
		t.Fatalf("Get() = %v", err)
	}
	if calls != 1 {
		t.Fatalf("API calls after first Get: got = %d, wanted = 1", calls)
	}

	// Second call should come from cache.
	_, gotID, err := mgr.Get(ctx, "cached-org", "cached-org/repo", "my-identity")
	if err != nil {
		t.Fatalf("Get() = %v", err)
	}
	if gotID != installID {
		t.Errorf("install ID: got = %d, wanted = %d", gotID, installID)
	}
	if calls != 1 {
		t.Errorf("API calls after second Get: got = %d, wanted = 1", calls)
	}
}

func TestGetNotFound(t *testing.T) {
	ctx := context.Background()

	atr := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/app/installations":
			json.NewEncoder(w).Encode([]github.Installation{{
				ID: github.Ptr(int64(1)),
				Account: &github.User{
					Login: github.Ptr("other-org"),
				},
			}})
		default:
			w.WriteHeader(http.StatusNotImplemented)
		}
	}))

	mgr, err := New(atr)
	if err != nil {
		t.Fatalf("New() = %v", err)
	}

	_, _, err = mgr.Get(ctx, "missing-org", "missing-org/repo", "my-identity")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected gRPC status error, got %T", err)
	}
	if st.Code() != codes.NotFound {
		t.Errorf("code: got = %v, wanted = %v", st.Code(), codes.NotFound)
	}
}

func TestConsistentHashing(t *testing.T) {
	ctx := context.Background()
	installID := int64(42)
	appIDs := []int64{12345678, 87654321}

	// Create two managers backed by different app transports, both installed
	// for "my-org".
	managers := make([]Manager, 0, len(appIDs))
	for _, appID := range appIDs {
		atr := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/app/installations":
				json.NewEncoder(w).Encode([]github.Installation{{
					ID: github.Ptr(installID),
					Account: &github.User{
						Login: github.Ptr("my-org"),
					},
				}})
			default:
				w.WriteHeader(http.StatusNotImplemented)
			}
		}), appID)
		m, err := New(atr)
		if err != nil {
			t.Fatalf("New() = %v", err)
		}
		managers = append(managers, m)
	}

	mm := NewMultiManager(managers)

	const scope, identity = "my-org/repo", "my-identity"

	// Derive the expected app index using the same hashing logic.
	h := fnv.New32a()
	h.Write([]byte(scope + ":" + identity))
	wantAppID := appIDs[int(h.Sum32())%len(appIDs)]

	// Multiple calls for the same (scope, identity) must always return the same app.
	for i := range 4 {
		atr, gotID, err := mm.Get(ctx, "my-org", scope, identity)
		if err != nil {
			t.Fatalf("Get() call %d = %v", i, err)
		}
		if gotID != installID {
			t.Errorf("call %d: install ID: got = %d, wanted = %d", i, gotID, installID)
		}
		if gotAppID := atr.AppID(); gotAppID != wantAppID {
			t.Errorf("call %d: app ID: got = %d, wanted = %d (consistent hash)", i, gotAppID, wantAppID)
		}
	}
}

func TestConsistentHashingDistribution(t *testing.T) {
	ctx := context.Background()
	installID := int64(42)
	appIDs := []int64{12345678, 87654321}

	// Both apps are installed for "my-org".
	handler := func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/app/installations":
			json.NewEncoder(w).Encode([]github.Installation{
				{ID: github.Ptr(installID), Account: &github.User{Login: github.Ptr("my-org")}},
			})
		default:
			w.WriteHeader(http.StatusNotImplemented)
		}
	}

	managers := make([]Manager, 0, len(appIDs))
	for _, appID := range appIDs {
		atr := newTestClient(t, http.HandlerFunc(handler), appID)
		m, err := New(atr)
		if err != nil {
			t.Fatalf("New() = %v", err)
		}
		managers = append(managers, m)
	}

	mm := NewMultiManager(managers)

	// Compute expected app index for a given (scope, identity) pair.
	expectedIndex := func(scope, identity string) int {
		h := fnv.New32a()
		h.Write([]byte(scope + ":" + identity))
		return int(h.Sum32()) % len(appIDs)
	}

	// Find two (scope, identity) pairs within the same org that hash to
	// different indices, confirming load is distributed across apps.
	type pair struct{ scope, identity string }
	candidates := []pair{
		{"my-org/repo-a", "identity-a"},
		{"my-org/repo-b", "identity-b"},
		{"my-org/repo-a", "identity-b"},
		{"my-org/repo-b", "identity-a"},
		{"my-org/repo-c", "identity-c"},
	}
	seen := map[int]pair{}
	for _, c := range candidates {
		idx := expectedIndex(c.scope, c.identity)
		if _, ok := seen[idx]; !ok {
			seen[idx] = c
		}
		if len(seen) == 2 {
			break
		}
	}
	if len(seen) < 2 {
		t.Skip("could not find two (scope, identity) pairs that hash to different app indices")
	}

	p0, p1 := seen[0], seen[1]

	atr0, _, err := mm.Get(ctx, "my-org", p0.scope, p0.identity)
	if err != nil {
		t.Fatalf("Get(%q, %q) = %v", p0.scope, p0.identity, err)
	}
	atr1, _, err := mm.Get(ctx, "my-org", p1.scope, p1.identity)
	if err != nil {
		t.Fatalf("Get(%q, %q) = %v", p1.scope, p1.identity, err)
	}

	if atr0.AppID() == atr1.AppID() {
		t.Errorf("expected different app IDs for (%q,%q) and (%q,%q), both got %d",
			p0.scope, p0.identity, p1.scope, p1.identity, atr0.AppID())
	}
}

func TestMultiManagerFallback(t *testing.T) {
	ctx := context.Background()
	installID := int64(42)
	primaryAppID := int64(12345678)
	secondaryAppID := int64(87654321)

	// The primary app is installed in "my-org".
	primaryATR := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/app/installations":
			json.NewEncoder(w).Encode([]github.Installation{{
				ID: github.Ptr(installID),
				Account: &github.User{
					Login: github.Ptr("my-org"),
				},
			}})
		default:
			w.WriteHeader(http.StatusNotImplemented)
		}
	}), primaryAppID)
	primaryMgr, err := New(primaryATR)
	if err != nil {
		t.Fatalf("New() = %v", err)
	}

	// The secondary app is NOT installed in "my-org".
	secondaryATR := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/app/installations":
			json.NewEncoder(w).Encode([]github.Installation{{
				ID: github.Ptr(int64(99)),
				Account: &github.User{
					Login: github.Ptr("other-org"),
				},
			}})
		default:
			w.WriteHeader(http.StatusNotImplemented)
		}
	}), secondaryAppID)
	secondaryMgr, err := New(secondaryATR)
	if err != nil {
		t.Fatalf("New() = %v", err)
	}

	mm := NewMultiManager([]Manager{primaryMgr, secondaryMgr})

	// Find a (scope, identity) pair that is confirmed to hash to index 1
	// (secondaryMgr), so the fallback path is reliably exercised.
	var scope, identity string
	for i := 0; ; i++ {
		s, id := fmt.Sprintf("my-org/repo-%d", i), "my-identity"
		h := fnv.New32a()
		h.Write([]byte(s + ":" + id))
		if int(h.Sum32())%2 == 1 {
			scope, identity = s, id
			break
		}
	}

	atr, gotID, err := mm.Get(ctx, "my-org", scope, identity)
	if err != nil {
		t.Fatalf("Get() = %v", err)
	}
	if gotID != installID {
		t.Errorf("install ID: got = %d, wanted = %d", gotID, installID)
	}
	// Must resolve via the primary app since the secondary is not installed.
	if gotAppID := atr.AppID(); gotAppID != primaryAppID {
		t.Errorf("app ID: got = %d, wanted primary = %d", gotAppID, primaryAppID)
	}
}

func TestMultiManagerFallbackNotInstalled(t *testing.T) {
	ctx := context.Background()
	fallbackAppID := int64(12345678)
	secondaryAppID := int64(87654321)

	// Neither app is installed for "missing-org".
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/app/installations":
			json.NewEncoder(w).Encode([]github.Installation{{
				ID: github.Ptr(int64(1)),
				Account: &github.User{
					Login: github.Ptr("other-org"),
				},
			}})
		default:
			w.WriteHeader(http.StatusNotImplemented)
		}
	})

	managers := make([]Manager, 0, 2)
	for _, appID := range []int64{fallbackAppID, secondaryAppID} {
		atr := newTestClient(t, handler, appID)
		m, err := New(atr)
		if err != nil {
			t.Fatalf("New() = %v", err)
		}
		managers = append(managers, m)
	}

	mm := NewMultiManager(managers)

	// All managers should return NotFound since neither is installed for "missing-org".
	for i := range 2 {
		_, _, err := mm.Get(ctx, "missing-org", "missing-org/repo", "my-identity")
		if err == nil {
			t.Fatalf("Get() call %d: expected error, got nil", i)
		}
		st, ok := status.FromError(err)
		if !ok {
			t.Fatalf("Get() call %d: expected gRPC status error, got %T", i, err)
		}
		if st.Code() != codes.NotFound {
			t.Errorf("Get() call %d: code: got = %v, wanted = %v", i, st.Code(), codes.NotFound)
		}
	}
}

func newTestClient(t *testing.T, h http.Handler, appIDs ...int64) *ghinstallation.AppsTransport {
	t.Helper()

	tlsConfig, err := generateTLS(&x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotAfter:     time.Now().Add(10 * time.Hour),
		DNSNames:     []string{"localhost"},
	})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(h)
	srv.TLS = tlsConfig
	srv.StartTLS()
	t.Cleanup(srv.Close)

	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
		DialTLS: func(network, addr string) (net.Conn, error) {
			return tls.Dial(network, strings.TrimPrefix(srv.URL, "https://"), tlsConfig)
		},
		Dial: func(network, addr string) (net.Conn, error) {
			return tls.Dial(network, strings.TrimPrefix(srv.URL, "http://"), tlsConfig)
		},
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	appID := int64(12345678)
	if len(appIDs) > 0 {
		appID = appIDs[0]
	}

	atr, err := ghinstallation.NewAppsTransportWithOptions(transport, appID, ghinstallation.WithSigner(ghinstallation.NewRSASigner(jwt.SigningMethodRS256, key)))
	if err != nil {
		t.Fatalf("NewAppsTransportWithOptions failed: %v", err)
	}
	atr.BaseURL = srv.URL

	return atr
}

func generateTLS(tmpl *x509.Certificate) (*tls.Config, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("error generating private key: %w", err)
	}
	raw, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		return nil, fmt.Errorf("error generating certificate: %w", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: raw,
	})
	keyBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("error marshaling key bytes: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyBytes,
	})
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("error loading tls certificate: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(certPEM) {
		return nil, fmt.Errorf("error adding cert to pool")
	}
	return &tls.Config{
		Certificates:       []tls.Certificate{tlsCert},
		RootCAs:            pool,
		InsecureSkipVerify: true,
	}, nil
}
