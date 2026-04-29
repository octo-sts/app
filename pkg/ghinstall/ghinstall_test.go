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

func TestNewRoundRobinPanicsOnEmpty(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic for empty managers slice, got none")
		}
	}()
	NewRoundRobin(nil)
}

func TestRoundRobin(t *testing.T) {
	ctx := context.Background()
	installID := int64(42)
	appIDs := []int64{12345678, 87654321}

	// Both apps installed for "my-org".
	managers := make([]Manager, 0, len(appIDs))
	for _, appID := range appIDs {
		atr := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/app/installations":
				json.NewEncoder(w).Encode([]github.Installation{{
					ID:      github.Ptr(installID),
					Account: &github.User{Login: github.Ptr("my-org")},
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

	rr := NewRoundRobin(managers)

	// Round-robin must distribute across apps: the same (scope, identity) must
	// NOT always return the same app (unlike consistent hashing).
	const scope, identity = "my-org/repo", "my-identity"
	seen := map[int64]bool{}
	for range 4 {
		atr, gotID, err := rr.Get(ctx, "my-org", scope, identity)
		if err != nil {
			t.Fatalf("Get() = %v", err)
		}
		if gotID != installID {
			t.Errorf("install ID: got = %d, wanted = %d", gotID, installID)
		}
		seen[atr.AppID()] = true
	}
	if len(seen) != len(appIDs) {
		t.Errorf("round-robin did not distribute across all apps: only saw app IDs %v", seen)
	}
}

func TestRoundRobinFallback(t *testing.T) {
	ctx := context.Background()
	installID := int64(42)
	primaryAppID := int64(12345678)
	secondaryAppID := int64(87654321)

	// Primary app is installed for "my-org"; secondary is not.
	primaryATR := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/app/installations":
			json.NewEncoder(w).Encode([]github.Installation{{
				ID:      github.Ptr(installID),
				Account: &github.User{Login: github.Ptr("my-org")},
			}})
		default:
			w.WriteHeader(http.StatusNotImplemented)
		}
	}), primaryAppID)
	primaryMgr, err := New(primaryATR)
	if err != nil {
		t.Fatalf("New() = %v", err)
	}

	secondaryATR := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/app/installations":
			json.NewEncoder(w).Encode([]github.Installation{}) // not installed
		default:
			w.WriteHeader(http.StatusNotImplemented)
		}
	}), secondaryAppID)
	secondaryMgr, err := New(secondaryATR)
	if err != nil {
		t.Fatalf("New() = %v", err)
	}

	rr := NewRoundRobin([]Manager{primaryMgr, secondaryMgr})

	// All calls must resolve via the primary app since the secondary is not installed.
	for i := range 4 {
		atr, gotID, err := rr.Get(ctx, "my-org", "my-org/repo", "my-identity")
		if err != nil {
			t.Fatalf("Get() call %d = %v", i, err)
		}
		if gotID != installID {
			t.Errorf("call %d: install ID: got = %d, wanted = %d", i, gotID, installID)
		}
		if got := atr.AppID(); got != primaryAppID {
			t.Errorf("call %d: app ID: got = %d, wanted primary = %d", i, got, primaryAppID)
		}
	}
}

func TestRoundRobinFallbackNotInstalled(t *testing.T) {
	ctx := context.Background()
	appIDs := []int64{12345678, 87654321}

	// Neither app is installed for "missing-org".
	managers := make([]Manager, 0, len(appIDs))
	for _, appID := range appIDs {
		atr := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/app/installations":
				json.NewEncoder(w).Encode([]github.Installation{})
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

	rr := NewRoundRobin(managers)

	for i := range 2 {
		_, _, err := rr.Get(ctx, "missing-org", "missing-org/repo", "my-identity")
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

// testOwner is the GitHub org login used by makeManagersWithDistinctInstalls.
const testOwner = "my-org"

// makeManagersWithDistinctInstalls builds one Manager per appID, each backed
// by a test server that reports a unique installation ID for testOwner.
// Installation IDs are 1000, 1001, ..., 1000+n-1 (parallel to manager index).
func makeManagersWithDistinctInstalls(t *testing.T, appIDs []int64) ([]Manager, []int64) {
	t.Helper()
	managers := make([]Manager, 0, len(appIDs))
	installIDs := make([]int64, 0, len(appIDs))
	for i, appID := range appIDs {
		installID := int64(1000 + i)
		atr := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/app/installations" {
				_ = json.NewEncoder(w).Encode([]github.Installation{{
					ID:      github.Ptr(installID),
					Account: &github.User{Login: github.Ptr(testOwner)},
				}})
				return
			}
			w.WriteHeader(http.StatusNotImplemented)
		}), appID)
		m, err := New(atr)
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		managers = append(managers, m)
		installIDs = append(installIDs, installID)
	}
	return managers, installIDs
}

func TestRoundRobinWithQuotaPicksMaxRemaining(t *testing.T) {
	ctx := context.Background()
	managers, installIDs := makeManagersWithDistinctInstalls(t, []int64{111, 222, 333})

	store := NewQuotaStore(time.Minute)
	// Make installIDs[1] the "best" by absolute remaining.
	store.Update(installIDs[0], 5000, 15000)
	store.Update(installIDs[1], 49000, 50000)
	store.Update(installIDs[2], 14000, 50000)

	rrm := NewRoundRobinWithQuota(managers, &QuotaConfig{Store: store, SoftFloor: 15000, HardFloor: 1500})

	// Run multiple times — capacity-aware path must always pick installIDs[1]
	// while the data is fresh, regardless of the atomic counter.
	for i := range 5 {
		_, id, err := rrm.Get(ctx, testOwner, testOwner+"/repo", "ident")
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if id != installIDs[1] {
			t.Errorf("call %d: picked install %d, want %d (max remaining)", i, id, installIDs[1])
		}
	}
}

func TestRoundRobinWithQuotaColdStartFallsBack(t *testing.T) {
	ctx := context.Background()
	managers, installIDs := makeManagersWithDistinctInstalls(t, []int64{111, 222, 333})

	store := NewQuotaStore(time.Minute)
	rrm := NewRoundRobinWithQuota(managers, &QuotaConfig{Store: store, SoftFloor: 15000, HardFloor: 1500})

	// No quota data yet — must fall back to atomic round-robin and visit
	// every install across enough calls.
	seen := make(map[int64]bool)
	for range 12 {
		_, id, err := rrm.Get(ctx, testOwner, testOwner+"/repo", "ident")
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		seen[id] = true
	}
	for _, want := range installIDs {
		if !seen[want] {
			t.Errorf("install %d never picked: cold-start fallback must spread across all installs (seen=%v)", want, seen)
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
