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
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bradleyfalzon/ghinstallation/v2"
	jwt "github.com/golang-jwt/jwt/v4"
	"github.com/google/go-github/v88/github"
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
	// NOT always return the same app.
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

func TestGetNotFoundCached(t *testing.T) {
	ctx := context.Background()
	calls := 0

	atr := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/app/installations":
			calls++
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

	// First call: should hit GitHub API and get NotFound.
	_, _, err = mgr.Get(ctx, "missing-org", "missing-org/repo", "my-identity")
	if err == nil {
		t.Fatal("expected error on first call, got nil")
	}
	st, ok := status.FromError(err)
	if !ok || st.Code() != codes.NotFound {
		t.Fatalf("expected gRPC NotFound, got %v", err)
	}
	if calls != 1 {
		t.Fatalf("API calls after first Get: got = %d, wanted = 1", calls)
	}

	// Second call: should be served from negative cache, no API call.
	_, _, err = mgr.Get(ctx, "missing-org", "missing-org/repo", "my-identity")
	if err == nil {
		t.Fatal("expected error on second call, got nil")
	}
	st, ok = status.FromError(err)
	if !ok || st.Code() != codes.NotFound {
		t.Fatalf("expected gRPC NotFound, got %v", err)
	}
	if calls != 1 {
		t.Errorf("API calls after second Get: got = %d, wanted = 1 (negative cache should prevent API call)", calls)
	}
}

func TestGetNotFoundCacheExpires(t *testing.T) {
	ctx := context.Background()
	calls := 0

	atr := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/app/installations":
			calls++
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

	mgr, err := NewWithNegativeTTL(atr, 50*time.Millisecond)
	if err != nil {
		t.Fatalf("NewWithNegativeTTL() = %v", err)
	}

	// First call: populates negative cache.
	_, _, err = mgr.Get(ctx, "missing-org", "missing-org/repo", "my-identity")
	if err == nil {
		t.Fatal("expected error on first call, got nil")
	}
	if calls != 1 {
		t.Fatalf("API calls after first Get: got = %d, wanted = 1", calls)
	}

	// Second call: served from negative cache.
	_, _, _ = mgr.Get(ctx, "missing-org", "missing-org/repo", "my-identity")
	if calls != 1 {
		t.Fatalf("API calls after second Get: got = %d, wanted = 1", calls)
	}

	// Wait for TTL to expire.
	time.Sleep(100 * time.Millisecond)

	// Third call: negative cache expired, should hit API again.
	_, _, _ = mgr.Get(ctx, "missing-org", "missing-org/repo", "my-identity")
	if calls != 2 {
		t.Errorf("API calls after TTL expiry: got = %d, wanted = 2", calls)
	}
}

func TestRoundRobinNotFoundCached(t *testing.T) {
	ctx := context.Background()
	appIDs := []int64{12345678, 87654321}
	callsByApp := map[int64]int{}

	managers := make([]Manager, 0, len(appIDs))
	for _, appID := range appIDs {
		calls := &callsByApp
		id := appID
		atr := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/app/installations":
				(*calls)[id]++
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

	// First call: both apps should be checked (primary miss + fallback).
	_, _, err := rr.Get(ctx, "missing-org", "missing-org/repo", "my-identity")
	if err == nil {
		t.Fatal("expected error on first call, got nil")
	}
	firstTotal := 0
	for _, c := range callsByApp {
		firstTotal += c
	}

	// Second call: negative cache should prevent any new API calls.
	_, _, err = rr.Get(ctx, "missing-org", "missing-org/repo", "my-identity")
	if err == nil {
		t.Fatal("expected error on second call, got nil")
	}
	secondTotal := 0
	for _, c := range callsByApp {
		secondTotal += c
	}
	if secondTotal != firstTotal {
		t.Errorf("API calls increased from %d to %d on second round-robin Get (negative cache should prevent new calls)", firstTotal, secondTotal)
	}
}

func TestGetWithBaseURL(t *testing.T) {
	ctx := context.Background()
	installID := int64(42)

	var calledPath string
	atr := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calledPath = r.URL.Path
		switch {
		case strings.HasSuffix(r.URL.Path, "/app/installations"):
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

	// Use the test server URL as the enterprise base URL.
	mgr, err := NewWithBaseURL(atr, atr.BaseURL)
	if err != nil {
		t.Fatalf("NewWithBaseURL() = %v", err)
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
	// Verify the enterprise URL path was used (go-github prepends /api/v3).
	if !strings.Contains(calledPath, "app/installations") {
		t.Errorf("expected app/installations in path, got %s", calledPath)
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

func TestManagerGetAll(t *testing.T) {
	// A single-app manager returns exactly one installation for an owner it
	// serves, and an empty slice (not an error) for one it does not.
	const installID = int64(1234)
	atr := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/app/installations" {
			_ = json.NewEncoder(w).Encode([]github.Installation{{
				ID:      github.Ptr(installID),
				Account: &github.User{Login: github.Ptr("org")},
			}})
			return
		}
		w.WriteHeader(http.StatusNotImplemented)
	}))
	m, err := New(atr)
	if err != nil {
		t.Fatalf("New() = %v", err)
	}

	got, err := m.GetAll(context.Background(), "org")
	if err != nil {
		t.Fatalf("GetAll(org) = %v, want nil", err)
	}
	if len(got) != 1 {
		t.Fatalf("GetAll(org) returned %d installations, want 1", len(got))
	}
	if got[0].ID != installID {
		t.Errorf("ID = %d, want %d", got[0].ID, installID)
	}
	if got[0].Transport == nil {
		t.Error("Transport = nil, want the app transport")
	}
	if got[0].AppID != atr.AppID() {
		t.Errorf("AppID = %d, want %d", got[0].AppID, atr.AppID())
	}

	// Not installed is an empty result, not an error: the caller distinguishes
	// "no installations" from "could not enumerate".
	none, err := m.GetAll(context.Background(), "other-org")
	if err != nil {
		t.Fatalf("GetAll(other-org) = %v, want nil", err)
	}
	if len(none) != 0 {
		t.Errorf("GetAll(other-org) returned %d installations, want 0", len(none))
	}
}

// TestManagerGetAllPropagatesFailure is the half of the not-installed-vs-
// enumeration-failed distinction that TestManagerGetAll's "other-org" case
// does not cover: when the API call itself fails (as opposed to cleanly
// reporting no matching installation), GetAll must surface that as an error,
// not silently collapse it to the same empty-slice-no-error result as
// not-installed. A refactor that lost this distinction would still pass
// every other GetAll test in this file.
func TestManagerGetAllPropagatesFailure(t *testing.T) {
	atr := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/app/installations" {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNotImplemented)
	}))
	m, err := New(atr)
	if err != nil {
		t.Fatalf("New() = %v", err)
	}

	got, err := m.GetAll(context.Background(), "org")
	if err == nil {
		t.Fatal("GetAll() = nil error, want an error when the API call fails")
	}
	if st, ok := status.FromError(err); !ok || st.Code() == codes.NotFound {
		t.Errorf("GetAll() code = %v, want anything but NotFound (that would be indistinguishable from not-installed)", err)
	}
	if len(got) != 0 {
		t.Errorf("GetAll() returned %d installations, want 0", len(got))
	}
}

// stubManager is a Manager returning fixed results, for roundRobin tests.
type stubManager struct {
	installs []Installation
	err      error

	// freshInstalls / freshErr are what GetAllFresh returns, full stop. They are
	// deliberately NOT defaulted to installs / err: a test that means "the fresh
	// enumeration sees nothing" must be able to say so and get nothing, rather
	// than silently falling back to installs and passing vacuously. Set them to
	// a superset of installs to model an App that the negative cache hides from
	// GetAll but not from GetAllFresh.
	freshInstalls []Installation
	freshErr      error
}

func (s *stubManager) Get(_ context.Context, _, _, _ string) (*ghinstallation.AppsTransport, int64, error) {
	if len(s.installs) == 0 {
		return nil, 0, status.Error(codes.NotFound, "not installed")
	}
	return s.installs[0].Transport, s.installs[0].ID, nil
}

func (s *stubManager) GetByInstallation(_ context.Context, _ string, id int64) (*ghinstallation.AppsTransport, int64, error) {
	for _, in := range s.installs {
		if in.ID == id {
			return in.Transport, in.ID, nil
		}
	}
	return nil, 0, status.Error(codes.NotFound, "not found")
}

func (s *stubManager) GetAll(_ context.Context, _ string) ([]Installation, error) {
	return s.installs, s.err
}

func (s *stubManager) GetAllFresh(_ context.Context, _ string) ([]Installation, error) {
	return s.freshInstalls, s.freshErr
}

var _ Manager = (*stubManager)(nil)

func TestRoundRobinGetAll(t *testing.T) {
	t.Run("concatenates and dedups", func(t *testing.T) {
		rr := NewRoundRobin([]Manager{
			&stubManager{installs: []Installation{{ID: 1, AppID: 10}}},
			&stubManager{installs: []Installation{{ID: 2, AppID: 20}}},
			// A duplicate installation ID must appear once.
			&stubManager{installs: []Installation{{ID: 1, AppID: 10}}},
		})
		got, err := rr.GetAll(context.Background(), "org")
		if err != nil {
			t.Fatalf("GetAll() = %v, want nil", err)
		}
		if len(got) != 2 {
			t.Fatalf("GetAll() returned %d installations, want 2 (deduped)", len(got))
		}
		if got[0].ID != 1 || got[1].ID != 2 {
			t.Errorf("GetAll() = %v, want stable order [1 2]", []int64{got[0].ID, got[1].ID})
		}
	})

	t.Run("partial enumeration reports an error", func(t *testing.T) {
		// A caller that must reason about ALL installations cannot treat a
		// partial list as exhaustive, so the error is surfaced alongside it.
		rr := NewRoundRobin([]Manager{
			&stubManager{installs: []Installation{{ID: 1, AppID: 10}}},
			&stubManager{err: errors.New("api down")},
		})
		got, err := rr.GetAll(context.Background(), "org")
		if err == nil {
			t.Fatal("GetAll() = nil error, want an error for a partial enumeration")
		}
		if len(got) != 1 {
			t.Errorf("GetAll() returned %d installations, want the 1 that succeeded", len(got))
		}
	})

	t.Run("no App serves the owner", func(t *testing.T) {
		// Aggregate-only check: when every sub-manager's GetAll already
		// reports (nil, nil) — as stubManager's zero value does directly,
		// with no translation involved — the aggregate must still be a clean
		// "no installations", not an error. This does NOT exercise the real
		// manager.Get-returns-NotFound-so-manager.GetAll-translates-it path;
		// see TestRoundRobinGetAllWithRealManagers for that.
		rr := NewRoundRobin([]Manager{
			&stubManager{},
			&stubManager{},
		})
		got, err := rr.GetAll(context.Background(), "org")
		if err != nil {
			t.Fatalf("GetAll() = %v, want nil", err)
		}
		if len(got) != 0 {
			t.Errorf("GetAll() returned %d installations, want 0", len(got))
		}
	})

	t.Run("all managers fail", func(t *testing.T) {
		// Companion to the case above: when every manager fails to enumerate
		// (as opposed to cleanly reporting not-installed), the result must be
		// empty AND carry a non-nil error, so the caller can tell "definitely
		// no installations" apart from "enumeration itself failed".
		rr := NewRoundRobin([]Manager{
			&stubManager{err: errors.New("api down")},
			&stubManager{err: errors.New("also api down")},
		})
		got, err := rr.GetAll(context.Background(), "org")
		if err == nil {
			t.Fatal("GetAll() = nil error, want an error when every manager fails")
		}
		if len(got) != 0 {
			t.Errorf("GetAll() returned %d installations, want 0", len(got))
		}
	})

	t.Run("a sub-manager returns installs and an error", func(t *testing.T) {
		// Regression test for the bug where GetAll discarded a sub-manager's
		// installations as soon as it also returned an error. Unreachable via
		// manager today (it is strictly either/or), but the interface
		// contract promises errors don't imply an empty slice, so a stub
		// exercising a manager that returns both must still contribute its
		// installs to the aggregate.
		rr := NewRoundRobin([]Manager{
			&stubManager{installs: []Installation{{ID: 1, AppID: 10}}},
			&stubManager{installs: []Installation{{ID: 2, AppID: 20}}, err: errors.New("partial failure")},
		})
		got, err := rr.GetAll(context.Background(), "org")
		if err == nil {
			t.Fatal("GetAll() = nil error, want an error since one manager failed")
		}
		if len(got) != 2 {
			t.Fatalf("GetAll() returned %d installations, want 2 (the failing manager's installs must still be collected)", len(got))
		}
		ids := map[int64]bool{got[0].ID: true, got[1].ID: true}
		if !ids[1] || !ids[2] {
			t.Errorf("GetAll() = %v, want installations [1 2]", got)
		}
	})
}

// TestRoundRobinGetAllWithRealManagers is the one that matters: it uses real
// managers, not stubs, so it exercises the actual enumeration path a
// multi-app deployment takes.
func TestRoundRobinGetAllWithRealManagers(t *testing.T) {
	managers, installIDs := makeManagersWithDistinctInstalls(t, []int64{111, 222, 333})
	rr := NewRoundRobin(managers)

	got, err := rr.GetAll(context.Background(), testOwner)
	if err != nil {
		t.Fatalf("GetAll() = %v, want nil", err)
	}
	if len(got) != len(installIDs) {
		t.Fatalf("GetAll() returned %d installations, want %d", len(got), len(installIDs))
	}
	for i, in := range got {
		if in.ID != installIDs[i] {
			t.Errorf("[%d] ID = %d, want %d", i, in.ID, installIDs[i])
		}
		if in.Transport == nil {
			t.Errorf("[%d] Transport = nil", i)
		}
	}

	// The literal allow-all trigger, end to end: no App serves this owner, so
	// every real manager.Get returns NotFound, every manager.GetAll translates
	// that to an empty error-free result, and the aggregate must be a clean
	// "no installations" rather than an error. A caller that treats an error
	// as "no allowlist applies" would be disabling the control on a failure.
	none, err := rr.GetAll(context.Background(), "nobody-serves-this-org")
	if err != nil {
		t.Fatalf("GetAll(unserved owner) = %v, want nil — an unserved owner is not an error", err)
	}
	if len(none) != 0 {
		t.Errorf("GetAll(unserved owner) returned %d installations, want 0", len(none))
	}
}

// TestManagerGetAllFreshBypassesNegativeCache is the regression test for the
// window this whole change exists to close.
//
// Sequence: the App is not installed, so a Get arms the negative cache. The App
// is then installed. GetAll still reports nothing — with a NIL error, because
// manager.GetAll maps NotFound to (nil, nil) — which is exactly what would let a
// caller conclude "no installation can see this" and grant allow-all.
// GetAllFresh must see the truth.
func TestManagerGetAllFreshBypassesNegativeCache(t *testing.T) {
	const installID = int64(4321)
	var installed atomic.Bool

	atr := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/app/installations" {
			if !installed.Load() {
				_ = json.NewEncoder(w).Encode([]github.Installation{})
				return
			}
			_ = json.NewEncoder(w).Encode([]github.Installation{{
				ID:      github.Ptr(installID),
				Account: &github.User{Login: github.Ptr("org")},
			}})
			return
		}
		w.WriteHeader(http.StatusNotImplemented)
	}))
	m, err := New(atr)
	if err != nil {
		t.Fatalf("New() = %v", err)
	}

	// Arm the negative cache the way ordinary routing traffic does.
	if _, _, err := m.Get(context.Background(), "org", "", ""); err == nil {
		t.Fatal("Get() = nil error, want NotFound before the App is installed")
	}

	installed.Store(true)

	// GetAll is still blind, and reports no error while being blind.
	stale, err := m.GetAll(context.Background(), "org")
	if err != nil {
		t.Fatalf("GetAll() = %v, want nil (a negative-cache hit is not an error)", err)
	}
	if len(stale) != 0 {
		t.Fatalf("GetAll() returned %d installations; this test is vacuous unless the negative cache hides the install", len(stale))
	}

	// GetAllFresh must not be fooled.
	fresh, err := m.GetAllFresh(context.Background(), "org")
	if err != nil {
		t.Fatalf("GetAllFresh() = %v, want nil", err)
	}
	if len(fresh) != 1 {
		t.Fatalf("GetAllFresh() returned %d installations, want 1 — the negative cache must not hide a real install", len(fresh))
	}
	if fresh[0].ID != installID {
		t.Errorf("ID = %d, want %d", fresh[0].ID, installID)
	}
	if fresh[0].AppID != atr.AppID() {
		t.Errorf("AppID = %d, want %d", fresh[0].AppID, atr.AppID())
	}
	if fresh[0].Transport == nil {
		t.Error("Transport = nil, want the app transport")
	}

	// Get checks the negative cache BEFORE the positive one, so discovering the
	// installation without clearing the negative entry would fix enforcement
	// while leaving routing broken for the rest of the TTL.
	if _, id, err := m.Get(context.Background(), "org", "", ""); err != nil {
		t.Errorf("Get() = %v, want the installation GetAllFresh just confirmed exists", err)
	} else if id != installID {
		t.Errorf("Get() id = %d, want %d", id, installID)
	}
}

// TestManagerGetAllFreshUsesPositiveCache pins that the confirm path is cheap
// once warm: GetAllFresh skips only the NEGATIVE cache. A stale positive entry
// yields a superset, which is the conservative direction for a caller deciding
// whether NO installation can see something.
func TestManagerGetAllFreshUsesPositiveCache(t *testing.T) {
	const installID = int64(99)
	var listCalls atomic.Int32

	atr := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/app/installations" {
			listCalls.Add(1)
			_ = json.NewEncoder(w).Encode([]github.Installation{{
				ID:      github.Ptr(installID),
				Account: &github.User{Login: github.Ptr("org")},
			}})
			return
		}
		w.WriteHeader(http.StatusNotImplemented)
	}))
	m, err := New(atr)
	if err != nil {
		t.Fatalf("New() = %v", err)
	}

	if _, _, err := m.Get(context.Background(), "org", "", ""); err != nil {
		t.Fatalf("Get() = %v", err)
	}
	before := listCalls.Load()

	got, err := m.GetAllFresh(context.Background(), "org")
	if err != nil {
		t.Fatalf("GetAllFresh() = %v", err)
	}
	if len(got) != 1 || got[0].ID != installID {
		t.Fatalf("GetAllFresh() = %v, want the cached installation %d", got, installID)
	}
	if listCalls.Load() != before {
		t.Errorf("GetAllFresh() made %d extra ListInstallations calls, want 0 — the positive cache must still short-circuit", listCalls.Load()-before)
	}
}

// TestManagerGetAllFreshPropagatesFailure: a failed walk must not look like
// not-installed, or a caller would treat it as a complete answer.
func TestManagerGetAllFreshPropagatesFailure(t *testing.T) {
	atr := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/app/installations" {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNotImplemented)
	}))
	m, err := New(atr)
	if err != nil {
		t.Fatalf("New() = %v", err)
	}

	got, err := m.GetAllFresh(context.Background(), "org")
	if err == nil {
		t.Fatal("GetAllFresh() = nil error, want an error when the API call fails")
	}
	if st, ok := status.FromError(err); !ok || st.Code() == codes.NotFound {
		t.Errorf("GetAllFresh() code = %v, want anything but NotFound (that would be indistinguishable from not-installed)", err)
	}
	if len(got) != 0 {
		t.Errorf("GetAllFresh() returned %d installations, want 0", len(got))
	}
}

// TestManagerGetAllFreshNotInstalledArmsNegativeCache: a genuine miss must still
// leave a negative entry, or every confirm would pay a full walk.
func TestManagerGetAllFreshNotInstalledArmsNegativeCache(t *testing.T) {
	var listCalls atomic.Int32
	atr := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/app/installations" {
			listCalls.Add(1)
			_ = json.NewEncoder(w).Encode([]github.Installation{})
			return
		}
		w.WriteHeader(http.StatusNotImplemented)
	}))
	m, err := New(atr)
	if err != nil {
		t.Fatalf("New() = %v", err)
	}

	got, err := m.GetAllFresh(context.Background(), "org")
	if err != nil {
		t.Fatalf("GetAllFresh() = %v, want nil for a not-installed owner", err)
	}
	if len(got) != 0 {
		t.Fatalf("GetAllFresh() returned %d installations, want 0", len(got))
	}

	before := listCalls.Load()
	if _, _, err := m.Get(context.Background(), "org", "", ""); err == nil {
		t.Fatal("Get() = nil error, want NotFound")
	}
	if listCalls.Load() != before {
		t.Errorf("Get() made %d extra ListInstallations calls, want 0 — GetAllFresh must arm the negative cache on a genuine miss", listCalls.Load()-before)
	}
}

func TestRoundRobinGetAllFresh(t *testing.T) {
	t.Run("concatenates and dedups", func(t *testing.T) {
		rr := NewRoundRobin([]Manager{
			&stubManager{freshInstalls: []Installation{{ID: 1, AppID: 10}}},
			&stubManager{freshInstalls: []Installation{{ID: 2, AppID: 20}, {ID: 1, AppID: 10}}},
		})
		got, err := rr.GetAllFresh(context.Background(), "org")
		if err != nil {
			t.Fatalf("GetAllFresh() = %v, want nil", err)
		}
		if len(got) != 2 {
			t.Fatalf("GetAllFresh() returned %d installations, want 2 (deduped)", len(got))
		}
		if got[0].ID != 1 || got[1].ID != 2 {
			t.Errorf("GetAllFresh() = %v, want stable order [1 2]", []int64{got[0].ID, got[1].ID})
		}
	})

	t.Run("one manager failing yields a partial result AND an error", func(t *testing.T) {
		rr := NewRoundRobin([]Manager{
			&stubManager{freshInstalls: []Installation{{ID: 1, AppID: 10}}},
			&stubManager{freshErr: errors.New("boom")},
		})
		got, err := rr.GetAllFresh(context.Background(), "org")
		if err == nil {
			t.Fatal("GetAllFresh() = nil error, want an error for a partial enumeration")
		}
		if len(got) != 1 {
			t.Errorf("GetAllFresh() returned %d installations, want the 1 that succeeded", len(got))
		}
	})

	t.Run("an unserved owner is not an error", func(t *testing.T) {
		rr := NewRoundRobin([]Manager{&stubManager{}, &stubManager{}})
		got, err := rr.GetAllFresh(context.Background(), "org")
		if err != nil {
			t.Fatalf("GetAllFresh() = %v, want nil", err)
		}
		if len(got) != 0 {
			t.Errorf("GetAllFresh() returned %d installations, want 0", len(got))
		}
	})

	// GetAll and GetAllFresh share one aggregation helper, so this covers the
	// cancellation bail-out for both.
	t.Run("a cancelled context bails instead of collecting N identical errors", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		rr := NewRoundRobin([]Manager{
			&stubManager{freshInstalls: []Installation{{ID: 1, AppID: 10}}},
			&stubManager{freshInstalls: []Installation{{ID: 2, AppID: 20}}},
		})
		got, err := rr.GetAllFresh(ctx, "org")
		if err == nil {
			t.Fatal("GetAllFresh() = nil error, want the cancellation")
		}
		if len(got) != 0 {
			t.Errorf("GetAllFresh() returned %d installations, want 0 — it must bail before querying any manager", len(got))
		}
	})
}

// TestManagerGetAllFreshRepairsCoexistingCacheEntries pins the invariant that a
// positive cache entry implies no negative entry, on the positive-cache-HIT path
// specifically.
//
// The two entries can coexist in production: GetAllFresh writes the positive
// entry, then a concurrent Get whose walk STARTED before the install completes
// and arms the negative entry afterwards. Because Get checks the negative cache
// first, routing then returns NotFound for the rest of the TTL — and every later
// GetAllFresh short-circuits on the positive hit, so without an unconditional
// Remove there the state never self-heals.
//
// Racing to that interleaving would be flaky, so this test seeds the resulting
// state directly (it is an in-package test) and asserts the repair. It covers
// the state, not the schedule that produces it.
func TestManagerGetAllFreshRepairsCoexistingCacheEntries(t *testing.T) {
	const installID = int64(777)
	var listCalls atomic.Int32

	atr := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/app/installations" {
			listCalls.Add(1)
			_ = json.NewEncoder(w).Encode([]github.Installation{{
				ID:      github.Ptr(installID),
				Account: &github.User{Login: github.Ptr("org")},
			}})
			return
		}
		w.WriteHeader(http.StatusNotImplemented)
	}))
	mgr, err := New(atr)
	if err != nil {
		t.Fatalf("New() = %v", err)
	}
	m, ok := mgr.(*manager)
	if !ok {
		t.Fatalf("New() returned %T, want *manager", mgr)
	}

	// Seed the coexistence state a lost race would leave behind.
	key := m.cacheKey("org")
	m.cache.Add(key, installID)
	m.negativeCache.Add(key, true)

	// Sanity: routing really is broken in this state, so the repair below is
	// load-bearing rather than decorative.
	if _, _, err := m.Get(context.Background(), "org", "", ""); err == nil {
		t.Fatal("Get() = nil error; this test is vacuous unless the negative entry shadows the positive one")
	}

	before := listCalls.Load()
	got, err := m.GetAllFresh(context.Background(), "org")
	if err != nil {
		t.Fatalf("GetAllFresh() = %v, want nil", err)
	}
	if len(got) != 1 || got[0].ID != installID {
		t.Fatalf("GetAllFresh() = %v, want the cached installation %d", got, installID)
	}
	if listCalls.Load() != before {
		t.Errorf("GetAllFresh() made %d extra ListInstallations calls, want 0 — this must be the positive-cache-hit path", listCalls.Load()-before)
	}

	// The repair: routing recovers immediately instead of at TTL expiry.
	if _, id, err := m.Get(context.Background(), "org", "", ""); err != nil {
		t.Errorf("Get() = %v, want the installation — GetAllFresh must clear the negative entry on a positive-cache hit too", err)
	} else if id != installID {
		t.Errorf("Get() id = %d, want %d", id, installID)
	}
}
