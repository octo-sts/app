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
	"github.com/google/go-github/v75/github"
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

	gotATR, gotID, err := mgr.Get(ctx, "my-org")
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
	if _, _, err := mgr.Get(ctx, "cached-org"); err != nil {
		t.Fatalf("Get() = %v", err)
	}
	if calls != 1 {
		t.Fatalf("API calls after first Get: got = %d, wanted = 1", calls)
	}

	// Second call should come from cache.
	_, gotID, err := mgr.Get(ctx, "cached-org")
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

	_, _, err = mgr.Get(ctx, "missing-org")
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

func TestRoundRobin(t *testing.T) {
	ctx := context.Background()
	installID := int64(42)
	appIDs := []int64{12345678, 87654321}

	// Create two managers backed by different app transports.
	var managers []Manager
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

	rr := NewRoundRobin(managers)

	// Call Get multiple times and verify we round-robin across app IDs.
	for i := range 4 {
		atr, gotID, err := rr.Get(ctx, "my-org")
		if err != nil {
			t.Fatalf("Get() call %d = %v", i, err)
		}
		if gotID != installID {
			t.Errorf("call %d: install ID: got = %d, wanted = %d", i, gotID, installID)
		}
		wantAppID := appIDs[(i+1)%len(appIDs)]
		if gotAppID := atr.AppID(); gotAppID != wantAppID {
			t.Errorf("call %d: app ID: got = %d, wanted = %d", i, gotAppID, wantAppID)
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
