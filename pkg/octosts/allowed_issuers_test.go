// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package octosts

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	v1 "chainguard.dev/sdk/proto/platform/oidc/v1"
	"github.com/go-jose/go-jose/v4"
	josejwt "github.com/go-jose/go-jose/v4/jwt"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func TestIssuerAllowed(t *testing.T) {
	const gh = "https://token.actions.githubusercontent.com"

	for _, tc := range []struct {
		name    string
		allowed []string
		issuer  string
		want    bool
	}{{
		name:   "empty allowlist permits any issuer",
		issuer: "https://example.com",
		want:   true,
	}, {
		name:    "listed issuer is permitted",
		allowed: []string{gh, "https://accounts.example.com"},
		issuer:  "https://accounts.example.com",
		want:    true,
	}, {
		name:    "unlisted issuer is refused",
		allowed: []string{gh},
		issuer:  "https://example.com",
		want:    false,
	}, {
		// Matching is exact, matching the org-level issuers list, where a
		// trailing slash likewise makes a different issuer.
		name:    "trailing slash is a different issuer",
		allowed: []string{gh},
		issuer:  gh + "/",
		want:    false,
	}, {
		name:    "suffix of a listed issuer is refused",
		allowed: []string{gh},
		issuer:  gh + ".example.com",
		want:    false,
	}} {
		t.Run(tc.name, func(t *testing.T) {
			s := &sts{allowedIssuers: tc.allowed}
			if got := s.issuerAllowed(tc.issuer); got != tc.want {
				t.Errorf("issuerAllowed(%q) = %t, wanted %t", tc.issuer, got, tc.want)
			}
		})
	}
}

// TestExchangeChecksAllowlistBeforeDiscovery pins the ordering that gives the
// allowlist its value: a refused issuer must never be contacted. The issuer
// here is a server we control, so any request reaching it is a discovery the
// allowlist was meant to prevent.
func TestExchangeChecksAllowlistBeforeDiscovery(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)

	ctx := metadata.NewIncomingContext(context.Background(), metadata.MD{
		"authorization": []string{"Bearer " + signedTokenForIssuer(t, srv.URL)},
	})

	s := &sts{allowedIssuers: []string{"https://token.actions.githubusercontent.com"}}
	_, err := s.Exchange(ctx, &v1.ExchangeRequest{Identity: "foo", Scope: "org/repo"})
	if err == nil {
		t.Fatal("Exchange() succeeded, wanted a refusal")
	}
	if got := status.Code(err); got != codes.InvalidArgument {
		t.Errorf("Exchange() code = %v, wanted %v", got, codes.InvalidArgument)
	}
	if got := hits.Load(); got != 0 {
		t.Errorf("issuer received %d requests, wanted 0: discovery ran before the allowlist check", got)
	}
}

// TestExchangeWithoutAllowlistPerformsDiscovery is the counterpart: with no
// allowlist configured the issuer is still contacted, so the new check cannot
// change what an existing deployment does.
func TestExchangeWithoutAllowlistPerformsDiscovery(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)

	ctx := metadata.NewIncomingContext(context.Background(), metadata.MD{
		"authorization": []string{"Bearer " + signedTokenForIssuer(t, srv.URL)},
	})

	s := &sts{}
	if _, err := s.Exchange(ctx, &v1.ExchangeRequest{Identity: "foo", Scope: "org/repo"}); err == nil {
		t.Fatal("Exchange() succeeded, wanted discovery against the stub to fail")
	}
	if hits.Load() == 0 {
		t.Error("issuer received no requests, wanted discovery to be attempted")
	}
}

func signedTokenForIssuer(t *testing.T, issuer string) string {
	t.Helper()

	pk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() = %v", err)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: pk}, nil)
	if err != nil {
		t.Fatalf("jose.NewSigner() = %v", err)
	}
	token, err := josejwt.Signed(signer).Claims(josejwt.Claims{
		Subject:  "foo",
		Issuer:   issuer,
		Audience: josejwt.Audience{"octosts"},
		Expiry:   josejwt.NewNumericDate(time.Now().Add(10 * time.Minute)),
	}).Serialize()
	if err != nil {
		t.Fatalf("Serialize() = %v", err)
	}
	return token
}
