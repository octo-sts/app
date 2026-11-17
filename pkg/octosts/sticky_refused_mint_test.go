// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package octosts

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"testing"
	"time"

	v1 "chainguard.dev/sdk/proto/platform/oidc/v1"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-jose/go-jose/v4"
	josejwt "github.com/go-jose/go-jose/v4/jwt"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/octo-sts/app/pkg/ghinstall"
	"github.com/octo-sts/app/pkg/provider"
	"github.com/octo-sts/app/pkg/routekey"
	"github.com/octo-sts/app/pkg/stickystore/memory"
)

func TestDropSticky(t *testing.T) {
	ctx := context.Background()
	key := routekey.Key("org/repo", "id", "subj")
	seeded := func(t *testing.T) *memory.Store {
		t.Helper()
		store := memory.New()
		if err := store.Put(ctx, key, 1234, "org/repo", "id", "subj"); err != nil {
			t.Fatal(err)
		}
		return store
	}
	mapped := func(t *testing.T, store *memory.Store) (int64, bool) {
		t.Helper()
		id, ok, err := store.Get(ctx, key)
		if err != nil {
			t.Fatal(err)
		}
		return id, ok
	}

	t.Run("drops the mapping to the refused installation", func(t *testing.T) {
		store := seeded(t)
		(&sts{sticky: store}).dropSticky(ctx, "org/repo", "id", "subj", true, 1234)
		if _, ok := mapped(t, store); ok {
			t.Fatal("mapping to the refused installation was kept")
		}
	})

	t.Run("keeps a mapping to another installation", func(t *testing.T) {
		store := seeded(t)
		(&sts{sticky: store}).dropSticky(ctx, "org/repo", "id", "subj", true, 999)
		if id, ok := mapped(t, store); !ok || id != 1234 {
			t.Fatalf("mapping = (%d, %v), want (1234, true): a reassignment must not be dropped", id, ok)
		}
	})

	t.Run("ignores exchanges that are not sticky-routed", func(t *testing.T) {
		store := seeded(t)
		(&sts{sticky: store}).dropSticky(ctx, "org/repo", "id", "subj", false, 1234)
		if _, ok := mapped(t, store); !ok {
			t.Fatal("mapping dropped for a policy without checks:write")
		}
		(&sts{}).dropSticky(ctx, "org/repo", "id", "subj", true, 1234)
	})
}

// TestExchangeRefusedMintDropsSticky covers #1907 end to end: a checks:write
// exchange routed by the sticky store to an installation GitHub refuses a
// token for must not leave that mapping behind.
func TestExchangeRefusedMintDropsSticky(t *testing.T) {
	key := freshTPKey(t, "sticky-refused")
	// Cached, so the read costs no mint and the refusal is the exchange's.
	trustPolicies.Add(key, "issuer: https://token.actions.githubusercontent.com\nsubject: foo\naudience: octosts\npermissions:\n  checks: write\n")
	orgIssuers.Add("org", absentOrgIssuerEntry())
	t.Cleanup(func() {
		orgIssuers.Remove("org")
		staleOrgIssuers.Remove("org")
	})

	mux := http.NewServeMux()
	mux.HandleFunc("/app/installations/{appID}/access_tokens", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnprocessableEntity)
		_, _ = w.Write([]byte(`{"message":"There is at least one repository that does not exist or is not accessible to the parent installation."}`))
	})
	atr := newAppsTransport(t, &fakeGitHub{mux: mux})

	pk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("cannot generate RSA key %v", err)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: pk}, nil)
	if err != nil {
		t.Fatalf("jose.NewSigner() = %v", err)
	}
	iss := "https://token.actions.githubusercontent.com"
	token, err := josejwt.Signed(signer).Claims(josejwt.Claims{
		Subject:  "foo",
		Issuer:   iss,
		Audience: josejwt.Audience{"octosts"},
		Expiry:   josejwt.NewNumericDate(time.Now().Add(10 * time.Minute)),
	}).Serialize()
	if err != nil {
		t.Fatalf("CompactSerialize failed: %v", err)
	}
	provider.AddTestKeySetVerifier(t, iss, &oidc.StaticKeySet{PublicKeys: []crypto.PublicKey{pk.Public()}})
	ctx := metadata.NewIncomingContext(context.Background(), metadata.MD{"authorization": []string{"Bearer " + token}})

	store := memory.New()
	stickyKey := routekey.Key("org/repo", key.identity, "foo")
	if err := store.Put(ctx, stickyKey, 1234, "org/repo", key.identity, "foo"); err != nil {
		t.Fatal(err)
	}
	pool := &ghinstall.OrgPool{M: &fakeInstallMgr{atr: atr}, AppCount: 1}
	s := &sts{
		router: ghinstall.NewOrgRouter(map[string]*ghinstall.OrgPool{"org": pool}),
		sticky: store,
	}

	_, err = s.Exchange(ctx, &v1.ExchangeRequest{Identity: key.identity, Scopes: []string{"org/repo"}})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("Exchange = %v, want PermissionDenied", err)
	}
	if _, ok, err := store.Get(ctx, stickyKey); err != nil || ok {
		t.Fatalf("sticky mapping after the refused mint = (ok %v, err %v), want dropped", ok, err)
	}
}
