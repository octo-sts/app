// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package octosts

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strconv"
	"sync"
	"testing"
	"time"

	v1 "chainguard.dev/sdk/proto/platform/oidc/v1"
	"github.com/bradleyfalzon/ghinstallation/v2"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-jose/go-jose/v4"
	josejwt "github.com/go-jose/go-jose/v4/jwt"
	"github.com/google/go-github/v88/github"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/octo-sts/app/pkg/ghinstall"
	"github.com/octo-sts/app/pkg/provider"
	"github.com/octo-sts/app/pkg/routekey"
	"github.com/octo-sts/app/pkg/stickystore/memory"
)

// stickyPoolMgr is a pool of installations on one fake GitHub. Get always
// returns the first, as a quota pick or an unlucky round-robin step can.
type stickyPoolMgr struct {
	atr *ghinstallation.AppsTransport
	ids []int64
}

func (m *stickyPoolMgr) Get(context.Context, string, string, string) (*ghinstallation.AppsTransport, int64, error) {
	return m.atr, m.ids[0], nil
}

func (m *stickyPoolMgr) GetByInstallation(_ context.Context, _ string, id int64) (*ghinstallation.AppsTransport, int64, error) {
	for _, known := range m.ids {
		if known == id {
			return m.atr, id, nil
		}
	}
	return nil, 0, status.Errorf(codes.NotFound, "not found")
}

func (m *stickyPoolMgr) GetAll(context.Context, string) ([]ghinstall.Installation, error) {
	out := make([]ghinstall.Installation, 0, len(m.ids))
	for _, id := range m.ids {
		out = append(out, ghinstall.Installation{Transport: m.atr, ID: id, AppID: m.atr.AppID()})
	}
	return out, nil
}

func (m *stickyPoolMgr) GetAllFresh(ctx context.Context, owner string) ([]ghinstall.Installation, error) {
	return m.GetAll(ctx, owner)
}

// TestExchangeRefusedMintRepointsSticky covers #1907 end to end: a
// checks:write exchange whose sticky installation GitHub refuses a token for.
func TestExchangeRefusedMintRepointsSticky(t *testing.T) {
	const (
		refused     = "refused"
		rateLimited = "rate-limited"
	)
	for _, tc := range []struct {
		name string
		// installs answers the mint per installation; the mapping starts at 1234.
		installs map[int64]string
		wantCode codes.Code
		wantMap  int64
		// wantMints is how many installations were asked for a token.
		wantMints int
	}{{
		name:      "moves the mapping to an installation that mints",
		installs:  map[int64]string{1234: refused, 1235: refused, 1236: ""},
		wantCode:  codes.OK,
		wantMap:   1236,
		wantMints: 3,
	}, {
		name:      "keeps the mapping when every installation refuses",
		installs:  map[int64]string{1234: refused, 1235: refused},
		wantCode:  codes.PermissionDenied,
		wantMap:   1234,
		wantMints: 2,
	}, {
		name:      "a rate-limited 422 is not a refusal",
		installs:  map[int64]string{1234: rateLimited, 1235: ""},
		wantCode:  codes.PermissionDenied,
		wantMap:   1234,
		wantMints: 1,
	}} {
		t.Run(tc.name, func(t *testing.T) {
			key := freshTPKey(t, "sticky-refused")
			// Cached, so the read costs no mint and every mint is the exchange's.
			trustPolicies.Add(key, "issuer: https://token.actions.githubusercontent.com\nsubject: foo\naudience: octosts\npermissions:\n  checks: write\n")
			orgIssuers.Add("org", absentOrgIssuerEntry())
			t.Cleanup(func() {
				orgIssuers.Remove("org")
				staleOrgIssuers.Remove("org")
			})

			var mu sync.Mutex
			asked := map[int64]bool{}
			mux := http.NewServeMux()
			mux.HandleFunc("/app/installations/{id}/access_tokens", func(w http.ResponseWriter, r *http.Request) {
				id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
				mu.Lock()
				asked[id] = true
				mu.Unlock()
				w.Header().Set("Content-Type", "application/json")
				switch tc.installs[id] {
				case rateLimited:
					w.Header().Set("Retry-After", "60")
					fallthrough
				case refused:
					w.WriteHeader(http.StatusUnprocessableEntity)
					_, _ = w.Write([]byte(`{"message":"There is at least one repository that does not exist or is not accessible to the parent installation."}`))
				default:
					_ = json.NewEncoder(w).Encode(github.InstallationToken{
						Token:     new("token-" + r.PathValue("id")),
						ExpiresAt: &github.Timestamp{Time: time.Now().Add(10 * time.Minute)},
					})
				}
			})
			atr := newAppsTransport(t, &fakeGitHub{mux: mux})

			ids := make([]int64, 0, len(tc.installs))
			for id := int64(1234); len(ids) < len(tc.installs); id++ {
				ids = append(ids, id)
			}
			store := memory.New()
			ctx := exchangeContext(t, "foo")
			stickyKey := routekey.Key("org/repo", key.identity, "foo")
			if err := store.Put(ctx, stickyKey, 1234, "org/repo", key.identity, "foo"); err != nil {
				t.Fatal(err)
			}
			pool := &ghinstall.OrgPool{M: &stickyPoolMgr{atr: atr, ids: ids}, AppCount: len(ids)}
			s := &sts{
				router: ghinstall.NewOrgRouter(map[string]*ghinstall.OrgPool{"org": pool}),
				sticky: store,
			}

			tok, err := s.Exchange(ctx, &v1.ExchangeRequest{Identity: key.identity, Scopes: []string{"org/repo"}})
			if status.Code(err) != tc.wantCode {
				t.Fatalf("Exchange = %v, want %v", err, tc.wantCode)
			}
			if want := "token-" + strconv.FormatInt(tc.wantMap, 10); err == nil && tok.Token != want {
				t.Errorf("token = %q, want %q", tok.Token, want)
			}
			if id, ok, err := store.Get(ctx, stickyKey); err != nil || !ok || id != tc.wantMap {
				t.Errorf("sticky mapping = (%d, %v, %v), want %d", id, ok, err, tc.wantMap)
			}
			if len(asked) != tc.wantMints {
				t.Errorf("installations asked for a token = %v, want %d", asked, tc.wantMints)
			}
		})
	}
}

// exchangeContext is an incoming context carrying a verifiable bearer token
// for subject.
func exchangeContext(t *testing.T, subject string) context.Context {
	t.Helper()
	pk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("cannot generate RSA key %v", err)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: pk}, nil)
	if err != nil {
		t.Fatalf("jose.NewSigner() = %v", err)
	}
	const iss = "https://token.actions.githubusercontent.com"
	token, err := josejwt.Signed(signer).Claims(josejwt.Claims{
		Subject:  subject,
		Issuer:   iss,
		Audience: josejwt.Audience{"octosts"},
		Expiry:   josejwt.NewNumericDate(time.Now().Add(10 * time.Minute)),
	}).Serialize()
	if err != nil {
		t.Fatalf("Serialize failed: %v", err)
	}
	provider.AddTestKeySetVerifier(t, iss, &oidc.StaticKeySet{PublicKeys: []crypto.PublicKey{pk.Public()}})
	return metadata.NewIncomingContext(context.Background(), metadata.MD{"authorization": []string{"Bearer " + token}})
}

// TestRepointStickyLeavesAlone: exchanges that are not sticky-routed by the
// unpinned path, and a mapping another exchange already moved.
func TestRepointStickyLeavesAlone(t *testing.T) {
	ctx := context.Background()
	checks := github.InstallationPermissions{Checks: new("write")}
	key := routekey.Key("org/repo", "id", "subj")
	minted := false
	mint := func(*ghinstallation.AppsTransport, int64) (string, error) {
		minted = true
		return "", errors.New("refused")
	}
	pool := &ghinstall.OrgPool{M: &stickyPoolMgr{ids: []int64{1234, 1235}}, AppCount: 2}
	router := ghinstall.NewOrgRouter(map[string]*ghinstall.OrgPool{"org": pool})

	for _, tc := range []struct {
		name   string
		tp     TrustPolicy
		sticky bool
		mapped int64
	}{
		{name: "no sticky store", tp: TrustPolicy{Permissions: checks}, mapped: 1234},
		{name: "no checks:write", tp: TrustPolicy{}, sticky: true, mapped: 1234},
		{name: "app pin", tp: TrustPolicy{Permissions: checks, App: "one"}, sticky: true, mapped: 1234},
		{name: "app_pattern pin", tp: TrustPolicy{Permissions: checks, appPattern: regexp.MustCompile("one")}, sticky: true, mapped: 1234},
		{name: "mapping already moved", tp: TrustPolicy{Permissions: checks}, sticky: true, mapped: 1235},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := memory.New()
			if err := store.Put(ctx, key, tc.mapped, "org/repo", "id", "subj"); err != nil {
				t.Fatal(err)
			}
			s := &sts{router: router}
			if tc.sticky {
				s.sticky = store
			}
			if _, _, ok := s.repointSticky(ctx, "org/repo", "id", "subj", &tc.tp, 1234, mint); ok {
				t.Error("repointSticky moved the exchange")
			}
			if minted {
				t.Error("minted on another installation")
			}
			if id, _, _ := store.Get(ctx, key); id != tc.mapped {
				t.Errorf("mapping = %d, want %d", id, tc.mapped)
			}
		})
	}
}
