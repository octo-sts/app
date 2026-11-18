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
	"slices"
	"strconv"
	"sync/atomic"
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

// stickyPoolMgr is a pool of installations, each on its own fake GitHub. Get
// always returns the first, as a quota pick or an unlucky round-robin step can.
type stickyPoolMgr struct {
	installs []ghinstall.Installation
}

func (m *stickyPoolMgr) Get(context.Context, string, string, string) (*ghinstallation.AppsTransport, int64, error) {
	return m.installs[0].Transport, m.installs[0].ID, nil
}

func (m *stickyPoolMgr) GetByInstallation(_ context.Context, _ string, id int64) (*ghinstallation.AppsTransport, int64, error) {
	for _, in := range m.installs {
		if in.ID == id {
			return in.Transport, id, nil
		}
	}
	return nil, 0, status.Errorf(codes.NotFound, "not found")
}

// GetAll lists the pool back to front, so the walk's own ordering is what
// the tests see.
func (m *stickyPoolMgr) GetAll(context.Context, string) ([]ghinstall.Installation, error) {
	out := slices.Clone(m.installs)
	slices.Reverse(out)
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
		otherReason = "other 422"
		failing     = "500"
	)
	for _, tc := range []struct {
		name string
		// installs answers the mint per installation, 1234 upwards; the
		// mapping starts at 1234.
		installs []string
		wantCode codes.Code
		wantMap  int64
		// wantMints is the mint requests per installation, in order, after
		// the exchange is sent twice.
		wantMints []int
	}{{
		name:      "moves the mapping to an installation that mints",
		installs:  []string{refused, refused, ""},
		wantCode:  codes.OK,
		wantMap:   1236,
		wantMints: []int{1, 1, 2},
	}, {
		name:      "keeps the mapping when every installation refuses, and does not walk again",
		installs:  []string{refused, refused},
		wantCode:  codes.PermissionDenied,
		wantMap:   1234,
		wantMints: []int{2, 1},
	}, {
		name:      "a failing installation ends the walk",
		installs:  []string{refused, failing, ""},
		wantCode:  codes.PermissionDenied,
		wantMap:   1234,
		wantMints: []int{2, 2, 0},
	}, {
		name:      "a rate-limited 422 is not a refusal",
		installs:  []string{rateLimited, ""},
		wantCode:  codes.PermissionDenied,
		wantMap:   1234,
		wantMints: []int{2, 0},
	}, {
		name:      "a 422 for another reason is not a refusal",
		installs:  []string{otherReason, ""},
		wantCode:  codes.PermissionDenied,
		wantMap:   1234,
		wantMints: []int{2, 0},
	}} {
		t.Run(tc.name, func(t *testing.T) {
			key := freshTPKey(t, "sticky-refused")
			// Cached, so the read costs no mint and every mint is the exchange's.
			trustPolicies.Add(key, "issuer: https://token.actions.githubusercontent.com\nsubject: foo\naudience: octosts\npermissions:\n  checks: write\n")
			orgIssuers.Add("org", absentOrgIssuerEntry())
			stickyKey := routekey.Key("org/repo", key.identity, "foo")
			t.Cleanup(func() {
				orgIssuers.Remove("org")
				staleOrgIssuers.Remove("org")
				repointMisses.Remove(stickyKey)
			})

			mints := make([]atomic.Int32, len(tc.installs))
			pool := make([]ghinstall.Installation, len(tc.installs))
			for i, answer := range tc.installs {
				id := int64(1234 + i)
				mux := http.NewServeMux()
				mux.HandleFunc("/app/installations/{id}/access_tokens", func(w http.ResponseWriter, r *http.Request) {
					// Each installation has its own GitHub, so a mint through
					// another installation's transport shows up here.
					if got := r.PathValue("id"); got != strconv.FormatInt(id, 10) {
						t.Errorf("installation %s minted on the transport of %d", got, id)
					}
					mints[i].Add(1)
					w.Header().Set("Content-Type", "application/json")
					switch answer {
					case rateLimited:
						w.Header().Set("Retry-After", "60")
						fallthrough
					case refused:
						w.WriteHeader(http.StatusUnprocessableEntity)
						_, _ = w.Write([]byte(`{"message":"There is at least one repository that does not exist or is not accessible to the parent installation."}`))
					case otherReason:
						w.WriteHeader(http.StatusUnprocessableEntity)
						_, _ = w.Write([]byte(`{"message":"The permissions requested are not granted to this installation."}`))
					case failing:
						w.WriteHeader(http.StatusInternalServerError)
					default:
						_ = json.NewEncoder(w).Encode(github.InstallationToken{
							Token:     new("token-" + r.PathValue("id")),
							ExpiresAt: &github.Timestamp{Time: time.Now().Add(10 * time.Minute)},
						})
					}
				})
				pool[i] = ghinstall.Installation{Transport: newAppsTransport(t, &fakeGitHub{mux: mux}), ID: id, AppID: id}
			}

			store := memory.New()
			ctx := exchangeContext(t, "foo")
			if err := store.Put(ctx, stickyKey, 1234, "org/repo", key.identity, "foo"); err != nil {
				t.Fatal(err)
			}
			s := &sts{
				router: ghinstall.NewOrgRouter(map[string]*ghinstall.OrgPool{
					"org": {M: &stickyPoolMgr{installs: pool}, AppCount: len(pool)},
				}),
				sticky: store,
			}

			for range 2 {
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
			}
			got := make([]int, len(mints))
			for i := range mints {
				got[i] = int(mints[i].Load())
			}
			if !slices.Equal(got, tc.wantMints) {
				t.Errorf("mints per installation after two exchanges = %v, want %v", got, tc.wantMints)
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
	pool := &ghinstall.OrgPool{M: &stickyPoolMgr{installs: []ghinstall.Installation{{ID: 1234}, {ID: 1235}}}, AppCount: 2}
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
