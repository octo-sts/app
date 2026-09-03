// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package octosts

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"maps"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	v1 "chainguard.dev/sdk/proto/platform/oidc/v1"
	"github.com/bradleyfalzon/ghinstallation/v2"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-jose/go-jose/v4"
	josejwt "github.com/go-jose/go-jose/v4/jwt"
	jwt "github.com/golang-jwt/jwt/v4"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-github/v88/github"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/octo-sts/app/pkg/ghinstall"
	"github.com/octo-sts/app/pkg/provider"
	"github.com/octo-sts/app/pkg/routekey"
	"github.com/octo-sts/app/pkg/stickystore"
	"github.com/octo-sts/app/pkg/stickystore/memory"
)

type fakeInstallMgr struct {
	atr *ghinstallation.AppsTransport
}

func (f *fakeInstallMgr) Get(_ context.Context, _, _, _ string) (*ghinstallation.AppsTransport, int64, error) {
	return f.atr, 1234, nil
}

func (f *fakeInstallMgr) GetByInstallation(_ context.Context, _ string, id int64) (*ghinstallation.AppsTransport, int64, error) {
	if id == 1234 {
		return f.atr, 1234, nil
	}
	return nil, 0, status.Errorf(codes.NotFound, "not found")
}

func (f *fakeInstallMgr) GetAll(_ context.Context, _ string) ([]ghinstall.Installation, error) {
	return []ghinstall.Installation{{Transport: f.atr, ID: 1234, AppID: f.atr.AppID()}}, nil
}

// GetAllFresh delegates: these tests exercise routing, not cache freshness.
func (f *fakeInstallMgr) GetAllFresh(ctx context.Context, owner string) ([]ghinstall.Installation, error) {
	return f.GetAll(ctx, owner)
}

var _ ghinstall.Manager = (*fakeInstallMgr)(nil)

type fakeGitHub struct {
	mux *http.ServeMux
}

func newFakeGitHub() *fakeGitHub {
	mux := http.NewServeMux()
	mux.HandleFunc("/app/installations", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode([]github.Installation{{
			ID: github.Ptr(int64(1234)),
			Account: &github.User{
				Login: github.Ptr("org"),
			},
		}})
	})
	mux.HandleFunc("/app/installations/{appID}/access_tokens", func(w http.ResponseWriter, r *http.Request) {
		b, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		json.NewEncoder(w).Encode(github.InstallationToken{
			Token:     github.Ptr(base64.StdEncoding.EncodeToString(b)),
			ExpiresAt: &github.Timestamp{Time: time.Now().Add(10 * time.Minute)},
		})
	})
	mux.HandleFunc("/repos/{org}/{repo}/contents/.github/chainguard/{identity}", func(w http.ResponseWriter, r *http.Request) {
		// Sentinel: owner "orgdir" always resolves the trusted-issuers path to
		// a directory rather than a file. go-github distinguishes the two by
		// response shape — a single JSON object is a file, a JSON array is a
		// directory listing — so this is the only way to make GetContents
		// return a nil *RepositoryContent without an actual directory on disk.
		// A real testdata directory would hit os.ReadFile's EISDIR below, which
		// is not os.IsNotExist and would fall into the 500 branch instead.
		if r.PathValue("org") == "orgdir" && r.PathValue("identity") == "trusted-token-issuers.yaml" {
			json.NewEncoder(w).Encode([]*github.RepositoryContent{
				{Type: github.Ptr("file"), Name: github.Ptr("placeholder")},
			})
			return
		}

		b, err := os.ReadFile(filepath.Join("testdata", r.PathValue("org"), r.PathValue("repo"), r.PathValue("identity")))
		if err != nil {
			// A missing fixture is a 404, matching real GitHub. The previous
			// 500 (which also fell through to write a body) made the
			// file-absent path indistinguishable from a server error.
			if os.IsNotExist(err) {
				writeGitHubNotFound(w)
				return
			}
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintf(io.MultiWriter(w, os.Stdout), "ReadFile failed: %v\n", err)
			return
		}
		json.NewEncoder(w).Encode(github.RepositoryContent{
			Content:  github.Ptr(base64.StdEncoding.EncodeToString(b)),
			Type:     github.Ptr("file"),
			Encoding: github.Ptr("base64"),
		})
	})
	// Revoke() posts to this path, but it does NOT reach this fake. Revoke's URL
	// follows the configured baseURL, which is empty in these tests, so it
	// resolves to https://api.github.com/installation/token; and it sends via
	// http.DefaultClient rather than the injected transport, so every revoke in
	// tests escapes to real GitHub and 401s. Callers only log that warning, so
	// nothing fails. This route is here so the fake is already correct if Revoke
	// is ever pointed at the fake. The same dead route already exists in
	// newFakeGitHubNotFoundCounter.
	mux.HandleFunc("/installation/token", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotImplemented)
		fmt.Fprintf(io.MultiWriter(w, os.Stdout), "%s %s not implemented\n", r.Method, r.URL.Path)
	})

	return &fakeGitHub{
		mux: mux,
	}
}

// writeGitHubNotFound writes a 404 shaped like a real GitHub error response, so
// go-github produces a *github.ErrorResponse whose Response.StatusCode is 404.
//
// The status comes from WriteHeader, not from the body: go-github's
// CheckResponse builds ErrorResponse{Response: r} from the real *http.Response
// and unmarshals only Message/Errors/Block/DocumentationURL out of the body.
// ErrorResponse.Response is tagged json:"-", so setting it here would be inert
// — hence only Message is encoded.
func writeGitHubNotFound(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotFound)
	json.NewEncoder(w).Encode(github.ErrorResponse{Message: "Not Found"})
}

func (f *fakeGitHub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mux.ServeHTTP(w, r)
}

// newFakeGitHubNoContents returns a fake GitHub server that handles
// installations and access_tokens but returns 404 for all content requests.
// Used to isolate orgs in the multi-org routing tests.
func newFakeGitHubNoContents() *fakeGitHub {
	mux := http.NewServeMux()
	mux.HandleFunc("/app/installations", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode([]github.Installation{{
			ID:      github.Ptr(int64(1234)),
			Account: &github.User{Login: github.Ptr("other-org")},
		}})
	})
	mux.HandleFunc("/app/installations/{appID}/access_tokens", func(w http.ResponseWriter, r *http.Request) {
		b, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(github.InstallationToken{
			Token:     github.Ptr(base64.StdEncoding.EncodeToString(b)),
			ExpiresAt: &github.Timestamp{Time: time.Now().Add(10 * time.Minute)},
		})
	})
	mux.HandleFunc("/repos/{org}/{repo}/contents/.github/chainguard/{identity}", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotImplemented)
		fmt.Fprintf(io.MultiWriter(w, os.Stdout), "%s %s not implemented\n", r.Method, r.URL.Path)
	})
	return &fakeGitHub{mux: mux}
}

func TestExchange(t *testing.T) {
	ctx := context.Background()
	atr := newAppsTransport(t, newFakeGitHub())

	pk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("cannot generate RSA key %v", err)
	}
	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.RS256,
		Key:       pk,
	}, nil)
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
	provider.AddTestKeySetVerifier(t, iss, &oidc.StaticKeySet{
		PublicKeys: []crypto.PublicKey{pk.Public()},
	})
	ctx = metadata.NewIncomingContext(ctx, metadata.MD{"authorization": []string{"Bearer " + token}})

	pool := &ghinstall.OrgPool{
		M:        &fakeInstallMgr{atr: atr},
		AppCount: 1,
	}
	router := ghinstall.NewOrgRouter(map[string]*ghinstall.OrgPool{"org": pool})
	sts := &sts{router: router}
	for _, tc := range []struct {
		name string
		req  *v1.ExchangeRequest
		want *github.InstallationTokenOptions
	}{
		{
			name: "repo",
			req: &v1.ExchangeRequest{
				Identity: "foo",
				Scope:    "org/repo",
			},
			want: &github.InstallationTokenOptions{
				Repositories: []string{"repo"},
				Permissions: &github.InstallationPermissions{
					PullRequests: github.Ptr("write"),
				},
			},
		},
		{
			name: "org",
			req: &v1.ExchangeRequest{
				Identity: "foo",
				Scope:    "org",
			},
			want: &github.InstallationTokenOptions{
				Permissions: &github.InstallationPermissions{
					PullRequests: github.Ptr("write"),
				},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tok, err := sts.Exchange(ctx, tc.req)
			if err != nil {
				t.Fatalf("Exchange failed: %v", err)
			}

			b, err := base64.StdEncoding.DecodeString(tok.Token)
			if err != nil {
				t.Fatalf("DecodeString failed: %v", err)
			}
			got := new(github.InstallationTokenOptions)
			if err := json.Unmarshal(b, got); err != nil {
				t.Fatalf("Unmarshal failed: %v", err)
			}
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Error(diff)
			}
		})
	}
}

// TestExchangeCustomOrgPolicyRepo verifies that an org-scoped exchange reads
// its trust policy from the repo named by ORG_POLICY_REPO rather than the
// hardcoded ".github" default.
func TestExchangeCustomOrgPolicyRepo(t *testing.T) {
	key := cacheTrustPolicyKey{owner: "org", repo: "my-policies", identity: "foo"}
	trustPolicies.Remove(key)
	t.Cleanup(func() { trustPolicies.Remove(key) })

	ctx := context.Background()
	atr := newAppsTransport(t, newFakeGitHub())

	pk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("cannot generate RSA key %v", err)
	}
	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.RS256,
		Key:       pk,
	}, nil)
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
	provider.AddTestKeySetVerifier(t, iss, &oidc.StaticKeySet{
		PublicKeys: []crypto.PublicKey{pk.Public()},
	})
	ctx = metadata.NewIncomingContext(ctx, metadata.MD{"authorization": []string{"Bearer " + token}})

	pool := &ghinstall.OrgPool{
		M:        &fakeInstallMgr{atr: atr},
		AppCount: 1,
	}
	router := ghinstall.NewOrgRouter(map[string]*ghinstall.OrgPool{"org": pool})
	sts := &sts{router: router, orgPolicyRepo: "my-policies"}

	tok, err := sts.Exchange(ctx, &v1.ExchangeRequest{
		Identity: "foo",
		Scope:    "org",
	})
	if err != nil {
		t.Fatalf("Exchange failed: %v", err)
	}

	b, err := base64.StdEncoding.DecodeString(tok.Token)
	if err != nil {
		t.Fatalf("DecodeString failed: %v", err)
	}
	got := new(github.InstallationTokenOptions)
	if err := json.Unmarshal(b, got); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}
	// Distinct permission from testdata/org/.github/foo.sts.yaml so this
	// test would fail if the lookup silently fell back to the default repo.
	want := &github.InstallationTokenOptions{
		Permissions: &github.InstallationPermissions{
			Contents: github.Ptr("read"),
		},
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Error(diff)
	}
}

func TestExchangeValidation(t *testing.T) {
	ctx := context.Background()
	atr := newAppsTransport(t, newFakeGitHub())

	pk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("cannot generate RSA key %v", err)
	}
	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.RS256,
		Key:       pk,
	}, nil)
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
	provider.AddTestKeySetVerifier(t, iss, &oidc.StaticKeySet{
		PublicKeys: []crypto.PublicKey{pk.Public()},
	})
	ctx = metadata.NewIncomingContext(ctx, metadata.MD{"authorization": []string{"Bearer " + token}})

	pool := &ghinstall.OrgPool{
		M:        &fakeInstallMgr{atr: atr},
		AppCount: 1,
	}
	router := ghinstall.NewOrgRouter(map[string]*ghinstall.OrgPool{"org": pool})
	sts := &sts{router: router}

	tests := []struct {
		name string
		req  *v1.ExchangeRequest
	}{
		{
			name: "empty scope",
			req: &v1.ExchangeRequest{
				Identity: "foo",
				Scope:    "",
			},
		},
		{
			name: "empty identity",
			req: &v1.ExchangeRequest{
				Identity: "",
				Scope:    "org/repo",
			},
		},
		{
			name: "both empty",
			req: &v1.ExchangeRequest{
				Identity: "",
				Scope:    "",
			},
		},
		{
			name: "nil",
			req:  nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := sts.Exchange(ctx, tc.req)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			st, ok := status.FromError(err)
			if !ok {
				t.Fatalf("expected gRPC status error, got %T", err)
			}
			if st.Code() != codes.InvalidArgument {
				t.Errorf("expected code InvalidArgument, got %v", st.Code())
			}
		})
	}
}

func newFakeGitHubRateLimit(statusCode int) *fakeGitHub {
	mux := http.NewServeMux()
	mux.HandleFunc("/app/installations", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode([]github.Installation{{
			ID: github.Ptr(int64(1234)),
			Account: &github.User{
				Login: github.Ptr("org"),
			},
		}})
	})
	mux.HandleFunc("/app/installations/{appID}/access_tokens", func(w http.ResponseWriter, r *http.Request) {
		b, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		json.NewEncoder(w).Encode(github.InstallationToken{
			Token:     github.Ptr(base64.StdEncoding.EncodeToString(b)),
			ExpiresAt: &github.Timestamp{Time: time.Now().Add(10 * time.Minute)},
		})
	})
	mux.HandleFunc("/repos/{org}/{repo}/contents/.github/chainguard/{identity}", func(w http.ResponseWriter, r *http.Request) {
		// The organization allowlist read must not be rate-limited here, or
		// these tests stop exercising the *policy* read they were written for.
		// A later task adds a separate all-paths rate-limit fake for testing
		// the allowlist read's own rate-limit handling.
		if r.PathValue("identity") == "trusted-token-issuers.yaml" {
			writeGitHubNotFound(w)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		// Real GitHub sends this on a primary rate limit, and it is what makes
		// go-github return a *github.RateLimitError rather than a bare
		// *github.ErrorResponse. Without it this fake cannot reproduce the
		// production classification path at all.
		w.Header().Set("X-RateLimit-Remaining", "0")
		w.Header().Set("X-RateLimit-Limit", "5000")
		w.Header().Set("X-RateLimit-Reset", fmt.Sprintf("%d", time.Now().Add(time.Minute).Unix()))
		w.WriteHeader(statusCode)
		json.NewEncoder(w).Encode(github.ErrorResponse{
			Response: &http.Response{StatusCode: statusCode},
			Message:  "API rate limit exceeded",
		})
	})
	mux.HandleFunc("/installation/token", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotImplemented)
		fmt.Fprintf(io.MultiWriter(w, os.Stdout), "%s %s not implemented\n", r.Method, r.URL.Path)
	})

	return &fakeGitHub{
		mux: mux,
	}
}

func TestExchangeRateLimit(t *testing.T) {
	for _, tc := range []struct {
		name       string
		statusCode int
		identity   string
	}{
		{
			name:       "403 Forbidden",
			statusCode: http.StatusForbidden,
			identity:   "ratelimited403",
		},
		{
			name:       "429 Too Many Requests",
			statusCode: http.StatusTooManyRequests,
			identity:   "ratelimited429",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			orgIssuers.Add("org", absentOrgIssuerEntry())
			t.Cleanup(func() {
				orgIssuers.Remove("org")
				staleOrgIssuers.Remove("org")
			})

			ctx := context.Background()
			atr := newAppsTransport(t, newFakeGitHubRateLimit(tc.statusCode))

			pk, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				t.Fatalf("cannot generate RSA key %v", err)
			}
			signer, err := jose.NewSigner(jose.SigningKey{
				Algorithm: jose.RS256,
				Key:       pk,
			}, nil)
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
			provider.AddTestKeySetVerifier(t, iss, &oidc.StaticKeySet{
				PublicKeys: []crypto.PublicKey{pk.Public()},
			})
			ctx = metadata.NewIncomingContext(ctx, metadata.MD{"authorization": []string{"Bearer " + token}})

			pool := &ghinstall.OrgPool{
				M:        &fakeInstallMgr{atr: atr},
				AppCount: 1,
			}
			router := ghinstall.NewOrgRouter(map[string]*ghinstall.OrgPool{"org": pool})
			s := &sts{router: router}
			_, err = s.Exchange(ctx, &v1.ExchangeRequest{
				Identity: tc.identity,
				Scope:    "org/repo",
			})
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			st, ok := status.FromError(err)
			if !ok {
				t.Fatalf("expected gRPC status error, got %T", err)
			}
			if st.Code() != codes.ResourceExhausted {
				t.Errorf("expected code ResourceExhausted, got %v", st.Code())
			}
		})
	}
}

// failInstallMgr is a Manager whose Get always returns an error.
type failInstallMgr struct{}

func (f *failInstallMgr) Get(_ context.Context, _, _, _ string) (*ghinstallation.AppsTransport, int64, error) {
	return nil, 0, fmt.Errorf("not installed")
}

func (f *failInstallMgr) GetByInstallation(_ context.Context, _ string, _ int64) (*ghinstallation.AppsTransport, int64, error) {
	return nil, 0, fmt.Errorf("not installed")
}

func (f *failInstallMgr) GetAll(_ context.Context, _ string) ([]ghinstall.Installation, error) {
	return nil, fmt.Errorf("kms unavailable")
}

// GetAllFresh delegates: these tests exercise routing, not cache freshness.
func (f *failInstallMgr) GetAllFresh(ctx context.Context, owner string) ([]ghinstall.Installation, error) {
	return f.GetAll(ctx, owner)
}

var _ ghinstall.Manager = (*failInstallMgr)(nil)

// sequentialInstallMgr returns transports in order on successive Get calls.
// Used to test retry behaviour where the first app is rate-limited and the
// second succeeds.
type sequentialInstallMgr struct {
	transports []*ghinstallation.AppsTransport
	idx        atomic.Int32
}

func (s *sequentialInstallMgr) Get(_ context.Context, _, _, _ string) (*ghinstallation.AppsTransport, int64, error) {
	i := int(s.idx.Add(1) - 1)
	if i >= len(s.transports) {
		return nil, 0, fmt.Errorf("no more transports")
	}
	return s.transports[i], 1234, nil
}

func (s *sequentialInstallMgr) GetByInstallation(ctx context.Context, owner string, id int64) (*ghinstallation.AppsTransport, int64, error) {
	return s.Get(ctx, owner, "", "")
}

// GetAll returns every configured transport, which is what a real multi-app
// manager does. Note this fake's Get advances an index on each call — real
// roundRobin.Get does not, which is exactly why enumeration needs GetAll.
func (s *sequentialInstallMgr) GetAll(_ context.Context, _ string) ([]ghinstall.Installation, error) {
	out := make([]ghinstall.Installation, 0, len(s.transports))
	for i, atr := range s.transports {
		out = append(out, ghinstall.Installation{Transport: atr, ID: int64(1234 + i), AppID: atr.AppID()})
	}
	return out, nil
}

// GetAllFresh delegates: these tests exercise routing, not cache freshness.
func (s *sequentialInstallMgr) GetAllFresh(ctx context.Context, owner string) ([]ghinstall.Installation, error) {
	return s.GetAll(ctx, owner)
}

var _ ghinstall.Manager = (*sequentialInstallMgr)(nil)

// TestPolicyReadUsesRoundRobin verifies that trust policy reads use the rrm
// transport. rrm points to a server with the policy file. Exchange succeeds
// only if rrm was used for the read.
func TestPolicyReadUsesRoundRobin(t *testing.T) {
	key := cacheTrustPolicyKey{owner: "org", repo: "repo", identity: "foo"}
	trustPolicies.Remove(key)
	staleTrustPolicies.Remove(key)
	t.Cleanup(func() {
		trustPolicies.Remove(key)
		staleTrustPolicies.Remove(key)
	})

	ctx := context.Background()
	rrmAtr := newAppsTransport(t, newFakeGitHub())

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
	ctx = metadata.NewIncomingContext(ctx, metadata.MD{"authorization": []string{"Bearer " + token}})

	pool := &ghinstall.OrgPool{
		M:        &fakeInstallMgr{atr: rrmAtr},
		AppCount: 2,
	}
	router := ghinstall.NewOrgRouter(map[string]*ghinstall.OrgPool{"org": pool})
	s := &sts{router: router}
	// Trust policy lives on the rrm server.
	_, err = s.Exchange(ctx, &v1.ExchangeRequest{
		Identity: "foo",
		Scope:    "org/repo",
	})
	if err != nil {
		t.Fatalf("Exchange failed: %v — policy read did not use rrm transport", err)
	}
}

// TestPolicyReadRetriesOnRateLimit verifies that when the first rrm app is
// rate-limited, the retry loop picks the next app and the exchange succeeds.
func TestPolicyReadRetriesOnRateLimit(t *testing.T) {
	key := cacheTrustPolicyKey{owner: "org", repo: "repo", identity: "foo"}
	trustPolicies.Remove(key)
	staleTrustPolicies.Remove(key)
	t.Cleanup(func() {
		trustPolicies.Remove(key)
		staleTrustPolicies.Remove(key)
	})

	orgIssuers.Add("org", absentOrgIssuerEntry())
	t.Cleanup(func() {
		orgIssuers.Remove("org")
		staleOrgIssuers.Remove("org")
	})

	ctx := context.Background()
	rateLimitedAtr := newAppsTransport(t, newFakeGitHubRateLimit(http.StatusForbidden))
	workingAtr := newAppsTransport(t, newFakeGitHub())

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
	ctx = metadata.NewIncomingContext(ctx, metadata.MD{"authorization": []string{"Bearer " + token}})

	pool := &ghinstall.OrgPool{
		M: &sequentialInstallMgr{
			transports: []*ghinstallation.AppsTransport{rateLimitedAtr, workingAtr},
		},
		AppCount: 2,
	}
	router := ghinstall.NewOrgRouter(map[string]*ghinstall.OrgPool{"org": pool})
	s := &sts{router: router}
	// First rrm.Get returns the rate-limited transport; retry picks the
	// working transport. Exchange should succeed.
	_, err = s.Exchange(ctx, &v1.ExchangeRequest{
		Identity: "foo",
		Scope:    "org/repo",
	})
	if err != nil {
		t.Fatalf("Exchange failed: %v — rate-limit retry did not recover", err)
	}
}

// TestPolicyReadAllRateLimitedReturnsError verifies that when every app is
// rate-limited the error is surfaced to the caller (not retried indefinitely).
func TestPolicyReadAllRateLimitedReturnsError(t *testing.T) {
	key := cacheTrustPolicyKey{owner: "org", repo: "repo", identity: "foo"}
	trustPolicies.Remove(key)
	staleTrustPolicies.Remove(key)
	t.Cleanup(func() {
		trustPolicies.Remove(key)
		staleTrustPolicies.Remove(key)
	})

	orgIssuers.Add("org", absentOrgIssuerEntry())
	t.Cleanup(func() {
		orgIssuers.Remove("org")
		staleOrgIssuers.Remove("org")
	})

	ctx := context.Background()
	rl1 := newAppsTransport(t, newFakeGitHubRateLimit(http.StatusForbidden))
	rl2 := newAppsTransport(t, newFakeGitHubRateLimit(http.StatusTooManyRequests))

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
	ctx = metadata.NewIncomingContext(ctx, metadata.MD{"authorization": []string{"Bearer " + token}})

	pool := &ghinstall.OrgPool{
		M: &sequentialInstallMgr{
			transports: []*ghinstallation.AppsTransport{rl1, rl2},
		},
		AppCount: 2,
	}
	router := ghinstall.NewOrgRouter(map[string]*ghinstall.OrgPool{"org": pool})
	s := &sts{router: router}
	_, err = s.Exchange(ctx, &v1.ExchangeRequest{
		Identity: "foo",
		Scope:    "org/repo",
	})
	if err == nil {
		t.Fatal("expected error, got nil — all apps are rate-limited")
	}
	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected gRPC status error, got %T", err)
	}
	if st.Code() != codes.ResourceExhausted {
		t.Errorf("expected code ResourceExhausted, got %v", st.Code())
	}
}

// newFakeGitHubNotFoundCounter returns a fake GitHub server that returns 404
// for content requests and counts how many times the endpoint was hit.
func newFakeGitHubNotFoundCounter() (*fakeGitHub, *atomic.Int32) {
	var counter atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/app/installations", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode([]github.Installation{{
			ID:      github.Ptr(int64(1234)),
			Account: &github.User{Login: github.Ptr("org")},
		}})
	})
	mux.HandleFunc("/app/installations/{appID}/access_tokens", func(w http.ResponseWriter, r *http.Request) {
		b, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(github.InstallationToken{
			Token:     github.Ptr(base64.StdEncoding.EncodeToString(b)),
			ExpiresAt: &github.Timestamp{Time: time.Now().Add(10 * time.Minute)},
		})
	})
	mux.HandleFunc("/repos/{org}/{repo}/contents/.github/chainguard/{identity}", func(w http.ResponseWriter, r *http.Request) {
		counter.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(github.ErrorResponse{
			Response: &http.Response{StatusCode: http.StatusNotFound},
			Message:  "Not Found",
		})
	})
	mux.HandleFunc("/installation/token", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotImplemented)
		fmt.Fprintf(io.MultiWriter(w, os.Stdout), "%s %s not implemented\n", r.Method, r.URL.Path)
	})
	return &fakeGitHub{mux: mux}, &counter
}

func TestNegativeCachePreventsRepeatedGitHubCalls(t *testing.T) {
	key := cacheTrustPolicyKey{owner: "org", repo: "repo", identity: "does-not-exist"}
	trustPolicies.Remove(key)
	t.Cleanup(func() { trustPolicies.Remove(key) })

	gh, counter := newFakeGitHubNotFoundCounter()
	atr := newAppsTransport(t, gh)

	// lookupTrustPolicy doesn't consult the router, but populate it for safety.
	pool := &ghinstall.OrgPool{M: &fakeInstallMgr{atr: atr}, AppCount: 1}
	s := &sts{router: ghinstall.NewOrgRouter(map[string]*ghinstall.OrgPool{"org": pool})}

	otp := &OrgTrustPolicy{}
	otp.Repositories = []string{"repo"}

	// First call: should hit GitHub and get a 404.
	err := s.lookupTrustPolicy(context.Background(), atr, 1234, key, &otp.TrustPolicy)
	if err == nil {
		t.Fatal("expected NotFound error on first call, got nil")
	}
	st, ok := status.FromError(err)
	if !ok || st.Code() != codes.NotFound {
		t.Fatalf("expected gRPC NotFound, got %v", err)
	}
	if got := counter.Load(); got != 1 {
		t.Fatalf("expected 1 GitHub API call, got %d", got)
	}

	// Second call: should be served from negative cache, no GitHub API call.
	err = s.lookupTrustPolicy(context.Background(), atr, 1234, key, &otp.TrustPolicy)
	if err == nil {
		t.Fatal("expected NotFound error on second call, got nil")
	}
	st, ok = status.FromError(err)
	if !ok || st.Code() != codes.NotFound {
		t.Fatalf("expected gRPC NotFound, got %v", err)
	}
	if got := counter.Load(); got != 1 {
		t.Fatalf("expected still 1 GitHub API call after negative cache hit, got %d", got)
	}
}

func TestNegativeCacheSkipsInstallationTokenCreation(t *testing.T) {
	key := cacheTrustPolicyKey{owner: "org", repo: "repo", identity: "cached-missing"}
	trustPolicies.Add(key, negativeCacheConst)
	t.Cleanup(func() { trustPolicies.Remove(key) })

	pool := &ghinstall.OrgPool{M: &failInstallMgr{}, AppCount: 1}
	s := &sts{router: ghinstall.NewOrgRouter(map[string]*ghinstall.OrgPool{"org": pool})}

	_, _, _, _, err := s.lookupInstallAndTrustPolicy(context.Background(), "org/repo", "cached-missing", "some-subject", testGitHubIssuer)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	st, ok := status.FromError(err)
	if !ok || st.Code() != codes.NotFound {
		t.Fatalf("expected gRPC NotFound from negative cache, got %v (managers should not have been called)", err)
	}
}

func TestRateLimitServesStaleCache(t *testing.T) {
	key := cacheTrustPolicyKey{owner: "org", repo: "repo", identity: "foo"}
	trustPolicies.Remove(key)
	staleTrustPolicies.Remove(key)
	t.Cleanup(func() {
		trustPolicies.Remove(key)
		staleTrustPolicies.Remove(key)
	})

	ctx := context.Background()
	workingGH := newFakeGitHub()
	workingAtr := newAppsTransport(t, workingGH)

	pool := &ghinstall.OrgPool{
		M:        &fakeInstallMgr{atr: workingAtr},
		AppCount: 1,
	}
	s := &sts{router: ghinstall.NewOrgRouter(map[string]*ghinstall.OrgPool{"org": pool})}

	// First call: populates both caches.
	otp := &OrgTrustPolicy{}
	otp.Repositories = []string{"repo"}
	err := s.lookupTrustPolicy(ctx, workingAtr, 1234, key, &otp.TrustPolicy)
	if err != nil {
		t.Fatalf("first lookup failed: %v", err)
	}

	// Expire the primary cache to force a GitHub call on next lookup.
	trustPolicies.Remove(key)

	// Verify the stale cache was populated.
	if _, ok := staleTrustPolicies.Get(key); !ok {
		t.Fatal("stale cache should have been populated after successful fetch")
	}

	// Switch to a rate-limited GitHub backend.
	rateLimitedAtr := newAppsTransport(t, newFakeGitHubRateLimit(http.StatusForbidden))
	pool.M = &fakeInstallMgr{atr: rateLimitedAtr}

	// Second call: primary cache miss, GitHub 403, should fall back to stale cache.
	otp2 := &OrgTrustPolicy{}
	otp2.Repositories = []string{"repo"}
	err = s.lookupTrustPolicy(ctx, rateLimitedAtr, 1234, key, &otp2.TrustPolicy)
	if err != nil {
		t.Fatalf("expected stale cache fallback on rate limit, got error: %v", err)
	}

	// The stale hit should have seeded the primary cache so further
	// exchanges during the rate-limit window skip the GitHub round-trip.
	if _, ok := trustPolicies.Get(key); !ok {
		t.Error("primary cache should be seeded after serving stale on rate limit")
	}
}

// TestExchangeOrgNotConfigured verifies that a request for an org with no
// configured apps returns NotFound.
func TestExchangeOrgNotConfigured(t *testing.T) {
	ctx := context.Background()
	atr := newAppsTransport(t, newFakeGitHub())

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
	ctx = metadata.NewIncomingContext(ctx, metadata.MD{"authorization": []string{"Bearer " + token}})

	// Only "org" is configured — "other-org" is not.
	pool := &ghinstall.OrgPool{
		M:        &fakeInstallMgr{atr: atr},
		AppCount: 1,
	}
	router := ghinstall.NewOrgRouter(map[string]*ghinstall.OrgPool{"org": pool})
	s := &sts{router: router}

	_, err = s.Exchange(ctx, &v1.ExchangeRequest{
		Identity: "foo",
		Scope:    "other-org/repo",
	})
	if err == nil {
		t.Fatal("expected error for unconfigured org")
	}
	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected gRPC status error, got %T", err)
	}
	if st.Code() != codes.NotFound {
		t.Errorf("expected code NotFound, got %v", st.Code())
	}
}

// TestExchangeOrgIsolation verifies that requests for different orgs route
// to their respective app pools.
func TestExchangeOrgIsolation(t *testing.T) {
	ctx := context.Background()

	// org1 points to a working server, org2 points to one with no contents.
	org1Atr := newAppsTransport(t, newFakeGitHub())
	org2Atr := newAppsTransport(t, newFakeGitHubNoContents())

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
	ctx = metadata.NewIncomingContext(ctx, metadata.MD{"authorization": []string{"Bearer " + token}})

	pool1 := &ghinstall.OrgPool{
		M:        &fakeInstallMgr{atr: org1Atr},
		AppCount: 1,
	}
	pool2 := &ghinstall.OrgPool{
		M:        &fakeInstallMgr{atr: org2Atr},
		AppCount: 1,
	}
	router := ghinstall.NewOrgRouter(map[string]*ghinstall.OrgPool{
		"org":       pool1,
		"other-org": pool2,
	})
	s := &sts{router: router}

	// org1 should succeed (has trust policy files).
	key := cacheTrustPolicyKey{owner: "org", repo: "repo", identity: "foo"}
	trustPolicies.Remove(key)
	t.Cleanup(func() { trustPolicies.Remove(key) })

	_, err = s.Exchange(ctx, &v1.ExchangeRequest{
		Identity: "foo",
		Scope:    "org/repo",
	})
	if err != nil {
		t.Fatalf("Exchange for org failed: %v", err)
	}

	// org2 should fail because its server has no contents.
	key2 := cacheTrustPolicyKey{owner: "other-org", repo: "repo", identity: "foo"}
	trustPolicies.Remove(key2)
	t.Cleanup(func() { trustPolicies.Remove(key2) })

	_, err = s.Exchange(ctx, &v1.ExchangeRequest{
		Identity: "foo",
		Scope:    "other-org/repo",
	})
	if err == nil {
		t.Fatal("expected error for other-org (no contents), got nil")
	}
}

// sharedAppKey returns one RSA key for the whole package. newAppsTransport is called
// ~50 times across these tests and RSA-2048 generation dominated the suite's runtime;
// the key only signs App JWTs that the fakes never verify, so one is enough.
var sharedAppKey = sync.OnceValue(func() *rsa.PrivateKey {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic("generating the shared test App key: " + err.Error())
	}
	return key
})

func newAppsTransport(t *testing.T, h http.Handler) *ghinstallation.AppsTransport {
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

	// Create a custom transport that overrides the Dial funcs - this forces all traffic
	// that uses this transport to go through this server, regardless of the URL.
	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
		DialTLS: func(network, addr string) (net.Conn, error) {
			return tls.Dial(network, strings.TrimPrefix(srv.URL, "https://"), tlsConfig)
		},
		Dial: func(network, addr string) (net.Conn, error) {
			return tls.Dial(network, strings.TrimPrefix(srv.URL, "http://"), tlsConfig)
		},
	}

	ghsigner := ghinstallation.NewRSASigner(jwt.SigningMethodRS256, sharedAppKey())

	atr, err := ghinstallation.NewAppsTransportWithOptions(transport, 1234, ghinstallation.WithSigner(ghsigner))
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
	pub := &priv.PublicKey
	raw, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
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

	// configuration of the certificate what we want to
	return &tls.Config{
		Certificates:       []tls.Certificate{tlsCert},
		RootCAs:            pool,
		InsecureSkipVerify: true,
	}, nil
}

func TestExtractUserAgent(t *testing.T) {
	for _, tc := range []struct {
		name string
		ctx  context.Context
		want string
	}{{
		name: "no metadata",
		ctx:  context.Background(),
		want: "",
	}, {
		name: "metadata without user-agent",
		ctx:  metadata.NewIncomingContext(context.Background(), metadata.MD{"other": []string{"value"}}),
		want: "",
	}, {
		name: "single user-agent",
		ctx:  metadata.NewIncomingContext(context.Background(), metadata.MD{"user-agent": []string{"octo-sts/1.0"}}),
		want: "octo-sts/1.0",
	}, {
		name: "multiple user-agent values joined",
		ctx:  metadata.NewIncomingContext(context.Background(), metadata.MD{"user-agent": []string{"octo-sts/1.0", "grpc-go/1.0"}}),
		want: "octo-sts/1.0 grpc-go/1.0",
	}} {
		t.Run(tc.name, func(t *testing.T) {
			if got := extractUserAgent(tc.ctx); got != tc.want {
				t.Errorf("extractUserAgent() = %q, want %q", got, tc.want)
			}
		})
	}
}

func poolOf(m ghinstall.Manager) *ghinstall.OrgPool {
	return &ghinstall.OrgPool{M: m, AppCount: 3}
}

func TestGetExchangeInstallAppPin(t *testing.T) {
	ctx := context.Background()
	pool := poolOf(&enumMgr{installs: []ghinstall.Installation{
		{ID: 11, AppID: 101},
		{ID: 12, AppID: 102},
		{ID: 21, AppID: 201},
	}})
	appNames := map[string]int64{"ci-a": 101, "ci-b": 102, "deploy": 201}
	appIDs := map[int64]bool{101: true, 102: true, 201: true}
	checksWrite := github.InstallationPermissions{Checks: github.Ptr("write")}
	stickyKey := routekey.Key("org/repo", "id", "subj")

	compile := func(t *testing.T, tp *TrustPolicy) *TrustPolicy {
		t.Helper()
		tp.Issuer = "https://example.com"
		tp.Subject = "subject"
		if err := tp.Compile(); err != nil {
			t.Fatalf("Compile: %v", err)
		}
		return tp
	}
	exchange := func(t *testing.T, s *sts, pool *ghinstall.OrgPool, tp *TrustPolicy) (int64, error) {
		t.Helper()
		_, id, err := s.getExchangeInstall(ctx, pool, "org", "org/repo", "id", "subj", tp, nil, 999)
		return id, err
	}
	seedSticky := func(t *testing.T, id int64) stickystore.Store {
		t.Helper()
		store := memory.New()
		if err := store.Put(ctx, stickyKey, id, "org/repo", "id", "subj"); err != nil {
			t.Fatal(err)
		}
		return store
	}

	t.Run("no pin returns read installation", func(t *testing.T) {
		id, err := exchange(t, &sts{}, pool, compile(t, &TrustPolicy{}))
		if err != nil || id != 999 {
			t.Fatalf("got (%d, %v), want (999, nil)", id, err)
		}
	})

	t.Run("no pin checks:write uses sticky", func(t *testing.T) {
		s := &sts{sticky: memory.New()}
		tp := compile(t, &TrustPolicy{Permissions: checksWrite})
		first, err := exchange(t, s, pool, tp)
		if err != nil {
			t.Fatal(err)
		}
		again, err := exchange(t, s, pool, tp)
		if err != nil || again != first {
			t.Fatalf("got (%d, %v), want sticky %d", again, err, first)
		}
	})

	t.Run("exact app pin", func(t *testing.T) {
		id, err := exchange(t, &sts{apps: AppSet{Names: appNames, IDs: appIDs}}, pool, compile(t, &TrustPolicy{App: "deploy"}))
		if err != nil || id != 21 {
			t.Fatalf("got (%d, %v), want (21, nil)", id, err)
		}
	})

	t.Run("numeric app pin", func(t *testing.T) {
		id, err := exchange(t, &sts{apps: AppSet{Names: appNames, IDs: appIDs}}, pool, compile(t, &TrustPolicy{App: "102"}))
		if err != nil || id != 12 {
			t.Fatalf("got (%d, %v), want (12, nil)", id, err)
		}
	})

	t.Run("unconfigured numeric app pin fails without enumeration", func(t *testing.T) {
		mgr := &enumMgr{}
		s := &sts{apps: AppSet{Names: appNames, IDs: appIDs}}
		_, err := exchange(t, s, poolOf(mgr), compile(t, &TrustPolicy{App: "999"}))
		if status.Code(err) != codes.FailedPrecondition {
			t.Fatalf("got %v, want FailedPrecondition", err)
		}
		if got := mgr.freshCalls.Load(); got != 0 {
			t.Errorf("GetAllFresh called %d times, want 0 (rejected before enumeration)", got)
		}
	})

	t.Run("concurrent pin misses share one confirmation walk", func(t *testing.T) {
		pinMisses.Purge()
		gate := make(chan struct{})
		mgr := &enumMgr{freshGate: gate}
		s := &sts{apps: AppSet{Names: appNames, IDs: appIDs}}
		tp := compile(t, &TrustPolicy{App: "deploy"})
		const n = 8
		var wg sync.WaitGroup
		errs := make([]error, n)
		for i := range n {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, _, errs[i] = s.getExchangeInstall(ctx, poolOf(mgr), "flightorg", "flightorg/repo", "id", "subj", tp, nil, 999)
			}()
		}
		// Generous settle time: a goroutine reaching the singleflight after
		// the gated leader completes would start a second walk and flake the
		// ==1 assertion.
		time.Sleep(300 * time.Millisecond)
		close(gate)
		wg.Wait()
		for i, err := range errs {
			if status.Code(err) != codes.FailedPrecondition {
				t.Errorf("goroutine %d: got %v, want FailedPrecondition", i, err)
			}
		}
		if got := mgr.freshCalls.Load(); got != 1 {
			t.Errorf("GetAllFresh called %d times, want 1 (coalesced)", got)
		}
	})

	t.Run("cancelled caller still records the detached confirmation", func(t *testing.T) {
		pinMisses.Purge()
		gate := make(chan struct{})
		mgr := &enumMgr{freshGate: gate}
		s := &sts{apps: AppSet{Names: appNames, IDs: appIDs}}
		tp := compile(t, &TrustPolicy{App: "deploy"})

		cctx, cancel := context.WithCancel(ctx)
		cancel()
		if _, _, err := s.getExchangeInstall(cctx, poolOf(mgr), "detachorg", "detachorg/repo", "id", "subj", tp, nil, 999); status.Code(err) != codes.Canceled {
			t.Fatalf("got %v, want Canceled", err)
		}

		missKey := pinMissKey("detachorg", map[int64]bool{201: true})
		if _, confirmed := pinMisses.Get(missKey); confirmed {
			t.Fatal("miss confirmed before the walk completed")
		}

		close(gate)
		deadline := time.Now().Add(5 * time.Second)
		for {
			if _, confirmed := pinMisses.Get(missKey); confirmed {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("detached confirmation never recorded")
			}
			time.Sleep(2 * time.Millisecond)
		}

		if _, _, err := s.getExchangeInstall(ctx, poolOf(mgr), "detachorg", "detachorg/repo", "id", "subj", tp, nil, 999); status.Code(err) != codes.FailedPrecondition {
			t.Fatalf("got %v, want FailedPrecondition from the recorded confirmation", err)
		}
		if got := mgr.freshCalls.Load(); got != 1 {
			t.Errorf("GetAllFresh called %d times, want 1", got)
		}
	})

	t.Run("unknown app", func(t *testing.T) {
		_, err := exchange(t, &sts{apps: AppSet{Names: appNames, IDs: appIDs}}, pool, compile(t, &TrustPolicy{App: "ghost"}))
		if status.Code(err) != codes.FailedPrecondition {
			t.Fatalf("got %v, want FailedPrecondition", err)
		}
	})

	t.Run("pinned app not installed", func(t *testing.T) {
		s := &sts{apps: AppSet{Names: map[string]int64{"ghost": 301}, IDs: map[int64]bool{301: true}}}
		_, err := exchange(t, s, pool, compile(t, &TrustPolicy{App: "ghost"}))
		if status.Code(err) != codes.FailedPrecondition {
			t.Fatalf("got %v, want FailedPrecondition", err)
		}
	})

	t.Run("pattern spreads deterministically", func(t *testing.T) {
		s := &sts{apps: AppSet{Names: appNames, IDs: appIDs}}
		tp := compile(t, &TrustPolicy{AppPattern: "ci-.*"})
		first, err := exchange(t, s, pool, tp)
		if err != nil {
			t.Fatal(err)
		}
		if first != 11 && first != 12 {
			t.Fatalf("got %d, want a ci install", first)
		}
		for range 5 {
			again, err := exchange(t, s, pool, tp)
			if err != nil || again != first {
				t.Fatalf("got (%d, %v), want stable %d", again, err, first)
			}
		}
	})

	t.Run("pattern alternation stays anchored", func(t *testing.T) {
		s := &sts{apps: AppSet{Names: map[string]int64{"ci": 1, "deploy": 2, "ci-privileged": 3}}}
		tp := compile(t, &TrustPolicy{AppPattern: "ci|deploy"})
		eligible, err := s.eligibleApps(tp)
		if err != nil {
			t.Fatal(err)
		}
		want := map[int64]bool{1: true, 2: true}
		if !maps.Equal(eligible, want) {
			t.Errorf("eligibleApps() = %v, want %v", eligible, want)
		}
	})

	t.Run("pattern matches nothing", func(t *testing.T) {
		_, err := exchange(t, &sts{apps: AppSet{Names: appNames, IDs: appIDs}}, pool, compile(t, &TrustPolicy{AppPattern: "nope-.*"}))
		if status.Code(err) != codes.FailedPrecondition {
			t.Fatalf("got %v, want FailedPrecondition", err)
		}
	})

	t.Run("checks:write sticky honored within pin set", func(t *testing.T) {
		s := &sts{apps: AppSet{Names: appNames, IDs: appIDs}, sticky: memory.New()}
		tp := compile(t, &TrustPolicy{AppPattern: "ci-.*", Permissions: checksWrite})
		first, err := exchange(t, s, pool, tp)
		if err != nil {
			t.Fatal(err)
		}
		again, err := exchange(t, s, pool, tp)
		if err != nil || again != first {
			t.Fatalf("got (%d, %v), want sticky %d", again, err, first)
		}
	})

	t.Run("checks:write sticky outside pin set reassigns", func(t *testing.T) {
		store := seedSticky(t, 21)
		s := &sts{apps: AppSet{Names: appNames, IDs: appIDs}, sticky: store}
		id, err := exchange(t, s, pool, compile(t, &TrustPolicy{AppPattern: "ci-.*", Permissions: checksWrite}))
		if err != nil {
			t.Fatal(err)
		}
		if id != 11 && id != 12 {
			t.Fatalf("got %d, want reassignment within ci apps", id)
		}
		if cached, ok, _ := store.Get(ctx, stickyKey); !ok || cached != id {
			t.Fatalf("sticky = (%d, %t), want (%d, true)", cached, ok, id)
		}
	})

	t.Run("negative-cached pin recovered by fresh enumeration", func(t *testing.T) {
		hidden := poolOf(&enumMgr{freshInstalls: []ghinstall.Installation{{ID: 21, AppID: 201}}})
		id, err := exchange(t, &sts{apps: AppSet{Names: appNames, IDs: appIDs}}, hidden, compile(t, &TrustPolicy{App: "deploy"}))
		if err != nil || id != 21 {
			t.Fatalf("got (%d, %v), want (21, nil)", id, err)
		}
	})

	t.Run("negative-cached sticky recovered by fresh enumeration", func(t *testing.T) {
		store := seedSticky(t, 12)
		hidden := poolOf(&enumMgr{
			installs:      []ghinstall.Installation{{ID: 11, AppID: 101}},
			freshInstalls: []ghinstall.Installation{{ID: 11, AppID: 101}, {ID: 12, AppID: 102}},
		})
		s := &sts{apps: AppSet{Names: appNames, IDs: appIDs}, sticky: store}
		id, err := exchange(t, s, hidden, compile(t, &TrustPolicy{AppPattern: "ci-.*", Permissions: checksWrite}))
		if err != nil || id != 12 {
			t.Fatalf("got (%d, %v), want sticky (12, nil)", id, err)
		}
		if cached, ok, _ := store.Get(ctx, stickyKey); !ok || cached != 12 {
			t.Fatalf("sticky = (%d, %t), want preserved (12, true)", cached, ok)
		}
	})

	t.Run("confirmed pin miss throttles fresh enumeration", func(t *testing.T) {
		pinMisses.Purge()
		mgr := &enumMgr{}
		s := &sts{apps: AppSet{Names: appNames, IDs: appIDs}}
		tp := compile(t, &TrustPolicy{App: "deploy"})
		for i := range 3 {
			_, _, err := s.getExchangeInstall(ctx, poolOf(mgr), "missorg", "missorg/repo", "id", "subj", tp, nil, 999)
			if status.Code(err) != codes.FailedPrecondition {
				t.Fatalf("call %d: got %v, want FailedPrecondition", i, err)
			}
		}
		if got := mgr.freshCalls.Load(); got != 1 {
			t.Errorf("GetAllFresh called %d times, want 1 (confirmed miss cached)", got)
		}
	})

	t.Run("sticky proven ineligible reassigns despite partial enumeration", func(t *testing.T) {
		store := seedSticky(t, 21)
		// Install 21 is enumerated (proving it ineligible for ci-.*), and an
		// unrelated manager fails.
		partial := poolOf(&enumMgr{
			installs: []ghinstall.Installation{{ID: 11, AppID: 101}, {ID: 21, AppID: 201}},
			err:      errors.New("unrelated manager failed"),
		})
		s := &sts{apps: AppSet{Names: appNames, IDs: appIDs}, sticky: store}
		id, err := exchange(t, s, partial, compile(t, &TrustPolicy{AppPattern: "ci-.*", Permissions: checksWrite}))
		if err != nil || id != 11 {
			t.Fatalf("got (%d, %v), want reassignment (11, nil)", id, err)
		}
		if cached, ok, _ := store.Get(ctx, stickyKey); !ok || cached != 11 {
			t.Fatalf("sticky = (%d, %t), want (11, true)", cached, ok)
		}
	})

	t.Run("fresh enumeration proving ineligibility outweighs its error", func(t *testing.T) {
		store := seedSticky(t, 21)
		hidden := poolOf(&enumMgr{
			installs:      []ghinstall.Installation{{ID: 11, AppID: 101}},
			freshInstalls: []ghinstall.Installation{{ID: 11, AppID: 101}, {ID: 21, AppID: 201}},
			freshErr:      errors.New("unrelated manager failed"),
		})
		s := &sts{apps: AppSet{Names: appNames, IDs: appIDs}, sticky: store}
		id, err := exchange(t, s, hidden, compile(t, &TrustPolicy{AppPattern: "ci-.*", Permissions: checksWrite}))
		if err != nil || id != 11 {
			t.Fatalf("got (%d, %v), want reassignment (11, nil)", id, err)
		}
	})

	t.Run("partial enumeration preserves sticky install", func(t *testing.T) {
		store := seedSticky(t, 12)
		// Install 12 holds the sticky mapping but is absent from the partial result.
		partial := poolOf(&enumMgr{
			installs: []ghinstall.Installation{{ID: 11, AppID: 101}},
			err:      errors.New("enumeration failed"),
		})
		s := &sts{apps: AppSet{Names: appNames, IDs: appIDs}, sticky: store}
		if _, err := exchange(t, s, partial, compile(t, &TrustPolicy{AppPattern: "ci-.*", Permissions: checksWrite})); err == nil {
			t.Fatal("want enumeration error, got nil")
		}
		if cached, ok, _ := store.Get(ctx, stickyKey); !ok || cached != 12 {
			t.Fatalf("sticky = (%d, %t), want preserved (12, true)", cached, ok)
		}
	})

	t.Run("partial enumeration still honors present sticky", func(t *testing.T) {
		store := seedSticky(t, 11)
		partial := poolOf(&enumMgr{
			installs: []ghinstall.Installation{{ID: 11, AppID: 101}},
			err:      errors.New("enumeration failed"),
		})
		s := &sts{apps: AppSet{Names: appNames, IDs: appIDs}, sticky: store}
		id, err := exchange(t, s, partial, compile(t, &TrustPolicy{AppPattern: "ci-.*", Permissions: checksWrite}))
		if err != nil || id != 11 {
			t.Fatalf("got (%d, %v), want (11, nil)", id, err)
		}
	})

	t.Run("enumeration error with no candidates propagates", func(t *testing.T) {
		errPool := poolOf(&enumMgr{err: errors.New("boom")})
		_, err := exchange(t, &sts{apps: AppSet{Names: appNames, IDs: appIDs}}, errPool, compile(t, &TrustPolicy{App: "deploy"}))
		if err == nil || status.Code(err) == codes.FailedPrecondition {
			t.Fatalf("got %v, want raw enumeration error", err)
		}
	})
}
