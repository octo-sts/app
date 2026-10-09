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
			ID: new(int64(1234)),
			Account: &github.User{
				Login: new("org"),
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
			Token:     new(base64.StdEncoding.EncodeToString(b)),
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
				{Type: new("file"), Name: new("placeholder")},
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
			Content:  new(base64.StdEncoding.EncodeToString(b)),
			Type:     new("file"),
			Encoding: new("base64"),
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
			ID:      new(int64(1234)),
			Account: &github.User{Login: new("other-org")},
		}})
	})
	mux.HandleFunc("/app/installations/{appID}/access_tokens", func(w http.ResponseWriter, r *http.Request) {
		b, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(github.InstallationToken{
			Token:     new(base64.StdEncoding.EncodeToString(b)),
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
				Scopes:   []string{"org/repo"},
			},
			want: &github.InstallationTokenOptions{
				Repositories: []string{"repo"},
				Permissions: &github.InstallationPermissions{
					PullRequests: new("write"),
				},
			},
		},
		{
			name: "org",
			req: &v1.ExchangeRequest{
				Identity: "foo",
				Scopes:   []string{"org"},
			},
			want: &github.InstallationTokenOptions{
				Permissions: &github.InstallationPermissions{
					PullRequests: new("write"),
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

// TestExchangeMismatchDoesNotLeakPolicy verifies that a caller whose token does
// not match a trust policy learns nothing about the policy's contents: neither
// the patterns CheckToken compared against nor the app pin, which used to be
// resolved (and its error returned) before the token was checked.
func TestExchangeMismatchDoesNotLeakPolicy(t *testing.T) {
	key := cacheTrustPolicyKey{owner: "org", repo: "repo", identity: "private"}
	trustPolicies.Remove(key)
	t.Cleanup(func() { trustPolicies.Remove(key) })

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
		Subject:  "repo:attacker/whatever:ref:refs/heads/main",
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
	ctx := metadata.NewIncomingContext(context.Background(), metadata.MD{"authorization": []string{"Bearer " + token}})

	pool := &ghinstall.OrgPool{
		M:        &fakeInstallMgr{atr: newAppsTransport(t, newFakeGitHub())},
		AppCount: 1,
	}
	ce := &captureCEClient{}
	sts := &sts{router: ghinstall.NewOrgRouter(map[string]*ghinstall.OrgPool{"org": pool}), ceclient: ce, metrics: true}

	_, err = sts.Exchange(ctx, &v1.ExchangeRequest{Identity: "private", Scopes: []string{"org/repo"}})
	if got := status.Code(err); got != codes.PermissionDenied {
		t.Fatalf("Exchange() code = %v, want PermissionDenied; err = %v", got, err)
	}
	if got, want := status.Convert(err).Message(), "token does not match trust policy"; got != want {
		t.Errorf("Exchange() message = %q, want %q", got, want)
	}

	// The operator-facing audit event keeps the detail the caller does not get.
	sent := ce.sent()
	if len(sent) != 1 {
		t.Fatalf("emitted %d events, want 1", len(sent))
	}
	var ev Event
	if err := json.Unmarshal(sent[0].Data(), &ev); err != nil {
		t.Fatalf("decoding event data: %v", err)
	}
	if !strings.Contains(ev.Error, "secret-internal-repo") {
		t.Errorf("Event.Error = %q, want the detailed mismatch reason", ev.Error)
	}
	if ev.InstallationID != 1234 {
		t.Errorf("Event.InstallationID = %d, want 1234 (the installation that read the policy)", ev.InstallationID)
	}

	// A malformed policy must be indistinguishable from a missing one.
	_, missing := sts.Exchange(ctx, &v1.ExchangeRequest{Identity: "does-not-exist", Scopes: []string{"org/repo"}})
	_, malformed := sts.Exchange(ctx, &v1.ExchangeRequest{Identity: "malformed", Scopes: []string{"org/repo"}})
	for _, id := range []string{"does-not-exist", "malformed"} {
		k := cacheTrustPolicyKey{owner: "org", repo: "repo", identity: id}
		t.Cleanup(func() { trustPolicies.Remove(k) })
	}
	if status.Code(missing) != codes.NotFound {
		t.Fatalf("Exchange(missing) = %v, want NotFound", missing)
	}
	if got, want := strings.ReplaceAll(status.Convert(malformed).Message(), "malformed", "does-not-exist"), status.Convert(missing).Message(); status.Code(malformed) != codes.NotFound || got != want {
		t.Errorf("Exchange(malformed) = %v, want same response as missing policy (%v)", malformed, missing)
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
		Scopes:   []string{"org"},
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
			Contents: new("read"),
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
				Scope:    "", //nolint:staticcheck // exercises deprecated Scope fallback (case 0)
			},
		},
		{
			name: "empty identity",
			req: &v1.ExchangeRequest{
				Identity: "",
				Scopes:   []string{"org/repo"},
			},
		},
		{
			name: "both empty",
			req: &v1.ExchangeRequest{
				Identity: "",
				Scope:    "", //nolint:staticcheck // exercises deprecated Scope fallback (case 0)
			},
		},
		{
			name: "nested identity",
			req: &v1.ExchangeRequest{
				Identity: "sub/foo",
				Scopes:   []string{"org/repo"},
			},
		},
		{
			name: "traversal identity",
			req: &v1.ExchangeRequest{
				Identity: "../secrets",
				Scopes:   []string{"org/repo"},
			},
		},
		{
			name: "dotdot identity",
			req: &v1.ExchangeRequest{
				Identity: "..",
				Scopes:   []string{"org/repo"},
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
			ID: new(int64(1234)),
			Account: &github.User{
				Login: new("org"),
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
			Token:     new(base64.StdEncoding.EncodeToString(b)),
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
				Scopes:   []string{"org/repo"},
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
		Scopes:   []string{"org/repo"},
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
	forbiddenPolicies.Remove(key)
	t.Cleanup(func() {
		trustPolicies.Remove(key)
		staleTrustPolicies.Remove(key)
		// A 403 in these tests seeds the forbidden cooldown for org/repo/foo,
		// a key other tests share; clear it so they do not inherit it.
		forbiddenPolicies.Remove(key)
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
		Scopes:   []string{"org/repo"},
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
	forbiddenPolicies.Remove(key)
	t.Cleanup(func() {
		trustPolicies.Remove(key)
		staleTrustPolicies.Remove(key)
		// A 403 in these tests seeds the forbidden cooldown for org/repo/foo,
		// a key other tests share; clear it so they do not inherit it.
		forbiddenPolicies.Remove(key)
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
		Scopes:   []string{"org/repo"},
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

// newFakeGitHubForbidden returns a fake GitHub whose policy read answers with a
// bare 403 carrying no rate-limit headers, so go-github surfaces a plain
// *github.ErrorResponse rather than a *RateLimitError. This is the
// permission-denied case of issue #1320, distinct from newFakeGitHubRateLimit.
func newFakeGitHubForbidden() *fakeGitHub {
	mux := http.NewServeMux()
	mux.HandleFunc("/app/installations", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode([]github.Installation{{
			ID:      new(int64(1234)),
			Account: &github.User{Login: new("org")},
		}})
	})
	mux.HandleFunc("/app/installations/{appID}/access_tokens", func(w http.ResponseWriter, r *http.Request) {
		b, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(github.InstallationToken{
			Token:     new(base64.StdEncoding.EncodeToString(b)),
			ExpiresAt: &github.Timestamp{Time: time.Now().Add(10 * time.Minute)},
		})
	})
	mux.HandleFunc("/repos/{org}/{repo}/contents/.github/chainguard/{identity}", func(w http.ResponseWriter, r *http.Request) {
		// Keep the org allowlist read out of the way, as newFakeGitHubRateLimit does.
		if r.PathValue("identity") == "trusted-token-issuers.yaml" {
			writeGitHubNotFound(w)
			return
		}
		// A bare 403: no X-RateLimit-Remaining, no Retry-After. This is a
		// permission failure, not a rate limit.
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(github.ErrorResponse{
			Response: &http.Response{StatusCode: http.StatusForbidden},
			Message:  "Resource not accessible by integration",
		})
	})
	mux.HandleFunc("/installation/token", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotImplemented)
		fmt.Fprintf(io.MultiWriter(w, os.Stdout), "%s %s not implemented\n", r.Method, r.URL.Path)
	})
	return &fakeGitHub{mux: mux}
}

// TestPolicyReadForbiddenDoesNotRotate covers issue #1320's wasteful-rotation
// impact: a bare 403 on the first app must surface as PermissionDenied without
// rotating to the next app. The pool's second transport works, so a rotation
// would succeed; a PermissionDenied result proves the retry loop stopped.
func TestPolicyReadForbiddenDoesNotRotate(t *testing.T) {
	key := cacheTrustPolicyKey{owner: "org", repo: "repo", identity: "foo"}
	trustPolicies.Remove(key)
	staleTrustPolicies.Remove(key)
	forbiddenPolicies.Remove(key)
	t.Cleanup(func() {
		trustPolicies.Remove(key)
		staleTrustPolicies.Remove(key)
		// A 403 in these tests seeds the forbidden cooldown for org/repo/foo,
		// a key other tests share; clear it so they do not inherit it.
		forbiddenPolicies.Remove(key)
	})

	orgIssuers.Add("org", absentOrgIssuerEntry())
	t.Cleanup(func() {
		orgIssuers.Remove("org")
		staleOrgIssuers.Remove("org")
	})

	ctx := context.Background()
	forbiddenAtr := newAppsTransport(t, newFakeGitHubForbidden())
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
			transports: []*ghinstallation.AppsTransport{forbiddenAtr, workingAtr},
		},
		AppCount: 2,
	}
	router := ghinstall.NewOrgRouter(map[string]*ghinstall.OrgPool{"org": pool})
	s := &sts{router: router}
	_, err = s.Exchange(ctx, &v1.ExchangeRequest{
		Identity: "foo",
		Scopes:   []string{"org/repo"},
	})
	if got := status.Code(err); got != codes.PermissionDenied {
		t.Fatalf("code = %v, want PermissionDenied (a 403 must not rotate to the next app); err = %v", got, err)
	}
}

// newFakeGitHubNotFoundCounter returns a fake GitHub server that returns 404
// for content requests and counts how many times the endpoint was hit.
func newFakeGitHubNotFoundCounter() (*fakeGitHub, *atomic.Int32) {
	var counter atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/app/installations", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode([]github.Installation{{
			ID:      new(int64(1234)),
			Account: &github.User{Login: new("org")},
		}})
	})
	mux.HandleFunc("/app/installations/{appID}/access_tokens", func(w http.ResponseWriter, r *http.Request) {
		b, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(github.InstallationToken{
			Token:     new(base64.StdEncoding.EncodeToString(b)),
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

// A caller can miss the cache, be descheduled until an earlier flight finishes,
// then become the leader of a new flight. It must use the result just cached by
// that earlier flight rather than fetching a stale 404 and overwriting a 200.
func TestPolicyReadRechecksCachesAfterJoiningFlight(t *testing.T) {
	const policy = "fresh policy"
	for _, tc := range []struct {
		name string
		seed func(cacheTrustPolicyKey)
		want codes.Code
	}{
		{"successful policy read", func(k cacheTrustPolicyKey) { trustPolicies.Add(k, policy) }, codes.OK},
		{"missing policy read", func(k cacheTrustPolicyKey) { trustPolicies.Add(k, negativeCacheConst) }, codes.NotFound},
		{"forbidden policy read", func(k cacheTrustPolicyKey) { forbiddenPolicies.Add(k, struct{}{}) }, codes.PermissionDenied},
	} {
		t.Run(tc.name, func(t *testing.T) {
			key := freshTPKey(t, "late-joiner-"+tc.name)
			gh, counter := newFakeGitHubNotFoundCounter()
			atr := newAppsTransport(t, gh)
			tc.seed(key)

			got, err := (&sts{}).fetchTrustPolicyRawAfterCacheMiss(t.Context(), atr, 1234, key)
			if status.Code(err) != tc.want {
				t.Fatalf("fetchTrustPolicyRawAfterCacheMiss() = (%q, %v), want cached %v", got, err, tc.want)
			}
			if tc.want == codes.OK && got != policy {
				t.Fatalf("fetchTrustPolicyRawAfterCacheMiss() = %q, want cached policy %q", got, policy)
			}
			if calls := counter.Load(); calls != 0 {
				t.Errorf("late joiner made %d GitHub contents requests, want 0", calls)
			}
		})
	}
}

func newPolicyReadTransport(t *testing.T, read http.HandlerFunc) *ghinstallation.AppsTransport {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/app/installations/{appID}/access_tokens", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(github.InstallationToken{
			Token:     new("test-installation-token"),
			ExpiresAt: &github.Timestamp{Time: time.Now().Add(10 * time.Minute)},
		})
	})
	mux.HandleFunc("/repos/{org}/{repo}/contents/.github/chainguard/{identity}", read)
	mux.HandleFunc("/installation/token", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	return newAppsTransport(t, &fakeGitHub{mux: mux})
}

func TestConcurrentPolicyReadCannotCacheLate404OverSuccess(t *testing.T) {
	key := freshTPKey(t, "concurrent-policy-read")

	firstStarted := make(chan struct{})
	releaseSuccess := make(chan struct{})
	release404 := make(chan struct{})
	closeSuccess := sync.OnceFunc(func() { close(releaseSuccess) })
	close404 := sync.OnceFunc(func() { close(release404) })
	defer closeSuccess()
	defer close404()
	var contentReads atomic.Int32
	const policy = "issuer: https://example.com\nsubject: example\n"

	atr := newPolicyReadTransport(t, func(w http.ResponseWriter, _ *http.Request) {
		if contentReads.Add(1) == 1 {
			close(firstStarted)
			<-releaseSuccess
			_ = json.NewEncoder(w).Encode(github.RepositoryContent{
				Content:  new(base64.StdEncoding.EncodeToString([]byte(policy))),
				Type:     new("file"),
				Encoding: new("base64"),
			})
			return
		}
		// Before single-flight, a concurrent response from an earlier snapshot
		// could arrive after the 200 and replace it with a five-minute 404.
		<-release404
		writeGitHubNotFound(w)
	})
	s := &sts{}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	type result struct {
		raw string
		err error
	}
	first := make(chan result, 1)
	second := make(chan result, 1)
	go func() {
		raw, err := s.fetchTrustPolicyRaw(ctx, atr, 1234, key)
		first <- result{raw, err}
	}()
	select {
	case <-firstStarted:
	case <-ctx.Done():
		t.Fatal("first GitHub contents read did not start")
	}
	secondCtx := newFlightJoinObserver(ctx)
	go func() {
		raw, err := s.fetchTrustPolicyRaw(secondCtx, atr, 1234, key)
		second <- result{raw, err}
	}()
	select {
	case <-secondCtx.joined:
	case <-ctx.Done():
		t.Fatal("second policy read never joined the flight")
	}
	closeSuccess()
	gotFirst := <-first
	close404()
	gotSecond := <-second
	if gotFirst.err != nil || gotFirst.raw != policy || gotSecond.err != nil || gotSecond.raw != policy {
		t.Fatalf("concurrent reads = (%q, %v), (%q, %v); want shared policy", gotFirst.raw, gotFirst.err, gotSecond.raw, gotSecond.err)
	}
	if reads := contentReads.Load(); reads != 1 {
		t.Errorf("GitHub contents read %d times for the same miss, want 1", reads)
	}
	if cached, ok := trustPolicies.Get(key); !ok || cached != policy {
		t.Errorf("cache = (%q, %v), want successful policy (not a late 404)", cached, ok)
	}
}

// The flight key must carry the whole policy key. Two identities in the same
// repository that miss the cache together must each read their own policy;
// sharing one flight would hand one caller the other identity's policy.
func TestConcurrentPolicyReadsForDifferentIdentitiesDoNotShareFlight(t *testing.T) {
	keyA := freshTPKey(t, "identity-a")
	keyB := freshTPKey(t, "identity-b")
	started := make(chan struct{}, 2)
	release := make(chan struct{})
	closeRelease := sync.OnceFunc(func() { close(release) })
	defer closeRelease()
	policyFor := func(identity string) string {
		return "issuer: https://example.com\nsubject: " + identity + "\n"
	}
	read := func(w http.ResponseWriter, r *http.Request) {
		identity := strings.TrimSuffix(r.PathValue("identity"), ".sts.yaml")
		started <- struct{}{}
		<-release
		_ = json.NewEncoder(w).Encode(github.RepositoryContent{
			Content:  new(base64.StdEncoding.EncodeToString([]byte(policyFor(identity)))),
			Type:     new("file"),
			Encoding: new("base64"),
		})
	}
	s := &sts{}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	type result struct {
		raw string
		err error
	}
	results := make(map[string]chan result)
	atr := newPolicyReadTransport(t, read)
	for _, key := range []cacheTrustPolicyKey{keyA, keyB} {
		ch := make(chan result, 1)
		results[key.identity] = ch
		go func() {
			raw, err := s.fetchTrustPolicyRaw(ctx, atr, 1234, key)
			ch <- result{raw, err}
		}()
	}
	for range 2 {
		select {
		case <-started:
		case <-ctx.Done():
			t.Fatal("both identities must start their own GitHub read; one joined the other's flight")
		}
	}
	closeRelease()
	for identity, ch := range results {
		got := <-ch
		if got.err != nil || got.raw != policyFor(identity) {
			t.Errorf("read for %s = (%q, %v), want its own policy", identity, got.raw, got.err)
		}
	}
}

// Sharing a rate-limit result must still let each exchange rotate to a
// healthy installation. The next read is single-flighted too, so concurrent
// rotations do not amplify GitHub requests for the same policy.
func TestConcurrentPolicyReadRateLimitStillRotates(t *testing.T) {
	key := freshTPKey(t, "shared-rate-limit")
	started := make(chan struct{})
	release := make(chan struct{})
	signalStarted := sync.OnceFunc(func() { close(started) })
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	var limitedReads, healthyReads atomic.Int32
	limited := newPolicyReadTransport(t, func(w http.ResponseWriter, _ *http.Request) {
		limitedReads.Add(1)
		signalStarted()
		<-release
		w.Header().Set("X-RateLimit-Remaining", "0")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"message":"API rate limit exceeded"}`))
	})
	const policy = "issuer: https://example.com\nsubject: example\n"
	healthy := newPolicyReadTransport(t, func(w http.ResponseWriter, _ *http.Request) {
		healthyReads.Add(1)
		_ = json.NewEncoder(w).Encode(github.RepositoryContent{
			Content:  new(base64.StdEncoding.EncodeToString([]byte(policy))),
			Type:     new("file"),
			Encoding: new("base64"),
		})
	})
	pool := &ghinstall.OrgPool{M: &fakeInstallMgr{atr: healthy}, AppCount: 2}
	s := &sts{}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	results := make(chan error, 2)
	go func() {
		_, _, err := s.lookupTrustPolicyWithRetry(ctx, pool, limited, 100, "org", "org/repo", key.identity, key, &TrustPolicy{})
		results <- err
	}()
	select {
	case <-started:
	case <-ctx.Done():
		t.Fatal("rate-limited policy read did not start")
	}
	waiterCtx := newFlightJoinObserver(ctx)
	go func() {
		_, _, err := s.lookupTrustPolicyWithRetry(waiterCtx, pool, healthy, 200, "org", "org/repo", key.identity, key, &TrustPolicy{})
		results <- err
	}()
	select {
	case <-waiterCtx.joined:
	case <-ctx.Done():
		t.Fatal("second policy read never joined the flight")
	}
	close(release)
	for range 2 {
		if err := <-results; err != nil {
			t.Fatalf("policy read did not recover after rate-limit rotation: %v", err)
		}
	}
	if got := limitedReads.Load(); got != 1 {
		t.Errorf("rate-limited installation read %d times, want 1", got)
	}
	if got := healthyReads.Load(); got != 1 {
		t.Errorf("healthy installation read %d times, want 1", got)
	}
}

// The flight shares the policy read, never the authorization decision: each
// caller's token is checked against the shared policy after the flight, so a
// refactor that moved the authorize gate inside the flight would fail here.
func TestConcurrentCallersShareOneFlightButAuthorizeSeparately(t *testing.T) {
	key := freshTPKey(t, "authorize-gate")
	orgIssuers.Remove(key.owner)
	t.Cleanup(func() { orgIssuers.Remove(key.owner) })
	started := make(chan struct{})
	release := make(chan struct{})
	signalStarted := sync.OnceFunc(func() { close(started) })
	closeRelease := sync.OnceFunc(func() { close(release) })
	defer closeRelease()
	const allowed = "repo:org/repo:ref:refs/heads/main"
	const policy = "issuer: https://example.com\nsubject: " + allowed + "\n"
	var reads atomic.Int32
	atr := newPolicyReadTransport(t, func(w http.ResponseWriter, r *http.Request) {
		// The helper routes the org allowlist path here too; no allowlist applies.
		if strings.HasSuffix(r.URL.Path, OrgTrustedIssuersPath(DefaultPolicyDir)) {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"message":"Not Found"}`))
			return
		}
		reads.Add(1)
		signalStarted()
		<-release
		_ = json.NewEncoder(w).Encode(github.RepositoryContent{
			Content:  new(base64.StdEncoding.EncodeToString([]byte(policy))),
			Type:     new("file"),
			Encoding: new("base64"),
		})
	})
	pool := &ghinstall.OrgPool{M: &fakeInstallMgr{atr: atr}, AppCount: 1}
	s := &sts{router: ghinstall.NewOrgRouter(map[string]*ghinstall.OrgPool{"org": pool}), domain: "octo-sts.dev"}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	authorizeAs := func(sub string) func(*OrgTrustPolicy) error {
		tok := &oidc.IDToken{Issuer: "https://example.com", Subject: sub, Audience: []string{"octo-sts.dev"}}
		return func(otp *OrgTrustPolicy) error {
			_, err := otp.CheckToken(tok, s.domain)
			return err
		}
	}
	lookup := func(ctx context.Context, sub string) error {
		_, _, _, _, err := s.lookupInstallAndTrustPolicy(ctx, "org/repo", key.identity, sub, "https://example.com", authorizeAs(sub))
		return err
	}

	matching := make(chan error, 1)
	go func() { matching <- lookup(ctx, allowed) }()
	select {
	case <-started:
	case <-ctx.Done():
		t.Fatal("the first caller's policy read did not start")
	}
	waiterCtx := newFlightJoinObserver(ctx)
	mismatched := make(chan error, 1)
	go func() { mismatched <- lookup(waiterCtx, "repo:attacker/other:ref:refs/heads/main") }()
	select {
	case <-waiterCtx.joined:
	case <-ctx.Done():
		t.Fatal("the second caller never joined the flight")
	}
	closeRelease()

	if err := <-matching; err != nil {
		t.Errorf("matching caller: %v, want success", err)
	}
	if err := <-mismatched; status.Code(err) != codes.PermissionDenied {
		t.Errorf("mismatched caller: %v, want PermissionDenied from its own authorize gate", err)
	}
	if got := reads.Load(); got != 1 {
		t.Errorf("policy read %d times, want 1 shared flight", got)
	}
}

// flightJoinObserver reports when a policy-read caller is parked on the
// flight. The waiter's first call to Done is the select after DoChan has
// registered it, so the leader can be held until the join is certain.
type flightJoinObserver struct {
	context.Context
	once   sync.Once
	joined chan struct{}
}

func newFlightJoinObserver(ctx context.Context) *flightJoinObserver {
	return &flightJoinObserver{Context: ctx, joined: make(chan struct{})}
}

func (o *flightJoinObserver) Done() <-chan struct{} {
	o.once.Do(func() { close(o.joined) })
	return o.Context.Done()
}

func TestPolicyReadWaiterRereadsOnOwnInstallAfterForeignRateLimit(t *testing.T) {
	key := freshTPKey(t, "foreign-rate-limit")
	started := make(chan struct{})
	release := make(chan struct{})
	signalStarted := sync.OnceFunc(func() { close(started) })
	closeRelease := sync.OnceFunc(func() { close(release) })
	defer closeRelease()
	var limitedReads, healthyReads atomic.Int32
	limited := newPolicyReadTransport(t, func(w http.ResponseWriter, _ *http.Request) {
		limitedReads.Add(1)
		signalStarted()
		<-release
		w.Header().Set("X-RateLimit-Remaining", "0")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"message":"API rate limit exceeded"}`))
	})
	const policy = "issuer: https://example.com\nsubject: example\n"
	healthy := newPolicyReadTransport(t, func(w http.ResponseWriter, _ *http.Request) {
		healthyReads.Add(1)
		_ = json.NewEncoder(w).Encode(github.RepositoryContent{
			Content:  new(base64.StdEncoding.EncodeToString([]byte(policy))),
			Type:     new("file"),
			Encoding: new("base64"),
		})
	})
	// Rotation only ever hands out the limited installation, so the waiter
	// can recover only by re-reading on the healthy one it already holds.
	pool := &ghinstall.OrgPool{M: &fakeInstallMgr{atr: limited}, AppCount: 2}
	s := &sts{}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	leaderDone := make(chan error, 1)
	go func() {
		_, _, err := s.lookupTrustPolicyWithRetry(ctx, pool, limited, 100, "org", "org/repo", key.identity, key, &TrustPolicy{})
		leaderDone <- err
	}()
	select {
	case <-started:
	case <-ctx.Done():
		t.Fatal("rate-limited policy read did not start")
	}

	waiterCtx := newFlightJoinObserver(ctx)
	waiterDone := make(chan error, 1)
	go func() {
		_, _, err := s.lookupTrustPolicyWithRetry(waiterCtx, pool, healthy, 200, "org", "org/repo", key.identity, key, &TrustPolicy{})
		waiterDone <- err
	}()
	select {
	case <-waiterCtx.joined:
	case <-ctx.Done():
		t.Fatal("waiter never joined the flight")
	}
	closeRelease()

	if err := <-waiterDone; err != nil {
		t.Fatalf("waiter on a healthy installation = %v, want success", err)
	}
	<-leaderDone
	if got := healthyReads.Load(); got != 1 {
		t.Errorf("healthy installation read %d times, want 1", got)
	}
	if got := limitedReads.Load(); got < 1 || got > 2 {
		t.Errorf("limited installation read %d times, want 1 (leader) or 2 (leader plus its rotation)", got)
	}
}

func TestPolicyReadLeaderKeepsItsOwnRateLimit(t *testing.T) {
	key := freshTPKey(t, "own-rate-limit")
	var reads atomic.Int32
	limited := newPolicyReadTransport(t, func(w http.ResponseWriter, _ *http.Request) {
		reads.Add(1)
		w.Header().Set("X-RateLimit-Remaining", "0")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"message":"API rate limit exceeded"}`))
	})
	_, err := (&sts{}).fetchTrustPolicyRaw(t.Context(), limited, 100, key)
	if got := status.Code(err); got != codes.ResourceExhausted {
		t.Fatalf("code = %v, want ResourceExhausted; err = %v", got, err)
	}
	if got := reads.Load(); got != 1 {
		t.Errorf("GitHub read %d times, want 1: a leader must not re-read on its own rate limit", got)
	}
}

func TestPolicyReadFlightSurvivesFirstCallerCancellation(t *testing.T) {
	key := freshTPKey(t, "policy-after-cancel")
	started := make(chan struct{})
	release := make(chan struct{})
	closeRelease := sync.OnceFunc(func() { close(release) })
	defer closeRelease()
	var reads atomic.Int32
	const policy = "issuer: https://example.com\nsubject: example\n"
	atr := newPolicyReadTransport(t, func(w http.ResponseWriter, _ *http.Request) {
		if reads.Add(1) == 1 {
			close(started)
		}
		<-release
		_ = json.NewEncoder(w).Encode(github.RepositoryContent{
			Content:  new(base64.StdEncoding.EncodeToString([]byte(policy))),
			Type:     new("file"),
			Encoding: new("base64"),
		})
	})
	s := &sts{}
	leaderCtx, cancelLeader := context.WithCancel(t.Context())
	defer cancelLeader()
	waiterCtx, cancelWaiter := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancelWaiter()
	leaderResult := make(chan error, 1)
	waiterResult := make(chan error, 1)
	go func() {
		_, err := s.fetchTrustPolicyRaw(leaderCtx, atr, 1234, key)
		leaderResult <- err
	}()
	select {
	case <-started:
	case <-waiterCtx.Done():
		t.Fatal("shared read did not start")
	}
	go func() {
		raw, err := s.fetchTrustPolicyRaw(waiterCtx, atr, 1234, key)
		if err == nil && raw != policy {
			err = fmt.Errorf("shared read returned %q, want %q", raw, policy)
		}
		waiterResult <- err
	}()
	cancelLeader()
	if err := <-leaderResult; status.Code(err) != codes.Canceled {
		t.Errorf("canceled caller got %v, want Canceled", err)
	}
	closeRelease()
	if err := <-waiterResult; err != nil {
		t.Fatalf("waiter lost the shared read: %v", err)
	}
	if got := reads.Load(); got != 1 {
		t.Errorf("GitHub contents read %d times, want 1", got)
	}
}

func TestPolicyReadTimeoutIsUnavailableNotCallerDeadline(t *testing.T) {
	key := freshTPKey(t, "policy-read-timeout")
	orig := policyReadTimeout
	policyReadTimeout = time.Second
	t.Cleanup(func() { policyReadTimeout = orig })

	var reads atomic.Int32
	atr := newPolicyReadTransport(t, func(_ http.ResponseWriter, r *http.Request) {
		reads.Add(1)
		<-r.Context().Done()
	})
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	_, err := (&sts{}).fetchTrustPolicyRaw(ctx, atr, 1234, key)
	if got := status.Code(err); got != codes.Unavailable {
		t.Fatalf("code = %v, want Unavailable (the caller never gave up); err = %v", got, err)
	}
	if ctx.Err() != nil {
		t.Fatal("caller context expired; the shared timeout was not what ended the read")
	}
	if got := reads.Load(); got != 1 {
		t.Errorf("GitHub contents read %d times, want 1", got)
	}
	if _, ok := trustPolicies.Get(key); ok {
		t.Error("a timed-out read must not populate the policy cache")
	}
	if _, ok := forbiddenPolicies.Get(key); ok {
		t.Error("a timed-out read must not populate the forbidden cooldown")
	}
}

func TestPolicyReadTimeoutRevokesMintedToken(t *testing.T) {
	key := freshTPKey(t, "policy-read-timeout-revocation")
	orig := policyReadTimeout
	policyReadTimeout = time.Second
	t.Cleanup(func() { policyReadTimeout = orig })

	var mintCalls, contentsCalls, revokeCalls atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/app/installations/{appID}/access_tokens", func(w http.ResponseWriter, _ *http.Request) {
		mintCalls.Add(1)
		_ = json.NewEncoder(w).Encode(github.InstallationToken{
			Token:     new("timeout-test-token"),
			ExpiresAt: &github.Timestamp{Time: time.Now().Add(10 * time.Minute)},
		})
	})
	mux.HandleFunc("/api/v3/repos/{org}/{repo}/contents/.github/chainguard/{identity}", func(_ http.ResponseWriter, r *http.Request) {
		contentsCalls.Add(1)
		<-r.Context().Done()
	})
	mux.HandleFunc("/installation/token", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete || r.Header.Get("Authorization") != "Bearer timeout-test-token" {
			t.Errorf("unexpected revocation request: %s %s", r.Method, r.Header.Get("Authorization"))
		}
		revokeCalls.Add(1)
		w.WriteHeader(http.StatusNoContent)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	signer := ghinstallation.NewRSASigner(jwt.SigningMethodRS256, sharedAppKey())
	atr, err := ghinstallation.NewAppsTransportWithOptions(http.DefaultTransport, 1234, ghinstallation.WithSigner(signer))
	if err != nil {
		t.Fatal(err)
	}
	atr.BaseURL = srv.URL

	_, err = (&sts{baseURL: srv.URL}).fetchTrustPolicyRaw(t.Context(), atr, 1234, key)
	if got := status.Code(err); got != codes.Unavailable {
		t.Fatalf("timed-out read = %v, want Unavailable", err)
	}
	if got := mintCalls.Load(); got != 1 {
		t.Errorf("token mint requests = %d, want 1", got)
	}
	if got := contentsCalls.Load(); got != 1 {
		t.Errorf("contents requests = %d, want 1", got)
	}
	if got := revokeCalls.Load(); got != 1 {
		t.Errorf("token revocations = %d, want 1 even after the read deadline", got)
	}
}

func TestPolicyReadFailedMintDoesNotMintForRevocation(t *testing.T) {
	key := freshTPKey(t, "failed-mint")
	var mintCalls, contentsCalls atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/app/installations/{appID}/access_tokens", func(w http.ResponseWriter, _ *http.Request) {
		mintCalls.Add(1)
		w.WriteHeader(http.StatusUnprocessableEntity)
		_, _ = w.Write([]byte(`{"message":"invalid installation"}`))
	})
	mux.HandleFunc("/repos/{org}/{repo}/contents/.github/chainguard/{identity}", func(w http.ResponseWriter, _ *http.Request) {
		contentsCalls.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	})
	atr := newAppsTransport(t, &fakeGitHub{mux: mux})
	if _, err := (&sts{}).fetchTrustPolicyRaw(t.Context(), atr, 1234, key); err == nil {
		t.Fatal("expected failed token mint to fail the policy read")
	}
	if got := mintCalls.Load(); got != 1 {
		t.Errorf("token mint requests = %d, want 1 (no second mint solely for cleanup)", got)
	}
	if got := contentsCalls.Load(); got != 0 {
		t.Errorf("contents requests = %d, want 0 without a token", got)
	}
}

// Single-flight only protects concurrent cache writers. A first (possibly
// transient) 404 is still shared and cached for five minutes, preserving
// #1334's quota tradeoff; recovering a newly visible policy is separate.
func TestPolicyReadFirst404StillUsesNegativeCache(t *testing.T) {
	key := freshTPKey(t, "first-404")
	started := make(chan struct{})
	release := make(chan struct{})
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	var reads atomic.Int32
	atr := newPolicyReadTransport(t, func(w http.ResponseWriter, _ *http.Request) {
		if reads.Add(1) == 1 {
			close(started)
			<-release
			writeGitHubNotFound(w)
			return
		}
		_ = json.NewEncoder(w).Encode(github.RepositoryContent{
			Content:  new(base64.StdEncoding.EncodeToString([]byte("new policy"))),
			Type:     new("file"),
			Encoding: new("base64"),
		})
	})
	s := &sts{}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	results := make(chan error, 2)
	go func() {
		_, err := s.fetchTrustPolicyRaw(ctx, atr, 1234, key)
		results <- err
	}()
	select {
	case <-started:
	case <-ctx.Done():
		t.Fatal("first policy read did not start")
	}
	secondCtx := newFlightJoinObserver(ctx)
	go func() {
		_, err := s.fetchTrustPolicyRaw(secondCtx, atr, 1234, key)
		results <- err
	}()
	select {
	case <-secondCtx.joined:
	case <-ctx.Done():
		t.Fatal("second policy read never joined the flight")
	}
	close(release)
	for range 2 {
		err := <-results
		if got := status.Code(err); got != codes.NotFound {
			t.Fatalf("policy read = %v, want NotFound", err)
		}
	}
	// Even though the next GitHub response would be 200, the first 404 is
	// cached; this PR must not add a GET for each concurrent caller.
	if _, err := s.fetchTrustPolicyRaw(ctx, atr, 1234, key); status.Code(err) != codes.NotFound {
		t.Fatalf("cached policy read = %v, want NotFound", err)
	}
	if got := reads.Load(); got != 1 {
		t.Errorf("contents requests = %d, want 1 (no retry of genuine missing policies)", got)
	}
}

func TestNegativeCacheSkipsInstallationTokenCreation(t *testing.T) {
	key := cacheTrustPolicyKey{owner: "org", repo: "repo", identity: "cached-missing"}
	trustPolicies.Add(key, negativeCacheConst)
	t.Cleanup(func() { trustPolicies.Remove(key) })

	pool := &ghinstall.OrgPool{M: &failInstallMgr{}, AppCount: 1}
	s := &sts{router: ghinstall.NewOrgRouter(map[string]*ghinstall.OrgPool{"org": pool})}

	_, _, _, _, err := s.lookupInstallAndTrustPolicy(context.Background(), "org/repo", "cached-missing", "some-subject", testGitHubIssuer, func(*OrgTrustPolicy) error {
		t.Fatal("authorize called for a negatively cached policy")
		return nil
	})
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
		Scopes:   []string{"other-org/repo"},
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
		Scopes:   []string{"org/repo"},
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
		Scopes:   []string{"other-org/repo"},
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
		DialTLSContext: func(_ context.Context, network, addr string) (net.Conn, error) {
			return tls.Dial(network, strings.TrimPrefix(srv.URL, "https://"), tlsConfig)
		},
		DialContext: func(_ context.Context, network, addr string) (net.Conn, error) {
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
	// Shared by the pin tests in this package, which configure apps 101
	// (ci-a), 102 (ci-b), 103 (ci-c, from pin_order_test.go and
	// pin_snapshot_test.go), and 201 (deploy), so mark them all as pool
	// members. eligibleApps fails closed on a nil AppIDs map, and production
	// always sets it, so the pool must set it here too.
	return &ghinstall.OrgPool{M: m, AppCount: 3, AppIDs: map[int64]bool{101: true, 102: true, 103: true, 201: true}}
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

	t.Run("confirmation walk timeout surfaces as Unavailable", func(t *testing.T) {
		pinMisses.Purge()
		mgr := &enumMgr{freshErr: status.Error(codes.DeadlineExceeded, "context deadline exceeded")}
		s := &sts{apps: AppSet{Names: appNames, IDs: appIDs}}
		tp := compile(t, &TrustPolicy{App: "deploy"})
		if _, _, err := s.getExchangeInstall(ctx, poolOf(mgr), "timeoutorg", "timeoutorg/repo", "id", "subj", tp, nil, 999); status.Code(err) != codes.Unavailable {
			t.Fatalf("got %v, want Unavailable for the walk's own timeout", err)
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
		// ghost/301 is a pool member but has no installation, so the pin must
		// reach installation enumeration and fail there, not on membership.
		ghostPool := &ghinstall.OrgPool{M: pool.M, AppCount: 3, AppIDs: map[int64]bool{301: true}}
		_, err := exchange(t, s, ghostPool, compile(t, &TrustPolicy{App: "ghost"}))
		if status.Code(err) != codes.FailedPrecondition {
			t.Fatalf("got %v, want FailedPrecondition", err)
		}
	})

	assertRotates := func(t *testing.T, s *sts, pool *ghinstall.OrgPool, tp *TrustPolicy) {
		t.Helper()
		seen := map[int64]bool{}
		for range 4 {
			id, err := exchange(t, s, pool, tp)
			if err != nil {
				t.Fatal(err)
			}
			if id != 11 && id != 12 {
				t.Fatalf("got %d, want a ci install", id)
			}
			seen[id] = true
		}
		if !seen[11] || !seen[12] {
			t.Fatalf("picks welded to %v, want rotation across both ci installs", seen)
		}
	}

	t.Run("pattern pin rotates across candidates without quota data", func(t *testing.T) {
		s := &sts{apps: AppSet{Names: appNames, IDs: appIDs}}
		assertRotates(t, s, pool, compile(t, &TrustPolicy{AppPattern: "ci-.*"}))
	})

	t.Run("pattern pin prefers quota headroom", func(t *testing.T) {
		qstore := ghinstall.NewQuotaStore(time.Minute)
		qstore.Update(11, 100, 15000)
		qstore.Update(12, 12000, 15000)
		qpool := &ghinstall.OrgPool{M: pool.M, AppCount: 3, AppIDs: appIDs, Quota: &ghinstall.QuotaConfig{Store: qstore, SoftFloor: 5000, HardFloor: 1500}}
		s := &sts{apps: AppSet{Names: appNames, IDs: appIDs}}
		id, err := exchange(t, s, qpool, compile(t, &TrustPolicy{AppPattern: "ci-.*"}))
		if err != nil || id != 12 {
			t.Fatalf("got (%d, %v), want headroom pick (12, nil)", id, err)
		}
	})

	t.Run("sticky pin ignores quota for deterministic assignment", func(t *testing.T) {
		idx := routekey.Index("org/repo", "id", "subj", 2)
		expected := []int64{11, 12}[idx]
		other := []int64{12, 11}[idx]
		qstore := ghinstall.NewQuotaStore(time.Minute)
		// Quota argmax favors the OTHER install; sticky assignment must stay
		// deterministic so concurrent replicas agree.
		qstore.Update(expected, 100, 15000)
		qstore.Update(other, 14000, 15000)
		qpool := &ghinstall.OrgPool{M: pool.M, AppCount: 3, AppIDs: appIDs, Quota: &ghinstall.QuotaConfig{Store: qstore, SoftFloor: 5000, HardFloor: 1500}}
		s := &sts{apps: AppSet{Names: appNames, IDs: appIDs}, sticky: memory.New()}
		tp := compile(t, &TrustPolicy{AppPattern: "ci-.*", Permissions: checksWrite})
		id, err := exchange(t, s, qpool, tp)
		if err != nil || id != expected {
			t.Fatalf("got (%d, %v), want deterministic (%d, nil) despite quota favoring %d", id, err, expected, other)
		}
		again, err := exchange(t, s, qpool, tp)
		if err != nil || again != expected {
			t.Fatalf("got (%d, %v), want sticky %d", again, err, expected)
		}
	})

	t.Run("checks:write pin stays deterministic without a sticky store", func(t *testing.T) {
		idx := routekey.Index("org/repo", "id", "subj", 2)
		expected := []int64{11, 12}[idx]
		other := []int64{12, 11}[idx]
		qstore := ghinstall.NewQuotaStore(time.Minute)
		qstore.Update(expected, 100, 15000)
		qstore.Update(other, 14000, 15000)
		qpool := &ghinstall.OrgPool{M: pool.M, AppCount: 3, AppIDs: appIDs, Quota: &ghinstall.QuotaConfig{Store: qstore, SoftFloor: 5000, HardFloor: 1500}}
		// No sticky store configured: determinism must hold anyway so
		// check-run ownership stays on one app.
		s := &sts{apps: AppSet{Names: appNames, IDs: appIDs}}
		tp := compile(t, &TrustPolicy{AppPattern: "ci-.*", Permissions: checksWrite})
		for range 3 {
			id, err := exchange(t, s, qpool, tp)
			if err != nil || id != expected {
				t.Fatalf("got (%d, %v), want deterministic (%d, nil) despite quota favoring %d", id, err, expected, other)
			}
		}
	})

	t.Run("pattern pin rotates when quota data is incomplete", func(t *testing.T) {
		qstore := ghinstall.NewQuotaStore(time.Minute)
		// Install 12 has no quota data: all-or-nothing disables quota picking.
		qstore.Update(11, 12000, 15000)
		qpool := &ghinstall.OrgPool{M: pool.M, AppCount: 3, AppIDs: appIDs, Quota: &ghinstall.QuotaConfig{Store: qstore, SoftFloor: 5000, HardFloor: 1500}}
		s := &sts{apps: AppSet{Names: appNames, IDs: appIDs}}
		assertRotates(t, s, qpool, compile(t, &TrustPolicy{AppPattern: "ci-.*"}))
	})

	t.Run("storeless checks:write pin rejects partial candidate sets", func(t *testing.T) {
		partial := poolOf(&enumMgr{
			installs: []ghinstall.Installation{{ID: 11, AppID: 101}},
			err:      errors.New("enumeration failed"),
		})
		s := &sts{apps: AppSet{Names: appNames, IDs: appIDs}}
		tp := compile(t, &TrustPolicy{AppPattern: "ci-.*", Permissions: checksWrite})
		_, err := exchange(t, s, partial, tp)
		if err == nil || status.Code(err) == codes.FailedPrecondition {
			t.Fatalf("got %v, want the raw enumeration error (a partial set is not a stable routing set)", err)
		}
	})

	t.Run("storeless checks:write pin heals negative-cache omissions before hashing", func(t *testing.T) {
		pinMisses.Purge()
		// GetAll omits install 12 behind a nil error; the fresh confirm must
		// complete the set before the ownership hash.
		mgr := &enumMgr{
			installs:      []ghinstall.Installation{{ID: 11, AppID: 101}},
			freshInstalls: []ghinstall.Installation{{ID: 11, AppID: 101}, {ID: 12, AppID: 102}},
		}
		s := &sts{apps: AppSet{Names: appNames, IDs: appIDs}}
		tp := compile(t, &TrustPolicy{AppPattern: "ci-.*", Permissions: checksWrite})
		expected := []int64{11, 12}[routekey.Index("healorg/repo", "id", "subj", 2)]
		_, id, err := s.getExchangeInstall(ctx, poolOf(mgr), "healorg", "healorg/repo", "id", "subj", tp, nil, 999)
		if err != nil || id != expected {
			t.Fatalf("got (%d, %v), want (%d, nil) hashed over the healed set", id, err, expected)
		}
		if got := mgr.freshCalls.Load(); got != 1 {
			t.Errorf("GetAllFresh called %d times, want 1", got)
		}
	})

	t.Run("storeless checks:write pin throttles confirmed-incomplete sets", func(t *testing.T) {
		pinMisses.Purge()
		// The fresh walk confirms the pattern genuinely matches only one
		// installed app: hash the confirmed set and stop re-walking.
		mgr := &enumMgr{
			installs:      []ghinstall.Installation{{ID: 11, AppID: 101}},
			freshInstalls: []ghinstall.Installation{{ID: 11, AppID: 101}},
		}
		s := &sts{apps: AppSet{Names: appNames, IDs: appIDs}}
		tp := compile(t, &TrustPolicy{AppPattern: "ci-.*", Permissions: checksWrite})
		for i := range 3 {
			_, id, err := s.getExchangeInstall(ctx, poolOf(mgr), "incorg", "incorg/repo", "id", "subj", tp, nil, 999)
			if err != nil || id != 11 {
				t.Fatalf("call %d: got (%d, %v), want (11, nil)", i, id, err)
			}
		}
		if got := mgr.freshCalls.Load(); got != 1 {
			t.Errorf("GetAllFresh called %d times, want 1 (confirmed incompleteness cached)", got)
		}
	})

	t.Run("pattern rotation is isolated per candidate set", func(t *testing.T) {
		s := &sts{apps: AppSet{Names: appNames, IDs: appIDs}}
		exactTP := compile(t, &TrustPolicy{App: "deploy"})
		patternTP := compile(t, &TrustPolicy{AppPattern: "ci-.*"})
		seen := map[int64]bool{}
		for range 10 {
			// The interleaved singleton pin must not phase-lock the
			// pattern's rotation.
			if _, err := exchange(t, s, pool, exactTP); err != nil {
				t.Fatal(err)
			}
			id, err := exchange(t, s, pool, patternTP)
			if err != nil {
				t.Fatal(err)
			}
			seen[id] = true
		}
		if !seen[11] || !seen[12] {
			t.Fatalf("pattern picks welded to %v under interleaving, want rotation across both", seen)
		}
	})

	t.Run("storeless checks:write pin tolerates partial enumeration when the eligible set is complete", func(t *testing.T) {
		partial := poolOf(&enumMgr{
			installs: []ghinstall.Installation{{ID: 11, AppID: 101}, {ID: 12, AppID: 102}},
			err:      errors.New("unrelated manager failed"),
		})
		s := &sts{apps: AppSet{Names: appNames, IDs: appIDs}}
		tp := compile(t, &TrustPolicy{AppPattern: "ci-.*", Permissions: checksWrite})
		expected := []int64{11, 12}[routekey.Index("org/repo", "id", "subj", 2)]
		for range 3 {
			id, err := exchange(t, s, partial, tp)
			if err != nil || id != expected {
				t.Fatalf("got (%d, %v), want deterministic (%d, nil): a complete eligible set cannot flip", id, err, expected)
			}
		}
	})

	t.Run("pattern alternation stays anchored", func(t *testing.T) {
		s := &sts{apps: AppSet{Names: map[string]int64{"ci": 1, "deploy": 2, "ci-privileged": 3}}}
		tp := compile(t, &TrustPolicy{AppPattern: "ci|deploy"})
		anchorPool := &ghinstall.OrgPool{AppIDs: map[int64]bool{1: true, 2: true, 3: true}}
		eligible, err := s.eligibleApps(anchorPool, "org", tp)
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

	t.Run("sticky proven ineligible fails closed on partial enumeration", func(t *testing.T) {
		store := seedSticky(t, 21)
		// Install 21 is enumerated (proving it ineligible for ci-.*), but an
		// unrelated manager failed: reassigning over the partial set could
		// diverge from a replica holding the complete set.
		partial := poolOf(&enumMgr{
			installs: []ghinstall.Installation{{ID: 11, AppID: 101}, {ID: 21, AppID: 201}},
			err:      errors.New("unrelated manager failed"),
		})
		s := &sts{apps: AppSet{Names: appNames, IDs: appIDs}, sticky: store}
		_, err := exchange(t, s, partial, compile(t, &TrustPolicy{AppPattern: "ci-.*", Permissions: checksWrite}))
		if err == nil || status.Code(err) == codes.FailedPrecondition {
			t.Fatalf("got %v, want the raw enumeration error (no reassignment over a partial set)", err)
		}
		if cached, ok, _ := store.Get(ctx, stickyKey); !ok || cached != 21 {
			t.Fatalf("sticky = (%d, %t), want preserved (21, true)", cached, ok)
		}
	})

	t.Run("fresh partial proof of ineligibility fails closed", func(t *testing.T) {
		store := seedSticky(t, 21)
		// The fresh walk proves 21 ineligible but is itself partial: its
		// error now travels with the swapped candidate set, so the pick
		// fails closed instead of hashing a subset.
		hidden := poolOf(&enumMgr{
			installs:      []ghinstall.Installation{{ID: 11, AppID: 101}},
			freshInstalls: []ghinstall.Installation{{ID: 11, AppID: 101}, {ID: 21, AppID: 201}},
			freshErr:      errors.New("unrelated manager failed"),
		})
		s := &sts{apps: AppSet{Names: appNames, IDs: appIDs}, sticky: store}
		_, err := exchange(t, s, hidden, compile(t, &TrustPolicy{AppPattern: "ci-.*", Permissions: checksWrite}))
		if err == nil || status.Code(err) == codes.FailedPrecondition {
			t.Fatalf("got %v, want the fresh walk's error (no reassignment over a partial set)", err)
		}
		if cached, ok, _ := store.Get(ctx, stickyKey); !ok || cached != 21 {
			t.Fatalf("sticky = (%d, %t), want preserved (21, true)", cached, ok)
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
