// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package octosts

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"slices"
	"strconv"
	"sync"
	"testing"
	"time"

	v1 "chainguard.dev/sdk/proto/platform/oidc/v1"
	"github.com/bradleyfalzon/ghinstallation/v2"
	"github.com/google/go-github/v88/github"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/octo-sts/app/pkg/ghinstall"
)

// fakePolicySource serves policies from memory, keyed "owner/repo/identity",
// and records each request.
type fakePolicySource struct {
	mu       sync.Mutex
	policies map[string]string
	issuers  map[string]*IssuerAllowlist
	err      error // returned by every call when set
	install  ghinstall.Installation
	requests []TrustPolicyRequest
}

func (f *fakePolicySource) TrustPolicy(_ context.Context, req TrustPolicyRequest) (TrustPolicyResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests = append(f.requests, req)
	if f.err != nil {
		return TrustPolicyResult{}, f.err
	}
	raw, ok := f.policies[req.Owner+"/"+req.Repo+"/"+req.Identity]
	if !ok {
		return TrustPolicyResult{}, TrustPolicyNotFound(req.Identity)
	}
	return TrustPolicyResult{Raw: []byte(raw), Install: f.install}, nil
}

func (f *fakePolicySource) OrgTrustedIssuers(_ context.Context, owner string) (*IssuerAllowlist, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.issuers[owner], nil
}

// mintOnlyGitHub mints installation tokens (each token is the base64 of the
// mint request) and fails the test on any other request, in particular a
// policy or allowlist read, which a non-GitHub source must never cause.
type mintOnlyGitHub struct {
	t       *testing.T
	mu      sync.Mutex
	minters []int64 // installation IDs that minted, in order
}

func (g *mintOnlyGitHub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /app/installations/{id}/access_tokens", func(w http.ResponseWriter, r *http.Request) {
		id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		b, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		g.mu.Lock()
		g.minters = append(g.minters, id)
		g.mu.Unlock()
		json.NewEncoder(w).Encode(github.InstallationToken{ //nolint:errcheck
			Token:     new(base64.StdEncoding.EncodeToString(b)),
			ExpiresAt: &github.Timestamp{Time: time.Now().Add(10 * time.Minute)},
		})
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		g.t.Errorf("unexpected GitHub request: %s %s", r.Method, r.URL.Path)
		w.WriteHeader(http.StatusNotImplemented)
	})
	mux.ServeHTTP(w, r)
}

func (g *mintOnlyGitHub) mintedBy() []int64 {
	g.mu.Lock()
	defer g.mu.Unlock()
	return slices.Clone(g.minters)
}

// mintOptions decodes the mint request carried by a mintOnlyGitHub token.
func mintOptions(t *testing.T, token string) github.InstallationTokenOptions {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(token)
	if err != nil {
		t.Fatalf("decoding token: %v", err)
	}
	var opts github.InstallationTokenOptions
	if err := json.Unmarshal(b, &opts); err != nil {
		t.Fatalf("decoding mint options: %v", err)
	}
	return opts
}

const sourcePolicy = `
issuer: https://token.actions.githubusercontent.com
subject: foo
audience: octosts
permissions:
  contents: read
`

func newSourceSTS(t *testing.T, src PolicySource) (*sts, *mintOnlyGitHub, *ghinstallation.AppsTransport) {
	t.Helper()
	gh := &mintOnlyGitHub{t: t}
	atr := newAppsTransport(t, gh)
	s := NewSecurityTokenServiceServer(routerFor(&fakeInstallMgr{atr: atr}, 1), nil, AppSet{}, nil, "octosts", false, "", "", "", nil, false, false, WithPolicySource(src)).(*sts)
	return s, gh, atr
}

func TestPolicySourceRepoScopedExchange(t *testing.T) {
	src := &fakePolicySource{policies: map[string]string{"srcorg/repo/foo": sourcePolicy}}
	s, gh, _ := newSourceSTS(t, src)

	tok, err := s.Exchange(newExchangeContext(t), &v1.ExchangeRequest{Identity: "foo", Scopes: []string{"srcorg/repo"}})
	if err != nil {
		t.Fatalf("Exchange() = %v", err)
	}

	opts := mintOptions(t, tok.GetToken())
	if want := []string{"repo"}; !slices.Equal(opts.Repositories, want) {
		t.Errorf("minted repositories = %v, want %v", opts.Repositories, want)
	}
	if opts.Permissions == nil || opts.Permissions.GetContents() != "read" {
		t.Errorf("minted permissions = %+v, want contents: read", opts.Permissions)
	}
	if got, want := gh.mintedBy(), []int64{1234}; !slices.Equal(got, want) {
		t.Errorf("minted by installations %v, want %v (the one the STS picked)", got, want)
	}

	if len(src.requests) != 1 {
		t.Fatalf("source got %d requests, want 1", len(src.requests))
	}
	req := src.requests[0]
	if req.Owner != "srcorg" || req.Repo != "repo" || req.Identity != "foo" || req.Scope != "srcorg/repo" {
		t.Errorf("request = %+v, want srcorg/repo/foo for scope srcorg/repo", req)
	}
	if req.Pool == nil || req.Install.ID != 1234 || req.Install.Transport == nil {
		t.Errorf("request pool/install = %v/%+v, want the org pool and installation 1234", req.Pool, req.Install)
	}
}

func TestPolicySourceOrgScopedExchange(t *testing.T) {
	// An org-scoped request reads from the org policy repository and parses
	// the policy as an org policy, so repositories is accepted.
	src := &fakePolicySource{policies: map[string]string{
		"srcorg/.github/foo": sourcePolicy + "repositories:\n  - a\n  - b\n",
	}}
	s, _, _ := newSourceSTS(t, src)

	tok, err := s.Exchange(newExchangeContext(t), &v1.ExchangeRequest{Identity: "foo", Scopes: []string{"srcorg"}})
	if err != nil {
		t.Fatalf("Exchange() = %v", err)
	}
	if got, want := mintOptions(t, tok.GetToken()).Repositories, []string{"a", "b"}; !slices.Equal(got, want) {
		t.Errorf("minted repositories = %v, want %v", got, want)
	}
	if got := src.requests[0].Repo; got != ".github" {
		t.Errorf("request repo = %q, want the org policy repo .github", got)
	}
}

func TestPolicySourceMintsWithReturnedInstallation(t *testing.T) {
	src := &fakePolicySource{policies: map[string]string{"srcorg/repo/foo": sourcePolicy}}
	s, gh, atr := newSourceSTS(t, src)
	// Same transport, different installation: the mint must follow the result.
	src.install = ghinstall.Installation{Transport: atr, ID: 5678}

	if _, err := s.Exchange(newExchangeContext(t), &v1.ExchangeRequest{Identity: "foo", Scopes: []string{"srcorg/repo"}}); err != nil {
		t.Fatalf("Exchange() = %v", err)
	}
	if got, want := gh.mintedBy(), []int64{5678}; !slices.Equal(got, want) {
		t.Errorf("minted by installations %v, want %v (the one the source returned)", got, want)
	}
}

func TestPolicySourceErrors(t *testing.T) {
	enforce, err := ParseOrgTrustedIssuers([]byte("issuers:\n  - https://other.example.com\n"))
	if err != nil {
		t.Fatal(err)
	}
	audit, err := ParseOrgTrustedIssuers([]byte("mode: audit\nissuers:\n  - https://other.example.com\n"))
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name     string
		src      *fakePolicySource
		wantCode codes.Code
		wantMsg  string
	}{{
		name:     "missing policy",
		src:      &fakePolicySource{},
		wantCode: codes.NotFound,
		wantMsg:  `unable to find trust policy for "foo"`,
	}, {
		name:     "unparseable policy looks missing",
		src:      &fakePolicySource{policies: map[string]string{"srcorg/repo/foo": "not: [valid"}},
		wantCode: codes.NotFound,
		wantMsg:  `unable to find trust policy for "foo"`,
	}, {
		name:     "policy failing compile looks missing",
		src:      &fakePolicySource{policies: map[string]string{"srcorg/repo/foo": "subject: foo\n"}},
		wantCode: codes.NotFound,
		wantMsg:  `unable to find trust policy for "foo"`,
	}, {
		name:     "token not matching policy",
		src:      &fakePolicySource{policies: map[string]string{"srcorg/repo/foo": "issuer: https://token.actions.githubusercontent.com\nsubject: bar\naudience: octosts\n"}},
		wantCode: codes.PermissionDenied,
	}, {
		name:     "source error fails closed",
		src:      &fakePolicySource{err: status.Error(codes.Unavailable, "store down")},
		wantCode: codes.Unavailable,
	}, {
		name: "enforcing allowlist denies unlisted issuer",
		src: &fakePolicySource{
			policies: map[string]string{"srcorg/repo/foo": sourcePolicy},
			issuers:  map[string]*IssuerAllowlist{"srcorg": enforce},
		},
		wantCode: codes.PermissionDenied,
		wantMsg:  msgIssuerNotPermitted,
	}, {
		name: "audit allowlist permits unlisted issuer",
		src: &fakePolicySource{
			policies: map[string]string{"srcorg/repo/foo": sourcePolicy},
			issuers:  map[string]*IssuerAllowlist{"srcorg": audit},
		},
		wantCode: codes.OK,
	}} {
		t.Run(tc.name, func(t *testing.T) {
			s, _, _ := newSourceSTS(t, tc.src)
			_, err := s.Exchange(newExchangeContext(t), &v1.ExchangeRequest{Identity: "foo", Scopes: []string{"srcorg/repo"}})
			st := status.Convert(err)
			if st.Code() != tc.wantCode {
				t.Fatalf("Exchange() = %v, want code %v", err, tc.wantCode)
			}
			if tc.wantMsg != "" && st.Message() != tc.wantMsg {
				t.Errorf("message = %q, want %q", st.Message(), tc.wantMsg)
			}
		})
	}
}

func TestPolicySourceDefaultsToGitHub(t *testing.T) {
	for _, tc := range []struct {
		name string
		opts []Option
	}{
		{name: "no option"},
		{name: "nil source", opts: []Option{WithPolicySource(nil)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := NewSecurityTokenServiceServer(nil, nil, AppSet{}, nil, "", false, "", "", "", nil, false, false, tc.opts...).(*sts)
			if _, ok := s.policySource().(githubPolicySource); !ok {
				t.Errorf("policySource() = %T, want githubPolicySource", s.policySource())
			}
		})
	}
}

func TestGitHubSourceRejectsEntriesWithoutPayload(t *testing.T) {
	// Present without an allowlist, or Invalid without an error, must never
	// read as "no allowlist", which would permit every issuer.
	for _, e := range []orgIssuerEntry{
		{},
		{state: orgIssuerPresent},
		{state: orgIssuerInvalid},
	} {
		const owner = "payloadless"
		cleanupOrgIssuers(t, owner)
		orgIssuers.Add(owner, e)

		allow, err := githubPolicySource{s: &sts{}}.OrgTrustedIssuers(t.Context(), owner)
		if allow != nil || status.Code(err) != codes.Internal {
			t.Errorf("entry %v: OrgTrustedIssuers() = %v, %v; want nil, Internal", e.state, allow, err)
		}
	}
}
