// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package octosts

import (
	"bytes"
	"cmp"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"
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

// fakePolicySource serves policies from memory, keyed exactly
// "owner/repo/identity", and records each request. Exact keys are deliberate:
// the STS, not the source, is responsible for lowercasing names.
type fakePolicySource struct {
	mu         sync.Mutex
	policies   map[string]string
	issuers    map[string]*IssuerAllowlist
	policyErr  error // returned by TrustPolicy when set
	issuersErr error // returned by OrgTrustedIssuers when set
	requests   []TrustPolicyRequest
	owners     []string // OrgTrustedIssuers arguments
}

func (f *fakePolicySource) TrustPolicy(_ context.Context, req TrustPolicyRequest) (TrustPolicyResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests = append(f.requests, req)
	if f.policyErr != nil {
		return TrustPolicyResult{}, f.policyErr
	}
	raw, ok := f.policies[req.Owner+"/"+req.Repo+"/"+req.Identity]
	if !ok {
		return TrustPolicyResult{}, TrustPolicyNotFound(req.Identity)
	}
	return TrustPolicyResult{Raw: []byte(raw)}, nil
}

func (f *fakePolicySource) OrgTrustedIssuers(_ context.Context, owner string) (*IssuerAllowlist, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.owners = append(f.owners, owner)
	if f.issuersErr != nil {
		return nil, f.issuersErr
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

// mintOptions decodes the mint request carried by a fake GitHub token.
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

func newSourceSTS(t *testing.T, src PolicySource) (*sts, *mintOnlyGitHub) {
	t.Helper()
	gh := &mintOnlyGitHub{t: t}
	atr := newAppsTransport(t, gh)
	s := NewSecurityTokenServiceServer(routerFor(&fakeInstallMgr{atr: atr}, 1), nil, AppSet{}, nil, "octosts", false, "", "", "", nil, false, false, WithPolicySource(src)).(*sts)
	return s, gh
}

func TestPolicySourceRepoScopedExchange(t *testing.T) {
	src := &fakePolicySource{policies: map[string]string{"srcorg/repo/foo": sourcePolicy}}
	s, gh := newSourceSTS(t, src)

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
	// With no installation from the source, the exchange mints with the one
	// the STS picked.
	if got, want := gh.mintedBy(), []int64{1234}; !slices.Equal(got, want) {
		t.Errorf("minted by installations %v, want %v", got, want)
	}
	if want := []TrustPolicyRequest{{Owner: "srcorg", Repo: "repo", Identity: "foo"}}; !slices.Equal(src.requests, want) {
		t.Errorf("source requests = %+v, want %+v", src.requests, want)
	}
}

func TestPolicySourceOrgScopedExchange(t *testing.T) {
	// An org-scoped request reads from the org policy repository and parses
	// the policy as an org policy, so repositories is accepted.
	src := &fakePolicySource{policies: map[string]string{
		"srcorg/.github/foo": sourcePolicy + "repositories:\n  - a\n  - b\n",
	}}
	s, _ := newSourceSTS(t, src)

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

func TestPolicySourceSeesLowercasedNames(t *testing.T) {
	// Owner and repo are lowercased for the source; the identity, a file
	// name in the GitHub layout, keeps its case.
	src := &fakePolicySource{policies: map[string]string{"srcorg/repo/Foo": sourcePolicy}}
	s, _ := newSourceSTS(t, src)

	if _, err := s.Exchange(newExchangeContext(t), &v1.ExchangeRequest{Identity: "Foo", Scopes: []string{"SrcOrg/Repo"}}); err != nil {
		t.Fatalf("Exchange() = %v", err)
	}
	if want := []TrustPolicyRequest{{Owner: "srcorg", Repo: "repo", Identity: "Foo"}}; !slices.Equal(src.requests, want) {
		t.Errorf("source requests = %+v, want %+v", src.requests, want)
	}
	if want := []string{"srcorg"}; !slices.Equal(src.owners, want) {
		t.Errorf("allowlist owners = %v, want %v", src.owners, want)
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
	const secret = "dial tcp 10.0.0.5:5432: password authentication failed"

	for _, tc := range []struct {
		name     string
		src      *fakePolicySource
		scope    string // default srcorg/repo
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
		name:     "status error passes through",
		src:      &fakePolicySource{policyErr: status.Error(codes.Unavailable, "store down")},
		wantCode: codes.Unavailable,
		wantMsg:  "store down",
	}, {
		name:     "wrapped status loses the wrapping text",
		src:      &fakePolicySource{policyErr: fmt.Errorf("query failed (%s): %w", secret, TrustPolicyNotFound("foo"))},
		wantCode: codes.NotFound,
		wantMsg:  `unable to find trust policy for "foo"`,
	}, {
		name:     "plain policy error is replaced",
		src:      &fakePolicySource{policyErr: errors.New(secret)},
		wantCode: codes.Unavailable,
		wantMsg:  "unable to read trust policy",
	}, {
		name:     "plain allowlist error is replaced and fails closed",
		src:      &fakePolicySource{policies: map[string]string{"srcorg/repo/foo": sourcePolicy}, issuersErr: errors.New(secret)},
		wantCode: codes.Unavailable,
		wantMsg:  "unable to read org trusted issuers",
	}, {
		name:     "context error keeps its code",
		src:      &fakePolicySource{policyErr: fmt.Errorf("query: %w", context.DeadlineExceeded)},
		wantCode: codes.DeadlineExceeded,
	}, {
		name: "enforcing allowlist denies unlisted issuer",
		src: &fakePolicySource{
			policies: map[string]string{"srcorg/repo/foo": sourcePolicy},
			issuers:  map[string]*IssuerAllowlist{"srcorg": enforce},
		},
		wantCode: codes.PermissionDenied,
		wantMsg:  msgIssuerNotPermitted,
	}, {
		// The source keys its allowlist on "srcorg". Without lowercasing it
		// would find none for "SrcOrg", and no allowlist permits every issuer.
		name: "allowlist applies whatever case the caller wrote",
		src: &fakePolicySource{
			policies: map[string]string{"srcorg/repo/foo": sourcePolicy},
			issuers:  map[string]*IssuerAllowlist{"srcorg": enforce},
		},
		scope:    "SrcOrg/repo",
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
			scope := cmp.Or(tc.scope, "srcorg/repo")
			s, _ := newSourceSTS(t, tc.src)
			_, err := s.Exchange(newExchangeContext(t), &v1.ExchangeRequest{Identity: "foo", Scopes: []string{scope}})
			st := status.Convert(err)
			if st.Code() != tc.wantCode {
				t.Fatalf("Exchange() = %v, want code %v", err, tc.wantCode)
			}
			if tc.wantMsg != "" && st.Message() != tc.wantMsg {
				t.Errorf("message = %q, want %q", st.Message(), tc.wantMsg)
			}
			if strings.Contains(st.Message(), "10.0.0.5") {
				t.Errorf("message %q leaks the source's error", st.Message())
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

// mintRecorder wraps a fake GitHub and records the installation and
// permissions of each token minted through it.
type mintRecorder struct {
	next  http.Handler
	mu    sync.Mutex
	mints []recordedMint
}

type recordedMint struct {
	install int64
	opts    github.InstallationTokenOptions
}

func (m *mintRecorder) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/access_tokens") {
		b, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(b))
		id, _ := strconv.ParseInt(strings.Split(r.URL.Path, "/")[3], 10, 64)
		var opts github.InstallationTokenOptions
		_ = json.Unmarshal(b, &opts)
		m.mu.Lock()
		m.mints = append(m.mints, recordedMint{install: id, opts: opts})
		m.mu.Unlock()
	}
	m.next.ServeHTTP(w, r)
}

// exchangeMints returns the installations that minted an exchange token,
// told apart from policy-read tokens by carrying the policy's
// pull_requests: write.
func (m *mintRecorder) exchangeMints() []int64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	var ids []int64
	for _, mint := range m.mints {
		if mint.opts.Permissions != nil && mint.opts.Permissions.GetPullRequests() == "write" {
			ids = append(ids, mint.install)
		}
	}
	return ids
}

func TestGitHubSourceMintsOnInstallationThatAnswered(t *testing.T) {
	// App A (installation 1234) is rate-limited on the policy read and App B
	// (installation 1235) answers it. The exchange token must come from B.
	key := cacheTrustPolicyKey{owner: "org", repo: "repo", identity: "foo"}
	purge := func() {
		trustPolicies.Remove(key)
		staleTrustPolicies.Remove(key)
		forbiddenPolicies.Remove(key)
	}
	purge()
	t.Cleanup(purge)
	cleanupOrgIssuers(t, "org")
	orgIssuers.Add("org", absentOrgIssuerEntry())

	appA := &mintRecorder{next: newFakeGitHubRateLimit(http.StatusForbidden)}
	appB := &mintRecorder{next: newFakeGitHub()}
	pool := &ghinstall.OrgPool{
		M: &sequentialInstallMgr{transports: []*ghinstallation.AppsTransport{
			newAppsTransport(t, appA),
			newAppsTransport(t, appB),
		}},
		AppCount: 2,
	}
	s := &sts{router: ghinstall.NewOrgRouter(map[string]*ghinstall.OrgPool{"org": pool})}

	if _, err := s.Exchange(newExchangeContext(t), &v1.ExchangeRequest{Identity: "foo", Scopes: []string{"org/repo"}}); err != nil {
		t.Fatalf("Exchange() = %v", err)
	}
	if got := appA.exchangeMints(); len(got) != 0 {
		t.Errorf("rate-limited App A minted the exchange token (installations %v)", got)
	}
	if got, want := appB.exchangeMints(), []int64{1235}; !slices.Equal(got, want) {
		t.Errorf("App B exchange mints = %v, want %v", got, want)
	}
}

func TestGitHubSourceTrustPolicyPicksItsOwnInstallation(t *testing.T) {
	// The public TrustPolicy, which the STS itself does not call, reads with
	// an installation it routes to on its own.
	forgetTrustPolicy(t, "org")
	atr := newAppsTransport(t, newFakeGitHub())
	s := &sts{router: routerFor(&fakeInstallMgr{atr: atr}, 1)}

	res, err := githubPolicySource{s: s}.TrustPolicy(t.Context(), TrustPolicyRequest{Owner: "org", Repo: "repo", Identity: "foo"})
	if err != nil {
		t.Fatalf("TrustPolicy() = %v", err)
	}
	if !strings.Contains(string(res.Raw), "pull_requests: write") {
		t.Errorf("TrustPolicy() raw = %q, want the org/repo foo policy", res.Raw)
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
