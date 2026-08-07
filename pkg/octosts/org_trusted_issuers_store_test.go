// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package octosts

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	v1 "chainguard.dev/sdk/proto/platform/oidc/v1"
	"github.com/bradleyfalzon/ghinstallation/v2"
	"github.com/chainguard-dev/clog"
	cloudevents "github.com/cloudevents/sdk-go/v2"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-jose/go-jose/v4"
	josejwt "github.com/go-jose/go-jose/v4/jwt"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-github/v88/github"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/octo-sts/app/pkg/ghinstall"
	"github.com/octo-sts/app/pkg/provider"
)

var errTestInvalid = errors.New("test: invalid config")

// cleanupOrgIssuers removes the owner keys a test seeded. The caches are
// package-level shared state, so leaking entries makes later tests in this
// package order-dependent. This mirrors the existing convention for
// trustPolicies/staleTrustPolicies.
func cleanupOrgIssuers(t *testing.T, owners ...string) {
	t.Helper()
	purge := func() {
		for _, o := range owners {
			orgIssuers.Remove(o)
			staleOrgIssuers.Remove(o)
		}
	}
	purge()
	t.Cleanup(purge)
}

func TestCacheOrgIssuerEntryStaleRouting(t *testing.T) {
	cleanupOrgIssuers(t, "o-present", "o-absent", "o-invalid")

	allow, err := (&OrgTrustedIssuers{Issuers: []string{testGitHubIssuer}}).Compile()
	if err != nil {
		t.Fatalf("Compile() = %v", err)
	}

	// Present and Absent are durable knowledge and belong in both caches.
	cacheOrgIssuerEntry(t.Context(), "o-present", presentOrgIssuerEntry(allow))
	cacheOrgIssuerEntry(t.Context(), "o-absent", absentOrgIssuerEntry())
	// Invalid is a transient bad state and must never become "last known good".
	cacheOrgIssuerEntry(t.Context(), "o-invalid", invalidOrgIssuerEntry(errTestInvalid))

	for _, owner := range []string{"o-present", "o-absent", "o-invalid"} {
		if _, ok := orgIssuers.Get(owner); !ok {
			t.Errorf("orgIssuers is missing %q", owner)
		}
	}
	for _, owner := range []string{"o-present", "o-absent"} {
		if _, ok := staleOrgIssuers.Get(owner); !ok {
			t.Errorf("staleOrgIssuers is missing %q", owner)
		}
	}
	if _, ok := staleOrgIssuers.Get("o-invalid"); ok {
		t.Error("staleOrgIssuers must not hold an Invalid entry — it would become last-known-good")
	}
}

func TestCacheOrgIssuerEntryWarnsOnEnforcementRemoved(t *testing.T) {
	cleanupOrgIssuers(t, "o-transition")

	allow, err := (&OrgTrustedIssuers{Issuers: []string{testGitHubIssuer}}).Compile()
	if err != nil {
		t.Fatalf("Compile() = %v", err)
	}

	// Capture the log output via a real slog handler wired through clog, so
	// the warning itself — not just the state it keys off — is asserted.
	var logs bytes.Buffer
	ctx := clog.WithLogger(t.Context(), clog.New(slog.NewTextHandler(&logs, nil)))

	// Present first, so staleOrgIssuers holds an enforcing entry...
	cacheOrgIssuerEntry(ctx, "o-transition", presentOrgIssuerEntry(allow))
	if prev, ok := staleOrgIssuers.Get("o-transition"); !ok || prev.state != orgIssuerPresent {
		t.Fatalf("setup: stale entry = %+v, ok = %v; want a Present entry", prev, ok)
	}
	if logs.Len() != 0 {
		t.Fatalf("unexpected log output after the initial Present write: %q", logs.String())
	}

	// ...then Absent, which is the enforcement-removed transition.
	cacheOrgIssuerEntry(ctx, "o-transition", absentOrgIssuerEntry())

	got, ok := staleOrgIssuers.Get("o-transition")
	if !ok || got.state != orgIssuerAbsent {
		t.Fatalf("stale entry = %+v, ok = %v; want Absent after the transition", got, ok)
	}
	if !bytes.Contains(logs.Bytes(), []byte("enforcement removed")) {
		t.Fatalf("log output = %q, want it to contain the enforcement-removed warning", logs.String())
	}

	// A repeat Absent write is not a transition (stale is already Absent), so
	// it must not warn again.
	logs.Reset()
	cacheOrgIssuerEntry(ctx, "o-transition", absentOrgIssuerEntry())
	if logs.Len() != 0 {
		t.Fatalf("repeat Absent write logged %q, want no warning — the transition is one-shot", logs.String())
	}
}

func TestZeroValueEntryIsNotAPass(t *testing.T) {
	// The Go zero value of orgIssuerEntry must never mean "allow". A dropped
	// ok from Get, an eviction, or a future struct-copy bug would otherwise
	// silently disable the control on the hot path.
	//
	// The invariant this actually protects is the CONSTANT ORDER: orgIssuerUnknown
	// must be the iota zero. Reordering the block so orgIssuerAbsent came first
	// would make every zero value an allow-all, which is why that is asserted
	// directly rather than only via the struct.
	if orgIssuerUnknown != 0 {
		t.Fatalf("orgIssuerUnknown = %d, want 0 — it must be the iota zero so a zero-value entry is never a pass", orgIssuerUnknown)
	}
	if orgIssuerAbsent == 0 {
		t.Fatal("orgIssuerAbsent must not be the iota zero — a zero-value entry would then permit all issuers")
	}

	var zero orgIssuerEntry
	if zero.state != orgIssuerUnknown {
		t.Fatalf("zero value state = %v, want orgIssuerUnknown", zero.state)
	}
}

func TestIsOrgIssuerRateLimit(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "typed primary rate limit",
			err:  &github.RateLimitError{Response: &http.Response{StatusCode: http.StatusForbidden}},
			want: true,
		},
		{
			name: "typed secondary rate limit",
			err:  &github.AbuseRateLimitError{Response: &http.Response{StatusCode: http.StatusForbidden}},
			want: true,
		},
		{
			name: "bare 429",
			err:  &github.ErrorResponse{Response: &http.Response{StatusCode: http.StatusTooManyRequests}},
			want: true,
		},
		{
			// The whole point: a bare 403 is a permission, SAML/IP-allowlist, or
			// suspended-installation failure. go-github would have returned a
			// typed error had it been a rate limit.
			name: "bare 403 is NOT a rate limit",
			err:  &github.ErrorResponse{Response: &http.Response{StatusCode: http.StatusForbidden}},
			want: false,
		},
		{
			name: "404",
			err:  &github.ErrorResponse{Response: &http.Response{StatusCode: http.StatusNotFound}},
			want: false,
		},
		{name: "nil", err: nil, want: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Wrap only a non-nil error. An earlier revision wrapped
			// unconditionally and guarded the assertion with `tc.err != nil`,
			// which silently skipped the nil row entirely — it asserted nothing.
			err := tc.err
			if err != nil {
				err = fmt.Errorf("wrapped: %w", err)
			}
			if got := isOrgIssuerRateLimit(err); got != tc.want {
				t.Errorf("isOrgIssuerRateLimit(%T) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

// TestOrgIssuerRateLimitDivergesFromWebhook pins the deliberate divergence: the
// webhook's helper treats any 403 as rate limiting, which is right there (it
// only suppresses a CheckRun) and wrong here (it would deny federation).
func TestOrgIssuerRateLimitDivergesFromWebhook(t *testing.T) {
	bare403 := &github.ErrorResponse{Response: &http.Response{StatusCode: http.StatusForbidden}}
	if isOrgIssuerRateLimit(bare403) {
		t.Error("isOrgIssuerRateLimit must NOT treat a bare 403 as a rate limit")
	}
	if !IsGitHubRateLimited(bare403) {
		t.Error("IsGitHubRateLimited is expected to treat a bare 403 as a rate limit; if this changed, revisit the divergence comment")
	}
}

func TestClassifyMintError(t *testing.T) {
	mk := func(code int, headers map[string]string) error {
		h := http.Header{}
		for k, v := range headers {
			h.Set(k, v)
		}
		return fmt.Errorf("wrapped: %w", &ghinstallation.HTTPError{
			Message:  "boom",
			Response: &http.Response{StatusCode: code, Header: h, Body: http.NoBody},
		})
	}

	for _, tc := range []struct {
		name     string
		err      error
		wantKind fetchKind
		wantCode codes.Code
	}{
		{
			// 422 conflates "repo absent", "not granted", and "permissions not
			// granted" — all mean this installation cannot see .github.
			name:     "422 unprocessable",
			err:      mk(http.StatusUnprocessableEntity, nil),
			wantKind: fetchNoAccess,
		},
		{
			name:     "429 too many requests",
			err:      mk(http.StatusTooManyRequests, nil),
			wantKind: fetchRateLimited,
			wantCode: codes.ResourceExhausted,
		},
		{
			// The installation-token endpoint is rate limited like any other.
			// Collapsing this into "other" meant one exhausted app denied every
			// exchange in the org while other apps still had quota.
			name:     "403 with rate limit marker",
			err:      mk(http.StatusForbidden, map[string]string{"X-RateLimit-Remaining": "0"}),
			wantKind: fetchRateLimited,
			wantCode: codes.ResourceExhausted,
		},
		{
			// Secondary limits carry Retry-After; X-RateLimit-Remaining is
			// typically nonzero, so the primary-only check would miss this.
			name:     "403 with only Retry-After (secondary limit)",
			err:      mk(http.StatusForbidden, map[string]string{"Retry-After": "60"}),
			wantKind: fetchRateLimited,
			wantCode: codes.ResourceExhausted,
		},
		{
			// A 429 is always a rate limit regardless of what the remaining
			// count says.
			name:     "429 with nonzero X-RateLimit-Remaining",
			err:      mk(http.StatusTooManyRequests, map[string]string{"X-RateLimit-Remaining": "10"}),
			wantKind: fetchRateLimited,
			wantCode: codes.ResourceExhausted,
		},
		{
			// A bare 403 is a suspended or blocked installation. It says nothing
			// about .github visibility, so it must not be fetchNoAccess.
			name:     "bare 403",
			err:      mk(http.StatusForbidden, nil),
			wantKind: fetchFailed,
			wantCode: codes.Unavailable,
		},
		{name: "401", err: mk(http.StatusUnauthorized, nil), wantKind: fetchFailed, wantCode: codes.Unavailable},
		{name: "404", err: mk(http.StatusNotFound, nil), wantKind: fetchFailed, wantCode: codes.Unavailable},
		{name: "500", err: mk(http.StatusInternalServerError, nil), wantKind: fetchFailed, wantCode: codes.Unavailable},
		{name: "untyped", err: errors.New("dial tcp: connection refused"), wantKind: fetchFailed, wantCode: codes.Unavailable},
		{
			// herr.Response != nil is a live guard: without it this row would
			// nil-dereference at herr.Response.StatusCode. The "untyped" row
			// above only exercises errors.As failing to match, not this branch.
			name:     "typed error with nil response",
			err:      fmt.Errorf("wrapped: %w", &ghinstallation.HTTPError{Message: "boom", Response: nil}),
			wantKind: fetchFailed,
			wantCode: codes.Unavailable,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := classifyMintError(t.Context(), "org", tc.err)
			if got.kind != tc.wantKind {
				t.Fatalf("kind = %v, want %v", got.kind, tc.wantKind)
			}
			// Only fetchOK carries an entry. Every other kind must leave it at
			// the fail-closed zero — asserted here, against the real classifier,
			// rather than against a test-local literal where it would be
			// guaranteed by Go's zero-value semantics and prove nothing.
			if got.kind != fetchOK && got.entry.state != orgIssuerUnknown {
				t.Errorf("entry.state = %v, want orgIssuerUnknown for kind %v", got.entry.state, got.kind)
			}
			if tc.wantCode == codes.OK {
				if got.err != nil {
					t.Errorf("err = %v, want nil — kind %v is an answer, not a failure", got.err, got.kind)
				}
				return
			}
			st, ok := status.FromError(got.err)
			if !ok {
				t.Fatalf("err = %T, want a gRPC status", got.err)
			}
			if st.Code() != tc.wantCode {
				t.Errorf("code = %v, want %v", st.Code(), tc.wantCode)
			}
		})
	}
}

func TestClassifyContentsError(t *testing.T) {
	for _, tc := range []struct {
		name     string
		err      error
		wantKind fetchKind
		wantCode codes.Code
	}{
		{
			name:     "typed primary rate limit",
			err:      &github.RateLimitError{Response: &http.Response{StatusCode: http.StatusForbidden}},
			wantKind: fetchRateLimited,
			wantCode: codes.ResourceExhausted,
		},
		{
			name:     "typed secondary rate limit",
			err:      &github.AbuseRateLimitError{Response: &http.Response{StatusCode: http.StatusForbidden}},
			wantKind: fetchRateLimited,
			wantCode: codes.ResourceExhausted,
		},
		{
			name:     "404 file absent",
			err:      &github.ErrorResponse{Response: &http.Response{StatusCode: http.StatusNotFound}},
			wantKind: fetchAbsent,
		},
		{
			// This is the row that a shared 403-means-rate-limit helper would
			// have made unreachable. It is ignorance, so fetchFailed.
			//
			// It used to assert fetchNoAccess, on the theory that a 403 is one
			// installation's blindness. That was wrong in a way worth recording,
			// because NoAccess counts as an installation AGREEING that no allowlist
			// applies: a read-time 403 is frequently org-wide (IP allow list,
			// SAML/SSO enforcement, ToS lock, an incident failing the contents API),
			// which makes every installation "agree" while carrying no information
			// about whether an allowlist exists — falling the org open to allow-all
			// precisely during the incident.
			//
			// The old rationale also mis-stated the aggregator: scanInstalls records
			// a failure and CONTINUES, so a 403 never stopped it from asking an
			// installation that can read the file. All fetchFailed changes is that an
			// all-403 enumeration fails closed instead of concluding absence.
			//
			// The genuinely per-installation case does not arrive here: an App
			// without .github in its repository selection fails at the mint with a
			// 422, which is still NoAccess and still falls open.
			name:     "bare 403 is ignorance, not agreement that no allowlist applies",
			err:      &github.ErrorResponse{Response: &http.Response{StatusCode: http.StatusForbidden}},
			wantKind: fetchFailed,
			wantCode: codes.Unavailable,
		},
		{
			name:     "502",
			err:      &github.ErrorResponse{Response: &http.Response{StatusCode: http.StatusBadGateway}},
			wantKind: fetchFailed,
			wantCode: codes.Unavailable,
		},
		{name: "untyped", err: errors.New("dial tcp: connection refused"), wantKind: fetchFailed, wantCode: codes.Unavailable},
		{
			// ghErr.Response != nil is a live guard: without it this row would
			// nil-dereference at ghErr.Response.StatusCode. The "untyped" row
			// above only exercises errors.As failing to match, not this branch.
			name:     "typed error with nil response",
			err:      &github.ErrorResponse{Response: nil},
			wantKind: fetchFailed,
			wantCode: codes.Unavailable,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := classifyContentsError(t.Context(), "org", ".github", fmt.Errorf("wrapped: %w", tc.err))
			if got.kind != tc.wantKind {
				t.Fatalf("kind = %v, want %v", got.kind, tc.wantKind)
			}
			// Only fetchOK carries an entry. Every other kind must leave it at
			// the fail-closed zero — asserted here, against the real classifier,
			// rather than against a test-local literal where it would be
			// guaranteed by Go's zero-value semantics and prove nothing.
			if got.kind != fetchOK && got.entry.state != orgIssuerUnknown {
				t.Errorf("entry.state = %v, want orgIssuerUnknown for kind %v", got.entry.state, got.kind)
			}
			if tc.wantCode == codes.OK {
				if got.err != nil {
					t.Errorf("err = %v, want nil — kind %v is an answer, not a failure", got.err, got.kind)
				}
				return
			}
			st, ok := status.FromError(got.err)
			if !ok {
				t.Fatalf("err = %T, want a gRPC status", got.err)
			}
			if st.Code() != tc.wantCode {
				t.Errorf("code = %v, want %v", st.Code(), tc.wantCode)
			}
		})
	}
}

func TestFetchOrgIssuersOnce(t *testing.T) {
	cleanupOrgIssuers(t, "orgallow")

	atr := newAppsTransport(t, newFakeGitHub())
	s := &sts{rrm: &fakeInstallMgr{atr: atr}, appCount: 1}

	res := s.fetchOrgIssuersOnce(t.Context(), atr, 1234, "orgallow")
	if res.kind != fetchOK {
		t.Fatalf("kind = %v, want fetchOK", res.kind)
	}
	if res.entry.state != orgIssuerPresent {
		t.Fatalf("state = %v, want orgIssuerPresent", res.entry.state)
	}
	if !res.entry.allow.Allows(testGitHubIssuer) {
		t.Errorf("Allows(%q) = false, want true", testGitHubIssuer)
	}
	if res.entry.allow.Mode() != ModeEnforce {
		t.Errorf("Mode() = %q, want %q", res.entry.allow.Mode(), ModeEnforce)
	}
	if res.err != nil {
		t.Errorf("err = %v, want nil — fetchOK is an answer, not a failure", res.err)
	}
}

func TestFetchOrgIssuersOnceAbsent(t *testing.T) {
	cleanupOrgIssuers(t, "orgnone")

	atr := newAppsTransport(t, newFakeGitHub())
	s := &sts{rrm: &fakeInstallMgr{atr: atr}, appCount: 1}

	// No fixture for orgnone, so the fake returns a GitHub-shaped 404. A 404 is
	// definitive: the repo was readable and the file is not there.
	res := s.fetchOrgIssuersOnce(t.Context(), atr, 1234, "orgnone")
	if res.kind != fetchAbsent {
		t.Fatalf("kind = %v, want fetchAbsent", res.kind)
	}
	if res.entry.state != orgIssuerUnknown {
		t.Errorf("entry.state = %v, want orgIssuerUnknown — fetchAbsent carries no entry", res.entry.state)
	}
	if res.err != nil {
		t.Errorf("err = %v, want nil", res.err)
	}
}

func TestFetchOrgIssuersOnceInvalid(t *testing.T) {
	cleanupOrgIssuers(t, "orgbad")

	atr := newAppsTransport(t, newFakeGitHub())
	s := &sts{rrm: &fakeInstallMgr{atr: atr}, appCount: 1}

	res := s.fetchOrgIssuersOnce(t.Context(), atr, 1234, "orgbad")
	if res.kind != fetchOK {
		t.Fatalf("kind = %v, want fetchOK (an invalid config is an answer, not a fetch failure)", res.kind)
	}
	if res.entry.state != orgIssuerInvalid {
		t.Fatalf("state = %v, want orgIssuerInvalid", res.entry.state)
	}
	st, ok := status.FromError(res.entry.err)
	if !ok || st.Code() != codes.FailedPrecondition {
		t.Fatalf("entry.err = %v, want FailedPrecondition", res.entry.err)
	}
	if st.Message() != msgIssuerConfigInvalid {
		t.Errorf("message = %q, want the fixed %q (no config detail may leak)", st.Message(), msgIssuerConfigInvalid)
	}
}

// scopeCapturingHandler wraps another handler and records the Authorization
// header GitHub received on each request to the contents endpoint. The fake's
// mint route echoes the InstallationTokenOptions JSON back as the token
// itself (base64-encoded), and ghinstallation attaches that token as the
// bearer on every subsequent request — so the header this handler captures
// IS the scope that was actually minted, recoverable without any new
// plumbing in the non-test code.
type scopeCapturingHandler struct {
	http.Handler

	mu       sync.Mutex
	lastAuth string
}

func (c *scopeCapturingHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if strings.Contains(r.URL.Path, "/contents/") {
		c.mu.Lock()
		c.lastAuth = r.Header.Get("Authorization")
		c.mu.Unlock()
	}
	c.Handler.ServeHTTP(w, r)
}

func (c *scopeCapturingHandler) mintedOptions(t *testing.T) *github.InstallationTokenOptions {
	t.Helper()
	c.mu.Lock()
	auth := c.lastAuth
	c.mu.Unlock()

	// ghinstallation sends the installation token as "token <value>", not the
	// OAuth2 "Bearer <value>" form used elsewhere in this codebase for the
	// caller's own OIDC token.
	tokenStr, ok := strings.CutPrefix(auth, "token ")
	if !ok {
		t.Fatalf("Authorization header = %q, want a %q-prefixed token", auth, "token ")
	}
	b, err := base64.StdEncoding.DecodeString(tokenStr)
	if err != nil {
		t.Fatalf("DecodeString(%q) failed: %v", tokenStr, err)
	}
	opts := new(github.InstallationTokenOptions)
	if err := json.Unmarshal(b, opts); err != nil {
		t.Fatalf("Unmarshal(%s) failed: %v", b, err)
	}
	return opts
}

// TestFetchOrgIssuersOnceMintsLeastPrivilegeToken pins the token scope
// fetchOrgIssuersOnce requests: exactly the organization's .github repository,
// with exactly contents:read. This is a security property, not an
// implementation detail — a token that could read more than .github, or that
// carried an extra permission, would hand any installation broader access
// than the org-allowlist lookup needs.
func TestFetchOrgIssuersOnceMintsLeastPrivilegeToken(t *testing.T) {
	cleanupOrgIssuers(t, "orgallow")

	capture := &scopeCapturingHandler{Handler: newFakeGitHub()}
	atr := newAppsTransport(t, capture)
	s := &sts{rrm: &fakeInstallMgr{atr: atr}, appCount: 1}

	res := s.fetchOrgIssuersOnce(t.Context(), atr, 1234, "orgallow")
	if res.kind != fetchOK {
		t.Fatalf("kind = %v, want fetchOK", res.kind)
	}

	got := capture.mintedOptions(t)
	want := &github.InstallationTokenOptions{
		Repositories: []string{".github"},
		Permissions: &github.InstallationPermissions{
			Contents: ptr("read"),
		},
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("minted InstallationTokenOptions mismatch (-want +got):\n%s", diff)
	}
}

// TestFetchOrgIssuersOnceDirectory exercises the guard against a path that
// resolves to a directory rather than a file. GetContents returns a nil
// *RepositoryContent in that case, and RepositoryContent.GetContent()
// dereferences its Encoding field with no nil-receiver guard — so without the
// guard in fetchOrgIssuersOnce, this panics on the token-exchange path
// instead of reporting a broken config. A directory is a broken config, not
// a fetch failure: the installation DID answer, the answer is just unusable.
func TestFetchOrgIssuersOnceDirectory(t *testing.T) {
	cleanupOrgIssuers(t, "orgdir")

	atr := newAppsTransport(t, newFakeGitHub())
	s := &sts{rrm: &fakeInstallMgr{atr: atr}, appCount: 1}

	// A different installation ID than the other tests use, so fetchOrgIssuersOnce
	// keeps this parameter's plumbing (EnrichContext, ghinstallation.NewFromAppsTransport)
	// exercised with more than one value — the aggregating caller in a later
	// task will vary it across installations.
	res := s.fetchOrgIssuersOnce(t.Context(), atr, 5678, "orgdir")
	if res.kind != fetchOK {
		t.Fatalf("kind = %v, want fetchOK", res.kind)
	}
	if res.entry.state != orgIssuerInvalid {
		t.Fatalf("state = %v, want orgIssuerInvalid", res.entry.state)
	}
}

// newOrgFakeGitHub builds a fake GitHub for the org-allowlist tests. With no
// options it behaves like newFakeGitHub: installations enumerate, mints echo
// their own InstallationTokenOptions back as the token, and contents are served
// from testdata. Each option replaces exactly one route, so a fake that only
// overrides the mint endpoint still reads testdata exactly as before.
func newOrgFakeGitHub(opts ...orgFakeGitHubOption) *fakeGitHub {
	routes := &orgFakeGitHubRoutes{
		mint:     defaultOrgFakeMint,
		contents: defaultOrgFakeContents,
	}
	for _, opt := range opts {
		opt(routes)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/app/installations", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode([]github.Installation{{
			ID:      github.Ptr(int64(1234)),
			Account: &github.User{Login: github.Ptr("org")},
		}})
	})
	mux.HandleFunc("/app/installations/{appID}/access_tokens", routes.mint)
	mux.HandleFunc("/repos/{org}/{repo}/contents/.github/chainguard/{identity}", routes.contents)
	// Revoke() posts here. It does not reach any fake: its URL follows the
	// configured baseURL, which is empty in these tests and so resolves to
	// https://api.github.com/installation/token, and it sends via
	// http.DefaultClient rather than the injected transport. The route keeps the
	// fake correct if Revoke is ever pointed at it. Same dead route as in
	// newFakeGitHub.
	mux.HandleFunc("/installation/token", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotImplemented)
		fmt.Fprintf(io.MultiWriter(w, os.Stdout), "%s %s not implemented\n", r.Method, r.URL.Path)
	})
	return &fakeGitHub{mux: mux}
}

// orgFakeGitHubRoutes holds the only two routes any of these fakes needs to
// vary. The others (installation enumeration, the revoke route, the
// not-implemented catch-all) are identical everywhere and stay in the builder.
type orgFakeGitHubRoutes struct {
	mint     http.HandlerFunc
	contents http.HandlerFunc
}

type orgFakeGitHubOption func(*orgFakeGitHubRoutes)

// defaultOrgFakeMint echoes the request body back as the token, base64-encoded.
// TestFetchOrgIssuersOnceMintsLeastPrivilegeToken depends on that echo to
// recover the scope that was actually minted.
func defaultOrgFakeMint(w http.ResponseWriter, r *http.Request) {
	b, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(github.InstallationToken{
		Token:     github.Ptr(base64.StdEncoding.EncodeToString(b)),
		ExpiresAt: &github.Timestamp{Time: time.Now().Add(10 * time.Minute)},
	})
}

// defaultOrgFakeContents serves a file out of testdata, mirroring newFakeGitHub.
func defaultOrgFakeContents(w http.ResponseWriter, r *http.Request) {
	// Sentinel: owner "orgdir" always resolves the trusted-issuers path to a
	// directory rather than a file. go-github distinguishes the two by response
	// shape — a single JSON object is a file, a JSON array is a directory
	// listing — so this is the only way to make GetContents return a nil
	// *RepositoryContent without an actual directory on disk. A real testdata
	// directory would hit os.ReadFile's EISDIR below, which is not
	// os.IsNotExist and would fall into the 500 branch instead.
	if r.PathValue("org") == "orgdir" && r.PathValue("identity") == "trusted-token-issuers.yaml" {
		json.NewEncoder(w).Encode([]*github.RepositoryContent{
			{Type: github.Ptr("file"), Name: github.Ptr("placeholder")},
		})
		return
	}

	b, err := os.ReadFile(filepath.Join("testdata", r.PathValue("org"), r.PathValue("repo"), r.PathValue("identity")))
	if err != nil {
		// A missing fixture is a 404, matching real GitHub.
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
}

// withNoGitHubRepoAccess rejects a .github-scoped mint with 422 while every
// other scope succeeds, simulating an App installed on selected repositories.
func withNoGitHubRepoAccess() orgFakeGitHubOption {
	return func(routes *orgFakeGitHubRoutes) {
		routes.mint = func(w http.ResponseWriter, r *http.Request) {
			b, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			if bytes.Contains(b, []byte(`".github"`)) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnprocessableEntity)
				json.NewEncoder(w).Encode(github.ErrorResponse{
					Response: &http.Response{StatusCode: http.StatusUnprocessableEntity},
					Message:  "There is at least one repository that does not exist or is not accessible to the parent installation.",
				})
				return
			}
			json.NewEncoder(w).Encode(github.InstallationToken{
				Token:     github.Ptr(base64.StdEncoding.EncodeToString(b)),
				ExpiresAt: &github.Timestamp{Time: time.Now().Add(10 * time.Minute)},
			})
		}
	}
}

// withMintRateLimited rate-limits the installation-token endpoint.
func withMintRateLimited() orgFakeGitHubOption {
	return func(routes *orgFakeGitHubRoutes) {
		routes.mint = func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			// X-RateLimit-Remaining: 0 is what makes go-github return a typed
			// *github.RateLimitError rather than a bare *github.ErrorResponse.
			// Without it this fake cannot reproduce the production
			// classification path at all.
			w.Header().Set("X-RateLimit-Remaining", "0")
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(github.ErrorResponse{
				Response: &http.Response{StatusCode: http.StatusForbidden},
				Message:  "API rate limit exceeded",
			})
		}
	}
}

// withContentsRateLimited rate-limits every contents request, including the
// allowlist. newFakeGitHubRateLimit deliberately exempts the allowlist so the
// policy-read tests keep testing the policy read.
func withContentsRateLimited() orgFakeGitHubOption {
	return func(routes *orgFakeGitHubRoutes) {
		routes.contents = func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			// See withMintRateLimited: the zero remaining count is what yields a
			// typed *github.RateLimitError.
			w.Header().Set("X-RateLimit-Remaining", "0")
			w.Header().Set("X-RateLimit-Limit", "5000")
			w.Header().Set("X-RateLimit-Reset", fmt.Sprintf("%d", time.Now().Add(time.Minute).Unix()))
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(github.ErrorResponse{
				Response: &http.Response{StatusCode: http.StatusForbidden},
				Message:  "API rate limit exceeded",
			})
		}
	}
}

// withContentsServerError fails every contents read with a 502 — a transient
// server error that is neither a rate limit nor evidence of this installation's
// blindness, so it classifies as fetchFailed. The mint still succeeds.
func withContentsServerError() orgFakeGitHubOption {
	return func(routes *orgFakeGitHubRoutes) {
		routes.contents = func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadGateway)
			json.NewEncoder(w).Encode(github.ErrorResponse{Message: "Bad gateway"})
		}
	}
}

// enumMgr is a Manager whose GetAll returns a fixed list, and whose Get always
// returns the FIRST entry — mimicking roundRobin with warm quota data, which
// selects argmax(remaining) with no rotation. A retry loop built on Get would
// see the same installation forever.
type enumMgr struct {
	installs []ghinstall.Installation
	err      error
	getCalls atomic.Int32

	// freshInstalls / freshErr model what GetAllFresh sees. freshInstalls
	// defaults to installs, so a fake that sets neither describes a manager
	// whose caches were not hiding anything — and the confirm step agrees with
	// the cheap enumeration. Set freshInstalls to a superset to model an App
	// installed within the negative-cache TTL.
	//
	// Precedence is freshErr, then freshInstalls, then a fallback that mirrors
	// GetAll exactly — installs AND err. So a fake that sets only err is a failed
	// enumeration on BOTH paths rather than one that reports success on the
	// confirm, while a fake that sets freshInstalls says "the confirm sees this,
	// successfully" and err stays scoped to GetAll.
	freshInstalls []ghinstall.Installation
	freshErr      error
	freshCalls    atomic.Int32
}

func (e *enumMgr) Get(_ context.Context, _, _, _ string) (*ghinstallation.AppsTransport, int64, error) {
	e.getCalls.Add(1)
	if len(e.installs) == 0 {
		return nil, 0, status.Error(codes.NotFound, "not installed")
	}
	return e.installs[0].Transport, e.installs[0].ID, nil
}

func (e *enumMgr) GetByInstallation(_ context.Context, _ string, id int64) (*ghinstallation.AppsTransport, int64, error) {
	for _, in := range e.installs {
		if in.ID == id {
			return in.Transport, in.ID, nil
		}
	}
	return nil, 0, status.Error(codes.NotFound, "not found")
}

func (e *enumMgr) GetAll(_ context.Context, _ string) ([]ghinstall.Installation, error) {
	return e.installs, e.err
}

func (e *enumMgr) GetAllFresh(_ context.Context, _ string) ([]ghinstall.Installation, error) {
	e.freshCalls.Add(1)
	if e.freshErr != nil {
		return nil, e.freshErr
	}
	if e.freshInstalls != nil {
		return e.freshInstalls, nil
	}
	return e.installs, e.err
}

var _ ghinstall.Manager = (*enumMgr)(nil)

// TestLookupSurvivesOneBlindInstallation is the regression test for the bypass.
// The FIRST installation cannot read .github; a second can and holds an
// enforcing allowlist. Because Get always returns the first one, only an
// enumeration-based lookup finds the second.
func TestLookupSurvivesOneBlindInstallation(t *testing.T) {
	cleanupOrgIssuers(t, "orgallow")

	blind := newAppsTransport(t, newOrgFakeGitHub(withNoGitHubRepoAccess()))
	working := newAppsTransport(t, newFakeGitHub())

	mgr := &enumMgr{installs: []ghinstall.Installation{
		{Transport: blind, ID: 1, AppID: 10},
		{Transport: working, ID: 2, AppID: 20},
	}}
	s := &sts{rrm: mgr, appCount: 2}

	entry, err := s.orgIssuerLookup(t.Context(), "orgallow")
	if err != nil {
		t.Fatalf("orgIssuerLookup() = %v, want nil", err)
	}
	if entry.state != orgIssuerPresent {
		t.Fatalf("state = %v, want orgIssuerPresent — one blind installation must not disable enforcement", entry.state)
	}
	if mgr.getCalls.Load() != 0 {
		t.Errorf("Get was called %d times; the lookup must enumerate via GetAll, not route via Get", mgr.getCalls.Load())
	}
}

// TestLookupAllInstallationsBlindIsAbsent is the fail-open that must survive:
// once CONFIRMED, a deployment that genuinely cannot read .github keeps working,
// which describes most installations. This fake sets neither freshInstalls nor
// freshErr, so the confirm agrees with the cheap enumeration.
//
// It also pins the confirm's cost: exactly one GetAllFresh call, bounded by the
// orgIssuers entry it writes rather than paid per exchange.
func TestLookupAllInstallationsBlindIsAbsent(t *testing.T) {
	cleanupOrgIssuers(t, "orgallow")

	a := newAppsTransport(t, newOrgFakeGitHub(withNoGitHubRepoAccess()))
	b := newAppsTransport(t, newOrgFakeGitHub(withNoGitHubRepoAccess()))

	mgr := &enumMgr{installs: []ghinstall.Installation{
		{Transport: a, ID: 1, AppID: 10},
		{Transport: b, ID: 2, AppID: 20},
	}}
	s := &sts{rrm: mgr, appCount: 2}

	entry, err := s.orgIssuerLookup(t.Context(), "orgallow")
	if err != nil {
		t.Fatalf("orgIssuerLookup() = %v, want nil", err)
	}
	if entry.state != orgIssuerAbsent {
		t.Fatalf("state = %v, want orgIssuerAbsent", entry.state)
	}
	if cached, ok := orgIssuers.Get("orgallow"); !ok || cached.state != orgIssuerAbsent {
		t.Error("an exhaustive all-blind verdict should be cached as Absent")
	}
	if got := mgr.freshCalls.Load(); got != 1 {
		t.Errorf("GetAllFresh called %d times, want exactly 1", got)
	}

	// The confirm is bounded by the cache it writes: a second lookup is served
	// from orgIssuers and pays nothing.
	if _, err := s.orgIssuerLookup(t.Context(), "orgallow"); err != nil {
		t.Fatalf("second orgIssuerLookup() = %v, want nil", err)
	}
	if got := mgr.freshCalls.Load(); got != 1 {
		t.Errorf("GetAllFresh called %d times across two lookups, want 1 — the confirm must be bounded by the orgIssuers TTL, not run per exchange", got)
	}
}

// TestLookupPartialEnumerationNeverCachesAbsent: a failed enumeration is not
// evidence of absence.
func TestLookupPartialEnumerationNeverCachesAbsent(t *testing.T) {
	cleanupOrgIssuers(t, "orgallow")

	blind := newAppsTransport(t, newOrgFakeGitHub(withNoGitHubRepoAccess()))

	// freshInstalls is deliberately set to a would-be-confirming superset. If the
	// enumErr == nil guard were dropped, the confirm would run, find the extra
	// installation blind too, and cache Absent off a GetAll that had already
	// reported itself incomplete. Without this the guard is unpinned: with
	// freshInstalls unset, GetAllFresh falls back to (installs, err) and the
	// confirm would fail on its own, so the test would pass either way.
	mgr := &enumMgr{
		installs: []ghinstall.Installation{{Transport: blind, ID: 1, AppID: 10}},
		err:      errors.New("could not list installations for app 20"),
		freshInstalls: []ghinstall.Installation{
			{Transport: blind, ID: 1, AppID: 10},
			{Transport: blind, ID: 2, AppID: 20},
		},
	}
	s := &sts{rrm: mgr, appCount: 2}

	_, err := s.orgIssuerLookup(t.Context(), "orgallow")
	st, ok := status.FromError(err)
	if !ok || st.Code() != codes.Unavailable {
		t.Fatalf("orgIssuerLookup() = %v, want Unavailable for an incomplete enumeration", err)
	}
	if _, ok := orgIssuers.Get("orgallow"); ok {
		t.Error("nothing may be cached when the enumeration was not exhaustive")
	}
	if got := mgr.freshCalls.Load(); got != 0 {
		t.Errorf("GetAllFresh called %d times, want 0 — a GetAll that reported itself incomplete is not a candidate for confirmation", got)
	}
}

// TestLookupMintRateLimitRetriesNextInstallation: a rate-limited mint must not
// end the lookup while another installation has quota.
func TestLookupMintRateLimitRetriesNextInstallation(t *testing.T) {
	cleanupOrgIssuers(t, "orgallow")

	limited := newAppsTransport(t, newOrgFakeGitHub(withMintRateLimited()))
	working := newAppsTransport(t, newFakeGitHub())

	s := &sts{rrm: &enumMgr{installs: []ghinstall.Installation{
		{Transport: limited, ID: 1, AppID: 10},
		{Transport: working, ID: 2, AppID: 20},
	}}, appCount: 2}

	entry, err := s.orgIssuerLookup(t.Context(), "orgallow")
	if err != nil {
		t.Fatalf("orgIssuerLookup() = %v, want nil — a rate-limited mint must try the next installation", err)
	}
	if entry.state != orgIssuerPresent {
		t.Fatalf("state = %v, want orgIssuerPresent", entry.state)
	}
}

// TestLookupServesStaleOnRateLimit also covers the audit escape hatch: a stale
// audit entry passes through simply by being served.
func TestLookupServesStaleOnRateLimit(t *testing.T) {
	cleanupOrgIssuers(t, "orgallow")

	allow, err := (&OrgTrustedIssuers{Mode: ModeAudit, Issuers: []string{testGitHubIssuer}}).Compile()
	if err != nil {
		t.Fatalf("Compile() = %v", err)
	}
	staleOrgIssuers.Add("orgallow", presentOrgIssuerEntry(allow))

	rl := newAppsTransport(t, newOrgFakeGitHub(withContentsRateLimited()))
	s := &sts{rrm: &enumMgr{installs: []ghinstall.Installation{{Transport: rl, ID: 1, AppID: 10}}}, appCount: 1}

	entry, err := s.orgIssuerLookup(t.Context(), "orgallow")
	if err != nil {
		t.Fatalf("orgIssuerLookup() = %v, want nil (stale should be served)", err)
	}
	if entry.state != orgIssuerPresent || entry.allow.Mode() != ModeAudit {
		t.Fatalf("entry = %+v, want the stale audit-mode allowlist", entry)
	}
	// Deliberately NOT reseeded. This assertion used to require the opposite, which
	// encoded a real widening: a fresh 5-minute primary TTL on an entry already up
	// to an hour old let an Absent admitted at t=0 be served past t=64:59, beyond
	// the stale bound it is supposed to have. Not reseeding costs a re-enumeration
	// per exchange for as long as the outage lasts.
	if _, ok := orgIssuers.Get("orgallow"); ok {
		t.Error("serving stale must not reseed the primary cache — that extends the window past the stale TTL")
	}
}

func TestLookupRateLimitedWithoutStaleDenies(t *testing.T) {
	cleanupOrgIssuers(t, "orgallow")

	rl := newAppsTransport(t, newOrgFakeGitHub(withContentsRateLimited()))
	s := &sts{rrm: &enumMgr{installs: []ghinstall.Installation{{Transport: rl, ID: 1, AppID: 10}}}, appCount: 1}

	_, err := s.orgIssuerLookup(t.Context(), "orgallow")
	st, ok := status.FromError(err)
	if !ok || st.Code() != codes.ResourceExhausted {
		t.Fatalf("orgIssuerLookup() = %v, want ResourceExhausted", err)
	}
	if _, ok := orgIssuers.Get("orgallow"); ok {
		t.Error("a rate-limited lookup must not be cached")
	}
}

func TestLookupInvalidServesLastKnownGood(t *testing.T) {
	cleanupOrgIssuers(t, "orgbad")

	good, err := (&OrgTrustedIssuers{Issuers: []string{testGitHubIssuer}}).Compile()
	if err != nil {
		t.Fatalf("Compile() = %v", err)
	}
	staleOrgIssuers.Add("orgbad", presentOrgIssuerEntry(good))

	atr := newAppsTransport(t, newFakeGitHub())
	s := &sts{rrm: &enumMgr{installs: []ghinstall.Installation{{Transport: atr, ID: 1, AppID: 10}}}, appCount: 1}

	entry, err := s.orgIssuerLookup(t.Context(), "orgbad")
	if err != nil {
		t.Fatalf("orgIssuerLookup() = %v, want nil", err)
	}
	if entry.state != orgIssuerPresent {
		t.Fatalf("state = %v, want orgIssuerPresent from the stale entry", entry.state)
	}
}

func TestLookupInvalidWithoutStaleReturnsInvalid(t *testing.T) {
	cleanupOrgIssuers(t, "orgbad")

	atr := newAppsTransport(t, newFakeGitHub())
	s := &sts{rrm: &enumMgr{installs: []ghinstall.Installation{{Transport: atr, ID: 1, AppID: 10}}}, appCount: 1}

	entry, err := s.orgIssuerLookup(t.Context(), "orgbad")
	if err != nil {
		t.Fatalf("orgIssuerLookup() = %v, want nil (Invalid is an answer)", err)
	}
	if entry.state != orgIssuerInvalid {
		t.Fatalf("state = %v, want orgIssuerInvalid", entry.state)
	}
}

// TestLookupInvalidIgnoresStaleAbsent pins the security-load-bearing
// `stale.state == orgIssuerPresent` conjunct in settleOrgIssuerEntry.
//
// Last-known-GOOD substitution is only safe when the last known state was an
// actual allowlist. A stale *Absent* entry is not a fallback allowlist, it is
// the absence of one — substituting it for a currently-Invalid config would
// silently convert a broken file into allow-all for the whole organization,
// which is exactly the outcome the enforcement boundary exists to prevent. So
// an Invalid config with only a stale Absent entry must stay Invalid.
func TestLookupInvalidIgnoresStaleAbsent(t *testing.T) {
	cleanupOrgIssuers(t, "orgbad")

	staleOrgIssuers.Add("orgbad", absentOrgIssuerEntry())

	atr := newAppsTransport(t, newFakeGitHub())
	s := &sts{rrm: &enumMgr{installs: []ghinstall.Installation{{Transport: atr, ID: 1, AppID: 10}}}, appCount: 1}

	entry, err := s.orgIssuerLookup(t.Context(), "orgbad")
	if err != nil {
		t.Fatalf("orgIssuerLookup() = %v, want nil (Invalid is an answer)", err)
	}
	if entry.state != orgIssuerInvalid {
		t.Fatalf("state = %v, want orgIssuerInvalid — a stale Absent entry must never be substituted for an invalid config, that would be org-wide allow-all", entry.state)
	}
	if cached, ok := orgIssuers.Get("orgbad"); !ok || cached.state != orgIssuerInvalid {
		t.Errorf("cached entry = %+v (ok = %v), want the Invalid entry, not the stale Absent one", cached, ok)
	}
}

// TestLookupBlindPlusFailedIsNotAbsent pins the exhaustiveness ARITHMETIC:
// Absent needs noAccess == len(installs), not merely noAccess > 0.
//
// Here the enumeration itself succeeded, so enumErr is nil and that guard does
// not help. One installation is blind and the other simply errored, so the org
// is only PARTLY surveyed — we never established that no installation can read
// .github. Relaxing the count to `noAccess > 0` would cache allow-all for the
// whole organization off the back of one blind installation plus one 502.
func TestLookupBlindPlusFailedIsNotAbsent(t *testing.T) {
	cleanupOrgIssuers(t, "orgallow")

	blind := newAppsTransport(t, newOrgFakeGitHub(withNoGitHubRepoAccess()))
	broken := newAppsTransport(t, newOrgFakeGitHub(withContentsServerError()))

	s := &sts{rrm: &enumMgr{installs: []ghinstall.Installation{
		{Transport: blind, ID: 1, AppID: 10},
		{Transport: broken, ID: 2, AppID: 20},
	}}, appCount: 2}

	_, err := s.orgIssuerLookup(t.Context(), "orgallow")
	st, ok := status.FromError(err)
	if !ok || st.Code() != codes.Unavailable {
		t.Fatalf("orgIssuerLookup() = %v, want Unavailable — a partly-surveyed org is unknown, not absent", err)
	}
	if cached, ok := orgIssuers.Get("orgallow"); ok {
		t.Errorf("cached %+v; a partial survey must never be cached, least of all as Absent", cached)
	}
}

// TestLookupEmptyEnumerationIsNotAbsent pins that an empty installation list is
// ignorance, not positive knowledge of absence.
//
// With no installations the loop body never runs, so noAccess stays 0 and
// enumErr is nil — "0 == len(installs)" would therefore cache allow-all for the
// whole organization off zero evidence. The lookup is only reached after
// routing already found an installation for this owner, so an empty enumeration
// means the two managers disagreed; falling through to the stale / fail-closed
// path is the correct reading.
func TestLookupEmptyEnumerationIsNotAbsent(t *testing.T) {
	cleanupOrgIssuers(t, "orgempty")

	s := &sts{rrm: &enumMgr{installs: nil}, appCount: 1}

	entry, err := s.orgIssuerLookup(t.Context(), "orgempty")
	st, ok := status.FromError(err)
	if !ok || st.Code() != codes.Unavailable {
		t.Fatalf("orgIssuerLookup() = %v, want Unavailable — an empty enumeration is not evidence of absence", err)
	}
	if entry.state == orgIssuerAbsent {
		t.Errorf("state = %v, want anything but orgIssuerAbsent", entry.state)
	}
	if cached, ok := orgIssuers.Get("orgempty"); ok {
		t.Errorf("cached %+v; an empty enumeration must never be cached, least of all as Absent", cached)
	}
	if cached, ok := staleOrgIssuers.Get("orgempty"); ok {
		t.Errorf("stale-cached %+v; an empty enumeration must never become last known good", cached)
	}
}

// TestLookupAllBlindWithStaleFallsOpen pins the ORDER of the two terminal
// branches: the exhaustive all-blind verdict is checked before the stale
// fallback.
//
// "Every installation reports it cannot read .github" is positive knowledge and
// falls open by design. Consulting the stale cache first would instead keep
// serving a Present entry forever for an org that has legitimately removed the
// App's access to .github, and would never re-cache the Absent verdict.
func TestLookupAllBlindWithStaleFallsOpen(t *testing.T) {
	cleanupOrgIssuers(t, "orgallow")

	allow, err := (&OrgTrustedIssuers{Issuers: []string{testGitHubIssuer}}).Compile()
	if err != nil {
		t.Fatalf("Compile() = %v", err)
	}
	staleOrgIssuers.Add("orgallow", presentOrgIssuerEntry(allow))

	blind := newAppsTransport(t, newOrgFakeGitHub(withNoGitHubRepoAccess()))
	s := &sts{rrm: &enumMgr{installs: []ghinstall.Installation{{Transport: blind, ID: 1, AppID: 10}}}, appCount: 1}

	entry, err := s.orgIssuerLookup(t.Context(), "orgallow")
	if err != nil {
		t.Fatalf("orgIssuerLookup() = %v, want nil", err)
	}
	if entry.state != orgIssuerAbsent {
		t.Fatalf("state = %v, want orgIssuerAbsent — the exhaustive all-blind verdict must win over the stale entry", entry.state)
	}
}

// TestLookupAbsentFileIsCachedAbsent covers the DEFINITIVE absent path: an
// installation that can read .github and finds no allowlist file there.
//
// This is the default state of every organization that has not adopted the
// feature, which makes it the most-travelled path in the whole lookup. If it
// resolved to an error instead of Absent, every token exchange in every such
// organization would fail closed.
//
// The blind-installation tests do not cover it. They reach Absent through the
// exhaustive-agreement branch (every installation reported fetchNoAccess via a
// 422 mint); this reaches it through a definitive 404, a separate branch that
// was otherwise unexercised.
func TestLookupAbsentFileIsCachedAbsent(t *testing.T) {
	cleanupOrgIssuers(t, "orgnone")

	atr := newAppsTransport(t, newFakeGitHub())
	s := &sts{rrm: &enumMgr{installs: []ghinstall.Installation{{Transport: atr, ID: 1, AppID: 10}}}, appCount: 1}

	entry, err := s.orgIssuerLookup(t.Context(), "orgnone")
	if err != nil {
		t.Fatalf("orgIssuerLookup() = %v, want nil — a missing allowlist file must not fail the exchange", err)
	}
	if entry.state != orgIssuerAbsent {
		t.Fatalf("state = %v, want orgIssuerAbsent", entry.state)
	}
	if cached, ok := orgIssuers.Get("orgnone"); !ok || cached.state != orgIssuerAbsent {
		t.Errorf("primary cache = %+v (ok = %v), want Absent", cached, ok)
	}
	// Absent is durable knowledge, so it belongs in the stale cache too.
	if cached, ok := staleOrgIssuers.Get("orgnone"); !ok || cached.state != orgIssuerAbsent {
		t.Errorf("stale cache = %+v (ok = %v), want Absent", cached, ok)
	}
}

func TestCheckOrgTrustedIssuers(t *testing.T) {
	enforce, err := (&OrgTrustedIssuers{Issuers: []string{testGitHubIssuer}}).Compile()
	if err != nil {
		t.Fatalf("Compile() = %v", err)
	}
	audit, err := (&OrgTrustedIssuers{Mode: ModeAudit, Issuers: []string{testGitHubIssuer}}).Compile()
	if err != nil {
		t.Fatalf("Compile() = %v", err)
	}

	for _, tc := range []struct {
		name         string
		entry        orgIssuerEntry
		issuer       string
		wantCode     codes.Code // OK means the exchange proceeds
		wantDecision bool
		wantAllowed  bool
	}{
		{
			name:     "absent permits anything",
			entry:    absentOrgIssuerEntry(),
			issuer:   "https://whatever.example.com",
			wantCode: codes.OK,
		},
		{
			name:     "enforce permits a listed issuer",
			entry:    presentOrgIssuerEntry(enforce),
			issuer:   testGitHubIssuer,
			wantCode: codes.OK,
		},
		{
			name:         "enforce denies an unlisted issuer",
			entry:        presentOrgIssuerEntry(enforce),
			issuer:       "https://evil.example.com",
			wantCode:     codes.PermissionDenied,
			wantDecision: true,
			wantAllowed:  false,
		},
		{
			name:         "audit permits an unlisted issuer but records it",
			entry:        presentOrgIssuerEntry(audit),
			issuer:       "https://evil.example.com",
			wantCode:     codes.OK,
			wantDecision: true,
			wantAllowed:  true,
		},
		{
			name:     "invalid denies",
			entry:    invalidOrgIssuerEntry(status.Error(codes.FailedPrecondition, msgIssuerConfigInvalid)),
			issuer:   testGitHubIssuer,
			wantCode: codes.FailedPrecondition,
		},
		{
			// A zero value reaching the check must be an internal error, never a pass.
			name:     "unknown state is internal, not a pass",
			entry:    orgIssuerEntry{},
			issuer:   testGitHubIssuer,
			wantCode: codes.Internal,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			owner := "owner-" + tc.name
			cleanupOrgIssuers(t, owner)
			orgIssuers.Add(owner, tc.entry)

			// rrm is deliberately nil: every row pre-seeds the primary cache, so
			// orgIssuerLookup must return on its cache hit without enumerating.
			// A nil-pointer panic here means the check is doing more than it should.
			s := &sts{appCount: 1}
			decision, err := s.checkOrgTrustedIssuers(t.Context(), owner, tc.issuer)

			if tc.wantCode == codes.OK {
				if err != nil {
					t.Fatalf("checkOrgTrustedIssuers() = %v, want nil", err)
				}
			} else {
				st, ok := status.FromError(err)
				if !ok {
					t.Fatalf("checkOrgTrustedIssuers() = %T, want a gRPC status", err)
				}
				if st.Code() != tc.wantCode {
					t.Fatalf("code = %v, want %v", st.Code(), tc.wantCode)
				}
			}

			if tc.wantDecision {
				if decision == nil {
					t.Fatal("decision = nil, want it recorded for the Event")
				}
				if decision.Issuer != tc.issuer {
					t.Errorf("decision.Issuer = %q, want %q", decision.Issuer, tc.issuer)
				}
				if decision.Allowed != tc.wantAllowed {
					t.Errorf("decision.Allowed = %v, want %v", decision.Allowed, tc.wantAllowed)
				}
			} else if decision != nil {
				t.Errorf("decision = %+v, want nil", decision)
			}
		})
	}
}

// TestCheckOrgTrustedIssuersPropagatesLookupError is the fail-closed guard. If
// the lookup cannot establish the org's allowlist, the exchange must be denied.
// Swallowing that error would return (nil, nil) — indistinguishable from
// "permitted" — and would silently disable the control for any org whose
// lookup is failing.
func TestCheckOrgTrustedIssuersPropagatesLookupError(t *testing.T) {
	cleanupOrgIssuers(t, "orgallow")

	rl := newAppsTransport(t, newOrgFakeGitHub(withContentsRateLimited()))
	s := &sts{rrm: &enumMgr{installs: []ghinstall.Installation{{Transport: rl, ID: 1, AppID: 10}}}, appCount: 1}

	decision, err := s.checkOrgTrustedIssuers(t.Context(), "orgallow", testGitHubIssuer)
	st, ok := status.FromError(err)
	if !ok || st.Code() != codes.ResourceExhausted {
		t.Fatalf("checkOrgTrustedIssuers() = %v, want ResourceExhausted — an unresolvable lookup must fail closed", err)
	}
	if decision != nil {
		t.Errorf("decision = %+v, want nil when the lookup itself failed", decision)
	}
}

// TestDeniedMessagesLeakNothing pins the caller-visible denial string. Identity
// is caller-controlled, so any holder of a verified token can probe an org; the
// fixed message is what bounds that disclosure.
func TestDeniedMessagesLeakNothing(t *testing.T) {
	owner := "leaky-org"
	cleanupOrgIssuers(t, owner)
	allow, err := (&OrgTrustedIssuers{Issuers: []string{"https://secret-idp.internal.example.com"}}).Compile()
	if err != nil {
		t.Fatalf("Compile() = %v", err)
	}
	orgIssuers.Add(owner, presentOrgIssuerEntry(allow))

	s := &sts{appCount: 1}
	_, err = s.checkOrgTrustedIssuers(t.Context(), owner, "https://evil.example.com")
	st, _ := status.FromError(err)
	if st.Message() != msgIssuerNotPermitted {
		t.Fatalf("message = %q, want exactly %q", st.Message(), msgIssuerNotPermitted)
	}
	// Belt-and-braces on the constant itself: the assertion above already pins
	// the message, so these guard msgIssuerNotPermitted's own definition rather
	// than this call.
	if strings.Contains(msgIssuerNotPermitted, "secret-idp") || strings.Contains(msgIssuerNotPermitted, owner) {
		t.Error("msgIssuerNotPermitted must not be able to carry org-specific detail")
	}
}

// newExchangeContext returns a context carrying a bearer token for
// testGitHubIssuer with subject "foo", and registers the verifier for it.
//
// Both values are fixed rather than parameters. Every trust-policy fixture in
// testdata specifies subject "foo", and the allowlist fixtures are written in
// terms of testGitHubIssuer, so a caller varying either would stop matching the
// fixtures it is testing against. An earlier revision took them as arguments
// for a schemeless-issuer test that turned out to be unbuildable —
// oidcvalidate.IsValidIssuer rejects "accounts.google.com", so TrustPolicy
// refuses it before any allowlist runs.
func newExchangeContext(t *testing.T) context.Context {
	t.Helper()

	const (
		iss     = testGitHubIssuer
		subject = "foo"
	)
	pk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("cannot generate RSA key: %v", err)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: pk}, nil)
	if err != nil {
		t.Fatalf("jose.NewSigner() = %v", err)
	}
	token, err := josejwt.Signed(signer).Claims(josejwt.Claims{
		Subject:  subject,
		Issuer:   iss,
		Audience: josejwt.Audience{"octosts"},
		Expiry:   josejwt.NewNumericDate(time.Now().Add(10 * time.Minute)),
	}).Serialize()
	if err != nil {
		t.Fatalf("Serialize() = %v", err)
	}
	provider.AddTestKeySetVerifier(t, iss, &oidc.StaticKeySet{PublicKeys: []crypto.PublicKey{pk.Public()}})
	return metadata.NewIncomingContext(t.Context(), metadata.MD{"authorization": []string{"Bearer " + token}})
}

// forgetTrustPolicy clears the trust-policy caches for a scope, before and after.
func forgetTrustPolicy(t *testing.T, owner string) {
	t.Helper()
	key := cacheTrustPolicyKey{owner: owner, repo: "repo", identity: "foo"}
	purge := func() {
		trustPolicies.Remove(key)
		staleTrustPolicies.Remove(key)
	}
	purge()
	t.Cleanup(purge)
}

func TestExchangeEnforcesOrgAllowlist(t *testing.T) {
	for _, tc := range []struct {
		name     string
		owner    string
		wantCode codes.Code // OK means the exchange succeeds
	}{
		{name: "listed issuer succeeds", owner: "orgallow", wantCode: codes.OK},
		{name: "unlisted issuer denied", owner: "orgdeny", wantCode: codes.PermissionDenied},
		{name: "audit permits unlisted", owner: "orgaudit", wantCode: codes.OK},
		{name: "invalid config denied", owner: "orgbad", wantCode: codes.FailedPrecondition},
		{name: "no config succeeds", owner: "org", wantCode: codes.OK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cleanupOrgIssuers(t, tc.owner)
			forgetTrustPolicy(t, tc.owner)

			atr := newAppsTransport(t, newFakeGitHub())
			ctx := newExchangeContext(t)
			s := &sts{rrm: &fakeInstallMgr{atr: atr}, appCount: 1}

			_, err := s.Exchange(ctx, &v1.ExchangeRequest{
				Identity: "foo",
				Scope:    tc.owner + "/repo",
			})
			if tc.wantCode == codes.OK {
				if err != nil {
					t.Fatalf("Exchange() = %v, want success", err)
				}
				return
			}
			st, ok := status.FromError(err)
			if !ok {
				t.Fatalf("Exchange() = %T, want a gRPC status", err)
			}
			if st.Code() != tc.wantCode {
				t.Errorf("code = %v, want %v", st.Code(), tc.wantCode)
			}
		})
	}
}

// allowlistCounter counts reads of the allowlist file so caching can be asserted
// by observed GitHub traffic rather than by the cache being non-empty — which a
// re-read on every exchange would also satisfy.
type allowlistCounter struct {
	http.Handler
	n atomic.Int32
}

func (c *allowlistCounter) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if strings.HasSuffix(r.URL.Path, "/trusted-token-issuers.yaml") {
		c.n.Add(1)
	}
	c.Handler.ServeHTTP(w, r)
}

// TestExchangeAllowlistIsCached is the regression test for a defect in the
// superseded PR #901: the absent-config case re-read GitHub on every exchange.
//
// It asserts the READ COUNT, not merely that the cache is populated. The weaker
// assertion passes even if the cache-hit early return in orgIssuerLookup is
// deleted, because each exchange would still write the entry on its way out.
func TestExchangeAllowlistIsCached(t *testing.T) {
	cleanupOrgIssuers(t, "org")
	forgetTrustPolicy(t, "org")

	counter := &allowlistCounter{Handler: newFakeGitHub()}
	atr := newAppsTransport(t, counter)
	ctx := newExchangeContext(t)
	s := &sts{rrm: &fakeInstallMgr{atr: atr}, appCount: 1}

	for i := range 2 {
		if _, err := s.Exchange(ctx, &v1.ExchangeRequest{Identity: "foo", Scope: "org/repo"}); err != nil {
			t.Fatalf("Exchange() attempt %d = %v", i+1, err)
		}
	}

	if got := counter.n.Load(); got != 1 {
		t.Errorf("allowlist was read %d times across 2 exchanges, want 1 — the verdict must be cached", got)
	}
	if _, ok := orgIssuers.Get("org"); !ok {
		t.Error("the allowlist verdict for org should be cached after the first exchange")
	}
}

// captureCEClient records the events the exchange emits. It exists because
// nothing else in this package observes the emitted Event, so dropping the
// e.IssuerAllowlist assignment in Exchange was otherwise invisible: the
// decision reached checkOrgTrustedIssuers' caller and went nowhere.
type captureCEClient struct {
	mu     sync.Mutex
	events []cloudevents.Event
}

func (c *captureCEClient) Send(_ context.Context, e cloudevents.Event) cloudevents.Result {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events = append(c.events, e)
	return nil
}

func (c *captureCEClient) Request(_ context.Context, _ cloudevents.Event) (*cloudevents.Event, cloudevents.Result) {
	return nil, nil
}

func (c *captureCEClient) StartReceiver(_ context.Context, _ interface{}) error { return nil }

func (c *captureCEClient) sent() []cloudevents.Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]cloudevents.Event(nil), c.events...)
}

var _ cloudevents.Client = (*captureCEClient)(nil)

// TestExchangeRecordsAuditDecisionOnEvent pins the audit-mode decision all the
// way onto the emitted Event. An audit-mode pass-through is invisible in the
// response — the exchange succeeds and returns a token exactly as an unlisted
// issuer with no allowlist would — so the Event is the ONLY place an operator
// can see that enforcement would have denied this exchange. That makes the
// assignment in Exchange part of the control, not bookkeeping.
func TestExchangeRecordsAuditDecisionOnEvent(t *testing.T) {
	cleanupOrgIssuers(t, "orgaudit")
	forgetTrustPolicy(t, "orgaudit")

	ce := &captureCEClient{}
	atr := newAppsTransport(t, newFakeGitHub())
	ctx := newExchangeContext(t)
	s := &sts{rrm: &fakeInstallMgr{atr: atr}, appCount: 1, ceclient: ce, metrics: true}

	if _, err := s.Exchange(ctx, &v1.ExchangeRequest{Identity: "foo", Scope: "orgaudit/repo"}); err != nil {
		t.Fatalf("Exchange() = %v, want success (audit mode never denies)", err)
	}

	sent := ce.sent()
	if len(sent) != 1 {
		t.Fatalf("emitted %d events, want 1", len(sent))
	}

	var got Event
	if err := json.Unmarshal(sent[0].Data(), &got); err != nil {
		t.Fatalf("decoding event data: %v", err)
	}
	if got.IssuerAllowlist == nil {
		t.Fatal("Event.IssuerAllowlist is nil — the audit decision was dropped on the way to the Event")
	}
	want := &IssuerDecision{Mode: ModeAudit, Issuer: testGitHubIssuer, Allowed: true}
	if diff := cmp.Diff(want, got.IssuerAllowlist); diff != "" {
		t.Errorf("Event.IssuerAllowlist (-want +got):\n%s", diff)
	}
}

// notInstalledMgr reports that the App is not installed — Get fails — while
// still being able to enumerate. That asymmetry is what makes the ORDER of the
// allowlist check observable: a lookup that consults GetAll before Get would
// read the allowlist here, and a correctly ordered one never gets that far.
type notInstalledMgr struct {
	atr *ghinstallation.AppsTransport
}

func (m *notInstalledMgr) Get(_ context.Context, _, _, _ string) (*ghinstallation.AppsTransport, int64, error) {
	return nil, 0, status.Error(codes.NotFound, "not installed")
}

func (m *notInstalledMgr) GetByInstallation(_ context.Context, _ string, _ int64) (*ghinstallation.AppsTransport, int64, error) {
	return nil, 0, status.Error(codes.NotFound, "not found")
}

func (m *notInstalledMgr) GetAll(_ context.Context, _ string) ([]ghinstall.Installation, error) {
	return []ghinstall.Installation{{Transport: m.atr, ID: 1234, AppID: m.atr.AppID()}}, nil
}

func (m *notInstalledMgr) GetAllFresh(ctx context.Context, owner string) ([]ghinstall.Installation, error) {
	return m.GetAll(ctx, owner)
}

var _ ghinstall.Manager = (*notInstalledMgr)(nil)

// TestExchangeUninstalledOwnerReadsNoAllowlist pins the ORDER of the allowlist
// check against the installation lookup, which is a security property rather
// than a cost one.
//
// scope is caller-supplied and arbitrary. The check therefore runs AFTER
// s.rrm.Get, whose negative install cache rejects an owner the App is not
// installed on. Hoisting the check above it would let any holder of one valid
// token drive an installation enumeration, a token mint and a contents read
// against ANY organization on GitHub, once per request — unauthenticated
// amplification through this service.
//
// Note the direction being pinned. Moving the check LATER is harmless and no
// test can distinguish it; moving it EARLIER is the regression that matters,
// and this is what catches it.
func TestExchangeUninstalledOwnerReadsNoAllowlist(t *testing.T) {
	cleanupOrgIssuers(t, "orgallow")
	forgetTrustPolicy(t, "orgallow")

	counter := &allowlistCounter{Handler: newFakeGitHub()}
	atr := newAppsTransport(t, counter)
	ctx := newExchangeContext(t)
	s := &sts{rrm: &notInstalledMgr{atr: atr}, appCount: 1}

	if _, err := s.Exchange(ctx, &v1.ExchangeRequest{
		Identity: "foo",
		Scope:    "orgallow/repo",
	}); err == nil {
		t.Fatal("Exchange() = nil, want an error for an owner with no installation")
	}

	if got := counter.n.Load(); got != 0 {
		t.Errorf("allowlist was read %d times for an owner with no installation, want 0 — the check must not run before s.rrm.Get", got)
	}
	if _, ok := orgIssuers.Get("orgallow"); ok {
		t.Error("nothing may be cached for an owner the App is not installed on")
	}
}

// TestLookupConfirmsBeforeGrantingAllowAll is the regression test for the
// negative-cache window.
//
// An organization runs App A on selected repositories only, so A cannot read
// .github. It installs App B to turn enforcement ON. For up to the
// negative-cache TTL, GetAll cannot see B — and reports a NIL error while not
// seeing it, because manager.GetAll maps NotFound to (nil, nil). Concluding from
// the cheap enumeration alone would cache allow-all for the whole organization
// at exactly the moment enforcement was meant to begin.
func TestLookupConfirmsBeforeGrantingAllowAll(t *testing.T) {
	cleanupOrgIssuers(t, "orgallow")

	blind := newAppsTransport(t, newOrgFakeGitHub(withNoGitHubRepoAccess()))
	hidden := newAppsTransport(t, newFakeGitHub())

	mgr := &enumMgr{
		installs: []ghinstall.Installation{{Transport: blind, ID: 1, AppID: 10}},
		freshInstalls: []ghinstall.Installation{
			{Transport: blind, ID: 1, AppID: 10},
			{Transport: hidden, ID: 2, AppID: 20},
		},
	}
	s := &sts{rrm: mgr, appCount: 2}

	entry, err := s.orgIssuerLookup(t.Context(), "orgallow")
	if err != nil {
		t.Fatalf("orgIssuerLookup() = %v, want nil", err)
	}
	if entry.state != orgIssuerPresent {
		t.Fatalf("state = %v, want orgIssuerPresent — an App hidden by the negative cache must not read as allow-all", entry.state)
	}
	if got := mgr.freshCalls.Load(); got != 1 {
		t.Errorf("GetAllFresh called %d times, want exactly 1", got)
	}
	if cached, ok := orgIssuers.Get("orgallow"); !ok || cached.state != orgIssuerPresent {
		t.Error("the confirmed allowlist should be cached")
	}
}

// TestLookupFailedConfirmNeverCachesAbsent: if the confirmation cannot be made,
// the conclusion has not been earned. That is ignorance, not absence.
func TestLookupFailedConfirmNeverCachesAbsent(t *testing.T) {
	cleanupOrgIssuers(t, "orgallow")

	blind := newAppsTransport(t, newOrgFakeGitHub(withNoGitHubRepoAccess()))

	s := &sts{rrm: &enumMgr{
		installs: []ghinstall.Installation{{Transport: blind, ID: 1, AppID: 10}},
		freshErr: errors.New("could not list installations for app 20"),
	}, appCount: 2}

	_, err := s.orgIssuerLookup(t.Context(), "orgallow")
	st, ok := status.FromError(err)
	if !ok || st.Code() != codes.Unavailable {
		t.Fatalf("orgIssuerLookup() = %v, want Unavailable when the confirmation failed", err)
	}
	if _, ok := orgIssuers.Get("orgallow"); ok {
		t.Error("nothing may be cached when the absence conclusion could not be confirmed")
	}
}

// TestLookupNewlyFoundInstallationBlindIsAbsent: a confirmation that finds a new
// App which ALSO cannot see .github earns the conclusion the cheap pass only
// guessed at.
func TestLookupNewlyFoundInstallationBlindIsAbsent(t *testing.T) {
	cleanupOrgIssuers(t, "orgallow")

	a := newAppsTransport(t, newOrgFakeGitHub(withNoGitHubRepoAccess()))
	b := newAppsTransport(t, newOrgFakeGitHub(withNoGitHubRepoAccess()))

	s := &sts{rrm: &enumMgr{
		installs: []ghinstall.Installation{{Transport: a, ID: 1, AppID: 10}},
		freshInstalls: []ghinstall.Installation{
			{Transport: a, ID: 1, AppID: 10},
			{Transport: b, ID: 2, AppID: 20},
		},
	}, appCount: 2}

	entry, err := s.orgIssuerLookup(t.Context(), "orgallow")
	if err != nil {
		t.Fatalf("orgIssuerLookup() = %v, want nil", err)
	}
	if entry.state != orgIssuerAbsent {
		t.Fatalf("state = %v, want orgIssuerAbsent", entry.state)
	}
	if cached, ok := orgIssuers.Get("orgallow"); !ok || cached.state != orgIssuerAbsent {
		t.Error("every installation, including the newly-found one, agreed — that verdict is cacheable")
	}
}

// TestLookupNewlyFoundInstallationRateLimitedFailsClosed: a newly-found App that
// cannot be READ leaves the conclusion unearned, so the exchange must fail
// closed rather than fall back to allow-all.
func TestLookupNewlyFoundInstallationRateLimitedFailsClosed(t *testing.T) {
	cleanupOrgIssuers(t, "orgallow")

	blind := newAppsTransport(t, newOrgFakeGitHub(withNoGitHubRepoAccess()))
	limited := newAppsTransport(t, newOrgFakeGitHub(withMintRateLimited()))

	s := &sts{rrm: &enumMgr{
		installs: []ghinstall.Installation{{Transport: blind, ID: 1, AppID: 10}},
		freshInstalls: []ghinstall.Installation{
			{Transport: blind, ID: 1, AppID: 10},
			{Transport: limited, ID: 2, AppID: 20},
		},
	}, appCount: 2}

	_, err := s.orgIssuerLookup(t.Context(), "orgallow")
	st, ok := status.FromError(err)
	if !ok || st.Code() != codes.ResourceExhausted {
		t.Fatalf("orgIssuerLookup() = %v, want ResourceExhausted", err)
	}
	if _, ok := orgIssuers.Get("orgallow"); ok {
		t.Error("nothing may be cached when a newly-found installation could not be read")
	}
}

// TestLookupConfirmSubsetIsAbsent: a confirmation showing FEWER installations
// (an App uninstalled since its positive cache entry was written) needs no
// special handling. The extras already reported no-access, which does not weaken
// "no installation can read .github".
func TestLookupConfirmSubsetIsAbsent(t *testing.T) {
	cleanupOrgIssuers(t, "orgallow")

	a := newAppsTransport(t, newOrgFakeGitHub(withNoGitHubRepoAccess()))
	b := newAppsTransport(t, newOrgFakeGitHub(withNoGitHubRepoAccess()))

	s := &sts{rrm: &enumMgr{
		installs: []ghinstall.Installation{
			{Transport: a, ID: 1, AppID: 10},
			{Transport: b, ID: 2, AppID: 20},
		},
		freshInstalls: []ghinstall.Installation{{Transport: a, ID: 1, AppID: 10}},
	}, appCount: 2}

	entry, err := s.orgIssuerLookup(t.Context(), "orgallow")
	if err != nil {
		t.Fatalf("orgIssuerLookup() = %v, want nil", err)
	}
	if entry.state != orgIssuerAbsent {
		t.Fatalf("state = %v, want orgIssuerAbsent", entry.state)
	}
}

// TestTallyAccumulatesAcrossPasses pins the property the confirmation step is
// built on: a second scanInstalls pass ADDS to the first pass's evidence.
// Recomputing instead of accumulating would let a failure in the second pass go
// unnoticed and turn ignorance into org-wide allow-all.
func TestTallyAccumulatesAcrossPasses(t *testing.T) {
	blindA := newAppsTransport(t, newOrgFakeGitHub(withNoGitHubRepoAccess()))
	blindB := newAppsTransport(t, newOrgFakeGitHub(withNoGitHubRepoAccess()))
	broken := newAppsTransport(t, newOrgFakeGitHub(withContentsServerError()))

	s := &sts{appCount: 2}
	first := []ghinstall.Installation{{Transport: blindA, ID: 1, AppID: 10}}

	t.Run("a failure in the second pass destroys exhaustiveness", func(t *testing.T) {
		var tally orgIssuerTally
		if _, definitive := s.scanInstalls(t.Context(), "orgallow", first, &tally); definitive {
			t.Fatal("scanInstalls() = definitive, want not definitive for an all-blind pass")
		}
		if !tally.exhaustiveNoAccess() {
			t.Fatal("after pass 1 the evidence should be exhaustive no-access; this test is vacuous otherwise")
		}
		second := []ghinstall.Installation{{Transport: broken, ID: 2, AppID: 20}}
		if _, definitive := s.scanInstalls(t.Context(), "orgallow", second, &tally); definitive {
			t.Fatal("scanInstalls() = definitive, want not definitive for a failed read")
		}
		if tally.exhaustiveNoAccess() {
			t.Error("a failure in the second pass must destroy exhaustiveness, or ignorance becomes org-wide allow-all")
		}
	})

	t.Run("a second pass that also agrees keeps exhaustiveness", func(t *testing.T) {
		var tally orgIssuerTally
		s.scanInstalls(t.Context(), "orgallow", first, &tally)
		second := []ghinstall.Installation{{Transport: blindB, ID: 2, AppID: 20}}
		s.scanInstalls(t.Context(), "orgallow", second, &tally)
		if !tally.exhaustiveNoAccess() {
			t.Error("every installation across both passes agreed; that is exhaustive no-access")
		}
	})

	// The common production path: the confirmation found nothing new, so
	// installsNotIn returns nil and the second pass scans an empty slice. It must
	// leave the first pass's verdict intact rather than resetting anything.
	t.Run("an empty second pass leaves the verdict intact", func(t *testing.T) {
		var tally orgIssuerTally
		s.scanInstalls(t.Context(), "orgallow", first, &tally)
		if _, definitive := s.scanInstalls(t.Context(), "orgallow", nil, &tally); definitive {
			t.Fatal("scanInstalls() over an empty slice = definitive, want not definitive")
		}
		if !tally.exhaustiveNoAccess() {
			t.Error("an empty second pass must not disturb the first pass's verdict")
		}
	})
}

// TestExhaustiveNoAccessZeroTallyIsFalse pins the fail-open guard that no
// end-to-end test can reach, since orgIssuerLookup is only entered after routing
// already found an installation. Without total > 0 the comparison is 0 == 0,
// which would grant allow-all off no evidence at all.
func TestExhaustiveNoAccessZeroTallyIsFalse(t *testing.T) {
	var tally orgIssuerTally
	if tally.exhaustiveNoAccess() {
		t.Error("a zero tally must not report exhaustive no-access")
	}
}

// TestInstallsNotInExcludesByID encodes the GetAllFresh contract: it can hand
// back a fresh *AppsTransport for an installation the first pass already asked,
// so exclusion must be by ID. Comparing structs or transport pointers would
// re-scan every installation and double the API cost of every absence conclusion.
func TestInstallsNotInExcludesByID(t *testing.T) {
	one := newAppsTransport(t, newFakeGitHub())
	two := newAppsTransport(t, newFakeGitHub())

	fresh := []ghinstall.Installation{
		{Transport: one, ID: 1, AppID: 10},
		{Transport: two, ID: 2, AppID: 20},
	}
	// Same ID as fresh[0], deliberately a DIFFERENT transport pointer.
	alreadyScanned := []ghinstall.Installation{{Transport: two, ID: 1, AppID: 10}}

	got := installsNotIn(fresh, alreadyScanned)
	if len(got) != 1 {
		t.Fatalf("installsNotIn() returned %d installations, want 1", len(got))
	}
	if got[0].ID != 2 {
		t.Errorf("installsNotIn() kept ID %d, want 2", got[0].ID)
	}

	if got := installsNotIn(fresh, fresh); len(got) != 0 {
		t.Errorf("installsNotIn(x, x) = %v, want empty", got)
	}
}

// TestClassifyMintErrorRateLimitedBeforeNoAccess pins the ordering that keeps a
// transient 422 from becoming AGREEMENT that .github is unreadable.
//
// GitHub documents 422 on the installation-token endpoint for both a genuine
// validation failure and "endpoint has been spammed", and mint-422 is the sole
// remaining source of agreement — so classifying an anti-abuse 422 as agreement
// would let concurrent load flip an enforcing org to allow-all. Only a 422 with no
// rate-limit signal counts.
func TestClassifyMintErrorRateLimitedBeforeNoAccess(t *testing.T) {
	mk := func(code int, hdr map[string]string) error {
		h := http.Header{}
		for k, v := range hdr {
			h.Set(k, v)
		}
		return &ghinstallation.HTTPError{
			Response: &http.Response{StatusCode: code, Header: h, Body: http.NoBody},
		}
	}
	for _, tc := range []struct {
		name     string
		err      error
		wantKind fetchKind
	}{
		{
			// The regression: agreement is what falls the org open, so a 422 that
			// carries a rate-limit signal must not supply it.
			name:     "422 with Retry-After is a limit, not agreement",
			err:      mk(http.StatusUnprocessableEntity, map[string]string{"Retry-After": "60"}),
			wantKind: fetchRateLimited,
		},
		{
			name:     "422 with exhausted quota is a limit, not agreement",
			err:      mk(http.StatusUnprocessableEntity, map[string]string{"X-RateLimit-Remaining": "0"}),
			wantKind: fetchRateLimited,
		},
		{
			// Still agreement: a bare 422 is the genuine "no .github in this
			// installation's repository selection" answer, and the org-wide
			// fail-open depends on it.
			name:     "bare 422 remains agreement",
			err:      mk(http.StatusUnprocessableEntity, nil),
			wantKind: fetchNoAccess,
		},
		{
			name:     "bare 403 is neither a limit nor agreement",
			err:      mk(http.StatusForbidden, nil),
			wantKind: fetchFailed,
		},
		{
			name:     "429 is a limit",
			err:      mk(http.StatusTooManyRequests, nil),
			wantKind: fetchRateLimited,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifyMintError(t.Context(), "org", tc.err); got.kind != tc.wantKind {
				t.Errorf("kind = %v, want %v", got.kind, tc.wantKind)
			}
		})
	}
}

// TestStaleEntryIsNotReseededIntoPrimary pins that serving a stale entry does not
// grant it a fresh primary TTL. Reseeding let an Absent admitted at t=0 be served
// past t=64:59 — five minutes beyond the one-hour stale bound it is supposed to
// have, silently widening a fail-open.
func TestStaleEntryIsNotReseededIntoPrimary(t *testing.T) {
	cleanupOrgIssuers(t, "orgallow")

	// A durable Absent, then an enumeration that cannot conclude anything.
	cacheOrgIssuerEntry(t.Context(), "orgallow", absentOrgIssuerEntry())
	orgIssuers.Remove("orgallow")
	if _, ok := staleOrgIssuers.Get("orgallow"); !ok {
		t.Fatal("stale entry missing; this test needs one to serve")
	}

	s := &sts{rrm: &enumMgr{err: errors.New("enumeration failed")}, appCount: 1}
	entry, err := s.orgIssuerLookup(t.Context(), "orgallow")
	if err != nil {
		t.Fatalf("orgIssuerLookup() = %v, want the stale entry served", err)
	}
	if entry.state != orgIssuerAbsent {
		t.Fatalf("state = %v, want the stale orgIssuerAbsent", entry.state)
	}
	if _, ok := orgIssuers.Get("orgallow"); ok {
		t.Error("stale entry was reseeded into the primary cache; that extends the fail-open past the stale TTL")
	}
}
