// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package octosts

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"path"
	"strings"
	"time"

	"github.com/bradleyfalzon/ghinstallation/v2"
	cloudevents "github.com/cloudevents/sdk-go/v2"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/google/go-github/v88/github"
	expirablelru "github.com/hashicorp/golang-lru/v2/expirable"

	"golang.org/x/sync/singleflight"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"sigs.k8s.io/yaml"

	apiauth "chainguard.dev/sdk/auth"
	pboidc "chainguard.dev/sdk/proto/platform/oidc/v1"
	"github.com/chainguard-dev/clog"
	"github.com/octo-sts/app/pkg/ghinstall"
	"github.com/octo-sts/app/pkg/ghtransport"
	"github.com/octo-sts/app/pkg/oidcvalidate"
	"github.com/octo-sts/app/pkg/provider"
	"github.com/octo-sts/app/pkg/routekey"
	"github.com/octo-sts/app/pkg/stickystore"
)

const (
	retryDelay         = 10 * time.Millisecond
	maxRetry           = 3
	negativeCacheConst = ""
)

// NewSecurityTokenServiceServer creates an STS that exchanges OIDC tokens for
// GitHub installation tokens. rrm handles installation selection; sticky (may
// be nil) persists checks:write routing for check-run ownership.
func NewSecurityTokenServiceServer(rrm ghinstall.Manager, sticky stickystore.Store, appCount int, ceclient cloudevents.Client, domain string, metrics bool, baseURL string, orgPolicyRepo string) pboidc.SecurityTokenServiceServer {
	return &sts{
		rrm:           rrm,
		sticky:        sticky,
		appCount:      appCount,
		ceclient:      ceclient,
		domain:        domain,
		metrics:       metrics,
		baseURL:       baseURL,
		orgPolicyRepo: orgPolicyRepo,
	}
}

var trustPolicies = expirablelru.NewLRU[cacheTrustPolicyKey, string](200, nil, time.Minute*5)
var staleTrustPolicies = expirablelru.NewLRU[cacheTrustPolicyKey, string](200, nil, time.Hour)

type sts struct {
	pboidc.UnimplementedSecurityTokenServiceServer

	rrm           ghinstall.Manager
	sticky        stickystore.Store
	appCount      int
	ceclient      cloudevents.Client
	domain        string
	metrics       bool
	baseURL       string
	orgPolicyRepo string

	// orgIssuerFlight collapses concurrent org-allowlist lookups for the same
	// owner into one enumeration. Its zero value is ready to use.
	orgIssuerFlight singleflight.Group
}

func (s *sts) policyRepo() string {
	if s.orgPolicyRepo != "" {
		return s.orgPolicyRepo
	}
	return ".github"
}

type cacheTrustPolicyKey struct {
	owner    string
	repo     string
	identity string
}

// Exchange implements pboidc.SecurityTokenServiceServer
func (s *sts) Exchange(ctx context.Context, request *pboidc.ExchangeRequest) (_ *pboidc.RawToken, err error) {
	clog.FromContext(ctx).Infof("exchange request: %#v", request.GetIdentity())

	scopes := request.GetScopes()
	var requestScope string
	switch len(scopes) {
	case 0:
		// TODO: remove this once we upgrade the action and we can make sure we are in sync with the new way
		clog.FromContext(ctx).Info("scopes not provided, fallback to scope")
		requestScope = request.GetScope() //nolint: staticcheck
	case 1:
		clog.FromContext(ctx).Infof("got scopes: %v", scopes)
		requestScope = scopes[0]
	default:
		clog.FromContext(ctx).Infof("got more than one scope: %v", scopes)
		return nil, status.Error(codes.InvalidArgument, "multiple scopes not supported")
	}

	e := Event{
		Scope:     requestScope,
		Identity:  request.GetIdentity(),
		Time:      time.Now(),
		UserAgent: extractUserAgent(ctx),
	}

	if s.metrics && s.ceclient != nil {
		defer func() {
			event := cloudevents.NewEvent()
			event.SetType("dev.octo-sts.exchange")
			event.SetSubject(fmt.Sprintf("%s/%s", requestScope, request.GetIdentity()))
			event.SetSource(fmt.Sprintf("https://%s", s.domain))
			if err != nil {
				e.Error = err.Error()
			}
			if err := event.SetData(cloudevents.ApplicationJSON, e); err != nil {
				clog.FromContext(ctx).Infof("Failed to encode event payload: %v", err)
				return
			}
			rctx := cloudevents.ContextWithRetriesExponentialBackoff(context.WithoutCancel(ctx), retryDelay, maxRetry)
			if ceresult := s.ceclient.Send(rctx, event); cloudevents.IsUndelivered(ceresult) || cloudevents.IsNACK(ceresult) {
				clog.FromContext(ctx).Errorf("Failed to deliver event: %v", ceresult)
			}
		}()
	}

	// Extract the incoming bearer token.
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "no metadata found")
	}
	auth := md.Get("authorization")
	if len(auth) != 1 {
		return nil, status.Error(codes.Unauthenticated, "expected exactly one authorization header")
	}
	bearer := strings.TrimPrefix(auth[0], "Bearer ")

	// Validate the Bearer token.
	issuer, err := apiauth.ExtractIssuer(bearer)
	if err != nil {
		clog.FromContext(ctx).Debugf("invalid bearer token: %v", err)
		return nil, status.Error(codes.InvalidArgument, "invalid bearer token")
	}

	// Validate issuer format
	if !oidcvalidate.IsValidIssuer(issuer) {
		return nil, status.Error(codes.InvalidArgument, "invalid issuer format")
	}

	// Fetch the provider from the cache or create a new one and add to the cache
	p, err := provider.Get(ctx, issuer)
	if err != nil {
		clog.FromContext(ctx).Debugf("unable to fetch or create the provider: %v", err)
		return nil, status.Error(codes.InvalidArgument, "unable to fetch or create the provider")
	}

	verifier := p.Verifier(&oidc.Config{
		// The audience is verified later on by the trust policy.
		SkipClientIDCheck: true,
	})
	tok, err := verifier.Verify(ctx, bearer)
	if err != nil {
		clog.FromContext(ctx).Debugf("unable to validate token: %v", err)
		return nil, status.Error(codes.Unauthenticated, "unable to verify bearer token")
	}
	// This is typically overwritten below, but we populate this here to enrich
	// certain error paths with the issuer and subject.
	e.Actor = Actor{
		Issuer:  tok.Issuer,
		Subject: tok.Subject,
	}

	// Request validation.
	if requestScope == "" {
		return nil, status.Error(codes.InvalidArgument, "scope must be provided")
	}
	if request.GetIdentity() == "" {
		return nil, status.Error(codes.InvalidArgument, "identity must be provided")
	}

	var base *ghinstallation.AppsTransport
	base, e.InstallationID, e.TrustPolicy, e.IssuerAllowlist, err = s.lookupInstallAndTrustPolicy(ctx, requestScope, request.GetIdentity(), tok.Subject, issuer)
	if err != nil {
		return nil, err
	}
	clog.FromContext(ctx).Infof("trust policy: %#v", e.TrustPolicy)

	// Check the token against the federation rules.
	e.Actor, err = e.TrustPolicy.CheckToken(tok, s.domain)
	if err != nil {
		clog.FromContext(ctx).Warnf("token does not match trust policy: %v", err)
		return nil, err
	}

	// Synthesize a token for the requested scope and permissions based on the
	// trust policy.
	atr := ghinstallation.NewFromAppsTransport(base, e.InstallationID)
	atr.InstallationTokenOptions = &github.InstallationTokenOptions{
		Repositories: e.TrustPolicy.Repositories,
		Permissions:  &e.TrustPolicy.Permissions,
	}
	// Enrich context so the httpmetrics transport labels the token exchange
	// rate limit metrics with the specific installation consuming quota.
	ctx = ghtransport.EnrichContext(ctx, base.AppID(), e.InstallationID)
	token, err := atr.Token(ctx)
	if err != nil {
		var herr *ghinstallation.HTTPError
		if errors.As(err, &herr) && herr.Response != nil {
			// Github returns a 422 response when something is off, and the
			// transport surfaces a not useful error message, but Github
			// actually has a pretty reasonable error message in the response
			// body typically, so extract that.
			if herr.Response.StatusCode == http.StatusUnprocessableEntity {
				if body, err := io.ReadAll(herr.Response.Body); err == nil {
					clog.FromContext(ctx).Debugf("token exchange failure (StatusUnprocessableEntity): %s", body)
					return nil, status.Error(codes.PermissionDenied, "token exchange failure (StatusUnprocessableEntity)")
				}
			} else if herr.Response.Body != nil {
				body, err := httputil.DumpResponse(herr.Response, true)
				if err == nil {
					clog.FromContext(ctx).Warn("token exchange failure, redacting body in logs")
					// Log the response body in debug mode only, as it may contain sensitive information.
					clog.FromContext(ctx).Debugf("token exchange failure: %s", body)
				}
			}
		} else {
			clog.FromContext(ctx).Debugf("token exchange failure: %v", err)
			clog.FromContext(ctx).Warn("token exchange failure, redacting error in logs")
		}
		clog.FromContext(ctx).Debugf("failed to get token: %v", err)
		return nil, status.Error(codes.Internal, "failed to get token")
	}

	// Compute the SHA256 hash of the token and store the hex-encoded value into e.TokenSHA256
	hash := sha256.Sum256([]byte(token))
	e.TokenSHA256 = hex.EncodeToString(hash[:])

	return &pboidc.RawToken{
		Token: token,
	}, nil
}

// hasChecksWrite reports whether the given permissions include checks:write.
func hasChecksWrite(perms github.InstallationPermissions) bool {
	return perms.Checks != nil && *perms.Checks == "write"
}

// getExchangeInstall picks the installation for the token exchange.
// For checks:write policies it returns the persisted sticky installation,
// or assigns a new one via capacity-aware round-robin and persists it.
// For all other policies it returns the installation that read the policy.
func (s *sts) getExchangeInstall(ctx context.Context, owner, scope, identity, subject string, perms github.InstallationPermissions, readAtr *ghinstallation.AppsTransport, readID int64) (*ghinstallation.AppsTransport, int64, error) {
	if s.sticky == nil || !hasChecksWrite(perms) {
		return readAtr, readID, nil
	}

	key := routekey.Key(scope, identity, subject)
	if cachedID, ok, err := s.sticky.Get(ctx, key); err == nil && ok {
		atr, id, err := s.rrm.GetByInstallation(ctx, owner, cachedID)
		if err == nil {
			return atr, id, nil
		}
		clog.FromContext(ctx).Infof("sticky install %d no longer valid for %s, reassigning", cachedID, owner)
	}

	atr, id, err := s.rrm.Get(ctx, owner, scope, identity)
	if err != nil {
		return nil, 0, err
	}

	if putErr := s.sticky.Put(ctx, key, id, scope, identity, subject); putErr != nil {
		clog.FromContext(ctx).Warnf("stickystore: Put failed for key %s: %v", key, putErr)
	}
	return atr, id, nil
}

// lookupInstallAndTrustPolicy resolves the installation, enforces the
// organization trusted-issuer allowlist, and loads the trust policy.
//
// issuer must be the value apiauth.ExtractIssuer returned — the same one
// provider.Get was given — because allowlist entries are always written with a
// scheme, and ExtractIssuer applies auth.NormalizeIssuer. In practice the two
// forms coincide for every token that reaches here: the only value
// NormalizeIssuer rewrites is the schemeless "accounts.google.com", and
// TrustPolicy.CheckToken rejects that outright because
// oidcvalidate.IsValidIssuer returns false for it. Passing the normalized value
// is the conservative choice should either of those change.
func (s *sts) lookupInstallAndTrustPolicy(ctx context.Context, scope, identity, subject, issuer string) (*ghinstallation.AppsTransport, int64, *OrgTrustPolicy, *IssuerDecision, error) {
	otp := &OrgTrustPolicy{}
	var tp trustPolicy = &otp.TrustPolicy

	owner, repo := path.Dir(scope), path.Base(scope)
	if owner == "." {
		owner, repo = repo, s.policyRepo()
	} else {
		otp.Repositories = []string{repo}
	}

	// If the repo is the org policy repo, then parse with an org policy even
	// if the repo was specified explicitly because we will reject the
	// repositories field in policies otherwise.
	if repo == s.policyRepo() {
		tp = otp
	}

	tpKey := cacheTrustPolicyKey{owner: owner, repo: repo, identity: identity}

	if cached, ok := trustPolicies.Get(tpKey); ok && cached == negativeCacheConst {
		clog.InfoContextf(ctx, "negative cache hit for %s", tpKey)
		return nil, 0, nil, nil, status.Errorf(codes.NotFound, "unable to find trust policy for %q", tpKey.identity)
	}

	// Read the trust policy using any available installation.
	readAtr, readID, err := s.rrm.Get(ctx, owner, scope, identity)
	if err != nil {
		return nil, 0, nil, nil, err
	}

	// Enforce the organization trusted-issuer allowlist before spending a policy
	// read or a second token mint on an issuer we may reject.
	//
	// This runs AFTER s.rrm.Get even though it ignores its return values: Get's
	// negative install cache rejects an owner the App is not installed on before
	// we do any allowlist work, which bounds the API amplification an arbitrary
	// caller-supplied scope can drive.
	decision, err := s.checkOrgTrustedIssuers(ctx, owner, issuer)
	if err != nil {
		return nil, 0, nil, decision, err
	}

	readAtr, readID, err = s.lookupTrustPolicyWithRetry(ctx, readAtr, readID, owner, scope, identity, tpKey, tp)
	if err != nil {
		return nil, 0, nil, decision, err
	}

	// Now that we know the permissions, pick the exchange installation.
	atr, id, err := s.getExchangeInstall(ctx, owner, scope, identity, subject, otp.Permissions, readAtr, readID)
	if err != nil {
		return nil, 0, nil, decision, err
	}

	return atr, id, otp, decision, nil
}

// lookupTrustPolicyWithRetry fetches the trust policy, retrying with
// different installations if the first attempt is rate-limited.
func (s *sts) lookupTrustPolicyWithRetry(ctx context.Context, atr *ghinstallation.AppsTransport, id int64, owner, scope, identity string, tpKey cacheTrustPolicyKey, tp trustPolicy) (*ghinstallation.AppsTransport, int64, error) {
	err := s.lookupTrustPolicy(ctx, atr, id, tpKey, tp)
	if !isRateLimit(err) || s.appCount <= 1 {
		return atr, id, err
	}

	retries := min(maxRetry, s.appCount-1)
	for i := range retries {
		clog.InfoContextf(ctx, "policy read rate-limited, trying next app (%d/%d)", i+1, retries)
		rAtr, rId, rErr := s.rrm.Get(ctx, owner, scope, identity)
		if rErr != nil {
			continue
		}
		err = s.lookupTrustPolicy(ctx, rAtr, rId, tpKey, tp)
		if !isRateLimit(err) {
			return rAtr, rId, err
		}
	}
	return atr, id, err
}

// isRateLimit reports whether err is a gRPC ResourceExhausted error,
// indicating a GitHub API rate limit (403 secondary or 429 primary).
func isRateLimit(err error) bool {
	if err == nil {
		return false
	}
	st, ok := status.FromError(err)
	return ok && st.Code() == codes.ResourceExhausted
}

// IsGitHubRateLimited reports whether err looks like a GitHub rate-limit
// response, primary or secondary.
//
// The typed errors must be checked first: go-github returns *RateLimitError for
// a 403 carrying X-RateLimit-Remaining: 0 and *AbuseRateLimitError for a
// secondary limit, and NEITHER unwraps to *ErrorResponse. A status-code-only
// check therefore misses every genuine rate limit from real GitHub — which is
// the bug this function exists to fix.
//
// This is deliberately LENIENT: a bare 403 with no rate-limit marker also
// counts. That is correct for both current callers, where a false positive
// costs a retry or a redelivery rather than granting access. Anything that
// gates access needs a stricter test.
func IsGitHubRateLimited(err error) bool {
	if err == nil {
		return false
	}
	var rateLimitErr *github.RateLimitError
	var abuseRateLimitErr *github.AbuseRateLimitError
	if errors.As(err, &rateLimitErr) || errors.As(err, &abuseRateLimitErr) {
		return true
	}
	var errResp *github.ErrorResponse
	if errors.As(err, &errResp) && errResp.Response != nil {
		switch errResp.Response.StatusCode {
		case http.StatusForbidden, http.StatusTooManyRequests:
			return true
		}
	}
	return false
}

type trustPolicy interface {
	Compile() error
}

// lookupTrustPolicy fetches, parses, and compiles a trust policy into tp.
// The raw YAML is served from the LRU cache when available; on a miss
// it is read from GitHub via a short-lived contents:read token that is
// revoked after the read.
func (s *sts) lookupTrustPolicy(ctx context.Context, base *ghinstallation.AppsTransport, install int64, tpKey cacheTrustPolicyKey, tp trustPolicy) error {
	ctx = ghtransport.EnrichContext(ctx, base.AppID(), install)

	raw, err := s.fetchTrustPolicyRaw(ctx, base, install, tpKey)
	if err != nil {
		return err
	}

	if err := yaml.UnmarshalStrict([]byte(raw), tp); err != nil {
		clog.InfoContextf(ctx, "failed to parse trust policy: %v", err)
		return status.Errorf(codes.NotFound, "unable to parse trust policy found for %q", tpKey.identity)
	}
	if err := tp.Compile(); err != nil {
		clog.InfoContextf(ctx, "failed to compile trust policy: %v", err)
		return status.Errorf(codes.NotFound, "unable to compile trust policy found for %q", tpKey.identity)
	}
	return nil
}

// fetchTrustPolicyRaw returns the raw YAML for a trust policy, serving
// from the LRU cache when possible and falling back to the GitHub API.
func (s *sts) fetchTrustPolicyRaw(ctx context.Context, base *ghinstallation.AppsTransport, install int64, tpKey cacheTrustPolicyKey) (string, error) {
	if cached, ok := trustPolicies.Get(tpKey); ok {
		if cached == negativeCacheConst {
			clog.InfoContextf(ctx, "negative cache hit for %s", tpKey)
			return "", status.Errorf(codes.NotFound, "unable to find trust policy for %q", tpKey.identity)
		}
		clog.InfoContextf(ctx, "found trust policy in cache for %s", tpKey)
		return cached, nil
	}

	atr := ghinstallation.NewFromAppsTransport(base, install)
	atr.InstallationTokenOptions = &github.InstallationTokenOptions{
		Repositories: []string{tpKey.repo},
		Permissions: &github.InstallationPermissions{
			Contents: ptr("read"),
		},
	}
	defer func() {
		tok, err := atr.Token(ctx)
		if err != nil {
			clog.WarnContextf(ctx, "failed to get token for revocation: %v", err)
			return
		}
		if err := Revoke(ctx, tok, s.baseURL); err != nil {
			clog.WarnContextf(ctx, "failed to revoke token: %v", err)
		}
	}()

	client, err := newGitHubClient(atr, s.baseURL)
	if err != nil {
		return "", status.Errorf(codes.Internal, "creating GitHub client: %v", err)
	}
	file, _, _, err := client.Repositories.GetContents(ctx,
		tpKey.owner, tpKey.repo,
		fmt.Sprintf(".github/chainguard/%s.sts.yaml", tpKey.identity),
		&github.RepositoryContentGetOptions{},
	)
	if err != nil {
		clog.InfoContextf(ctx, "failed to find trust policy: %v", err)
		if IsGitHubRateLimited(err) {
			if stale, ok := staleTrustPolicies.Get(tpKey); ok {
				clog.InfoContextf(ctx, "rate-limited, serving stale cached trust policy for %s", tpKey)
				// Seed the primary cache so further exchanges during the
				// rate-limit window hit it instead of re-probing GitHub.
				trustPolicies.Add(tpKey, stale)
				return stale, nil
			}
			return "", status.Errorf(codes.ResourceExhausted, "GitHub API rate limit exceeded for %q", tpKey.identity)
		}
		var ghErr *github.ErrorResponse
		if errors.As(err, &ghErr) && ghErr.Response != nil && ghErr.Response.StatusCode == http.StatusNotFound {
			trustPolicies.Add(tpKey, negativeCacheConst)
		}
		return "", status.Errorf(codes.NotFound, "unable to find trust policy for %q", tpKey.identity)
	}

	raw, err := file.GetContent()
	if err != nil {
		clog.ErrorContextf(ctx, "failed to read trust policy: %v", err)
		return "", status.Errorf(codes.NotFound, "unable to read trust policy found for %q", tpKey.identity)
	}

	if evicted := trustPolicies.Add(tpKey, raw); evicted {
		clog.InfoContextf(ctx, "evicted cachekey %s", tpKey)
	}
	staleTrustPolicies.Add(tpKey, raw)
	return raw, nil
}

// ExchangeRefreshToken implements pboidc.SecurityTokenServiceServer
func (s *sts) ExchangeRefreshToken(ctx context.Context, request *pboidc.ExchangeRefreshTokenRequest) (*pboidc.TokenPair, error) {
	return nil, status.Error(codes.Unimplemented, "octo-sts does not support refresh tokens")
}

func ptr[T any](in T) *T {
	return &in
}

func extractUserAgent(ctx context.Context) string {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return ""
	}
	ua := md.Get("user-agent")
	return strings.Join(ua, " ")
}
