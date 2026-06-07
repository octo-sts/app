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
	"github.com/google/go-github/v84/github"
	expirablelru "github.com/hashicorp/golang-lru/v2/expirable"

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
// GitHub installation tokens. router selects the per-org app pool; sticky (may
// be nil) persists checks:write routing for check-run ownership across all
// pools (installation IDs are globally unique within GitHub).
func NewSecurityTokenServiceServer(router *ghinstall.OrgRouter, sticky stickystore.Store, ceclient cloudevents.Client, domain string, metrics bool) pboidc.SecurityTokenServiceServer {
	return &sts{
		router:   router,
		sticky:   sticky,
		ceclient: ceclient,
		domain:   domain,
		metrics:  metrics,
	}
}

var trustPolicies = expirablelru.NewLRU[cacheTrustPolicyKey, string](200, nil, time.Minute*5)

type sts struct {
	pboidc.UnimplementedSecurityTokenServiceServer

	router   *ghinstall.OrgRouter
	sticky   stickystore.Store
	ceclient cloudevents.Client
	domain   string
	metrics  bool
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
		Scope:    requestScope,
		Identity: request.GetIdentity(),
		Time:     time.Now(),
	}

	if s.metrics {
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
	base, e.InstallationID, e.TrustPolicy, err = s.lookupInstallAndTrustPolicy(ctx, requestScope, request.GetIdentity(), tok.Subject)
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
func (s *sts) getExchangeInstall(ctx context.Context, pool *ghinstall.OrgPool, owner, scope, identity, subject string, perms github.InstallationPermissions, readAtr *ghinstallation.AppsTransport, readID int64) (*ghinstallation.AppsTransport, int64, error) {
	if s.sticky == nil || !hasChecksWrite(perms) {
		return readAtr, readID, nil
	}

	key := routekey.Key(scope, identity, subject)
	if cachedID, ok, err := s.sticky.Get(ctx, key); err == nil && ok {
		atr, id, err := pool.M.GetByInstallation(ctx, owner, cachedID)
		if err == nil {
			return atr, id, nil
		}
		clog.FromContext(ctx).Infof("sticky install %d no longer valid for %s, reassigning", cachedID, owner)
	}

	atr, id, err := pool.M.Get(ctx, owner, scope, identity)
	if err != nil {
		return nil, 0, err
	}

	if putErr := s.sticky.Put(ctx, key, id, scope, identity, subject); putErr != nil {
		clog.FromContext(ctx).Warnf("stickystore: Put failed for key %s: %v", key, putErr)
	}
	return atr, id, nil
}

func (s *sts) lookupInstallAndTrustPolicy(ctx context.Context, scope, identity, subject string) (*ghinstallation.AppsTransport, int64, *OrgTrustPolicy, error) {
	otp := &OrgTrustPolicy{}
	var tp trustPolicy = &otp.TrustPolicy

	owner, repo := path.Dir(scope), path.Base(scope)
	if owner == "." {
		owner, repo = repo, ".github"
	} else {
		otp.Repositories = []string{repo}
	}

	if repo == ".github" {
		tp = otp
	}

	// Look up the org's app pool.
	pool, err := s.router.GetPool(owner)
	if err != nil {
		return nil, 0, nil, err
	}

	tpKey := cacheTrustPolicyKey{owner: owner, repo: repo, identity: identity}

	if cached, ok := trustPolicies.Get(tpKey); ok && cached == negativeCacheConst {
		clog.InfoContextf(ctx, "negative cache hit for %s", tpKey)
		return nil, 0, nil, status.Errorf(codes.NotFound, "unable to find trust policy for %q", tpKey.identity)
	}

	// Read the trust policy using any available installation in this org's pool.
	readAtr, readID, err := pool.M.Get(ctx, owner, scope, identity)
	if err != nil {
		return nil, 0, nil, err
	}

	readAtr, readID, err = s.lookupTrustPolicyWithRetry(ctx, pool, readAtr, readID, owner, scope, identity, tpKey, tp)
	if err != nil {
		return nil, 0, nil, err
	}

	// Now that we know the permissions, pick the exchange installation.
	atr, id, err := s.getExchangeInstall(ctx, pool, owner, scope, identity, subject, otp.Permissions, readAtr, readID)
	if err != nil {
		return nil, 0, nil, err
	}

	return atr, id, otp, nil
}

// lookupTrustPolicyWithRetry fetches the trust policy, retrying with
// different installations from the pool if the first attempt is rate-limited.
func (s *sts) lookupTrustPolicyWithRetry(ctx context.Context, pool *ghinstall.OrgPool, atr *ghinstallation.AppsTransport, id int64, owner, scope, identity string, tpKey cacheTrustPolicyKey, tp trustPolicy) (*ghinstallation.AppsTransport, int64, error) {
	err := s.lookupTrustPolicy(ctx, atr, id, tpKey, tp)
	if !isRateLimit(err) || pool.AppCount <= 1 {
		return atr, id, err
	}

	retries := min(maxRetry, pool.AppCount-1)
	for i := range retries {
		clog.InfoContextf(ctx, "policy read rate-limited, trying next app (%d/%d)", i+1, retries)
		rAtr, rId, rErr := pool.M.Get(ctx, owner, scope, identity)
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
		if err := Revoke(ctx, tok); err != nil {
			clog.WarnContextf(ctx, "failed to revoke token: %v", err)
		}
	}()

	file, _, _, err := github.NewClient(&http.Client{Transport: atr}).Repositories.GetContents(ctx,
		tpKey.owner, tpKey.repo,
		fmt.Sprintf(".github/chainguard/%s.sts.yaml", tpKey.identity),
		&github.RepositoryContentGetOptions{},
	)
	if err != nil {
		clog.InfoContextf(ctx, "failed to find trust policy: %v", err)
		var ghErr *github.ErrorResponse
		if errors.As(err, &ghErr) && ghErr.Response != nil {
			switch ghErr.Response.StatusCode {
			case http.StatusForbidden:
				return "", status.Errorf(codes.ResourceExhausted, "GitHub API rate limit exceeded (403) for %q", tpKey.identity)
			case http.StatusTooManyRequests:
				return "", status.Errorf(codes.ResourceExhausted, "GitHub API rate limit exceeded (429) for %q", tpKey.identity)
			case http.StatusNotFound:
				trustPolicies.Add(tpKey, negativeCacheConst)
			}
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
	return raw, nil
}

// ExchangeRefreshToken implements pboidc.SecurityTokenServiceServer
func (s *sts) ExchangeRefreshToken(ctx context.Context, request *pboidc.ExchangeRefreshTokenRequest) (*pboidc.TokenPair, error) {
	return nil, status.Error(codes.Unimplemented, "octo-sts does not support refresh tokens")
}

func ptr[T any](in T) *T {
	return &in
}
