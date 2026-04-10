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
	"github.com/octo-sts/app/pkg/oidcvalidate"
	"github.com/octo-sts/app/pkg/provider"
)

const (
	retryDelay = 10 * time.Millisecond
	maxRetry   = 3
)

func NewSecurityTokenServiceServer(im, rrm ghinstall.Manager, ceclient cloudevents.Client, domain string, metrics bool) pboidc.SecurityTokenServiceServer {
	return &sts{
		im:       im,
		rrm:      rrm,
		ceclient: ceclient,
		domain:   domain,
		metrics:  metrics,
	}
}

var trustPolicies = expirablelru.NewLRU[cacheTrustPolicyKey, string](200, nil, time.Minute*5)

type sts struct {
	pboidc.UnimplementedSecurityTokenServiceServer

	// im is the consistent-hash manager used when the trust policy requires
	// checks:write. Consistent hashing ensures the same GitHub App always
	// handles a given (scope, identity), which is required because GitHub
	// check runs can only be updated by the app that created them.
	im ghinstall.Manager
	// rrm is the round-robin manager used when the trust policy does NOT
	// require checks:write. If nil, im is used for all requests.
	rrm      ghinstall.Manager
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
	base, e.InstallationID, e.TrustPolicy, err = s.lookupInstallAndTrustPolicy(ctx, requestScope, request.GetIdentity())
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

// managerFor returns the appropriate Manager for the given trust policy key.
//
// If the trust policy is already cached and does NOT require checks:write,
// round-robin is used to distribute load across apps. Otherwise consistent
// hashing is used, which guarantees that the same (scope, identity) always
// routes to the same GitHub App — a requirement for updating check runs.
//
// On a cache miss we cannot know the required permissions yet, so we default
// to consistent hashing (the safe choice: it is always correct for
// checks:write policies and merely suboptimal for others on the first call).
func (s *sts) managerFor(key cacheTrustPolicyKey) ghinstall.Manager {
	if s.rrm == nil {
		return s.im
	}
	raw, ok := trustPolicies.Get(key)
	if !ok {
		return s.im
	}
	var tp OrgTrustPolicy
	if err := yaml.UnmarshalStrict([]byte(raw), &tp); err != nil {
		return s.im
	}
	if hasChecksWrite(tp.Permissions) {
		return s.im
	}
	return s.rrm
}

// hasChecksWrite reports whether the given permissions include checks:write.
func hasChecksWrite(perms github.InstallationPermissions) bool {
	return perms.Checks != nil && *perms.Checks == "write"
}

func (s *sts) lookupInstallAndTrustPolicy(ctx context.Context, scope, identity string) (*ghinstallation.AppsTransport, int64, *OrgTrustPolicy, error) {
	otp := &OrgTrustPolicy{}
	var tp trustPolicy = &otp.TrustPolicy

	owner, repo := path.Dir(scope), path.Base(scope)
	if owner == "." {
		owner, repo = repo, ".github"
	} else {
		otp.Repositories = []string{repo}
	}

	// If the repo is .github, then parse with an org policy even if the repo
	// was specified as .github because we will reject the repositories field
	// in policies otherwise.
	if repo == ".github" {
		tp = otp
	}

	trustPolicyKey := cacheTrustPolicyKey{
		owner:    owner,
		repo:     repo,
		identity: identity,
	}

	// Choose routing strategy before fetching the installation. managerFor
	// peeks the trust policy cache so that, after the first call, policies
	// without checks:write use round-robin instead of consistent hashing.
	im := s.managerFor(trustPolicyKey)
	atr, id, err := im.Get(ctx, owner, scope, identity)
	if err != nil {
		return nil, 0, nil, err
	}

	if err := s.lookupTrustPolicy(ctx, atr, id, trustPolicyKey, tp); err != nil {
		return atr, id, nil, err
	}
	return atr, id, otp, nil
}

type trustPolicy interface {
	Compile() error
}

func (s *sts) lookupTrustPolicy(ctx context.Context, base *ghinstallation.AppsTransport, install int64, trustPolicyKey cacheTrustPolicyKey, tp trustPolicy) error {
	raw := ""
	// check the LRU cache for the TrustPolicy
	if cachedRawPolicy, ok := trustPolicies.Get(trustPolicyKey); ok {
		clog.InfoContextf(ctx, "found trust policy in cache for %s", trustPolicyKey)
		raw = cachedRawPolicy
	}

	// if is not cached will get the trustpolicy from the api
	if raw == "" {
		atr := ghinstallation.NewFromAppsTransport(base, install)
		// We only need to read from the repository, so create that token to fetch
		// the trust policy.
		atr.InstallationTokenOptions = &github.InstallationTokenOptions{
			Repositories: []string{trustPolicyKey.repo},
			Permissions: &github.InstallationPermissions{
				Contents: ptr("read"),
			},
		}
		// Once we have looked up the trust policy we should revoke the token.
		defer func() {
			tok, err := atr.Token(ctx)
			if err != nil {
				clog.WarnContextf(ctx, "failed to get token for revocation: %v", err)
				return
			}
			if err := Revoke(ctx, tok); err != nil {
				clog.WarnContextf(ctx, "failed to revoke token: %v", err)
				return
			}
		}()

		client := github.NewClient(&http.Client{
			Transport: atr,
		})

		file, _, _, err := client.Repositories.GetContents(ctx,
			trustPolicyKey.owner, trustPolicyKey.repo,
			fmt.Sprintf(".github/chainguard/%s.sts.yaml", trustPolicyKey.identity),
			&github.RepositoryContentGetOptions{ /* defaults to the default branch */ },
		)
		if err != nil {
			clog.InfoContextf(ctx, "failed to find trust policy: %v", err)
			// Don't leak the error to the client.
			var ghErr *github.ErrorResponse
			if errors.As(err, &ghErr) && ghErr.Response != nil {
				switch ghErr.Response.StatusCode {
				case http.StatusForbidden:
					return status.Errorf(codes.ResourceExhausted, "GitHub API rate limit exceeded (403) for %q", trustPolicyKey.identity)
				case http.StatusTooManyRequests:
					return status.Errorf(codes.ResourceExhausted, "GitHub API rate limit exceeded (429) for %q", trustPolicyKey.identity)
				}
			}
			return status.Errorf(codes.NotFound, "unable to find trust policy for %q", trustPolicyKey.identity)
		}

		raw, err = file.GetContent()
		if err != nil {
			clog.ErrorContextf(ctx, "failed to read trust policy: %v", err)
			// Don't leak the error to the client.
			return status.Errorf(codes.NotFound, "unable to read trust policy found for %q", trustPolicyKey.identity)
		}

		if evicted := trustPolicies.Add(trustPolicyKey, raw); evicted {
			clog.InfoContextf(ctx, "evicted cachekey %s", trustPolicyKey)
		}
	}

	if err := yaml.UnmarshalStrict([]byte(raw), tp); err != nil {
		clog.InfoContextf(ctx, "failed to parse trust policy: %v", err)
		// Don't leak the error to the client.
		return status.Errorf(codes.NotFound, "unable to parse trust policy found for %q", trustPolicyKey.identity)
	}

	if err := tp.Compile(); err != nil {
		clog.InfoContextf(ctx, "failed to compile trust policy: %v", err)
		// Don't leak the error to the client.
		return status.Errorf(codes.NotFound, "unable to compile trust policy found for %q", trustPolicyKey.identity)
	}

	return nil
}

// ExchangeRefreshToken implements pboidc.SecurityTokenServiceServer
func (s *sts) ExchangeRefreshToken(ctx context.Context, request *pboidc.ExchangeRefreshTokenRequest) (*pboidc.TokenPair, error) {
	return nil, status.Error(codes.Unimplemented, "octo-sts does not support refresh tokens")
}

func ptr[T any](in T) *T {
	return &in
}
