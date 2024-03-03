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
	"github.com/google/go-github/v58/github"
	lru "github.com/hashicorp/golang-lru/v2"
	expirablelru "github.com/hashicorp/golang-lru/v2/expirable"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"sigs.k8s.io/yaml"

	apiauth "chainguard.dev/sdk/auth"
	pboidc "chainguard.dev/sdk/proto/platform/oidc/v1"
	"github.com/chainguard-dev/clog"
	"github.com/chainguard-dev/octo-sts/pkg/provider"
)

const (
	retryDelay = 10 * time.Millisecond
	maxRetry   = 3
)

func NewSecurityTokenServiceServer(atr *ghinstallation.AppsTransport, ceclient cloudevents.Client) pboidc.SecurityTokenServiceServer {
	return &sts{
		atr:      atr,
		ceclient: ceclient,
	}
}

var (
	// installationIDs is an LRU cache of recently used GitHub App installlations IDs.
	installationIDs, _ = lru.New2Q[string, int64](200)
	trustPolicies      = expirablelru.NewLRU[cacheTrustPolicyKey, string](200, nil, time.Minute*5)
)

type sts struct {
	pboidc.UnimplementedSecurityTokenServiceServer

	atr      *ghinstallation.AppsTransport
	ceclient cloudevents.Client
}

type cacheTrustPolicyKey struct {
	owner    string
	repo     string
	identity string
}

// Exchange implements pboidc.SecurityTokenServiceServer
func (s *sts) Exchange(ctx context.Context, request *pboidc.ExchangeRequest) (_ *pboidc.RawToken, err error) {
	clog.FromContext(ctx).Infof("exchange request: %#v", request)
	e := Event{
		Scope:    request.Scope,
		Identity: request.Identity,
	}
	defer func() {
		event := cloudevents.NewEvent()
		event.SetType("dev.octo-sts.exchange")
		event.SetSubject(fmt.Sprintf("%s/%s", request.Scope, request.Identity))
		event.SetSource("https://octo-sts.dev")
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
		return nil, status.Errorf(codes.InvalidArgument, "invalid bearer token: %v", err)
	}

	// Fetch the provider from the cache or create a new one and add to the cache
	p, err := provider.Get(ctx, issuer)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "unable to fetch or create the provider: %v", err)
	}

	verifier := p.Verifier(&oidc.Config{
		ClientID: "octo-sts.dev",
	})
	tok, err := verifier.Verify(ctx, bearer)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "unable to validate token: %v", err)
	}
	// This is typically overwritten below, but we populate this here to enrich
	// certain error paths with the issuer and subject.
	e.Actor = Actor{
		Issuer:  tok.Issuer,
		Subject: tok.Subject,
	}

	e.InstallationID, e.TrustPolicy, err = s.lookupInstallAndTrustPolicy(ctx, request.Scope, request.Identity)
	if err != nil {
		return nil, err
	}
	clog.FromContext(ctx).Infof("trust policy: %#v", e.TrustPolicy)

	// Check the token against the federation rules.
	e.Actor, err = e.TrustPolicy.CheckToken(tok)
	if err != nil {
		clog.FromContext(ctx).Warnf("token does not match trust policy: %v", err)
		return nil, err
	}

	// Synthesize a token for the requested scope and permissions based on the
	// trust policy.
	atr := ghinstallation.NewFromAppsTransport(s.atr, e.InstallationID)
	atr.InstallationTokenOptions = &github.InstallationTokenOptions{
		Repositories: e.TrustPolicy.Repositories,
		Permissions:  &e.TrustPolicy.Permissions,
	}
	token, err := atr.Token(ctx)
	if err != nil {
		var herr *ghinstallation.HTTPError
		if errors.As(err, &herr) {
			// Github returns a 422 response when something is off, and the
			// transport surfaces a not useful error message, but Github
			// actually has a pretty reasonable error message in the response
			// body typically, so extract that.
			if herr.Response.StatusCode == http.StatusUnprocessableEntity {
				if body, err := io.ReadAll(herr.Response.Body); err == nil {
					return nil, status.Errorf(codes.PermissionDenied, "token exchange failure: %s", body)
				}
			} else {
				body, err := httputil.DumpResponse(herr.Response, true)
				if err == nil {
					clog.FromContext(ctx).Warnf("token exchange failure: %s", body)
				}
			}
		} else {
			clog.FromContext(ctx).Warnf("token exchange failure: %v", err)
		}
		return nil, status.Errorf(codes.Internal, "failed to get token: %v", err)
	}

	// Compute the SHA256 hash of the token and store the hex-encoded value into e.TokenSHA256
	hash := sha256.Sum256([]byte(token))
	e.TokenSHA256 = hex.EncodeToString(hash[:])

	return &pboidc.RawToken{
		Token: token,
	}, nil
}

func (s *sts) lookupInstallAndTrustPolicy(ctx context.Context, scope, identity string) (int64, *OrgTrustPolicy, error) {
	otp := &OrgTrustPolicy{}
	var tp trustPolicy = &otp.TrustPolicy

	owner, repo := path.Dir(scope), path.Base(scope)
	if owner == "." {
		owner, repo = repo, ".github"
		tp = otp
	} else {
		otp.Repositories = []string{repo}
	}

	id, err := s.lookupInstall(ctx, owner)
	if err != nil {
		return 0, nil, err
	}

	trustPolicyKey := cacheTrustPolicyKey{
		owner:    owner,
		repo:     repo,
		identity: identity,
	}

	if err := s.lookupTrustPolicy(ctx, id, trustPolicyKey, tp); err != nil {
		return 0, nil, err
	}
	return id, otp, nil
}

func (s *sts) lookupInstall(ctx context.Context, owner string) (int64, error) {
	// check the LRU cache for the installation ID
	if v, ok := installationIDs.Get(owner); ok {
		clog.InfoContextf(ctx, "found installation in cache for %s", owner)
		return v, nil
	}

	client := github.NewClient(&http.Client{
		Transport: s.atr,
	})
	// Walk through the pages of installations looking for an organization
	// matching owner.
	page := 1
	for page != 0 {
		installs, resp, err := client.Apps.ListInstallations(ctx, &github.ListOptions{
			Page:    page,
			PerPage: 100,
		})
		if err != nil {
			return 0, err
		}

		for _, install := range installs {
			if install.Account.GetLogin() == owner {
				installID := install.GetID()
				// store in the LRU cache
				installationIDs.Add(owner, installID)
				return installID, nil
			}
		}
		page = resp.NextPage
	}

	return 0, status.Errorf(codes.NotFound, "no installation found for %q", owner)
}

type trustPolicy interface {
	Compile() error
}

func (s *sts) lookupTrustPolicy(ctx context.Context, install int64, trustPolicyKey cacheTrustPolicyKey, tp trustPolicy) error {
	raw := ""
	// check the LRU cache for the TrustPolicy
	if cachedRawPolicy, ok := trustPolicies.Get(trustPolicyKey); ok {
		clog.InfoContextf(ctx, "found trust policy in cache for %s", trustPolicyKey)
		raw = cachedRawPolicy
	}

	// if is not cached will get the trustpolicy from the api
	if raw == "" {
		atr := ghinstallation.NewFromAppsTransport(s.atr, install)
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
			return status.Errorf(codes.NotFound, "unable to find trust policy found for %q", trustPolicyKey.identity)
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
