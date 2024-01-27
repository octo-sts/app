/*
Copyright 2024 Chainguard, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package octosts

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httputil"
	"path"
	"strings"

	"github.com/bradleyfalzon/ghinstallation/v2"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/google/go-github/v58/github"
	lru "github.com/hashicorp/golang-lru"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"sigs.k8s.io/yaml"

	apiauth "chainguard.dev/sdk/auth"
	pboidc "chainguard.dev/sdk/proto/platform/oidc/v1"
	"github.com/chainguard-dev/clog"
	"github.com/chainguard-dev/octo-sts/pkg/provider"
)

func NewSecurityTokenServiceServer(atr *ghinstallation.AppsTransport) pboidc.SecurityTokenServiceServer {
	return &sts{atr: atr}
}

var (
	// installationIDs is an LRU cache of recently used GitHub App installlations IDs.
	installationIDs, _ = lru.New2Q(20 /* size */)
)

type sts struct {
	pboidc.UnimplementedSecurityTokenServiceServer

	atr *ghinstallation.AppsTransport
}

// Exchange implements pboidc.SecurityTokenServiceServer
func (s *sts) Exchange(ctx context.Context, request *pboidc.ExchangeRequest) (*pboidc.RawToken, error) {
	clog.FromContext(ctx).Infof("exchange request: %#v", request)

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

	id, tp, err := s.lookupInstallAndTrustPolicy(ctx, request.Scope, request.Identity)
	if err != nil {
		return nil, err
	}
	clog.FromContext(ctx).Infof("trust policy: %#v", tp)

	// Check the token against the federation rules.
	if err := tp.CheckToken(tok); err != nil {
		clog.FromContext(ctx).Warnf("token does not match trust policy: %v", err)
		return nil, err
	}

	// Synthesize a token for the requested scope and permissions based on the
	// trust policy.
	atr := ghinstallation.NewFromAppsTransport(s.atr, id)
	atr.InstallationTokenOptions = &github.InstallationTokenOptions{
		Repositories: tp.Repositories,
		Permissions:  &tp.Permissions,
	}
	token, err := atr.Token(ctx)
	if err != nil {
		var herr *ghinstallation.HTTPError
		if errors.As(err, &herr) {
			body, err := httputil.DumpResponse(herr.Response, true)
			if err == nil {
				clog.FromContext(ctx).Warnf("token exchange failure: %s", body)
			}
		} else {
			clog.FromContext(ctx).Warnf("token exchange failure: %v", err)
		}
		return nil, status.Errorf(codes.Internal, "failed to get token: %v", err)
	}
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

	if err := s.lookupTrustPolicy(ctx, id, owner, repo, identity, tp); err != nil {
		return 0, nil, err
	}
	return id, otp, nil
}

func (s *sts) lookupInstall(ctx context.Context, owner string) (int64, error) {
	// check the LRU cache for the installation ID
	if v, ok := installationIDs.Get(owner); ok {
		return v.(int64), nil
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

func (s *sts) lookupTrustPolicy(ctx context.Context, install int64, owner, repo, identity string, tp trustPolicy) error {
	atr := ghinstallation.NewFromAppsTransport(s.atr, install)
	// We only need to read from the repository, so create that token to fetch
	// the trust policy.
	atr.InstallationTokenOptions = &github.InstallationTokenOptions{
		Repositories: []string{repo},
		Permissions: &github.InstallationPermissions{
			Contents: ptr("read"),
		},
	}

	client := github.NewClient(&http.Client{
		Transport: atr,
	})
	file, _, _, err := client.Repositories.GetContents(ctx,
		owner, repo,
		fmt.Sprintf(".github/chainguard/%s.sts.yaml", identity),
		&github.RepositoryContentGetOptions{ /* defaults to the default branch */ },
	)
	if err != nil {
		clog.InfoContextf(ctx, "failed to find trust policy: %v", err)
		// Don't leak the error to the client.
		return status.Errorf(codes.NotFound, "unable to find trust policy found for %q", identity)
	}
	raw, err := file.GetContent()
	if err != nil {
		clog.ErrorContextf(ctx, "failed to read trust policy: %v", err)
		// Don't leak the error to the client.
		return status.Errorf(codes.NotFound, "unable to read trust policy found for %q", identity)
	}

	if err := yaml.UnmarshalStrict([]byte(raw), tp); err != nil {
		clog.InfoContextf(ctx, "failed to parse trust policy: %v", err)
		// Don't leak the error to the client.
		return status.Errorf(codes.NotFound, "unable to parse trust policy found for %q", identity)
	}

	if err := tp.Compile(); err != nil {
		clog.InfoContextf(ctx, "failed to compile trust policy: %v", err)
		// Don't leak the error to the client.
		return status.Errorf(codes.NotFound, "unable to compile trust policy found for %q", identity)
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
