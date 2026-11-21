// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package octosts

import (
	"context"

	"github.com/bradleyfalzon/ghinstallation/v2"
	"github.com/chainguard-dev/clog"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/octo-sts/app/pkg/ghinstall"
)

// PolicySource is where the STS reads trust policies and org trusted-issuer
// allowlists from. The default, used unless WithPolicySource names another,
// reads them from the organization's repositories through its GitHub App
// installations.
//
// A source only stores and returns policies. Parsing, compiling, matching the
// caller's token against the policy, app pins and minting the GitHub token
// all stay in the STS, so every source is held to the same rules.
//
// Errors are returned to the caller as they are, so they should be gRPC
// statuses that reveal nothing about the policy. Report a missing policy with
// TrustPolicyNotFound.
type PolicySource interface {
	// TrustPolicy returns the raw trust policy (YAML or JSON) for req.
	TrustPolicy(ctx context.Context, req TrustPolicyRequest) (TrustPolicyResult, error)

	// OrgTrustedIssuers returns owner's trusted-issuer allowlist, or nil
	// when the org has none, which permits any issuer the trust policies
	// allow. A source that cannot establish the allowlist must return an
	// error, never nil: the exchange fails closed on an error.
	OrgTrustedIssuers(ctx context.Context, owner string) (*IssuerAllowlist, error)
}

// TrustPolicyRequest identifies the trust policy an exchange needs.
type TrustPolicyRequest struct {
	// Owner is the organization or user the requested scope belongs to.
	Owner string
	// Repo is the repository the policy belongs to. For an org-scoped
	// request it is the org policy repository (ORG_POLICY_REPO, ".github"
	// by default), and the policy is parsed as an OrgTrustPolicy.
	Repo string
	// Identity names the policy within Repo. It is a single path segment.
	Identity string
	// Scope is the scope as the caller sent it, used for installation
	// routing.
	Scope string

	// Pool is Owner's GitHub App pool and Install the installation the STS
	// picked from it for this exchange. A source that reads through GitHub
	// uses them; other sources can ignore them.
	Pool    *ghinstall.OrgPool
	Install ghinstall.Installation
}

// TrustPolicyResult is a trust policy as a PolicySource stores it.
type TrustPolicyResult struct {
	// Raw is the policy document, YAML or JSON.
	Raw []byte

	// Install, when set, is the installation the exchange mints with if
	// neither an app pin nor a sticky route chooses one. The GitHub source
	// returns the installation that read the policy. Other sources leave it
	// zero to keep the installation the STS picked.
	Install ghinstall.Installation
}

// TrustPolicyNotFound is the error for a trust policy that does not exist.
// The STS returns the same error for a policy that exists but does not parse,
// so a caller cannot tell the two apart.
func TrustPolicyNotFound(identity string) error {
	return status.Errorf(codes.NotFound, "unable to find trust policy for %q", identity)
}

// Option configures NewSecurityTokenServiceServer.
type Option func(*sts)

// WithPolicySource reads trust policies and org allowlists from src instead
// of from GitHub. A nil src keeps the GitHub default.
func WithPolicySource(src PolicySource) Option {
	return func(s *sts) { s.policies = src }
}

// policySource returns the configured source, or GitHub when none is set.
func (s *sts) policySource() PolicySource {
	if s.policies != nil {
		return s.policies
	}
	return githubPolicySource{s: s}
}

// missingPolicyCache is implemented by a source that remembers missing
// policies, so the STS can answer them before spending an installation lookup.
type missingPolicyCache interface {
	knownMissing(ctx context.Context, key cacheTrustPolicyKey) bool
}

// installation describes an installation picked by the STS.
func installation(atr *ghinstallation.AppsTransport, id int64) ghinstall.Installation {
	in := ghinstall.Installation{Transport: atr, ID: id}
	if atr != nil {
		in.AppID = atr.AppID()
	}
	return in
}

// githubPolicySource reads <identity>.sts.yaml and the org trusted-issuers
// file from the policy directory of the org's repositories, through its GitHub
// App installations. Its caching, rotation across installations on rate
// limits and unreadable repositories, and handling of GitHub's transient 404s
// and 403s are implemented by the sts methods it calls.
type githubPolicySource struct {
	s *sts
}

var (
	_ PolicySource       = githubPolicySource{}
	_ missingPolicyCache = githubPolicySource{}
)

func (g githubPolicySource) TrustPolicy(ctx context.Context, req TrustPolicyRequest) (TrustPolicyResult, error) {
	tpKey := cacheTrustPolicyKey{owner: req.Owner, repo: req.Repo, identity: req.Identity}
	atr, id, raw, err := g.s.lookupTrustPolicyWithRetry(ctx, req.Pool, req.Install.Transport, req.Install.ID, req.Owner, req.Scope, req.Identity, tpKey)
	if err != nil {
		return TrustPolicyResult{}, err
	}
	return TrustPolicyResult{Raw: []byte(raw), Install: installation(atr, id)}, nil
}

func (g githubPolicySource) knownMissing(ctx context.Context, key cacheTrustPolicyKey) bool {
	if cached, ok := trustPolicies.Get(key); ok && cached == negativeCacheConst {
		clog.InfoContextf(ctx, "negative cache hit for %s", key)
		return true
	}
	return false
}

func (g githubPolicySource) OrgTrustedIssuers(ctx context.Context, owner string) (*IssuerAllowlist, error) {
	entry, err := g.s.orgIssuerLookup(ctx, owner)
	if err != nil {
		return nil, err
	}

	switch entry.state {
	case orgIssuerAbsent:
		return nil, nil
	case orgIssuerInvalid:
		if entry.err != nil {
			return nil, entry.err
		}
	case orgIssuerPresent:
		if entry.allow != nil {
			return entry.allow, nil
		}
	}
	// orgIssuerUnknown, or an entry missing its payload. None may be a pass:
	// a nil allowlist with a nil error would permit every issuer.
	clog.ErrorContextf(ctx, "org issuer cache returned an unusable entry for %s: %v", owner, entry.state)
	return nil, status.Error(codes.Internal, msgIssuerUnavailable)
}
