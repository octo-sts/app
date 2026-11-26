// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package octosts

import (
	"context"
	"errors"
	"strings"

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
// all stay in the STS, so every source is held to the same rules. The STS
// also lowercases owner and repo names before asking the source, and replaces
// any error that is not a gRPC status, so a source does not have to.
type PolicySource interface {
	// TrustPolicy returns the raw trust policy (YAML or JSON) for req. Report
	// a missing policy with TrustPolicyNotFound.
	TrustPolicy(ctx context.Context, req TrustPolicyRequest) (TrustPolicyResult, error)

	// OrgTrustedIssuers returns owner's trusted-issuer allowlist, or nil
	// when the org has none, which permits any issuer the trust policies
	// allow. A source that cannot establish the allowlist must return an
	// error, never nil: the exchange fails closed on an error. owner is
	// lowercased.
	OrgTrustedIssuers(ctx context.Context, owner string) (*IssuerAllowlist, error)
}

// TrustPolicyRequest identifies the trust policy an exchange needs.
type TrustPolicyRequest struct {
	// Owner is the organization or user the requested scope belongs to,
	// lowercased.
	Owner string
	// Repo is the repository the policy belongs to, lowercased. For an
	// org-scoped request it is the org policy repository (ORG_POLICY_REPO,
	// ".github" by default), and the policy is parsed as an OrgTrustPolicy.
	Repo string
	// Identity names the policy within Repo. It is a single path segment and
	// keeps its case, as a file name in the repository would.
	Identity string
}

// TrustPolicyResult is a trust policy as a PolicySource stores it.
type TrustPolicyResult struct {
	// Raw is the policy document, YAML or JSON.
	Raw []byte
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
	return func(s *sts) {
		if src == nil {
			s.policies = nil
			return
		}
		s.policies = guardedSource{src: src}
	}
}

// policySource returns the configured source, or GitHub when none is set.
func (s *sts) policySource() PolicySource {
	if s.policies != nil {
		return s.policies
	}
	return githubPolicySource{s: s}
}

// guardedSource wraps a configured PolicySource with what the STS owns for
// every source: names are lowercased, since GitHub owner and repository
// names are case-insensitive and a source keyed on exact names would miss an
// org's allowlist for a caller who wrote "Org/repo" (and a missing allowlist
// permits every issuer); and errors are made safe to return to the caller.
//
// The GitHub source is not wrapped: installation lookup matches GitHub logins
// exactly, so it needs the owner as the caller wrote it, and its errors are
// already statuses.
type guardedSource struct {
	src PolicySource
}

func (g guardedSource) TrustPolicy(ctx context.Context, req TrustPolicyRequest) (TrustPolicyResult, error) {
	req.Owner, req.Repo = strings.ToLower(req.Owner), strings.ToLower(req.Repo)
	res, err := g.src.TrustPolicy(ctx, req)
	if err != nil {
		return TrustPolicyResult{}, sourceError(ctx, "trust policy", err)
	}
	return res, nil
}

func (g guardedSource) OrgTrustedIssuers(ctx context.Context, owner string) (*IssuerAllowlist, error) {
	allow, err := g.src.OrgTrustedIssuers(ctx, strings.ToLower(owner))
	if err != nil {
		return nil, sourceError(ctx, "org trusted issuers", err)
	}
	return allow, nil
}

// sourceError makes a source's error safe to return to the caller. A gRPC
// status passes through, and one wrapped in another error loses the wrapping
// text. A context error becomes its status. Anything else may carry the
// store's internals, so it is logged and replaced by Unavailable.
func sourceError(ctx context.Context, what string, err error) error {
	if _, ok := err.(interface{ GRPCStatus() *status.Status }); ok {
		return err
	}
	var se interface{ GRPCStatus() *status.Status }
	if errors.As(err, &se) {
		return se.GRPCStatus().Err()
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return status.FromContextError(err).Err()
	}
	clog.WarnContextf(ctx, "policy source failed reading %s: %v", what, err)
	return status.Errorf(codes.Unavailable, "unable to read %s", what)
}

// missingPolicyCache is implemented by a source that remembers missing
// policies, so the STS can answer them before spending an installation lookup.
type missingPolicyCache interface {
	knownMissing(ctx context.Context, key cacheTrustPolicyKey) bool
}

// installationSource is implemented by a source that reads through the org's
// GitHub App installations. The STS hands it the org's pool and the
// installation it picked, and gets back the installation that answered, which
// the exchange then mints with when neither an app pin nor a sticky route
// chooses one. These can mint tokens, so a PolicySource never sees them.
type installationSource interface {
	trustPolicyVia(ctx context.Context, key cacheTrustPolicyKey, scope string, pool *ghinstall.OrgPool, atr *ghinstallation.AppsTransport, id int64) (raw []byte, _ *ghinstallation.AppsTransport, _ int64, _ error)
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
	_ installationSource = githubPolicySource{}
)

// TrustPolicy reads with an installation it picks itself. The STS does not
// call it: trustPolicyVia reuses the installation the STS already picked and
// reports which one answered.
func (g githubPolicySource) TrustPolicy(ctx context.Context, req TrustPolicyRequest) (TrustPolicyResult, error) {
	pool, err := g.s.router.GetPool(req.Owner)
	if err != nil {
		return TrustPolicyResult{}, err
	}
	scope := req.Owner + "/" + req.Repo
	atr, id, err := pool.M.Get(ctx, req.Owner, scope, req.Identity)
	if err != nil {
		return TrustPolicyResult{}, err
	}
	key := cacheTrustPolicyKey{owner: req.Owner, repo: req.Repo, identity: req.Identity}
	raw, _, _, err := g.trustPolicyVia(ctx, key, scope, pool, atr, id)
	if err != nil {
		return TrustPolicyResult{}, err
	}
	return TrustPolicyResult{Raw: raw}, nil
}

func (g githubPolicySource) trustPolicyVia(ctx context.Context, key cacheTrustPolicyKey, scope string, pool *ghinstall.OrgPool, atr *ghinstallation.AppsTransport, id int64) ([]byte, *ghinstallation.AppsTransport, int64, error) {
	atr, id, raw, err := g.s.lookupTrustPolicyWithRetry(ctx, pool, atr, id, key.owner, scope, key.identity, key)
	if err != nil {
		return nil, nil, 0, err
	}
	return []byte(raw), atr, id, nil
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
