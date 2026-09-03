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
	"maps"
	"net/http"
	"net/http/httputil"
	"path"
	"slices"
	"strconv"
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
// GitHub installation tokens. router selects the per-org app pool; sticky (may
// be nil) persists checks:write routing for check-run ownership across all
// pools (installation IDs are globally unique within GitHub).
func NewSecurityTokenServiceServer(router *ghinstall.OrgRouter, sticky stickystore.Store, apps AppSet, ceclient cloudevents.Client, domain string, metrics bool, baseURL string, orgPolicyRepo string) pboidc.SecurityTokenServiceServer {
	return &sts{
		router:        router,
		sticky:        sticky,
		apps:          apps,
		ceclient:      ceclient,
		domain:        domain,
		metrics:       metrics,
		baseURL:       baseURL,
		orgPolicyRepo: orgPolicyRepo,
	}
}

var trustPolicies = expirablelru.NewLRU[cacheTrustPolicyKey, string](200, nil, time.Minute*5)
var staleTrustPolicies = expirablelru.NewLRU[cacheTrustPolicyKey, string](200, nil, time.Hour)

// pinMisses throttles repeated GetAllFresh confirmations of app-pin misses,
// which bypass the negative install cache and hit GitHub's API. The TTL
// matches ghinstall's negative-cache TTL.
var pinMisses = expirablelru.NewLRU[string, struct{}](256, nil, time.Minute*5)

// pinConfirmTimeout bounds a shared pin-miss confirmation walk once its
// leader detaches from the triggering request's cancellation.
const pinConfirmTimeout = 30 * time.Second

// AppSet is the configured GitHub App directory used to resolve trust policy
// app pins. Names maps app_name to app ID for named apps; IDs holds every
// configured app ID (named or not) that a numeric pin may select.
type AppSet struct {
	Names map[string]int64
	IDs   map[int64]bool
}

type sts struct {
	pboidc.UnimplementedSecurityTokenServiceServer

	router        *ghinstall.OrgRouter
	sticky        stickystore.Store
	apps          AppSet
	ceclient      cloudevents.Client
	domain        string
	metrics       bool
	baseURL       string
	orgPolicyRepo string

	// orgIssuerFlight collapses concurrent org-allowlist lookups for the same
	// owner into one enumeration. Its zero value is ready to use.
	orgIssuerFlight singleflight.Group

	// pinFreshFlight collapses concurrent pin-miss confirmation walks for the
	// same owner into one GetAllFresh. Its zero value is ready to use.
	pinFreshFlight singleflight.Group
}

func (s *sts) policyRepo() string {
	if s.orgPolicyRepo != "" {
		return s.orgPolicyRepo
	}
	return ".github"
}

// managerFor returns the installation manager for owner's app pool. The
// error, when non-nil, is a terminal gRPC status (NotFound for an org with
// no configured apps).
func (s *sts) managerFor(owner string) (ghinstall.Manager, error) {
	pool, err := s.router.GetPool(owner)
	if err != nil {
		return nil, err
	}
	return pool.M, nil
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

// getExchangeInstall picks the installation for the token exchange, in
// precedence order: the policy's app pin, the persisted sticky installation
// for checks:write policies, then the installation that read the policy.
func (s *sts) getExchangeInstall(ctx context.Context, pool *ghinstall.OrgPool, owner, scope, identity, subject string, tp *TrustPolicy, readAtr *ghinstallation.AppsTransport, readID int64) (*ghinstallation.AppsTransport, int64, error) {
	eligible, err := s.eligibleApps(tp)
	if err != nil {
		return nil, 0, err
	}
	sticky := s.sticky != nil && hasChecksWrite(tp.Permissions)
	if eligible != nil {
		return s.getPinnedInstall(ctx, pool, owner, scope, identity, subject, sticky, eligible)
	}

	if !sticky {
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

	s.putSticky(ctx, key, id, scope, identity, subject)
	return atr, id, nil
}

// putSticky persists a sticky mapping, warning instead of failing on error.
func (s *sts) putSticky(ctx context.Context, key string, id int64, scope, identity, subject string) {
	if err := s.sticky.Put(ctx, key, id, scope, identity, subject); err != nil {
		clog.FromContext(ctx).Warnf("stickystore: Put failed for key %s: %v", key, err)
	}
}

// eligibleApps resolves the policy's app pin to configured app IDs.
// Returns nil when the policy does not restrict apps.
func (s *sts) eligibleApps(tp *TrustPolicy) (map[int64]bool, error) {
	switch {
	case tp.App != "":
		if id, ok := s.apps.Names[tp.App]; ok {
			return map[int64]bool{id: true}, nil
		}
		if id, err := strconv.ParseInt(tp.App, 10, 64); err == nil && s.apps.IDs[id] {
			return map[int64]bool{id: true}, nil
		}
		return nil, status.Errorf(codes.FailedPrecondition, "trust policy app %q is not a configured app", tp.App)
	case tp.appPattern != nil:
		eligible := make(map[int64]bool)
		for name, id := range s.apps.Names {
			if tp.appPattern.MatchString(name) {
				eligible[id] = true
			}
		}
		if len(eligible) == 0 {
			return nil, status.Errorf(codes.FailedPrecondition, "trust policy app_pattern %q matches no configured apps", tp.AppPattern)
		}
		return eligible, nil
	}
	return nil, nil
}

// getPinnedInstall picks among owner's installations of the eligible apps.
// Sticky policies keep sticky routing within the eligible set; others spread
// deterministically by route key. Absence conclusions (no candidates, cached
// sticky install missing) are confirmed with GetAllFresh — GetAll's negative
// cache can hide a newly installed app behind a nil error — and confirmed
// absences are cached to throttle the fresh walks.
func (s *sts) getPinnedInstall(ctx context.Context, pool *ghinstall.OrgPool, owner, scope, identity, subject string, sticky bool, eligible map[int64]bool) (*ghinstallation.AppsTransport, int64, error) {
	insts, enumErr := pool.M.GetAll(ctx, owner)
	candidates := eligibleInstalls(insts, eligible)
	fresh := false
	if len(candidates) == 0 {
		if enumErr != nil {
			return nil, 0, enumErr
		}
		missErr := status.Errorf(codes.FailedPrecondition, "no installation for %q matches the trust policy app pin", owner)
		missKey := pinMissKey(owner, eligible)
		if _, confirmed := pinMisses.Get(missKey); confirmed {
			return nil, 0, missErr
		}
		recordMiss := func(insts []ghinstall.Installation, err error) {
			if err == nil && len(eligibleInstalls(insts, eligible)) == 0 {
				pinMisses.Add(missKey, struct{}{})
			}
		}
		insts, enumErr = s.getAllFreshShared(ctx, pool, owner, recordMiss)
		candidates = eligibleInstalls(insts, eligible)
		fresh = true
		if len(candidates) == 0 {
			if enumErr != nil {
				return nil, 0, enumErr
			}
			pinMisses.Add(missKey, struct{}{})
			return nil, 0, missErr
		}
	}

	key := routekey.Key(scope, identity, subject)
	if sticky {
		if cachedID, ok, err := s.sticky.Get(ctx, key); err == nil && ok {
			inst, present, eligibleOK := locate(insts, eligible, cachedID)
			if eligibleOK {
				return inst.Transport, inst.ID, nil
			}
			// Present but ineligible is proof; absence needs confirmation,
			// since an incomplete enumeration cannot prove the install is
			// gone.
			if !present {
				if enumErr != nil {
					return nil, 0, enumErr
				}
				absKey := fmt.Sprintf("%s|inst|%d", owner, cachedID)
				_, confirmed := pinMisses.Get(absKey)
				if !confirmed && !fresh {
					recordAbsent := func(freshInsts []ghinstall.Installation, err error) {
						if err != nil {
							return
						}
						if _, p, _ := locate(freshInsts, eligible, cachedID); !p {
							pinMisses.Add(absKey, struct{}{})
						}
					}
					freshInsts, freshErr := s.getAllFreshShared(ctx, pool, owner, recordAbsent)
					inst, present, eligibleOK = locate(freshInsts, eligible, cachedID)
					if eligibleOK {
						return inst.Transport, inst.ID, nil
					}
					if !present && freshErr != nil {
						return nil, 0, freshErr
					}
					if fc := eligibleInstalls(freshInsts, eligible); len(fc) > 0 {
						candidates = fc
					}
				}
				if !present && !confirmed {
					pinMisses.Add(absKey, struct{}{})
				}
			}
			clog.FromContext(ctx).Infof("sticky install %d not in pinned app set for %s, reassigning", cachedID, owner)
		}
	}

	pick := candidates[routekey.Index(scope, identity, subject, len(candidates))]
	if sticky {
		s.putSticky(ctx, key, pick.ID, scope, identity, subject)
	}
	return pick.Transport, pick.ID, nil
}

// getAllFreshShared collapses concurrent GetAllFresh confirmation walks for
// the same owner into one. The leader detaches from its caller's cancellation
// so waiters sharing the walk are not failed by an unrelated cancel; the
// result pairs installations with the enumeration error, preserving
// partial-enumeration semantics. A shared walk may have started before a
// waiter's own cache observation, so a confirmation can lag reality by up to
// the walk's duration. record, when non-nil, receives the flight's result
// even if this caller's context ends first, so a completed walk is recorded
// rather than discarded.
func (s *sts) getAllFreshShared(ctx context.Context, pool *ghinstall.OrgPool, owner string, record func([]ghinstall.Installation, error)) ([]ghinstall.Installation, error) {
	ch := s.pinFreshFlight.DoChan(owner, func() (any, error) {
		workCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), pinConfirmTimeout)
		defer cancel()
		insts, err := pool.M.GetAllFresh(workCtx, owner)
		return insts, err
	})
	select {
	case <-ctx.Done():
		if record != nil {
			go func() {
				res := <-ch
				insts, _ := res.Val.([]ghinstall.Installation)
				record(insts, res.Err)
			}()
		}
		return nil, status.FromContextError(ctx.Err()).Err()
	case res := <-ch:
		insts, _ := res.Val.([]ghinstall.Installation)
		return insts, res.Err
	}
}

// eligibleInstalls filters insts to installations of the eligible apps.
func eligibleInstalls(insts []ghinstall.Installation, eligible map[int64]bool) []ghinstall.Installation {
	out := make([]ghinstall.Installation, 0, len(insts))
	for _, inst := range insts {
		if eligible[inst.AppID] {
			out = append(out, inst)
		}
	}
	return out
}

// pinMissKey identifies a confirmed (owner, eligible apps) pin miss.
func pinMissKey(owner string, eligible map[int64]bool) string {
	return fmt.Sprintf("%s|%v", owner, slices.Sorted(maps.Keys(eligible)))
}

// locate finds the installation with the given ID in insts, reporting
// whether it is present and whether its app is eligible.
func locate(insts []ghinstall.Installation, eligible map[int64]bool, id int64) (inst ghinstall.Installation, present, ok bool) {
	for _, c := range insts {
		if c.ID == id {
			return c, true, eligible[c.AppID]
		}
	}
	return ghinstall.Installation{}, false, false
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

	// Look up the org's app pool.
	pool, err := s.router.GetPool(owner)
	if err != nil {
		return nil, 0, nil, nil, err
	}

	tpKey := cacheTrustPolicyKey{owner: owner, repo: repo, identity: identity}

	if cached, ok := trustPolicies.Get(tpKey); ok && cached == negativeCacheConst {
		clog.InfoContextf(ctx, "negative cache hit for %s", tpKey)
		return nil, 0, nil, nil, status.Errorf(codes.NotFound, "unable to find trust policy for %q", tpKey.identity)
	}

	// Read the trust policy using any available installation in this org's pool.
	readAtr, readID, err := pool.M.Get(ctx, owner, scope, identity)
	if err != nil {
		return nil, 0, nil, nil, err
	}

	// Enforce the organization trusted-issuer allowlist before spending a policy
	// read or a second token mint on an issuer we may reject.
	//
	// This runs AFTER pool.M.Get even though it ignores its return values: Get's
	// negative install cache rejects an owner the App is not installed on before
	// we do any allowlist work, which bounds the API amplification an arbitrary
	// caller-supplied scope can drive.
	decision, err := s.checkOrgTrustedIssuers(ctx, owner, issuer)
	if err != nil {
		return nil, 0, nil, decision, err
	}

	readAtr, readID, err = s.lookupTrustPolicyWithRetry(ctx, pool, readAtr, readID, owner, scope, identity, tpKey, tp)
	if err != nil {
		return nil, 0, nil, decision, err
	}

	// Now that we know the permissions, pick the exchange installation.
	atr, id, err := s.getExchangeInstall(ctx, pool, owner, scope, identity, subject, &otp.TrustPolicy, readAtr, readID)
	if err != nil {
		return nil, 0, nil, decision, err
	}

	return atr, id, otp, decision, nil
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
