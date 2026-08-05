// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package octosts

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/bradleyfalzon/ghinstallation/v2"
	"github.com/chainguard-dev/clog"
	"github.com/google/go-github/v88/github"
	expirablelru "github.com/hashicorp/golang-lru/v2/expirable"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/octo-sts/app/pkg/ghinstall"
	"github.com/octo-sts/app/pkg/ghtransport"
)

// OrgTrustedIssuersPath locates the org allowlist inside the org's .github
// repository. Exported because pkg/webhook's check run reads it too and both
// paths must agree. The name avoids the substring "token": gosec's G101 matches
// identifier names and would flag it as a hardcoded credential.
const OrgTrustedIssuersPath = ".github/chainguard/trusted-token-issuers.yaml"

// orgIssuerState is the cached knowledge about one org's allowlist. The zero
// value is orgIssuerUnknown, not "no allowlist", so it can never be a pass.
type orgIssuerState int

const (
	orgIssuerUnknown orgIssuerState = iota // zero value — never a pass
	orgIssuerAbsent                        // no allowlist applies; all issuers permitted
	orgIssuerPresent                       // allow holds a compiled allowlist
	orgIssuerInvalid                       // file present but unusable; err is set
)

func (s orgIssuerState) String() string {
	switch s {
	case orgIssuerUnknown:
		return "orgIssuerUnknown"
	case orgIssuerAbsent:
		return "orgIssuerAbsent"
	case orgIssuerPresent:
		return "orgIssuerPresent"
	case orgIssuerInvalid:
		return "orgIssuerInvalid"
	default:
		return fmt.Sprintf("orgIssuerState(%d)", int(s))
	}
}

type orgIssuerEntry struct {
	state orgIssuerState
	allow *IssuerAllowlist // set iff state == orgIssuerPresent
	err   error            // set iff state == orgIssuerInvalid
}

// These constructors keep the payload invariant (allow only for Present, err only
// for Invalid) in one place. None for Unknown: the zero value is the only source.

func absentOrgIssuerEntry() orgIssuerEntry {
	return orgIssuerEntry{state: orgIssuerAbsent}
}

func presentOrgIssuerEntry(allow *IssuerAllowlist) orgIssuerEntry {
	return orgIssuerEntry{state: orgIssuerPresent, allow: allow}
}

func invalidOrgIssuerEntry(err error) orgIssuerEntry {
	return orgIssuerEntry{state: orgIssuerInvalid, err: err}
}

// Keyed on owner alone, so 200 bounds concurrently active *organizations*.
var orgIssuers = expirablelru.NewLRU[string, orgIssuerEntry](200, nil, time.Minute*5)

// staleOrgIssuers holds Absent and Present only: Invalid is never "last known good".
var staleOrgIssuers = expirablelru.NewLRU[string, orgIssuerEntry](200, nil, time.Hour)

// cacheOrgIssuerEntry routes durable knowledge to the stale cache and logs the
// otherwise-invisible enforcing-to-not-enforcing shift.
func cacheOrgIssuerEntry(ctx context.Context, owner string, e orgIssuerEntry) {
	if prev, ok := staleOrgIssuers.Get(owner); ok &&
		prev.state == orgIssuerPresent && e.state == orgIssuerAbsent {
		clog.WarnContextf(ctx, "org trusted issuers no longer apply for %s; enforcement removed", owner)
	}

	orgIssuers.Add(owner, e)
	if e.state == orgIssuerAbsent || e.state == orgIssuerPresent {
		staleOrgIssuers.Add(owner, e)
	}
}

// fetchKind is one installation's answer about an org's allowlist. Retryability
// is a property of the kind, not something inferred from a gRPC code: inferring
// it let a rate-limited token mint skip the retry across other installations.
type fetchKind int

const (
	// fetchOK means the file was read; entry is Present or Invalid. Invalid rides
	// fetchOK: "the config is broken" is an answer, not a failure to enumerate.
	fetchOK          fetchKind = iota
	fetchAbsent                // no allowlist applies; definitive
	fetchNoAccess              // this installation cannot see .github; try the next
	fetchRateLimited           // rate limited at mint or read time; try the next
	fetchFailed                // anything else; try the next
)

// String renders fetchKind by name so logs distinguish fail-open from fail-closed.
func (k fetchKind) String() string {
	switch k {
	case fetchOK:
		return "fetchOK"
	case fetchAbsent:
		return "fetchAbsent"
	case fetchNoAccess:
		return "fetchNoAccess"
	case fetchRateLimited:
		return "fetchRateLimited"
	case fetchFailed:
		return "fetchFailed"
	default:
		return fmt.Sprintf("fetchKind(%d)", int(k))
	}
}

type fetchResult struct {
	kind  fetchKind
	entry orgIssuerEntry // valid when kind == fetchOK
	err   error          // terminal status for fetchRateLimited / fetchFailed
}

// The kind-to-payload pairing IS the security contract — retryable kinds carry a
// terminal status, fetchAbsent/fetchNoAccess carry none — so it lives in one place.

func absentFetch() fetchResult   { return fetchResult{kind: fetchAbsent} }
func noAccessFetch() fetchResult { return fetchResult{kind: fetchNoAccess} }

func rateLimitedFetch() fetchResult {
	return fetchResult{kind: fetchRateLimited, err: status.Error(codes.ResourceExhausted, msgIssuerRateLimited)}
}

func failedFetch() fetchResult {
	return fetchResult{kind: fetchFailed, err: status.Error(codes.Unavailable, msgIssuerUnavailable)}
}

func okFetch(e orgIssuerEntry) fetchResult { return fetchResult{kind: fetchOK, entry: e} }

// Fixed messages returned to callers. Org, issuer, mode and the underlying error
// go to logs and the Event only: echoing them would let any holder of a verified
// token enumerate an org's identity providers.
const (
	msgIssuerNotPermitted  = "issuer not permitted by organization policy"
	msgIssuerConfigInvalid = "organization trusted-issuer configuration is invalid"
	msgIssuerUnavailable   = "organization trusted-issuer lookup unavailable"
	msgIssuerRateLimited   = "organization trusted-issuer lookup rate limited"
)

// isOrgIssuerRateLimit reports whether err is PROVEN to be a rate limit. Stricter
// than IsGitHubRateLimited: a bare *ErrorResponse 403 is a permanent permission,
// SAML/IP-allowlist or suspended-installation failure, and calling it a rate limit
// would deny every exchange in the org indefinitely. Real limits are typed
// *RateLimitError or *AbuseRateLimitError.
func isOrgIssuerRateLimit(err error) bool {
	if err == nil {
		return false
	}
	var rl *github.RateLimitError
	var abuse *github.AbuseRateLimitError
	if errors.As(err, &rl) || errors.As(err, &abuse) {
		return true
	}
	var resp *github.ErrorResponse
	return errors.As(err, &resp) && resp.Response != nil &&
		resp.Response.StatusCode == http.StatusTooManyRequests
}

// isMintRateLimit reports whether a mint failure response is a rate limit. Below
// go-github's CheckResponse there is no typed *RateLimitError: 429 and 403 with
// X-RateLimit-Remaining: 0 are primary limits; Retry-After catches secondary
// limits, where Remaining is typically NONZERO.
func isMintRateLimit(resp *http.Response) bool {
	if resp == nil {
		return false
	}
	if resp.StatusCode == http.StatusTooManyRequests {
		return true
	}
	if resp.StatusCode != http.StatusForbidden {
		return false
	}
	return resp.Header.Get("X-RateLimit-Remaining") == "0" || resp.Header.Get("Retry-After") != ""
}

// classifyMintError maps an installation-token mint failure. These are
// *ghinstallation.HTTPError, not *github.ErrorResponse: RoundTrip returns
// (nil, err), so CheckResponse never runs. Closes err's response body.
func classifyMintError(ctx context.Context, owner string, err error) fetchResult {
	var herr *ghinstallation.HTTPError
	if errors.As(err, &herr) && herr.Response != nil {
		// ghinstallation deliberately leaves the body open for inspection, so
		// closing it is our job.
		if herr.Response.Body != nil {
			defer herr.Response.Body.Close()
		}
		if herr.Response.Body != nil {
			if body, rerr := io.ReadAll(io.LimitReader(herr.Response.Body, 4096)); rerr == nil && len(body) > 0 {
				clog.DebugContextf(ctx, "org trusted issuers: mint failure body for %s: %s", owner, body)
			}
		}

		switch {
		case herr.Response.StatusCode == http.StatusUnprocessableEntity:
			return noAccessFetch()

		case isMintRateLimit(herr.Response):
			clog.WarnContextf(ctx, "org trusted issuers: mint rate limited for %s", owner)
			return rateLimitedFetch()
		}
	}

	clog.WarnContextf(ctx, "org trusted issuers: mint failed for %s: %v", owner, err)
	return failedFetch()
}

// classifyContentsError maps a GetContents failure.
func classifyContentsError(ctx context.Context, owner string, err error) fetchResult {
	if isOrgIssuerRateLimit(err) {
		clog.WarnContextf(ctx, "org trusted issuers: read rate limited for %s", owner)
		return rateLimitedFetch()
	}

	var ghErr *github.ErrorResponse
	if errors.As(err, &ghErr) && ghErr.Response != nil {
		switch ghErr.Response.StatusCode {
		case http.StatusNotFound:
			return absentFetch()

		case http.StatusForbidden:
			// Ignorance, NOT agreement, so fail CLOSED rather than return NoAccess:
			// a read-time 403 is often org-wide (IP allowlist, SAML/SSO, ToS lock,
			// contents-API incident), which would make every installation "agree"
			// that no allowlist applies and fall the org open to allow-all during
			// the incident. Genuine per-installation blindness does not arrive here
			// — it fails at the MINT with a 422 — so reaching this means the mint
			// already proved this installation can see .github.
			clog.WarnContextf(ctx, "org trusted issuers: read forbidden for %s/.github (403, not a rate limit); treating as unknown", owner)
			return failedFetch()
		}
	}

	clog.WarnContextf(ctx, "org trusted issuers: read failed for %s: %v", owner, err)
	return failedFetch()
}

// fetchOrgIssuersOnce reads and compiles the org allowlist using one installation
// and reports only what it could determine; deciding the org's actual allowlist is
// the aggregating caller's job.
func (s *sts) fetchOrgIssuersOnce(ctx context.Context, base *ghinstallation.AppsTransport, install int64, owner string) fetchResult {
	// Label rate-limit metrics with the installation consuming the quota.
	ctx = ghtransport.EnrichContext(ctx, base.AppID(), install)

	atr := ghinstallation.NewFromAppsTransport(base, install)
	atr.InstallationTokenOptions = &github.InstallationTokenOptions{
		Repositories: []string{".github"},
		Permissions: &github.InstallationPermissions{
			Contents: ptr("read"),
		},
	}

	// Mint explicitly, not lazily inside the revoke defer: only successful tokens
	// are cached, so a deferred Token() would issue a SECOND failing mint on the
	// 422 path, common for orgs installing the App on selected repositories.
	tok, err := atr.Token(ctx)
	if err != nil {
		return classifyMintError(ctx, owner, err)
	}
	defer func() {
		if err := Revoke(ctx, tok, s.baseURL); err != nil {
			clog.WarnContextf(ctx, "org trusted issuers: failed to revoke token: %v", err)
		}
	}()

	client, err := newGitHubClient(atr, s.baseURL)
	if err != nil {
		return fetchResult{
			kind: fetchFailed,
			err:  status.Errorf(codes.Internal, "creating GitHub client: %v", err),
		}
	}

	file, _, _, err := client.Repositories.GetContents(ctx,
		owner, ".github", OrgTrustedIssuersPath,
		&github.RepositoryContentGetOptions{},
	)
	if err != nil {
		return classifyContentsError(ctx, owner, err)
	}
	if file == nil {
		// A directory: GetContent() dereferences Encoding unguarded and would
		// panic on the exchange path.
		clog.ErrorContextf(ctx, "org trusted issuers: path is not a file for %s", owner)
		return invalidConfigResult()
	}

	raw, err := file.GetContent()
	if err != nil {
		clog.ErrorContextf(ctx, "org trusted issuers: failed to decode for %s: %v", owner, err)
		return invalidConfigResult()
	}

	allow, err := ParseOrgTrustedIssuers([]byte(raw))
	if err != nil {
		clog.ErrorContextf(ctx, "org trusted issuers: invalid config for %s: %v", owner, err)
		return invalidConfigResult()
	}

	return okFetch(presentOrgIssuerEntry(allow))
}

// invalidConfigResult is the outcome for a config present but unusable. The kind
// is fetchOK because the installation DID answer; the cause is logged at the call
// site and the caller-visible message stays fixed.
func invalidConfigResult() fetchResult {
	return okFetch(invalidOrgIssuerEntry(status.Error(codes.FailedPrecondition, msgIssuerConfigInvalid)))
}

type orgIssuerTally struct {
	total        int
	noAccess     int
	anyFailed    bool // a fetchFailed or fetchRateLimited was seen
	sawRateLimit bool
}

// exhaustiveNoAccess reports whether every installation considered so far
// ANSWERED, and every answer was "I cannot see .github".
//
// total > 0 is a security guard: with no installations the comparison degenerates
// to 0 == 0 and would grant org-wide allow-all off no evidence; an empty
// enumeration is ignorance and belongs on the stale / fail-closed path.
//
// anyFailed is redundant today (only fetchNoAccess increments noAccess) but only
// because of scanInstalls' and record's counting discipline; an edit that stops
// counting an unanswered installation in total would silently turn ignorance into
// allow-all. Do not simplify it away.
func (t *orgIssuerTally) exhaustiveNoAccess() bool {
	return t.total > 0 && !t.anyFailed && t.noAccess == t.total
}

// record folds one non-definitive outcome into the tally, holding in one place the
// invariant exhaustiveNoAccess relies on: every non-definitive answer counts as a
// no-access agreement or a failure. total belongs to scanInstalls.
func (t *orgIssuerTally) record(k fetchKind) {
	switch k {
	case fetchNoAccess:
		t.noAccess++

	case fetchRateLimited:
		t.anyFailed = true
		t.sawRateLimit = true

	default: // fetchFailed
		t.anyFailed = true
	}
}

// scanInstalls returns the first DEFINITIVE answer — fetchOK or fetchAbsent —
// which ends the lookup; everything else is ignorance and folds into t via record.
//
// On a definitive (true) return the tally is PARTIAL — the answering installation
// is counted in total but nowhere else — so exhaustiveNoAccess must not be
// consulted. Only a false return leaves a tally worth reading.
func (s *sts) scanInstalls(ctx context.Context, owner string, installs []ghinstall.Installation, t *orgIssuerTally) (entry orgIssuerEntry, definitive bool) {
	for _, in := range installs {
		t.total++
		res := s.fetchOrgIssuersOnce(ctx, in.Transport, in.ID, owner)
		switch res.kind {
		case fetchOK:
			return res.entry, true

		case fetchAbsent:
			return absentOrgIssuerEntry(), true

		default:
			t.record(res.kind)
		}
	}
	return orgIssuerEntry{}, false
}

// orgIssuerLookup returns the effective allowlist entry for owner, enumerating
// EVERY installation and stopping at the first definitive answer. Not s.rrm.Get:
// pickByQuota is argmax(remaining) with no rotation, so a Get-based loop could see
// one blind installation forever and wrongly cache allow-all for the whole org.
//
// A non-nil error is a terminal gRPC status; a nil error with an Invalid entry
// means the config is unusable and the caller surfaces entry.err.
func (s *sts) orgIssuerLookup(ctx context.Context, owner string) (orgIssuerEntry, error) {
	if e, ok := orgIssuers.Get(owner); ok {
		return e, nil
	}

	installs, enumErr := s.rrm.GetAll(ctx, owner)

	var t orgIssuerTally
	if entry, ok := s.scanInstalls(ctx, owner, installs, &t); ok {
		return s.settleOrgIssuerEntry(ctx, owner, entry), nil
	}

	// Absent requires POSITIVE knowledge: a failed or partial enumeration is not
	// evidence of absence and is never cached. See exhaustiveNoAccess.
	if enumErr == nil && t.exhaustiveNoAccess() {
		clog.WarnContextf(ctx, "no installation can read %s/.github; org issuer enforcement not applied", owner)
		absent := absentOrgIssuerEntry()
		cacheOrgIssuerEntry(ctx, owner, absent)
		return absent, nil
	}

	// Not exhaustive, or something failed. Serving stale is inherently mode-aware:
	// an audit-mode allowlist never denies.
	if stale, ok := staleOrgIssuers.Get(owner); ok {
		clog.InfoContextf(ctx, "org issuer lookup incomplete for %s, serving stale entry", owner)
		orgIssuers.Add(owner, stale)
		return stale, nil
	}

	if enumErr != nil {
		clog.WarnContextf(ctx, "enumerating installations for %s failed: %v", owner, enumErr)
	} else if len(installs) == 0 {
		clog.WarnContextf(ctx, "enumerating installations for %s returned none, but routing found one", owner)
	}
	if t.sawRateLimit {
		return orgIssuerEntry{}, status.Error(codes.ResourceExhausted, msgIssuerRateLimited)
	}
	return orgIssuerEntry{}, status.Error(codes.Unavailable, msgIssuerUnavailable)
}

// settleOrgIssuerEntry caches a definitive entry, substituting the last known good
// allowlist when the current file is unusable: a typo must not be an org-wide kill
// switch. That list may be broader than intended, hence the Error log.
func (s *sts) settleOrgIssuerEntry(ctx context.Context, owner string, entry orgIssuerEntry) orgIssuerEntry {
	if entry.state == orgIssuerInvalid {
		if stale, ok := staleOrgIssuers.Get(owner); ok && stale.state == orgIssuerPresent {
			clog.ErrorContextf(ctx, "org trusted issuers for %s is invalid; serving last known good", owner)
			orgIssuers.Add(owner, stale)
			return stale
		}
	}
	cacheOrgIssuerEntry(ctx, owner, entry)
	return entry
}

// checkOrgTrustedIssuers evaluates the org allowlist for owner, returning a
// decision to record on the Event (nil when no allowlist applied or the issuer was
// permitted) and a terminal error when the exchange must be denied.
func (s *sts) checkOrgTrustedIssuers(ctx context.Context, owner, issuer string) (*IssuerDecision, error) {
	entry, err := s.orgIssuerLookup(ctx, owner)
	if err != nil {
		// Fail closed: an allowlist we could not establish is not allow-all.
		return nil, err
	}

	switch entry.state {
	case orgIssuerAbsent:
		return nil, nil
	case orgIssuerInvalid:
		return nil, entry.err
	case orgIssuerPresent:
	default:
		// orgIssuerUnknown. A zero value must never be a pass.
		clog.ErrorContextf(ctx, "org issuer cache returned an unknown state for %s", owner)
		return nil, status.Error(codes.Internal, msgIssuerUnavailable)
	}

	if entry.allow.Allows(issuer) {
		return nil, nil
	}

	d := &IssuerDecision{Mode: entry.allow.Mode(), Issuer: issuer}
	if entry.allow.Mode() == ModeAudit {
		d.Allowed = true
		clog.WarnContextf(ctx, "org issuer audit: %s would deny issuer %q", owner, issuer)
		return d, nil
	}
	d.Allowed = false
	clog.WarnContextf(ctx, "org issuer enforce: %s denied issuer %q", owner, issuer)
	return d, status.Error(codes.PermissionDenied, msgIssuerNotPermitted)
}
