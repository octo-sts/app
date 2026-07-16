// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package webhook

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/bradleyfalzon/ghinstallation/v2"
	"github.com/chainguard-dev/clog"
	"github.com/google/go-github/v88/github"
	"github.com/hashicorp/go-multierror"
	lru "github.com/hashicorp/golang-lru/v2"
	"k8s.io/apimachinery/pkg/util/sets"
	"sigs.k8s.io/yaml"

	"github.com/octo-sts/app/pkg/ghtransport"
	"github.com/octo-sts/app/pkg/octosts"
)

const (
	// See https://docs.github.com/en/developers/webhooks-and-events/webhooks/webhook-events-and-payloads#delivery-headers for list of available headers

	// HeaderDelivery is the GUID of the webhook event.
	HeaderDelivery = "X-GitHub-Delivery"
	// HeaderEvent is the event name of the webhook.
	HeaderEvent = "X-GitHub-Event"

	// zeroHash is a special SHA value indicating a non-existent commit,
	// i.e. when a branch is newly created or destroyed.
	zeroHash = "0000000000000000000000000000000000000000"
)

type Validator struct {
	Transport *ghinstallation.AppsTransport
	// Store multiple secrets to allow for rolling updates.
	// Only one needs to match for the event to be considered valid.
	WebhookSecret [][]byte

	Organizations []string

	// OrgPolicyRepo is the repository name (without owner) that holds
	// org-scoped trust policies and the org trusted-issuer allowlist.
	// Defaults to ".github" when empty.
	OrgPolicyRepo string

	// clients caches one client per installation ID so the transport's token is
	// reused (~1h) instead of re-minted per event. Keyed on installation ID
	// alone: IDs are globally unique and the webhook serves one App. Building a
	// client is cheap (the token is minted lazily on first use), so clientsMu
	// can guard the whole get-or-create.
	clientsMu sync.Mutex
	clients   *lru.Cache[int64, *github.Client]
}

func (e *Validator) policyRepo() string {
	if e.OrgPolicyRepo != "" {
		return e.OrgPolicyRepo
	}
	return ".github"
}

// prActionsThatChangeFiles is the set of pull_request actions that can alter
// the file diff (and therefore introduce or modify a trust policy). Every other
// action (labeled, edited, assigned, review_requested, closed, ready_for_review,
// …) leaves the diff untouched, so there is nothing new for us to validate — we
// don't skip drafts, so draft PRs are already validated on opened/synchronize.
var prActionsThatChangeFiles = sets.New("opened", "synchronize", "reopened")

// installationClientCacheSize matches the app's other LRUs (e.g. ghinstall,
// octosts); entries are tiny and least-recently-used installations evict first.
const installationClientCacheSize = 200

func isBotSender(sender *github.User) bool {
	return sender != nil && sender.Login != nil && strings.HasSuffix(sender.GetLogin(), "[bot]")
}

func (e *Validator) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log := clog.FromContext(r.Context()).With(
		HeaderDelivery, r.Header.Get(HeaderDelivery),
		HeaderEvent, r.Header.Get(HeaderEvent),
	)
	ctx := clog.WithLogger(r.Context(), log)

	payload, err := e.validatePayload(r)
	if err != nil {
		log.Errorf("error validating payload: %v", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	eventType := github.WebHookType(r)
	event, err := github.ParseWebHook(eventType, payload)
	if err != nil {
		log.Errorf("error parsing webhook: %v", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// For every event handler, return back an identifier that we can
	// return back to the webhook in case we need to debug. This could
	// be the resource that was created, an event ID, etc.
	var cr *github.CheckRun
	switch event := event.(type) {
	case *github.PullRequestEvent:
		cr, err = e.handlePullRequest(ctx, event)
	case *github.PushEvent:
		cr, err = e.handlePush(ctx, event)
	case *github.CheckSuiteEvent:
		if isBotSender(event.GetSender()) {
			log.Infof("skipping bot-triggered check_suite from %s", event.GetSender().GetLogin())
			w.WriteHeader(http.StatusAccepted)
			return
		}
		cr, err = e.handleCheckSuite(ctx, event)
	case *github.CheckRunEvent:
		if isBotSender(event.GetSender()) {
			log.Infof("skipping bot-triggered check_run from %s", event.GetSender().GetLogin())
			w.WriteHeader(http.StatusAccepted)
			return
		}
		cr, err = e.handleCheckSuite(ctx, &fauxCheckSuite{event})
	// TODO: CheckRun retry
	default:
		log.Infof("unsupported event type: %s", eventType)
		// Use accepted as "we got it but didn't do anything"
		w.WriteHeader(http.StatusAccepted)
		return
	}
	if err != nil {
		log.Errorf("error handling event: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if cr != nil {
		log.Info("created CheckRun", "check_run", cr)
	}
	w.WriteHeader(http.StatusOK)
}

func (e *Validator) validatePayload(r *http.Request) ([]byte, error) {
	// Taken from github.ValidatePayload - we can't use this directly since the body is consumed.
	signature := r.Header.Get(github.SHA256SignatureHeader)
	if signature == "" {
		signature = r.Header.Get(github.SHA1SignatureHeader)
	}
	contentType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil {
		return nil, err
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}

	for _, s := range e.WebhookSecret {
		payload, err := github.ValidatePayloadFromBody(contentType, bytes.NewBuffer(body), signature, s)
		if err == nil {
			return payload, nil
		}
	}
	return nil, errors.New("no matching secrets")
}

// clientForInstallation returns a cached (or freshly built) client for the
// installation, reusing its token instead of minting one per event.
func (e *Validator) clientForInstallation(installationID int64) (*github.Client, error) {
	e.clientsMu.Lock()
	defer e.clientsMu.Unlock()

	if e.clients == nil {
		cache, err := lru.New[int64, *github.Client](installationClientCacheSize)
		if err != nil {
			return nil, err
		}
		e.clients = cache
	}
	if client, ok := e.clients.Get(installationID); ok {
		return client, nil
	}

	opts := []github.ClientOptionsFunc{
		github.WithTransport(ghinstallation.NewFromAppsTransport(e.Transport, installationID)),
	}
	if e.Transport.BaseURL != "" {
		opts = append(opts, github.WithEnterpriseURLs(e.Transport.BaseURL, e.Transport.BaseURL))
	}
	client, err := github.NewClient(opts...)
	if err != nil {
		return nil, err
	}
	e.clients.Add(installationID, client)
	return client, nil
}

func (e *Validator) handleSHA(ctx context.Context, client *github.Client, owner, repo, sha string, files []string) (*github.CheckRun, error) {
	log := clog.FromContext(ctx)

	// Commit doesn't exist - nothing to do.
	if sha == zeroHash {
		return nil, nil
	}

	err := validatePolicies(ctx, client, owner, repo, sha, files, e.policyRepo())
	// If we were rate-limited, acknowledge the delivery and skip the CheckRun.
	// Returning an error would surface as a 5xx, which GitHub treats as a
	// failed delivery and redelivers — amplifying load on the rate-limited API.
	if octosts.IsGitHubRateLimited(err) {
		log.Warnf("rate-limited validating policies for %s/%s@%s; skipping CheckRun", owner, repo, sha)
		return nil, nil
	}
	// Whether or not the commit is verified, we still create a CheckRun.
	// The only difference is whether it shows up to the user as success or
	// failure.
	var conclusion, title, summary string
	if err == nil {
		conclusion = "success"
		title = "Valid trust policy."
	} else {
		conclusion = "failure"
		title = "Invalid trust policy."
		summary = "Failed to validate trust policy.\n\n" + err.Error()
	}

	opts := github.CreateCheckRunOptions{
		Name:        "Trust Policy Validation",
		HeadSHA:     sha,
		ExternalID:  github.Ptr(sha),
		Status:      github.Ptr("completed"),
		Conclusion:  github.Ptr(conclusion),
		StartedAt:   &github.Timestamp{Time: time.Now()},
		CompletedAt: &github.Timestamp{Time: time.Now()},
		Output: &github.CheckRunOutput{
			Title:   github.Ptr(title),
			Summary: github.Ptr(summary),
		},
	}

	cr, _, err := client.Checks.CreateCheckRun(ctx, owner, repo, opts)
	if err != nil {
		log.Errorf("error creating CheckRun: %v", err)
		return nil, err
	}
	return cr, nil
}

func validatePolicies(ctx context.Context, client *github.Client, owner, repo, sha string, files []string, orgPolicyRepo string) error {
	var merr error
	for _, f := range sets.List(sets.New(files...)) {
		log := clog.FromContext(ctx).With("path", f)

		resp, _, _, err := client.Repositories.GetContents(ctx, owner, repo, f, &github.RepositoryContentGetOptions{Ref: sha})
		if err != nil {
			log.Infof("failed to get content for: %v", err)
			if octosts.IsGitHubRateLimited(err) {
				log.Warnf("rate-limited, aborting remaining policy validations")
				return fmt.Errorf("%s: %w", f, err)
			}
			merr = multierror.Append(merr, fmt.Errorf("%s: %w", f, err))
			continue
		}

		// GetContents returns a nil file and a populated slice when the path is a
		// DIRECTORY, and RepositoryContent.GetContent dereferences its receiver
		// without a nil check — so a directory named like a policy or the allowlist
		// would panic the handler rather than fail the check run.
		if resp == nil {
			log.Infof("%s is not a file, skipping", f)
			merr = multierror.Append(merr, fmt.Errorf("%s: not a file", f))
			continue
		}

		raw, err := resp.GetContent()
		if err != nil {
			log.Infof("failed to read content: %v", err)
			merr = multierror.Append(merr, fmt.Errorf("%s: %w", f, err))
			continue
		}

		switch {
		case strings.EqualFold(repo, orgPolicyRepo) && f == octosts.OrgTrustedIssuersPath:
			// Parse AND compile: only compiling catches uncompilable patterns,
			// invalid issuer URLs, and an empty allowlist. The exchange path calls
			// this same function, so the two verdicts cannot diverge.
			if _, err := octosts.ParseOrgTrustedIssuers([]byte(raw)); err != nil {
				log.Infof("failed to validate org trusted issuers: %v", err)
				merr = multierror.Append(merr, fmt.Errorf("%s: %w", f, err))
			}

		// EqualFold, matching the arm above: GitHub preserves repository-name case,
		// so an org whose repo is literally ".GitHub" would otherwise fall through
		// to the default arm and have its org policy strict-unmarshalled as a
		// repo-level TrustPolicy — a bogus check-run failure on a valid file.
		case strings.EqualFold(repo, orgPolicyRepo):
			if err := yaml.UnmarshalStrict([]byte(raw), &octosts.OrgTrustPolicy{}); err != nil {
				log.Infof("failed to parse org trust policy: %v", err)
				merr = multierror.Append(merr, fmt.Errorf("%s: %w", f, err))
			}

		default:
			if err := yaml.UnmarshalStrict([]byte(raw), &octosts.TrustPolicy{}); err != nil {
				log.Infof("failed to parse trust policy: %v", err)
				merr = multierror.Append(merr, fmt.Errorf("%s: %w", f, err))
			}
		}
	}

	return merr
}

func (e *Validator) handlePush(ctx context.Context, event *github.PushEvent) (*github.CheckRun, error) {
	log := clog.FromContext(ctx).With(
		"github/repo", event.GetRepo().GetFullName(),
		"github/installation", event.GetInstallation().GetID(),
		"github/action", event.GetAction(),
		"git/ref", event.GetRef(),
		"git/commit", event.GetAfter(),
		"github/user", event.GetSender().GetLogin(),
	)
	ctx = clog.WithLogger(ctx, log)

	owner := event.GetRepo().GetOwner().GetLogin()
	repo := event.GetRepo().GetName()
	sha := event.GetAfter()
	installationID := event.GetInstallation().GetID()
	ctx = ghtransport.EnrichContext(ctx, e.Transport.AppID(), installationID)

	// Skip if the organization is not in the list of organizations to validate.
	if e.shouldSkipOrganization(owner) {
		log.Infof("skipping organization %s", owner)
		return nil, nil
	}

	client, err := e.clientForInstallation(installationID)
	if err != nil {
		return nil, err
	}

	var files []string

	// GitHub push payloads include up to 20 commits. When not truncated,
	// use the payload directly to avoid a Compare API call.
	switch {
	case len(event.Commits) < 20:
		files = e.filesFromPushEvent(repo, event)
	case event.GetBefore() == zeroHash:
		// A push that creates a new ref carries the zero SHA as "before",
		// which the Compare API rejects with a 404 (previously surfacing as a
		// webhook 500). The payload is also truncated, so commits beyond the
		// first 20 could carry policy files never seen before. Scan the
		// policy directory at the pushed SHA instead — the same approach as
		// handleCheckSuite's zero-SHA path. A missing directory just means
		// there are no policies to validate.
		_, dirContents, resp, err := client.Repositories.GetContents(ctx, owner, repo, ".github/chainguard", &github.RepositoryContentGetOptions{Ref: sha})
		if err != nil && (resp == nil || resp.StatusCode != http.StatusNotFound) {
			return nil, err
		}
		for _, file := range dirContents {
			if file.GetType() == "file" && isValidatedPath(repo, file.GetPath(), e.policyRepo()) {
				files = append(files, file.GetPath())
			}
		}
	default:
		resp, _, err := client.Repositories.CompareCommits(ctx, owner, repo, event.GetBefore(), sha, &github.ListOptions{})
		if err != nil {
			return nil, err
		}
		for _, file := range resp.Files {
			if isValidatedPath(repo, file.GetFilename(), e.policyRepo()) {
				if file.GetStatus() != "removed" {
					files = append(files, file.GetFilename())
				}
			}
		}
	}

	if len(files) == 0 {
		return nil, nil
	}

	return e.handleSHA(ctx, client, owner, repo, sha, files)
}

func (e *Validator) handlePullRequest(ctx context.Context, pr *github.PullRequestEvent) (*github.CheckRun, error) {
	log := clog.FromContext(ctx).With(
		"github/repo", pr.GetRepo().GetFullName(),
		"github/installation", pr.GetInstallation().GetID(),
		"github/action", pr.GetAction(),
		"github/pull_request", pr.GetNumber(),
		"git/commit", pr.GetPullRequest().GetHead().GetSHA(),
		"github/user", pr.GetSender().GetLogin(),
	)
	ctx = clog.WithLogger(ctx, log)

	owner := pr.GetRepo().GetOwner().GetLogin()
	repo := pr.GetRepo().GetName()
	sha := pr.GetPullRequest().GetHead().GetSHA()
	installationID := pr.GetInstallation().GetID()
	ctx = ghtransport.EnrichContext(ctx, e.Transport.AppID(), installationID)

	// Skip if the organization is not in the list of organizations to validate.
	if e.shouldSkipOrganization(owner) {
		log.Infof("skipping organization %s", owner)
		return nil, nil
	}

	// Only actions that can change the PR's file diff can introduce or modify
	// a trust policy. Skipping the rest avoids a ListFiles call (and its token
	// mint) on the ~99% of PR events that can't affect policy.
	if !prActionsThatChangeFiles.Has(pr.GetAction()) {
		log.Infof("skipping pull_request action %q: cannot change file diff", pr.GetAction())
		return nil, nil
	}

	client, err := e.clientForInstallation(installationID)
	if err != nil {
		return nil, err
	}

	// Check diff
	var files []string
	resp, _, err := client.PullRequests.ListFiles(ctx, owner, repo, pr.GetNumber(), &github.ListOptions{})
	if err != nil {
		return nil, err
	}
	for _, file := range resp {
		if isValidatedPath(repo, file.GetFilename(), e.policyRepo()) {
			if file.GetStatus() != "removed" {
				files = append(files, file.GetFilename())
			}
		}
	}
	if len(files) == 0 {
		return nil, nil
	}

	return e.handleSHA(ctx, client, owner, repo, sha, files)
}

type checkSuite interface {
	GetRepo() *github.Repository
	GetInstallation() *github.Installation
	GetAction() string
	GetCheckSuite() *github.CheckSuite
	GetSender() *github.User
}

func (e *Validator) handleCheckSuite(ctx context.Context, cs checkSuite) (*github.CheckRun, error) {
	log := clog.FromContext(ctx).With(
		"github/repo", cs.GetRepo().GetFullName(),
		"github/installation", cs.GetInstallation().GetID(),
		"github/action", cs.GetAction(),
		"github/private", cs.GetRepo().GetPrivate(),
		"github/checksuite_id", cs.GetCheckSuite().GetID(),
		"git/commit", cs.GetCheckSuite().GetHeadSHA(),
		"github/user", cs.GetSender().GetLogin(),
	)
	ctx = clog.WithLogger(ctx, log)

	owner := cs.GetRepo().GetOwner().GetLogin()
	repo := cs.GetRepo().GetName()
	sha := cs.GetCheckSuite().GetHeadSHA()
	installationID := cs.GetInstallation().GetID()
	ctx = ghtransport.EnrichContext(ctx, e.Transport.AppID(), installationID)

	// Skip if the organization is not in the list of organizations to validate.
	if e.shouldSkipOrganization(owner) {
		log.Infof("skipping organization %s", owner)
		return nil, nil
	}

	client, err := e.clientForInstallation(installationID)
	if err != nil {
		return nil, err
	}

	var files []string
	if cs.GetCheckSuite().GetBeforeSHA() == zeroHash {
		// New non-default branch: skip if there are no associated PRs.
		// A feature branch points at a commit already present in the
		// repository and doesn't need a full directory scan. This
		// avoids reading every policy file (O(N) API calls) on every
		// new-branch event.
		//
		// We still process the default branch (initial commit) and
		// any branch with associated PRs, since those may introduce
		// new or modified policy files.
		defaultBranch := cs.GetRepo().GetDefaultBranch()
		headBranch := cs.GetCheckSuite().GetHeadBranch()
		if headBranch != defaultBranch && len(cs.GetCheckSuite().PullRequests) == 0 {
			log.Infof("skipping new non-default branch with no PRs")
			return nil, nil
		}
		_, dirContents, _, err := client.Repositories.GetContents(ctx, owner, repo, ".github/chainguard", &github.RepositoryContentGetOptions{Ref: sha})
		if err != nil {
			return nil, err
		}
		// This branch lists the policy directory rather than diffing it, so the
		// entries are everything the directory holds — not just trust policies.
		// Filter here as every diff-based path already does, otherwise unrelated
		// files (a README, a .gitkeep, the organization allowlist) get fetched
		// and parsed as trust policies and fail the check run.
		for _, file := range dirContents {
			// Type matters as well as path: a directory can be named to match, and
			// listing it as a candidate would send a non-file down the read path.
			if file.GetType() == "file" && isValidatedPath(repo, file.GetPath(), e.policyRepo()) {
				files = append(files, file.GetPath())
			}
		}
	} else {
		resp, _, err := client.Repositories.CompareCommits(ctx, owner, repo, cs.GetCheckSuite().GetBeforeSHA(), sha, &github.ListOptions{})
		if err != nil {
			return nil, err
		}
		for _, file := range resp.Files {
			if isValidatedPath(repo, file.GetFilename(), e.policyRepo()) {
				if file.GetStatus() != "removed" {
					files = append(files, file.GetFilename())
				}
			}
		}
	}

	for _, pr := range cs.GetCheckSuite().PullRequests {
		resp, _, err := client.PullRequests.ListFiles(ctx, owner, repo, pr.GetNumber(), &github.ListOptions{})
		if err != nil {
			return nil, err
		}
		for _, file := range resp {
			if isValidatedPath(repo, file.GetFilename(), e.policyRepo()) {
				if file.GetStatus() != "removed" {
					files = append(files, file.GetFilename())
				}
			}
		}
	}
	if len(files) == 0 {
		return nil, nil
	}

	return e.handleSHA(ctx, client, owner, repo, sha, files)
}

type fauxCheckSuite struct {
	*github.CheckRunEvent
}

var _ checkSuite = (*fauxCheckSuite)(nil)

func (f *fauxCheckSuite) GetCheckSuite() *github.CheckSuite {
	return f.GetCheckRun().GetCheckSuite()
}

func (e *Validator) shouldSkipOrganization(org string) bool {
	if len(e.Organizations) == 0 {
		return false
	}
	for _, o := range e.Organizations {
		if strings.EqualFold(o, org) {
			return false
		}
	}
	return true
}

// isValidatedPath reports whether octo-sts validates the given file. Trust
// policies are validated in every repository; the organization trusted-issuer
// allowlist only in the organization's org policy repository (orgPolicyRepo).
//
// The repository comparison folds case because GitHub repository names are
// case-insensitive and the exchange path resolves the repo name through the API.
func isValidatedPath(repo, path, orgPolicyRepo string) bool {
	if ok, err := filepath.Match(".github/chainguard/*.sts.yaml", path); err == nil && ok {
		return true
	}
	return strings.EqualFold(repo, orgPolicyRepo) && path == octosts.OrgTrustedIssuersPath
}

// filterValidatedFiles returns the subset of files octo-sts validates.
func filterValidatedFiles(repo string, files []string, orgPolicyRepo string) []string {
	var filtered []string
	for _, f := range files {
		if isValidatedPath(repo, f, orgPolicyRepo) {
			filtered = append(filtered, f)
		}
	}
	return filtered
}

// filesFromPushEvent returns the validated files touched by the push.
//
// Deletions are deliberately excluded: validation reads each file's content at
// the head SHA, and a deleted path 404s there, so including removals would turn
// every trust-policy deletion into a failing check run. The CompareCommits
// branches skip "removed" for the same reason.
func (e *Validator) filesFromPushEvent(repo string, event *github.PushEvent) []string {
	var files []string //nolint:prealloc // size depends on file content, not commit count
	for _, commit := range event.Commits {
		files = append(files, filterValidatedFiles(repo, commit.Added, e.policyRepo())...)
		files = append(files, filterValidatedFiles(repo, commit.Modified, e.policyRepo())...)
	}
	return files
}
