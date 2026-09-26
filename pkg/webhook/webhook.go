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
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/bradleyfalzon/ghinstallation/v2"
	"github.com/chainguard-dev/clog"
	cloudevents "github.com/cloudevents/sdk-go/v2"
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

type PolicyAction string

const (
	PolicyCreated PolicyAction = "created"
	PolicyUpdated PolicyAction = "updated"
	PolicyDeleted PolicyAction = "deleted"
	// PolicyPresent means the policy is live at the pushed commit but this
	// push's effect on it is unknown. It is only produced when a forced push
	// leaves the previous SHA unresolvable, so there is no prior state to
	// compare against and no honest way to say whether the policy was created,
	// updated, or left alone. Always accompanied by DetectionDegraded.
	PolicyPresent PolicyAction = "present"
)

type PolicyChange struct {
	Path   string       `json:"path"`
	Policy string       `json:"policy"`
	Action PolicyAction `json:"action"`
}

// DetectionMethod records how a push's policy changes were derived. An audit
// consumer needs this to know how much weight a record carries: a snapshot is
// an authoritative before/after comparison of what is live, while the commit
// and compare paths mirror the diffs GitHub volunteers and can therefore be
// incomplete if history is rewritten under them.
type DetectionMethod string

const (
	// DetectionCommits derived changes from the push payload's commit list.
	DetectionCommits DetectionMethod = "commits"
	// DetectionCompare derived changes directly from the Compare API, used
	// when the payload's commit list is truncated and the response is complete.
	DetectionCompare DetectionMethod = "compare"
	// DetectionSnapshot derived changes by diffing the policy directory at the
	// pushed SHA against the ref's previous SHA. Used for forced pushes and
	// comparisons at GitHub's file cap.
	DetectionSnapshot DetectionMethod = "snapshot"
	// DetectionDegraded means change detection could not be completed and the
	// accompanying changes, if any, may be incomplete. Always accompanied by a
	// push-level event with no change attached, so the gap is visible in the
	// stream rather than silently absent from it. Any policy records alongside
	// it carry PolicyPresent: they say what is live at the pushed commit, not
	// what this push did.
	DetectionDegraded DetectionMethod = "degraded"
)

type PolicyEvent struct {
	Org            string `json:"org"`
	Repo           string `json:"repo"`
	Ref            string `json:"ref"`
	Commit         string `json:"commit"`
	Before         string `json:"before"`
	InstallationID int64  `json:"installation_id"`
	Actor          string `json:"actor"`
	ActorID        int64  `json:"actor_id"`
	Pusher         string `json:"pusher"`
	Forced         bool   `json:"forced"`
	// Change is the policy this event describes, and is absent on a push-level
	// event — currently only the marker emitted when Detection is
	// DetectionDegraded. ChangeIndex and ChangeCount are meaningful only when
	// Change is present.
	Change *PolicyChange `json:"change,omitempty"`
	// Detection records how Change was derived, and DetectionError explains a
	// DetectionDegraded result. A consumer treating this stream as an audit
	// trail should surface anything that is not DetectionSnapshot or
	// DetectionCommits as reduced assurance.
	Detection      DetectionMethod `json:"detection"`
	DetectionError string          `json:"detection_error,omitempty"`
	// ChangeIndex and ChangeCount locate this event within its push. Delivery
	// is per-event and best-effort, so a push can land partially; a consumer
	// that groups by Commit can compare the rows it holds against ChangeCount
	// to detect the gap. They also restore the grouping that emitting one
	// event per policy otherwise loses, e.g. spotting a bulk policy rewrite.
	ChangeIndex int `json:"change_index"`
	ChangeCount int `json:"change_count"`
	// Valid reports whether THIS policy parsed at Commit, and is nil when the
	// policy was never read: deletions (the path no longer exists at Commit),
	// a validation pass aborted by GitHub rate limiting, or a push that failed
	// before validation ran. A nil Valid must not be read as "valid" — it means
	// unknown. Except for deletions, PushError explains why.
	Valid *bool `json:"valid"`
	// Error is this policy's own validation failure, not the push's aggregate.
	Error string `json:"error,omitempty"`
	// PushError records a failure encountered while handling this push — a
	// rate limit that cut validation short, or a check run that could not be
	// created. It describes the push, not this policy, and specifically does
	// not imply that this policy went unvalidated: a non-nil Valid alongside
	// a PushError is an authoritative verdict on a push that had trouble
	// elsewhere. Read Valid, not PushError, to decide whether a verdict exists.
	PushError string    `json:"push_error,omitempty"`
	Time      time.Time `json:"time"`
}

// OrgTrustedIssuersPolicyName is the Policy value used for the organization
// trusted-issuer allowlist, which is not a named trust policy and so has no
// name of its own. A sentinel keeps every event's subject well-formed rather
// than leaving a trailing separator, and stays distinguishable from a real
// policy because "." cannot appear in a *.sts.yaml basename stem here.
const OrgTrustedIssuersPolicyName = ".trusted-token-issuers"

// policyName extracts the policy identity from a validated path:
// ".github/chainguard/foo.sts.yaml" -> "foo".
func policyName(path string) string {
	base := filepath.Base(path)
	stem, found := strings.CutSuffix(base, ".sts.yaml")
	if !found {
		return OrgTrustedIssuersPolicyName
	}
	if stem == "" {
		// A literal ".sts.yaml" matches the glob octo-sts validates but leaves
		// no stem, which would degenerate the event subject to "org/repo/".
		// Fall back to the filename so the subject stays well-formed.
		return base
	}
	return stem
}

func (e *Validator) policyChangesFromPushEvent(repo string, event *github.PushEvent) []PolicyChange {
	byPath := make(map[string]PolicyAction)

	apply := func(paths []string, action PolicyAction) {
		for _, p := range filterValidatedFiles(repo, paths, e.policyRepo()) {
			switch prev, seen := byPath[p]; {
			case !seen:
				byPath[p] = action
			case prev == PolicyCreated && action == PolicyUpdated:
				// Created then edited in the same push is still a creation.
			default:
				byPath[p] = action
			}
		}
	}

	for _, commit := range event.Commits {
		apply(commit.Added, PolicyCreated)
		apply(commit.Modified, PolicyUpdated)
		apply(commit.Removed, PolicyDeleted)
	}

	changes := make([]PolicyChange, 0, len(byPath))
	for path, action := range byPath {
		changes = append(changes, PolicyChange{
			Path:   path,
			Policy: policyName(path),
			Action: action,
		})
	}
	// Stable output so consumers diffing records don't see spurious churn.
	sort.Slice(changes, func(i, j int) bool { return changes[i].Path < changes[j].Path })
	return changes
}

// policyChangesFromCompare derives policy changes from a CompareCommits (or
// ListFiles) response.
//
// This is the path taken when the push payload's commit list is truncated, and
// it is the only path that sees renames: GitHub reports a rename as a single
// entry for the new path plus a PreviousFilename, so a policy renamed from a to
// b is recorded as b created and a deleted.
func (e *Validator) policyChangesFromCompare(ctx context.Context, repo string, files []*github.CommitFile) []PolicyChange {
	log := clog.FromContext(ctx)

	var changes []PolicyChange //nolint:prealloc // most files in a push aren't policies

	add := func(path string, action PolicyAction) {
		if !isValidatedPath(repo, path, e.policyRepo()) {
			return
		}
		changes = append(changes, PolicyChange{
			Path:   path,
			Policy: policyName(path),
			Action: action,
		})
	}

	for _, file := range files {
		switch status := file.GetStatus(); status {
		case "added", "copied":
			add(file.GetFilename(), PolicyCreated)
		case "removed":
			add(file.GetFilename(), PolicyDeleted)
		case "renamed":
			add(file.GetFilename(), PolicyCreated)
			add(file.GetPreviousFilename(), PolicyDeleted)
		case "modified", "changed":
			add(file.GetFilename(), PolicyUpdated)
		case "unchanged":
			// GitHub includes unchanged entries in some compares. The file is
			// byte-identical across the range, so nothing happened to this
			// policy in this push and reporting an update would be a lie.
		default:
			// An unrecognised status is more likely a new GitHub value than a
			// non-event, so report it as an update rather than dropping it —
			// over-reporting a change is the safer failure for a signal meant
			// to catch policy movement. Log it so the gap can be closed.
			log.Warnf("unrecognised compare status %q for %s; recording as an update", status, file.GetFilename())
			add(file.GetFilename(), PolicyUpdated)
		}
	}

	sort.Slice(changes, func(i, j int) bool { return changes[i].Path < changes[j].Path })
	return changes
}

// policyDir is the directory holding trust policies and the org trusted-issuer
// allowlist. Both live here, so one listing covers every validated path.
const policyDir = ".github/chainguard"

// policySnapshot lists every trust policy visible at ref, mapped to its blob
// SHA so that two snapshots can be compared by content.
//
// A ref that cannot be resolved is an error rather than an empty snapshot: the
// GitHub contents API answers 404 both for "this ref has no policy directory"
// and for "this ref no longer exists", and conflating the two would report a
// repository's entire policy set as deleted.
func (e *Validator) policySnapshot(ctx context.Context, client *github.Client, owner, repo, ref string) (map[string]string, error) {
	// Resolve the ref first so the 404 below can only mean a missing directory.
	if _, _, err := client.Repositories.GetCommit(ctx, owner, repo, ref, &github.ListOptions{PerPage: 1}); err != nil {
		return nil, fmt.Errorf("resolving %s: %w", ref, err)
	}

	out := make(map[string]string)
	_, dir, resp, err := client.Repositories.GetContents(ctx, owner, repo, policyDir, &github.RepositoryContentGetOptions{Ref: ref})
	if err != nil {
		if resp != nil && resp.StatusCode == http.StatusNotFound {
			// The ref resolved, so this is genuinely a repository with no
			// policy directory: an empty snapshot, not an unknown one.
			return out, nil
		}
		return nil, fmt.Errorf("listing %s at %s: %w", policyDir, ref, err)
	}
	for _, f := range dir {
		if f.GetType() != "file" || !isValidatedPath(repo, f.GetPath(), e.policyRepo()) {
			continue
		}
		out[f.GetPath()] = f.GetSHA()
	}
	return out, nil
}

// policyChangesFromSnapshot derives policy changes by comparing the policies
// live at before with those live at after. It also returns the snapshot taken
// at after, which stays usable when only before fails to resolve.
//
// This is the only detection path that survives a history rewrite. The commit
// and compare paths both describe the commits a push carries, which for a
// forced push does not describe its effect on the branch: a rewind that
// restores a deleted policy carries no commits at all and three-dot-compares
// as empty, so those paths would report nothing while the policy became live
// again. Comparing state instead of commits reports the restoration.
func (e *Validator) policyChangesFromSnapshot(ctx context.Context, client *github.Client, owner, repo, before, after string) ([]PolicyChange, map[string]string, error) {
	// after is the SHA this push just placed on the branch, so it resolves
	// whenever the push itself was real. before is the one GitHub is free to
	// garbage collect after a rewind, so take after first: that way a failure
	// to resolve before still leaves the caller a live listing to fall back on.
	afterSnap, err := e.policySnapshot(ctx, client, owner, repo, after)
	if err != nil {
		return nil, nil, err
	}

	// A push that creates the ref has no prior state to compare against.
	beforeSnap := map[string]string{}
	if before != "" && before != zeroHash {
		if beforeSnap, err = e.policySnapshot(ctx, client, owner, repo, before); err != nil {
			return nil, afterSnap, err
		}
	}

	var changes []PolicyChange //nolint:prealloc // most pushes change no policies
	add := func(path string, action PolicyAction) {
		changes = append(changes, PolicyChange{Path: path, Policy: policyName(path), Action: action})
	}
	for path, sha := range afterSnap {
		switch prev, existed := beforeSnap[path]; {
		case !existed:
			add(path, PolicyCreated)
		case prev != sha:
			add(path, PolicyUpdated)
		}
	}
	for path := range beforeSnap {
		if _, ok := afterSnap[path]; !ok {
			add(path, PolicyDeleted)
		}
	}

	sort.Slice(changes, func(i, j int) bool { return changes[i].Path < changes[j].Path })
	return changes, afterSnap, nil
}

// policiesPresent reports every policy in a snapshot as PolicyPresent.
//
// Used when a forced push leaves the previous SHA unresolvable. The diff
// cannot be computed, but the live listing still answers "which policies are
// in force at this commit" — enough to keep the check-run gate and to put a
// per-policy record in the stream, instead of only a content-free marker that
// says a rewind happened and nothing about what it left behind.
func policiesPresent(snap map[string]string) []PolicyChange {
	changes := make([]PolicyChange, 0, len(snap))
	for path := range snap {
		changes = append(changes, PolicyChange{Path: path, Policy: policyName(path), Action: PolicyPresent})
	}
	sort.Slice(changes, func(i, j int) bool { return changes[i].Path < changes[j].Path })
	return changes
}

// pathsToValidate returns the paths that still exist at the head SHA, and so
// can be read and parsed. Deletions are excluded: validation reads content at
// the head SHA, where a deleted path 404s, which would turn every policy
// deletion into a failing check run.
func pathsToValidate(changes []PolicyChange) []string {
	var files []string //nolint:prealloc // deletions are dropped
	for _, c := range changes {
		if c.Action == PolicyDeleted {
			continue
		}
		files = append(files, c.Path)
	}
	return files
}

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

	// Emitter publishes trust policy audit events. Nil disables auditing.
	Emitter *PolicyEmitter

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

// handleSHA validates the given files at sha and reports the result as a check
// run. The returned map holds one entry per validated file (a nil value means
// the file parsed). It is nil when no validation happened, which callers must
// distinguish from "everything was valid".
// validationOutcome is what handleSHA learned about a push.
//
// The two fields are deliberately separate from handleSHA's returned error,
// because "something went wrong" and "what should the HTTP response be" are
// different questions: a rate limit has to be reported on the events while
// still answering 200, since a 5xx would have GitHub redeliver the push and
// amplify load on the API that just rate-limited us.
type validationOutcome struct {
	// verdicts holds one entry per file that was read: nil for a policy that
	// parsed cleanly, otherwise its own error. A file absent from the map was
	// never read and stays unknown.
	verdicts map[string]error
	// incomplete records a failure that limited how much of the push could be
	// validated or reported. It applies to the push rather than to any one
	// policy.
	incomplete error
}

func (e *Validator) handleSHA(ctx context.Context, client *github.Client, owner, repo, sha string, files []string) (*github.CheckRun, validationOutcome, error) {
	return e.handleSHAForPolicyRepo(ctx, client, owner, repo, repo, sha, files)
}

func (e *Validator) handleSHAForPolicyRepo(ctx context.Context, client *github.Client, owner, readRepo, policyRepo, sha string, files []string) (*github.CheckRun, validationOutcome, error) {
	policyFiles := make([]policyFile, 0, len(files))
	for _, path := range files {
		policyFiles = append(policyFiles, policyFile{path: path, repo: policyRepo})
	}
	return e.handleSHAForPolicyFiles(ctx, client, owner, readRepo, sha, policyFiles)
}

type policyFile struct {
	path string
	repo string
}

func (e *Validator) handleSHAForPolicyFiles(ctx context.Context, client *github.Client, owner, readRepo, sha string, files []policyFile) (*github.CheckRun, validationOutcome, error) {
	log := clog.FromContext(ctx)

	// Commit doesn't exist - nothing to do.
	if sha == zeroHash {
		return nil, validationOutcome{}, nil
	}

	var results map[string]error
	var err error
	singleRepo := len(files) > 0
	if singleRepo {
		for _, file := range files[1:] {
			if !strings.EqualFold(file.repo, files[0].repo) {
				singleRepo = false
				break
			}
		}
	}
	if singleRepo {
		paths := make([]string, 0, len(files))
		for _, file := range files {
			paths = append(paths, file.path)
		}
		results, err = validatePoliciesForRepo(ctx, client, owner, readRepo, files[0].repo, sha, paths, e.policyRepo())
	} else {
		results, err = validatePolicyFiles(ctx, client, owner, readRepo, sha, files, e.policyRepo())
	}
	// If we were rate-limited, acknowledge the delivery and skip the CheckRun.
	// Returning an error would surface as a 5xx, which GitHub treats as a
	// failed delivery and redelivers — amplifying load on the rate-limited API.
	if octosts.IsGitHubRateLimited(err) {
		log.Warnf("rate-limited validating policies for %s/%s@%s; skipping CheckRun", owner, readRepo, sha)
		// Files validated before the limit was hit still have real verdicts;
		// the rest are simply absent from the map and stay unknown. The limit
		// is carried on the events so that "unknown" comes with a reason.
		return nil, validationOutcome{verdicts: results, incomplete: err}, nil
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
		ExternalID:  new(sha),
		Status:      new("completed"),
		Conclusion:  new(conclusion),
		StartedAt:   &github.Timestamp{Time: time.Now()},
		CompletedAt: &github.Timestamp{Time: time.Now()},
		Output: &github.CheckRunOutput{
			Title:   new(title),
			Summary: new(summary),
		},
	}

	cr, _, err := client.Checks.CreateCheckRun(ctx, owner, readRepo, opts)
	if err != nil {
		log.Errorf("error creating CheckRun: %v", err)
		// The verdicts are still authoritative; only reporting them to the
		// check run failed.
		return nil, validationOutcome{verdicts: results, incomplete: err}, err
	}
	return cr, validationOutcome{verdicts: results}, nil
}

// validatePoliciesForRepo reads each file from readRepo at sha, classifies it
// using policyRepo, and returns per-file verdicts and the aggregate error used
// for the check run. A file present in the map with a nil value parsed
// cleanly; a file absent from the map was never read,
// because a rate limit aborted the pass before reaching it.
func validatePoliciesForRepo(ctx context.Context, client *github.Client, owner, readRepo, policyRepo, sha string, files []string, orgPolicyRepo string) (map[string]error, error) {
	policyFiles := make([]policyFile, 0, len(files))
	for _, path := range files {
		policyFiles = append(policyFiles, policyFile{path: path, repo: policyRepo})
	}
	return validatePolicyFiles(ctx, client, owner, readRepo, sha, policyFiles, orgPolicyRepo)
}

func validatePolicyFiles(ctx context.Context, client *github.Client, owner, readRepo, sha string, files []policyFile, orgPolicyRepo string) (map[string]error, error) {
	var merr error
	results := make(map[string]error, len(files))

	// fail records a file's verdict and folds it into the aggregate.
	fail := func(f string, err error) {
		results[f] = err
		merr = multierror.Append(merr, err)
	}

	unique := make(map[policyFile]struct{}, len(files))
	for _, file := range files {
		unique[file] = struct{}{}
	}
	ordered := make([]policyFile, 0, len(unique))
	for file := range unique {
		ordered = append(ordered, file)
	}
	sort.Slice(ordered, func(i, j int) bool {
		if ordered[i].path == ordered[j].path {
			return ordered[i].repo < ordered[j].repo
		}
		return ordered[i].path < ordered[j].path
	})
	contents := make(map[string]string, len(ordered))
	for _, file := range ordered {
		f := file.path
		log := clog.FromContext(ctx).With("path", f)
		raw, cached := contents[f]
		if !cached {
			resp, _, _, err := client.Repositories.GetContents(ctx, owner, readRepo, f, &github.RepositoryContentGetOptions{Ref: sha})
			if err != nil {
				log.Infof("failed to get content for: %v", err)
				if octosts.IsGitHubRateLimited(err) {
					log.Warnf("rate-limited, aborting remaining policy validations")
					// Deliberately not recorded as a verdict: being rate-limited
					// says nothing about whether this policy is valid, and an
					// audit consumer must not read it as a policy failure.
					return results, fmt.Errorf("%s: %w", f, err)
				}
				fail(f, fmt.Errorf("%s: %w", f, err))
				continue
			}

			// GetContents returns a nil file and a populated slice when the path is a
			// DIRECTORY, and RepositoryContent.GetContent dereferences its receiver
			// without a nil check — so a directory named like a policy or the allowlist
			// would panic the handler rather than fail the check run.
			if resp == nil {
				log.Infof("%s is not a file, skipping", f)
				fail(f, fmt.Errorf("%s: not a file", f))
				continue
			}

			raw, err = resp.GetContent()
			if err != nil {
				log.Infof("failed to read content: %v", err)
				fail(f, fmt.Errorf("%s: %w", f, err))
				continue
			}
			contents[f] = raw
		}

		switch {
		case strings.EqualFold(file.repo, orgPolicyRepo) && f == octosts.OrgTrustedIssuersPath:
			// Parse AND compile: only compiling catches uncompilable patterns,
			// invalid issuer URLs, and an empty allowlist. The exchange path calls
			// this same function, so the two verdicts cannot diverge.
			if _, err := octosts.ParseOrgTrustedIssuers([]byte(raw)); err != nil {
				log.Infof("failed to validate org trusted issuers: %v", err)
				fail(f, fmt.Errorf("%s: %w", f, err))
				continue
			}

		// EqualFold, matching the arm above: GitHub preserves repository-name case,
		// so an org whose repo is literally ".GitHub" would otherwise fall through
		// to the default arm and have its org policy strict-unmarshalled as a
		// repo-level TrustPolicy — a bogus check-run failure on a valid file.
		//
		// Parse AND compile, as for the allowlist above: only compiling catches an
		// uncompilable pattern, which would otherwise pass this check and fail at
		// token exchange. lookupTrustPolicy on the exchange path does the same.
		case strings.EqualFold(file.repo, orgPolicyRepo):
			if err := parseAndCompile(raw, &octosts.OrgTrustPolicy{}); err != nil {
				log.Infof("failed to validate org trust policy: %v", err)
				fail(f, fmt.Errorf("%s: %w", f, err))
				continue
			}

		default:
			if err := parseAndCompile(raw, &octosts.TrustPolicy{}); err != nil {
				log.Infof("failed to validate trust policy: %v", err)
				fail(f, fmt.Errorf("%s: %w", f, err))
				continue
			}
		}

		// The same path can appear in a push diff and in a PR against the
		// organization policy repository. Keep any earlier failed verdict.
		if _, seen := results[f]; !seen {
			results[f] = nil
		}
	}

	return results, merr
}

// compilableTrustPolicy is satisfied by *octosts.TrustPolicy and *octosts.OrgTrustPolicy.
type compilableTrustPolicy interface {
	Compile() error
}

// parseAndCompile strict-unmarshals raw into tp and compiles it, so the check run
// applies the same verdict as the token-exchange path.
func parseAndCompile(raw string, tp compilableTrustPolicy) error {
	if err := yaml.UnmarshalStrict([]byte(raw), tp); err != nil {
		return err
	}
	return tp.Compile()
}

func (e *Validator) handlePush(ctx context.Context, event *github.PushEvent) (checkRun *github.CheckRun, err error) {
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

	// GitHub push payloads include up to 20 commits. When not truncated, use
	// the payload directly to avoid a Compare API call. When truncated, the
	// payload's commit list silently omits changes, so a large push would
	// under-report both the files to validate and the policies to audit.
	//
	// A forced push is handled ahead of both: it can rewrite the branch to a
	// state the commits it carries do not describe, so neither payload nor
	// compare reports its net effect.
	isDefaultBranch := event.GetRef() == "refs/heads/"+event.GetRepo().GetDefaultBranch()

	var changes []PolicyChange
	detection := DetectionCommits
	var detectionErr string

	switch {
	case event.GetForced() && isDefaultBranch:
		snapshot, live, serr := e.policyChangesFromSnapshot(ctx, client, owner, repo, event.GetBefore(), sha)
		if serr != nil {
			// Most often the pre-push SHA is no longer reachable, which GitHub
			// is free to garbage collect after a rewind, so the diff cannot be
			// computed. Record that the audit view of this push is incomplete.
			log.Warnf("policy snapshot failed, falling back: %v", serr)
			detection, detectionErr = DetectionDegraded, serr.Error()
			if isProvenWebhookRateLimit(serr) {
				// Further reads would amplify the limit. The degraded marker
				// records the gap without posting a partial check run.
				break
			}

			// Only before failed to resolve; the listing at the pushed SHA is
			// still good. Report what is live rather than the commit list,
			// which for the rewind that caused this is empty — that would
			// leave the resurfaced policy unvalidated and unrecorded, the very
			// gap the snapshot path exists to close.
			if live != nil {
				changes = policiesPresent(live)
				break
			}
			changes = e.policyChangesFromPushEvent(repo, event)
			break
		}
		detection = DetectionSnapshot
		changes = snapshot

	case len(event.Commits) < 20:
		changes = e.policyChangesFromPushEvent(repo, event)

	case event.GetBefore() == zeroHash:
		changes, err = e.policyChangesFromTrees(ctx, client, owner, repo, zeroHash, sha)
		if err != nil {
			if isProvenWebhookRateLimit(err) {
				log.Warnf("rate-limited discovering policies for new ref %s/%s@%s; recording degraded detection", owner, repo, sha)
				detection, detectionErr = DetectionDegraded, err.Error()
				break
			}
			return nil, err
		}
		detection = DetectionSnapshot

	default:
		resp, _, err := client.Repositories.CompareCommits(ctx, owner, repo, event.GetBefore(), sha, &github.ListOptions{})
		if err != nil {
			if isProvenWebhookRateLimit(err) {
				detection, detectionErr = DetectionDegraded, err.Error()
				break
			}
			return nil, err
		}
		changes, detection, err = e.completeCompareChanges(ctx, client, owner, repo, event.GetBefore(), sha, resp)
		if err != nil {
			if isProvenWebhookRateLimit(err) {
				detection, detectionErr = DetectionDegraded, err.Error()
				break
			}
			return nil, err
		}
	}

	// Validation and auditing share one view of the push so the two can't
	// disagree about which policies it touched.
	files := pathsToValidate(changes)

	// outcome is populated by handleSHA below; the deferred closure reads it
	// after the fact, so a push that returns early leaves it zero and every
	// policy is reported with an unknown verdict rather than a clean one.
	//
	// A degraded push is emitted even with no changes to show: the absence of
	// events is exactly what a suppressed audit looks like, so the marker has
	// to be published for the gap to be visible.
	var outcome validationOutcome
	if e.Emitter != nil && isDefaultBranch && (len(changes) > 0 || detection == DetectionDegraded) {
		defer func() {
			e.emitPolicyEvents(ctx, event, owner, repo, sha, installationID, changes, detection, detectionErr, outcome)
		}()
	}

	// Deletions leave nothing to read at the head SHA, so a push that only
	// removes policies has nothing to validate — but the removals still belong
	// in the audit trail, which the deferred emit above has already captured.
	if len(files) == 0 {
		return nil, nil
	}

	checkRun, outcome, err = e.handleSHA(ctx, client, owner, repo, sha, files)
	return checkRun, err
}

// emitPolicyEvents publishes one audit event per trust policy touched by a push
// to the default branch, preceded by a push-level marker when change detection
// degraded.
//
// outcome carries the per-file verdicts from handleSHA and may be zero or
// partial: a policy missing from it was never read, and is reported with a nil
// Valid so consumers can tell "unknown" from "valid".
func (e *Validator) emitPolicyEvents(ctx context.Context, event *github.PushEvent, owner, repo, sha string, installationID int64, changes []PolicyChange, detection DetectionMethod, detectionErr string, outcome validationOutcome) {
	base := PolicyEvent{
		Org:            owner,
		Repo:           repo,
		Ref:            event.GetRef(),
		Commit:         sha,
		Before:         event.GetBefore(),
		InstallationID: installationID,
		Actor:          event.GetSender().GetLogin(),
		ActorID:        event.GetSender().GetID(),
		Pusher:         event.GetPusher().GetName(),
		Forced:         event.GetForced(),
		Detection:      detection,
		DetectionError: detectionErr,
		ChangeCount:    len(changes),
	}
	if outcome.incomplete != nil {
		base.PushError = outcome.incomplete.Error()
	}

	// The marker carries no change: it says only that this push's change list
	// cannot be trusted to be complete, which is a statement about the push.
	if detection == DetectionDegraded {
		marker := base
		marker.Time = time.Now()
		e.sendPolicyEvent(ctx, event, owner, repo, sha, installationID, marker)
	}

	for i, change := range changes {
		pe := base
		pe.Change = &change
		pe.ChangeIndex = i
		pe.Time = time.Now()
		if verr, ok := outcome.verdicts[change.Path]; ok {
			pe.Valid = new(verr == nil)
			if verr != nil {
				pe.Error = verr.Error()
			}
		}
		e.sendPolicyEvent(ctx, event, owner, repo, sha, installationID, pe)
	}
}

// sendPolicyEvent wraps one PolicyEvent as a CloudEvent and hands it to the
// emitter, which delivers it asynchronously.
func (e *Validator) sendPolicyEvent(ctx context.Context, event *github.PushEvent, owner, repo, sha string, installationID int64, pe PolicyEvent) {
	subject := event.GetRepo().GetFullName()
	if pe.Change != nil {
		subject += "/" + pe.Change.Policy
	}

	ce := cloudevents.NewEvent()
	ce.SetType("dev.octo-sts.policy")
	ce.SetSource(fmt.Sprintf("https://github.com/%s/%s", owner, repo))
	ce.SetSubject(subject)
	ce.SetTime(pe.Time)
	ce.SetExtension("githubinstallationid", strconv.FormatInt(installationID, 10))
	ce.SetExtension("githubcommit", sha)
	if err := ce.SetData(cloudevents.ApplicationJSON, pe); err != nil {
		clog.FromContext(ctx).Errorf("failed to set cloudevents data: %v", err)
		return
	}
	e.Emitter.Enqueue(ctx, ce)
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
	baseEdited := pr.GetAction() == "edited" && pr.GetChanges().GetBase() != nil
	if !prActionsThatChangeFiles.Has(pr.GetAction()) && !baseEdited {
		log.Infof("skipping pull_request action %q: cannot change file diff", pr.GetAction())
		return nil, nil
	}

	client, err := e.clientForInstallation(installationID)
	if err != nil {
		return nil, err
	}

	files, err := e.policyFilesFromPR(ctx, client, owner, repo, pr.GetNumber(), sha)
	if err != nil {
		if errors.Is(err, errPRHeadMismatch) || isProvenWebhookRateLimit(err) {
			log.Warnf("skipping PR file validation: %v", err)
			return nil, nil
		}
		return nil, err
	}
	if len(files) == 0 {
		return nil, nil
	}

	cr, _, err := e.handleSHA(ctx, client, owner, repo, sha, files)
	return cr, err
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

	var files []policyFile
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
		_, dirContents, resp, err := client.Repositories.GetContents(ctx, owner, repo, policyDir, &github.RepositoryContentGetOptions{Ref: sha})
		if err != nil {
			if isProvenWebhookRateLimit(err) {
				log.Warnf("rate-limited discovering policies for check suite; skipping CheckRun: %v", err)
				return nil, nil
			}
			if resp == nil || resp.StatusCode != http.StatusNotFound {
				return nil, err
			}
			log.Infof("no policy directory at %s, skipping validation", sha)
		}
		for _, file := range dirContents {
			if file.GetType() == "file" && isValidatedPath(repo, file.GetPath(), e.policyRepo()) {
				files = append(files, policyFile{path: file.GetPath(), repo: repo})
			}
		}
	} else {
		resp, _, err := client.Repositories.CompareCommits(ctx, owner, repo, cs.GetCheckSuite().GetBeforeSHA(), sha, &github.ListOptions{})
		if err != nil {
			if isProvenWebhookRateLimit(err) {
				log.Warnf("rate-limited comparing check suite; skipping CheckRun: %v", err)
				return nil, nil
			}
			return nil, err
		}
		changes, _, err := e.completeCompareChanges(ctx, client, owner, repo, cs.GetCheckSuite().GetBeforeSHA(), sha, resp)
		if err != nil {
			if isProvenWebhookRateLimit(err) {
				log.Warnf("rate-limited discovering check suite changes; skipping CheckRun: %v", err)
				return nil, nil
			}
			return nil, err
		}
		for _, path := range pathsToValidate(changes) {
			files = append(files, policyFile{path: path, repo: repo})
		}
	}

	for _, pr := range cs.GetCheckSuite().PullRequests {
		prOwner, prRepo, crossRepo, err := checkSuitePRHome(pr, owner, repo)
		if err != nil {
			return nil, err
		}
		prFiles, err := e.policyFilesFromPR(ctx, client, prOwner, prRepo, pr.GetNumber(), sha)
		if err != nil {
			if errors.Is(err, errPRHeadMismatch) {
				log.Warnf("PR %s/%s#%d head differs from check suite commit; skipping CheckRun: %v", prOwner, prRepo, pr.GetNumber(), err)
				return nil, nil
			}
			if isProvenWebhookRateLimit(err) {
				log.Warnf("rate-limited listing check suite PR files; skipping CheckRun: %v", err)
				return nil, nil
			}
			if crossRepo && inaccessibleCrossRepoPR(err) {
				log.Warnf("skipping inaccessible PR %s/%s#%d: %v", prOwner, prRepo, pr.GetNumber(), err)
				continue
			}
			return nil, err
		}
		for _, path := range prFiles {
			files = append(files, policyFile{path: path, repo: prRepo})
		}
	}
	if len(files) == 0 {
		return nil, nil
	}

	cr, _, err := e.handleSHAForPolicyFiles(ctx, client, owner, repo, sha, files)
	return cr, err
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
