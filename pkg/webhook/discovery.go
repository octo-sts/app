// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package webhook

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/chainguard-dev/clog"
	"github.com/google/go-github/v88/github"
)

// isProvenWebhookRateLimit excludes ordinary permission 403s so discovery
// failures remain visible while genuine limits are acknowledged rather than failing the delivery.
func isProvenWebhookRateLimit(err error) bool {
	var rate *github.RateLimitError
	var abuse *github.AbuseRateLimitError
	if errors.As(err, &rate) || errors.As(err, &abuse) {
		return true
	}
	var response *github.ErrorResponse
	if !errors.As(err, &response) || response.Response == nil {
		return false
	}
	return response.Response.StatusCode == http.StatusTooManyRequests ||
		(response.Response.StatusCode == http.StatusForbidden &&
			(response.Response.Header.Get("X-RateLimit-Remaining") == "0" || response.Response.Header.Get("Retry-After") != ""))
}

// isNoCommonAncestor reports GitHub refusing a compare because the two commits
// share no history, as after a branch is rewritten onto unrelated commits. That
// compare can never succeed, so callers validate what is live at the head.
func isNoCommonAncestor(err error) bool {
	var response *github.ErrorResponse
	return errors.As(err, &response) && response.Response != nil &&
		response.Response.StatusCode == http.StatusNotFound &&
		strings.HasPrefix(response.Message, "No common ancestor")
}

// policyReadDeniedError is the per-file verdict for a policy content read that
// GitHub refused with a 403 that is not a proven rate limit. Its message names
// the likely cause without echoing the request URL. The GitHub error stays in
// the chain for errors.As.
type policyReadDeniedError struct {
	path string
	err  error
}

func (e *policyReadDeniedError) Error() string {
	return e.path + ": cannot read policy: permission denied (403); check the GitHub App's contents permission"
}

func (e *policyReadDeniedError) Unwrap() error { return e.err }

const (
	prFilesPerPage = 100
	maxPRFiles     = 3000
	maxPRPages     = maxPRFiles / prFilesPerPage
	compareFileCap = 300
	// Count every expanded path, including repeated tree SHAs and non-policies.
	maxPolicySnapshotPaths = 10000
	// Including the policy root, this caps tree requests even for unique SHAs.
	maxPolicySnapshotDirs = 512
	// Depth is directory levels below the policy directory, which is depth 0.
	maxPolicySnapshotDepth = 32
)

var errPRHeadMismatch = errors.New("pull request head differs from event commit")

var errPolicySnapshotIncomplete = errors.New("recursive policy snapshot incomplete")
var errPolicySnapshotLimit = fmt.Errorf("policy snapshot limit exceeded: %w", errPolicySnapshotIncomplete)

// snapshotBeforeIncompleteError preserves a complete live snapshot when only the
// prior tree failed during recursive discovery. It is scoped to the compare fallback.
type snapshotBeforeIncompleteError struct {
	err  error
	live map[string]string
}

func (e *snapshotBeforeIncompleteError) Error() string { return e.err.Error() }
func (e *snapshotBeforeIncompleteError) Unwrap() error { return e.err }

// errTooManyPRFiles marks a PR whose diff GitHub cannot list completely. A
// partial list could miss a changed policy, so callers must not use one.
var errTooManyPRFiles = errors.New("pull request has more changed files than GitHub lists")

// prTooLargeError reports a PR past GitHub's list-files cap. It matches
// errTooManyPRFiles. scanErr is set when the policy directory scan that
// replaces the diff also failed, leaving the head commit unvalidated.
type prTooLargeError struct {
	number, count int
	scanErr       error
}

func (e *prTooLargeError) Error() string {
	msg := fmt.Sprintf("pull request %d has %d changed files; GitHub lists at most %d", e.number, e.count, maxPRFiles)
	if e.scanErr != nil {
		msg += fmt.Sprintf("; policy directory scan failed: %v", e.scanErr)
	}
	return msg
}

func (e *prTooLargeError) Is(target error) bool { return target == errTooManyPRFiles }

// policyChangesFromPR lists a complete, stable PR diff before selecting
// policies, deletions included. owner/repo is where the PR lives; classifyRepo
// is the repository name used to decide which listed paths are policies, so
// selection matches how the files will be parsed.
func (e *Validator) policyChangesFromPR(ctx context.Context, client *github.Client, owner, repo string, number int, expectedHead, classifyRepo string) ([]PolicyChange, error) {
	snapshot := func() (head, base string, count int, err error) {
		pr, resp, err := client.PullRequests.Get(ctx, owner, repo, number)
		if err != nil {
			return "", "", 0, err
		}
		if resp == nil || resp.Response == nil || pr == nil || pr.Head == nil || pr.Head.SHA == nil || pr.GetHead().GetSHA() == "" || pr.Base == nil || pr.Base.SHA == nil || pr.GetBase().GetSHA() == "" || pr.ChangedFiles == nil {
			return "", "", 0, fmt.Errorf("pull request %d has incomplete snapshot metadata", number)
		}
		return pr.GetHead().GetSHA(), pr.GetBase().GetSHA(), pr.GetChangedFiles(), nil
	}

	for attempt := 0; attempt < 2; attempt++ {
		head, base, count, err := snapshot()
		if err != nil {
			return nil, err
		}
		if head != expectedHead {
			// The PR API may lag the event; retry once.
			if attempt == 0 {
				continue
			}
			return nil, fmt.Errorf("pull request %d head %s differs from event head %s: %w", number, head, expectedHead, errPRHeadMismatch)
		}
		if count < 0 {
			return nil, fmt.Errorf("pull request %d reports %d changed files", number, count)
		}
		if count > maxPRFiles {
			return nil, &prTooLargeError{number: number, count: count}
		}

		seen := make(map[string]struct{}, count)
		var files []*github.CommitFile
		page := 1
		retrySnapshot := false
		for range maxPRPages {
			listed, resp, err := client.PullRequests.ListFiles(ctx, owner, repo, number, &github.ListOptions{Page: page, PerPage: prFilesPerPage})
			if err != nil {
				return nil, err
			}
			if resp == nil || resp.Response == nil || listed == nil {
				return nil, fmt.Errorf("pull request %d file page %d is incomplete", number, page)
			}
			for _, file := range listed {
				if file == nil || file.Filename == nil || file.GetFilename() == "" || file.Status == nil || file.GetStatus() == "" {
					return nil, fmt.Errorf("pull request %d file page %d has an incomplete entry", number, page)
				}
				if _, exists := seen[file.GetFilename()]; exists {
					return nil, fmt.Errorf("pull request %d repeats file %q", number, file.GetFilename())
				}
				seen[file.GetFilename()] = struct{}{}
				files = append(files, file)
			}
			if resp.NextPage == 0 {
				finalHead, finalBase, finalCount, err := snapshot()
				if err != nil {
					return nil, err
				}
				if finalHead != expectedHead {
					if attempt == 0 {
						retrySnapshot = true
						break
					}
					return nil, fmt.Errorf("pull request %d head %s differs from event head %s: %w", number, finalHead, expectedHead, errPRHeadMismatch)
				}
				if head != finalHead || base != finalBase {
					return nil, fmt.Errorf("pull request %d changed during file listing", number)
				}
				if count != finalCount || len(seen) != finalCount {
					if attempt == 0 {
						retrySnapshot = true
						break
					}
					return nil, fmt.Errorf("pull request %d file list has %d entries, expected %d", number, len(seen), finalCount)
				}
				return e.policyChangesFromCompare(ctx, classifyRepo, files), nil
			}
			if resp.NextPage != page+1 {
				return nil, fmt.Errorf("pull request %d file pages jump from %d to %d", number, page, resp.NextPage)
			}
			page = resp.NextPage
		}
		if !retrySnapshot {
			return nil, fmt.Errorf("pull request %d exceeds %d file pages", number, maxPRPages)
		}
	}
	return nil, fmt.Errorf("pull request %d file listing stayed incomplete after retry", number)
}

// prPolicyChanges returns the policy changes a PR makes at sha, deletions
// included. The PR is listed in prOwner/prRepo; content is read from
// readOwner/readRepo and classified as classifyRepo, matching how the files
// will be parsed.
//
// When the diff is too large for GitHub to list, every policy in the read
// repository's policy directory at sha is returned as PolicyPresent instead,
// so all of them are validated. That scan cannot see deletions, which is safe:
// it validates everything live at sha rather than only what changed. A rate
// limit or token-mint 403 during that scan is returned as is. Any other scan
// failure returns a *prTooLargeError with scanErr set, so the caller can fail
// the check run rather than skip it.
func (e *Validator) prPolicyChanges(ctx context.Context, client *github.Client, prOwner, prRepo string, number int, sha, readOwner, readRepo, classifyRepo string) ([]PolicyChange, error) {
	changes, err := e.policyChangesFromPR(ctx, client, prOwner, prRepo, number, sha, classifyRepo)
	tooLarge, ok := errors.AsType[*prTooLargeError](err)
	if !ok {
		return changes, err
	}
	clog.FromContext(ctx).Warnf("%v; validating every policy in %s/%s@%s instead", tooLarge, readOwner, readRepo, sha)
	snapshot, err := e.policyTreeSnapshotAs(ctx, client, readOwner, readRepo, classifyRepo, sha)
	if err != nil {
		if installationToken403(err) != nil || isProvenWebhookRateLimit(err) {
			return nil, err
		}
		return nil, &prTooLargeError{number: tooLarge.number, count: tooLarge.count, scanErr: err}
	}
	return e.policiesPresent(snapshot), nil
}

// reportPRTooLarge posts a failed check run for a PR that could be validated
// neither by its diff nor by a policy directory scan. The conclusion must be
// failure: branch protection treats neutral and skipped as passing, so either
// would let a PR padded past GitHub's cap skip validation.
func (e *Validator) reportPRTooLarge(ctx context.Context, client *github.Client, owner, repo, sha string, tooLarge *prTooLargeError) (*github.CheckRun, error) {
	clog.FromContext(ctx).Warnf("failing check run: %v", tooLarge)
	summary := fmt.Sprintf("Pull request #%d changes %d files. GitHub lists at most %d changed files for a pull request, "+
		"so the trust policies it touches cannot be identified, and scanning the policy directory instead failed: %v\n\n"+
		"Split this pull request into smaller ones so each changes at most %d files.",
		tooLarge.number, tooLarge.count, maxPRFiles, tooLarge.scanErr, maxPRFiles)
	cr, _, err := client.Checks.CreateCheckRun(ctx, owner, repo, github.CreateCheckRunOptions{
		Name:        checkRunName,
		HeadSHA:     sha,
		ExternalID:  new(sha),
		Status:      new("completed"),
		Conclusion:  new("failure"),
		StartedAt:   &github.Timestamp{Time: time.Now()},
		CompletedAt: &github.Timestamp{Time: time.Now()},
		Output: &github.CheckRunOutput{
			Title:   new("Pull request too large to validate"),
			Summary: new(summary),
		},
	})
	return cr, err
}

// policyTreeSnapshot reads only the policy directory at a commit and refuses
// incomplete responses. It avoids both the Compare API's 300-file limit and
// GitHub's recursive tree limit for large repositories.
func (e *Validator) policyTreeSnapshot(ctx context.Context, client *github.Client, owner, repo, ref string) (map[string]string, error) {
	return e.policyTreeSnapshotAs(ctx, client, owner, repo, repo, ref)
}

// policyTreeSnapshotAs is policyTreeSnapshot reading from owner/repo but
// selecting validated paths as classifyRepo, for content read from a fork.
func (e *Validator) policyTreeSnapshotAs(ctx context.Context, client *github.Client, owner, repo, classifyRepo, ref string) (map[string]string, error) {
	commit, _, err := client.Git.GetCommit(ctx, owner, repo, ref)
	if err != nil {
		return nil, err
	}
	if commit == nil || commit.Tree == nil || commit.GetTree().GetSHA() == "" {
		return nil, fmt.Errorf("commit %s has no tree SHA", ref)
	}
	treeSHA := commit.GetTree().GetSHA()
	trees := make(map[string]*github.Tree)
	getTree := func(sha string) (*github.Tree, error) {
		if tree := trees[sha]; tree != nil {
			return tree, nil
		}
		tree, err := completePolicyTree(ctx, client, owner, repo, sha)
		if err == nil {
			trees[sha] = tree
		}
		return tree, err
	}
	for directory := range strings.SplitSeq(e.policyDir(), "/") {
		tree, err := getTree(treeSHA)
		if err != nil {
			return nil, fmt.Errorf("tree at %s: %w", ref, err)
		}
		found := false
		for _, entry := range tree.Entries {
			if entry.GetPath() != directory {
				continue
			}
			if entry.GetType() != "tree" {
				if entry.GetMode() == "120000" {
					return nil, fmt.Errorf("policy directory component %q is a symlink: %w", directory, errPolicySnapshotIncomplete)
				}
				return map[string]string{}, nil
			}
			if entry.GetMode() != "040000" {
				return nil, fmt.Errorf("policy directory component %q has invalid mode %q: %w", directory, entry.GetMode(), errPolicySnapshotIncomplete)
			}
			treeSHA = entry.GetSHA()
			found = true
			break
		}
		if !found {
			return map[string]string{}, nil
		}
	}
	out := make(map[string]string)
	type pendingTree struct {
		sha, dir string
		depth    int
	}
	pending := []pendingTree{{treeSHA, e.policyDir(), 0}}
	paths := 1 // The policy directory itself.
	dirs := 1
	for len(pending) > 0 {
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("%w: %w", errPolicySnapshotIncomplete, err)
		}
		current := pending[len(pending)-1]
		pending = pending[:len(pending)-1]
		tree, err := getTree(current.sha)
		if err != nil {
			if current.depth > 0 {
				return nil, fmt.Errorf("policy tree %s at %s: %w: %w", current.dir, ref, errPolicySnapshotIncomplete, err)
			}
			return nil, fmt.Errorf("policy tree %s at %s: %w", current.dir, ref, err)
		}
		// Reserve before appending children: both pending work and output stay
		// bounded even when many paths reference the same cached tree.
		if len(tree.Entries) > maxPolicySnapshotPaths-paths {
			return nil, fmt.Errorf("policy snapshot exceeds %d paths: %w", maxPolicySnapshotPaths, errPolicySnapshotLimit)
		}
		paths += len(tree.Entries)
		for _, entry := range tree.Entries {
			name := entry.GetPath()
			if strings.Contains(name, "/") || !pathIsClean(name) {
				return nil, fmt.Errorf("tree %s has invalid entry path %q: %w", current.sha, name, errPolicySnapshotIncomplete)
			}
			filePath := current.dir + "/" + name
			if entry.GetMode() == "120000" {
				if isValidatedPath(classifyRepo, filePath, e.policyRepo(), e.policyDir()) {
					return nil, fmt.Errorf("policy path is a symlink: %s: %w", filePath, errPolicySnapshotIncomplete)
				}
				// A symlink is not a tree. Git alone cannot enumerate paths that
				// Contents might resolve through it; changed descendants are
				// rejected by policyPathIsRegular before their content is read.
				continue
			}
			switch entry.GetType() {
			case "blob":
				if isValidatedPath(classifyRepo, filePath, e.policyRepo(), e.policyDir()) {
					if entry.GetMode() != "100644" && entry.GetMode() != "100755" {
						return nil, fmt.Errorf("policy %s has invalid mode %q: %w", filePath, entry.GetMode(), errPolicySnapshotIncomplete)
					}
					out[filePath] = entry.GetSHA()
				}
			case "tree":
				if entry.GetMode() != "040000" {
					return nil, fmt.Errorf("policy directory %s has invalid mode %q: %w", filePath, entry.GetMode(), errPolicySnapshotIncomplete)
				}
				if current.depth == maxPolicySnapshotDepth {
					return nil, fmt.Errorf("policy snapshot exceeds directory depth %d at %s: %w", maxPolicySnapshotDepth, filePath, errPolicySnapshotLimit)
				}
				if dirs == maxPolicySnapshotDirs {
					return nil, fmt.Errorf("policy snapshot exceeds %d directories: %w", maxPolicySnapshotDirs, errPolicySnapshotLimit)
				}
				dirs++
				pending = append(pending, pendingTree{entry.GetSHA(), filePath, current.depth + 1})
			case "commit": // Submodules cannot contain repository policies.
			default:
				if current.depth > 0 {
					return nil, fmt.Errorf("tree at %s has unknown entry type %q: %w", ref, entry.GetType(), errPolicySnapshotIncomplete)
				}
				return nil, fmt.Errorf("tree at %s has unknown entry type %q", ref, entry.GetType())
			}
		}
	}
	return out, nil
}

// policyPathIsRegular resolves each component from immutable Git trees before
// Contents can dereference a symlink. A missing or non-regular component fails.
func policyPathIsRegular(ctx context.Context, client *github.Client, owner, repo, ref, filePath string) error {
	return (&policyPathVerifier{client: client, owner: owner, repo: repo, ref: ref}).verify(ctx, filePath)
}

// policyPathVerifier caches successful Git reads for one validation pass and ref.
type policyPathVerifier struct {
	client           *github.Client
	owner, repo, ref string
	root             string
	trees            map[string]*github.Tree
}

func (v *policyPathVerifier) verify(ctx context.Context, filePath string) error {
	if v.root == "" {
		commit, _, err := v.client.Git.GetCommit(ctx, v.owner, v.repo, v.ref)
		if err != nil {
			return err
		}
		if commit == nil || commit.Tree == nil || commit.GetTree().GetSHA() == "" {
			return fmt.Errorf("commit %s has no tree SHA", v.ref)
		}
		v.root = commit.GetTree().GetSHA()
	}
	if v.trees == nil {
		v.trees = make(map[string]*github.Tree)
	}
	sha := v.root
	parts := strings.Split(filePath, "/")
	for i, part := range parts {
		tree := v.trees[sha]
		if tree == nil {
			var err error
			tree, err = completePolicyTree(ctx, v.client, v.owner, v.repo, sha)
			if err != nil {
				return err
			}
			v.trees[sha] = tree
		}
		var match *github.TreeEntry
		for _, entry := range tree.Entries {
			if entry.GetPath() == part {
				if match != nil {
					return fmt.Errorf("duplicate tree entry %q", part)
				}
				match = entry
			}
		}
		if match == nil {
			return fmt.Errorf("path %s does not exist in Git tree", filePath)
		}
		if i == len(parts)-1 {
			if match.GetType() != "blob" || (match.GetMode() != "100644" && match.GetMode() != "100755") {
				return fmt.Errorf("path %s is not a regular file", filePath)
			}
			return nil
		}
		if match.GetType() != "tree" || match.GetMode() != "040000" {
			return fmt.Errorf("path %s has a non-directory or symlink parent %q", filePath, part)
		}
		sha = match.GetSHA()
	}
	return fmt.Errorf("empty policy path")
}

func completePolicyTree(ctx context.Context, client *github.Client, owner, repo, sha string) (*github.Tree, error) {
	tree, _, err := client.Git.GetTree(ctx, owner, repo, sha, false)
	if err != nil {
		return nil, err
	}
	if tree == nil || tree.Truncated == nil || tree.Entries == nil || tree.GetTruncated() {
		return nil, fmt.Errorf("tree %s is incomplete or truncated", sha)
	}
	for _, entry := range tree.Entries {
		if entry == nil || entry.GetPath() == "" || entry.GetType() == "" || entry.GetSHA() == "" {
			return nil, fmt.Errorf("tree %s has an incomplete entry", sha)
		}
	}
	return tree, nil
}

func (e *Validator) policyChangesFromTrees(ctx context.Context, client *github.Client, owner, repo, before, after string) ([]PolicyChange, error) {
	afterFiles, err := e.policyTreeSnapshot(ctx, client, owner, repo, after)
	if err != nil {
		return nil, err
	}
	beforeFiles := map[string]string{}
	if before != zeroHash {
		beforeFiles, err = e.policyTreeSnapshot(ctx, client, owner, repo, before)
		if err != nil {
			if errors.Is(err, errPolicySnapshotIncomplete) {
				return nil, &snapshotBeforeIncompleteError{err: err, live: afterFiles}
			}
			return nil, err
		}
	}
	var changes []PolicyChange
	for path, sha := range afterFiles {
		beforeSHA, existed := beforeFiles[path]
		switch {
		case !existed:
			changes = append(changes, PolicyChange{Path: path, Policy: policyName(path, e.policyDir()), Action: PolicyCreated})
		case sha != beforeSHA:
			changes = append(changes, PolicyChange{Path: path, Policy: policyName(path, e.policyDir()), Action: PolicyUpdated})
		}
	}
	for path := range beforeFiles {
		if _, exists := afterFiles[path]; !exists {
			changes = append(changes, PolicyChange{Path: path, Policy: policyName(path, e.policyDir()), Action: PolicyDeleted})
		}
	}
	sort.Slice(changes, func(i, j int) bool { return changes[i].Path < changes[j].Path })
	return changes, nil
}

func (e *Validator) completeCompareChanges(ctx context.Context, client *github.Client, owner, repo, before, after string, comparison *github.CommitsComparison) ([]PolicyChange, DetectionMethod, error) {
	if comparison == nil || comparison.Files == nil {
		changes, err := e.policyChangesFromTrees(ctx, client, owner, repo, before, after)
		return changes, DetectionSnapshot, err
	}
	for _, file := range comparison.Files {
		if file == nil || file.GetFilename() == "" || file.GetStatus() == "" {
			return nil, "", errors.New("GitHub comparison has an incomplete file entry")
		}
	}
	if len(comparison.Files) >= compareFileCap {
		changes, err := e.policyChangesFromTrees(ctx, client, owner, repo, before, after)
		return changes, DetectionSnapshot, err
	}
	return e.policyChangesFromCompare(ctx, repo, comparison.Files), DetectionCompare, nil
}
