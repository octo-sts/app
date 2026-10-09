// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package webhook

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"time"

	"github.com/chainguard-dev/clog"
	"github.com/google/go-github/v88/github"
)

// isProvenWebhookRateLimit excludes ordinary permission 403s so discovery
// failures remain visible while genuine limits do not trigger redelivery.
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
)

var errPRHeadMismatch = errors.New("pull request head differs from event commit")

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
// limit during that scan is returned as is. Any other scan failure returns a
// *prTooLargeError with scanErr set, so the caller can fail the check run
// rather than skip it.
func (e *Validator) prPolicyChanges(ctx context.Context, client *github.Client, prOwner, prRepo string, number int, sha, readOwner, readRepo, classifyRepo string) ([]PolicyChange, error) {
	changes, err := e.policyChangesFromPR(ctx, client, prOwner, prRepo, number, sha, classifyRepo)
	tooLarge, ok := errors.AsType[*prTooLargeError](err)
	if !ok {
		return changes, err
	}
	clog.FromContext(ctx).Warnf("%v; validating every policy in %s/%s@%s instead", tooLarge, readOwner, readRepo, sha)
	snapshot, err := e.policyTreeSnapshotAs(ctx, client, readOwner, readRepo, classifyRepo, sha)
	if err != nil {
		if isProvenWebhookRateLimit(err) {
			return nil, err
		}
		return nil, &prTooLargeError{number: tooLarge.number, count: tooLarge.count, scanErr: err}
	}
	return policiesPresent(snapshot), nil
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
	for _, directory := range []string{".github", "chainguard"} {
		tree, err := completePolicyTree(ctx, client, owner, repo, treeSHA)
		if err != nil {
			return nil, fmt.Errorf("tree at %s: %w", ref, err)
		}
		found := false
		for _, entry := range tree.Entries {
			if entry.GetPath() != directory {
				continue
			}
			if entry.GetType() != "tree" {
				// A file or submodule with this name cannot contain policies.
				return map[string]string{}, nil
			}
			treeSHA = entry.GetSHA()
			found = true
			break
		}
		if !found {
			return map[string]string{}, nil
		}
	}
	tree, err := completePolicyTree(ctx, client, owner, repo, treeSHA)
	if err != nil {
		return nil, fmt.Errorf("policy tree at %s: %w", ref, err)
	}
	out := make(map[string]string)
	for _, entry := range tree.Entries {
		if entry == nil || entry.GetSHA() == "" || entry.GetType() == "" || entry.GetPath() == "" {
			return nil, fmt.Errorf("tree at %s has an incomplete entry", ref)
		}
		switch entry.GetType() {
		case "blob":
			path := policyDir + "/" + entry.GetPath()
			if isValidatedPath(classifyRepo, path, e.policyRepo()) {
				out[path] = entry.GetSHA()
			}
		case "tree", "commit":
		default:
			return nil, fmt.Errorf("tree at %s has unknown entry type %q", ref, entry.GetType())
		}
	}
	return out, nil
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
			return nil, err
		}
	}
	var changes []PolicyChange
	for path, sha := range afterFiles {
		beforeSHA, existed := beforeFiles[path]
		switch {
		case !existed:
			changes = append(changes, PolicyChange{Path: path, Policy: policyName(path), Action: PolicyCreated})
		case sha != beforeSHA:
			changes = append(changes, PolicyChange{Path: path, Policy: policyName(path), Action: PolicyUpdated})
		}
	}
	for path := range beforeFiles {
		if _, exists := afterFiles[path]; !exists {
			changes = append(changes, PolicyChange{Path: path, Policy: policyName(path), Action: PolicyDeleted})
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
