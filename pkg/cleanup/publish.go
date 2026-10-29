// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package cleanup

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"path"
	"slices"
	"strings"
	"time"

	"github.com/google/go-github/v88/github"
)

const (
	// PullTitle is the title of the pull request that removes unused
	// policies from a repository.
	PullTitle = "Remove unused Octo STS trust policies"

	// IssueTitle is the title of the issue that reports policies that only
	// fail. Open issues are found again by this exact title.
	IssueTitle = "Octo STS trust policies that only fail"

	// maxCodeLen caps how much of a value, such as a recorded exchange
	// error, is quoted.
	maxCodeLen = 200
)

// Publisher acts on an organization's Plan: it keeps one pull request per
// repository removing its unused policies, and one issue per repository
// reporting its failing ones. Each run brings both up to date, and closes
// those that no longer have anything to say.
type Publisher struct {
	// Client is authenticated as the organization's installation.
	Client *github.Client
	// Org is the organization name.
	Org string
	// PolicyDir is the directory holding trust policies in each repository.
	PolicyDir string
	// Branch holds each repository's cleanup commit, such as
	// "octo-sts/octo-sts-cleanup". It is force-pushed on every run that
	// changes what is removed, the way Dependabot keeps one branch per
	// update.
	Branch string
}

// Publish brings the organization's cleanup pull requests and issues in line
// with plan. A failure in one repository does not stop the others; all
// failures are returned together.
func (p Publisher) Publish(ctx context.Context, plan Plan) error {
	if p.Client == nil || p.Org == "" || p.PolicyDir == "" || p.Branch == "" {
		return errors.New("cleanup: publisher needs a client, org, policy dir and branch")
	}
	// Decide always sets the window. Without it this is not a decided plan,
	// and publishing its emptiness would close every open proposal.
	if plan.WindowStart.IsZero() {
		return errors.New("cleanup: plan has no window start; publish only what Decide returns")
	}
	pulls, err := p.open(ctx, "is:pr head:"+p.Branch, "")
	if err != nil {
		return err
	}
	issues, err := p.open(ctx, fmt.Sprintf("is:issue in:title %q", IssueTitle), IssueTitle)
	if err != nil {
		return err
	}

	plans := make(map[string]RepoPlan, len(plan.Repos))
	names := map[string]string{}
	for _, rp := range plan.Repos {
		plans[strings.ToLower(rp.Repo)] = rp
		names[strings.ToLower(rp.Repo)] = rp.Repo
	}
	for _, open := range []map[string]*github.Issue{pulls, issues} {
		for key, i := range open {
			if _, ok := names[key]; !ok {
				names[key] = repoName(i)
			}
		}
	}
	keys := make([]string, 0, len(names))
	for key := range names {
		keys = append(keys, key)
	}
	slices.Sort(keys)

	var errs []error
	for _, key := range keys {
		repo, rp := names[key], plans[key]
		switch {
		case len(rp.Remove) > 0:
			errs = append(errs, p.propose(ctx, repo, rp.Remove, pulls[key], plan.WindowStart))
		case pulls[key] != nil:
			errs = append(errs, p.close(ctx, repo, pulls[key], "Every policy this pull request removed has been used or changed since, so there is nothing left to remove."))
		}
		switch {
		case len(rp.Failing) > 0:
			errs = append(errs, p.report(ctx, repo, rp.Failing, issues[key], plan.WindowStart))
		case issues[key] != nil:
			errs = append(errs, p.close(ctx, repo, issues[key], "None of the policies this issue listed is only failing anymore: each has succeeded, changed, or been removed."))
		}
	}
	return errors.Join(errs...)
}

// open returns the organization's open issues or pull requests matching
// query and authored by a bot, keyed by lowercased repository name. When title
// is set, only exact title matches count, since search matches words.
//
// Search is one request per hundred results, far cheaper than asking every
// repository. Incomplete results fail the run, since a missed pull request
// would be opened twice and a missed stale one left open.
func (p Publisher) open(ctx context.Context, query, title string) (map[string]*github.Issue, error) {
	q := fmt.Sprintf("org:%s is:open %s", p.Org, query)
	opts := &github.SearchOptions{AdvancedSearch: github.Ptr(true), ListOptions: github.ListOptions{PerPage: 100}}
	found := map[string]*github.Issue{}
	for {
		res, resp, err := p.Client.Search.Issues(ctx, q, opts)
		if err != nil {
			return nil, fmt.Errorf("cleanup: searching %q: %w", q, err)
		}
		if res.GetIncompleteResults() {
			return nil, fmt.Errorf("cleanup: searching %q: GitHub returned incomplete results", q)
		}
		for _, i := range res.Issues {
			if i.GetUser().GetType() != "Bot" || (title != "" && i.GetTitle() != title) {
				continue
			}
			key := strings.ToLower(repoName(i))
			if prev, ok := found[key]; !ok || i.GetNumber() < prev.GetNumber() {
				found[key] = i
			}
		}
		if resp.NextPage == 0 {
			return found, nil
		}
		opts.Page = resp.NextPage
	}
}

// propose points the cleanup branch at a commit removing policies from the
// default branch, and opens or updates its pull request.
func (p Publisher) propose(ctx context.Context, repo string, policies []Policy, pr *github.Issue, since time.Time) error {
	r, _, err := p.Client.Repositories.Get(ctx, p.Org, repo)
	if err != nil {
		return fmt.Errorf("cleanup: %s/%s: getting repository: %w", p.Org, repo, err)
	}
	base := r.GetDefaultBranch()
	b, _, err := p.Client.Repositories.GetBranch(ctx, p.Org, repo, base, 0)
	if err != nil {
		return fmt.Errorf("cleanup: %s/%s: getting branch %s: %w", p.Org, repo, base, err)
	}

	// An entry with neither SHA nor content deletes the path.
	entries := make([]*github.TreeEntry, 0, len(policies))
	for _, pol := range policies {
		entries = append(entries, &github.TreeEntry{Path: github.Ptr(p.file(pol)), Mode: github.Ptr("100644"), Type: github.Ptr("blob")})
	}
	tree, _, err := p.Client.Git.CreateTree(ctx, p.Org, repo, b.GetCommit().GetCommit().GetTree().GetSHA(), entries)
	if err != nil {
		return fmt.Errorf("cleanup: %s/%s: building tree: %w", p.Org, repo, err)
	}

	ref := "heads/" + p.Branch
	cur, resp, err := p.Client.Git.GetRef(ctx, p.Org, repo, ref)
	switch {
	case resp != nil && resp.StatusCode == http.StatusNotFound:
		cur = nil
	case err != nil:
		return fmt.Errorf("cleanup: %s/%s: getting %s: %w", p.Org, repo, ref, err)
	}

	// Leave the branch alone when it already holds the same files, so an
	// unchanged proposal does not rerun checks or notify reviewers.
	same := false
	if cur != nil {
		c, _, err := p.Client.Git.GetCommit(ctx, p.Org, repo, cur.GetObject().GetSHA())
		if err != nil {
			return fmt.Errorf("cleanup: %s/%s: getting %s: %w", p.Org, repo, ref, err)
		}
		same = c.GetTree().GetSHA() == tree.GetSHA()
	}
	if !same {
		// No author is set, so GitHub authors and signs the commit as the
		// App.
		commit, _, err := p.Client.Git.CreateCommit(ctx, p.Org, repo, github.Commit{
			Message: github.Ptr(commitMessage(policies, since)),
			Tree:    &github.Tree{SHA: tree.SHA},
			Parents: []*github.Commit{{SHA: b.GetCommit().SHA}},
		}, nil)
		if err != nil {
			return fmt.Errorf("cleanup: %s/%s: committing: %w", p.Org, repo, err)
		}
		if cur == nil {
			_, _, err = p.Client.Git.CreateRef(ctx, p.Org, repo, github.CreateRef{Ref: "refs/" + ref, SHA: commit.GetSHA()})
		} else {
			_, _, err = p.Client.Git.UpdateRef(ctx, p.Org, repo, ref, github.UpdateRef{SHA: commit.GetSHA(), Force: github.Ptr(true)})
		}
		if err != nil {
			return fmt.Errorf("cleanup: %s/%s: pushing %s: %w", p.Org, repo, ref, err)
		}
	}

	body := p.pullBody(policies, since)
	if pr == nil {
		if _, _, err := p.Client.PullRequests.Create(ctx, p.Org, repo, &github.NewPullRequest{
			Title: github.Ptr(PullTitle),
			Head:  github.Ptr(p.Branch),
			Base:  github.Ptr(base),
			Body:  github.Ptr(body),
		}); err != nil {
			return fmt.Errorf("cleanup: %s/%s: opening pull request: %w", p.Org, repo, err)
		}
		return nil
	}
	return p.update(ctx, repo, pr, body)
}

// report opens or updates the issue listing policies that only fail.
func (p Publisher) report(ctx context.Context, repo string, failing []Failing, issue *github.Issue, since time.Time) error {
	body := p.issueBody(failing, since)
	if issue == nil {
		if _, _, err := p.Client.Issues.Create(ctx, p.Org, repo, &github.IssueRequest{
			Title: github.Ptr(IssueTitle),
			Body:  github.Ptr(body),
		}); err != nil {
			return fmt.Errorf("cleanup: %s/%s: opening issue: %w", p.Org, repo, err)
		}
		return nil
	}
	return p.update(ctx, repo, issue, body)
}

// update replaces an open issue or pull request's body when it changed.
func (p Publisher) update(ctx context.Context, repo string, i *github.Issue, body string) error {
	if i.GetBody() == body {
		return nil
	}
	if _, _, err := p.Client.Issues.Edit(ctx, p.Org, repo, i.GetNumber(), &github.IssueRequest{Body: github.Ptr(body)}); err != nil {
		return fmt.Errorf("cleanup: %s/%s#%d: updating: %w", p.Org, repo, i.GetNumber(), err)
	}
	return nil
}

// close explains why an issue or pull request is no longer needed and closes
// it. A closed pull request's branch is left for the next run to reuse.
func (p Publisher) close(ctx context.Context, repo string, i *github.Issue, why string) error {
	n := i.GetNumber()
	if _, _, err := p.Client.Issues.CreateComment(ctx, p.Org, repo, n, &github.IssueComment{Body: github.Ptr(why)}); err != nil {
		return fmt.Errorf("cleanup: %s/%s#%d: commenting: %w", p.Org, repo, n, err)
	}
	req := &github.IssueRequest{State: github.Ptr("closed")}
	if !i.IsPullRequest() {
		req.StateReason = github.Ptr("completed")
	}
	if _, _, err := p.Client.Issues.Edit(ctx, p.Org, repo, n, req); err != nil {
		return fmt.Errorf("cleanup: %s/%s#%d: closing: %w", p.Org, repo, n, err)
	}
	return nil
}

func (p Publisher) file(pol Policy) string {
	return path.Join(p.PolicyDir, pol.Identity+policySuffix)
}

func (p Publisher) pullBody(policies []Policy, since time.Time) string {
	var b strings.Builder
	fmt.Fprintf(&b, "These trust policies have had no token exchanges since %s, and none has changed since then:\n\n", day(since))
	for _, pol := range policies {
		fmt.Fprintf(&b, "- %s, last changed %s\n", code(p.file(pol)), day(pol.LastChanged))
	}
	b.WriteString("\nMerging this pull request removes them. A policy drops out of it once it is used or changed. ")
	fmt.Fprintf(&b, "Octo STS keeps this pull request up to date on the %s branch and closes it when nothing is left to remove.\n", code(p.Branch))
	return b.String()
}

func (p Publisher) issueBody(failing []Failing, since time.Time) string {
	var b strings.Builder
	fmt.Fprintf(&b, "These trust policies were used since %s, but every token exchange for them since they last changed has failed:\n\n", day(since))
	for _, f := range failing {
		msg := f.LastError
		if msg == "" {
			msg = "no error recorded"
		}
		fmt.Fprintf(&b, "- %s, last failed %s: %s\n", code(p.file(f.Policy)), day(f.LastFailed), code(msg))
	}
	b.WriteString("\nThey are kept, since someone is trying to use them. Octo STS keeps this issue up to date and closes it once each one succeeds, changes, or is removed.\n")
	return b.String()
}

func commitMessage(policies []Policy, since time.Time) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s\n\nThese policies have had no token exchanges since %s:\n\n", PullTitle, day(since))
	for _, pol := range policies {
		fmt.Fprintf(&b, "- %s\n", pol.Identity)
	}
	return b.String()
}

// repoName returns the name of the repository an issue belongs to. Search
// results carry only the repository's API URL.
func repoName(i *github.Issue) string {
	if r := i.GetRepository(); r != nil && r.GetName() != "" {
		return r.GetName()
	}
	return path.Base(i.GetRepositoryURL())
}

// code quotes s as inline Markdown code on one line. Exchange errors can carry
// claim values from whoever requested the token, so they are kept out of
// Markdown that could mention users or link elsewhere.
func code(s string) string {
	s = strings.Join(strings.Fields(strings.ReplaceAll(s, "`", "'")), " ")
	if r := []rune(s); len(r) > maxCodeLen {
		s = string(r[:maxCodeLen]) + "…"
	}
	return "`" + s + "`"
}

func day(t time.Time) string {
	if t.IsZero() {
		return "at an unknown time"
	}
	return t.UTC().Format(time.DateOnly)
}
