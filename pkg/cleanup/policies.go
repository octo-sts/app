// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package cleanup

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"slices"
	"strings"
	"time"

	"github.com/google/go-github/v88/github"
)

const (
	policySuffix = ".sts.yaml"

	// batchSize is how many repositories one directory query covers.
	batchSize = 50

	// historyPerQuery caps the history lookups in one query. A query costs
	// about a point per hundred lookups, so this bounds its size, not its
	// cost.
	historyPerQuery = 100
)

// ListPolicies returns the trust policies in every repository of org that the
// client's installation can read, with when each policy file last changed.
//
// Archived repositories are skipped: their policies still work, but a cleanup
// PR could never land there. Forks are included, since their policies are as
// live as any other.
//
// The repositories come from the installation's REST listing, which only
// includes repositories the App was granted. The policy files and their last
// changes are read through GraphQL in batches, which costs far less of the
// installation's quota than a REST call per repository and per file.
func ListPolicies(ctx context.Context, client *github.Client, org, policyDir string) ([]Policy, error) {
	repos, err := listRepos(ctx, client, org)
	if err != nil {
		return nil, err
	}

	var policies []Policy
	for batch := range slices.Chunk(repos, batchSize) {
		files, err := policyFiles(ctx, client, org, policyDir, batch)
		if err != nil {
			return nil, err
		}
		changed, err := lastChanged(ctx, client, org, policyDir, batch, files)
		if err != nil {
			return nil, err
		}
		for i, repo := range batch {
			for j, name := range files[i] {
				identity, _ := strings.CutSuffix(name, policySuffix)
				policies = append(policies, Policy{Repo: repo, Identity: identity, LastChanged: changed[i][j]})
			}
		}
	}
	return policies, nil
}

// listRepos returns the names of the unarchived repositories in org that the
// installation can access.
func listRepos(ctx context.Context, client *github.Client, org string) ([]string, error) {
	var repos []string
	opts := &github.ListOptions{PerPage: 100}
	for {
		page, resp, err := client.Apps.ListRepos(ctx, opts)
		if err != nil {
			return nil, fmt.Errorf("cleanup: listing repositories: %w", err)
		}
		for _, r := range page.Repositories {
			if r.GetArchived() || !strings.EqualFold(r.GetOwner().GetLogin(), org) {
				continue
			}
			repos = append(repos, r.GetName())
		}
		if resp.NextPage == 0 {
			return repos, nil
		}
		opts.Page = resp.NextPage
	}
}

// policyFiles returns, for each repository in repos, the names of the policy
// files in policyDir on its default branch.
func policyFiles(ctx context.Context, client *github.Client, org, policyDir string, repos []string) ([][]string, error) {
	var q strings.Builder
	q.WriteString("query {\n")
	for i, repo := range repos {
		fmt.Fprintf(&q, "  r%d: repository(owner: %s, name: %s) { object(expression: %s) { ... on Tree { entries { name type } } } }\n",
			i, quote(org), quote(repo), quote("HEAD:"+policyDir))
	}
	q.WriteString("}")

	var data map[string]*struct {
		Object *struct {
			Entries []struct {
				Name string `json:"name"`
				Type string `json:"type"`
			} `json:"entries"`
		} `json:"object"`
	}
	if err := graphql(ctx, client, q.String(), &data); err != nil {
		return nil, fmt.Errorf("cleanup: listing %s in %s: %w", policyDir, org, err)
	}

	files := make([][]string, len(repos))
	for i := range repos {
		r := data[fmt.Sprintf("r%d", i)]
		if r == nil || r.Object == nil {
			continue // No such directory (or an empty repository).
		}
		for _, e := range r.Object.Entries {
			identity, ok := strings.CutSuffix(e.Name, policySuffix)
			if e.Type == "blob" && ok && identity != "" {
				files[i] = append(files[i], e.Name)
			}
		}
	}
	return files, nil
}

// lastChanged returns when each file in files was last changed on its
// repository's default branch. A file with no history gets the zero time.
//
// Path history leaves out merge commits, so a policy merged with a merge
// commit (rather than squashed) gets its branch commit's date. A policy that
// sat on a branch for longer than the window can then look old on the day it
// lands; the cleanup PR's reviewer is the backstop for that.
func lastChanged(ctx context.Context, client *github.Client, org, policyDir string, repos []string, files [][]string) ([][]time.Time, error) {
	changed := make([][]time.Time, len(repos))
	type ref struct{ repo, file int }
	var refs []ref
	for i := range repos {
		changed[i] = make([]time.Time, len(files[i]))
		for j := range files[i] {
			refs = append(refs, ref{i, j})
		}
	}

	// Each history lookup is its own field, so cap them per query rather
	// than per repository: a few repositories with many policies would
	// otherwise build one query large enough to time out on every run.
	for chunk := range slices.Chunk(refs, historyPerQuery) {
		var q strings.Builder
		q.WriteString("query {\n")
		for k, r := range chunk {
			if k == 0 || chunk[k-1].repo != r.repo {
				if k > 0 {
					q.WriteString("  } } } }\n")
				}
				fmt.Fprintf(&q, "  r%d: repository(owner: %s, name: %s) { defaultBranchRef { target { ... on Commit {\n", r.repo, quote(org), quote(repos[r.repo]))
			}
			fmt.Fprintf(&q, "    f%d: history(first: 1, path: %s) { nodes { committedDate } }\n", r.file, quote(path.Join(policyDir, files[r.repo][r.file])))
		}
		q.WriteString("  } } } }\n}")

		var data map[string]*struct {
			DefaultBranchRef *struct {
				Target map[string]struct {
					Nodes []struct {
						CommittedDate time.Time `json:"committedDate"`
					} `json:"nodes"`
				} `json:"target"`
			} `json:"defaultBranchRef"`
		}
		if err := graphql(ctx, client, q.String(), &data); err != nil {
			return nil, fmt.Errorf("cleanup: last changes in %s: %w", org, err)
		}
		for _, r := range chunk {
			d := data[fmt.Sprintf("r%d", r.repo)]
			if d == nil || d.DefaultBranchRef == nil {
				continue
			}
			if h := d.DefaultBranchRef.Target[fmt.Sprintf("f%d", r.file)]; len(h.Nodes) > 0 {
				changed[r.repo][r.file] = h.Nodes[0].CommittedDate
			}
		}
	}
	return changed, nil
}

// graphql runs query and decodes its data into out. A NOT_FOUND error, such as
// for a repository deleted since it was listed, leaves that field null and
// so yields no policies, which never removes anything. Any other error fails
// the query, so a partial answer is never mistaken for a complete one.
func graphql(ctx context.Context, client *github.Client, query string, out any) error {
	base, err := url.Parse(client.BaseURL())
	if err != nil {
		return err
	}
	req, err := client.NewRequest(ctx, http.MethodPost, graphqlURL(base), map[string]string{"query": query})
	if err != nil {
		return err
	}
	var resp struct {
		Data   json.RawMessage `json:"data"`
		Errors []struct {
			Type    string `json:"type"`
			Message string `json:"message"`
		} `json:"errors"`
	}
	if _, err := client.Do(req, &resp); err != nil {
		return err
	}
	for _, e := range resp.Errors {
		if e.Type != "NOT_FOUND" {
			return fmt.Errorf("graphql: %s", e.Message)
		}
	}
	return json.Unmarshal(resp.Data, out)
}

// graphqlURL returns the GraphQL endpoint for a REST base URL: "/graphql" at
// the API root on github.com, and "/api/graphql" next to GitHub Enterprise
// Server's "/api/v3/".
func graphqlURL(base *url.URL) string {
	u := *base
	if p, ok := strings.CutSuffix(u.Path, "/api/v3/"); ok {
		u.Path = p + "/api/graphql"
	} else {
		u.Path = strings.TrimSuffix(u.Path, "/") + "/graphql"
	}
	return u.String()
}

// quote returns s as a GraphQL string literal. GraphQL strings share JSON's
// escapes, so JSON encoding is a valid literal.
func quote(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}
