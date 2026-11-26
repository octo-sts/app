// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package cleanup

import (
	"context"
	"encoding/json"
	"errors"
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

	// Limits apply across all repository batches in one ListPolicies call.
	// Count paths, not distinct tree objects: Git trees can be shared.
	maxPolicyDirectories = 4096 // Includes each queried policy root.
	maxPolicyDepth       = 32   // Root is depth zero.
	maxPolicyEntries     = 100000
	maxPolicyFiles       = 10000
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
	budget := newTraversalBudget()
	for batch := range slices.Chunk(repos, batchSize) {
		snapshots, err := policySnapshots(ctx, client, org, policyDir, batch)
		if err != nil {
			return nil, err
		}
		files, err := policyFiles(ctx, client, org, policyDir, batch, snapshots, &budget)
		if err != nil {
			return nil, err
		}
		changed, err := lastChanged(ctx, client, org, policyDir, batch, files, snapshots)
		if err != nil {
			return nil, err
		}
		for i, repo := range batch {
			for j, name := range files[i] {
				identity, _ := strings.CutSuffix(name, policySuffix)
				policies = append(policies, Policy{Repo: repo, Identity: identity, LastChanged: changed[i][j], DefaultBranch: snapshots[i].branch, SnapshotSHA: snapshots[i].oid})
			}
		}
	}
	return policies, nil
}

type policySnapshot struct {
	branch string
	oid    string
}

// policySnapshots resolves each default branch once, before reading any trees.
func policySnapshots(ctx context.Context, client *github.Client, org, policyDir string, repos []string) ([]policySnapshot, error) {
	var q strings.Builder
	q.WriteString("query {\n")
	for i, repo := range repos {
		fmt.Fprintf(&q, "  r%d: repository(owner: %s, name: %s) { defaultBranchRef { name target { __typename oid } } }\n", i, quote(org), quote(repo))
	}
	q.WriteString("}")
	var data map[string]json.RawMessage
	notFound, err := graphqlNotFound(ctx, client, q.String(), &data)
	if err != nil {
		return nil, fmt.Errorf("cleanup: listing %s in %s: %w", policyDir, org, err)
	}
	snapshots := make([]policySnapshot, len(repos))
	for i, repo := range repos {
		raw, ok := data[fmt.Sprintf("r%d", i)]
		if !ok {
			return nil, fmt.Errorf("cleanup: missing snapshot response for %s/%s", org, repo)
		}
		if string(raw) == "null" {
			if notFound[fmt.Sprintf("r%d", i)] {
				continue // Repository deleted after the installation listing.
			}
			return nil, fmt.Errorf("cleanup: malformed snapshot for %s/%s", org, repo)
		}
		var r struct {
			DefaultBranchRef json.RawMessage `json:"defaultBranchRef"`
		}
		if err := json.Unmarshal(raw, &r); err != nil || len(r.DefaultBranchRef) == 0 {
			return nil, fmt.Errorf("cleanup: malformed snapshot for %s/%s", org, repo)
		}
		if string(r.DefaultBranchRef) == "null" {
			continue // Empty repository.
		}
		var ref struct {
			Name   string `json:"name"`
			Target *struct {
				Type string `json:"__typename"`
				OID  string `json:"oid"`
			} `json:"target"`
		}
		if err := json.Unmarshal(r.DefaultBranchRef, &ref); err != nil || ref.Name == "" || ref.Target == nil || ref.Target.Type != "Commit" || !validOID(ref.Target.OID) {
			return nil, fmt.Errorf("cleanup: malformed snapshot for %s/%s", org, repo)
		}
		snapshots[i] = policySnapshot{branch: ref.Name, oid: ref.Target.OID}
	}
	return snapshots, nil
}

func validOID(oid string) bool {
	if len(oid) != 40 && len(oid) != 64 {
		return false
	}
	for _, c := range oid {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
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

type traversalBudget struct {
	directories, entries, files                    int
	maxDirectories, maxDepth, maxEntries, maxFiles int
}

func newTraversalBudget() traversalBudget {
	return traversalBudget{maxDirectories: maxPolicyDirectories, maxDepth: maxPolicyDepth, maxEntries: maxPolicyEntries, maxFiles: maxPolicyFiles}
}

// policyFiles returns policy paths relative to policyDir, recursively, for
// each repository in repos on its default branch.
func policyFiles(ctx context.Context, client *github.Client, org, policyDir string, repos []string, snapshots []policySnapshot, budget *traversalBudget) ([][]string, error) {
	type directory struct {
		repo  int
		path  string // relative to policyDir
		depth int
	}
	files := make([][]string, len(repos))
	var pending []directory
	enqueue := func(dir directory) error {
		if dir.depth > budget.maxDepth {
			return fmt.Errorf("cleanup: policy directory depth exceeds %d at %s/%s:%s", budget.maxDepth, org, repos[dir.repo], path.Join(policyDir, dir.path))
		}
		if budget.directories >= budget.maxDirectories {
			return fmt.Errorf("cleanup: policy directory limit %d exceeded", budget.maxDirectories)
		}
		budget.directories++
		pending = append(pending, dir)
		return nil
	}
	for i := range repos {
		if snapshots[i].oid != "" {
			if err := enqueue(directory{repo: i}); err != nil {
				return nil, err
			}
		}
	}
	for len(pending) > 0 {
		n := min(len(pending), batchSize)
		batch := pending[:n]
		pending = pending[n:]
		var q strings.Builder
		q.WriteString("query {\n")
		for i, dir := range batch {
			expression := snapshots[dir.repo].oid + ":" + policyDir
			if dir.path != "" {
				expression = snapshots[dir.repo].oid + ":" + path.Join(policyDir, dir.path)
			}
			fmt.Fprintf(&q, "  r%d: repository(owner: %s, name: %s) { object(expression: %s) { __typename ... on Tree { entries { name type mode } } } }\n",
				i, quote(org), quote(repos[dir.repo]), quote(expression))
		}
		q.WriteString("}")

		var data map[string]json.RawMessage
		if err := graphql(ctx, client, q.String(), &data); err != nil {
			return nil, fmt.Errorf("cleanup: listing %s in %s: %w", policyDir, org, err)
		}
		for i, dir := range batch {
			raw, ok := data[fmt.Sprintf("r%d", i)]
			location := org + "/" + repos[dir.repo] + ":" + path.Join(policyDir, dir.path)
			if !ok || string(raw) == "null" {
				return nil, fmt.Errorf("cleanup: missing directory response for %s", location)
			}
			var r struct {
				Object json.RawMessage `json:"object"`
			}
			if err := json.Unmarshal(raw, &r); err != nil || len(r.Object) == 0 {
				return nil, fmt.Errorf("cleanup: malformed directory response for %s", location)
			}
			if string(r.Object) == "null" {
				if dir.path == "" {
					continue // The policy root does not exist.
				}
				return nil, fmt.Errorf("cleanup: missing nested directory %s", location)
			}
			var tree struct {
				Type    string `json:"__typename"`
				Entries []struct {
					Name string `json:"name"`
					Type string `json:"type"`
					Mode *int   `json:"mode"`
				} `json:"entries"`
			}
			if err := json.Unmarshal(r.Object, &tree); err != nil || tree.Type != "Tree" || tree.Entries == nil {
				return nil, fmt.Errorf("cleanup: malformed directory response for %s", location)
			}
			if len(tree.Entries) > budget.maxEntries-budget.entries {
				return nil, fmt.Errorf("cleanup: policy directory entry limit %d exceeded at %s", budget.maxEntries, location)
			}
			budget.entries += len(tree.Entries)
			seen := map[string]bool{}
			for _, e := range tree.Entries {
				if e.Name == "" || e.Name == "." || e.Name == ".." || strings.ContainsAny(e.Name, "/\x00") || seen[e.Name] || (e.Type != "tree" && e.Type != "blob" && e.Type != "commit") {
					return nil, fmt.Errorf("cleanup: invalid directory entry %q in %s", e.Name, location)
				}
				if e.Mode == nil || !validEntryMode(e.Type, *e.Mode) {
					return nil, fmt.Errorf("cleanup: invalid mode for directory entry %q in %s", e.Name, location)
				}
				seen[e.Name] = true
				name := path.Join(dir.path, e.Name)
				identity, ok := strings.CutSuffix(e.Name, policySuffix)
				switch {
				case e.Type == "tree":
					if err := enqueue(directory{repo: dir.repo, path: name, depth: dir.depth + 1}); err != nil {
						return nil, err
					}
				case e.Type == "blob" && *e.Mode != 0120000 && ok && identity != "":
					if budget.files >= budget.maxFiles {
						return nil, fmt.Errorf("cleanup: policy file limit %d exceeded at %s", budget.maxFiles, location)
					}
					budget.files++
					files[dir.repo] = append(files[dir.repo], name)
				}
			}
		}
	}
	return files, nil
}

// GraphQL returns Git modes as decimal integers, not octal strings.
func validEntryMode(typ string, mode int) bool {
	switch typ {
	case "tree":
		return mode == 0040000
	case "blob":
		return mode == 0100644 || mode == 0100755 || mode == 0120000
	case "commit":
		return mode == 0160000
	default:
		return false
	}
}

// lastChanged returns when each file in files was last changed on its
// repository's captured commit. A file with no history gets the zero time.
//
// Path history leaves out merge commits, so a policy merged with a merge
// commit (rather than squashed) gets its branch commit's date. A policy that
// sat on a branch for longer than the window can then look old on the day it
// lands; the cleanup PR's reviewer is the backstop for that.
func lastChanged(ctx context.Context, client *github.Client, org, policyDir string, repos []string, files [][]string, snapshots []policySnapshot) ([][]time.Time, error) {
	changed := make([][]time.Time, len(repos))
	var refs []historyRef
	for i := range repos {
		changed[i] = make([]time.Time, len(files[i]))
		for j := range files[i] {
			refs = append(refs, historyRef{i, j})
		}
	}

	// Each history lookup is its own field, so cap them per query rather
	// than per repository: a few repositories with many policies would
	// otherwise build one query large enough to time out on every run.
	for chunk := range slices.Chunk(refs, historyPerQuery) {
		if err := history(ctx, client, org, policyDir, repos, files, snapshots, chunk, changed); err != nil {
			return nil, fmt.Errorf("cleanup: last changes in %s: %w", org, err)
		}
	}
	return changed, nil
}

// historyRef names one policy file: files[repo][file].
type historyRef struct{ repo, file int }

// history looks up the last change of each file in chunk with one query and
// records it in changed. Path history is slow in large repositories, and GitHub answers a
// query that runs too long with a gateway error, so on one of those the
// chunk is split in half and each half retried. A single lookup that still
// times out fails, so no file is ever left looking unchanged.
func history(ctx context.Context, client *github.Client, org, policyDir string, repos []string, files [][]string, snapshots []policySnapshot, chunk []historyRef, changed [][]time.Time) error {
	var q strings.Builder
	q.WriteString("query {\n")
	for k, r := range chunk {
		if k == 0 || chunk[k-1].repo != r.repo {
			if k > 0 {
				q.WriteString("  } } }\n")
			}
			fmt.Fprintf(&q, "  r%d: repository(owner: %s, name: %s) { object(expression: %s) { __typename ... on Commit {\n", r.repo, quote(org), quote(repos[r.repo]), quote(snapshots[r.repo].oid))
		}
		fmt.Fprintf(&q, "    f%d: history(first: 1, path: %s) { nodes { committedDate } }\n", r.file, quote(path.Join(policyDir, files[r.repo][r.file])))
	}
	q.WriteString("  } } }\n}")

	var data map[string]json.RawMessage
	if err := graphql(ctx, client, q.String(), &data); err != nil {
		if len(chunk) > 1 && timedOut(err) {
			half := len(chunk) / 2
			if err := history(ctx, client, org, policyDir, repos, files, snapshots, chunk[:half], changed); err != nil {
				return err
			}
			return history(ctx, client, org, policyDir, repos, files, snapshots, chunk[half:], changed)
		}
		return err
	}
	for _, r := range chunk {
		raw, ok := data[fmt.Sprintf("r%d", r.repo)]
		if !ok || string(raw) == "null" {
			return fmt.Errorf("missing history response for %s/%s", org, repos[r.repo])
		}
		var d struct {
			Object map[string]json.RawMessage `json:"object"`
		}
		if err := json.Unmarshal(raw, &d); err != nil || d.Object == nil || string(d.Object["__typename"]) != `"Commit"` {
			return fmt.Errorf("malformed history response for %s/%s", org, repos[r.repo])
		}
		var h struct {
			Nodes []struct {
				CommittedDate time.Time `json:"committedDate"`
			} `json:"nodes"`
		}
		field, ok := d.Object[fmt.Sprintf("f%d", r.file)]
		if !ok || json.Unmarshal(field, &h) != nil || h.Nodes == nil || len(h.Nodes) > 1 || len(h.Nodes) == 1 && h.Nodes[0].CommittedDate.IsZero() {
			return fmt.Errorf("malformed history for %s/%s:%s", org, repos[r.repo], path.Join(policyDir, files[r.repo][r.file]))
		}
		if len(h.Nodes) > 0 {
			changed[r.repo][r.file] = h.Nodes[0].CommittedDate
		}
	}
	return nil
}

// timedOut reports whether err is a gateway error, which is how GitHub
// answers a GraphQL query that ran past its time limit.
func timedOut(err error) bool {
	var e *github.ErrorResponse
	if !errors.As(err, &e) || e.Response == nil {
		return false
	}
	switch e.Response.StatusCode {
	case http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return true
	}
	return false
}

// graphql runs query and decodes its data into out. A NOT_FOUND error, such as
// for a repository deleted since it was listed, leaves that field null and
// so yields no policies, which never removes anything. Any other error fails
// the query, so a partial answer is never mistaken for a complete one.
func graphql(ctx context.Context, client *github.Client, query string, out any) error {
	_, err := graphqlNotFound(ctx, client, query, out)
	return err
}

// graphqlNotFound also records aliases with NOT_FOUND errors, so a missing
// repository can be distinguished from an unexplained null response.
func graphqlNotFound(ctx context.Context, client *github.Client, query string, out any) (map[string]bool, error) {
	base, err := url.Parse(client.BaseURL())
	if err != nil {
		return nil, err
	}
	req, err := client.NewRequest(ctx, http.MethodPost, graphqlURL(base), map[string]string{"query": query})
	if err != nil {
		return nil, err
	}
	var resp struct {
		Data   json.RawMessage `json:"data"`
		Errors []struct {
			Type    string `json:"type"`
			Message string `json:"message"`
			Path    []any  `json:"path"`
		} `json:"errors"`
	}
	if _, err := client.Do(req, &resp); err != nil {
		return nil, err
	}
	notFound := map[string]bool{}
	for _, e := range resp.Errors {
		if e.Type != "NOT_FOUND" {
			return nil, fmt.Errorf("graphql: %s", e.Message)
		}
		if len(e.Path) == 1 {
			if alias, ok := e.Path[0].(string); ok {
				notFound[alias] = true
			}
		}
	}
	return notFound, json.Unmarshal(resp.Data, out)
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
