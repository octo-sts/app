// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package cleanup

import (
	"cmp"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/go-github/v88/github"
)

const policyDir = ".github/chainguard"

var changed = time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

type entry struct{ name, typ string }

// fakeRepo is one repository the installation can see.
type fakeRepo struct {
	owner, name    string
	archived, fork bool
	// noDir means the repository has no policy directory.
	noDir bool
	// gone means the repository is listed but deleted before it is queried.
	gone    bool
	entries []entry
	// dates maps a file name to its last change; files missing here have no
	// history.
	dates map[string]time.Time
	// branch is the default branch, "main" when empty.
	branch string
}

func defaultRepos() []fakeRepo {
	return []fakeRepo{{
		owner: "acme", name: "svc",
		entries: []entry{
			{"README.md", "blob"},
			{"deploy.sts.yaml", "blob"},
			{"nested.sts.yaml", "tree"},
			{"release.sts.yaml", "blob"},
			{".sts.yaml", "blob"},
		},
		dates: map[string]time.Time{"deploy.sts.yaml": changed, "release.sts.yaml": changed},
	}, {
		owner: "acme", name: "old", archived: true,
		entries: []entry{{"archived.sts.yaml", "blob"}},
	}, {
		owner: "other", name: "svc",
		entries: []entry{{"foreign.sts.yaml", "blob"}},
	}, {
		owner: "acme", name: "fork", fork: true, branch: "trunk",
		entries: []entry{{"upstream.sts.yaml", "blob"}},
		dates:   map[string]time.Time{"upstream.sts.yaml": changed},
	}, {
		owner: "acme", name: ".github",
		entries: []entry{{"octo-sts-cleanup.sts.yaml", "blob"}},
	}, {
		owner: "acme", name: "empty", noDir: true,
	}, {
		owner: "acme", name: "gone", gone: true,
	}}
}

var (
	treeAlias    = regexp.MustCompile(`(r\d+): repository\(owner: "([^"]+)", name: "([^"]+)"\) \{ object\(expression: "HEAD:([^"]+)"\)`)
	historyAlias = regexp.MustCompile(`(r\d+): repository\(owner: "([^"]+)", name: "([^"]+)"\) \{ defaultBranchRef`)
	fileAlias    = regexp.MustCompile(`(f\d+): history\(first: 1, path: "([^"]+)"\)`)
)

// fakeGitHub serves the installation's repositories over REST, 100 per page,
// and answers the GraphQL policy and history queries from repos. graphqlErr,
// when set, replaces every GraphQL response. It returns the client and a
// counter of GraphQL queries.
func fakeGitHub(t *testing.T, repos []fakeRepo, graphqlErr http.HandlerFunc, restErr bool) (*github.Client, *atomic.Int32) {
	t.Helper()
	byName := map[string]fakeRepo{}
	for _, r := range repos {
		byName[r.owner+"/"+r.name] = r
	}
	queries := &atomic.Int32{}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v3/installation/repositories":
			if restErr {
				http.Error(w, `{"message":"boom"}`, http.StatusInternalServerError)
				return
			}
			page := 1
			fmt.Sscan(r.URL.Query().Get("page"), &page)
			from, to := (page-1)*100, min(page*100, len(repos))
			if to < len(repos) {
				w.Header().Set("Link", fmt.Sprintf(`<%s?page=%d>; rel="next"`, r.URL.Path, page+1))
			}
			var out []string
			for _, fr := range repos[from:to] {
				out = append(out, fmt.Sprintf(`{"name":%q,"owner":{"login":%q},"archived":%t,"fork":%t}`, fr.name, fr.owner, fr.archived, fr.fork))
			}
			fmt.Fprintf(w, `{"total_count":%d,"repositories":[%s]}`, len(repos), strings.Join(out, ","))

		case "/api/graphql":
			queries.Add(1)
			if r.Method != http.MethodPost {
				t.Errorf("graphql method = %s, want POST", r.Method)
			}
			if graphqlErr != nil {
				graphqlErr(w, r)
				return
			}
			var req struct {
				Query string `json:"query"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Errorf("decoding graphql request: %v", err)
			}
			data, errs := answer(t, byName, req.Query)
			_ = json.NewEncoder(w).Encode(map[string]any{"data": data, "errors": errs})

		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			http.Error(w, `{"message":"Not Found"}`, http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)

	client, err := github.NewClient(github.WithHTTPClient(srv.Client()), github.WithEnterpriseURLs(srv.URL, srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	return client, queries
}

// answer builds the data for one GraphQL query, mirroring how GitHub resolves
// a missing repository, directory or file.
func answer(t *testing.T, repos map[string]fakeRepo, query string) (map[string]any, []map[string]any) {
	t.Helper()
	data := map[string]any{}
	var errs []map[string]any
	notFound := func(alias, repo string) {
		data[alias] = nil
		errs = append(errs, map[string]any{"type": "NOT_FOUND", "path": []string{alias}, "message": "Could not resolve to a Repository with the name '" + repo + "'."})
	}

	for _, m := range treeAlias.FindAllStringSubmatch(query, -1) {
		alias, full, dir := m[1], m[2]+"/"+m[3], m[4]
		if dir != policyDir {
			t.Errorf("tree expression for %s = HEAD:%s, want HEAD:%s", full, dir, policyDir)
		}
		r, ok := repos[full]
		switch {
		case !ok || r.gone:
			notFound(alias, full)
		case r.noDir:
			data[alias] = map[string]any{"object": nil}
		default:
			var entries []map[string]string
			for _, e := range r.entries {
				entries = append(entries, map[string]string{"name": e.name, "type": e.typ})
			}
			data[alias] = map[string]any{"object": map[string]any{"entries": entries}}
		}
	}

	if n := len(fileAlias.FindAllString(query, -1)); n > historyPerQuery {
		t.Errorf("query asks for %d history lookups, more than %d", n, historyPerQuery)
	}

	// Each repository block lists its files on the following lines.
	blocks := historyAlias.FindAllStringSubmatchIndex(query, -1)
	for i, b := range blocks {
		alias, full := query[b[2]:b[3]], query[b[4]:b[5]]+"/"+query[b[6]:b[7]]
		end := len(query)
		if i+1 < len(blocks) {
			end = blocks[i+1][0]
		}
		r, ok := repos[full]
		if !ok || r.gone {
			notFound(alias, full)
			continue
		}
		target := map[string]any{}
		for _, f := range fileAlias.FindAllStringSubmatch(query[b[1]:end], -1) {
			name, ok := strings.CutPrefix(f[2], policyDir+"/")
			if !ok {
				t.Errorf("history path %q is not under %s", f[2], policyDir)
			}
			nodes := []map[string]string{}
			if d, ok := r.dates[name]; ok {
				nodes = append(nodes, map[string]string{"committedDate": d.Format(time.RFC3339)})
			}
			target[f[1]] = map[string]any{"nodes": nodes}
		}
		branch := cmp.Or(r.branch, "main")
		data[alias] = map[string]any{"defaultBranchRef": map[string]any{"name": branch, "target": target}}
	}
	return data, errs
}

func TestListPolicies(t *testing.T) {
	client, queries := fakeGitHub(t, defaultRepos(), nil, false)
	got, err := ListPolicies(t.Context(), client, "acme", policyDir)
	if err != nil {
		t.Fatalf("ListPolicies() = %v", err)
	}
	want := []Policy{
		{Repo: "svc", Identity: "deploy", LastChanged: changed, DefaultBranch: "main"},
		{Repo: "svc", Identity: "release", LastChanged: changed, DefaultBranch: "main"},
		{Repo: "fork", Identity: "upstream", LastChanged: changed, DefaultBranch: "trunk"},
		{Repo: ".github", Identity: "octo-sts-cleanup", DefaultBranch: "main"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ListPolicies() =\n%+v\nwant\n%+v", got, want)
	}
	// One batch: one query for the directories and one for the history.
	if n := queries.Load(); n != 2 {
		t.Errorf("GraphQL queries = %d, want 2", n)
	}
}

func TestListPoliciesBatches(t *testing.T) {
	// 120 repositories make three batches; only the first two hold policies,
	// so the third needs no history query.
	repos := make([]fakeRepo, 0, 120)
	for i := range 120 {
		r := fakeRepo{owner: "acme", name: fmt.Sprintf("repo-%03d", i), noDir: true}
		if i < 2*batchSize {
			r = fakeRepo{owner: "acme", name: r.name, entries: []entry{{"p.sts.yaml", "blob"}}, dates: map[string]time.Time{"p.sts.yaml": changed}}
		}
		repos = append(repos, r)
	}
	client, queries := fakeGitHub(t, repos, nil, false)
	got, err := ListPolicies(t.Context(), client, "acme", policyDir)
	if err != nil {
		t.Fatalf("ListPolicies() = %v", err)
	}
	if len(got) != 2*batchSize {
		t.Fatalf("ListPolicies() returned %d policies, want %d", len(got), 2*batchSize)
	}
	for i, p := range got {
		if want := fmt.Sprintf("repo-%03d", i); p.Repo != want || p.Identity != "p" || !p.LastChanged.Equal(changed) || p.DefaultBranch != "main" {
			t.Fatalf("policy %d = %+v, want %s/p changed %v", i, p, want, changed)
		}
	}
	if n := queries.Load(); n != 5 {
		t.Errorf("GraphQL queries = %d, want 5 (three directory queries, two history queries)", n)
	}
}

func TestListPoliciesManyPolicies(t *testing.T) {
	// 280 policies in two repositories need three history queries, and the
	// first repository's policies span two of them.
	repos := []fakeRepo{{owner: "acme", name: ".github", dates: map[string]time.Time{}}, {owner: "acme", name: "svc", dates: map[string]time.Time{}}}
	for i, n := range []int{250, 30} {
		for j := range n {
			name := fmt.Sprintf("p%03d.sts.yaml", j)
			repos[i].entries = append(repos[i].entries, entry{name, "blob"})
			repos[i].dates[name] = changed.Add(time.Duration(i*1000+j) * time.Minute)
		}
	}
	client, queries := fakeGitHub(t, repos, nil, false)
	got, err := ListPolicies(t.Context(), client, "acme", policyDir)
	if err != nil {
		t.Fatalf("ListPolicies() = %v", err)
	}
	if len(got) != 280 {
		t.Fatalf("ListPolicies() returned %d policies, want 280", len(got))
	}
	for k, p := range got {
		i, j := 0, k
		if k >= 250 {
			i, j = 1, k-250
		}
		want := Policy{Repo: repos[i].name, Identity: fmt.Sprintf("p%03d", j), LastChanged: changed.Add(time.Duration(i*1000+j) * time.Minute), DefaultBranch: "main"}
		if p != want {
			t.Fatalf("policy %d = %+v, want %+v", k, p, want)
		}
	}
	if n := queries.Load(); n != 4 {
		t.Errorf("GraphQL queries = %d, want 4 (one directory query, three history queries)", n)
	}
}

func TestListPoliciesErrors(t *testing.T) {
	tests := []struct {
		name       string
		graphqlErr http.HandlerFunc
		restErr    bool
		wantErr    string
	}{{
		name:    "repository listing fails",
		restErr: true,
		wantErr: "listing repositories",
	}, {
		name: "graphql request fails",
		graphqlErr: func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, `{"message":"boom"}`, http.StatusBadGateway)
		},
		wantErr: "listing .github/chainguard in acme",
	}, {
		name: "graphql returns an error other than NOT_FOUND",
		graphqlErr: func(w http.ResponseWriter, _ *http.Request) {
			fmt.Fprint(w, `{"data":null,"errors":[{"type":"RATE_LIMITED","message":"API rate limit exceeded"}]}`)
		},
		wantErr: "API rate limit exceeded",
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, _ := fakeGitHub(t, defaultRepos(), tt.graphqlErr, tt.restErr)
			_, err := ListPolicies(t.Context(), client, "acme", policyDir)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("ListPolicies() = %v, want error containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestListPoliciesHistoryError(t *testing.T) {
	// The directory query succeeds and the history query fails.
	var calls atomic.Int32
	byName := map[string]fakeRepo{}
	for _, r := range defaultRepos() {
		byName[r.owner+"/"+r.name] = r
	}
	client, _ := fakeGitHub(t, defaultRepos(), func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			var req struct {
				Query string `json:"query"`
			}
			_ = json.NewDecoder(r.Body).Decode(&req)
			data, errs := answer(t, byName, req.Query)
			_ = json.NewEncoder(w).Encode(map[string]any{"data": data, "errors": errs})
			return
		}
		fmt.Fprint(w, `{"data":null,"errors":[{"type":"INTERNAL","message":"something went wrong"}]}`)
	}, false)
	_, err := ListPolicies(t.Context(), client, "acme", policyDir)
	if err == nil || !strings.Contains(err.Error(), "last changes in acme") {
		t.Fatalf("ListPolicies() = %v, want error containing %q", err, "last changes in acme")
	}
}

func TestGraphqlURL(t *testing.T) {
	for base, want := range map[string]string{
		"https://api.github.com/":            "https://api.github.com/graphql",
		"https://ghes.example.com/api/v3/":   "https://ghes.example.com/api/graphql",
		"https://ghes.example.com/x/api/v3/": "https://ghes.example.com/x/api/graphql",
	} {
		u, err := url.Parse(base)
		if err != nil {
			t.Fatal(err)
		}
		if got := graphqlURL(u); got != want {
			t.Errorf("graphqlURL(%s) = %s, want %s", base, got, want)
		}
	}
}

func TestQuote(t *testing.T) {
	for in, want := range map[string]string{
		"svc":            `"svc"`,
		`we"ird\name`:    `"we\"ird\\name"`,
		"line\nbreak":    `"line\nbreak"`,
		"HEAD:.github/x": `"HEAD:.github/x"`,
	} {
		if got := quote(in); got != want {
			t.Errorf("quote(%q) = %s, want %s", in, got, want)
		}
	}
}
