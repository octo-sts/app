// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package cleanup

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/go-github/v88/github"
)

const branch = "octo-sts/octo-sts-cleanup"

var since = time.Date(2026, 7, 23, 0, 0, 0, 0, time.UTC)

// pubRepo is one repository's git state.
type pubRepo struct {
	defaultBranch string
	files         []string
	// branches maps a branch name to its commit.
	branches map[string]string
}

// item is an open issue or pull request, as search returns it.
type item struct {
	repo   string
	number int
	title  string
	body   string
	pull   bool
	bot    bool
}

// fakeOrg is a GitHub organization that records every write.
type fakeOrg struct {
	t     *testing.T
	mu    sync.Mutex
	repos map[string]*pubRepo
	items []item
	// commits maps a commit to its tree; trees maps a tree to its files.
	commits map[string]string
	trees   map[string][]string
	// incomplete makes search report incomplete results.
	incomplete bool
	// fail makes requests whose "METHOD path" has this prefix fail.
	fail    string
	queries []string
	writes  []string
	next    int
}

func newFakeOrg(t *testing.T) *fakeOrg {
	return &fakeOrg{t: t, repos: map[string]*pubRepo{}, commits: map[string]string{}, trees: map[string][]string{}, next: 100}
}

// addRepo adds a repository whose default branch holds files.
func (f *fakeOrg) addRepo(name string, files ...string) {
	r := &pubRepo{defaultBranch: "main", files: files, branches: map[string]string{}}
	r.branches["main"] = f.commit(name, files)
	f.repos[name] = r
}

// commit records a commit holding files and returns its SHA.
func (f *fakeOrg) commit(repo string, files []string) string {
	tree := f.tree(files)
	sha := fmt.Sprintf("commit-%s-%d", repo, len(f.commits))
	f.commits[sha] = tree
	return sha
}

func (f *fakeOrg) tree(files []string) string {
	files = slices.Sorted(slices.Values(files))
	sha := "tree:" + strings.Join(files, ",")
	f.trees[sha] = files
	return sha
}

// filesOn returns the files on a branch, or nil if it does not exist.
func (f *fakeOrg) filesOn(repo, branch string) []string {
	sha, ok := f.repos[repo].branches[branch]
	if !ok {
		return nil
	}
	return f.trees[f.commits[sha]]
}

func (f *fakeOrg) client() *github.Client {
	srv := httptest.NewServer(http.HandlerFunc(f.serve))
	f.t.Cleanup(srv.Close)
	c, err := github.NewClient(github.WithHTTPClient(srv.Client()), github.WithEnterpriseURLs(srv.URL, srv.URL))
	if err != nil {
		f.t.Fatal(err)
	}
	return c
}

func (f *fakeOrg) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	t := f.t
	w.Header().Set("Content-Type", "application/json")
	route := r.Method + " " + strings.TrimPrefix(r.URL.Path, "/api/v3")
	if f.fail != "" && strings.HasPrefix(route, f.fail) {
		http.Error(w, `{"message":"boom"}`, http.StatusInternalServerError)
		return
	}
	var body map[string]any
	if r.Body != nil {
		_ = json.NewDecoder(r.Body).Decode(&body)
	}
	reply := func(v any) { _ = json.NewEncoder(w).Encode(v) }
	str := func(k string) string { s, _ := body[k].(string); return s }

	if route == "GET /search/issues" {
		q := r.URL.Query()
		if q.Get("advanced_search") != "true" {
			t.Errorf("search without advanced_search: %s", r.URL.RawQuery)
		}
		f.queries = append(f.queries, q.Get("q"))
		var all []map[string]any
		for _, it := range f.items {
			if strings.Contains(q.Get("q"), "is:pr") != it.pull {
				continue
			}
			typ := "User"
			if it.bot {
				typ = "Bot"
			}
			m := map[string]any{
				"number": it.number, "title": it.title, "body": it.body,
				"repository_url": "https://api.github.com/repos/acme/" + it.repo,
				"user":           map[string]any{"login": "someone", "type": typ},
			}
			if it.pull {
				m["pull_request"] = map[string]any{"url": "x"}
			}
			all = append(all, m)
		}
		// Two results per page, so paging is exercised.
		page := 1
		fmt.Sscan(q.Get("page"), &page)
		from, to := min((page-1)*2, len(all)), min(page*2, len(all))
		if to < len(all) {
			w.Header().Set("Link", fmt.Sprintf(`<%s?page=%d>; rel="next"`, r.URL.Path, page+1))
		}
		reply(map[string]any{"total_count": len(all), "incomplete_results": f.incomplete, "items": all[from:to]})
		return
	}

	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/v3/repos/acme/"), "/")
	repo, ok := f.repos[parts[0]]
	if !ok || !strings.HasPrefix(r.URL.Path, "/api/v3/repos/acme/") {
		t.Errorf("unexpected request %s", route)
		http.Error(w, `{"message":"Not Found"}`, http.StatusNotFound)
		return
	}
	name, rest := parts[0], strings.Join(parts[1:], "/")
	write := func(s string) { f.writes = append(f.writes, name+": "+s) }

	switch {
	case r.Method == http.MethodGet && rest == "":
		reply(map[string]any{"name": name, "default_branch": repo.defaultBranch})

	case r.Method == http.MethodGet && strings.HasPrefix(rest, "branches/"):
		sha := repo.branches[strings.TrimPrefix(rest, "branches/")]
		reply(map[string]any{"commit": map[string]any{"sha": sha, "commit": map[string]any{"tree": map[string]any{"sha": f.commits[sha]}}}})

	case r.Method == http.MethodPost && rest == "git/trees":
		files := f.trees[str("base_tree")]
		entries, _ := body["tree"].([]any)
		for _, e := range entries {
			e := e.(map[string]any)
			if sha, ok := e["sha"]; !ok || sha != nil {
				t.Errorf("tree entry %v does not delete its path", e)
			}
			p, _ := e["path"].(string)
			i := slices.Index(files, p)
			if i < 0 {
				http.Error(w, `{"message":"path not found"}`, http.StatusUnprocessableEntity)
				return
			}
			files = slices.Delete(slices.Clone(files), i, i+1)
		}
		reply(map[string]any{"sha": f.tree(files)})

	case r.Method == http.MethodGet && strings.HasPrefix(rest, "git/ref/heads/"):
		b := strings.TrimPrefix(rest, "git/ref/heads/")
		sha, ok := repo.branches[b]
		if !ok {
			http.Error(w, `{"message":"Not Found"}`, http.StatusNotFound)
			return
		}
		reply(map[string]any{"ref": "refs/heads/" + b, "object": map[string]any{"sha": sha}})

	case r.Method == http.MethodGet && strings.HasPrefix(rest, "git/commits/"):
		reply(map[string]any{"tree": map[string]any{"sha": f.commits[strings.TrimPrefix(rest, "git/commits/")]}})

	case r.Method == http.MethodPost && rest == "git/commits":
		parents, _ := body["parents"].([]any)
		if want := []any{repo.branches[repo.defaultBranch]}; !reflect.DeepEqual(parents, want) {
			t.Errorf("%s: commit parents = %v, want %v", name, parents, want)
		}
		if _, ok := body["author"]; ok {
			t.Errorf("%s: commit sets an author", name)
		}
		sha := fmt.Sprintf("commit-%s-%d", name, len(f.commits))
		f.commits[sha] = str("tree")
		write("commit " + str("message"))
		reply(map[string]any{"sha": sha})

	case r.Method == http.MethodPost && rest == "git/refs":
		b := strings.TrimPrefix(str("ref"), "refs/heads/")
		repo.branches[b] = str("sha")
		write("create ref " + b)
		reply(map[string]any{"ref": str("ref")})

	case r.Method == http.MethodPatch && strings.HasPrefix(rest, "git/refs/heads/"):
		b := strings.TrimPrefix(rest, "git/refs/heads/")
		if body["force"] != true {
			t.Errorf("%s: ref update is not forced", name)
		}
		repo.branches[b] = str("sha")
		write("force-push " + b)
		reply(map[string]any{"ref": "refs/heads/" + b})

	case r.Method == http.MethodPost && rest == "pulls":
		write(fmt.Sprintf("open pull %q %s->%s", str("title"), str("head"), str("base")))
		f.next++
		f.items = append(f.items, item{repo: name, number: f.next, title: str("title"), body: str("body"), pull: true, bot: true})
		reply(map[string]any{"number": f.next})

	case r.Method == http.MethodPost && rest == "issues":
		write(fmt.Sprintf("open issue %q", str("title")))
		f.next++
		f.items = append(f.items, item{repo: name, number: f.next, title: str("title"), body: str("body"), bot: true})
		reply(map[string]any{"number": f.next})

	case r.Method == http.MethodPost && strings.HasSuffix(rest, "/comments"):
		write("comment #" + strings.TrimSuffix(strings.TrimPrefix(rest, "issues/"), "/comments"))
		reply(map[string]any{})

	case r.Method == http.MethodPatch && strings.HasPrefix(rest, "issues/"):
		var n int
		fmt.Sscan(strings.TrimPrefix(rest, "issues/"), &n)
		i := slices.IndexFunc(f.items, func(it item) bool { return it.repo == name && it.number == n })
		if i < 0 {
			t.Errorf("%s: editing unknown #%d", name, n)
			http.Error(w, `{"message":"Not Found"}`, http.StatusNotFound)
			return
		}
		switch {
		case str("state") == "closed":
			write(fmt.Sprintf("close #%d %s", n, str("state_reason")))
			f.items = slices.Delete(f.items, i, i+1)
		case str("body") != "":
			write(fmt.Sprintf("edit #%d", n))
			f.items[i].body = str("body")
		}
		reply(map[string]any{"number": n})

	default:
		t.Errorf("unexpected request %s", route)
		http.Error(w, `{"message":"Not Found"}`, http.StatusNotFound)
	}
}

func publisher(c *github.Client) Publisher {
	return Publisher{Client: c, Org: "acme", PolicyDir: policyDir, Branch: branch}
}

func pol(repo, identity string) Policy {
	return Policy{Repo: repo, Identity: identity, LastChanged: changed}
}

func file(identity string) string { return policyDir + "/" + identity + ".sts.yaml" }

func TestPublishOpensPullRequest(t *testing.T) {
	f := newFakeOrg(t)
	f.addRepo("svc", "README.md", file("deploy"), file("release"), file("keep"))
	pub := publisher(f.client())
	plan := Plan{WindowStart: since, Repos: []RepoPlan{{Repo: "svc", Remove: []Policy{pol("svc", "deploy"), pol("svc", "release")}}}}

	if err := pub.Publish(t.Context(), plan); err != nil {
		t.Fatalf("Publish() = %v", err)
	}
	if got, want := f.filesOn("svc", branch), []string{file("keep"), "README.md"}; !reflect.DeepEqual(got, want) {
		t.Errorf("files on %s = %v, want %v", branch, got, want)
	}
	if got, want := f.filesOn("svc", "main"), []string{file("deploy"), file("keep"), file("release"), "README.md"}; !reflect.DeepEqual(got, want) {
		t.Errorf("files on main = %v, want %v", got, want)
	}
	wantWrites := []string{
		"svc: commit Remove unused Octo STS trust policies\n\nThese policies have had no token exchanges since 2026-07-23:\n\n- deploy\n- release\n",
		"svc: create ref " + branch,
		`svc: open pull "Remove unused Octo STS trust policies" ` + branch + "->main",
	}
	if !reflect.DeepEqual(f.writes, wantWrites) {
		t.Errorf("writes =\n%q\nwant\n%q", f.writes, wantWrites)
	}
	wantQueries := []string{
		"org:acme is:open is:pr head:" + branch,
		`org:acme is:open is:issue in:title "Octo STS trust policies that only fail"`,
	}
	if !reflect.DeepEqual(f.queries, wantQueries) {
		t.Errorf("search queries = %q, want %q", f.queries, wantQueries)
	}

	wantBody := "These trust policies have had no token exchanges since 2026-07-23, and none has changed since then:\n\n" +
		"- `.github/chainguard/deploy.sts.yaml`, last changed 2026-01-02\n" +
		"- `.github/chainguard/release.sts.yaml`, last changed 2026-01-02\n\n" +
		"Merging this pull request removes them. A policy drops out of it once it is used or changed. " +
		"Octo STS keeps this pull request up to date on the `octo-sts/octo-sts-cleanup` branch and closes it when nothing is left to remove.\n"
	if got := f.items[0].body; got != wantBody {
		t.Errorf("pull request body =\n%s\nwant\n%s", got, wantBody)
	}

	// The next run with the same plan changes nothing.
	f.writes = nil
	if err := pub.Publish(t.Context(), plan); err != nil {
		t.Fatalf("second Publish() = %v", err)
	}
	if len(f.writes) != 0 {
		t.Errorf("second run writes = %q, want none", f.writes)
	}
}

func TestPublishUpdatesPullRequest(t *testing.T) {
	f := newFakeOrg(t)
	f.addRepo("svc", file("deploy"), file("release"))
	pub := publisher(f.client())
	first := Plan{WindowStart: since, Repos: []RepoPlan{{Repo: "svc", Remove: []Policy{pol("svc", "deploy")}}}}
	if err := pub.Publish(t.Context(), first); err != nil {
		t.Fatalf("Publish() = %v", err)
	}

	// A month later release is unused too, and main has moved on.
	r := f.repos["svc"]
	r.files = append(r.files, "new.go")
	r.branches["main"] = f.commit("svc", r.files)
	f.writes = nil
	later := since.AddDate(0, 1, 0)
	second := Plan{WindowStart: later, Repos: []RepoPlan{{Repo: "svc", Remove: []Policy{pol("svc", "deploy"), pol("svc", "release")}}}}
	if err := pub.Publish(t.Context(), second); err != nil {
		t.Fatalf("second Publish() = %v", err)
	}
	if got, want := f.filesOn("svc", branch), []string{"new.go"}; !reflect.DeepEqual(got, want) {
		t.Errorf("files on %s = %v, want %v", branch, got, want)
	}
	if len(f.writes) != 3 || !strings.HasPrefix(f.writes[0], "svc: commit ") || f.writes[1] != "svc: force-push "+branch || f.writes[2] != "svc: edit #101" {
		t.Errorf("writes = %q, want a commit, a force-push and an edit of #101", f.writes)
	}
	if !strings.Contains(f.items[0].body, "release.sts.yaml") || !strings.Contains(f.items[0].body, "since 2026-08-23") {
		t.Errorf("pull request body was not updated:\n%s", f.items[0].body)
	}
}

func TestPublishReusesBranchWithoutPullRequest(t *testing.T) {
	// Someone closed last month's pull request; the branch still holds the
	// same proposal, so it is reopened without a new commit.
	f := newFakeOrg(t)
	f.addRepo("svc", file("deploy"))
	pub := publisher(f.client())
	plan := Plan{WindowStart: since, Repos: []RepoPlan{{Repo: "svc", Remove: []Policy{pol("svc", "deploy")}}}}
	if err := pub.Publish(t.Context(), plan); err != nil {
		t.Fatalf("Publish() = %v", err)
	}
	f.items, f.writes = nil, nil
	if err := pub.Publish(t.Context(), plan); err != nil {
		t.Fatalf("second Publish() = %v", err)
	}
	if want := []string{`svc: open pull "Remove unused Octo STS trust policies" ` + branch + "->main"}; !reflect.DeepEqual(f.writes, want) {
		t.Errorf("writes = %q, want %q", f.writes, want)
	}
}

func TestPublishClosesStale(t *testing.T) {
	f := newFakeOrg(t)
	f.addRepo("svc")
	f.addRepo("lib")
	f.items = []item{
		{repo: "svc", number: 7, title: PullTitle, pull: true, bot: true},
		{repo: "lib", number: 8, title: IssueTitle, bot: true},
	}
	if err := publisher(f.client()).Publish(t.Context(), Plan{WindowStart: since}); err != nil {
		t.Fatalf("Publish() = %v", err)
	}
	want := []string{"lib: comment #8", "lib: close #8 completed", "svc: comment #7", "svc: close #7 "}
	if !reflect.DeepEqual(f.writes, want) {
		t.Errorf("writes = %q, want %q", f.writes, want)
	}
}

func TestPublishReportsFailing(t *testing.T) {
	f := newFakeOrg(t)
	f.addRepo("svc")
	pub := publisher(f.client())
	plan := Plan{WindowStart: since, Repos: []RepoPlan{{Repo: "svc", Failing: []Failing{
		{Policy: pol("svc", "deploy"), LastFailed: time.Date(2026, 10, 20, 5, 0, 0, 0, time.UTC), LastError: "subject `x`\n@everyone [click](https://evil.example)"},
		{Policy: pol("svc", "release"), LastFailed: time.Date(2026, 10, 19, 0, 0, 0, 0, time.UTC)},
	}}}}
	if err := pub.Publish(t.Context(), plan); err != nil {
		t.Fatalf("Publish() = %v", err)
	}
	if want := []string{`svc: open issue "Octo STS trust policies that only fail"`}; !reflect.DeepEqual(f.writes, want) {
		t.Fatalf("writes = %q, want %q", f.writes, want)
	}
	wantBody := "These trust policies were used since 2026-07-23, but every token exchange for them since they last changed has failed:\n\n" +
		"- `.github/chainguard/deploy.sts.yaml`, last failed 2026-10-20: `subject 'x' @everyone [click](https://evil.example)`\n" +
		"- `.github/chainguard/release.sts.yaml`, last failed 2026-10-19: `no error recorded`\n\n" +
		"They are kept, since someone is trying to use them. Octo STS keeps this issue up to date and closes it once each one succeeds, changes, or is removed.\n"
	if got := f.items[0].body; got != wantBody {
		t.Errorf("issue body =\n%s\nwant\n%s", got, wantBody)
	}

	// Unchanged, the issue is left alone; changed, it is edited in place.
	f.writes = nil
	if err := pub.Publish(t.Context(), plan); err != nil {
		t.Fatalf("second Publish() = %v", err)
	}
	plan.Repos[0].Failing = plan.Repos[0].Failing[:1]
	if err := pub.Publish(t.Context(), plan); err != nil {
		t.Fatalf("third Publish() = %v", err)
	}
	if want := []string{"svc: edit #101"}; !reflect.DeepEqual(f.writes, want) {
		t.Errorf("writes = %q, want %q", f.writes, want)
	}
}

func TestPublishIgnoresOthers(t *testing.T) {
	// Issues opened by people, or with a merely similar title, are not ours.
	f := newFakeOrg(t)
	f.addRepo("svc")
	f.items = []item{
		{repo: "svc", number: 1, title: IssueTitle},
		{repo: "svc", number: 2, title: IssueTitle + " (copy)", bot: true},
		{repo: "svc", number: 3, title: PullTitle, pull: true},
	}
	plan := Plan{WindowStart: since, Repos: []RepoPlan{{Repo: "svc", Failing: []Failing{{Policy: pol("svc", "deploy"), LastFailed: since}}}}}
	if err := publisher(f.client()).Publish(t.Context(), plan); err != nil {
		t.Fatalf("Publish() = %v", err)
	}
	if want := []string{`svc: open issue "Octo STS trust policies that only fail"`}; !reflect.DeepEqual(f.writes, want) {
		t.Errorf("writes = %q, want %q", f.writes, want)
	}
}

func TestPublishPagesAndPrefersOldest(t *testing.T) {
	// Five bot issues across three search pages; the oldest in each
	// repository is the one kept up to date.
	f := newFakeOrg(t)
	for _, r := range []string{"a", "b", "c"} {
		f.addRepo(r)
	}
	f.items = []item{
		{repo: "a", number: 9, title: IssueTitle, bot: true},
		{repo: "a", number: 4, title: IssueTitle, bot: true},
		{repo: "b", number: 5, title: IssueTitle, bot: true},
		{repo: "c", number: 6, title: IssueTitle, bot: true},
		{repo: "a", number: 11, title: IssueTitle, bot: true},
	}
	failing := func(repo string) RepoPlan {
		return RepoPlan{Repo: repo, Failing: []Failing{{Policy: pol(repo, "p"), LastFailed: since}}}
	}
	plan := Plan{WindowStart: since, Repos: []RepoPlan{failing("a"), failing("b"), failing("c")}}
	if err := publisher(f.client()).Publish(t.Context(), plan); err != nil {
		t.Fatalf("Publish() = %v", err)
	}
	if want := []string{"a: edit #4", "b: edit #5", "c: edit #6"}; !reflect.DeepEqual(f.writes, want) {
		t.Errorf("writes = %q, want %q", f.writes, want)
	}
}

func TestPublishErrors(t *testing.T) {
	remove := Plan{WindowStart: since, Repos: []RepoPlan{{Repo: "svc", Remove: []Policy{pol("svc", "deploy")}}}}
	tests := []struct {
		name    string
		fail    string
		setup   func(*fakeOrg)
		plan    Plan
		wantErr string
	}{
		{name: "pull request search", fail: "GET /search/issues", plan: remove, wantErr: "searching"},
		{name: "incomplete search", setup: func(f *fakeOrg) { f.incomplete = true }, plan: remove, wantErr: "incomplete results"},
		{name: "repository", fail: "GET /repos/acme/svc", plan: remove, wantErr: "getting repository"},
		{name: "branch", fail: "GET /repos/acme/svc/branches", plan: remove, wantErr: "getting branch main"},
		{name: "tree", fail: "POST /repos/acme/svc/git/trees", plan: remove, wantErr: "building tree"},
		{name: "missing file", plan: Plan{WindowStart: since, Repos: []RepoPlan{{Repo: "svc", Remove: []Policy{pol("svc", "gone")}}}}, wantErr: "building tree"},
		{name: "ref", fail: "GET /repos/acme/svc/git/ref/", plan: remove, wantErr: "getting heads/" + branch},
		{name: "existing commit", fail: "GET /repos/acme/svc/git/commits/", setup: existingBranch, plan: remove, wantErr: "getting heads/" + branch},
		{name: "commit", fail: "POST /repos/acme/svc/git/commits", plan: remove, wantErr: "committing"},
		{name: "push new", fail: "POST /repos/acme/svc/git/refs", plan: remove, wantErr: "pushing"},
		{name: "push existing", fail: "PATCH /repos/acme/svc/git/refs/", setup: existingBranch, plan: remove, wantErr: "pushing"},
		{name: "open pull request", fail: "POST /repos/acme/svc/pulls", plan: remove, wantErr: "opening pull request"},
		{name: "open issue", fail: "POST /repos/acme/svc/issues", plan: Plan{WindowStart: since, Repos: []RepoPlan{{Repo: "svc", Failing: []Failing{{Policy: pol("svc", "deploy")}}}}}, wantErr: "opening issue"},
		{name: "update", fail: "PATCH /repos/acme/svc/issues/", setup: openIssue, plan: Plan{WindowStart: since, Repos: []RepoPlan{{Repo: "svc", Failing: []Failing{{Policy: pol("svc", "deploy")}}}}}, wantErr: "svc#3: updating"},
		{name: "comment", fail: "POST /repos/acme/svc/issues/3/comments", setup: openIssue, plan: Plan{WindowStart: since}, wantErr: "svc#3: commenting"},
		{name: "close", fail: "PATCH /repos/acme/svc/issues/3", setup: openIssue, plan: Plan{WindowStart: since}, wantErr: "svc#3: closing"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFakeOrg(t)
			f.addRepo("svc", file("deploy"))
			if tt.setup != nil {
				tt.setup(f)
			}
			f.fail = tt.fail
			err := publisher(f.client()).Publish(t.Context(), tt.plan)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Publish() = %v, want error containing %q", err, tt.wantErr)
			}
		})
	}
}

func existingBranch(f *fakeOrg) { f.repos["svc"].branches[branch] = f.repos["svc"].branches["main"] }

func openIssue(f *fakeOrg) {
	f.items = []item{{repo: "svc", number: 3, title: IssueTitle, body: "old", bot: true}}
}

func TestPublishContinuesPastFailures(t *testing.T) {
	// A repository that cannot be changed does not stop the others.
	f := newFakeOrg(t)
	f.addRepo("bad", file("x"))
	f.addRepo("good", file("y"))
	f.fail = "POST /repos/acme/bad/git/trees"
	plan := Plan{WindowStart: since, Repos: []RepoPlan{
		{Repo: "bad", Remove: []Policy{pol("bad", "x")}},
		{Repo: "good", Remove: []Policy{pol("good", "y")}},
	}}
	err := publisher(f.client()).Publish(t.Context(), plan)
	if err == nil || !strings.Contains(err.Error(), "acme/bad: building tree") {
		t.Fatalf("Publish() = %v, want the bad repository's error", err)
	}
	if _, ok := f.repos["good"].branches[branch]; !ok || len(f.items) != 1 || f.items[0].repo != "good" {
		t.Errorf("good repository was not proposed: writes %q", f.writes)
	}
}

func TestPublishRefusesUndecidedPlan(t *testing.T) {
	// A zero plan must not close the open pull request and issue.
	f := newFakeOrg(t)
	f.addRepo("svc")
	f.items = []item{{repo: "svc", number: 7, title: PullTitle, pull: true, bot: true}, {repo: "svc", number: 8, title: IssueTitle, bot: true}}
	if err := publisher(f.client()).Publish(t.Context(), Plan{}); err == nil || !strings.Contains(err.Error(), "no window start") {
		t.Fatalf("Publish(Plan{}) = %v, want an error about the window start", err)
	}
	if len(f.writes) != 0 || len(f.queries) != 0 {
		t.Errorf("Publish(Plan{}) made requests: writes %q, queries %q", f.writes, f.queries)
	}
}

func TestPublishNeedsSettings(t *testing.T) {
	client, err := github.NewClient()
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []Publisher{{}, {Client: client, Org: "acme", PolicyDir: policyDir}} {
		if err := p.Publish(t.Context(), Plan{WindowStart: since}); err == nil {
			t.Errorf("Publish() with %+v succeeded, want an error", p)
		}
	}
}

func TestCode(t *testing.T) {
	long := strings.Repeat("é", maxCodeLen+5)
	for in, want := range map[string]string{
		"plain":              "`plain`",
		"a `b` c":            "`a 'b' c`",
		"line\nbreak\r\n  x": "`line break x`",
		long:                 "`" + strings.Repeat("é", maxCodeLen) + "…`",
	} {
		if got := code(in); got != want {
			t.Errorf("code(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestRepoName(t *testing.T) {
	if got := repoName(&github.Issue{Repository: &github.Repository{Name: github.Ptr("svc")}}); got != "svc" {
		t.Errorf("repoName(repository) = %q, want svc", got)
	}
	if got := repoName(&github.Issue{RepositoryURL: github.Ptr("https://api.github.com/repos/acme/lib")}); got != "lib" {
		t.Errorf("repoName(url) = %q, want lib", got)
	}
}

func TestDay(t *testing.T) {
	if got := day(time.Time{}); got != "at an unknown time" {
		t.Errorf("day(zero) = %q", got)
	}
	if got := day(time.Date(2026, 1, 2, 23, 0, 0, 0, time.FixedZone("x", -5*3600))); got != "2026-01-03" {
		t.Errorf("day() = %q, want the UTC date 2026-01-03", got)
	}
}
