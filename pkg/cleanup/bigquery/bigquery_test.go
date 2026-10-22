// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package bigquery

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"cloud.google.com/go/bigquery"
	"google.golang.org/api/option"

	"github.com/octo-sts/app/pkg/cleanup"
)

func TestNew(t *testing.T) {
	for _, table := range []string{
		"octo-sts.cloudevents_octo_sts_recorder.dev_octo-sts_exchange",
		"p.d.t",
	} {
		if _, err := New(nil, table); err != nil {
			t.Errorf("New(%q) = %v, want nil", table, err)
		}
	}
	for _, table := range []string{
		"",
		"dataset.table",
		"p.d.t.extra",
		"p.d.t`; DROP TABLE x; --",
		"p.d-ash.t",
	} {
		if _, err := New(nil, table); err == nil {
			t.Errorf("New(%q) = nil, want an error", table)
		}
	}
}

func TestUsageRow(t *testing.T) {
	ok := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	bad := time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC)
	tests := []struct {
		name    string
		row     usageRow
		wantOrg string
		want    cleanup.Usage
	}{{
		name: "repository scope with both outcomes",
		row: usageRow{
			Scope:         "Acme/Svc",
			Identity:      bigquery.NullString{StringVal: "deploy", Valid: true},
			LastSucceeded: bigquery.NullTimestamp{Timestamp: ok, Valid: true},
			LastFailed:    bigquery.NullTimestamp{Timestamp: bad, Valid: true},
			LastError:     bigquery.NullString{StringVal: "denied", Valid: true},
		},
		wantOrg: "acme",
		want:    cleanup.Usage{Scope: "Acme/Svc", Identity: "deploy", LastSucceeded: ok, LastFailed: bad, LastError: "denied"},
	}, {
		name: "org scope that only succeeded",
		row: usageRow{
			Scope:         "acme",
			Identity:      bigquery.NullString{StringVal: "release", Valid: true},
			LastSucceeded: bigquery.NullTimestamp{Timestamp: ok, Valid: true},
		},
		wantOrg: "acme",
		want:    cleanup.Usage{Scope: "acme", Identity: "release", LastSucceeded: ok},
	}, {
		name:    "missing identity",
		row:     usageRow{Scope: "acme/svc", LastFailed: bigquery.NullTimestamp{Timestamp: bad, Valid: true}},
		wantOrg: "acme",
		want:    cleanup.Usage{Scope: "acme/svc", LastFailed: bad},
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			org, got := tt.row.usage()
			if org != tt.wantOrg {
				t.Errorf("org = %q, want %q", org, tt.wantOrg)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("usage = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestHistoryOrgs(t *testing.T) {
	h := History{Usage: map[string][]cleanup.Usage{"acme": nil, "globex": nil}}
	got := h.Orgs()
	slices.Sort(got)
	if want := []string{"acme", "globex"}; !reflect.DeepEqual(got, want) {
		t.Errorf("Orgs() = %v, want %v", got, want)
	}
}

func TestQueries(t *testing.T) {
	// Both queries must be parameterized and bound the partitions they scan.
	const table = "p.d.t"
	for name, q := range map[string]string{"usage": usageQuery, "history start": historyStartQuery} {
		sql := fmt.Sprintf(q, table)
		for _, want := range []string{"`p.d.t`", "@since", "_PARTITIONTIME"} {
			if !strings.Contains(sql, want) {
				t.Errorf("%s query does not contain %q:\n%s", name, want, sql)
			}
		}
	}
}

// fakeBigQuery answers jobs.query requests. Each response is chosen by
// whether the SQL is the history start query.
func fakeBigQuery(t *testing.T, since time.Time, usage, history func(w http.ResponseWriter)) *Source {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || !strings.HasSuffix(r.URL.Path, "/projects/p/queries") {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			http.Error(w, "unexpected", http.StatusNotFound)
			return
		}
		var req struct {
			Query           string `json:"query"`
			QueryParameters []struct {
				Name           string `json:"name"`
				ParameterValue struct {
					Value string `json:"value"`
				} `json:"parameterValue"`
			} `json:"queryParameters"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("decoding request: %v", err)
		}
		if len(req.QueryParameters) != 1 || req.QueryParameters[0].Name != "since" {
			t.Errorf("query parameters = %+v, want only since", req.QueryParameters)
		} else if got, err := time.Parse("2006-01-02 15:04:05.999999-07:00", req.QueryParameters[0].ParameterValue.Value); err != nil || !got.Equal(since) {
			t.Errorf("since = %q, want %v", req.QueryParameters[0].ParameterValue.Value, since)
		}
		if !strings.Contains(req.Query, "`p.d.t`") {
			t.Errorf("query does not read p.d.t:\n%s", req.Query)
		}
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(req.Query, "MIN(time)") {
			history(w)
		} else {
			usage(w)
		}
	}))
	t.Cleanup(srv.Close)

	client, err := bigquery.NewClient(t.Context(), "p",
		option.WithEndpoint(srv.URL+"/"), option.WithHTTPClient(srv.Client()), option.WithoutAuthentication())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })
	s, err := New(client, "p.d.t")
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// rows writes a completed jobs.query response. Values are strings, and
// timestamps are microseconds since the epoch, as the client requests.
func rows(w http.ResponseWriter, fields []string, values ...[]any) {
	type cell struct {
		V any `json:"v"`
	}
	schema := make([]map[string]string, 0, len(fields))
	for _, f := range fields {
		typ := "STRING"
		if strings.HasPrefix(f, "last_") && f != "last_error" || f == "oldest" {
			typ = "TIMESTAMP"
		}
		schema = append(schema, map[string]string{"name": f, "type": typ})
	}
	out := make([]map[string][]cell, 0, len(values))
	for _, v := range values {
		cells := make([]cell, 0, len(v))
		for _, x := range v {
			if t, ok := x.(time.Time); ok {
				x = strconv.FormatInt(t.UnixMicro(), 10)
			}
			cells = append(cells, cell{V: x})
		}
		out = append(out, map[string][]cell{"f": cells})
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"kind":         "bigquery#queryResponse",
		"jobComplete":  true,
		"jobReference": map[string]string{"projectId": "p", "jobId": "j"},
		"schema":       map[string]any{"fields": schema},
		"rows":         out,
		"totalRows":    strconv.Itoa(len(out)),
	})
}

var usageFields = []string{"scope", "identity", "last_succeeded", "last_failed", "last_error"}

func TestLoad(t *testing.T) {
	since := time.Date(2026, 7, 24, 0, 0, 0, 0, time.UTC)
	ok := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	bad := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	oldest := time.Date(2026, 7, 23, 23, 55, 22, 0, time.UTC)

	s := fakeBigQuery(t, since,
		func(w http.ResponseWriter) {
			rows(w, usageFields,
				[]any{"Acme/svc", "deploy", ok, nil, nil},
				[]any{"acme", "release", nil, bad, "denied"},
				[]any{"globex/web", nil, ok, nil, nil},
			)
		},
		func(w http.ResponseWriter) { rows(w, []string{"oldest"}, []any{oldest}) },
	)
	got, err := s.Load(t.Context(), since)
	if err != nil {
		t.Fatalf("Load() = %v", err)
	}
	want := History{
		Start: oldest,
		Usage: map[string][]cleanup.Usage{
			"acme": {
				{Scope: "Acme/svc", Identity: "deploy", LastSucceeded: ok},
				{Scope: "acme", Identity: "release", LastFailed: bad, LastError: "denied"},
			},
			"globex": {{Scope: "globex/web", LastSucceeded: ok}},
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Load() =\n%+v\nwant\n%+v", got, want)
	}
}

func TestLoadNoHistory(t *testing.T) {
	since := time.Date(2026, 7, 24, 0, 0, 0, 0, time.UTC)
	s := fakeBigQuery(t, since,
		func(w http.ResponseWriter) { rows(w, usageFields) },
		func(w http.ResponseWriter) { rows(w, []string{"oldest"}, []any{nil}) },
	)
	got, err := s.Load(t.Context(), since)
	if err != nil {
		t.Fatalf("Load() = %v", err)
	}
	if !got.Start.IsZero() || len(got.Usage) != 0 {
		t.Errorf("Load() = %+v, want no start and no usage", got)
	}
}

func TestLoadErrors(t *testing.T) {
	since := time.Date(2026, 7, 24, 0, 0, 0, 0, time.UTC)
	// A 400 is not retried by the client, so the error surfaces at once.
	fail := func(w http.ResponseWriter) {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, `{"error":{"code":400,"message":"bad query","errors":[{"reason":"invalidQuery"}]}}`)
	}
	empty := func(w http.ResponseWriter) { rows(w, []string{"oldest"}, []any{nil}) }
	for name, tc := range map[string]struct {
		usage, history func(http.ResponseWriter)
		wantErr        string
	}{
		"usage query fails":         {usage: fail, history: empty, wantErr: "querying usage"},
		"history start query fails": {usage: func(w http.ResponseWriter) { rows(w, usageFields) }, history: fail, wantErr: "querying history start"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := fakeBigQuery(t, since, tc.usage, tc.history).Load(t.Context(), since)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("Load() = %v, want error containing %q", err, tc.wantErr)
			}
		})
	}
}
