// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package bigquery loads trust policy usage from the exchange events that
// octo-sts records in BigQuery.
package bigquery

import (
	"context"
	"errors"
	"fmt"
	"path"
	"regexp"
	"strings"
	"time"

	"cloud.google.com/go/bigquery"
	"cloud.google.com/go/civil"
	"google.golang.org/api/iterator"

	"github.com/octo-sts/app/pkg/cleanup"
)

// The exchange table is partitioned by ingestion time, so each query bounds
// _PARTITIONTIME as well as the event time to scan only what it needs.
// Events land in a partition at or after their own time, so filtering
// partitions from the day of the window start drops nothing in the window.
const (
	usageQuery = `SELECT
  scope,
  identity,
  MAX(IF(IFNULL(error, '') = '', time, NULL)) AS last_succeeded,
  MAX(IF(IFNULL(error, '') != '', time, NULL)) AS last_failed,
  ARRAY_AGG(IF(IFNULL(error, '') != '', error, NULL) IGNORE NULLS ORDER BY time DESC LIMIT 1)[SAFE_OFFSET(0)] AS last_error
FROM ` + "`%s`" + `
WHERE _PARTITIONTIME >= TIMESTAMP_TRUNC(@since, DAY) AND time >= @since AND IFNULL(scope, '') != ''
GROUP BY scope, identity`

	// daysQuery lists each UTC day with at least one exchange and its first
	// exchange. It reads only the time column of the whole table, which is
	// bounded by the table's retention.
	daysQuery = `SELECT DATE(time) AS day, MIN(time) AS first
FROM ` + "`%s`" + `
WHERE time IS NOT NULL
GROUP BY day`
)

// tableID matches "project.dataset.table". Project and table names may contain
// hyphens (octo-sts.dev's table is "dev_octo-sts_exchange"); datasets may not.
var tableID = regexp.MustCompile(`^[A-Za-z0-9_-]+\.[A-Za-z0-9_]+\.[A-Za-z0-9_-]+$`)

// Source reads exchange events from one BigQuery table.
type Source struct {
	client *bigquery.Client
	table  string
}

// New returns a Source for table, given as "project.dataset.table".
func New(client *bigquery.Client, table string) (*Source, error) {
	if !tableID.MatchString(table) {
		return nil, fmt.Errorf("bigquery: table must be project.dataset.table, got %q", table)
	}
	return &Source{client: client, table: table}, nil
}

// History is the exchange usage loaded for a window.
type History struct {
	// Start is where the unbroken exchange history begins: the first
	// exchange of the earliest day in the run of consecutive days with
	// exchanges that ends today or yesterday. It is zero when there is no
	// such run. Event delivery is best effort, so a missing day means
	// exchanges may have been lost; Start then moves past the gap and
	// cleanup.Decide declines to decide over it. This assumes at least one
	// exchange every UTC day, which a prober guarantees.
	Start time.Time
	// Usage holds the usage per organization, keyed by lowercased org name.
	Usage map[string][]cleanup.Usage
}

// Orgs returns the organizations with at least one exchange in the window.
func (h History) Orgs() []string {
	orgs := make([]string, 0, len(h.Usage))
	for org := range h.Usage {
		orgs = append(orgs, org)
	}
	return orgs
}

// For returns org's usage. The org name is matched case-insensitively.
func (h History) For(org string) []cleanup.Usage {
	return h.Usage[strings.ToLower(org)]
}

// Load reads every organization's usage since since, and where the unbroken
// history before now begins.
func (s *Source) Load(ctx context.Context, since, now time.Time) (History, error) {
	params := []bigquery.QueryParameter{{Name: "since", Value: since}}

	h := History{Usage: map[string][]cleanup.Usage{}}
	it, err := s.read(ctx, fmt.Sprintf(usageQuery, s.table), params)
	if err != nil {
		return History{}, fmt.Errorf("bigquery: querying usage: %w", err)
	}
	for {
		var r usageRow
		err := it.Next(&r)
		if errors.Is(err, iterator.Done) {
			break
		}
		if err != nil {
			return History{}, fmt.Errorf("bigquery: reading usage: %w", err)
		}
		org, u := r.usage()
		h.Usage[org] = append(h.Usage[org], u)
	}

	it, err = s.read(ctx, fmt.Sprintf(daysQuery, s.table), nil)
	if err != nil {
		return History{}, fmt.Errorf("bigquery: querying history days: %w", err)
	}
	firsts := map[civil.Date]time.Time{}
	for {
		var r struct {
			Day   civil.Date `bigquery:"day"`
			First time.Time  `bigquery:"first"`
		}
		err := it.Next(&r)
		if errors.Is(err, iterator.Done) {
			break
		}
		if err != nil {
			return History{}, fmt.Errorf("bigquery: reading history days: %w", err)
		}
		firsts[r.Day] = r.First
	}
	h.Start = unbrokenStart(firsts, now)
	return h, nil
}

// unbrokenStart walks back from today, or from yesterday if today has no
// exchanges yet, while every day has exchanges, and returns the first
// exchange of the earliest day reached.
func unbrokenStart(firsts map[civil.Date]time.Time, now time.Time) time.Time {
	day := civil.DateOf(now.UTC())
	if _, ok := firsts[day]; !ok {
		day = day.AddDays(-1)
	}
	var start time.Time
	for {
		first, ok := firsts[day]
		if !ok {
			return start
		}
		start = first
		day = day.AddDays(-1)
	}
}

func (s *Source) read(ctx context.Context, sql string, params []bigquery.QueryParameter) (*bigquery.RowIterator, error) {
	q := s.client.Query(sql)
	q.Parameters = params
	return q.Read(ctx)
}

type usageRow struct {
	Scope         string                 `bigquery:"scope"`
	Identity      bigquery.NullString    `bigquery:"identity"`
	LastSucceeded bigquery.NullTimestamp `bigquery:"last_succeeded"`
	LastFailed    bigquery.NullTimestamp `bigquery:"last_failed"`
	LastError     bigquery.NullString    `bigquery:"last_error"`
}

// usage converts a row, returning the lowercased org the scope belongs to.
func (r usageRow) usage() (string, cleanup.Usage) {
	scope := canonicalScope(r.Scope)
	org, _, _ := strings.Cut(scope, "/")
	u := cleanup.Usage{Scope: scope, Identity: r.Identity.StringVal, LastError: r.LastError.StringVal}
	if r.LastSucceeded.Valid {
		u.LastSucceeded = r.LastSucceeded.Timestamp
	}
	if r.LastFailed.Valid {
		u.LastFailed = r.LastFailed.Timestamp
	}
	return strings.ToLower(org), u
}

// canonicalScope resolves a recorded scope the way the exchange does, with
// path.Dir and path.Base, so "acme//svc" and "./acme/svc" count as "acme/svc"
// and "./acme" as "acme".
func canonicalScope(scope string) string {
	owner, repo := path.Dir(scope), path.Base(scope)
	if owner == "." {
		return repo
	}
	return owner + "/" + repo
}
