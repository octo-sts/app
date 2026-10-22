// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package bigquery loads trust policy usage from the exchange events that
// octo-sts records in BigQuery.
package bigquery

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"cloud.google.com/go/bigquery"
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

	// The oldest record only needs to be found when it is older than the
	// window start, so only the partitions up to then are scanned.
	historyStartQuery = `SELECT MIN(time) AS oldest
FROM ` + "`%s`" + `
WHERE _PARTITIONTIME < TIMESTAMP_ADD(TIMESTAMP_TRUNC(@since, DAY), INTERVAL 1 DAY)`
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
	// Start is the time of the oldest record found, or zero if there is no
	// record before the window start.
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

// Load reads every organization's usage since since, and how far back the
// table's history goes.
func (s *Source) Load(ctx context.Context, since time.Time) (History, error) {
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

	it, err = s.read(ctx, fmt.Sprintf(historyStartQuery, s.table), params)
	if err != nil {
		return History{}, fmt.Errorf("bigquery: querying history start: %w", err)
	}
	var r struct {
		Oldest bigquery.NullTimestamp `bigquery:"oldest"`
	}
	if err := it.Next(&r); err != nil && !errors.Is(err, iterator.Done) {
		return History{}, fmt.Errorf("bigquery: reading history start: %w", err)
	}
	if r.Oldest.Valid {
		h.Start = r.Oldest.Timestamp
	}
	return h, nil
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
	org, _, _ := strings.Cut(r.Scope, "/")
	u := cleanup.Usage{Scope: r.Scope, Identity: r.Identity.StringVal, LastError: r.LastError.StringVal}
	if r.LastSucceeded.Valid {
		u.LastSucceeded = r.LastSucceeded.Timestamp
	}
	if r.LastFailed.Valid {
		u.LastFailed = r.LastFailed.Timestamp
	}
	return strings.ToLower(org), u
}
