// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package maxsize

import (
	"io"
	"net/http"
)

// NewRoundTripper creates a new http.RoundTripper that wraps the given
// http.RoundTripper and limits the size of the response body to maxSize bytes.
func NewRoundTripper(maxSize int64, inner http.RoundTripper) http.RoundTripper {
	return &ms{
		base:        inner,
		maxBodySize: maxSize,
	}
}

type ms struct {
	base        http.RoundTripper // The underlying RoundTripper
	maxBodySize int64             // Maximum allowed response body size in bytes
}

// RoundTrip implements http.RoundTripper
func (rt *ms) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := rt.base.RoundTrip(req)
	if err != nil {
		return nil, err
	}

	resp.Body = &lr{
		LimitedReader: io.LimitedReader{
			R: resp.Body,
			N: rt.maxBodySize,
		},
		close: resp.Body.Close,
	}
	return resp, nil
}

type lr struct {
	io.LimitedReader
	close func() error
}

// Close implements io.Closer
func (r *lr) Close() error {
	return r.close()
}
