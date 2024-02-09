// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package http

import (
	"context"
	"net/http"

	"golang.org/x/time/rate"
)

// RLHTTPClient Rate Limited HTTP Client
type RLHTTPClient struct {
	Client      *http.Client
	Ratelimiter *rate.Limiter
}

// Do dispatches the HTTP request to the network
func (c *RLHTTPClient) Do(req *http.Request) (*http.Response, error) {
	// Comment out the below 5 lines to turn off ratelimiting
	ctx := context.Background()
	err := c.Ratelimiter.Wait(ctx) // This is a blocking call. Honors the rate limit
	if err != nil {
		return nil, err
	}
	resp, err := c.Client.Do(req)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// NewClient return rate_limitted_http client with a ratelimiter
func NewClient(rl *rate.Limiter) *RLHTTPClient {
	c := &RLHTTPClient{
		Client:      http.DefaultClient,
		Ratelimiter: rl,
	}
	return c
}

// RateLimitingRoundTripper is a custom RoundTripper that enforces rate limits
type RateLimitingRoundTripper struct {
	transport http.RoundTripper
	limiter   *rate.Limiter
}

// RoundTrip is the method that gets called for each HTTP request
func (r *RateLimitingRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	ctx := req.Context()

	// Wait blocks until limiter allows another event
	if err := r.limiter.Wait(ctx); err != nil {
		// handle error: could be context cancellation
		return nil, err
	}

	// Proceed with the request
	return r.transport.RoundTrip(req)
}

// NewRateLimitingRoundTripper creates a new instance of RateLimitingRoundTripper
func NewRateLimitingRoundTripper(limiter *rate.Limiter, transport http.RoundTripper) *RateLimitingRoundTripper {
	if transport == nil {
		transport = http.DefaultTransport
	}
	return &RateLimitingRoundTripper{
		transport: transport,
		limiter:   limiter,
	}
}
