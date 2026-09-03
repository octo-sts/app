// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package webhook

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/chainguard-dev/clog"
	cloudevents "github.com/cloudevents/sdk-go/v2"
)

const (
	retryDelay = 10 * time.Millisecond
	maxRetry   = 3

	// policyEventQueueSize bounds the audit backlog held in memory. Sized to
	// absorb a bulk policy migration plus GitHub's redelivery of it, while
	// staying small enough that a wedged sink costs bounded memory.
	policyEventQueueSize = 2048
	// policyEmitWorkers deliver concurrently so one slow request does not hold
	// up the events queued behind it. Arrival order is therefore not
	// significant; consumers order by commit and change_index.
	policyEmitWorkers = 4
	// policyEmitTimeout bounds one event's delivery, retries included, so a
	// black-holed sink cannot pin a worker indefinitely.
	policyEmitTimeout = 30 * time.Second
)

// PolicyEmitter delivers trust policy audit events off the webhook's request
// path.
//
// GitHub allows a webhook roughly ten seconds to respond and treats an overrun
// as a failed delivery, which it then redelivers. Sending inline meant a slow
// or unavailable ingress could both stall the response and, through that
// redelivery, duplicate the very events it was failing to accept — while also
// delaying the policy validation the same request performs. Handlers now
// enqueue and return.
//
// Enqueue never blocks. Under sustained sink failure the choice is between
// dropping audit events and stalling webhook responses, and stalling would
// take policy validation down with it. Drops are counted and logged so the
// gap is visible rather than silent.
type PolicyEmitter struct {
	client    cloudevents.Client
	queue     chan policyEmission
	wg        sync.WaitGroup
	dropped   atomic.Int64
	closeOnce sync.Once
}

type policyEmission struct {
	event cloudevents.Event
	log   *clog.Logger
}

// NewPolicyEmitter starts an emitter delivering to client. Callers should
// Shutdown it to drain the queue.
func NewPolicyEmitter(client cloudevents.Client) *PolicyEmitter {
	return newPolicyEmitter(client, policyEmitWorkers, policyEventQueueSize)
}

func newPolicyEmitter(client cloudevents.Client, workers, queueSize int) *PolicyEmitter {
	p := &PolicyEmitter{
		client: client,
		queue:  make(chan policyEmission, queueSize),
	}
	p.wg.Add(workers)
	for range workers {
		go p.run()
	}
	return p
}

func (p *PolicyEmitter) run() {
	defer p.wg.Done()
	for item := range p.queue {
		// Deliberately rooted in Background: the request that produced this
		// event has long since been answered, so its context is gone.
		ctx, cancel := context.WithTimeout(context.Background(), policyEmitTimeout)
		rctx := cloudevents.ContextWithRetriesExponentialBackoff(ctx, retryDelay, maxRetry)
		if res := p.client.Send(rctx, item.event); cloudevents.IsUndelivered(res) || cloudevents.IsNACK(res) {
			item.log.Errorf("failed to deliver policy event for %q: %v", item.event.Subject(), res)
		}
		cancel()
	}
}

// Enqueue submits an event for delivery, dropping it if the queue is full.
func (p *PolicyEmitter) Enqueue(ctx context.Context, ce cloudevents.Event) {
	log := clog.FromContext(ctx)
	select {
	case p.queue <- policyEmission{event: ce, log: log}:
	default:
		log.Errorf("policy audit queue full: dropped event for %q (%d dropped since start)",
			ce.Subject(), p.dropped.Add(1))
	}
}

// Dropped reports how many events have been discarded for want of queue space.
func (p *PolicyEmitter) Dropped() int64 { return p.dropped.Load() }

// Shutdown stops accepting events and waits for the queue to drain, or for ctx
// to expire. It is safe to call more than once.
func (p *PolicyEmitter) Shutdown(ctx context.Context) error {
	p.closeOnce.Do(func() { close(p.queue) })

	done := make(chan struct{})
	go func() {
		p.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
