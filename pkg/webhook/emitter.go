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
	client  cloudevents.Client
	queue   chan policyEmission
	wg      sync.WaitGroup
	dropped atomic.Int64

	// mu guards closed against queue. Enqueue holds it for reading, so it is
	// held by any number of senders at once but never at the same time as the
	// close in Shutdown — which is what makes "check closed, then send" safe.
	// A bare flag or a done channel would leave the gap between the check and
	// the send open, and a send on a closed channel panics: the select's
	// default case only covers full-but-open.
	mu     sync.RWMutex
	closed bool

	// drainCancel interrupts in-flight sends once Shutdown's deadline expires,
	// so a worker stuck on an unresponsive sink cannot hold the process past
	// the grace period its platform allows.
	drainCancel context.CancelFunc
	sendCtx     context.Context
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
	// Deliberately rooted in Background: the request that produces an event has
	// long since been answered by the time a worker sends it, so its context is
	// gone. Shutdown owns the cancel and always calls it.
	sendCtx, cancel := context.WithCancel(context.Background()) //nolint:gosec // G118: cancel is held on the emitter and called by Shutdown
	p := &PolicyEmitter{
		client:      client,
		queue:       make(chan policyEmission, queueSize),
		sendCtx:     sendCtx,
		drainCancel: cancel,
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
		ctx, cancel := context.WithTimeout(p.sendCtx, policyEmitTimeout)
		rctx := cloudevents.ContextWithRetriesExponentialBackoff(ctx, retryDelay, maxRetry)
		if res := p.client.Send(rctx, item.event); cloudevents.IsUndelivered(res) || cloudevents.IsNACK(res) {
			item.log.Errorf("failed to deliver policy event for %q: %v", item.event.Subject(), res)
		}
		cancel()
	}
}

// Enqueue submits an event for delivery, dropping it if the queue is full or
// the emitter has been shut down. It never blocks and is safe to call at any
// point in the emitter's life, including concurrently with Shutdown.
func (p *PolicyEmitter) Enqueue(ctx context.Context, ce cloudevents.Event) {
	log := clog.FromContext(ctx)

	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.closed {
		// Reachable only if a request is still in flight once shutdown has
		// begun. Dropping is the right answer — the queue is on its way out —
		// but it must be counted, and it must not be a panic.
		log.Errorf("policy emitter shut down: dropped event for %q (%d dropped since start)",
			ce.Subject(), p.dropped.Add(1))
		return
	}

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
// to expire. It is safe to call more than once, and safe to call while other
// goroutines are still enqueueing.
func (p *PolicyEmitter) Shutdown(ctx context.Context) error {
	// Releases sendCtx on every path. On the deadline path this is also what
	// cuts the in-flight sends: the caller's deadline is usually a platform
	// grace period, after which the process is killed regardless, and a
	// cancelled send at least lets the worker log the failure rather than
	// vanishing mid-request.
	defer p.drainCancel()

	p.mu.Lock()
	if !p.closed {
		p.closed = true
		close(p.queue)
	}
	p.mu.Unlock()

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
