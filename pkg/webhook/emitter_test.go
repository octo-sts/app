// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package webhook

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/chainguard-dev/clog/slogtest"
	cloudevents "github.com/cloudevents/sdk-go/v2"
	"github.com/cloudevents/sdk-go/v2/protocol"
)

// blockingCEClient holds every Send open until release is closed, standing in
// for an ingress that has stopped answering.
type blockingCEClient struct {
	started chan struct{}
	release chan struct{}
	fakeCEClient
}

func newBlockingCEClient() *blockingCEClient {
	return &blockingCEClient{
		started: make(chan struct{}, 1),
		release: make(chan struct{}),
	}
}

func (b *blockingCEClient) Send(ctx context.Context, e cloudevents.Event) protocol.Result {
	select {
	case b.started <- struct{}{}:
	default:
	}
	<-b.release
	return b.fakeCEClient.Send(ctx, e)
}

// ctxAwareCEClient blocks in Send until its context is cancelled, standing in
// for an ingress that has accepted the connection and then stopped responding.
type ctxAwareCEClient struct {
	started   chan struct{}
	cancelled chan struct{}
	once      sync.Once
	fakeCEClient
}

func newCtxAwareCEClient() *ctxAwareCEClient {
	return &ctxAwareCEClient{
		started:   make(chan struct{}, 1),
		cancelled: make(chan struct{}),
	}
}

func (c *ctxAwareCEClient) Send(ctx context.Context, _ cloudevents.Event) protocol.Result {
	select {
	case c.started <- struct{}{}:
	default:
	}
	<-ctx.Done()
	c.once.Do(func() { close(c.cancelled) })
	return ctx.Err()
}

func testEvent(t *testing.T, subject string) cloudevents.Event {
	t.Helper()
	ce := cloudevents.NewEvent()
	ce.SetType("dev.octo-sts.policy")
	ce.SetSource("https://github.com/foo/bar")
	ce.SetSubject(subject)
	if err := ce.SetData(cloudevents.ApplicationJSON, PolicyEvent{Org: "foo", Repo: "bar"}); err != nil {
		t.Fatal(err)
	}
	return ce
}

// TestPolicyEmitterDoesNotBlockOnAStalledSink is the point of the queue: a
// webhook handler must return well inside GitHub's delivery timeout even when
// the ingress has stopped answering, because an overrun is retried as a failed
// delivery and would re-emit the whole push.
func TestPolicyEmitterDoesNotBlockOnAStalledSink(t *testing.T) {
	ctx := slogtest.Context(t)
	client := newBlockingCEClient()
	p := newPolicyEmitter(client, 1, 1)

	// Occupy the single worker so nothing can drain behind it.
	p.Enqueue(ctx, testEvent(t, "foo/bar/first"))
	select {
	case <-client.started:
	case <-time.After(10 * time.Second):
		t.Fatal("worker never picked up the first event")
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		p.Enqueue(ctx, testEvent(t, "foo/bar/second")) // fills the queue
		p.Enqueue(ctx, testEvent(t, "foo/bar/third"))  // no room: dropped
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Enqueue blocked on a stalled sink")
	}

	if got := p.Dropped(); got != 1 {
		t.Errorf("got %d dropped, want 1", got)
	}

	close(client.release)
	sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := p.Shutdown(sctx); err != nil {
		t.Fatalf("emitter did not drain: %v", err)
	}
	// The dropped event is gone for good; the two that fit are delivered.
	if got := len(client.sent()); got != 2 {
		t.Errorf("got %d delivered, want 2", got)
	}
}

// TestPolicyEmitterShutdownDrains keeps the queue from being a silent hole at
// process exit.
func TestPolicyEmitterShutdownDrains(t *testing.T) {
	ctx := slogtest.Context(t)
	client := &fakeCEClient{}
	p := newPolicyEmitter(client, 2, 64)

	for i := range 20 {
		p.Enqueue(ctx, testEvent(t, "foo/bar/policy"+string(rune('a'+i))))
	}

	sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := p.Shutdown(sctx); err != nil {
		t.Fatalf("emitter did not drain: %v", err)
	}
	if got := len(client.sent()); got != 20 {
		t.Errorf("got %d delivered, want 20", got)
	}

	// Shutting down twice must not panic on a closed channel.
	if err := p.Shutdown(sctx); err != nil {
		t.Errorf("second Shutdown: %v", err)
	}
}

// TestPolicyEmitterShutdownRespectsDeadline stops a wedged sink from holding
// the process open indefinitely.
func TestPolicyEmitterShutdownRespectsDeadline(t *testing.T) {
	ctx := slogtest.Context(t)
	client := newBlockingCEClient()
	defer close(client.release)

	p := newPolicyEmitter(client, 1, 4)
	p.Enqueue(ctx, testEvent(t, "foo/bar/stuck"))
	<-client.started

	sctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := p.Shutdown(sctx); err == nil {
		t.Error("expected Shutdown to give up on a wedged sink")
	}
}

// TestPolicyEmitterEnqueueAfterShutdown pins the guard around the queue.
//
// A send on a closed channel panics, and the select's default case does not
// cover that — it only covers full-but-open. Today's main shuts the server
// down before the emitter so this ordering should not arise, but a panic in a
// webhook handler is a poor way to discover that a future change reordered
// them, and it would take down live policy validation to lose an event that
// was already destined to be dropped.
func TestPolicyEmitterEnqueueAfterShutdown(t *testing.T) {
	ctx := slogtest.Context(t)
	client := &fakeCEClient{}
	p := newPolicyEmitter(client, 1, 4)

	sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := p.Shutdown(sctx); err != nil {
		t.Fatalf("emitter did not drain: %v", err)
	}

	// The assertion is that this returns at all rather than panicking.
	p.Enqueue(ctx, testEvent(t, "foo/bar/late"))

	if got := len(client.sent()); got != 0 {
		t.Errorf("got %d delivered after shutdown, want 0", got)
	}
	// Silently discarding a detection event would defeat the point, so the
	// drop is counted like any other.
	if got := p.Dropped(); got != 1 {
		t.Errorf("got %d dropped, want 1", got)
	}
}

// TestPolicyEmitterEnqueueRacesShutdown covers the same guard under the
// interleaving that actually threatens it: an in-flight request enqueueing at
// the moment shutdown closes the queue. Run with -race.
func TestPolicyEmitterEnqueueRacesShutdown(t *testing.T) {
	ctx := slogtest.Context(t)
	client := &fakeCEClient{}
	p := newPolicyEmitter(client, 2, 64)

	start := make(chan struct{})
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			<-start
			for range 25 {
				p.Enqueue(ctx, testEvent(t, "foo/bar/racy"))
			}
		})
	}

	wg.Go(func() {
		<-start
		sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := p.Shutdown(sctx); err != nil {
			t.Errorf("emitter did not drain: %v", err)
		}
	})

	close(start)
	wg.Wait()

	// Every event is either delivered or counted as dropped; none may vanish.
	if got, want := int64(len(client.sent()))+p.Dropped(), int64(200); got != want {
		t.Errorf("accounted for %d events, want %d", got, want)
	}
}

// TestPolicyEmitterShutdownCancelsInFlightSends makes the shutdown deadline
// real rather than advisory.
//
// The per-event budget is longer than the drain budget, so without cancelling
// the send a worker wedged on an unresponsive sink would keep running past the
// deadline until the platform killed the process outright.
func TestPolicyEmitterShutdownCancelsInFlightSends(t *testing.T) {
	ctx := slogtest.Context(t)
	client := newCtxAwareCEClient()
	p := newPolicyEmitter(client, 1, 4)

	p.Enqueue(ctx, testEvent(t, "foo/bar/stuck"))
	select {
	case <-client.started:
	case <-time.After(10 * time.Second):
		t.Fatal("worker never picked up the event")
	}

	sctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := p.Shutdown(sctx); err == nil {
		t.Error("expected Shutdown to report that it gave up")
	}

	// The send must be cut short by the drain deadline, not left to run out
	// the full per-event timeout.
	select {
	case <-client.cancelled:
	case <-time.After(10 * time.Second):
		t.Error("in-flight send was not cancelled when the drain deadline expired")
	}

	// Shutdown gave up on its deadline without waiting for the worker, so wait
	// for the worker to exit before returning. Its deferred error log uses the
	// t-bound logger, and logging after the test completes races with test
	// teardown ("Log in goroutine after test has completed").
	p.wg.Wait()
}
