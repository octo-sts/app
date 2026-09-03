// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package webhook

import (
	"context"
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
