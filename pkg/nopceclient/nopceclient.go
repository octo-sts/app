package nopceclient

import (
	"context"

	"github.com/cloudevents/sdk-go/v2/event"
	"github.com/cloudevents/sdk-go/v2/protocol"
)

type Client struct{}

func (n Client) Send(_ context.Context, _ event.Event) protocol.Result {
	return nil
}

func (n Client) Request(_ context.Context, _ event.Event) (*event.Event, protocol.Result) {
	panic("implement me")
}

func (n Client) StartReceiver(_ context.Context, _ interface{}) error {
	panic("implement me")
}
