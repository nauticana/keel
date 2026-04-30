package messaging

import (
	"context"
	"fmt"
	"strings"

	"cloud.google.com/go/pubsub/v2"
	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/port"
)

// PubSubSubscriber subscribes to Google Cloud Pub/Sub subscriptions.
type PubSubSubscriber struct {
	client *pubsub.Client
}

func NewPubSubSubscriber() (*PubSubSubscriber, error) {
	projectID := strings.TrimSpace(*common.ProjectID)
	if projectID == "" {
		return nil, fmt.Errorf("pubsub: --gcp_project_id is required")
	}
	client, err := pubsub.NewClient(context.Background(), projectID)
	if err != nil {
		return nil, fmt.Errorf("pubsub: failed to create client: %w", err)
	}
	return &PubSubSubscriber{client: client}, nil
}

func (s *PubSubSubscriber) Subscribe(ctx context.Context, subscription string, handler port.MessageHandler) error {
	sub := s.client.Subscriber(subscription)
	return sub.Receive(ctx, func(ctx context.Context, m *pubsub.Message) {
		msg := &port.Message{
			ID:         m.ID,
			Data:       m.Data,
			Attributes: m.Attributes,
			Ack:        m.Ack,
			Nack:       m.Nack,
		}
		if err := handler(ctx, msg); err != nil {
			m.Nack()
			return
		}
		m.Ack()
	})
}

func (s *PubSubSubscriber) Close() error {
	if s.client != nil {
		return s.client.Close()
	}
	return nil
}

var _ port.MessageSubscriber = (*PubSubSubscriber)(nil)
