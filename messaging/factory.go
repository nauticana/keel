package messaging

import (
	"context"
	"fmt"

	"github.com/nats-io/nats.go/jetstream"
	"github.com/nauticana/keel/port"
	"github.com/nauticana/keel/secret"
)

// NewMessagePublisher returns the publisher implementation for the given
// messaging mode. Supported modes:
//
//	"gcp"   — Google Cloud Pub/Sub (PubSubPublisher). Requires --gcp_project_id.
//	"aws"   — Amazon SNS (SNSPublisher). Loads AWS credentials via the
//	          standard SDK chain.
//	"nats"  — NATS JetStream (NATSPublisher). Honors the nats_url / nats_name /
//	          nats_creds_secret config; creds material comes from the secret provider.
//
// Empty or unknown modes return an error so deployments fail fast on
// misconfiguration. Callers that want graceful degradation should treat
// the error as "publisher unavailable" and fall back to a DB-only path.
func NewMessagePublisher(ctx context.Context, mode string, secrets secret.SecretProvider) (port.MessagePublisher, error) {
	switch mode {
	case "gcp":
		return NewPubSubPublisher()
	case "aws":
		return NewSNSPublisher()
	case "nats":
		return NewNATSPublisher(ctx, secrets)
	default:
		return nil, fmt.Errorf("messaging: unknown publisher mode %q (supported: gcp, aws, nats)", mode)
	}
}

// NewMessageSubscriber returns the subscriber implementation for the given
// messaging mode. Supported modes:
//
//	"gcp"   — Google Cloud Pub/Sub (PubSubSubscriber).
//	"aws"   — Amazon SQS (SQSSubscriber). SNS topics fan out to SQS queues
//	          on the AWS path; subscribers always receive from SQS.
//	"nats"  — NATS JetStream pull-consumer (NATSSubscriber).
func NewMessageSubscriber(ctx context.Context, mode string, secrets secret.SecretProvider) (port.MessageSubscriber, error) {
	switch mode {
	case "gcp":
		return NewPubSubSubscriber()
	case "aws":
		return NewSQSSubscriber()
	case "nats":
		return NewNATSSubscriber(ctx, secrets)
	default:
		return nil, fmt.Errorf("messaging: unknown subscriber mode %q (supported: gcp, aws, nats)", mode)
	}
}

func NewNATSPublisher(ctx context.Context, secrets secret.SecretProvider) (*NATSPublisher, error) {
	nc, err := NATSConnect(ctx, secrets)
	if err != nil {
		return nil, err
	}
	js, err := jetstream.New(nc)
	if err != nil {
		nc.Close()
		return nil, fmt.Errorf("nats: jetstream: %w", err)
	}
	return &NATSPublisher{nc: nc, js: js, streams: map[string]bool{}}, nil
}

var (
	_ port.MessagePublisher  = (*NATSPublisher)(nil)
	_ port.MessageSubscriber = (*NATSSubscriber)(nil)
)
