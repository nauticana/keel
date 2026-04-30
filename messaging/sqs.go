package messaging

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/nauticana/keel/port"
)

// ackDeadline bounds the time Ack/Nack get to complete. Detached
// from the request ctx (P1-22) so a parent-cancellation during
// graceful shutdown doesn't prevent us from finalizing in-flight
// messages — that would leave them invisible-but-undelivered until
// SQS's visibility timeout elapses, causing duplicate processing.
const sqsAckDeadline = 10 * time.Second

// SQSSubscriber subscribes to messages from AWS SQS queues. Queue URLs are
// resolved by name on first use and cached for the lifetime of the
// subscriber.
//
// The queueURL cache is mutex-guarded so concurrent Subscribe calls
// against fresh queue names don't race on the map. (Subscribe usually
// runs once per queue per process — but the data race exists regardless
// and Go's runtime panics on detection.)
type SQSSubscriber struct {
	client *sqs.Client

	mu       sync.Mutex
	queueURL map[string]string // queue name → URL cache
}

func NewSQSSubscriber() (*SQSSubscriber, error) {
	cfg, err := config.LoadDefaultConfig(context.Background())
	if err != nil {
		return nil, fmt.Errorf("sqs: load AWS config: %w", err)
	}
	return &SQSSubscriber{
		client:   sqs.NewFromConfig(cfg),
		queueURL: make(map[string]string),
	}, nil
}

func (s *SQSSubscriber) Subscribe(ctx context.Context, subscription string, handler port.MessageHandler) error {
	queueURL, err := s.resolveQueueURL(ctx, subscription)
	if err != nil {
		return err
	}
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		out, err := s.client.ReceiveMessage(ctx, &sqs.ReceiveMessageInput{
			QueueUrl:              &queueURL,
			MaxNumberOfMessages:   10,
			WaitTimeSeconds:       20,
			MessageAttributeNames: []string{"All"},
		})
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return fmt.Errorf("sqs: receive from %s: %w", subscription, err)
		}
		for _, m := range out.Messages {
			attrs := make(map[string]string, len(m.MessageAttributes))
			for k, v := range m.MessageAttributes {
				if v.StringValue != nil {
					attrs[k] = *v.StringValue
				}
			}
			receiptHandle := m.ReceiptHandle
			msg := &port.Message{
				ID:         derefStr(m.MessageId),
				Data:       []byte(derefStr(m.Body)),
				Attributes: attrs,
				Ack: func() {
					ackCtx, cancel := context.WithTimeout(context.Background(), sqsAckDeadline)
					defer cancel()
					_, _ = s.client.DeleteMessage(ackCtx, &sqs.DeleteMessageInput{
						QueueUrl:      &queueURL,
						ReceiptHandle: receiptHandle,
					})
				},
				Nack: func() {
					ackCtx, cancel := context.WithTimeout(context.Background(), sqsAckDeadline)
					defer cancel()
					zero := int32(0)
					_, _ = s.client.ChangeMessageVisibility(ackCtx, &sqs.ChangeMessageVisibilityInput{
						QueueUrl:          &queueURL,
						ReceiptHandle:     receiptHandle,
						VisibilityTimeout: zero,
					})
				},
			}
			if err := handler(ctx, msg); err != nil {
				msg.Nack()
			} else {
				msg.Ack()
			}
		}
	}
}

func (s *SQSSubscriber) resolveQueueURL(ctx context.Context, name string) (string, error) {
	s.mu.Lock()
	cached, ok := s.queueURL[name]
	s.mu.Unlock()
	if ok {
		return cached, nil
	}
	out, err := s.client.GetQueueUrl(ctx, &sqs.GetQueueUrlInput{QueueName: &name})
	if err != nil {
		return "", fmt.Errorf("sqs: resolve queue %q: %w", name, err)
	}
	if out.QueueUrl == nil {
		return "", fmt.Errorf("sqs: empty queue URL for %q", name)
	}
	resolved := *out.QueueUrl
	s.mu.Lock()
	s.queueURL[name] = resolved
	s.mu.Unlock()
	return resolved, nil
}

func (s *SQSSubscriber) Close() error {
	return nil
}

func derefStr(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

var _ port.MessageSubscriber = (*SQSSubscriber)(nil)
