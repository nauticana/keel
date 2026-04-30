package messaging

import (
	"context"
	"fmt"
	"sync"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sns"
	snstypes "github.com/aws/aws-sdk-go-v2/service/sns/types"
	"golang.org/x/sync/singleflight"

	"github.com/nauticana/keel/port"
)

// SNSPublisher publishes messages to AWS SNS topics. Topics are looked up by
// name on first use and the resolved ARN is cached for the lifetime of the
// publisher.
//
// Concurrent Publish calls share the topicARN map; without a mutex two
// publishes against previously-unseen topics would race and crash with
// "concurrent map read and map write".
type SNSPublisher struct {
	client *sns.Client

	mu       sync.Mutex
	topicARN map[string]string // topic name → ARN cache

	// resolveSF collapses concurrent first-callers for the same
	// topic into a single CreateTopic round-trip (v0.4.5 perf).
	// Without it, N goroutines all racing to publish to a brand-new
	// topic each issue their own CreateTopic call — idempotent on
	// AWS's side, but burns the 30 calls/s account quota and adds
	// latency to every loser.
	resolveSF singleflight.Group
}

func NewSNSPublisher() (*SNSPublisher, error) {
	cfg, err := config.LoadDefaultConfig(context.Background())
	if err != nil {
		return nil, fmt.Errorf("sns: load AWS config: %w", err)
	}
	return &SNSPublisher{
		client:   sns.NewFromConfig(cfg),
		topicARN: make(map[string]string),
	}, nil
}

func (p *SNSPublisher) Publish(ctx context.Context, topic string, data []byte, attributes map[string]string) error {
	arn, err := p.resolveTopicARN(ctx, topic)
	if err != nil {
		return err
	}
	msg := string(data)
	input := &sns.PublishInput{
		TopicArn: &arn,
		Message:  &msg,
	}
	if len(attributes) > 0 {
		msgAttrs := make(map[string]snstypes.MessageAttributeValue, len(attributes))
		dataType := "String"
		for k, v := range attributes {
			val := v
			msgAttrs[k] = snstypes.MessageAttributeValue{
				DataType:    &dataType,
				StringValue: &val,
			}
		}
		input.MessageAttributes = msgAttrs
	}
	_, err = p.client.Publish(ctx, input)
	if err != nil {
		return fmt.Errorf("sns: publish to %s: %w", topic, err)
	}
	return nil
}

// resolveTopicARN returns the ARN for an SNS topic, creating it lazily
// when absent. CreateTopic is idempotent on AWS's side — a second
// call with the same name returns the existing ARN — so we use it
// instead of ListTopics-and-scan (the previous strategy, which is
// paginated, rate-limited at 30 calls/s, and O(N) over every topic
// in the account on first use of each name). P1-21.
func (p *SNSPublisher) resolveTopicARN(ctx context.Context, topic string) (string, error) {
	p.mu.Lock()
	arn, ok := p.topicARN[topic]
	p.mu.Unlock()
	if ok {
		return arn, nil
	}
	v, err, _ := p.resolveSF.Do(topic, func() (any, error) {
		p.mu.Lock()
		if cached, ok := p.topicARN[topic]; ok {
			p.mu.Unlock()
			return cached, nil
		}
		p.mu.Unlock()
		out, err := p.client.CreateTopic(ctx, &sns.CreateTopicInput{Name: &topic})
		if err != nil {
			return "", fmt.Errorf("sns: create/find topic %q: %w", topic, err)
		}
		if out.TopicArn == nil {
			return "", fmt.Errorf("sns: empty ARN for topic %q", topic)
		}
		resolved := *out.TopicArn
		p.mu.Lock()
		p.topicARN[topic] = resolved
		p.mu.Unlock()
		return resolved, nil
	})
	if err != nil {
		return "", err
	}
	return v.(string), nil
}

func (p *SNSPublisher) Close() error {
	return nil
}

var _ port.MessagePublisher = (*SNSPublisher)(nil)
