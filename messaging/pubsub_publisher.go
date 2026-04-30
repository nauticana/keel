package messaging

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"cloud.google.com/go/pubsub/v2"
	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/port"
)

// PubSubPublisher publishes messages to Google Cloud Pub/Sub topics.
//
// *pubsub.Publisher carries an internal goroutine pool + outbound queue;
// it must be Stop()'d when no longer used or its goroutines leak. We
// cache publishers by topic name (lazy) and Stop them on Close — without
// that every Publish call against a fresh topic name would leak a
// Publisher instance for the lifetime of the process.
//
// closed is the post-Close flag: any Publish after Close returns an
// error immediately rather than panicking on a nil topics map.
type PubSubPublisher struct {
	client *pubsub.Client

	mu     sync.Mutex
	topics map[string]*pubsub.Publisher
	closed bool
}

func NewPubSubPublisher() (*PubSubPublisher, error) {
	projectID := strings.TrimSpace(*common.ProjectID)
	if projectID == "" {
		return nil, fmt.Errorf("pubsub: --gcp_project_id is required")
	}
	client, err := pubsub.NewClient(context.Background(), projectID)
	if err != nil {
		return nil, fmt.Errorf("pubsub: failed to create client: %w", err)
	}
	return &PubSubPublisher{client: client, topics: map[string]*pubsub.Publisher{}}, nil
}

// topicFor returns the cached Publisher handle for name, creating one
// if needed. Holds the mutex for the whole lookup-or-create so two
// concurrent Publish calls against an unseen topic don't end up with
// two leaked Publisher instances. Returns (nil, false) when the
// publisher has already been Closed — Publish maps that to an
// explicit error rather than nil-map panicking on the assignment
// below (MAJOR 4).
func (p *PubSubPublisher) topicFor(name string) (*pubsub.Publisher, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil, false
	}
	if t, ok := p.topics[name]; ok {
		return t, true
	}
	t := p.client.Publisher(name)
	p.topics[name] = t
	return t, true
}

func (p *PubSubPublisher) Publish(ctx context.Context, topic string, data []byte, attributes map[string]string) error {
	t, ok := p.topicFor(topic)
	if !ok {
		return fmt.Errorf("pubsub: publisher closed")
	}
	result := t.Publish(ctx, &pubsub.Message{
		Data:       data,
		Attributes: attributes,
	})
	if _, err := result.Get(ctx); err != nil {
		return fmt.Errorf("pubsub: failed to publish to %s: %w", topic, err)
	}
	return nil
}

// Close stops every cached Publisher (releasing its goroutine pool)
// and then closes the client. Idempotent — a second Close after the
// first sees `closed == true` and short-circuits.
func (p *PubSubPublisher) Close() error {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil
	}
	p.closed = true
	for _, t := range p.topics {
		t.Stop()
	}
	p.topics = nil
	p.mu.Unlock()
	if p.client != nil {
		return p.client.Close()
	}
	return nil
}

var _ port.MessagePublisher = (*PubSubPublisher)(nil)
