package messaging

import (
	"context"
	"fmt"

	"github.com/nauticana/keel/port"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

// NATSSubscriber consumes a JetStream subject via a durable pull consumer.
// Subscription name is used as the consumer's `Durable` — survives restarts.
// Messages unacked within AckWait are redelivered up to MaxDeliver times,
// then routed to the stream's DLQ (`<stream>.DLQ`) if one is configured.
type NATSSubscriber struct {
	nc *nats.Conn
	js jetstream.JetStream
}

func NewNATSSubscriber() (*NATSSubscriber, error) {
	nc, err := NATSConnect()
	if err != nil {
		return nil, err
	}
	js, err := jetstream.New(nc)
	if err != nil {
		nc.Close()
		return nil, fmt.Errorf("nats: jetstream: %w", err)
	}
	return &NATSSubscriber{nc: nc, js: js}, nil
}

func (s *NATSSubscriber) Subscribe(ctx context.Context, subscription string, handler port.MessageHandler) error {
	stream, err := s.js.Stream(ctx, streamName(subscription))
	if err != nil {
		return fmt.Errorf("nats: stream %s: %w", streamName(subscription), err)
	}
	cons, err := stream.CreateOrUpdateConsumer(ctx, jetstream.ConsumerConfig{
		Durable:       subscription,
		AckPolicy:     jetstream.AckExplicitPolicy,
		AckWait:       natsDefaultAckWait,
		MaxDeliver:    natsDefaultMaxDeliver,
		MaxAckPending: natsDefaultMaxAckPending,
	})
	if err != nil {
		return fmt.Errorf("nats: consumer %s: %w", subscription, err)
	}

	for {
		if err := ctx.Err(); err != nil {
			return nil
		}
		batch, err := cons.Fetch(natsDefaultFetch, jetstream.FetchMaxWait(natsFetchTimeout))
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("nats: fetch: %w", err)
		}
		for m := range batch.Messages() {
			s.dispatch(ctx, m, handler)
		}
		if err := batch.Error(); err != nil {
			return fmt.Errorf("nats: batch: %w", err)
		}
	}
}

func (s *NATSSubscriber) dispatch(ctx context.Context, m jetstream.Msg, handler port.MessageHandler) {
	attrs := map[string]string{}
	for k, v := range m.Headers() {
		if len(v) > 0 {
			attrs[k] = v[0]
		}
	}
	meta, _ := m.Metadata()
	id := ""
	if meta != nil {
		id = fmt.Sprintf("%s:%d", meta.Stream, meta.Sequence.Stream)
	}
	msg := &port.Message{
		ID:         id,
		Data:       m.Data(),
		Attributes: attrs,
		Ack:        func() { _ = m.Ack() },
		Nack:       func() { _ = m.NakWithDelay(natsBackoff) },
	}
	if err := handler(ctx, msg); err != nil {
		// NakWithDelay tells JetStream to wait `natsBackoff` before
		// re-delivering — the default Nak() retries immediately and
		// turns a sustained handler failure into a tight loop that
		// blocks all other in-flight messages (P1-20).
		_ = m.NakWithDelay(natsBackoff)
		return
	}
	_ = m.Ack()
}

func (s *NATSSubscriber) Close() error {
	if s.nc != nil {
		s.nc.Close()
	}
	return nil
}
