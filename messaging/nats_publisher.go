package messaging

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/nauticana/keel/common"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

// NATS configuration:
//
//	--nats_url    — NATS server URL flag (keel common). Comma-separated for clustered deployments. Falls back to nats.DefaultURL.
//	NATS_CREDS    — env. Optional path to a credentials file (Synadia Cloud).
//	NATS_NAME     — env. Optional client name surfaced in NATS observability.
const (
	natsDefaultFetch      = 16
	natsFetchTimeout      = 2 * time.Second
	natsDefaultAckWait    = 30 * time.Second
	natsDefaultMaxDeliver = 3

	// natsDefaultMaxAckPending bounds the number of in-flight (unacked) messages a single durable consumer can hold.
	natsDefaultMaxAckPending = 256

	// natsBackoff is the wait between Nak and redelivery on handler failure. JetStream's default of zero retries immediately,
	// which in a sustained-failure scenario amounts to a tight loop that also blocks any other in-flight messages on the consumer.
	natsBackoff = 5 * time.Second

	// natsConnectTimeout caps the initial dial / handshake. Without nats.Connect will sit on a misconfigured URL
	// until the OS connect timeout (~75s on Linux) — long enough that a stuck server defers startup readiness past
	// most container schedulers' patience window (P2-14).
	natsConnectTimeout = 10 * time.Second
)

// NATSConnect opens a connection using the standard keel NATS configuration.
// Connect attempt is bounded by natsConnectTimeout so a hung server can't stall startup indefinitely (P2-14).
// Once connected, the nats.MaxReconnects(-1) + nats.ReconnectWait(2s) options take over for runtime resilience.
func NATSConnect() (*nats.Conn, error) {
	url := strings.TrimSpace(*common.NatsURL)
	if url == "" {
		url = nats.DefaultURL
	}
	opts := []nats.Option{
		nats.MaxReconnects(-1),
		nats.ReconnectWait(2 * time.Second),
		nats.Timeout(natsConnectTimeout),
	}
	if name := strings.TrimSpace(os.Getenv("NATS_NAME")); name != "" {
		opts = append(opts, nats.Name(name))
	}
	if creds := os.Getenv("NATS_CREDS"); creds != "" {
		opts = append(opts, nats.UserCredentials(creds))
	}
	nc, err := nats.Connect(url, opts...)
	if err != nil {
		return nil, fmt.Errorf("nats: connect %s: %w", url, err)
	}
	return nc, nil
}

// streamName derives a JetStream stream name from a topic/subject.
// `ride.completed` → `RIDE`, `notification.dispatch` → `NOTIFICATION`.
// All subjects that share a first segment share a stream, which matches
// Pub/Sub's one-topic-per-name semantics while letting per-entity subjects
// like `ride.<id>.completed` coexist under the same stream.
func streamName(topic string) string {
	head, _, _ := strings.Cut(topic, ".")
	if head == "" {
		head = topic
	}
	return strings.ToUpper(head)
}

// subjectFilter returns the wildcard subject a stream should cover.
func subjectFilter(topic string) string {
	head, _, _ := strings.Cut(topic, ".")
	if head == "" {
		return topic
	}
	return head + ".>"
}

// NATSPublisher publishes to a JetStream-backed subject.
// Streams are created lazily on first publish per first-segment prefix.
//
// Concurrency model: Publish may be called from many goroutines. The
// streams cache is therefore guarded by a mutex; without it, concurrent
// publishes on previously-unseen subjects would race on the map and
// crash with "concurrent map read and map write".
type NATSPublisher struct {
	nc *nats.Conn
	js jetstream.JetStream

	streamsMu sync.Mutex
	streams   map[string]bool
}

func (p *NATSPublisher) ensureStream(ctx context.Context, topic string) error {
	name := streamName(topic)
	// Fast path: stream already known. Holding the mutex across the
	// lookup is fine — the map is touched on every publish but the
	// fast path is a single read, so contention is negligible.
	p.streamsMu.Lock()
	known := p.streams[name]
	p.streamsMu.Unlock()
	if known {
		return nil
	}
	// Slow path: actually create/update the stream against JetStream,
	// then mark it known. CreateOrUpdateStream is idempotent so two
	// goroutines hitting the slow path simultaneously is harmless.
	// LimitsPolicy + per-consumer durables provides Pub/Sub fan-out
	// semantics — every subscriber group sees every message. The
	// previous WorkQueuePolicy delivered each message to exactly one
	// consumer, which is the load-balanced model — useful, but not
	// what the port.MessagePublisher contract advertises and not
	// what consumers porting from GCP Pub/Sub expect (P1-19).
	_, err := p.js.CreateOrUpdateStream(ctx, jetstream.StreamConfig{
		Name:      name,
		Subjects:  []string{subjectFilter(topic)},
		Retention: jetstream.LimitsPolicy,
		Storage:   jetstream.FileStorage,
		MaxAge:    7 * 24 * time.Hour,
	})
	if err != nil {
		// JetStream rejects retention transitions on existing streams
		// (e.g. an old WorkQueuePolicy stream surviving a keel
		// upgrade). Detect that by looking up the stream — if it
		// exists, we treat it as usable as-is and continue
		// publishing; the operator can recreate it offline if they
		// want the new retention semantics. Without this fallback
		// (MAJOR 6) every publish on a pre-existing stream fails
		// forever after a keel bump.
		if _, lookupErr := p.js.Stream(ctx, name); lookupErr == nil {
			fmt.Fprintf(os.Stderr,
				"nats: stream %q exists with a different config than keel would create; "+
					"using as-is. Recreate manually for the new retention policy. underlying err: %v\n",
				name, err)
			p.streamsMu.Lock()
			p.streams[name] = true
			p.streamsMu.Unlock()
			return nil
		}
		return fmt.Errorf("nats: ensure stream %s: %w", name, err)
	}
	p.streamsMu.Lock()
	p.streams[name] = true
	p.streamsMu.Unlock()
	return nil
}

func (p *NATSPublisher) Publish(ctx context.Context, topic string, data []byte, attributes map[string]string) error {
	if err := p.ensureStream(ctx, topic); err != nil {
		return err
	}
	msg := &nats.Msg{Subject: topic, Data: data, Header: nats.Header{}}
	for k, v := range attributes {
		msg.Header.Set(k, v)
	}
	if _, err := p.js.PublishMsg(ctx, msg); err != nil {
		return fmt.Errorf("nats: publish %s: %w", topic, err)
	}
	return nil
}

func (p *NATSPublisher) Close() error {
	if p.nc != nil {
		p.nc.Close()
	}
	return nil
}
