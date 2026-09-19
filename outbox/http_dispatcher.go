package outbox

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/nauticana/keel/clock"
	"github.com/nauticana/keel/secret"
)

// WebhookDestination is where one event goes. PartnerID must equal the event's:
// a resolver that answers with another partner's endpoint is refused unsent.
type WebhookDestination struct {
	PartnerID int64
	URL       string
	SecretRef string // path handed to secret.SecretProvider; never the secret itself
}

// WebhookDestinationResolver maps an event to exactly one destination. Enqueue
// one outbox row per subscriber so each retries and dead-letters on its own.
// Wrap the error with Permanent when no retry can help (subscription removed).
type WebhookDestinationResolver interface {
	ResolveWebhookDestination(ctx context.Context, e Event) (WebhookDestination, error)
}

// WebhookEnvelope is the JSON request body. Ids are strings: they are bigint and
// would lose precision as JSON numbers.
type WebhookEnvelope struct {
	ID            int64           `json:"id,string"`
	Type          string          `json:"type"`
	AggregateType string          `json:"aggregateType"`
	AggregateID   string          `json:"aggregateId"`
	PartnerID     int64           `json:"partnerId,string"`
	Payload       json.RawMessage `json:"payload"`
}

type HTTPDispatcherConfig struct {
	Resolver WebhookDestinationResolver
	Secrets  secret.SecretProvider
	Egress   EgressPolicy
	Timeout  time.Duration // whole delivery attempt; 0 → 10s. Keep below the worker's LeaseTTL.
	TLS      *tls.Config   // nil → system roots
	Clock    clock.Clock   // nil → system time
}

const (
	webhookTimeout      = 10 * time.Second
	webhookResponseCap  = 64 << 10
	webhookUserAgent    = "keel-outbox-webhook/1"
	webhookDialTimeout  = 5 * time.Second
	webhookIdleConnTime = 90 * time.Second
)

// HTTPDispatcher delivers events as signed HTTPS POSTs. 2xx is delivered;
// 408/425/429/5xx and transport failures retry; every other status, a redirect,
// an egress rejection or a partner mismatch is a PermanentError. Redirects are
// never followed, so the signed request cannot be bounced to another host.
type HTTPDispatcher struct {
	resolver WebhookDestinationResolver
	secrets  secret.SecretProvider
	egress   EgressPolicy
	clock    clock.Clock
	client   *http.Client
}

var _ Dispatcher = (*HTTPDispatcher)(nil)

func NewHTTPDispatcher(cfg HTTPDispatcherConfig) (*HTTPDispatcher, error) {
	if cfg.Resolver == nil {
		return nil, errors.New("outbox: HTTPDispatcher needs a Resolver")
	}
	if cfg.Secrets == nil {
		return nil, errors.New("outbox: HTTPDispatcher needs Secrets")
	}
	if len(cfg.Egress.AllowedHosts) == 0 {
		return nil, errors.New("outbox: HTTPDispatcher needs a non-empty Egress.AllowedHosts")
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = webhookTimeout
	}
	if cfg.Clock == nil {
		cfg.Clock = clock.System{}
	}
	dialer := &net.Dialer{Timeout: webhookDialTimeout, Control: cfg.Egress.dialControl}
	return &HTTPDispatcher{
		resolver: cfg.Resolver,
		secrets:  cfg.Secrets,
		egress:   cfg.Egress,
		clock:    cfg.Clock,
		client: &http.Client{
			Timeout: cfg.Timeout,
			// No proxy: dialControl must see the destination's own address.
			Transport: &http.Transport{
				DialContext:         dialer.DialContext,
				TLSClientConfig:     cfg.TLS,
				TLSHandshakeTimeout: webhookDialTimeout,
				IdleConnTimeout:     webhookIdleConnTime,
				ForceAttemptHTTP2:   true,
			},
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}, nil
}

func (d *HTTPDispatcher) Dispatch(ctx context.Context, e Event) error {
	if e.Id <= 0 || e.PartnerID <= 0 {
		return Permanent(fmt.Errorf("outbox webhook: event %d is not partner-scoped", e.Id))
	}
	dest, err := d.resolver.ResolveWebhookDestination(ctx, e)
	if err != nil {
		return fmt.Errorf("outbox webhook: resolve destination: %w", err)
	}
	if dest.PartnerID != e.PartnerID {
		return Permanent(fmt.Errorf("outbox webhook: destination belongs to partner %d, event to %d", dest.PartnerID, e.PartnerID))
	}
	target, err := url.Parse(dest.URL)
	if err != nil {
		return Permanent(errors.New("outbox webhook: malformed destination URL"))
	}
	if err := d.egress.checkURL(target); err != nil {
		return Permanent(err)
	}
	body, err := envelopeJSON(e)
	if err != nil {
		return Permanent(err)
	}
	secretValue, err := d.secrets.GetSecret(ctx, dest.SecretRef)
	if err != nil {
		return fmt.Errorf("outbox webhook: resolve signing secret: %w", err)
	}
	key, err := signingKey(secretValue)
	if err != nil {
		return err
	}

	id := strconv.FormatInt(e.Id, 10)
	timestamp := strconv.FormatInt(d.clock.Now().Unix(), 10)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target.String(), bytes.NewReader(body))
	if err != nil {
		return Permanent(errors.New("outbox webhook: malformed destination URL"))
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", webhookUserAgent)
	req.Header.Set("Idempotency-Key", id)
	req.Header.Set(HeaderWebhookID, id)
	req.Header.Set(HeaderWebhookTimestamp, timestamp)
	req.Header.Set(HeaderWebhookSignature, signWebhook(key, id, timestamp, body))

	resp, err := d.client.Do(req)
	if err != nil {
		return transportError(target.Host, err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, webhookResponseCap))
	return classifyStatus(target.Host, resp.StatusCode)
}

func envelopeJSON(e Event) ([]byte, error) {
	payload := json.RawMessage("null")
	if e.Payload != "" {
		if !json.Valid([]byte(e.Payload)) {
			return nil, fmt.Errorf("outbox webhook: event %d payload is not valid JSON", e.Id)
		}
		payload = json.RawMessage(e.Payload)
	}
	return json.Marshal(WebhookEnvelope{
		ID:            e.Id,
		Type:          e.EventType,
		AggregateType: e.AggregateType,
		AggregateID:   e.AggregateID,
		PartnerID:     e.PartnerID,
		Payload:       payload,
	})
}

// transportError drops the *url.Error wrapper: its message carries the full
// URL, whose path or query may hold a receiver token, into outbox_event.last_error.
func transportError(host string, err error) error {
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		err = urlErr.Err
	}
	err = fmt.Errorf("outbox webhook %s: %w", host, err)
	if errors.Is(err, ErrEgressDenied) {
		return Permanent(err)
	}
	return err
}

func classifyStatus(host string, status int) error {
	switch {
	case status >= 200 && status < 300:
		return nil
	case status == http.StatusRequestTimeout, status == http.StatusTooEarly,
		status == http.StatusTooManyRequests, status >= 500:
		return fmt.Errorf("outbox webhook %s: HTTP %d", host, status)
	default:
		return Permanent(fmt.Errorf("outbox webhook %s: HTTP %d", host, status))
	}
}
