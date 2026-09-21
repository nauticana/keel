package dispatcher

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/nauticana/keel/model"
	"github.com/nauticana/keel/port"
)

// Channels keel ships an address-based dispatcher for. Suppression is checked
// on the contact these resolve to; a channel addressed by something other than
// a contact (InboxChannel, push device tokens) has nothing to suppress.
const (
	EmailChannel = "email"
	SMSChannel   = "sms"
)

// LocalNotificationService is the keel-shipped implementation of
// port.NotificationService. It holds a channel-keyed registry of
// MessageDispatcher implementations and routes each Send call to the
// dispatcher matching req.Channel. Consumers register one dispatcher per
// channel at startup:
//
//	notif := service.NewLocalNotificationService()
//	notif.Register("email", &service.EmailDispatcher{Mail: mailClient, Users: userSvc})
//	notif.Register("push",  fcmProvider)            // FCMPushProvider satisfies MessageDispatcher
//	notif.Register("sms",   smsDispatcher)          // dispatcher.NewSMSDispatcher(...)
//
// Send returns a typed error when the channel is not registered so the
// caller can distinguish "no dispatcher configured" from "dispatcher
// failed". Concurrent Register and Send are safe.
//
// Suppressor, Recipients and Ledger are optional and set after construction:
//
//	notif.Suppressor = &dispatcher.SuppressionService{DB: db}
//	notif.Recipients = userService // resolves a userID to its email/phone
//	notif.Ledger     = ledger      // collapses repeats under NotificationRequest.DedupeKey
type LocalNotificationService struct {
	// Suppressor, when set, is consulted before every delivery to a resolvable
	// contact; a suppressed recipient is refused with port.ErrNotificationSuppressed.
	Suppressor port.NotificationSuppressor
	// Recipients resolves a request carrying only a UserID to the contact the
	// suppression check needs. Without it, only an explicit To is checked.
	Recipients port.RecipientResolver
	// Ledger backs DedupeKey. Without it, a DedupeKey is inert.
	Ledger port.IdempotencyLedger

	mu          sync.RWMutex
	dispatchers map[string]port.MessageDispatcher
}

// Compile-time check: LocalNotificationService satisfies port.NotificationService.
var _ port.NotificationService = (*LocalNotificationService)(nil)

// NewLocalNotificationService returns a notification service with no
// dispatchers registered. Call Register at app startup for each channel
// the deployment supports.
func NewLocalNotificationService() *LocalNotificationService {
	return &LocalNotificationService{dispatchers: make(map[string]port.MessageDispatcher)}
}

// Register binds a MessageDispatcher to a channel name. Re-registering
// the same channel overwrites the previous dispatcher — useful for tests.
// Empty channel or nil dispatcher is silently ignored.
func (s *LocalNotificationService) Register(channel string, d port.MessageDispatcher) {
	if channel == "" || d == nil {
		return
	}
	s.mu.Lock()
	s.dispatchers[channel] = d
	s.mu.Unlock()
}

// Channels returns the sorted list of registered channel names. Useful
// for diagnostics and admin endpoints.
func (s *LocalNotificationService) Channels() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]string, 0, len(s.dispatchers))
	for k := range s.dispatchers {
		out = append(out, k)
	}
	return out
}

// Send routes the request to the dispatcher registered under req.Channel,
// after refusing a suppressed recipient and a repeat of an already-sent
// DedupeKey. Returns a wrapped error when the channel is unknown so callers can
// detect "channel not configured" without string-matching.
func (s *LocalNotificationService) Send(ctx context.Context, req port.NotificationRequest) error {
	if req.Channel == "" {
		return fmt.Errorf("notification: empty channel in request")
	}
	s.mu.RLock()
	d, ok := s.dispatchers[req.Channel]
	s.mu.RUnlock()
	if !ok {
		return fmt.Errorf("notification: no dispatcher registered for channel %q", req.Channel)
	}
	if err := s.checkSuppressed(ctx, req); err != nil {
		return err
	}
	return s.deduped(ctx, req, func() error { return s.deliver(ctx, d, req) })
}

func (s *LocalNotificationService) deliver(ctx context.Context, d port.MessageDispatcher, req port.NotificationRequest) error {
	// An explicit address routes to Send (no userID resolution); otherwise
	// resolve the recipient from UserID via Dispatch.
	if req.To != "" {
		return d.Send(ctx, req.To, req.Title, req.Body, req.Data)
	}
	if inbox, ok := d.(port.NotificationInbox); ok {
		_, err := inbox.Add(ctx, req.UserID, req.Type, req.Title, req.Body, req.Data)
		return err
	}
	return d.Dispatch(ctx, req.UserID, req.Title, req.Body, req.Data)
}

// checkSuppressed refuses a delivery to a suppressed contact. A contact that
// cannot be determined — no explicit To and no resolver, or a channel not
// addressed by a contact — is not suppressible and passes.
func (s *LocalNotificationService) checkSuppressed(ctx context.Context, req port.NotificationRequest) error {
	if s.Suppressor == nil {
		return nil
	}
	contact, err := s.contactFor(req)
	if err != nil {
		return err
	}
	if contact == "" {
		return nil
	}
	suppressed, reason, err := s.Suppressor.Suppressed(ctx, req.Channel, contact, req.PartnerID)
	if err != nil {
		return fmt.Errorf("notification: suppression check: %w", err)
	}
	if suppressed {
		return &port.SuppressedError{Channel: req.Channel, Reason: reason}
	}
	return nil
}

// contactFor is the address the request will be delivered to, as far as the
// service can tell before handing it to the dispatcher.
func (s *LocalNotificationService) contactFor(req port.NotificationRequest) (string, error) {
	if req.Channel != EmailChannel && req.Channel != SMSChannel {
		return "", nil
	}
	if req.To != "" {
		return req.To, nil
	}
	if s.Recipients == nil || req.UserID <= 0 {
		return "", nil
	}
	var (
		contact string
		err     error
	)
	switch req.Channel {
	case EmailChannel:
		contact, err = s.Recipients.EmailFor(req.UserID)
	case SMSChannel:
		contact, err = s.Recipients.PhoneFor(req.UserID)
	}
	if err != nil {
		return "", fmt.Errorf("notification: resolve %s recipient for user %d: %w", req.Channel, req.UserID, err)
	}
	return contact, nil
}

// deduped runs send once per DedupeKey. The claim is released when the delivery
// fails, so a transport error stays retryable; only a delivered notification
// blocks the repeat.
func (s *LocalNotificationService) deduped(ctx context.Context, req port.NotificationRequest, send func() error) error {
	if s.Ledger == nil || req.DedupeKey == "" {
		return send()
	}
	key := "notification:" + req.Channel + ":" + req.DedupeKey
	entry, err := s.Ledger.Begin(ctx, key)
	if err != nil {
		return fmt.Errorf("notification: dedupe %q: %w", req.DedupeKey, err)
	}
	if entry.State != model.LedgerNew {
		return fmt.Errorf("%w: %s", port.ErrNotificationDuplicate, req.DedupeKey)
	}
	if err := send(); err != nil {
		return errors.Join(err, s.Ledger.Release(ctx, key, entry.Fence))
	}
	if err := s.Ledger.Complete(ctx, key, entry.Fence, []byte(req.Channel)); err != nil {
		return errors.Join(err, s.Ledger.MarkUnknown(ctx, key, entry.Fence))
	}
	return nil
}
