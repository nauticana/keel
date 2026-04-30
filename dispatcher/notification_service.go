package dispatcher

import (
	"context"
	"fmt"
	"sync"

	"github.com/nauticana/keel/port"
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
//	notif.Register("sms",   twilioDispatcher)       // consumer-supplied
//
// Send returns a typed error when the channel is not registered so the
// caller can distinguish "no dispatcher configured" from "dispatcher
// failed". Concurrent Register and Send are safe.
type LocalNotificationService struct {
	mu          sync.RWMutex
	dispatchers map[string]MessageDispatcher
}

// Compile-time check: LocalNotificationService satisfies port.NotificationService.
var _ port.NotificationService = (*LocalNotificationService)(nil)

// NewLocalNotificationService returns a notification service with no
// dispatchers registered. Call Register at app startup for each channel
// the deployment supports.
func NewLocalNotificationService() *LocalNotificationService {
	return &LocalNotificationService{dispatchers: make(map[string]MessageDispatcher)}
}

// Register binds a MessageDispatcher to a channel name. Re-registering
// the same channel overwrites the previous dispatcher — useful for tests.
// Empty channel or nil dispatcher is silently ignored.
func (s *LocalNotificationService) Register(channel string, d MessageDispatcher) {
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

// Send routes the request to the dispatcher registered under req.Channel.
// Returns a wrapped error when the channel is unknown so callers can
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
	return d.Dispatch(ctx, req.UserID, req.Title, req.Body, req.Data)
}
