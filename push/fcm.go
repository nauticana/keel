package push

import (
	"context"
	"fmt"

	firebase "firebase.google.com/go/v4"
	"firebase.google.com/go/v4/messaging"

	"github.com/nauticana/keel/dispatcher"
	"github.com/nauticana/keel/logger"
	"github.com/nauticana/keel/user"
)

// FCMPushProvider dispatches notifications via Firebase Cloud Messaging.
// iOS devices can register FCM tokens through Firebase's APNs integration
// — one provider covers both platforms. Stale tokens returned by FCM
// (registration-token-not-registered) are deactivated automatically via
// the injected UserService so the next Dispatch call skips them.
//
// Construct via New or via the factory (selected by --push_mode=fcm).
// Requires GOOGLE_APPLICATION_CREDENTIALS or running inside GCP.
type FCMPushProvider struct {
	client  *messaging.Client
	users   user.UserService
	journal logger.ApplicationLogger
}

// New builds an FCMPushProvider using default GCP credentials. Returns
// error when Firebase cannot initialize (missing creds, bad project,
// network). Callers typically wrap this in a factory that falls back to
// NoOpPushProvider on error so the app can still boot without FCM creds.
func New(ctx context.Context, users user.UserService, journal logger.ApplicationLogger) (*FCMPushProvider, error) {
	app, err := firebase.NewApp(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("push: init firebase app: %w", err)
	}
	client, err := app.Messaging(ctx)
	if err != nil {
		return nil, fmt.Errorf("push: init FCM client: %w", err)
	}
	return &FCMPushProvider{client: client, users: users, journal: journal}, nil
}

// Dispatch sends one MulticastMessage to every active device token for
// userID. Tokens rejected as unregistered are deactivated so they stop
// receiving attempts on subsequent calls. Zero active tokens is not an
// error — it's "nobody to notify".
func (p *FCMPushProvider) Dispatch(ctx context.Context, userID int, title, body string, data map[string]string) error {
	devices, err := p.users.ListActiveDeviceTokens(userID)
	if err != nil {
		return fmt.Errorf("push: list tokens for user %d: %w", userID, err)
	}
	if len(devices) == 0 {
		return nil
	}

	tokens := make([]string, len(devices))
	for i, d := range devices {
		tokens[i] = d.Token
	}

	msg := &messaging.MulticastMessage{
		Tokens: tokens,
		Notification: &messaging.Notification{
			Title: title,
			Body:  body,
		},
		Data: data,
	}

	resp, err := p.client.SendEachForMulticast(ctx, msg)
	if err != nil {
		return fmt.Errorf("push: FCM send for user %d: %w", userID, err)
	}

	// Revoke tokens that FCM tells us are unusable. Two distinct
	// signals deserve revocation (P1-32):
	//   - IsRegistrationTokenNotRegistered: the device uninstalled
	//     the app or otherwise dropped the token. Token will never
	//     succeed again.
	//   - IsInvalidArgument: the stored value isn't a valid FCM
	//     token string (most often produced when the client posted
	//     a bare APNs token instead of going through Firebase).
	//     Same outcome — never going to deliver — so revoke.
	// Other transient errors (Internal, Unavailable, Quota) are
	// retryable upstream and must NOT trigger revoke.
	revokedAny := 0
	for i, sendResp := range resp.Responses {
		if sendResp.Error == nil {
			continue
		}
		if messaging.IsRegistrationTokenNotRegistered(sendResp.Error) ||
			messaging.IsInvalidArgument(sendResp.Error) {
			if revokeErr := p.users.RevokeDeviceToken(userID, tokens[i]); revokeErr != nil && p.journal != nil {
				p.journal.Info(fmt.Sprintf("push: failed to deactivate stale token for user %d: %v", userID, revokeErr))
			}
			revokedAny++
		}
	}
	if revokedAny > 0 && p.journal != nil {
		p.journal.Info(fmt.Sprintf("push: deactivated %d stale token(s) for user %d", revokedAny, userID))
	}

	if p.journal != nil {
		p.journal.Info(fmt.Sprintf("push: sent to user %d (%d/%d delivered)", userID, resp.SuccessCount, len(tokens)))
	}
	return nil
}

var _ dispatcher.MessageDispatcher = (*FCMPushProvider)(nil)
