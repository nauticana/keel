package dispatcher

import (
	"context"
	"fmt"
	"strings"

	"github.com/nauticana/keel/port"
)

// EmailDispatcher adapts the concrete MailClient to the channel-keyed
// MessageDispatcher contract so it can plug into LocalNotificationService
// alongside push, sms, and any future channels. Resolves userID ->
// email via the narrow port.RecipientResolver port; sends via
// MailClient.SendEmail.
//
// As of v0.5 the EmailDispatcher depends on port.RecipientResolver
// instead of the full user.UserService surface. Any value satisfying
// EmailFor(userID) (string, error) plugs in — typically the
// LocalUserService which now implements RecipientResolver, but
// downstream consumers can wire a thinner address-only resolver to
// keep the user package out of dispatcher's import graph.
//
// Returns nil when the user has no usable email (deleted account, social
// account that never set one) — the channel-level "nobody to notify" no-op.
// Returns a wrapped error for transport failures the caller should retry.
type EmailDispatcher struct {
	Mail  *MailClient
	Users port.RecipientResolver
}

// Compile-time check: EmailDispatcher satisfies port.MessageDispatcher.
var _ MessageDispatcher = (*EmailDispatcher)(nil)

// Dispatch sends a single notification email to the user. The body
// argument is treated as plain text; callers that need HTML should send
// directly via MailClient.SendEmailHTML and skip the dispatcher.
func (d *EmailDispatcher) Dispatch(ctx context.Context, userID int, title, body string, _ map[string]string) error {
	if d.Mail == nil || d.Users == nil {
		return fmt.Errorf("EmailDispatcher: Mail and Users must be set")
	}
	to, err := d.Users.EmailFor(userID)
	if err != nil {
		return fmt.Errorf("email: lookup user %d: %w", userID, err)
	}
	to = strings.TrimSpace(to)
	if to == "" {
		return nil
	}
	if err := d.Mail.SendEmail(ctx, title, body, []string{to}); err != nil {
		return fmt.Errorf("email: send to user %d: %w", userID, err)
	}
	return nil
}
