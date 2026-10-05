package user

import (
	"context"
)

// MailSender is the mail transport the registration flow needs.
// dispatcher.MailClient satisfies it; dispatcher imports user, so user must
// not import dispatcher.
type MailSender interface {
	SendEmail(ctx context.Context, subject string, body string, recipients []string, headers map[string]string) error
}
