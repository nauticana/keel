package user

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/nauticana/keel/model"
)

var errNoEmail = errors.New("user: account has no email address")

// MailSignInNotifier sends sign-in notices and step-up codes by email.
type MailSignInNotifier struct {
	Mail  MailSender
	Brand string // product name in subjects; empty is brand-less
}

var _ SignInNotifier = (*MailSignInNotifier)(nil)

func (n *MailSignInNotifier) NewDeviceSignIn(ctx context.Context, account *model.UserSession, device SessionDevice) error {
	var b strings.Builder
	b.WriteString("Your account was signed in from a new device.\n\n")
	b.WriteString("Time: " + time.Now().UTC().Format(time.RFC1123) + "\n")
	if device.ClientIP != "" {
		b.WriteString("Address: " + device.ClientIP + "\n")
	}
	if device.UserAgent != "" {
		b.WriteString("Device: " + device.UserAgent + "\n")
	}
	b.WriteString("\nIf this was not you, sign out that session and change your password.\n")
	return n.send(ctx, account, "New sign-in", b.String())
}

func (n *MailSignInNotifier) StepUpCode(ctx context.Context, account *model.UserSession, code string) error {
	return n.send(ctx, account, "Sign-in code", "Your sign-in code is "+code+".\n\nIf you did not try to sign in, change your password.\n")
}

func (n *MailSignInNotifier) send(ctx context.Context, account *model.UserSession, subject, body string) error {
	if n == nil || n.Mail == nil {
		return ErrStepUpUnavailable
	}
	if account == nil || account.Email == "" {
		return errNoEmail
	}
	if n.Brand != "" {
		subject = n.Brand + ": " + subject
	}
	return n.Mail.SendEmail(ctx, subject, body, []string{account.Email}, nil)
}
