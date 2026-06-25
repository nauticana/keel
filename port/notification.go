package port

import "context"

type NotificationSender interface {
	SendEmail(ctx context.Context, to, subject, body string) error
	SendSMS(ctx context.Context, to, body string) error
}

type NotificationRequest struct {
	UserID int
	// To, when set, is an explicit channel address (email / phone / device token)
	// delivered via MessageDispatcher.Send, bypassing userID resolution. Leave it
	// empty to resolve the address from UserID via Dispatch. For SMS to a national
	// number, pass the ISO region in Data["country"] so it normalizes to E.164.
	To      string
	Type    string
	Channel string
	Title   string
	Body    string
	Data    map[string]string
}

type NotificationService interface {
	Send(ctx context.Context, req NotificationRequest) error
}
