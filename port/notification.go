package port

import "context"

type NotificationSender interface {
	SendEmail(ctx context.Context, to, subject, body string) error
	SendSMS(ctx context.Context, to, body string) error
}

type NotificationRequest struct {
	UserID  int
	Type    string
	Channel string
	Title   string
	Body    string
	Data    map[string]string
}

type NotificationService interface {
	Send(ctx context.Context, req NotificationRequest) error
}
