package dispatcher

import (
	"context"
	"testing"

	"github.com/nauticana/keel/port"
)

// recordingDispatcher records which interface method the router invoked.
type recordingDispatcher struct {
	method string
	to     string
	userID int
}

func (r *recordingDispatcher) Dispatch(_ context.Context, userID int, _, _ string, _ map[string]string) error {
	r.method, r.userID = "Dispatch", userID
	return nil
}

func (r *recordingDispatcher) Send(_ context.Context, to, _, _ string, _ map[string]string) error {
	r.method, r.to = "Send", to
	return nil
}

var _ port.MessageDispatcher = (*recordingDispatcher)(nil)

func TestLocalNotificationService_RoutesByTo(t *testing.T) {
	rec := &recordingDispatcher{}
	notif := NewLocalNotificationService()
	notif.Register("sms", rec)

	// An explicit To routes to Send.
	if err := notif.Send(context.Background(), port.NotificationRequest{
		Channel: "sms", To: "+15551234567", Body: "hi",
	}); err != nil {
		t.Fatalf("Send with To: %v", err)
	}
	if rec.method != "Send" || rec.to != "+15551234567" {
		t.Fatalf("explicit To: got method=%q to=%q, want Send / +15551234567", rec.method, rec.to)
	}

	// No To falls back to userID resolution via Dispatch.
	if err := notif.Send(context.Background(), port.NotificationRequest{
		Channel: "sms", UserID: 42, Body: "hi",
	}); err != nil {
		t.Fatalf("Send without To: %v", err)
	}
	if rec.method != "Dispatch" || rec.userID != 42 {
		t.Fatalf("no To: got method=%q userID=%d, want Dispatch / 42", rec.method, rec.userID)
	}

	// Unknown channel still errors.
	if err := notif.Send(context.Background(), port.NotificationRequest{Channel: "carrier-pigeon"}); err == nil {
		t.Fatal("unknown channel: want error, got nil")
	}
}

type recordingInbox struct {
	recordingDispatcher
	port.NotificationInbox
	addedType string
}

func (r *recordingInbox) Add(_ context.Context, _ int, notificationType, _, _ string, _ map[string]string) (int64, error) {
	r.addedType = notificationType
	return 1, nil
}

func TestLocalNotificationService_InboxKeepsType(t *testing.T) {
	inbox := &recordingInbox{}
	notif := NewLocalNotificationService()
	notif.Register(InboxChannel, inbox)
	if err := notif.Send(context.Background(), port.NotificationRequest{
		Channel: InboxChannel, UserID: 7, Type: "S", Title: "hello",
	}); err != nil {
		t.Fatal(err)
	}
	if inbox.addedType != "S" || inbox.method != "" {
		t.Fatalf("type = %q, dispatcher method = %q", inbox.addedType, inbox.method)
	}
}
