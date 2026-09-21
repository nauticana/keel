package dispatcher

import (
	"context"
	"errors"
	"testing"

	"github.com/nauticana/keel/model"
	"github.com/nauticana/keel/port"
)

// --- test doubles -----------------------------------------------------------

type fakeSuppressor struct {
	suppressed map[string]string // channel|contact -> reason
	gotPartner int64
	err        error
}

func (f *fakeSuppressor) Suppressed(_ context.Context, channel, contact string, partnerID int64) (bool, string, error) {
	f.gotPartner = partnerID
	if f.err != nil {
		return false, "", f.err
	}
	reason, ok := f.suppressed[channel+"|"+contact]
	return ok, reason, nil
}

type fakeRecipients struct {
	email, phone string
	err          error
}

func (f *fakeRecipients) EmailFor(int) (string, error) { return f.email, f.err }
func (f *fakeRecipients) PhoneFor(int) (string, error) { return f.phone, f.err }

// fakeLedger is a minimal in-memory IdempotencyLedger.
type fakeLedger struct {
	states      map[string]model.LedgerState
	completed   []string
	released    []string
	unknown     []string
	completeErr error
}

func newLedger() *fakeLedger { return &fakeLedger{states: map[string]model.LedgerState{}} }

func (l *fakeLedger) Begin(_ context.Context, key string) (model.LedgerEntry, error) {
	if state, ok := l.states[key]; ok {
		return model.LedgerEntry{State: state}, nil
	}
	l.states[key] = model.LedgerInFlight
	return model.LedgerEntry{State: model.LedgerNew, Fence: "F"}, nil
}
func (l *fakeLedger) Renew(context.Context, string, string) error { return nil }
func (l *fakeLedger) Complete(_ context.Context, key, _ string, _ []byte) error {
	if l.completeErr != nil {
		return l.completeErr
	}
	l.states[key] = model.LedgerCompleted
	l.completed = append(l.completed, key)
	return nil
}
func (l *fakeLedger) Release(_ context.Context, key, _ string) error {
	delete(l.states, key)
	l.released = append(l.released, key)
	return nil
}
func (l *fakeLedger) MarkUnknown(_ context.Context, key, _ string) error {
	l.states[key] = model.LedgerUnknown
	l.unknown = append(l.unknown, key)
	return nil
}

var (
	_ port.NotificationSuppressor = (*fakeSuppressor)(nil)
	_ port.RecipientResolver      = (*fakeRecipients)(nil)
	_ port.IdempotencyLedger      = (*fakeLedger)(nil)
)

// --- suppression ------------------------------------------------------------

func TestSendRefusesSuppressedAddress(t *testing.T) {
	rec := &recordingDispatcher{}
	notif := NewLocalNotificationService()
	notif.Register(EmailChannel, rec)
	notif.Suppressor = &fakeSuppressor{suppressed: map[string]string{"email|gone@x.test": SuppressBounced}}

	err := notif.Send(context.Background(), port.NotificationRequest{
		Channel: EmailChannel, To: "gone@x.test", PartnerID: 7, Title: "hi",
	})
	if !errors.Is(err, port.ErrNotificationSuppressed) {
		t.Fatalf("err = %v, want ErrNotificationSuppressed", err)
	}
	var suppressed *port.SuppressedError
	if !errors.As(err, &suppressed) || suppressed.Reason != SuppressBounced {
		t.Fatalf("err = %v, want the reason", err)
	}
	if rec.method != "" {
		t.Error("a suppressed recipient must not reach the dispatcher")
	}
}

// The suppression check must see the address the dispatcher would resolve, not
// just an explicit To — otherwise a userID send bypasses the list entirely.
func TestSendResolvesContactForSuppression(t *testing.T) {
	rec := &recordingDispatcher{}
	notif := NewLocalNotificationService()
	notif.Register(SMSChannel, rec)
	sup := &fakeSuppressor{suppressed: map[string]string{"sms|+15550001111": SuppressUnsubscribed}}
	notif.Suppressor = sup
	notif.Recipients = &fakeRecipients{phone: "+15550001111"}

	err := notif.Send(context.Background(), port.NotificationRequest{
		Channel: SMSChannel, UserID: 42, PartnerID: 9, Title: "hi",
	})
	if !errors.Is(err, port.ErrNotificationSuppressed) {
		t.Fatalf("err = %v, want ErrNotificationSuppressed", err)
	}
	if sup.gotPartner != 9 {
		t.Errorf("partner scope = %d, want 9", sup.gotPartner)
	}
	if rec.method != "" {
		t.Error("a suppressed recipient must not reach the dispatcher")
	}
}

func TestSendDeliversUnsuppressed(t *testing.T) {
	rec := &recordingDispatcher{}
	notif := NewLocalNotificationService()
	notif.Register(EmailChannel, rec)
	notif.Suppressor = &fakeSuppressor{suppressed: map[string]string{"email|other@x.test": SuppressBounced}}

	if err := notif.Send(context.Background(), port.NotificationRequest{
		Channel: EmailChannel, To: "ok@x.test", Title: "hi",
	}); err != nil {
		t.Fatal(err)
	}
	if rec.method != "Send" || rec.to != "ok@x.test" {
		t.Fatalf("not delivered: %+v", rec)
	}
}

// A suppression store that is down must not be read as "not suppressed".
func TestSendFailsWhenSuppressionCheckErrors(t *testing.T) {
	rec := &recordingDispatcher{}
	notif := NewLocalNotificationService()
	notif.Register(EmailChannel, rec)
	notif.Suppressor = &fakeSuppressor{err: errors.New("db down")}

	if err := notif.Send(context.Background(), port.NotificationRequest{
		Channel: EmailChannel, To: "ok@x.test", Title: "hi",
	}); err == nil {
		t.Fatal("a failed suppression check must not deliver")
	}
	if rec.method != "" {
		t.Error("nothing should have been dispatched")
	}
}

// Channels not addressed by a contact (the inbox) have nothing to suppress.
func TestSendSkipsSuppressionWithoutContact(t *testing.T) {
	rec := &recordingDispatcher{}
	notif := NewLocalNotificationService()
	notif.Register(InboxChannel, rec)
	notif.Suppressor = &fakeSuppressor{}
	notif.Recipients = &fakeRecipients{email: "user@x.test"}

	if err := notif.Send(context.Background(), port.NotificationRequest{
		Channel: InboxChannel, UserID: 42, Title: "hi",
	}); err != nil {
		t.Fatal(err)
	}
	if rec.method != "Dispatch" {
		t.Fatalf("inbox send should dispatch, got %q", rec.method)
	}
}

func TestSendSkipsSuppressionForExplicitNonContactAddress(t *testing.T) {
	rec := &recordingDispatcher{}
	notif := NewLocalNotificationService()
	notif.Register(InboxChannel, rec)
	notif.Suppressor = &fakeSuppressor{err: errors.New("should not be called")}
	if err := notif.Send(context.Background(), port.NotificationRequest{
		Channel: InboxChannel, To: "device-token", Title: "hi",
	}); err != nil {
		t.Fatal(err)
	}
}

// --- dedupe -----------------------------------------------------------------

func TestSendCollapsesRepeatUnderDedupeKey(t *testing.T) {
	rec := &recordingDispatcher{}
	notif := NewLocalNotificationService()
	notif.Register(EmailChannel, rec)
	ledger := newLedger()
	notif.Ledger = ledger

	req := port.NotificationRequest{Channel: EmailChannel, To: "a@x.test", Title: "quota", DedupeKey: "quota:7"}
	if err := notif.Send(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	if len(ledger.completed) != 1 {
		t.Fatalf("first send should complete the key: %v", ledger.completed)
	}
	rec.method = ""
	if err := notif.Send(context.Background(), req); !errors.Is(err, port.ErrNotificationDuplicate) {
		t.Fatalf("err = %v, want ErrNotificationDuplicate", err)
	}
	if rec.method != "" {
		t.Error("the repeat must not be delivered")
	}
}

// A transport failure releases the key: a retry of a notification that never
// went out must not be mistaken for a duplicate.
func TestSendReleasesDedupeKeyOnFailure(t *testing.T) {
	failing := &failingDispatcher{}
	notif := NewLocalNotificationService()
	notif.Register(EmailChannel, failing)
	ledger := newLedger()
	notif.Ledger = ledger

	req := port.NotificationRequest{Channel: EmailChannel, To: "a@x.test", Title: "t", DedupeKey: "k"}
	if err := notif.Send(context.Background(), req); err == nil {
		t.Fatal("expected the transport failure")
	}
	if len(ledger.released) != 1 {
		t.Fatalf("failed send should release the key: %v", ledger.released)
	}
	if err := notif.Send(context.Background(), req); err == nil {
		t.Fatal("retry should reach the dispatcher again, not be a duplicate")
	}
}

// A DedupeKey without a ledger is inert, not a silent drop.
func TestDedupeKeyWithoutLedgerDelivers(t *testing.T) {
	rec := &recordingDispatcher{}
	notif := NewLocalNotificationService()
	notif.Register(EmailChannel, rec)

	for range 2 {
		if err := notif.Send(context.Background(), port.NotificationRequest{
			Channel: EmailChannel, To: "a@x.test", Title: "t", DedupeKey: "k",
		}); err != nil {
			t.Fatal(err)
		}
	}
	if rec.method != "Send" {
		t.Fatal("delivery expected")
	}
}

func TestSendMarksUnknownWhenDedupeCompletionFails(t *testing.T) {
	notif := NewLocalNotificationService()
	notif.Register(EmailChannel, &recordingDispatcher{})
	ledger := newLedger()
	ledger.completeErr = errors.New("db down")
	notif.Ledger = ledger

	err := notif.Send(context.Background(), port.NotificationRequest{Channel: EmailChannel, To: "a@x.test", DedupeKey: "k"})
	if err == nil || len(ledger.unknown) != 1 || ledger.states["notification:email:k"] != model.LedgerUnknown {
		t.Fatalf("err = %v, unknown = %v, states = %v", err, ledger.unknown, ledger.states)
	}
}

type failingDispatcher struct{}

func (failingDispatcher) Dispatch(context.Context, int, string, string, map[string]string) error {
	return errors.New("smtp down")
}
func (failingDispatcher) Send(context.Context, string, string, string, map[string]string) error {
	return errors.New("smtp down")
}

// --- SuppressionService -----------------------------------------------------

type suppressionQS struct {
	calls []struct {
		name string
		args []any
	}
	rows map[string]*model.QueryResult
}

func (q *suppressionQS) Query(_ context.Context, name string, args ...any) (*model.QueryResult, error) {
	q.calls = append(q.calls, struct {
		name string
		args []any
	}{name, args})
	if r, ok := q.rows[name]; ok {
		return r, nil
	}
	return &model.QueryResult{}, nil
}
func (q *suppressionQS) GenID() int64 { return 1 }

func (q *suppressionQS) argsFor(name string) []any {
	for _, c := range q.calls {
		if c.name == name {
			return c.args
		}
	}
	return nil
}

func newSuppressionService(qs *suppressionQS) *SuppressionService {
	s := &SuppressionService{}
	s.qs = qs
	s.once.Do(func() {})
	return s
}

// A differently-cased address must not slip past its own entry.
func TestSuppressionServiceNormalizesContact(t *testing.T) {
	qs := &suppressionQS{rows: map[string]*model.QueryResult{
		qSuppressionLookup: {Rows: [][]any{{SuppressComplained}}},
	}}
	s := newSuppressionService(qs)

	suppressed, reason, err := s.Suppressed(context.Background(), EmailChannel, "  Gone@X.Test ", 7)
	if err != nil || !suppressed || reason != SuppressComplained {
		t.Fatalf("got (%v, %q, %v)", suppressed, reason, err)
	}
	args := qs.argsFor(qSuppressionLookup)
	if args[1].(string) != "gone@x.test" || args[2].(int64) != 7 {
		t.Fatalf("lookup args = %v", args)
	}
}

func TestSuppressionServiceMissIsNotSuppressed(t *testing.T) {
	s := newSuppressionService(&suppressionQS{})
	if suppressed, _, err := s.Suppressed(context.Background(), EmailChannel, "ok@x.test", 0); err != nil || suppressed {
		t.Fatalf("got (%v, %v)", suppressed, err)
	}
}

func TestSuppressAndRelease(t *testing.T) {
	qs := &suppressionQS{}
	s := newSuppressionService(qs)
	ctx := context.Background()

	if err := s.Suppress(ctx, EmailChannel, "Gone@X.test", AllPartners, SuppressBounced); err != nil {
		t.Fatal(err)
	}
	args := qs.argsFor(qSuppressionInsert)
	if args[1].(string) != "gone@x.test" || args[2].(int64) != AllPartners || args[3].(string) != SuppressBounced {
		t.Fatalf("insert args = %v", args)
	}
	if err := s.Suppress(ctx, EmailChannel, "", 0, SuppressBounced); err == nil {
		t.Error("an empty contact must be refused")
	}
	if err := s.Release(ctx, EmailChannel, "GONE@x.test", AllPartners); err != nil {
		t.Fatal(err)
	}
	if got := qs.argsFor(qSuppressionRelease)[1].(string); got != "gone@x.test" {
		t.Fatalf("release contact = %q", got)
	}
}

func TestSuppressionServiceWithoutDatabase(t *testing.T) {
	s := &SuppressionService{}
	if _, _, err := s.Suppressed(context.Background(), EmailChannel, "a@x.test", 0); err == nil {
		t.Error("an unconfigured suppressor must fail loudly, not report 'not suppressed'")
	}
}
