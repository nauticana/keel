package dispatcher

import (
	"context"
	"strings"
	"testing"

	"github.com/nauticana/keel/logger"
	"github.com/nauticana/keel/port"
)

type stubRecipientResolver struct {
	phone string
}

func (s stubRecipientResolver) EmailFor(int) (string, error) { return "", nil }
func (s stubRecipientResolver) PhoneFor(int) (string, error) { return s.phone, nil }

var _ port.RecipientResolver = stubRecipientResolver{}

type capturingLogger struct {
	warnings []string
}

func (l *capturingLogger) Initialize(string, string) error { return nil }
func (l *capturingLogger) Close()                          {}
func (l *capturingLogger) Access(string)                   {}
func (l *capturingLogger) Info(string)                     {}
func (l *capturingLogger) Warning(log string)              { l.warnings = append(l.warnings, log) }
func (l *capturingLogger) Error(string)                    {}
func (l *capturingLogger) Fatal(string)                    {}

var _ logger.ApplicationLogger = (*capturingLogger)(nil)

// A user with no phone on file stays a no-op, but must leave a trace:
// a silently dead SMS channel is indistinguishable from a delivered one.
func TestSMSDispatchEmptyRecipientIsJournalledNoOp(t *testing.T) {
	journal := &capturingLogger{}
	posted := false
	d := &smsDispatcher{
		users:   stubRecipientResolver{phone: ""},
		journal: journal,
		name:    "testsms",
		postFn: func(context.Context, string, string) error {
			posted = true
			return nil
		},
	}

	if err := d.Dispatch(context.Background(), 42, "", "hello", nil); err != nil {
		t.Fatalf("Dispatch: %v", err)
	}
	if posted {
		t.Error("postFn was called for an empty recipient")
	}
	if len(journal.warnings) != 1 {
		t.Fatalf("warnings = %v, want exactly one", journal.warnings)
	}
	if !strings.Contains(journal.warnings[0], "42") {
		t.Errorf("warning = %q, want it to name user 42", journal.warnings[0])
	}
}

func TestSMSDispatchResolvedRecipientPosts(t *testing.T) {
	journal := &capturingLogger{}
	var gotTo string
	d := &smsDispatcher{
		users:   stubRecipientResolver{phone: "+19493946318"},
		journal: journal,
		name:    "testsms",
		postFn: func(_ context.Context, to, _ string) error {
			gotTo = to
			return nil
		},
	}

	if err := d.Dispatch(context.Background(), 42, "", "hello", nil); err != nil {
		t.Fatalf("Dispatch: %v", err)
	}
	if gotTo != "+19493946318" {
		t.Errorf("to = %q, want +19493946318", gotTo)
	}
	if len(journal.warnings) != 0 {
		t.Errorf("warnings = %v, want none", journal.warnings)
	}
}
