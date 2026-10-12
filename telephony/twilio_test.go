package telephony

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/nauticana/keel/clock"
	"github.com/nauticana/keel/config"
)

const twilioTarget = "https://app.example.com/public/phone/twilio?partner=3"

var twilioNow = time.Date(2026, 9, 20, 15, 5, 0, 0, time.UTC)

func signedTwilio(token string, form url.Values) Webhook {
	header := http.Header{}
	header.Set(twilioSignatureHeader, twilioSignature(token, twilioTarget, form))
	return Webhook{URL: twilioTarget, Header: header, Body: []byte(form.Encode())}
}

func twilioCallForm(status string) url.Values {
	return url.Values{"CallSid": {"CA9"}, "CallStatus": {status}, "Direction": {"inbound"},
		"From": {"+19495550100"}, "To": {"+19495550000"}, "Timestamp": {"Sun, 20 Sep 2026 15:00:00 +0000"}}
}

func newTestTwilio() *Twilio { return NewTwilio(clock.NewFake(twilioNow)) }

// The signature follows Twilio's published worked example.
func TestTwilioSignatureMatchesTheDocumentedExample(t *testing.T) {
	form := url.Values{"CallSid": {"CA1234567890ABCDE"}, "Caller": {"+12349013030"}, "Digits": {"1234"},
		"From": {"+12349013030"}, "To": {"+18005551212"}}
	got := twilioSignature("12345", "https://mycompany.com/myapp.php?foo=1&bar=2", form)
	if got != "0/KCTR6DLpKmkAf8muzZqo1nDgQ=" {
		t.Fatalf("signature = %s", got)
	}
}

func TestTwilioSignatureSortsAndDeduplicatesRepeatedValues(t *testing.T) {
	form := url.Values{"A": {"2", "1", "2"}}
	got := twilioSignature("tok", "https://example.com/hook", form)
	want := twilioSignature("tok", "https://example.com/hook", url.Values{"A": {"1", "2"}})
	if got != want || strings.Join(form["A"], ",") != "2,1,2" {
		t.Fatalf("signature = %q, want %q; form = %v", got, want, form)
	}
}

func TestTwilioReadsAFinalCall(t *testing.T) {
	form := twilioCallForm("completed")
	form.Set("Direction", "outbound-api")
	form.Set("CallDuration", "75")
	form.Set("RecordingUrl", "https://api.twilio.com/rec/RE1")
	got, err := newTestTwilio().Events(signedTwilio("tok", form), "tok")
	if err != nil || len(got) != 1 {
		t.Fatalf("got %+v, err %v", got, err)
	}
	e := got[0]
	if e.Kind != KindCall || e.Direction != DirectionOutbound || e.ExternalID != "CA9" || !e.Answered ||
		e.Duration != 75*time.Second || e.RecordingURL != "https://api.twilio.com/rec/RE1" ||
		!e.At.Equal(time.Date(2026, 9, 20, 15, 0, 0, 0, time.UTC)) || e.Counterpart() != "+19495550000" || e.MessageStatus != "" {
		t.Fatalf("event = %+v", e)
	}
}

func TestTwilioReadsAnUnansweredCall(t *testing.T) {
	got, err := newTestTwilio().Events(signedTwilio("tok", twilioCallForm("no-answer")), "tok")
	if err != nil || len(got) != 1 || got[0].Answered || got[0].Duration != 0 ||
		got[0].Direction != DirectionInbound || got[0].Counterpart() != "+19495550100" {
		t.Fatalf("got %+v, err %v", got, err)
	}
}

func TestTwilioCompletedCallIsAnsweredWithoutDuration(t *testing.T) {
	got, err := newTestTwilio().Events(signedTwilio("tok", twilioCallForm("completed")), "tok")
	if err != nil || len(got) != 1 || !got[0].Answered || got[0].Duration != 0 {
		t.Fatalf("got %+v, err %v", got, err)
	}
}

func TestTwilioIgnoresIntermediateStatuses(t *testing.T) {
	p := newTestTwilio()
	for _, status := range []string{"queued", "ringing", "in-progress", "initiated"} {
		if got, err := p.Events(signedTwilio("tok", twilioCallForm(status)), "tok"); err != nil || len(got) != 0 {
			t.Errorf("call %s: %v, %v", status, got, err)
		}
	}
	for _, status := range []string{"queued", "accepted", "sending", "receiving"} {
		form := url.Values{"MessageSid": {"SM1"}, "MessageStatus": {status}, "From": {"+1"}, "To": {"+2"}}
		if got, err := p.Events(signedTwilio("tok", form), "tok"); err != nil || len(got) != 0 {
			t.Errorf("message %s: %v, %v", status, got, err)
		}
	}
}

func TestTwilioReadsMessages(t *testing.T) {
	for _, tc := range []struct {
		form      url.Values
		status    MessageStatus
		direction Direction
	}{
		{url.Values{"SmsSid": {"SM1"}, "SmsStatus": {"received"}}, MessageReceived, DirectionInbound},
		{url.Values{"MessageSid": {"SM1"}, "MessageStatus": {"sent"}}, MessageSent, DirectionOutbound},
		{url.Values{"MessageSid": {"SM1"}, "MessageStatus": {"delivered"}}, MessageDelivered, DirectionOutbound},
		{url.Values{"MessageSid": {"SM1"}, "MessageStatus": {"undelivered"}}, MessageFailed, DirectionOutbound},
	} {
		tc.form.Set("From", "+19495550100")
		tc.form.Set("To", "+19495550000")
		got, err := newTestTwilio().Events(signedTwilio("tok", tc.form), "tok")
		if err != nil || len(got) != 1 {
			t.Fatalf("%v: got %+v, err %v", tc.form, got, err)
		}
		e := got[0]
		if e.Kind != KindMessage || e.MessageStatus != tc.status || e.Direction != tc.direction ||
			e.ExternalID != "SM1" || !e.At.Equal(twilioNow) {
			t.Errorf("%v: event = %+v", tc.form, e)
		}
	}
}

func TestTwilioRejectsBadSignatures(t *testing.T) {
	p := newTestTwilio()
	form := twilioCallForm("completed")
	if _, err := p.Events(signedTwilio("other", form), "tok"); !errors.Is(err, ErrSignature) {
		t.Errorf("wrong token: err = %v", err)
	}
	tampered := signedTwilio("tok", form)
	tampered.Body = []byte(strings.Replace(string(tampered.Body), "inbound", "outbound-api", 1))
	if _, err := p.Events(tampered, "tok"); !errors.Is(err, ErrSignature) {
		t.Errorf("tampered body: err = %v", err)
	}
	moved := signedTwilio("tok", form)
	moved.URL = "https://app.example.com/public/phone/twilio?partner=4"
	if _, err := p.Events(moved, "tok"); !errors.Is(err, ErrSignature) {
		t.Errorf("other url: err = %v", err)
	}
	unsigned := signedTwilio("tok", form)
	unsigned.Header = nil
	if _, err := p.Events(unsigned, "tok"); !errors.Is(err, ErrSignature) {
		t.Errorf("no header: err = %v", err)
	}
	if _, err := p.Events(signedTwilio("", form), ""); !errors.Is(err, ErrSignature) {
		t.Errorf("empty token: err = %v", err)
	}
}

func TestTwilioRejectsMalformedPayloads(t *testing.T) {
	p := newTestTwilio()
	badDuration := twilioCallForm("completed")
	badDuration.Set("CallDuration", "-3")
	badTime := twilioCallForm("completed")
	badTime.Set("Timestamp", "yesterday")
	noNumber := twilioCallForm("completed")
	noNumber.Del("From")
	for name, form := range map[string]url.Values{
		"neither call nor message": {"AccountSid": {"AC1"}},
		"negative duration":        badDuration,
		"unparseable timestamp":    badTime,
		"no counterpart":           noNumber,
	} {
		if _, err := p.Events(signedTwilio("tok", form), "tok"); !errors.Is(err, ErrPayload) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	broken := Webhook{URL: twilioTarget, Header: http.Header{twilioSignatureHeader: {"x"}}, Body: []byte("a=%zz")}
	if _, err := p.Events(broken, "tok"); !errors.Is(err, ErrPayload) {
		t.Errorf("bad form encoding: err = %v", err)
	}
	huge := signedTwilio("tok", url.Values{"Body": {strings.Repeat("x", int(config.Config().TelephonyMaxBodyBytes))}})
	if _, err := p.Events(huge, "tok"); !errors.Is(err, ErrPayload) {
		t.Errorf("oversized body: err = %v", err)
	}
}

func TestTwilioZeroValueUsesTheSystemClock(t *testing.T) {
	form := url.Values{"MessageSid": {"SM1"}, "MessageStatus": {"received"}, "From": {"+1"}, "To": {"+2"}}
	got, err := (&Twilio{}).Events(signedTwilio("tok", form), "tok")
	if err != nil || len(got) != 1 || time.Since(got[0].At) > time.Minute {
		t.Fatalf("got %+v, err %v", got, err)
	}
}
