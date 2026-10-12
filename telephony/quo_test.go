package telephony

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/nauticana/keel/clock"
	"github.com/nauticana/keel/config"
)

var (
	quoNow       = time.Date(2026, 9, 20, 15, 3, 0, 0, time.UTC)
	quoLegacyKey = base64.StdEncoding.EncodeToString([]byte("partner-signing-key"))
	quoStdKey    = []byte("new-partner-signing-key")
	quoStdSecret = "whsec_" + base64.StdEncoding.EncodeToString(quoStdKey)
)

const quoCall = `{"type":"call.completed","data":{"object":{"id":"AC1","direction":"outgoing",
 "participants":["+1 (949) 555-0100"],"status":"completed","createdAt":"2026-09-20T15:00:00Z",
 "answeredAt":"2026-09-20T15:00:10Z","completedAt":"2026-09-20T15:02:10Z",
 "media":[{"url":"https://files.example.com/rec.mp3"}]}}}`

func signedQuoLegacy(body string, at time.Time) Webhook {
	ts := fmt.Sprint(at.UnixMilli())
	key, _ := base64.StdEncoding.DecodeString(quoLegacyKey)
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(ts + "." + body))
	header := http.Header{}
	header.Set(quoLegacySignatureHeader, "hmac;1;"+ts+";"+base64.StdEncoding.EncodeToString(mac.Sum(nil)))
	return Webhook{Header: header, Body: []byte(body)}
}

func signedQuoStandard(body string, at time.Time) Webhook {
	id, ts := "msg_123", fmt.Sprint(at.Unix())
	mac := hmac.New(sha256.New, quoStdKey)
	mac.Write([]byte(id + "." + ts + "." + body))
	header := http.Header{}
	header.Set(quoStandardIDHeader, id)
	header.Set(quoStandardTimestampHeader, ts)
	header.Set(quoStandardSignatureHeader, "v1,"+base64.StdEncoding.EncodeToString(mac.Sum(nil)))
	return Webhook{Header: header, Body: []byte(body)}
}

func newTestQuo() *Quo { return NewQuo(clock.NewFake(quoNow)) }

func TestQuoReadsASignedCall(t *testing.T) {
	for name, webhook := range map[string]struct {
		w      Webhook
		secret string
	}{
		"legacy":   {signedQuoLegacy(quoCall, quoNow), quoLegacyKey},
		"standard": {signedQuoStandard(quoCall, quoNow), quoStdSecret},
	} {
		got, err := newTestQuo().Events(webhook.w, webhook.secret)
		if err != nil || len(got) != 1 {
			t.Fatalf("%s: got %+v, err %v", name, got, err)
		}
		e := got[0]
		if e.Kind != KindCall || e.ExternalID != "AC1" || e.Direction != DirectionOutbound || !e.Answered ||
			e.Duration != 2*time.Minute || e.Counterpart() != "+1 (949) 555-0100" ||
			e.RecordingURL != "https://files.example.com/rec.mp3" || !e.At.Equal(time.Date(2026, 9, 20, 15, 0, 0, 0, time.UTC)) {
			t.Fatalf("%s: event = %+v", name, e)
		}
	}
}

func TestQuoReadsAMissedCallWithVoicemail(t *testing.T) {
	body := `{"type":"call.completed","data":{"object":{"id":"AC2","direction":"incoming","participants":["+19495550100"],
 "createdAt":"2026-09-20T15:00:00Z","voicemail":{"url":"https://files.example.com/vm.mp3"}}}}`
	got, err := newTestQuo().Events(signedQuoLegacy(body, quoNow), quoLegacyKey)
	if err != nil || len(got) != 1 || got[0].Answered || got[0].Duration != 0 ||
		got[0].RecordingURL != "https://files.example.com/vm.mp3" || got[0].Counterpart() != "+19495550100" {
		t.Fatalf("got %+v, err %v", got, err)
	}
}

func TestQuoReadsMessages(t *testing.T) {
	for typ, status := range map[string]MessageStatus{"message.received": MessageReceived, "message.delivered": MessageDelivered} {
		direction := "incoming"
		if status == MessageDelivered {
			direction = "outgoing"
		}
		body := `{"type":"` + typ + `","data":{"object":{"id":"MS1","direction":"` + direction + `",
 "from":"+19495550100","to":["+19495550000"],"createdAt":"2026-09-20T15:01:00Z"}}}`
		got, err := newTestQuo().Events(signedQuoLegacy(body, quoNow), quoLegacyKey)
		if err != nil || len(got) != 1 {
			t.Fatalf("%s: got %+v, err %v", typ, got, err)
		}
		if e := got[0]; e.Kind != KindMessage || e.MessageStatus != status || e.To != "+19495550000" || e.ExternalID != "MS1" {
			t.Errorf("%s: event = %+v", typ, e)
		}
	}
}

func TestQuoIgnoresEventsWithoutFinalState(t *testing.T) {
	for _, typ := range []string{"call.ringing", "call.recording.completed", "contact.updated"} {
		body := `{"type":"` + typ + `","data":{"object":{"id":"AC2","direction":"incoming","from":"+1","to":"+2"}}}`
		got, err := newTestQuo().Events(signedQuoLegacy(body, quoNow), quoLegacyKey)
		if err != nil || len(got) != 0 {
			t.Errorf("%s: got %v, err %v", typ, got, err)
		}
	}
}

func TestQuoRejectsTamperedDeliveries(t *testing.T) {
	p := newTestQuo()
	tampered := strings.Replace(quoCall, "outgoing", "incoming", 1)
	legacy := signedQuoLegacy(quoCall, quoNow)
	legacy.Body = []byte(tampered)
	if _, err := p.Events(legacy, quoLegacyKey); !errors.Is(err, ErrSignature) {
		t.Errorf("legacy tampered: err = %v", err)
	}
	standard := signedQuoStandard(quoCall, quoNow)
	standard.Body = []byte(tampered)
	if _, err := p.Events(standard, quoStdSecret); !errors.Is(err, ErrSignature) {
		t.Errorf("standard tampered: err = %v", err)
	}
	if _, err := p.Events(signedQuoLegacy(quoCall, quoNow), base64.StdEncoding.EncodeToString([]byte("other"))); !errors.Is(err, ErrSignature) {
		t.Errorf("legacy wrong key: err = %v", err)
	}
	if _, err := p.Events(signedQuoStandard(quoCall, quoNow), quoLegacyKey); !errors.Is(err, ErrSignature) {
		t.Errorf("standard without whsec_ secret: err = %v", err)
	}
	if _, err := p.Events(Webhook{Body: []byte(quoCall)}, quoLegacyKey); !errors.Is(err, ErrSignature) {
		t.Errorf("unsigned: err = %v", err)
	}
	dotted := signedQuoStandard(quoCall, quoNow)
	dotted.Header.Set(quoStandardIDHeader, "msg.123")
	if _, err := p.Events(dotted, quoStdSecret); !errors.Is(err, ErrSignature) {
		t.Errorf("dotted id: err = %v", err)
	}
	long := signedQuoStandard(quoCall, quoNow)
	long.Header.Set(quoStandardSignatureHeader, strings.Repeat("v1,x ", 300))
	if _, err := p.Events(long, quoStdSecret); !errors.Is(err, ErrSignature) {
		t.Errorf("oversized signature header: err = %v", err)
	}
}

func TestQuoRejectsStaleAndFutureTimestamps(t *testing.T) {
	p := newTestQuo()
	for _, skew := range []time.Duration{-config.Config().TelephonySignatureTolerance - time.Second, config.Config().TelephonySignatureTolerance + time.Second} {
		if _, err := p.Events(signedQuoLegacy(quoCall, quoNow.Add(skew)), quoLegacyKey); !errors.Is(err, ErrSignature) {
			t.Errorf("legacy skew %v: err = %v", skew, err)
		}
		if _, err := p.Events(signedQuoStandard(quoCall, quoNow.Add(skew)), quoStdSecret); !errors.Is(err, ErrSignature) {
			t.Errorf("standard skew %v: err = %v", skew, err)
		}
	}
	if _, err := p.Events(signedQuoLegacy(quoCall, quoNow.Add(-config.Config().TelephonySignatureTolerance)), quoLegacyKey); err != nil {
		t.Errorf("at the tolerance edge: err = %v", err)
	}
}

func TestQuoRejectsMalformedPayloads(t *testing.T) {
	p := newTestQuo()
	for name, body := range map[string]string{
		"not json":      `{"type":`,
		"no id":         `{"type":"call.completed","data":{"object":{"direction":"incoming","from":"+1","to":"+2"}}}`,
		"no number":     `{"type":"call.completed","data":{"object":{"id":"AC1","direction":"incoming","to":"+2"}}}`,
		"bad to shape":  `{"type":"message.received","data":{"object":{"id":"MS1","direction":"incoming","from":"+1","to":{"n":1}}}}`,
		"bad direction": `{"type":"message.received","data":{"object":{"id":"MS1","direction":"sideways","from":"+1","to":["+2"]}}}`,
	} {
		if _, err := p.Events(signedQuoLegacy(body, quoNow), quoLegacyKey); !errors.Is(err, ErrPayload) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	huge := signedQuoLegacy(`{"pad":"`+strings.Repeat("x", int(config.Config().TelephonyMaxBodyBytes))+`"}`, quoNow)
	if _, err := p.Events(huge, quoLegacyKey); !errors.Is(err, ErrPayload) {
		t.Errorf("oversized body: err = %v", err)
	}
}
