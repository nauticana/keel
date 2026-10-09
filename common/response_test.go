package common

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/nauticana/keel/config"
)

func TestWriteJSONError(t *testing.T) {
	rec := httptest.NewRecorder()
	WriteJSONError(rec, http.StatusTooManyRequests, "API quota exceeded")

	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("code=%d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("Content-Type=%q", ct)
	}
	if ns := rec.Header().Get("X-Content-Type-Options"); ns != "nosniff" {
		t.Fatalf("nosniff=%q", ns)
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body["error"] != "API quota exceeded" {
		t.Fatalf("body=%s err=%v", rec.Body.String(), err)
	}
}

func TestWriteJSONReusesEchoedRequestID(t *testing.T) {
	saved := config.Config().RequestIDHeader
	config.Config().RequestIDHeader = "X-Request-Id"
	t.Cleanup(func() { config.Config().RequestIDHeader = saved })

	rec := httptest.NewRecorder()
	rec.Header().Set("X-Request-Id", "edge-7")
	WriteJSON(rec, http.StatusOK, "ok")
	var body APIResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body.Meta.RequestID != "edge-7" {
		t.Fatalf("meta=%+v err=%v", body.Meta, err)
	}

	rec = httptest.NewRecorder()
	WriteJSON(rec, http.StatusOK, "ok")
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body.Meta.RequestID == "" || body.Meta.RequestID == "edge-7" {
		t.Fatalf("meta=%+v err=%v", body.Meta, err)
	}
}

type requestIDTestWriter struct {
	http.ResponseWriter
	id string
}

func (w requestIDTestWriter) RequestID() string { return w.id }

func TestWriteJSONReusesRequestIDWithoutResponseHeader(t *testing.T) {
	saved := config.Config().RequestIDHeader
	config.Config().RequestIDHeader = ""
	t.Cleanup(func() { config.Config().RequestIDHeader = saved })

	rec := httptest.NewRecorder()
	WriteJSON(requestIDTestWriter{ResponseWriter: rec, id: "internal-7"}, http.StatusOK, "ok")
	var body APIResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body.Meta.RequestID != "internal-7" {
		t.Fatalf("meta=%+v err=%v", body.Meta, err)
	}
}
