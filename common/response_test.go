package common

import (
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
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

func TestWriteJSONAndProblemNumberTypes(t *testing.T) {
	rec := httptest.NewRecorder()
	WriteJSONPaged(rec, http.StatusOK, []map[string]any{{"id": int64(1)<<53 + 1}}, map[string]int{"total": 1})
	if body := rec.Body.String(); !strings.Contains(body, `"data":[{"id":"9007199254740993"}]`) || !strings.Contains(body, `"pagination":{"total":"1"}`) {
		t.Fatalf("envelope: %s", body)
	}
	rec = httptest.NewRecorder()
	if err := WriteProblem(rec, ProblemDetail{Title: "Conflict", Status: http.StatusConflict, Details: []map[string]any{{"user_id": int64(1)<<53 + 1}}}); err != nil {
		t.Fatal(err)
	}
	if body := rec.Body.String(); !strings.Contains(body, `"status":409`) || !strings.Contains(body, `"details":[{"user_id":"9007199254740993"}]`) || strings.Count(body, `"details"`) != 1 {
		t.Fatalf("problem: %s", body)
	}
	rec = httptest.NewRecorder()
	_ = WriteProblem(rec, ProblemDetail{Title: "Gone", Status: http.StatusGone})
	if strings.Contains(rec.Body.String(), "details") {
		t.Fatalf("absent details must be omitted: %s", rec.Body.String())
	}
}

func TestDecodeAPIResponse(t *testing.T) {
	type item struct {
		ID   int64  `json:"id"`
		Name string `json:"name"`
	}
	body := `{"data":{"id":"9007199254740993","name":"x"},"meta":{"request_id":"r1","timestamp":"t","version":"v1"}}`
	got, meta, err := DecodeAPIResponse[item](strings.NewReader(body), int64(len(body)))
	if err != nil || got.ID != 9007199254740993 || got.Name != "x" || meta == nil || meta.RequestID != "r1" {
		t.Fatalf("got=%+v meta=%+v err=%v", got, meta, err)
	}
	if _, _, err := DecodeAPIResponse[item](strings.NewReader(body), int64(len(body))-1); err == nil {
		t.Fatal("oversized body must fail")
	}
	for _, b := range []string{`{"meta":{}}`, `{"data":null,"meta":{}}`, `{"data": null ,"meta":{}}`} {
		if _, _, err := DecodeAPIResponse[item](strings.NewReader(b), 1<<10); !errors.Is(err, ErrEmptyData) {
			t.Fatalf("%s: err=%v, want ErrEmptyData", b, err)
		}
	}
	for _, limit := range []int64{0, -1, math.MaxInt64} {
		if _, _, err := DecodeAPIResponse[item](strings.NewReader(body), limit); err == nil {
			t.Fatalf("limit %d must fail", limit)
		}
	}
	if _, _, err := DecodeAPIResponse[item](strings.NewReader(`{"data":{"id":"x"}}`), 1<<10); err == nil {
		t.Fatal("malformed data must fail")
	}
	if _, _, err := DecodeAPIResponse[item](strings.NewReader(`{"data":{"id":1,"id":2}}`), 1<<10); err == nil {
		t.Fatal("duplicate member must fail")
	}
}

func TestMarshalJSONPassesRawMessageThrough(t *testing.T) {
	raw := json.RawMessage(`{"n": 12345678901234567890, "a": [1, 2]}`)
	got, err := MarshalJSON(struct {
		Doc json.RawMessage `json:"doc"`
	}{raw})
	want, _ := json.Marshal(struct {
		Doc json.RawMessage `json:"doc"`
	}{raw})
	if err != nil || string(got) != string(want) {
		t.Fatalf("got %s err=%v, want %s", got, err, want)
	}
}
