package handler_test

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/nauticana/keel/handler"
)

func TestSessionLimitEmbedsInAppRequest(t *testing.T) {
	for _, tc := range []struct {
		body string
		want time.Duration
	}{
		{`{"email":"a@b"}`, 0},
		{`{"email":"a@b","sessionMaxDays":null}`, 0},
		{`{"email":"a@b","sessionMaxDays":30}`, 30 * 24 * time.Hour},
		{`{"email":"a@b","sessionMaxDays":3650}`, 3650 * 24 * time.Hour},
	} {
		var req struct {
			Email string `json:"email"`
			handler.SessionLimit
		}
		if err := json.Unmarshal([]byte(tc.body), &req); err != nil {
			t.Fatal(err)
		}
		if got, err := req.MaxAge(); err != nil || got != tc.want {
			t.Errorf("%s: MaxAge = %v, %v; want %v", tc.body, got, err, tc.want)
		}
	}
	for _, days := range []int{-1, 0, 3651} {
		if _, err := (handler.SessionLimit{SessionMaxDays: &days}).MaxAge(); !errors.Is(err, handler.ErrInvalidSessionMaxDays) {
			t.Errorf("%d days: err = %v", days, err)
		}
	}
}

func TestSessionLimitErrorIsRegistered(t *testing.T) {
	rec := httptest.NewRecorder()
	(&handler.AbstractHandler{}).WriteServiceError(
		rec,
		httptest.NewRequest(http.MethodPost, "/login", nil),
		handler.ErrInvalidSessionMaxDays,
	)

	var problem handler.ProblemDetail
	if err := json.NewDecoder(rec.Body).Decode(&problem); err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusBadRequest || problem.Code != "invalid_session_max_days" {
		t.Fatalf("problem = %d %+v", rec.Code, problem)
	}
}
