package handler

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestWriteServiceError_RegisteredMapsToStatus_DetailShownFor4xx(t *testing.T) {
	errTaken := errors.New("email already registered")
	RegisterErrorStatus(errTaken, http.StatusConflict)

	h := &AbstractHandler{}
	rec := httptest.NewRecorder()
	// wrapped sentinel still matches via errors.Is
	h.WriteServiceError(rec, httptest.NewRequest(http.MethodPost, "/x", nil),
		fmt.Errorf("register partner: %w", errTaken))

	if rec.Code != http.StatusConflict {
		t.Fatalf("code=%d, want 409", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "email already registered") {
		t.Errorf("4xx detail should pass through: %s", rec.Body.String())
	}
}

func TestWriteServiceError_UnregisteredIs500AndSanitized(t *testing.T) {
	h := &AbstractHandler{}
	rec := httptest.NewRecorder()
	h.WriteServiceError(rec, httptest.NewRequest(http.MethodGet, "/y", nil),
		errors.New("pq: connection refused at 10.0.0.5 with secret"))

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("code=%d, want 500", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "secret") {
		t.Errorf("5xx detail leaked internal text: %s", rec.Body.String())
	}
}
