package handler

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nauticana/keel/logger"
	"github.com/nauticana/keel/model"
)

func TestWriteServiceError_RegisteredCodeIsMachineReadable(t *testing.T) {
	errNeedsBusiness := errors.New("human-readable wording may change")
	RegisterErrorCode(errNeedsBusiness, http.StatusConflict, "agency_no_partner")

	h := &AbstractHandler{}
	rec := httptest.NewRecorder()
	h.WriteServiceError(rec, httptest.NewRequest(http.MethodPost, "/agency/accept", nil), errNeedsBusiness)

	var problem ProblemDetail
	if err := json.NewDecoder(rec.Body).Decode(&problem); err != nil {
		t.Fatalf("decode problem: %v", err)
	}
	if problem.Code != "agency_no_partner" {
		t.Fatalf("code=%q, want agency_no_partner", problem.Code)
	}
}

func TestWriteServiceError_RegisteredMapsToStatusAndPublicDetail(t *testing.T) {
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

type recordingJournal struct {
	logger.ApplicationLogger
	warnings, errors []string
}

func (j *recordingJournal) Warning(msg string) { j.warnings = append(j.warnings, msg) }
func (j *recordingJournal) Error(msg string)   { j.errors = append(j.errors, msg) }

func decodeProblem(t *testing.T, rec *httptest.ResponseRecorder) ProblemDetail {
	t.Helper()
	var problem ProblemDetail
	if err := json.NewDecoder(rec.Body).Decode(&problem); err != nil {
		t.Fatalf("decode problem: %v", err)
	}
	return problem
}

func TestWriteServiceError_4xxHidesCauseAndLogsIt(t *testing.T) {
	journal := &recordingJournal{}
	h := &AbstractHandler{Journal: journal}
	forbidden := model.NewForbidden(model.NoAuthorizationMessage)
	forbidden.Detail = "no authorization for UPDATE on user_account"
	r := httptest.NewRequest(http.MethodPost, "/profile", nil)
	stashSession(r, &model.UserSession{Id: 3})
	rec := httptest.NewRecorder()
	h.WriteServiceError(rec, r, fmt.Errorf("update user profile: %w", forbidden))

	problem := decodeProblem(t, rec)
	if rec.Code != http.StatusForbidden || problem.Detail != model.NoAuthorizationMessage || problem.Code != model.ErrForbidden {
		t.Fatalf("problem = %d %+v", rec.Code, problem)
	}
	if len(journal.warnings) != 1 || !strings.Contains(journal.warnings[0], "request_id="+problem.RequestID) ||
		!strings.Contains(journal.warnings[0], "user=3 POST /profile") || !strings.Contains(journal.warnings[0], "update user profile") ||
		!strings.Contains(journal.warnings[0], "on user_account") {
		t.Fatalf("warnings = %v", journal.warnings)
	}
}

func TestWriteServiceError_RegisteredSentinelTextWithoutWrapChain(t *testing.T) {
	errClosed := errors.New("booking window closed")
	RegisterErrorStatus(errClosed, http.StatusConflict)
	journal := &recordingJournal{}
	h := &AbstractHandler{Journal: journal}
	rec := httptest.NewRecorder()
	h.WriteServiceError(rec, httptest.NewRequest(http.MethodPost, "/x", nil), fmt.Errorf("book slot 42 for partner 7: %w", errClosed))
	if problem := decodeProblem(t, rec); problem.Detail != "booking window closed" {
		t.Fatalf("detail = %q", problem.Detail)
	}
	if len(journal.warnings) != 1 || !strings.Contains(journal.warnings[0], "user=-1 POST /x") {
		t.Fatalf("warnings = %v", journal.warnings)
	}
}
