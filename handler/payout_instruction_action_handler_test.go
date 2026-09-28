package handler

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/nauticana/keel/payout"
)

func TestPayoutInstructionActionsRequirePost(t *testing.T) {
	h := &PayoutInstructionActionHandler{}
	for _, action := range []func(http.ResponseWriter, *http.Request){h.cancel, h.execute, h.resolve} {
		rec := httptest.NewRecorder()
		action(rec, httptest.NewRequest(http.MethodGet, "/payout_instruction/action", nil))
		if rec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("GET status=%d, want %d", rec.Code, http.StatusMethodNotAllowed)
		}
	}
}

func TestPayoutInstructionReversalLimitIsClientError(t *testing.T) {
	rec := httptest.NewRecorder()
	(&AbstractHandler{}).WriteServiceError(rec, httptest.NewRequest(http.MethodPost, "/payout_instruction/resolve", nil), payout.ErrReversalExceedsLeg)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d, want %d", rec.Code, http.StatusBadRequest)
	}
}
