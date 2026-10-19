package handler

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/port"
)

// requireHuman runs the challenge check when a verifier is wired. It reports
// whether the request may proceed; a refusal has been written. A provider
// outage refuses with 503: the check fails closed.
func (h *AbstractHandler) requireHuman(w http.ResponseWriter, r *http.Request, verifier port.HumanVerifier, token string) bool {
	if verifier == nil {
		return true
	}
	err := verifier.Verify(r.Context(), token, common.TrustedClientIP(r))
	switch {
	case err == nil:
		return true
	case errors.Is(err, port.ErrChallengeRequired):
		h.WriteError(w, http.StatusForbidden, "Forbidden", "challengeToken is required")
	case errors.Is(err, port.ErrChallengeFailed):
		h.WriteError(w, http.StatusForbidden, "Forbidden", "human verification failed")
	default:
		if h.Journal != nil {
			h.Journal.Error(fmt.Sprintf("human verification unavailable: %v", err))
		}
		h.WriteError(w, http.StatusServiceUnavailable, "Service Unavailable", "human verification is temporarily unavailable, try again later")
	}
	return false
}
