package handler

import (
	crand "crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/nauticana/keel/config"
	"github.com/nauticana/keel/model"
	"github.com/nauticana/keel/user"
)

// Cache namespaces of a registration whose contact is not yet proven. No
// user_account row exists until the code is entered, so an abandoned or
// automated send leaves nothing behind once the token expires.
const (
	otpPendingPrefix         = "otp_pending:"
	otpPendingAttemptsPrefix = "otp_pending_attempts:"
)

// otpPendingSignup is everything VerifyOTP needs to create the account.
type otpPendingSignup struct {
	Channel          string              `json:"channel"`
	Contact          string              `json:"contact"`
	SecondaryContact string              `json:"secondaryContact,omitempty"`
	DefaultRegion    string              `json:"defaultRegion,omitempty"`
	Consent          *user.SignupConsent `json:"consent,omitempty"`
	CodeHash         string              `json:"codeHash"`
	ExpiresAt        int64               `json:"expiresAt"`
}

func hashOTPCode(code string) string {
	sum := sha256.Sum256([]byte(code))
	return hex.EncodeToString(sum[:])
}

// setCode stores a fresh code and its expiry; the code itself is only ever sent.
func (p *otpPendingSignup) setCode(code string) {
	p.CodeHash = hashOTPCode(code)
	p.ExpiresAt = time.Now().Add(time.Duration(config.Config().OTPTTLSeconds) * time.Second).Unix()
}

func (p *otpPendingSignup) matches(code string) bool {
	if time.Now().Unix() >= p.ExpiresAt {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(p.CodeHash), []byte(hashOTPCode(code))) == 1
}

func newOTPToken() (string, error) {
	var raw [32]byte
	if _, err := crand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("otp: rng: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw[:]), nil
}

func (h *OTPHandler) storePending(r *http.Request, token string, p *otpPendingSignup) error {
	if h.Cache == nil {
		return fmt.Errorf("OTPHandler: Cache must be set")
	}
	raw, err := json.Marshal(p)
	if err != nil {
		return err
	}
	return h.Cache.Set(r.Context(), otpPendingPrefix+token, string(raw), config.Config().OTPTokenTTL)
}

// loadPending returns the pending signup behind token and its stored form, or
// nil when there is none.
func (h *OTPHandler) loadPending(r *http.Request, token string) (*otpPendingSignup, string) {
	if h.Cache == nil || token == "" {
		return nil, ""
	}
	raw, err := h.Cache.Get(r.Context(), otpPendingPrefix+token)
	if err != nil || raw == "" {
		return nil, ""
	}
	var p otpPendingSignup
	if json.Unmarshal([]byte(raw), &p) != nil || p.Contact == "" {
		return nil, ""
	}
	return &p, raw
}

// claimPendingAttempt counts a guess under max_registration_attempts; once
// the cap is reached the pending signup is dropped and every later guess fails.
func (h *OTPHandler) claimPendingAttempt(r *http.Request, token string) bool {
	cap := config.Config().MaxRegistrationAttempts
	if cap <= 0 {
		cap = 5
	}
	count, err := h.Cache.IncrementWithTTL(r.Context(), otpPendingAttemptsPrefix+token, config.Config().OTPTokenTTL)
	if err != nil || count > int64(cap) {
		_ = h.Cache.Delete(r.Context(), otpPendingPrefix+token)
		return false
	}
	return true
}

// consumePending takes the pending signup out of the cache; only one of two
// concurrent correct guesses succeeds.
func (h *OTPHandler) consumePending(r *http.Request, token, raw string) bool {
	won, err := h.Cache.CompareAndSet(r.Context(), otpPendingPrefix+token, raw, "", time.Second)
	if err != nil || !won {
		return false
	}
	_ = h.Cache.Delete(r.Context(), otpPendingPrefix+token)
	_ = h.Cache.Delete(r.Context(), otpPendingAttemptsPrefix+token)
	return true
}

// restorePending puts a consumed signup back after account creation failed so
// the same code can be retried while it is valid.
func (h *OTPHandler) restorePending(r *http.Request, token, raw string, p *otpPendingSignup) {
	ttl := time.Until(time.Unix(p.ExpiresAt, 0))
	if ttl > 0 {
		_ = h.Cache.Set(r.Context(), otpPendingPrefix+token, raw, ttl)
	}
}

// createPendingUser creates the account the proven contact registered for. The
// lookup-or-create keeps a contact that gained an account meanwhile.
func (h *OTPHandler) createPendingUser(w http.ResponseWriter, p *otpPendingSignup) (*model.UserSession, bool) {
	var session *model.UserSession
	var err error
	if p.Channel == otpChannelEmail {
		session, _, err = h.UserService.GetOrCreateUserByEmail(p.Contact, p.SecondaryContact, p.Consent)
	} else {
		session, _, err = h.UserService.GetOrCreateUserByPhone(p.Contact, p.DefaultRegion, p.SecondaryContact, p.Consent)
	}
	if err != nil {
		if session != nil {
			h.WriteError(w, http.StatusFailedDependency, "Consent Not Recorded", err.Error())
			return nil, false
		}
		h.WriteError(w, http.StatusInternalServerError, "Internal Server Error", "failed to create user")
		return nil, false
	}
	return session, true
}
