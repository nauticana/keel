package handler

import (
	"errors"
	"net/http"
	"time"
)

const maxSessionDays = 3650

var ErrInvalidSessionMaxDays = errors.New("sessionMaxDays must be between 1 and 3650")

func init() {
	RegisterErrorCode(ErrInvalidSessionMaxDays, http.StatusBadRequest, "invalid_session_max_days")
}

// SessionLimit parses the optional sessionMaxDays field in login requests.
type SessionLimit struct {
	SessionMaxDays *int `json:"sessionMaxDays,omitempty"`
}

// MaxAge returns zero when SessionMaxDays is absent.
func (l SessionLimit) MaxAge() (time.Duration, error) {
	if l.SessionMaxDays == nil {
		return 0, nil
	}
	if *l.SessionMaxDays < 1 || *l.SessionMaxDays > maxSessionDays {
		return 0, ErrInvalidSessionMaxDays
	}
	return time.Duration(*l.SessionMaxDays) * 24 * time.Hour, nil
}
