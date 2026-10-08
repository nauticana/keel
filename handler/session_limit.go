package handler

import (
	"errors"
	"net/http"
	"time"
)

const maxSessionDays = 3650

var errSessionMaxDays = errors.New("sessionMaxDays must be between 1 and 3650")

func init() {
	RegisterErrorCode(errSessionMaxDays, http.StatusBadRequest, "invalid_session_max_days")
}

type sessionLimit struct {
	SessionMaxDays *int `json:"sessionMaxDays,omitempty"`
}

func (l sessionLimit) maxAge() (time.Duration, error) {
	if l.SessionMaxDays == nil {
		return 0, nil
	}
	if *l.SessionMaxDays < 1 || *l.SessionMaxDays > maxSessionDays {
		return 0, errSessionMaxDays
	}
	return time.Duration(*l.SessionMaxDays) * 24 * time.Hour, nil
}
