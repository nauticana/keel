package recording

import (
	"context"
	"fmt"
	"time"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/port"
)

const (
	StatusAwaitingConsent = "W"
	StatusAuthorized      = "A"
	StatusRecording       = "R"
	StatusFinalizing      = "F"
	StatusReady           = "D"
	StatusStopped         = "S"
	StatusFailed          = "X"
)

type Participant struct {
	UserID int
	Role   string
}

// Session is one capture context. Attempt counts Reopen calls; consent is
// scoped to the attempt through EventRef.
type Session struct {
	ID               int64
	PartnerID        int64
	ContextRef       string
	ConsentType      string
	PolicyID         int64
	Status           string
	Attempt          int
	CreatedAt        time.Time
	CaptureExpiresAt time.Time
	Participants     []Participant
}

// EventRef is the consent_event reference for a session attempt; consent
// recorded against any other reference does not authorize it.
func EventRef(sessionID int64, attempt int) string {
	if attempt <= 1 {
		return fmt.Sprintf("recording_session:%d", sessionID)
	}
	return fmt.Sprintf("recording_session:%d:%d", sessionID, attempt)
}

func (s *Session) has(userID int) bool {
	for _, p := range s.Participants {
		if p.UserID == userID {
			return true
		}
	}
	return false
}

func (s *Session) joinable() bool {
	return s.Status == StatusAwaitingConsent || s.Status == StatusAuthorized || s.Status == StatusRecording
}

type sessionRow struct {
	Session
	captureHash string
}

func loadSession(ctx context.Context, qs port.QueryService, query string, args ...any) (*sessionRow, error) {
	res, err := qs.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	if len(res.Rows) == 0 {
		return nil, ErrNotFound
	}
	row := res.Rows[0]
	session := &sessionRow{Session: Session{
		ID:          common.AsInt64(row[0]),
		PartnerID:   common.AsInt64(row[1]),
		ContextRef:  common.AsString(row[2]),
		ConsentType: common.AsString(row[3]),
		Status:      common.AsString(row[4]),
		PolicyID:    common.AsInt64(row[7]),
		Attempt:     int(common.AsInt64(row[8])),
		CreatedAt:   common.AsTime(row[9]),
	}, captureHash: common.AsString(row[5])}
	if t, ok := row[6].(time.Time); ok {
		session.CaptureExpiresAt = t
	}
	parts, err := qs.Query(ctx, qListParticipants, session.ID)
	if err != nil {
		return nil, err
	}
	for _, p := range parts.Rows {
		session.Participants = append(session.Participants, Participant{UserID: int(common.AsInt64(p[0])), Role: common.AsString(p[1])})
	}
	return session, nil
}
