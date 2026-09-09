// Package recording orchestrates consent-gated capture sessions over an
// application-defined context. Keel enforces consent, session state and
// media storage; capture itself happens on the client or a capture provider.
package recording

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/port"
	"github.com/nauticana/keel/storage"
	"github.com/nauticana/keel/user"
)

var (
	ErrNotFound       = errors.New("recording: session not found")
	ErrForbidden      = errors.New("recording: actor is not a participant")
	ErrConsentMissing = errors.New("recording: a required participant has not consented")
	ErrInvalidState   = errors.New("recording: operation not allowed in the session's state")
	ErrCaptureToken   = errors.New("recording: invalid or expired capture token")
	ErrMediaNotReady  = errors.New("recording: media is not ready")
	ErrMediaTooLarge  = errors.New("recording: media exceeds size limit")
	ErrConflict       = errors.New("recording: context already has a session with different terms")
)

const (
	StatusAwaitingConsent = "W"
	StatusAuthorized      = "A"
	StatusRecording       = "R"
	StatusFinalizing      = "F"
	StatusReady           = "D"
	StatusStopped         = "S"
	StatusFailed          = "X"

	MediaPending = "P"
	MediaReady   = "U"
	MediaFailed  = "X"
)

type Participant struct {
	UserID int
	Role   string
}

type Session struct {
	ID               int64
	PartnerID        int64
	ContextRef       string
	ConsentType      string
	PolicyID         int64
	Status           string
	CaptureExpiresAt time.Time
	Participants     []Participant
}

type Media struct {
	ID          int64
	SessionID   int64
	Bucket      string
	ObjectKey   string
	ContentType string
	SizeBytes   int64
	Status      string
}

const (
	qInsertSession      = "insert_session"
	qInsertParticipant  = "insert_participant"
	qGetSession         = "get_session"
	qGetSessionByCtx    = "get_session_by_context"
	qLockSession        = "lock_session"
	qListParticipants   = "list_participants"
	qSetStatus          = "set_status"
	qSetCapture         = "set_capture"
	qInsertMedia        = "insert_media"
	qGetMediaByKey      = "get_media_by_key"
	qResetMedia         = "reset_media"
	qSetMediaStatus     = "set_media_status"
	qGetMedia           = "get_media"
	qMediaCounts        = "media_counts"
	selectSessionFields = "SELECT id, partner_id, context_ref, consent_type, status, capture_token_hash, capture_expires_at, policy_id FROM recording_session"
)

var queries = map[string]string{
	qInsertSession: `
INSERT INTO recording_session (id, partner_id, context_ref, consent_type, policy_id, created_by)
VALUES (?, ?, ?, ?, ?, ?)`,
	qInsertParticipant: `INSERT INTO recording_participant (session_id, user_id, role) VALUES (?, ?, ?)`,
	qGetSession:        selectSessionFields + ` WHERE id = ?`,
	qGetSessionByCtx:   selectSessionFields + ` WHERE partner_id = ? AND context_ref = ?`,
	qLockSession:       selectSessionFields + ` WHERE id = ? FOR UPDATE`,
	qListParticipants:  `SELECT user_id, role FROM recording_participant WHERE session_id = ? ORDER BY user_id`,
	qSetStatus:         `UPDATE recording_session SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`,
	qSetCapture:        `UPDATE recording_session SET capture_token_hash = ?, capture_expires_at = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`,
	qInsertMedia: `
INSERT INTO recording_media (id, session_id, bucket, object_key, content_type, size_bytes, uploaded_by)
VALUES (?, ?, ?, ?, ?, ?, ?)`,
	qGetMediaByKey:  `SELECT id, session_id, bucket, object_key, content_type, size_bytes, status FROM recording_media WHERE session_id = ? AND object_key = ?`,
	qResetMedia:     `UPDATE recording_media SET status = 'P', size_bytes = 0, content_type = ?, uploaded_by = ?, completed_at = NULL WHERE id = ?`,
	qSetMediaStatus: `UPDATE recording_media SET status = ?, size_bytes = ?, completed_at = CASE WHEN ? = 'U' THEN CURRENT_TIMESTAMP ELSE completed_at END WHERE id = ?`,
	qGetMedia:       `SELECT id, session_id, bucket, object_key, content_type, size_bytes, status FROM recording_media WHERE id = ? AND session_id = ?`,
	qMediaCounts:    `SELECT COALESCE(SUM(CASE WHEN status = 'U' THEN 1 ELSE 0 END), 0), COALESCE(SUM(CASE WHEN status = 'P' THEN 1 ELSE 0 END), 0), COALESCE(SUM(CASE WHEN status = 'X' THEN 1 ELSE 0 END), 0) FROM recording_media WHERE session_id = ?`,
}

// Service is the consent-gated session state machine. Bucket and Storage
// are required for uploads; CaptureTTL bounds a capture authorization.
type Service struct {
	DB                 port.DatabaseRepository
	Consents           user.ConsentService
	Storage            storage.ObjectStorage
	Bucket             string
	CaptureTTL         time.Duration
	MaxMediaBytes      int64
	AllowedContentType map[string]bool

	once sync.Once
	qs   port.QueryService
}

func (s *Service) query(ctx context.Context) port.QueryService {
	s.once.Do(func() { s.qs = s.DB.GetQueryService(ctx, queries) })
	return s.qs
}

func (s *Service) captureTTL() time.Duration {
	if s.CaptureTTL > 0 {
		return s.CaptureTTL
	}
	return 15 * time.Minute
}

// EventRef is the consent_event reference for a session; consent recorded
// against any other reference does not authorize it.
func EventRef(sessionID int64) string { return fmt.Sprintf("recording_session:%d", sessionID) }

// CreateSession returns the session for (partnerID, contextRef), creating
// it with the given required participants when absent.
func (s *Service) CreateSession(ctx context.Context, partnerID int64, contextRef, consentType string, policy user.ConsentPolicyRef, createdBy int, participants []Participant) (*Session, error) {
	if s.DB == nil || s.Consents == nil {
		return nil, fmt.Errorf("recording: database and consent service are required")
	}
	if partnerID <= 0 || contextRef == "" || createdBy <= 0 || len(participants) == 0 {
		return nil, fmt.Errorf("recording: partner, context_ref and participants are required")
	}
	seen := map[int]bool{}
	for _, participant := range participants {
		if participant.UserID <= 0 || participant.Role == "" || seen[participant.UserID] {
			return nil, fmt.Errorf("recording: participants require unique user ids and roles")
		}
		seen[participant.UserID] = true
	}
	if consentType == "" {
		consentType = user.ConsentTypeVideoSession
	}
	policyID, err := s.Consents.ResolvePolicyID(ctx, policy)
	if err != nil {
		return nil, err
	}
	if existing, err := s.sessionBy(ctx, s.query(ctx), qGetSessionByCtx, partnerID, contextRef); err == nil {
		if existing.ConsentType != consentType || existing.PolicyID != policyID {
			return nil, ErrConflict
		}
		return &existing.Session, nil
	} else if !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	tx, err := s.DB.BeginTx(ctx, queries)
	if err != nil {
		return nil, err
	}
	committed := false
	defer func() {
		if !committed {
			_ = port.RollbackDetached(tx)
		}
	}()
	id := tx.GenID()
	if _, err := tx.Query(ctx, qInsertSession, id, partnerID, contextRef, consentType, policyID, createdBy); err != nil {
		return nil, err
	}
	for _, p := range participants {
		if _, err := tx.Query(ctx, qInsertParticipant, id, p.UserID, p.Role); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	committed = true
	created, err := s.sessionBy(ctx, s.query(ctx), qGetSession, id)
	if err != nil {
		return nil, err
	}
	return &created.Session, nil
}

// GetSession returns a session to one of its participants.
func (s *Service) GetSession(ctx context.Context, sessionID int64, actorID int) (*Session, error) {
	session, err := s.sessionBy(ctx, s.query(ctx), qGetSession, sessionID)
	if err != nil {
		return nil, err
	}
	if !session.has(actorID) {
		return nil, ErrForbidden
	}
	return &session.Session, nil
}

// Decide records a participant's consent for this session. Declining or
// withdrawing while authorized or recording stops the session.
func (s *Service) Decide(ctx context.Context, sessionID int64, actorID int, consented bool, meta user.ConsentRequest) error {
	tx, err := s.DB.BeginTx(ctx, queries)
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			_ = port.RollbackDetached(tx)
		}
	}()
	session, err := s.sessionBy(ctx, tx, qLockSession, sessionID)
	if err != nil {
		return err
	}
	if !session.has(actorID) {
		return ErrForbidden
	}
	meta.UserID = actorID
	meta.ConsentType = session.ConsentType
	meta.EventRef = EventRef(sessionID)
	meta.Consented = consented
	meta.PolicyID = session.PolicyID
	if consented {
		err = s.Consents.Record(ctx, meta)
	} else {
		err = s.Consents.Withdraw(ctx, meta)
	}
	if err != nil {
		return err
	}
	if !consented {
		switch session.Status {
		case StatusAuthorized:
			if _, err := tx.Query(ctx, qSetCapture, nil, nil, sessionID); err != nil {
				return err
			}
			if _, err := tx.Query(ctx, qSetStatus, StatusStopped, sessionID); err != nil {
				return err
			}
		case StatusRecording:
			if _, err := tx.Query(ctx, qSetStatus, StatusFinalizing, sessionID); err != nil {
				return err
			}
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	committed = true
	return nil
}

// Start authorizes capture once every participant's current decision for
// this session is affirmative. Returns the capture token the client must
// present to Acknowledge, Renew and Upload.
func (s *Service) Start(ctx context.Context, sessionID int64, actorID int) (token string, expiresAt time.Time, err error) {
	tx, err := s.DB.BeginTx(ctx, queries)
	if err != nil {
		return "", time.Time{}, err
	}
	committed := false
	defer func() {
		if !committed {
			_ = port.RollbackDetached(tx)
		}
	}()
	session, err := s.sessionBy(ctx, tx, qLockSession, sessionID)
	if err != nil {
		return "", time.Time{}, err
	}
	if !session.has(actorID) {
		return "", time.Time{}, ErrForbidden
	}
	if session.Status != StatusAwaitingConsent && session.Status != StatusAuthorized {
		return "", time.Time{}, ErrInvalidState
	}
	for _, p := range session.Participants {
		consented, found, err := s.Consents.LatestConsentFor(ctx, p.UserID, session.ConsentType, EventRef(sessionID), session.PolicyID)
		if err != nil {
			return "", time.Time{}, err
		}
		if !found || !consented {
			return "", time.Time{}, ErrConsentMissing
		}
	}
	token, hash, err := newCaptureToken()
	if err != nil {
		return "", time.Time{}, err
	}
	expiresAt = time.Now().Add(s.captureTTL())
	if _, err := tx.Query(ctx, qSetCapture, hash, expiresAt, sessionID); err != nil {
		return "", time.Time{}, err
	}
	if _, err := tx.Query(ctx, qSetStatus, StatusAuthorized, sessionID); err != nil {
		return "", time.Time{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return "", time.Time{}, err
	}
	committed = true
	return token, expiresAt, nil
}

// Acknowledge marks capture as actually running; only then is the session recording.
func (s *Service) Acknowledge(ctx context.Context, sessionID int64, actorID int, captureToken string) error {
	return s.withCapture(ctx, sessionID, actorID, captureToken, func(tx port.TxQueryService, session *sessionRow) error {
		if session.Status != StatusAuthorized && session.Status != StatusRecording {
			return ErrInvalidState
		}
		_, err := tx.Query(ctx, qSetStatus, StatusRecording, sessionID)
		return err
	})
}

// Renew extends the capture authorization so a live capture never runs on
// an expired token.
func (s *Service) Renew(ctx context.Context, sessionID int64, actorID int, captureToken string) (time.Time, error) {
	expiresAt := time.Now().Add(s.captureTTL())
	err := s.withCapture(ctx, sessionID, actorID, captureToken, func(tx port.TxQueryService, session *sessionRow) error {
		if session.Status != StatusAuthorized && session.Status != StatusRecording {
			return ErrInvalidState
		}
		_, err := tx.Query(ctx, qSetCapture, sha256Hex(captureToken), expiresAt, sessionID)
		return err
	})
	return expiresAt, err
}

// Stop ends capture authorization. Idempotent: recording moves to
// finalizing (ready once media exists), authorized-but-never-captured to stopped.
func (s *Service) Stop(ctx context.Context, sessionID int64, actorID int) error {
	tx, err := s.DB.BeginTx(ctx, queries)
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			_ = port.RollbackDetached(tx)
		}
	}()
	session, err := s.sessionBy(ctx, tx, qLockSession, sessionID)
	if err != nil {
		return err
	}
	if !session.has(actorID) {
		return ErrForbidden
	}
	next := ""
	switch session.Status {
	case StatusAwaitingConsent, StatusAuthorized:
		next = StatusStopped
	case StatusRecording:
		next = StatusFinalizing
		ready, pending, _, err := s.mediaCounts(ctx, tx, sessionID)
		if err != nil {
			return err
		}
		if ready > 0 && pending == 0 {
			next = StatusReady
		}
	}
	if next != "" {
		if next == StatusStopped || next == StatusReady {
			if _, err := tx.Query(ctx, qSetCapture, nil, nil, sessionID); err != nil {
				return err
			}
		}
		if _, err := tx.Query(ctx, qSetStatus, next, sessionID); err != nil {
			return err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	committed = true
	return nil
}

// Upload stores one object for a recording or finalizing session. The media
// row is pending until the object is persisted; a failed upload stays failed.
func (s *Service) Upload(ctx context.Context, sessionID int64, actorID int, captureToken, objectKey, contentType string, body io.Reader) (*Media, error) {
	if s.Storage == nil || s.Bucket == "" || s.MaxMediaBytes <= 0 {
		return nil, fmt.Errorf("recording: storage is not configured")
	}
	if body == nil || !s.AllowedContentType[contentType] {
		return nil, fmt.Errorf("recording: media body or content type is invalid")
	}
	cleanKey := path.Clean(strings.TrimSpace(objectKey))
	if cleanKey == "." || cleanKey == ".." || strings.HasPrefix(cleanKey, "../") || strings.HasPrefix(cleanKey, "/") {
		return nil, fmt.Errorf("recording: invalid object key")
	}
	storageKey := fmt.Sprintf("recording/%d/%s", sessionID, cleanKey)
	var media *Media
	err := s.withCapture(ctx, sessionID, actorID, captureToken, func(tx port.TxQueryService, session *sessionRow) error {
		if session.Status != StatusRecording && session.Status != StatusFinalizing {
			return ErrInvalidState
		}
		existing, err := tx.Query(ctx, qGetMediaByKey, sessionID, storageKey)
		if err != nil {
			return err
		}
		if len(existing.Rows) > 0 {
			row := existing.Rows[0]
			media = mediaFromRow(row)
			if media.Status == MediaReady {
				return nil
			}
			if media.Status != MediaFailed {
				return ErrInvalidState
			}
			_, err = tx.Query(ctx, qResetMedia, contentType, actorID, media.ID)
			return err
		}
		media = &Media{ID: tx.GenID(), SessionID: sessionID, Bucket: s.Bucket, ObjectKey: storageKey, ContentType: contentType, Status: MediaPending}
		_, err = tx.Query(ctx, qInsertMedia, media.ID, sessionID, s.Bucket, storageKey, contentType, 0, actorID)
		return err
	})
	if err != nil {
		return nil, err
	}
	if media.Status == MediaReady {
		return media, nil
	}
	counter := &countingReader{r: io.LimitReader(body, s.MaxMediaBytes+1)}
	if err := s.Storage.Upload(ctx, s.Bucket, storageKey, counter, contentType); err != nil || counter.n > s.MaxMediaBytes {
		_ = s.Storage.Delete(ctx, s.Bucket, storageKey)
		_, updateErr := s.query(ctx).Query(ctx, qSetMediaStatus, MediaFailed, counter.n, MediaFailed, media.ID)
		media.Status = MediaFailed
		if counter.n > s.MaxMediaBytes {
			err = ErrMediaTooLarge
		}
		return media, errors.Join(err, updateErr)
	}
	media.SizeBytes, media.Status = counter.n, MediaReady
	if _, err := s.query(ctx).Query(ctx, qSetMediaStatus, MediaReady, counter.n, MediaReady, media.ID); err != nil {
		return media, err
	}
	return media, s.promoteIfFinalizing(ctx, sessionID)
}

// MediaURL returns a short-lived read URL for ready media to a participant.
func (s *Service) MediaURL(ctx context.Context, sessionID int64, actorID int, mediaID int64, expirySeconds int) (string, error) {
	if s.Storage == nil || expirySeconds <= 0 {
		return "", fmt.Errorf("recording: storage and positive expiry are required")
	}
	if _, err := s.GetSession(ctx, sessionID, actorID); err != nil {
		return "", err
	}
	res, err := s.query(ctx).Query(ctx, qGetMedia, mediaID, sessionID)
	if err != nil {
		return "", err
	}
	if len(res.Rows) == 0 {
		return "", ErrNotFound
	}
	row := res.Rows[0]
	if common.AsString(row[6]) != MediaReady {
		return "", ErrMediaNotReady
	}
	return s.Storage.GetSignedURL(ctx, common.AsString(row[2]), common.AsString(row[3]), expirySeconds)
}

func (s *Service) withCapture(ctx context.Context, sessionID int64, actorID int, captureToken string, fn func(port.TxQueryService, *sessionRow) error) error {
	tx, err := s.DB.BeginTx(ctx, queries)
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			_ = port.RollbackDetached(tx)
		}
	}()
	session, err := s.sessionBy(ctx, tx, qLockSession, sessionID)
	if err != nil {
		return err
	}
	if session.captureHash == "" || session.captureHash != sha256Hex(captureToken) || time.Now().After(session.CaptureExpiresAt) {
		return ErrCaptureToken
	}
	if !session.has(actorID) {
		return ErrForbidden
	}
	if err := fn(tx, session); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	committed = true
	return nil
}

func (s *Service) promoteIfFinalizing(ctx context.Context, sessionID int64) error {
	tx, err := s.DB.BeginTx(ctx, queries)
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			_ = port.RollbackDetached(tx)
		}
	}()
	session, err := s.sessionBy(ctx, tx, qLockSession, sessionID)
	if err != nil {
		return err
	}
	if session.Status == StatusFinalizing {
		ready, pending, _, err := s.mediaCounts(ctx, tx, sessionID)
		if err != nil {
			return err
		}
		if ready > 0 && pending == 0 {
			if _, err := tx.Query(ctx, qSetCapture, nil, nil, sessionID); err != nil {
				return err
			}
			if _, err := tx.Query(ctx, qSetStatus, StatusReady, sessionID); err != nil {
				return err
			}
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	committed = true
	return nil
}

func (s *Service) mediaCounts(ctx context.Context, qs port.QueryService, sessionID int64) (int64, int64, int64, error) {
	res, err := qs.Query(ctx, qMediaCounts, sessionID)
	if err != nil {
		return 0, 0, 0, err
	}
	if len(res.Rows) == 0 {
		return 0, 0, 0, nil
	}
	return common.AsInt64(res.Rows[0][0]), common.AsInt64(res.Rows[0][1]), common.AsInt64(res.Rows[0][2]), nil
}

type sessionRow struct {
	Session
	captureHash string
}

func (s *Service) sessionBy(ctx context.Context, qs port.QueryService, query string, args ...any) (*sessionRow, error) {
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
	}, captureHash: common.AsString(row[5])}
	if t, ok := row[6].(time.Time); ok {
		session.CaptureExpiresAt = t
	}
	session.PolicyID = common.AsInt64(row[7])
	parts, err := qs.Query(ctx, qListParticipants, session.ID)
	if err != nil {
		return nil, err
	}
	for _, p := range parts.Rows {
		session.Participants = append(session.Participants, Participant{UserID: int(common.AsInt64(p[0])), Role: common.AsString(p[1])})
	}
	return session, nil
}

func (r *sessionRow) has(userID int) bool {
	for _, p := range r.Participants {
		if p.UserID == userID {
			return true
		}
	}
	return false
}

func mediaFromRow(row []any) *Media {
	return &Media{ID: common.AsInt64(row[0]), SessionID: common.AsInt64(row[1]), Bucket: common.AsString(row[2]), ObjectKey: common.AsString(row[3]), ContentType: common.AsString(row[4]), SizeBytes: common.AsInt64(row[5]), Status: common.AsString(row[6])}
}

type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

func newCaptureToken() (raw, hash string, err error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", "", err
	}
	raw = hex.EncodeToString(b[:])
	return raw, sha256Hex(raw), nil
}

func sha256Hex(v string) string {
	sum := sha256.Sum256([]byte(v))
	return hex.EncodeToString(sum[:])
}
