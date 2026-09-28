// Package recording orchestrates consent-gated capture sessions over an
// application-defined context. Keel enforces consent, session state and
// media storage; capture itself happens on the client or a capture provider.
package recording

import (
	"context"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/data"
	"github.com/nauticana/keel/port"
	"github.com/nauticana/keel/storage"
	"github.com/nauticana/keel/user"
)

// Service is the consent-gated session state machine. Storage is required for
// uploads; CaptureTTL bounds a capture authorization.
type Service struct {
	DB                 port.DatabaseRepository
	Consents           user.ConsentService
	Storage            storage.ObjectStorage
	CaptureTTL         time.Duration
	MaxMediaBytes      int64
	AllowedContentType map[string]bool
	// ObjectKey overrides the default "recording/<sessionID>/<key>" layout. It
	// must be deterministic and unique per (session, key), and stay under "recording/".
	ObjectKey func(s Session, key string) string

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
	if existing, err := loadSession(ctx, s.query(ctx), qGetSessionByCtx, partnerID, contextRef); err == nil {
		if existing.ConsentType != consentType || existing.PolicyID != policyID {
			return nil, ErrConflict
		}
		return &existing.Session, nil
	} else if !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	var id int64
	err = s.inTx(ctx, func(tx port.TxQueryService) error {
		id = tx.GenID()
		if _, err := tx.Query(ctx, qInsertSession, id, partnerID, contextRef, consentType, policyID, createdBy); err != nil {
			return err
		}
		for _, p := range participants {
			if _, err := tx.Query(ctx, qInsertParticipant, id, p.UserID, p.Role); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	created, err := loadSession(ctx, s.query(ctx), qGetSession, id)
	if err != nil {
		return nil, err
	}
	return &created.Session, nil
}

// GetSession returns a session to one of its participants.
func (s *Service) GetSession(ctx context.Context, sessionID int64, actorID int) (*Session, error) {
	session, err := loadSession(ctx, s.query(ctx), qGetSession, sessionID)
	if err != nil {
		return nil, err
	}
	if !session.has(actorID) {
		return nil, ErrForbidden
	}
	return &session.Session, nil
}

// Decide records a participant's consent for the session's current attempt.
// Declining or withdrawing while authorized or recording stops the session.
func (s *Service) Decide(ctx context.Context, sessionID int64, actorID int, consented bool, meta user.ConsentRequest) error {
	return s.withLocked(ctx, sessionID, actorID, func(tx port.TxQueryService, session *sessionRow) error {
		if err := s.recordConsent(ctx, &session.Session, actorID, consented, meta); err != nil {
			return err
		}
		if consented {
			return nil
		}
		switch session.Status {
		case StatusAuthorized:
			if _, err := tx.Query(ctx, qSetCapture, nil, nil, sessionID); err != nil {
				return err
			}
			_, err := tx.Query(ctx, qSetStatus, StatusStopped, sessionID)
			return err
		case StatusRecording:
			_, err := tx.Query(ctx, qSetStatus, StatusFinalizing, sessionID)
			return err
		}
		return nil
	})
}

// Start authorizes capture once every participant's current decision for
// this attempt is affirmative. Returns the capture token the client must
// present to Acknowledge, Renew and Upload.
func (s *Service) Start(ctx context.Context, sessionID int64, actorID int) (token string, expiresAt time.Time, err error) {
	err = s.withLocked(ctx, sessionID, actorID, func(tx port.TxQueryService, session *sessionRow) error {
		if session.Status != StatusAwaitingConsent && session.Status != StatusAuthorized {
			return ErrInvalidState
		}
		for _, p := range session.Participants {
			consented, found, err := s.Consents.LatestConsentFor(ctx, p.UserID, session.ConsentType, EventRef(sessionID, session.Attempt), session.PolicyID)
			if err != nil {
				return err
			}
			if !found || !consented {
				return ErrConsentMissing
			}
		}
		var hash string
		if token, hash, err = newToken(); err != nil {
			return err
		}
		expiresAt = time.Now().Add(s.captureTTL())
		if _, err := tx.Query(ctx, qSetCapture, hash, expiresAt, sessionID); err != nil {
			return err
		}
		_, err := tx.Query(ctx, qSetStatus, StatusAuthorized, sessionID)
		return err
	})
	if err != nil {
		return "", time.Time{}, err
	}
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
	return s.withLocked(ctx, sessionID, actorID, func(tx port.TxQueryService, session *sessionRow) error {
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
		if next == "" {
			return nil
		}
		if next == StatusStopped || next == StatusReady {
			if _, err := tx.Query(ctx, qSetCapture, nil, nil, sessionID); err != nil {
				return err
			}
		}
		_, err := tx.Query(ctx, qSetStatus, next, sessionID)
		return err
	})
}

// Reopen returns a stopped or ready session to awaiting consent under a new
// attempt, so every participant must consent again. Media is kept.
func (s *Service) Reopen(ctx context.Context, sessionID int64, actorID int) (*Session, error) {
	err := s.withLocked(ctx, sessionID, actorID, func(tx port.TxQueryService, session *sessionRow) error {
		if session.Status != StatusStopped && session.Status != StatusReady {
			return ErrInvalidState
		}
		_, err := tx.Query(ctx, qReopen, sessionID)
		return err
	})
	if err != nil {
		return nil, err
	}
	return s.GetSession(ctx, sessionID, actorID)
}

// Invite mints a join token for a session that is still capturable; only a
// participant may mint. The token is reusable until it expires.
func (s *Service) Invite(ctx context.Context, sessionID int64, actorID int, ttl time.Duration) (token string, expiresAt time.Time, err error) {
	if ttl <= 0 {
		return "", time.Time{}, fmt.Errorf("recording: invite ttl must be positive")
	}
	session, err := s.GetSession(ctx, sessionID, actorID)
	if err != nil {
		return "", time.Time{}, err
	}
	if !session.joinable() {
		return "", time.Time{}, ErrInvalidState
	}
	token, hash, err := newToken()
	if err != nil {
		return "", time.Time{}, err
	}
	expiresAt = time.Now().Add(ttl)
	if _, err := s.query(ctx).Query(ctx, qInsertInvite, hash, sessionID, expiresAt, actorID); err != nil {
		return "", time.Time{}, err
	}
	return token, expiresAt, nil
}

// InviteSession resolves an unexpired invite token without consuming it.
func (s *Service) InviteSession(ctx context.Context, token string) (*Session, error) {
	sessionID, err := s.inviteSessionID(ctx, token)
	if err != nil {
		return nil, err
	}
	session, err := loadSession(ctx, s.query(ctx), qGetSession, sessionID)
	if err != nil {
		return nil, err
	}
	return &session.Session, nil
}

// JoinWithConsent adds userID under role and records its affirmative consent
// in the same session lock, so no state holds an unconsented participant. An
// existing participant keeps its role and re-records consent.
func (s *Service) JoinWithConsent(ctx context.Context, token string, userID int, role string, meta user.ConsentRequest) (*Session, error) {
	if userID <= 0 || role == "" {
		return nil, fmt.Errorf("recording: user id and role are required")
	}
	sessionID, err := s.inviteSessionID(ctx, token)
	if err != nil {
		return nil, err
	}
	var joined Session
	err = s.inTx(ctx, func(tx port.TxQueryService) error {
		session, err := loadSession(ctx, tx, qLockSession, sessionID)
		if err != nil {
			return err
		}
		if !session.joinable() {
			return ErrInvalidState
		}
		if !session.has(userID) {
			if _, err := tx.Query(ctx, qInsertParticipant, sessionID, userID, role); err != nil {
				return err
			}
			session.Participants = append(session.Participants, Participant{UserID: userID, Role: role})
		}
		joined = session.Session
		return s.recordConsent(ctx, &session.Session, userID, true, meta)
	})
	if err != nil {
		return nil, err
	}
	return &joined, nil
}

// Upload stores one object for a recording or finalizing session. The media
// row is pending until the object is persisted; a failed upload stays failed.
func (s *Service) Upload(ctx context.Context, sessionID int64, actorID int, captureToken, objectKey, contentType string, body io.Reader) (*Media, error) {
	if s.Storage == nil || s.MaxMediaBytes <= 0 {
		return nil, fmt.Errorf("recording: storage is not configured")
	}
	if body == nil || !s.AllowedContentType[contentType] {
		return nil, fmt.Errorf("recording: media body or content type is invalid")
	}
	cleanKey := path.Clean(strings.TrimSpace(objectKey))
	if cleanKey == "." || cleanKey == ".." || strings.HasPrefix(cleanKey, "../") || strings.HasPrefix(cleanKey, "/") {
		return nil, fmt.Errorf("recording: invalid object key")
	}
	var media *Media
	err := s.withCapture(ctx, sessionID, actorID, captureToken, func(tx port.TxQueryService, session *sessionRow) error {
		if session.Status != StatusRecording && session.Status != StatusFinalizing {
			return ErrInvalidState
		}
		storageKey, err := s.storageKey(session.Session, cleanKey)
		if err != nil {
			return err
		}
		existing, err := tx.Query(ctx, qGetMediaByKey, sessionID, storageKey)
		if err != nil {
			return err
		}
		if len(existing.Rows) > 0 {
			media = mediaFromRow(existing.Rows[0])
			if media.Status == MediaReady {
				return nil
			}
			if media.Status != MediaFailed {
				return ErrInvalidState
			}
			_, err = tx.Query(ctx, qResetMedia, contentType, actorID, media.ID)
			return err
		}
		media = &Media{ID: tx.GenID(), SessionID: sessionID, Bucket: s.Storage.Bucket(), ObjectKey: storageKey, ContentType: contentType, Status: MediaPending}
		_, err = tx.Query(ctx, qInsertMedia, media.ID, sessionID, s.Storage.Bucket(), storageKey, contentType, 0, actorID)
		return err
	})
	if err != nil {
		return nil, err
	}
	if media.Status == MediaReady {
		return media, nil
	}
	counter := &countingReader{r: io.LimitReader(body, s.MaxMediaBytes+1)}
	if err := s.Storage.PutObject(ctx, media.ObjectKey, counter, contentType, nil); err != nil || counter.n > s.MaxMediaBytes {
		_ = s.Storage.DeleteObject(ctx, media.ObjectKey)
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
	if _, err := s.GetSession(ctx, sessionID, actorID); err != nil {
		return "", err
	}
	return s.signedMediaURL(ctx, expirySeconds, qGetMedia, mediaID, sessionID)
}

// ListMedia returns every media row of a session without a participant
// check; the caller must already have authorized the actor.
func (s *Service) ListMedia(ctx context.Context, sessionID int64) ([]Media, error) {
	if _, err := loadSession(ctx, s.query(ctx), qGetSession, sessionID); err != nil {
		return nil, err
	}
	res, err := s.query(ctx).Query(ctx, qListMedia, sessionID)
	if err != nil {
		return nil, err
	}
	media := make([]Media, 0, len(res.Rows))
	for _, row := range res.Rows {
		media = append(media, *mediaFromRow(row))
	}
	return media, nil
}

// PrivilegedMediaURL is MediaURL without the participant check, for a caller
// the application has already authorized (e.g. a reviewer role).
func (s *Service) PrivilegedMediaURL(ctx context.Context, mediaID int64, expirySeconds int) (string, error) {
	return s.signedMediaURL(ctx, expirySeconds, qGetMediaByID, mediaID)
}

func (s *Service) signedMediaURL(ctx context.Context, expirySeconds int, query string, args ...any) (string, error) {
	if s.Storage == nil || expirySeconds <= 0 {
		return "", fmt.Errorf("recording: storage and positive expiry are required")
	}
	res, err := s.query(ctx).Query(ctx, query, args...)
	if err != nil {
		return "", err
	}
	if len(res.Rows) == 0 {
		return "", ErrMediaNotFound
	}
	media := mediaFromRow(res.Rows[0])
	switch media.Status {
	case MediaReady:
	case MediaPurged:
		return "", ErrMediaPurged
	default:
		return "", ErrMediaNotReady
	}
	if media.Bucket != s.Storage.Bucket() {
		return "", fmt.Errorf("recording: media %d is in bucket %q, storage is bound to %q", media.ID, media.Bucket, s.Storage.Bucket())
	}
	return s.Storage.GetSignedURL(ctx, media.ObjectKey, expirySeconds)
}

func (s *Service) storageKey(session Session, key string) (string, error) {
	if s.ObjectKey == nil {
		return fmt.Sprintf("recording/%d/%s", session.ID, key), nil
	}
	custom := path.Clean(s.ObjectKey(session, key))
	if !strings.HasPrefix(custom, "recording/") {
		return "", fmt.Errorf("recording: ObjectKey %q is outside recording/", custom)
	}
	return custom, nil
}

func (s *Service) recordConsent(ctx context.Context, session *Session, userID int, consented bool, meta user.ConsentRequest) error {
	meta.UserID = userID
	meta.ConsentType = session.ConsentType
	meta.EventRef = EventRef(session.ID, session.Attempt)
	meta.Consented = consented
	meta.PolicyID = session.PolicyID
	if consented {
		return s.Consents.Record(ctx, meta)
	}
	return s.Consents.Withdraw(ctx, meta)
}

func (s *Service) inviteSessionID(ctx context.Context, token string) (int64, error) {
	if token == "" {
		return 0, ErrInviteToken
	}
	res, err := s.query(ctx).Query(ctx, qInviteSession, sha256Hex(token), time.Now())
	if err != nil {
		return 0, err
	}
	if len(res.Rows) == 0 {
		return 0, ErrInviteToken
	}
	return common.AsInt64(res.Rows[0][0]), nil
}

func (s *Service) inTx(ctx context.Context, fn func(port.TxQueryService) error) error {
	tx, err := s.DB.BeginTx(ctx, queries)
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			_ = data.RollbackDetached(tx)
		}
	}()
	if err := fn(tx); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	committed = true
	return nil
}

// withLocked runs fn under the session row lock for a participant actor.
func (s *Service) withLocked(ctx context.Context, sessionID int64, actorID int, fn func(port.TxQueryService, *sessionRow) error) error {
	return s.inTx(ctx, func(tx port.TxQueryService) error {
		session, err := loadSession(ctx, tx, qLockSession, sessionID)
		if err != nil {
			return err
		}
		if !session.has(actorID) {
			return ErrForbidden
		}
		return fn(tx, session)
	})
}

func (s *Service) withCapture(ctx context.Context, sessionID int64, actorID int, captureToken string, fn func(port.TxQueryService, *sessionRow) error) error {
	return s.inTx(ctx, func(tx port.TxQueryService) error {
		session, err := loadSession(ctx, tx, qLockSession, sessionID)
		if err != nil {
			return err
		}
		if session.captureHash == "" || session.captureHash != sha256Hex(captureToken) || time.Now().After(session.CaptureExpiresAt) {
			return ErrCaptureToken
		}
		if !session.has(actorID) {
			return ErrForbidden
		}
		return fn(tx, session)
	})
}

func (s *Service) promoteIfFinalizing(ctx context.Context, sessionID int64) error {
	return s.inTx(ctx, func(tx port.TxQueryService) error {
		session, err := loadSession(ctx, tx, qLockSession, sessionID)
		if err != nil || session.Status != StatusFinalizing {
			return err
		}
		ready, pending, _, err := s.mediaCounts(ctx, tx, sessionID)
		if err != nil || ready == 0 || pending > 0 {
			return err
		}
		if _, err := tx.Query(ctx, qSetCapture, nil, nil, sessionID); err != nil {
			return err
		}
		_, err = tx.Query(ctx, qSetStatus, StatusReady, sessionID)
		return err
	})
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
