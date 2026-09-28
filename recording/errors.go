package recording

import "errors"

var (
	ErrNotFound       = errors.New("recording: session not found")
	ErrForbidden      = errors.New("recording: actor is not a participant")
	ErrConsentMissing = errors.New("recording: a required participant has not consented")
	ErrInvalidState   = errors.New("recording: operation not allowed in the session's state")
	ErrCaptureToken   = errors.New("recording: invalid or expired capture token")
	ErrInviteToken    = errors.New("recording: invalid or expired invite token")
	ErrMediaNotFound  = errors.New("recording: media not found")
	ErrMediaNotReady  = errors.New("recording: media is not ready")
	ErrMediaPurged    = errors.New("recording: media was purged by retention")
	ErrMediaTooLarge  = errors.New("recording: media exceeds size limit")
	ErrConflict       = errors.New("recording: context already has a session with different terms")
)
