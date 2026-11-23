package user

import (
	"context"
	"fmt"
	"time"
	"unicode/utf8"

	"github.com/nauticana/keel/data"
	"github.com/nauticana/keel/model"
	"github.com/nauticana/keel/port"
)

// LockAccount sets an active or self-locked account to UserStatusAdminLock, so
// sign-in and token refresh are refused, revokes every refresh and access
// token, and records actorID and reason. Any other account returns
// ErrAccountState, so unlocking cannot activate an expired or deleted one.
func (s *LocalUserService) LockAccount(actorID, userID int, reason string) error {
	return s.setAdminLock(actorID, userID, reason, true)
}

// UnlockAccount returns an account LockAccount locked to active, clears its
// failed sign-in count and records actorID and note. Any other account
// returns ErrAccountState.
func (s *LocalUserService) UnlockAccount(actorID, userID int, note string) error {
	return s.setAdminLock(actorID, userID, note, false)
}

func (s *LocalUserService) setAdminLock(actorID, userID int, reason string, locked bool) error {
	switch {
	case actorID <= 0 || userID <= 0:
		return model.NewBadRequest("id is required")
	case actorID == userID:
		return ErrSelfAction
	case utf8.RuneCountInString(reason) > MaxHistoryReason:
		return ErrReasonTooLong
	}
	query, activity, status := qClearAdminLock, UserActivityUnlock, UserStatusActive
	if locked {
		query, activity, status = qSetAdminLock, UserActivityLock, UserStatusAdminLock
	}
	lock := s.tokenCutoffLock(userID)
	lock.Lock()
	defer lock.Unlock()
	ctx := s.ctx()
	err := data.InTx(ctx, s.database, LocalUserQueries, func(tx port.TxQueryService) error {
		res, err := tx.Query(ctx, query, userID)
		if err != nil {
			return err
		}
		if len(res.Rows) == 0 {
			return ErrAccountState
		}
		if _, err := tx.Query(ctx, qAddUserActivity, userID, time.Now(), activity, status, reason, "", actorID); err != nil {
			return err
		}
		if !locked {
			return nil
		}
		return s.revokeTokensTx(ctx, tx, userID)
	})
	if err != nil || !locked {
		return err
	}
	return s.revokedTokens(ctx, userID)
}

// revokeTokensTx revokes every refresh and access token of userID in tx; call
// revokedTokens after the commit.
func (s *LocalUserService) revokeTokensTx(ctx context.Context, tx port.TxQueryService, userID int) error {
	if _, err := tx.Query(ctx, qRevokeAllRefreshTokensForID, userID); err != nil {
		return fmt.Errorf("revoke refresh tokens: %w", err)
	}
	if _, err := tx.Query(ctx, qRevokeAccessTokens, userID); err != nil {
		return fmt.Errorf("revoke access tokens: %w", err)
	}
	return nil
}

// revokedTokens drops the cached access-token cutoff and revokes the
// authorization-server tokens of userID.
func (s *LocalUserService) revokedTokens(ctx context.Context, userID int) error {
	s.forgetTokenCutoff(userID)
	if s.OAuthTokens == nil {
		return nil
	}
	if err := s.OAuthTokens.RevokeForUser(ctx, int64(userID)); err != nil {
		return fmt.Errorf("revoke authorization-server tokens: %w", err)
	}
	return nil
}
