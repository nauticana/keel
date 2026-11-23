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

// accountStatusChange moves an account in one of the from statuses to to and
// records activity.
type accountStatusChange struct {
	from         [2]string
	to, activity string
}

var (
	lockAccount     = accountStatusChange{[2]string{UserStatusActive, UserStatusSelfLocked}, UserStatusAdminLock, UserActivityLock}
	unlockAccount   = accountStatusChange{[2]string{UserStatusAdminLock, UserStatusAdminLock}, UserStatusActive, UserActivityUnlock}
	expireAccount   = accountStatusChange{[2]string{UserStatusActive, UserStatusSelfLocked}, UserStatusExpired, UserActivityExpire}
	activateAccount = accountStatusChange{[2]string{UserStatusExpired, UserStatusInitial}, UserStatusActive, UserActivityActivate}
)

// LockAccount sets an active or self-locked account to UserStatusAdminLock.
func (s *LocalUserService) LockAccount(actorID, userID int, reason string) error {
	return s.changeAccountStatus(actorID, userID, reason, lockAccount)
}

// UnlockAccount returns an account LockAccount locked to active.
func (s *LocalUserService) UnlockAccount(actorID, userID int, note string) error {
	return s.changeAccountStatus(actorID, userID, note, unlockAccount)
}

// ExpireAccount sets an active or self-locked account to UserStatusExpired.
func (s *LocalUserService) ExpireAccount(actorID, userID int, reason string) error {
	return s.changeAccountStatus(actorID, userID, reason, expireAccount)
}

// ActivateAccount sets an expired or not yet activated account to active.
func (s *LocalUserService) ActivateAccount(actorID, userID int, note string) error {
	return s.changeAccountStatus(actorID, userID, note, activateAccount)
}

// changeAccountStatus applies change and records actorID and reason in one
// transaction; an account in no from status returns ErrAccountState. A change
// away from active revokes every refresh and access token; one to active
// clears the failed sign-in count.
func (s *LocalUserService) changeAccountStatus(actorID, userID int, reason string, change accountStatusChange) error {
	switch {
	case actorID <= 0 || userID <= 0:
		return model.NewBadRequest("id is required")
	case actorID == userID:
		return ErrSelfAction
	case utf8.RuneCountInString(reason) > MaxHistoryReason:
		return ErrReasonTooLong
	}
	active := change.to == UserStatusActive
	lock := s.tokenCutoffLock(userID)
	lock.Lock()
	defer lock.Unlock()
	ctx := s.ctx()
	err := data.InTx(ctx, s.database, LocalUserQueries, func(tx port.TxQueryService) error {
		res, err := tx.Query(ctx, qSetAccountStatus, change.to, active, userID, change.from[0], change.from[1])
		if err != nil {
			return err
		}
		if len(res.Rows) == 0 {
			return ErrAccountState
		}
		if _, err := tx.Query(ctx, qAddUserActivity, userID, time.Now(), change.activity, change.to, reason, "", actorID); err != nil {
			return err
		}
		if active {
			return nil
		}
		return s.revokeTokensTx(ctx, tx, userID)
	})
	if err != nil || active {
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
