package user

import (
	"fmt"
	"strings"
	"time"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/guard"
	"github.com/nauticana/keel/model"
)

const maxUserAgentLen = 400 // user_refresh_token.user_agent

var localUserTxQueries = common.MergeMaps(LocalUserQueries, guard.Queries)

// deviceHashOf is the stored form of a device cookie; "" for none.
func deviceHashOf(secret string) string {
	if secret == "" {
		return ""
	}
	return sha256Hex(secret)
}

// deviceSeen reports whether the user has signed in before, and from deviceHash.
func (s *LocalUserService) deviceSeen(userID int, deviceHash string) (prior, known bool, err error) {
	res, err := s.queryService.Query(s.ctx(), qDeviceSeen, userID, userID, deviceHash)
	if err != nil {
		return false, false, err
	}
	if len(res.Rows) != 1 || len(res.Rows[0]) != 2 {
		return false, false, fmt.Errorf("device lookup returned %d rows", len(res.Rows))
	}
	return common.AsBool(res.Rows[0][0]), deviceHash != "" && common.AsBool(res.Rows[0][1]), nil
}

// IsKnownDevice reports whether the user has signed in from the device
// cookie's device before.
func (s *LocalUserService) IsKnownDevice(userID int, deviceSecret string) (bool, error) {
	if deviceSecret == "" {
		return false, nil
	}
	_, known, err := s.deviceSeen(userID, deviceHashOf(deviceSecret))
	return known, err
}

// checkSignInNetwork refuses ip unless the user's session partner lists no
// sign-in networks or one of them holds it.
func (s *LocalUserService) checkSignInNetwork(userID int, ip string) error {
	res, err := s.queryService.Query(s.ctx(), qSignInNetworks, userID)
	if err != nil {
		return fmt.Errorf("sign-in networks: %w", err)
	}
	if len(res.Rows) == 0 {
		return nil
	}
	cidrs := make([]string, len(res.Rows))
	for i, r := range res.Rows {
		cidrs[i] = common.AsString(r[0])
	}
	nets, err := common.ParseCIDRList(strings.Join(cidrs, ","))
	if err != nil {
		return fmt.Errorf("sign-in networks of user %d: %w", userID, err)
	}
	if !common.CIDRListAllows(nets, ip) {
		return ErrSignInNetwork
	}
	return nil
}

// notifyNewDevice is best effort: the sign-in has already succeeded.
func (s *LocalUserService) notifyNewDevice(session *model.UserSession, device SessionDevice) {
	err := ErrStepUpUnavailable
	if s.SignInNotifier != nil {
		err = s.SignInNotifier.NewDeviceSignIn(s.ctx(), session, device)
	}
	if err != nil && s.Journal != nil {
		s.Journal.Error(fmt.Sprintf("user: new-device sign-in notice for user %d: %v", session.Id, err))
	}
}

// SendStepUpCode delivers a one-time code (OTPPurposeStepUp) the user must
// present to finish signing in from a new device.
func (s *LocalUserService) SendStepUpCode(userID int) error {
	if s.SignInNotifier == nil {
		return ErrStepUpUnavailable
	}
	account, err := s.GetUserById(userID)
	if err != nil {
		return err
	}
	code, err := s.GenerateOTP(userID, OTPPurposeStepUp)
	if err != nil {
		return err
	}
	return s.SignInNotifier.StepUpCode(s.ctx(), account, code)
}

// Sessions lists the user's live sign-in sessions, most recently used first.
func (s *LocalUserService) Sessions(userID int) ([]ActiveSession, error) {
	res, err := s.queryService.Query(s.ctx(), qLiveSessions, userID)
	if err != nil {
		return nil, err
	}
	out := make([]ActiveSession, 0, len(res.Rows))
	for _, r := range res.Rows {
		created, _ := r[4].(time.Time)
		seen, _ := r[5].(time.Time)
		out = append(out, ActiveSession{
			ID: common.AsInt64(r[0]), UserAgent: common.AsString(r[1]), ClientIP: common.AsString(r[2]),
			SignInMethod: common.AsString(r[3]), CreatedAt: created, LastSeenAt: seen,
		})
	}
	return out, nil
}

// RevokeSession signs the user out of one session. Access tokens it already
// holds stay valid until they expire (session_timeout).
func (s *LocalUserService) RevokeSession(userID int, sessionID int64) error {
	if userID <= 0 || sessionID <= 0 {
		return ErrSessionNotFound
	}
	res, err := s.queryService.Query(s.ctx(), qRevokeSession, userID, sessionID)
	if err != nil {
		return err
	}
	if len(res.Rows) == 0 {
		return ErrSessionNotFound
	}
	return nil
}
