package agency

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/port"
	"github.com/nauticana/keel/service"
)

const (
	qAddClient             = "agency_add_client"
	qListClients           = "agency_list_clients"
	qMarkInvited           = "agency_mark_invited"
	qCancelClient          = "agency_cancel_client"
	qInviteInfo            = "agency_invite_info"
	qInviteForUpdate       = "agency_invite_for_update"
	qAcceptClient          = "agency_accept_client"
	qProfile               = "agency_profile"
	qInsertProfile         = "agency_insert_profile"
	qApproveProfile        = "agency_approve_profile"
	qInsertDelegation      = "agency_insert_delegation"
	qClientPartnerLock     = "agency_client_partner_lock"
	qActiveDelegation      = "agency_active_delegation"
	qInsertBilling         = "agency_insert_billing"
	qClientDelegation      = "agency_client_delegation"
	qDelegationForRevoke   = "agency_delegation_for_revoke"
	qCloseBilling          = "agency_close_billing"
	qRevokeDelegation      = "agency_revoke_delegation"
	qBillingDelegationLock = "agency_billing_delegation_lock"
	qCurrentBillingLock    = "agency_current_billing_lock"
	qCountDelegations      = "agency_count_delegations"
	qGrantRole             = "agency_grant_role"
	qEarningsBalances      = "agency_earnings_balances"
	qEarningsEntries       = "agency_earnings_entries"
	qEarningsPayouts       = "agency_earnings_payouts"
	qPayingClients         = "agency_paying_clients"
	qPayoutProfile         = "agency_payout_profile"
	qPayoutDestinations    = "agency_payout_destinations"
	qSetPayoutProfile      = "agency_set_payout_profile"
)

var baseAgencyQueries = map[string]string{
	qAddClient: `
INSERT INTO agency_client_invitation
 (id, agency_partner_id, client_name, client_email, client_website)
VALUES (?, ?, ?, ?, ?)`,

	qListClients: `
SELECT i.id, i.client_name, COALESCE(i.client_email, ''), COALESCE(i.client_website, ''),
       i.status, COALESCE(i.client_partner_id, 0), COALESCE(i.accepted_by, 0),
       i.invited_at, i.accepted_at, COALESCE(b.billing_model, '')
  FROM agency_client_invitation i
  LEFT JOIN agency_client_delegation d
    ON d.client_partner_id = i.client_partner_id
   AND d.agency_partner_id = i.agency_partner_id AND d.status = 'A'
  LEFT JOIN agency_client_billing b
    ON b.client_delegation_id = d.id AND b.effective_to IS NULL
 WHERE i.agency_partner_id = ? AND i.status <> 'X'
 ORDER BY i.id DESC`,

	qMarkInvited: `
UPDATE agency_client_invitation
   SET status = 'I', invite_token = COALESCE(invite_token, ?),
       invited_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP
 WHERE id = ? AND agency_partner_id = ? AND status IN ('S', 'I')
RETURNING invite_token`,

	qCancelClient: `
UPDATE agency_client_invitation
   SET status = 'X', updated_at = CURRENT_TIMESTAMP
 WHERE id = ? AND agency_partner_id = ? AND status IN ('S', 'I')
RETURNING id`,

	qInviteInfo: `
SELECT i.id, p.caption, i.client_name, i.status, i.invited_at
  FROM agency_client_invitation i
  JOIN business_partner p ON p.id = i.agency_partner_id
 WHERE i.invite_token = ?`,

	qInviteForUpdate: `
SELECT id, agency_partner_id, invited_at
  FROM agency_client_invitation
 WHERE invite_token = ? AND status = 'I'
 FOR UPDATE`,

	qAcceptClient: `
UPDATE agency_client_invitation
   SET status = 'V', client_partner_id = ?, accepted_by = ?,
       accepted_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP
 WHERE id = ? AND status = 'I'
RETURNING id`,

	qProfile: `
SELECT agency_partner_id, wholesale_allowed,
       COALESCE(default_commission_rate_bp, 0), approved_at, suspended
  FROM agency_profile
 WHERE agency_partner_id = ?`,

	qInsertProfile: `
INSERT INTO agency_profile (agency_partner_id) VALUES (?)
ON CONFLICT (agency_partner_id) DO NOTHING`,

	qApproveProfile: `
UPDATE agency_profile
   SET approved_at = COALESCE(approved_at, CURRENT_TIMESTAMP),
       suspended = FALSE, updated_at = CURRENT_TIMESTAMP
 WHERE agency_partner_id = ?
RETURNING agency_partner_id`,

	qInsertDelegation: `
INSERT INTO agency_client_delegation
 (id, client_partner_id, agency_partner_id, granted_by)
VALUES (?, ?, ?, ?)
RETURNING id`,

	qClientPartnerLock: `
SELECT id FROM business_partner WHERE id = ? FOR UPDATE`,

	qActiveDelegation: `
SELECT id
  FROM agency_client_delegation
 WHERE client_partner_id = ? AND status = 'A'
 LIMIT 1`,

	qInsertBilling: `
INSERT INTO agency_client_billing
 (id, client_delegation_id, billing_model)
VALUES (?, ?, ?)`,

	qClientDelegation: `
SELECT d.id, d.client_partner_id, cp.caption, d.agency_partner_id, ap.caption,
       COALESCE(b.billing_model, ''), d.granted_at
  FROM agency_client_delegation d
  JOIN business_partner cp ON cp.id = d.client_partner_id
  JOIN business_partner ap ON ap.id = d.agency_partner_id
  LEFT JOIN agency_client_billing b
    ON b.client_delegation_id = d.id
   AND b.effective_from <= CURRENT_TIMESTAMP
   AND (b.effective_to IS NULL OR b.effective_to > CURRENT_TIMESTAMP)
 WHERE d.client_partner_id = ? AND d.status = 'A'`,

	qDelegationForRevoke: `
SELECT id, agency_partner_id
  FROM agency_client_delegation
 WHERE client_partner_id = ? AND status = 'A'
 FOR UPDATE`,

	qCloseBilling: `
UPDATE agency_client_billing
   SET effective_to = CURRENT_TIMESTAMP
 WHERE client_delegation_id = ? AND effective_to IS NULL`,

	qRevokeDelegation: `
UPDATE agency_client_delegation
   SET status = 'R', revoked_at = CURRENT_TIMESTAMP, revoked_by = ?
 WHERE id = ? AND status = 'A'
RETURNING id`,

	qBillingDelegationLock: `
SELECT d.id, p.wholesale_allowed, p.approved_at, p.suspended
  FROM agency_client_delegation d
  JOIN agency_profile p ON p.agency_partner_id = d.agency_partner_id
 WHERE d.agency_partner_id = ? AND d.client_partner_id = ? AND d.status = 'A'
 FOR UPDATE OF d`,

	qCurrentBillingLock: `
SELECT id, billing_model
  FROM agency_client_billing
 WHERE client_delegation_id = ? AND effective_to IS NULL
 FOR UPDATE`,

	qCountDelegations: `
SELECT count(*)
  FROM agency_client_delegation
 WHERE agency_partner_id = ? AND status = 'A'`,

	qGrantRole: `
INSERT INTO user_permission (user_id, role_id, begda)
SELECT ?, 'AGENCY', CURRENT_TIMESTAMP
 WHERE NOT EXISTS (
   SELECT 1 FROM user_permission
    WHERE user_id = ? AND role_id = 'AGENCY'
      AND (endda IS NULL OR endda > CURRENT_TIMESTAMP))`,

	qEarningsBalances: `
SELECT c.currency,
       COALESCE(SUM(CASE WHEN c.status = 'H' THEN c.commission_amount_minor ELSE 0 END), 0),
       COALESCE(SUM(CASE WHEN c.status IN ('P', 'R') THEN c.commission_amount_minor ELSE 0 END), 0),
       COALESCE(SUM(CASE WHEN c.status IN ('D', 'O') THEN c.commission_amount_minor ELSE 0 END), 0)
  FROM agency_commission c
  JOIN agency_client_billing b ON b.id = c.client_billing_id
  JOIN agency_client_delegation d ON d.id = b.client_delegation_id
 WHERE d.agency_partner_id = ?
 GROUP BY c.currency
 ORDER BY c.currency`,

	qEarningsEntries: `
SELECT c.id, cp.caption, c.earning_period_start, c.earning_period_end,
       c.commission_amount_minor, c.currency, c.entry_type, c.status, c.earned_at
  FROM agency_commission c
  JOIN agency_client_billing b ON b.id = c.client_billing_id
  JOIN agency_client_delegation d ON d.id = b.client_delegation_id
  JOIN business_partner cp ON cp.id = d.client_partner_id
 WHERE d.agency_partner_id = ?
 ORDER BY c.id DESC
 LIMIT 50`,

	qEarningsPayouts: `
SELECT id, amount_minor, currency, status, selection_cutoff_at, paid_at
  FROM agency_payout
 WHERE agency_partner_id = ?
 ORDER BY id DESC
 LIMIT 24`,

	qPayingClients: `
SELECT count(*) FROM agency_client_rate WHERE agency_partner_id = ?`,

	qPayoutProfile: `
SELECT pp.agency_partner_id, ubi.id, ubi.country_code,
       ubi.currency, ubi.provider, COALESCE(ubi.provider_account_id, ''), pp.status
  FROM agency_payout_profile pp
  JOIN user_bank_info ubi
    ON ubi.id = pp.user_bank_info_id
   AND ubi.partner_id = pp.agency_partner_id
 WHERE pp.agency_partner_id = ?`,

	qPayoutDestinations: `
SELECT id, country_code, currency, provider, provider_account_id
  FROM user_bank_info
 WHERE partner_id = ? AND user_id = ? AND status = 'A'
   AND provider_agreement = TRUE
   AND provider_account_id IS NOT NULL
   AND provider_onboarded_at IS NOT NULL
 ORDER BY id DESC`,

	qSetPayoutProfile: `
INSERT INTO agency_payout_profile
 (agency_partner_id, user_bank_info_id, status)
SELECT p.agency_partner_id, ubi.id, 'A'
  FROM agency_profile p
  JOIN user_bank_info ubi
    ON ubi.id = ? AND ubi.partner_id = p.agency_partner_id
 WHERE p.agency_partner_id = ? AND p.approved_at IS NOT NULL AND p.suspended = FALSE
   AND ubi.user_id = ? AND ubi.status = 'A'
   AND ubi.provider_agreement = TRUE
   AND ubi.provider_account_id IS NOT NULL
   AND ubi.provider_onboarded_at IS NOT NULL
ON CONFLICT (agency_partner_id) DO UPDATE
   SET user_bank_info_id = EXCLUDED.user_bank_info_id,
       status = 'A', updated_at = CURRENT_TIMESTAMP
RETURNING agency_partner_id`,
}

type BaseAgencyServiceOptions struct {
	InviteTTL time.Duration
	Now       func() time.Time
}

// BaseAgencyService is the complete partner-to-partner agency lifecycle.
// Applications extend it with FK-backed entity tables when their managed
// client is narrower than business_partner.
type BaseAgencyService struct {
	service.AbstractService
	db        port.DatabaseRepository
	inviteTTL time.Duration
	now       func() time.Time
}

func NewBaseAgencyService(db port.DatabaseRepository, opts BaseAgencyServiceOptions) *BaseAgencyService {
	if opts.InviteTTL <= 0 {
		opts.InviteTTL = 30 * 24 * time.Hour
	}
	if opts.Now == nil {
		opts.Now = func() time.Time { return time.Now().UTC() }
	}
	return &BaseAgencyService{
		AbstractService: service.NewAbstractService(db, baseAgencyQueries),
		db:              db,
		inviteTTL:       opts.InviteTTL,
		now:             opts.Now,
	}
}

func (s *BaseAgencyService) AddClients(ctx context.Context, agencyPartnerID int64, clients []port.AgencyClientInput) (int, error) {
	if err := s.requireActive(ctx, agencyPartnerID); err != nil {
		return 0, err
	}
	tx, err := s.db.BeginTx(ctx, baseAgencyQueries)
	if err != nil {
		return 0, fmt.Errorf("agency: begin add-clients transaction: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = port.RollbackDetached(tx)
		}
	}()

	added := 0
	for _, client := range clients {
		name := strings.TrimSpace(client.Name)
		if name == "" {
			continue
		}
		_, err = tx.Query(ctx, qAddClient, tx.GenID(), agencyPartnerID, name,
			nullIfEmpty(strings.ToLower(strings.TrimSpace(client.Email))),
			nullIfEmpty(strings.TrimSpace(client.Website)))
		if err != nil {
			return 0, fmt.Errorf("agency: add client %q: %w", name, err)
		}
		added++
	}
	if err = tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("agency: commit add clients: %w", err)
	}
	committed = true
	return added, nil
}

func (s *BaseAgencyService) ListClients(ctx context.Context, agencyPartnerID int64) ([]port.AgencyClient, error) {
	rows, err := s.QueryRows(ctx, qListClients, agencyPartnerID)
	if err != nil {
		return nil, fmt.Errorf("agency: list clients: %w", err)
	}
	out := make([]port.AgencyClient, 0, len(rows))
	for _, row := range rows {
		client := port.AgencyClient{
			ID:              common.AsInt64(row[0]),
			Name:            common.AsString(row[1]),
			Email:           common.AsString(row[2]),
			Website:         common.AsString(row[3]),
			Status:          common.AsString(row[4]),
			ClientPartnerID: common.AsInt64(row[5]),
			AcceptedBy:      common.AsInt64(row[6]),
		}
		if invitedAt := common.AsTime(row[7]); !invitedAt.IsZero() {
			client.InvitedAt = &invitedAt
			client.Expired = client.Status == "I" && s.expired(invitedAt)
		}
		if acceptedAt := common.AsTime(row[8]); !acceptedAt.IsZero() {
			client.AcceptedAt = &acceptedAt
		}
		client.BillingModel = common.AsString(row[9])
		out = append(out, client)
	}
	return out, nil
}

func (s *BaseAgencyService) Invite(ctx context.Context, agencyPartnerID, invitationID int64) (string, error) {
	if err := s.requireActive(ctx, agencyPartnerID); err != nil {
		return "", err
	}
	token, err := randomToken()
	if err != nil {
		return "", fmt.Errorf("agency: mint invite token: %w", err)
	}
	row, err := s.QueryFirst(ctx, qMarkInvited, token, invitationID, agencyPartnerID)
	if err != nil {
		return "", fmt.Errorf("agency: invite client: %w", err)
	}
	if row == nil {
		return "", port.ErrAgencyNotFound
	}
	return common.AsString(row[0]), nil
}

func (s *BaseAgencyService) CancelClient(ctx context.Context, agencyPartnerID, invitationID int64) error {
	if err := s.requireActive(ctx, agencyPartnerID); err != nil {
		return err
	}
	row, err := s.QueryFirst(ctx, qCancelClient, invitationID, agencyPartnerID)
	if err != nil {
		return fmt.Errorf("agency: cancel client: %w", err)
	}
	if row == nil {
		return port.ErrAgencyNotFound
	}
	return nil
}

func (s *BaseAgencyService) InviteInfo(ctx context.Context, token string) (*port.AgencyInvite, error) {
	if strings.TrimSpace(token) == "" {
		return nil, port.ErrAgencyNotFound
	}
	row, err := s.QueryFirst(ctx, qInviteInfo, token)
	if err != nil {
		return nil, fmt.Errorf("agency: invite info: %w", err)
	}
	if row == nil {
		return nil, port.ErrAgencyNotFound
	}
	return &port.AgencyInvite{
		InvitationID: common.AsInt64(row[0]),
		AgencyName:   common.AsString(row[1]),
		ClientName:   common.AsString(row[2]),
		Status:       common.AsString(row[3]),
		Expired:      common.AsString(row[3]) == "I" && s.expired(common.AsTime(row[4])),
	}, nil
}

func (s *BaseAgencyService) AcceptInvite(ctx context.Context, token string, userID, clientPartnerID int64) error {
	if clientPartnerID <= 0 {
		return port.ErrNoPartnerYet
	}
	tx, err := s.db.BeginTx(ctx, baseAgencyQueries)
	if err != nil {
		return fmt.Errorf("agency: begin accept transaction: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = port.RollbackDetached(tx)
		}
	}()

	invite, err := tx.Query(ctx, qInviteForUpdate, token)
	if err != nil {
		return fmt.Errorf("agency: lock invite: %w", err)
	}
	if len(invite.Rows) == 0 {
		return port.ErrAgencyNotFound
	}
	if s.expired(common.AsTime(invite.Rows[0][2])) {
		return port.ErrInviteExpired
	}
	invitationID := common.AsInt64(invite.Rows[0][0])
	agencyPartnerID := common.AsInt64(invite.Rows[0][1])
	if agencyPartnerID == clientPartnerID {
		return port.ErrSelfDelegation
	}
	profile, err := tx.Query(ctx, qProfile, agencyPartnerID)
	if err != nil {
		return fmt.Errorf("agency: profile check: %w", err)
	}
	if len(profile.Rows) == 0 {
		return port.ErrAgencyNotFound
	}
	if err = activeProfileRow(profile.Rows[0]); err != nil {
		return err
	}
	lockedClient, err := tx.Query(ctx, qClientPartnerLock, clientPartnerID)
	if err != nil {
		return fmt.Errorf("agency: lock client partner: %w", err)
	}
	if len(lockedClient.Rows) == 0 {
		return port.ErrNoPartnerYet
	}
	activeDelegation, err := tx.Query(ctx, qActiveDelegation, clientPartnerID)
	if err != nil {
		return fmt.Errorf("agency: check active delegation: %w", err)
	}
	if len(activeDelegation.Rows) > 0 {
		return port.ErrDelegationExists
	}
	if accepted, err := tx.Query(ctx, qAcceptClient, clientPartnerID, userID, invitationID); err != nil {
		return fmt.Errorf("agency: accept invite: %w", err)
	} else if len(accepted.Rows) == 0 {
		return port.ErrAgencyNotFound
	}
	delegation, err := tx.Query(ctx, qInsertDelegation, tx.GenID(), clientPartnerID, agencyPartnerID, userID)
	if err != nil {
		return fmt.Errorf("agency: grant delegation: %w", err)
	}
	if len(delegation.Rows) == 0 {
		return port.ErrDelegationExists
	}
	// Acceptance always starts in referral mode. wholesale_allowed permits a
	// later per-client switch; it must never force every client wholesale.
	if _, err = tx.Query(ctx, qInsertBilling, tx.GenID(), common.AsInt64(delegation.Rows[0][0]), "R"); err != nil {
		return fmt.Errorf("agency: initial billing model: %w", err)
	}
	if err = tx.Commit(ctx); err != nil {
		return fmt.Errorf("agency: commit accept invite: %w", err)
	}
	committed = true
	return nil
}

func (s *BaseAgencyService) ClientDelegation(ctx context.Context, clientPartnerID int64) (*port.AgencyDelegation, error) {
	row, err := s.QueryFirst(ctx, qClientDelegation, clientPartnerID)
	if err != nil {
		return nil, fmt.Errorf("agency: client delegation: %w", err)
	}
	if row == nil {
		return nil, nil
	}
	return &port.AgencyDelegation{
		ID:              common.AsInt64(row[0]),
		ClientPartnerID: common.AsInt64(row[1]),
		ClientName:      common.AsString(row[2]),
		AgencyPartnerID: common.AsInt64(row[3]),
		AgencyName:      common.AsString(row[4]),
		BillingModel:    common.AsString(row[5]),
		GrantedAt:       common.AsTime(row[6]),
	}, nil
}

func (s *BaseAgencyService) RevokeDelegation(ctx context.Context, clientPartnerID, callerPartnerID, callerUserID int64) error {
	tx, err := s.db.BeginTx(ctx, baseAgencyQueries)
	if err != nil {
		return fmt.Errorf("agency: begin revoke transaction: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = port.RollbackDetached(tx)
		}
	}()
	if _, err = tx.Query(ctx, qClientPartnerLock, clientPartnerID); err != nil {
		return fmt.Errorf("agency: lock client partner: %w", err)
	}
	delegation, err := tx.Query(ctx, qDelegationForRevoke, clientPartnerID)
	if err != nil {
		return fmt.Errorf("agency: delegation lookup: %w", err)
	}
	if len(delegation.Rows) == 0 {
		return port.ErrAgencyNotFound
	}
	delegationID := common.AsInt64(delegation.Rows[0][0])
	agencyPartnerID := common.AsInt64(delegation.Rows[0][1])
	if callerPartnerID != agencyPartnerID && callerPartnerID != clientPartnerID {
		return port.ErrNotClientOwner
	}
	if _, err = tx.Query(ctx, qCloseBilling, delegationID); err != nil {
		return fmt.Errorf("agency: close billing model: %w", err)
	}
	if result, err := tx.Query(ctx, qRevokeDelegation, callerUserID, delegationID); err != nil {
		return fmt.Errorf("agency: revoke delegation: %w", err)
	} else if len(result.Rows) == 0 {
		return port.ErrAgencyNotFound
	}
	if err = tx.Commit(ctx); err != nil {
		return fmt.Errorf("agency: commit revoke: %w", err)
	}
	committed = true
	return nil
}

func (s *BaseAgencyService) SetBillingModel(ctx context.Context, agencyPartnerID, clientPartnerID int64, model string) error {
	model = strings.ToUpper(strings.TrimSpace(model))
	if model != "R" && model != "W" {
		return port.ErrInvalidBillingModel
	}
	tx, err := s.db.BeginTx(ctx, baseAgencyQueries)
	if err != nil {
		return fmt.Errorf("agency: begin billing-model transaction: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = port.RollbackDetached(tx)
		}
	}()
	delegation, err := tx.Query(ctx, qBillingDelegationLock, agencyPartnerID, clientPartnerID)
	if err != nil {
		return fmt.Errorf("agency: lock delegation: %w", err)
	}
	if len(delegation.Rows) == 0 {
		return port.ErrAgencyNotFound
	}
	if err = activeProfileValues(delegation.Rows[0][2], delegation.Rows[0][3]); err != nil {
		return err
	}
	if model == "W" && !common.AsBool(delegation.Rows[0][1]) {
		return port.ErrWholesaleNotAllowed
	}
	delegationID := common.AsInt64(delegation.Rows[0][0])
	current, err := tx.Query(ctx, qCurrentBillingLock, delegationID)
	if err != nil {
		return fmt.Errorf("agency: current billing model: %w", err)
	}
	if len(current.Rows) > 0 && common.AsString(current.Rows[0][1]) == model {
		if err = tx.Commit(ctx); err != nil {
			return fmt.Errorf("agency: commit unchanged billing model: %w", err)
		}
		committed = true
		return nil
	}
	if len(current.Rows) > 0 {
		if _, err = tx.Query(ctx, qCloseBilling, delegationID); err != nil {
			return fmt.Errorf("agency: close billing model: %w", err)
		}
	}
	if _, err = tx.Query(ctx, qInsertBilling, tx.GenID(), delegationID, model); err != nil {
		return fmt.Errorf("agency: insert billing model: %w", err)
	}
	if err = tx.Commit(ctx); err != nil {
		return fmt.Errorf("agency: commit billing model: %w", err)
	}
	committed = true
	return nil
}

func (s *BaseAgencyService) CountActiveDelegations(ctx context.Context, agencyPartnerID int64) (int, error) {
	row, err := s.QueryFirst(ctx, qCountDelegations, agencyPartnerID)
	if err != nil {
		return 0, fmt.Errorf("agency: count delegations: %w", err)
	}
	if row == nil {
		return 0, nil
	}
	return int(common.AsInt64(row[0])), nil
}

func (s *BaseAgencyService) Enroll(ctx context.Context, agencyPartnerID, userID int64) error {
	tx, err := s.db.BeginTx(ctx, baseAgencyQueries)
	if err != nil {
		return fmt.Errorf("agency: begin enrollment transaction: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = port.RollbackDetached(tx)
		}
	}()
	if _, err = tx.Query(ctx, qInsertProfile, agencyPartnerID); err != nil {
		return fmt.Errorf("agency: create profile: %w", err)
	}
	if _, err = tx.Query(ctx, qGrantRole, userID, userID); err != nil {
		return fmt.Errorf("agency: grant role: %w", err)
	}
	if err = tx.Commit(ctx); err != nil {
		return fmt.Errorf("agency: commit enrollment: %w", err)
	}
	committed = true
	return nil
}

func (s *BaseAgencyService) Profile(ctx context.Context, agencyPartnerID int64) (*port.AgencyProfile, error) {
	row, err := s.QueryFirst(ctx, qProfile, agencyPartnerID)
	if err != nil {
		return nil, fmt.Errorf("agency: profile: %w", err)
	}
	if row == nil {
		return nil, nil
	}
	profile := &port.AgencyProfile{
		AgencyPartnerID:  common.AsInt64(row[0]),
		WholesaleAllowed: common.AsBool(row[1]),
		DefaultRateBP:    int(common.AsInt64(row[2])),
		Suspended:        common.AsBool(row[4]),
	}
	if approvedAt := common.AsTime(row[3]); !approvedAt.IsZero() {
		profile.ApprovedAt = &approvedAt
	}
	return profile, nil
}

func (s *BaseAgencyService) Approve(ctx context.Context, agencyPartnerID int64) error {
	row, err := s.QueryFirst(ctx, qApproveProfile, agencyPartnerID)
	if err != nil {
		return fmt.Errorf("agency: approve: %w", err)
	}
	if row == nil {
		return port.ErrAgencyNotFound
	}
	return nil
}

func (s *BaseAgencyService) Earnings(ctx context.Context, agencyPartnerID int64) (*port.AgencyEarnings, error) {
	out := &port.AgencyEarnings{
		Balances: []port.AgencyEarningsBalance{},
		Entries:  []port.AgencyEarningEntry{},
		Payouts:  []port.AgencyPayout{},
	}
	rows, err := s.QueryRows(ctx, qEarningsBalances, agencyPartnerID)
	if err != nil {
		return nil, fmt.Errorf("agency: earnings balances: %w", err)
	}
	for _, row := range rows {
		out.Balances = append(out.Balances, port.AgencyEarningsBalance{
			Currency:  common.AsString(row[0]),
			HeldMinor: common.AsInt64(row[1]),
			DueMinor:  common.AsInt64(row[2]),
			PaidMinor: common.AsInt64(row[3]),
		})
	}
	rows, err = s.QueryRows(ctx, qEarningsEntries, agencyPartnerID)
	if err != nil {
		return nil, fmt.Errorf("agency: earnings entries: %w", err)
	}
	for _, row := range rows {
		out.Entries = append(out.Entries, port.AgencyEarningEntry{
			ID:          common.AsInt64(row[0]),
			ClientName:  common.AsString(row[1]),
			PeriodStart: common.AsTime(row[2]),
			PeriodEnd:   common.AsTime(row[3]),
			AmountMinor: common.AsInt64(row[4]),
			Currency:    common.AsString(row[5]),
			EntryType:   common.AsString(row[6]),
			Status:      common.AsString(row[7]),
			EarnedAt:    common.AsTime(row[8]),
		})
	}
	rows, err = s.QueryRows(ctx, qEarningsPayouts, agencyPartnerID)
	if err != nil {
		return nil, fmt.Errorf("agency: earnings payouts: %w", err)
	}
	for _, row := range rows {
		payout := port.AgencyPayout{
			ID:          common.AsInt64(row[0]),
			AmountMinor: common.AsInt64(row[1]),
			Currency:    common.AsString(row[2]),
			Status:      common.AsString(row[3]),
			CutoffAt:    common.AsTime(row[4]),
		}
		if paidAt := common.AsTime(row[5]); !paidAt.IsZero() {
			payout.PaidAt = &paidAt
		}
		out.Payouts = append(out.Payouts, payout)
	}
	if row, queryErr := s.QueryFirst(ctx, qPayingClients, agencyPartnerID); queryErr != nil {
		return nil, fmt.Errorf("agency: paying clients: %w", queryErr)
	} else if row != nil {
		out.PayingClients = int(common.AsInt64(row[0]))
	}
	return out, nil
}

func (s *BaseAgencyService) PayoutProfile(ctx context.Context, agencyPartnerID, userID int64) (*port.AgencyPayoutProfile, []port.AgencyPayoutDestination, error) {
	if err := s.requireActive(ctx, agencyPartnerID); err != nil {
		return nil, nil, err
	}
	var profile *port.AgencyPayoutProfile
	row, err := s.QueryFirst(ctx, qPayoutProfile, agencyPartnerID)
	if err != nil {
		return nil, nil, fmt.Errorf("agency: payout profile: %w", err)
	}
	if row != nil {
		profile = &port.AgencyPayoutProfile{
			AgencyPartnerID:   common.AsInt64(row[0]),
			UserBankInfoID:    common.AsInt64(row[1]),
			CountryCode:       common.AsString(row[2]),
			Currency:          common.AsString(row[3]),
			Provider:          common.AsString(row[4]),
			ProviderAccountID: common.AsString(row[5]),
			Status:            common.AsString(row[6]),
		}
	}
	rows, err := s.QueryRows(ctx, qPayoutDestinations, agencyPartnerID, userID)
	if err != nil {
		return nil, nil, fmt.Errorf("agency: payout destinations: %w", err)
	}
	destinations := make([]port.AgencyPayoutDestination, 0, len(rows))
	for _, destinationRow := range rows {
		destinations = append(destinations, port.AgencyPayoutDestination{
			UserBankInfoID:    common.AsInt64(destinationRow[0]),
			CountryCode:       common.AsString(destinationRow[1]),
			Currency:          common.AsString(destinationRow[2]),
			Provider:          common.AsString(destinationRow[3]),
			ProviderAccountID: common.AsString(destinationRow[4]),
		})
	}
	return profile, destinations, nil
}

func (s *BaseAgencyService) SetPayoutProfile(ctx context.Context, agencyPartnerID, userID, userBankInfoID int64) error {
	if err := s.requireActive(ctx, agencyPartnerID); err != nil {
		return err
	}
	row, err := s.QueryFirst(ctx, qSetPayoutProfile, userBankInfoID, agencyPartnerID, userID)
	if err != nil {
		return fmt.Errorf("agency: set payout profile: %w", err)
	}
	if row == nil {
		return port.ErrPayoutDestination
	}
	return nil
}

func (s *BaseAgencyService) requireActive(ctx context.Context, agencyPartnerID int64) error {
	row, err := s.QueryFirst(ctx, qProfile, agencyPartnerID)
	if err != nil {
		return fmt.Errorf("agency: profile: %w", err)
	}
	if row == nil {
		return port.ErrAgencyNotFound
	}
	return activeProfileRow(row)
}

func activeProfileRow(row []any) error {
	return activeProfileValues(row[3], row[4])
}

func activeProfileValues(approvedAt, suspended any) error {
	if common.AsBool(suspended) {
		return port.ErrAgencySuspended
	}
	if common.AsTime(approvedAt).IsZero() {
		return port.ErrAgencyNotApproved
	}
	return nil
}

func (s *BaseAgencyService) expired(invitedAt time.Time) bool {
	return invitedAt.IsZero() || !s.now().Before(invitedAt.Add(s.inviteTTL))
}

func randomToken() (string, error) {
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func nullIfEmpty(value string) any {
	if value == "" {
		return nil
	}
	return value
}

var _ port.AgencyService = (*BaseAgencyService)(nil)
