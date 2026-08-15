package agency

import (
	"context"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/config"
	"github.com/nauticana/keel/logger"
	"github.com/nauticana/keel/payment"
	"github.com/nauticana/keel/payout"
	"github.com/nauticana/keel/port"
	"github.com/nauticana/keel/service"
)

type AgencyPayoutRunner interface {
	RunCycle(ctx context.Context) error
}

type BaseAgencyPayoutOptions struct {
	Journal              logger.ApplicationLogger
	Now                  func() time.Time
	ClaimStaleAfter      time.Duration
	IdempotencyRetention time.Duration
	MaxDispatchAttempts  int
}

// BaseAgencyPayoutService selects, reserves, dispatches, and reconciles
// aggregate agency payouts. Database claims happen in short transactions;
// provider calls never run while a database transaction is open.
type BaseAgencyPayoutService struct {
	service.AbstractService
	DB       port.DatabaseRepository
	Provider payout.PayoutProvider
	Ledger   port.AgencyCommissionLedger
	Journal  logger.ApplicationLogger

	now                  func() time.Time
	claimStaleAfter      time.Duration
	idempotencyRetention time.Duration
	maxDispatchAttempts  int
}

func NewBaseAgencyPayoutService(db port.DatabaseRepository, provider payout.PayoutProvider, ledger port.AgencyCommissionLedger, opts BaseAgencyPayoutOptions) *BaseAgencyPayoutService {
	if opts.Now == nil {
		opts.Now = func() time.Time { return time.Now().UTC() }
	}
	if opts.ClaimStaleAfter <= 0 {
		opts.ClaimStaleAfter = time.Hour
	}
	if opts.IdempotencyRetention <= 0 {
		opts.IdempotencyRetention = 20 * time.Hour
	}
	if opts.MaxDispatchAttempts <= 0 {
		opts.MaxDispatchAttempts = 3
	}
	return &BaseAgencyPayoutService{
		AbstractService:      service.NewAbstractService(db, agencyPayoutQueries),
		DB:                   db,
		Provider:             provider,
		Ledger:               ledger,
		Journal:              opts.Journal,
		now:                  opts.Now,
		claimStaleAfter:      opts.ClaimStaleAfter,
		idempotencyRetention: opts.IdempotencyRetention,
		maxDispatchAttempts:  opts.MaxDispatchAttempts,
	}
}

const (
	qPayoutGroups          = "agency_payout_groups"
	qPayoutBlockedGroups   = "agency_payout_blocked_groups"
	qPayoutDestinationLock = "agency_payout_destination_lock"
	qPayoutEntries         = "agency_payout_entries"
	qPayoutInsert          = "agency_payout_insert"
	qPayoutInsertLine      = "agency_payout_insert_line"
	qPayoutReserveEntry    = "agency_payout_reserve_entry"
	qPayoutDispatchable    = "agency_payout_dispatchable"
	qPayoutClaim           = "agency_payout_claim"
	qPayoutRecordDispatch  = "agency_payout_record_dispatch"
	qPayoutRecordFailure   = "agency_payout_record_failure"
	qPayoutByTransfer      = "agency_payout_by_transfer"
	qPayoutMarkPaid        = "agency_payout_mark_paid"
	qPayoutEntriesPaid     = "agency_payout_entries_paid"
	qPayoutReleaseLines    = "agency_payout_release_lines"
	qPayoutEntriesPayable  = "agency_payout_entries_payable"
	qPayoutMarkManual      = "agency_payout_mark_manual"
	qPayoutMarkReturned    = "agency_payout_mark_returned"
	qPayoutMarkReversed    = "agency_payout_mark_reversed"
	qPayoutReclaimStale    = "agency_payout_reclaim_stale"
	qPayoutStaleDispatched = "agency_payout_stale_dispatched"
)

var agencyPayoutQueries = map[string]string{
	qPayoutGroups: `
SELECT c.currency, d.agency_partner_id, ubi.id, ubi.user_id,
       ubi.provider, ubi.provider_account_id, SUM(c.commission_amount_minor)
  FROM agency_commission c
  JOIN agency_client_billing b ON b.id = c.client_billing_id
  JOIN agency_client_delegation d ON d.id = b.client_delegation_id
  JOIN agency_profile a
    ON a.agency_partner_id = d.agency_partner_id
   AND a.approved_at IS NOT NULL AND a.suspended = FALSE
  JOIN agency_payout_profile pp
    ON pp.agency_partner_id = d.agency_partner_id AND pp.status = 'A'
  JOIN user_bank_info ubi ON ubi.id = pp.user_bank_info_id
 WHERE c.status = 'P' AND (c.entry_type = 'R' OR c.earned_at < ?)
   AND ubi.status = 'A' AND ubi.provider = ?
   AND ubi.provider_account_id IS NOT NULL
   AND ubi.provider_agreement = TRUE
   AND ubi.provider_onboarded_at IS NOT NULL
   AND ubi.currency = c.currency
 GROUP BY c.currency, d.agency_partner_id, ubi.id, ubi.user_id,
          ubi.provider, ubi.provider_account_id`,

	qPayoutBlockedGroups: `
SELECT c.currency, d.agency_partner_id, SUM(c.commission_amount_minor)
  FROM agency_commission c
  JOIN agency_client_billing b ON b.id = c.client_billing_id
  JOIN agency_client_delegation d ON d.id = b.client_delegation_id
  JOIN agency_profile a
    ON a.agency_partner_id = d.agency_partner_id
   AND a.approved_at IS NOT NULL AND a.suspended = FALSE
 WHERE c.status = 'P' AND (c.entry_type = 'R' OR c.earned_at < ?)
GROUP BY c.currency, d.agency_partner_id
HAVING SUM(c.commission_amount_minor) > 0
   AND SUM(c.commission_amount_minor) >= ?
   AND NOT EXISTS (
       SELECT 1
         FROM agency_payout_profile pp
         JOIN user_bank_info ubi ON ubi.id = pp.user_bank_info_id
        WHERE pp.agency_partner_id = d.agency_partner_id AND pp.status = 'A'
          AND ubi.status = 'A' AND ubi.provider = ?
          AND ubi.provider_account_id IS NOT NULL
          AND ubi.provider_agreement = TRUE
          AND ubi.provider_onboarded_at IS NOT NULL
          AND ubi.currency = c.currency
   )`,

	qPayoutEntries: `
SELECT c.id, c.commission_amount_minor
  FROM agency_commission c
  JOIN agency_client_billing b ON b.id = c.client_billing_id
  JOIN agency_client_delegation d ON d.id = b.client_delegation_id
  JOIN agency_profile a
    ON a.agency_partner_id = d.agency_partner_id
   AND a.approved_at IS NOT NULL AND a.suspended = FALSE
 WHERE c.status = 'P' AND (c.entry_type = 'R' OR c.earned_at < ?)
   AND d.agency_partner_id = ? AND c.currency = ?
 ORDER BY c.id
 FOR UPDATE OF c`,

	qPayoutDestinationLock: `
SELECT ubi.id
  FROM agency_payout_profile pp
  JOIN user_bank_info ubi ON ubi.id = pp.user_bank_info_id
 WHERE pp.agency_partner_id = ? AND pp.status = 'A' AND ubi.id = ?
   AND ubi.status = 'A' AND ubi.provider = ?
   AND ubi.provider_account_id = ? AND ubi.currency = ?
   AND ubi.provider_agreement = TRUE AND ubi.provider_onboarded_at IS NOT NULL
 FOR UPDATE OF pp, ubi`,

	qPayoutInsert: `
INSERT INTO agency_payout
 (id, agency_partner_id, user_bank_info_id, amount_minor, currency,
  provider, provider_account_id, selection_cutoff_at, idempotency_key)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (agency_partner_id, currency, provider_account_id, selection_cutoff_at)
  WHERE status <> 'F' DO NOTHING
RETURNING id`,

	qPayoutInsertLine: `
INSERT INTO agency_payout_line (payout_id, commission_id, amount_minor)
VALUES (?, ?, ?)`,

	qPayoutReserveEntry: `
UPDATE agency_commission SET status = 'R'
 WHERE id = ? AND status = 'P'
RETURNING id`,

	qPayoutDispatchable: `
SELECT id
  FROM agency_payout
 WHERE status = 'C' AND provider_transfer_id IS NULL
   AND (next_attempt_at IS NULL OR next_attempt_at <= CURRENT_TIMESTAMP)
 ORDER BY id`,

	qPayoutClaim: `
WITH claimed AS (
  UPDATE agency_payout
     SET status = 'P', attempt_count = attempt_count + 1,
         attempted_at = CURRENT_TIMESTAMP
   WHERE id = ? AND status = 'C' AND provider_transfer_id IS NULL
  RETURNING agency_partner_id, user_bank_info_id, amount_minor, currency,
            provider_account_id, idempotency_key, provider_funding_id,
            attempt_count, created_at
)
SELECT c.agency_partner_id, ubi.user_id, c.amount_minor, c.currency,
       c.provider_account_id, c.idempotency_key, c.provider_funding_id,
       c.attempt_count, c.created_at
  FROM claimed c
  JOIN user_bank_info ubi ON ubi.id = c.user_bank_info_id`,

	qPayoutRecordDispatch: `
UPDATE agency_payout
   SET provider_transfer_id = COALESCE(?, provider_transfer_id),
       provider_funding_id = COALESCE(?, provider_funding_id),
       status = ?, next_attempt_at = ?, failure_message = ?
 WHERE id = ? AND status = 'P'
RETURNING id`,

	qPayoutRecordFailure: `
UPDATE agency_payout
   SET status = 'F', failure_message = ?, next_attempt_at = NULL
 WHERE id = ? AND status IN ('C', 'P', 'F')
RETURNING id`,

	qPayoutByTransfer: `
SELECT id, status
  FROM agency_payout
 WHERE (provider = ? AND provider_transfer_id = ?)
    OR (provider = ? AND provider_funding_id = ?)
 LIMIT 1`,

	qPayoutMarkPaid: `
UPDATE agency_payout
   SET status = 'D', paid_at = COALESCE(paid_at, CURRENT_TIMESTAMP)
 WHERE id = ? AND status IN ('C', 'P', 'D')
RETURNING id`,

	qPayoutEntriesPaid: `
UPDATE agency_commission c
   SET status = CASE WHEN c.entry_type = 'E' THEN 'D' ELSE 'O' END
  FROM agency_payout_line l
 WHERE l.payout_id = ? AND l.released_at IS NULL
   AND c.id = l.commission_id AND c.status = 'R'`,

	qPayoutReleaseLines: `
UPDATE agency_payout_line SET released_at = CURRENT_TIMESTAMP
 WHERE payout_id = ? AND released_at IS NULL`,

	qPayoutEntriesPayable: `
UPDATE agency_commission c
   SET status = 'P'
  FROM agency_payout_line l
 WHERE l.payout_id = ? AND l.released_at IS NULL
   AND c.id = l.commission_id AND c.status IN ('R', 'D', 'O')`,

	qPayoutMarkManual: `
UPDATE agency_payout
   SET status = 'M', failure_message = COALESCE(?, failure_message)
 WHERE id = ? AND status IN ('C', 'P', 'M')
RETURNING id`,

	qPayoutMarkReturned: `
UPDATE agency_payout
   SET status = 'R', failure_message = COALESCE(?, failure_message)
 WHERE id = ? AND status IN ('P', 'D', 'R')
RETURNING id`,

	qPayoutMarkReversed: `
UPDATE agency_payout
   SET status = 'V', failure_message = COALESCE(?, failure_message)
 WHERE id = ? AND status IN ('P', 'D', 'V')
RETURNING id`,

	qPayoutReclaimStale: `
UPDATE agency_payout
   SET status = 'C', next_attempt_at = CURRENT_TIMESTAMP
 WHERE status = 'P' AND provider_transfer_id IS NULL AND attempted_at < ?`,

	qPayoutStaleDispatched: `
SELECT id, provider_transfer_id
  FROM agency_payout
 WHERE status = 'P' AND provider_transfer_id IS NOT NULL AND attempted_at < ?
 ORDER BY id
 LIMIT 50`,
}

func (s *BaseAgencyPayoutService) RunCycle(ctx context.Context) error {
	if s.Ledger == nil {
		return fmt.Errorf("agency payout: commission ledger is not configured")
	}
	if err := s.Ledger.PromoteHeld(ctx); err != nil {
		return err
	}
	if s.Provider == nil {
		return fmt.Errorf("agency payout: provider is not configured")
	}
	now := s.now()
	cutoff := monthStart(now)
	var cycleErrors []error
	if err := s.buildPayouts(ctx, cutoff); err != nil {
		cycleErrors = append(cycleErrors, fmt.Errorf("agency payout: build: %w", err))
	}
	staleBefore := now.Add(-s.claimStaleAfter)
	if _, err := s.Query(ctx, qPayoutReclaimStale, staleBefore); err != nil {
		cycleErrors = append(cycleErrors, fmt.Errorf("agency payout: reclaim stale claims: %w", err))
	}
	cycleErrors = append(cycleErrors, s.dispatch(ctx), s.reconcileStale(ctx, staleBefore))
	return errors.Join(cycleErrors...)
}

func (s *BaseAgencyPayoutService) buildPayouts(ctx context.Context, cutoff time.Time) error {
	minimum := config.Config().AgencyPayoutMinMinor
	result, err := s.Query(ctx, qPayoutGroups, cutoff, s.Provider.Code())
	if err != nil {
		return err
	}
	blocked, err := s.Query(ctx, qPayoutBlockedGroups, cutoff, minimum, s.Provider.Code())
	if err != nil {
		return fmt.Errorf("find unpayable agency balances: %w", err)
	}
	var reserveErrors []error
	for _, row := range blocked.Rows {
		blockedErr := fmt.Errorf(
			"agency %d has %d %s payable but no active %s payout destination for that currency",
			common.AsInt64(row[1]), common.AsInt64(row[2]), common.AsString(row[0]), s.Provider.Code())
		s.logWarning(blockedErr.Error())
		reserveErrors = append(reserveErrors, blockedErr)
	}
	for _, row := range result.Rows {
		net := common.AsInt64(row[6])
		if net <= 0 || net < minimum {
			continue
		}
		if err = s.reserveGroup(ctx,
			common.AsInt64(row[1]), common.AsInt64(row[2]),
			common.AsString(row[0]), common.AsString(row[4]),
			common.AsString(row[5]), cutoff, minimum); err != nil {
			reserveErrors = append(reserveErrors,
				fmt.Errorf("agency %d %s: %w", common.AsInt64(row[1]), common.AsString(row[0]), err))
		}
	}
	return errors.Join(reserveErrors...)
}

func (s *BaseAgencyPayoutService) reserveGroup(ctx context.Context, agencyID, bankInfoID int64, currency, providerCode, accountID string, cutoff time.Time, minimum int64) error {
	tx, err := s.DB.BeginTx(ctx, agencyPayoutQueries)
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			_ = port.RollbackDetached(tx)
		}
	}()
	destination, err := tx.Query(ctx, qPayoutDestinationLock,
		agencyID, bankInfoID, providerCode, accountID, currency)
	if err != nil {
		return err
	}
	if len(destination.Rows) == 0 {
		return fmt.Errorf("agency payout: destination %d is no longer active for %s/%s", bankInfoID, providerCode, currency)
	}
	entries, err := tx.Query(ctx, qPayoutEntries, cutoff, agencyID, currency)
	if err != nil {
		return err
	}
	var total int64
	for _, row := range entries.Rows {
		amount := common.AsInt64(row[1])
		if (amount > 0 && total > math.MaxInt64-amount) ||
			(amount < 0 && total < math.MinInt64-amount) {
			return payment.ErrMoneyArithmetic
		}
		total += amount
	}
	if total <= 0 || total < minimum {
		if err = tx.Commit(ctx); err != nil {
			return err
		}
		committed = true
		return nil
	}
	payoutID := tx.GenID()
	inserted, err := tx.Query(ctx, qPayoutInsert,
		payoutID, agencyID, bankInfoID, total, currency, providerCode,
		accountID, cutoff, fmt.Sprintf("agency-%d", payoutID))
	if err != nil {
		return err
	}
	if len(inserted.Rows) == 0 {
		if err = tx.Commit(ctx); err != nil {
			return err
		}
		committed = true
		return nil
	}
	for _, row := range entries.Rows {
		commissionID := common.AsInt64(row[0])
		reserved, reserveErr := tx.Query(ctx, qPayoutReserveEntry, commissionID)
		if reserveErr != nil {
			return reserveErr
		}
		if len(reserved.Rows) == 0 {
			return fmt.Errorf("agency payout: commission %d lost its reservation race", commissionID)
		}
		if _, err = tx.Query(ctx, qPayoutInsertLine, payoutID, commissionID, common.AsInt64(row[1])); err != nil {
			return err
		}
	}
	if err = tx.Commit(ctx); err != nil {
		return err
	}
	committed = true
	return nil
}

func (s *BaseAgencyPayoutService) dispatch(ctx context.Context) error {
	result, err := s.Query(ctx, qPayoutDispatchable)
	if err != nil {
		return fmt.Errorf("agency payout: list dispatchable: %w", err)
	}
	var dispatchErrors []error
	for _, row := range result.Rows {
		if err = s.dispatchOne(ctx, common.AsInt64(row[0])); err != nil {
			s.logError(err.Error())
			dispatchErrors = append(dispatchErrors, err)
		}
	}
	return errors.Join(dispatchErrors...)
}

func (s *BaseAgencyPayoutService) dispatchOne(ctx context.Context, payoutID int64) error {
	claim, err := s.Query(ctx, qPayoutClaim, payoutID)
	if err != nil {
		return fmt.Errorf("agency payout %d: claim: %w", payoutID, err)
	}
	if len(claim.Rows) == 0 {
		return nil
	}
	row := claim.Rows[0]
	agencyID := common.AsInt64(row[0])
	userID := common.AsInt64(row[1])
	input := payout.InstantPayoutInput{
		UserID:            userID,
		PartnerID:         agencyID,
		ProviderAccountID: common.AsString(row[4]),
		Amount:            common.AsInt64(row[2]),
		Currency:          common.AsString(row[3]),
		IdempotencyKey:    common.AsString(row[5]),
	}
	fundingID := common.AsString(row[6])
	attempts := int(common.AsInt64(row[7]))
	createdAt := common.AsTime(row[8])
	var response *payout.InstantPayoutResult
	if fundingID != "" {
		resumer, ok := s.Provider.(payout.PayoutResumer)
		if !ok {
			return s.parkManual(ctx, payoutID, "provider cannot resume a partially funded payout")
		}
		response, err = resumer.ResumePayout(ctx, input, fundingID)
	} else {
		if attempts > s.maxDispatchAttempts || s.now().Sub(createdAt) > s.idempotencyRetention {
			return s.parkManual(ctx, payoutID, "dispatch unresolved beyond the provider idempotency window")
		}
		response, err = s.Provider.RequestInstantPayout(ctx, input)
	}
	var transferValue, fundingValue any
	if response != nil {
		if response.ProviderPayoutID != "" {
			transferValue = response.ProviderPayoutID
		}
		if response.ProviderFundingID != "" {
			fundingValue = response.ProviderFundingID
		}
	}
	if err != nil {
		status := "P"
		var nextAttempt any
		if transferValue == nil {
			status = "C"
			nextAttempt = s.now().Add(time.Hour)
		}
		if errors.Is(err, payout.ErrInsufficientBalance) {
			s.logError(fmt.Sprintf("agency payout %d: insufficient platform balance", payoutID))
		}
		return s.recordDispatch(ctx, payoutID, transferValue, fundingValue, status, nextAttempt, err.Error())
	}
	if err = s.recordDispatch(ctx, payoutID, transferValue, fundingValue, "P", nil, ""); err != nil {
		return err
	}
	if response != nil && response.Status == "paid" {
		return s.markPaid(ctx, payoutID)
	}
	return nil
}

func (s *BaseAgencyPayoutService) recordDispatch(ctx context.Context, payoutID int64, transferID, fundingID any, status string, nextAttempt any, failure string) error {
	var failureValue any
	if failure != "" {
		failureValue = failure
	}
	result, err := s.Query(ctx, qPayoutRecordDispatch,
		transferID, fundingID, status, nextAttempt, failureValue, payoutID)
	if err != nil {
		return fmt.Errorf("agency payout %d: record dispatch: %w", payoutID, err)
	}
	if len(result.Rows) == 0 {
		return fmt.Errorf("agency payout %d: dispatch result conflicts with its current state", payoutID)
	}
	return nil
}

func (s *BaseAgencyPayoutService) failTerminal(ctx context.Context, payoutID int64, message string) error {
	return s.release(ctx, payoutID, "F", message, true)
}

func (s *BaseAgencyPayoutService) parkManual(ctx context.Context, payoutID int64, message string) error {
	result, err := s.Query(ctx, qPayoutMarkManual, message, payoutID)
	if err != nil {
		return fmt.Errorf("agency payout %d: park for manual review: %w", payoutID, err)
	}
	if len(result.Rows) == 0 {
		return fmt.Errorf("agency payout %d: cannot enter manual review from its current state", payoutID)
	}
	s.logError(fmt.Sprintf("agency payout %d: %s", payoutID, message))
	return nil
}

func (s *BaseAgencyPayoutService) markPaid(ctx context.Context, payoutID int64) error {
	tx, err := s.DB.BeginTx(ctx, agencyPayoutQueries)
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			_ = port.RollbackDetached(tx)
		}
	}()
	result, err := tx.Query(ctx, qPayoutMarkPaid, payoutID)
	if err != nil {
		return err
	}
	if len(result.Rows) == 0 {
		return fmt.Errorf("agency payout %d: paid event conflicts with its current state", payoutID)
	}
	if _, err = tx.Query(ctx, qPayoutEntriesPaid, payoutID); err != nil {
		return err
	}
	if err = tx.Commit(ctx); err != nil {
		return err
	}
	committed = true
	return nil
}

func (s *BaseAgencyPayoutService) release(ctx context.Context, payoutID int64, status, message string, failed bool) error {
	tx, err := s.DB.BeginTx(ctx, agencyPayoutQueries)
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			_ = port.RollbackDetached(tx)
		}
	}()
	query := qPayoutMarkReturned
	args := []any{message, payoutID}
	if failed {
		query = qPayoutRecordFailure
		args = []any{message, payoutID}
	}
	result, err := tx.Query(ctx, query, args...)
	if err != nil {
		return err
	}
	if len(result.Rows) == 0 {
		return fmt.Errorf("agency payout %d: %s event conflicts with its current state", payoutID, status)
	}
	if _, err = tx.Query(ctx, qPayoutEntriesPayable, payoutID); err != nil {
		return err
	}
	if _, err = tx.Query(ctx, qPayoutReleaseLines, payoutID); err != nil {
		return err
	}
	if err = tx.Commit(ctx); err != nil {
		return err
	}
	committed = true
	return nil
}

func (s *BaseAgencyPayoutService) ApplyTransferEvent(ctx context.Context, event *payout.PayoutWebhookEvent) error {
	if event == nil || s.Provider == nil {
		return nil
	}
	result, err := s.Query(ctx, qPayoutByTransfer,
		s.Provider.Code(), event.ProviderTransferID,
		s.Provider.Code(), event.ProviderTransferID)
	if err != nil {
		return err
	}
	if len(result.Rows) == 0 {
		return fmt.Errorf("agency payout: no payout for transfer %s", event.ProviderTransferID)
	}
	payoutID := common.AsInt64(result.Rows[0][0])
	switch event.Type {
	case payout.PayoutEventTransferPaid:
		return s.markPaid(ctx, payoutID)
	case payout.PayoutEventTransferFailed:
		return s.failTerminal(ctx, payoutID, "provider reported transfer failed")
	case payout.PayoutEventTransferReturned:
		return s.release(ctx, payoutID, "R", "provider reported transfer returned", false)
	case payout.PayoutEventTransferReversed:
		if event.AmountReversedMinor > 0 && event.AmountMinor > 0 && event.AmountReversedMinor < event.AmountMinor {
			return s.parkManual(ctx, payoutID, fmt.Sprintf("partial provider reversal %d of %d", event.AmountReversedMinor, event.AmountMinor))
		}
		result, markErr := s.Query(ctx, qPayoutMarkReversed, "provider reported transfer reversed", payoutID)
		if markErr != nil {
			return markErr
		}
		if len(result.Rows) == 0 {
			return fmt.Errorf("agency payout %d: reversed event conflicts with its current state", payoutID)
		}
		s.logError(fmt.Sprintf("agency payout %d: reversed after payment; recoverable balance needs operations review", payoutID))
	}
	return nil
}

func (s *BaseAgencyPayoutService) reconcileStale(ctx context.Context, staleBefore time.Time) error {
	result, err := s.Query(ctx, qPayoutStaleDispatched, staleBefore)
	if err != nil {
		return fmt.Errorf("agency payout: list stale dispatches: %w", err)
	}
	var reconcileErrors []error
	for _, row := range result.Rows {
		payoutID := common.AsInt64(row[0])
		providerID := common.AsString(row[1])
		status, statusErr := s.Provider.GetPayoutStatus(ctx, providerID)
		if statusErr != nil {
			wrapped := fmt.Errorf("agency payout %d: reconcile: %w", payoutID, statusErr)
			s.logWarning(wrapped.Error())
			reconcileErrors = append(reconcileErrors, wrapped)
			continue
		}
		switch status.Status {
		case "paid":
			err = s.markPaid(ctx, payoutID)
		case "failed":
			err = s.failTerminal(ctx, payoutID, "reconciliation reports failed")
		case "returned":
			err = s.release(ctx, payoutID, "R", "reconciliation reports returned", false)
		case "reversed":
			marked, markErr := s.Query(ctx, qPayoutMarkReversed, "reconciliation reports reversed", payoutID)
			err = markErr
			if markErr == nil && len(marked.Rows) == 0 {
				err = fmt.Errorf("agency payout %d: reconciled reversal conflicts with its current state", payoutID)
			}
		}
		if err != nil {
			reconcileErrors = append(reconcileErrors, err)
		}
	}
	return errors.Join(reconcileErrors...)
}

func (s *BaseAgencyPayoutService) logError(message string) {
	if s.Journal != nil {
		s.Journal.Error(message)
	}
}

func (s *BaseAgencyPayoutService) logWarning(message string) {
	if s.Journal != nil {
		s.Journal.Warning(message)
	}
}

func monthStart(at time.Time) time.Time {
	at = at.UTC()
	return time.Date(at.Year(), at.Month(), 1, 0, 0, 0, 0, time.UTC)
}

var _ AgencyPayoutRunner = (*BaseAgencyPayoutService)(nil)
var _ payout.TransferEventSink = (*BaseAgencyPayoutService)(nil)
