package payout

import (
	"context"
	"sync"
	"time"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/data"
	"github.com/nauticana/keel/port"
)

const (
	qInstructionInsert       = "payout_instruction_insert"
	qInstructionByKey        = "payout_instruction_by_key"
	qInstructionLock         = "payout_instruction_lock"
	qInstructionLegs         = "payout_instruction_legs"
	qInstructionByTransfer   = "payout_instruction_by_transfer"
	qInstructionUpdateStatus = "payout_instruction_update_status"
	qInstructionDestination  = "payout_instruction_destination"
	qInstructionLegInsert    = "payout_instruction_leg_insert"
	qInstructionLegUpdate    = "payout_instruction_leg_update"
	qInstructionEventRecord  = "payout_instruction_event_record"
	qInstructionInFlight     = "payout_instruction_in_flight"
)

var instructionQueries = map[string]string{
	qInstructionInsert: `
INSERT INTO payout_instruction
 (id, partner_id, user_id, currency, amount_minor, idempotency_key, status, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
ON CONFLICT (partner_id, idempotency_key) DO NOTHING
RETURNING id`,

	qInstructionByKey: `
SELECT id FROM payout_instruction WHERE partner_id = ? AND idempotency_key = ?`,

	qInstructionLock: `
SELECT id, partner_id, user_id, currency, amount_minor, idempotency_key, status,
       COALESCE(failure_reason, ''), created_at
  FROM payout_instruction
 WHERE id = ?
   FOR UPDATE`,

	qInstructionLegs: `
SELECT leg_no, provider, user_bank_info_id, provider_account_id, amount_minor,
       provider_idempotency_key, COALESCE(provider_funding_id, ''), COALESCE(provider_payout_id, ''),
       status, reversed_minor, attempts, COALESCE(failure_reason, ''), created_at
  FROM payout_instruction_leg
 WHERE instruction_id = ?
 ORDER BY leg_no`,

	qInstructionByTransfer: `
SELECT DISTINCT instruction_id
  FROM payout_instruction_leg
 WHERE provider = ? AND (provider_payout_id = ? OR provider_funding_id = ?)`,

	qInstructionUpdateStatus: `
UPDATE payout_instruction
   SET status = ?, failure_reason = ?, updated_at = CURRENT_TIMESTAMP
 WHERE id = ?`,

	qInstructionDestination: `
SELECT id, provider, COALESCE(provider_account_id, ''), currency,
       provider_agreement AND provider_onboarded_at IS NOT NULL
  FROM user_bank_info
 WHERE user_id = ? AND partner_id = ? AND status = 'A'`,

	qInstructionLegInsert: `
INSERT INTO payout_instruction_leg
 (instruction_id, leg_no, provider, user_bank_info_id, provider_account_id, amount_minor,
  provider_idempotency_key, status, reversed_minor, attempts, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)`,

	qInstructionLegUpdate: `
UPDATE payout_instruction_leg
   SET provider_funding_id = ?, provider_payout_id = ?, status = ?, reversed_minor = ?,
       attempts = ?, failure_reason = ?, updated_at = CURRENT_TIMESTAMP
 WHERE instruction_id = ? AND leg_no = ?`,

	qInstructionEventRecord: `
INSERT INTO payout_instruction_event
 (provider, event_id, instruction_id, leg_no, event_type, amount_minor, amount_reversed_minor)
VALUES (?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (provider, event_id) DO NOTHING
RETURNING event_id`,

	qInstructionInFlight: `
SELECT id
  FROM payout_instruction
 WHERE status IN ('D', 'P') AND updated_at < ?
 ORDER BY updated_at
 LIMIT ?`,
}

// SQLInstructionStore is the PostgreSQL InstructionStore over
// payout_instruction, payout_instruction_leg and payout_instruction_event.
type SQLInstructionStore struct {
	DB port.DatabaseRepository

	qsOnce sync.Once
	qs     port.QueryService
}

func NewSQLInstructionStore(db port.DatabaseRepository) *SQLInstructionStore {
	return &SQLInstructionStore{DB: db}
}

func (s *SQLInstructionStore) queryService(ctx context.Context) port.QueryService {
	s.qsOnce.Do(func() {
		s.qs = s.DB.GetQueryService(ctx, instructionQueries)
	})
	return s.qs
}

func (s *SQLInstructionStore) InTx(ctx context.Context, fn func(InstructionTx) error) error {
	tx, err := s.DB.BeginTx(ctx, instructionQueries)
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			_ = data.RollbackDetached(tx)
		}
	}()
	if err := fn(&sqlInstructionTx{tx: tx}); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	committed = true
	return nil
}

func (s *SQLInstructionStore) InFlight(ctx context.Context, updatedBefore time.Time, limit int) ([]int64, error) {
	res, err := s.queryService(ctx).Query(ctx, qInstructionInFlight, updatedBefore, limit)
	if err != nil {
		return nil, err
	}
	ids := make([]int64, 0, len(res.Rows))
	for _, row := range res.Rows {
		ids = append(ids, common.AsInt64(row[0]))
	}
	return ids, nil
}

var _ InstructionStore = (*SQLInstructionStore)(nil)
