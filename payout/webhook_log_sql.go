package payout

import (
	"context"
	"fmt"
	"sync"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/port"
)

// Processing status values stored in payout_webhook_log.processing_status.
const (
	WebhookStatusReceived  = "R"
	WebhookStatusProcessed = "P"
	WebhookStatusFailed    = "F"
)

const (
	qPayoutLogWebhook     = "payout_log_webhook"
	qPayoutWebhookExists  = "payout_check_webhook_exists"
	qPayoutWebhookStatus  = "payout_update_webhook_status"
	qPayoutWebhookReclaim = "payout_reclaim_webhook"
	qPayoutWebhookVerify  = "payout_verify_webhook_index"
)

var payoutWebhookQueries = map[string]string{
	qPayoutLogWebhook: `
INSERT INTO payout_webhook_log
 (id, provider, event_id, event_type, provider_account_id, provider_transfer_id, processing_status, raw_payload)
VALUES
 (nextval('payout_webhook_log_seq'), ?, ?, ?, ?, ?, 'R', ?)
RETURNING id
`,
	qPayoutWebhookExists: `
SELECT processing_status
  FROM payout_webhook_log
 WHERE provider = ? AND event_id = ?
 LIMIT 1
`,
	qPayoutWebhookStatus: `
UPDATE payout_webhook_log
   SET processing_status = ?,
       error_message = ?,
       processed_at = CURRENT_TIMESTAMP
 WHERE id = ?
`,
	qPayoutWebhookVerify: `
SELECT indexdef
  FROM pg_indexes
 WHERE schemaname = current_schema()
   AND tablename = 'payout_webhook_log'
   AND indexname = 'payout_webhook_log_uq'
 LIMIT 1
`,
	// Atomically re-claim a failed delivery — or an in-flight claim
	// abandoned for over an hour (crash between claim and status update)
	// — for reprocessing. The status predicate is the race guard: among
	// concurrent provider retries exactly one UPDATE wins the RETURNING
	// id; processed rows are never re-claimed.
	qPayoutWebhookReclaim: `
UPDATE payout_webhook_log
   SET processing_status = 'R',
       error_message = NULL,
       received_at = CURRENT_TIMESTAMP
 WHERE provider = ? AND event_id = ?
   AND (processing_status = 'F'
        OR (processing_status = 'R' AND received_at < CURRENT_TIMESTAMP - INTERVAL '1 hour'))
RETURNING id
`,
}

// SQLWebhookLog is the default SQL-backed WebhookLog over the basis
// payout_webhook_log table. The UNIQUE (provider, event_id) index is the
// authoritative race guard against concurrent provider retries.
//
// PostgreSQL-only (nextval / RETURNING / INTERVAL), like
// payment.SQLWebhookRepository — MySQL consumers must provide their own
// WebhookLog implementation.
type SQLWebhookLog struct {
	DB port.DatabaseRepository

	qsOnce sync.Once
	qs     port.QueryService

	verifyMu sync.Mutex
	verified bool
}

func NewSQLWebhookLog(db port.DatabaseRepository) *SQLWebhookLog {
	return &SQLWebhookLog{DB: db}
}

func (r *SQLWebhookLog) queryService(ctx context.Context) port.QueryService {
	r.qsOnce.Do(func() {
		r.qs = r.DB.GetQueryService(ctx, payoutWebhookQueries)
	})
	return r.qs
}

// Claim implements the WebhookLog contract: re-claim a retryable prior
// delivery, otherwise treat any existing row as duplicate, otherwise
// insert fresh (the unique index resolves the concurrent-insert race).
func (r *SQLWebhookLog) Claim(ctx context.Context, provider string, ev *PayoutWebhookEvent, rawBody []byte) (int64, bool, error) {
	qs := r.queryService(ctx)
	if err := r.verify(ctx, qs); err != nil {
		return 0, false, err
	}

	res, err := qs.Query(ctx, qPayoutWebhookReclaim, provider, ev.RawEventID)
	if err != nil {
		return 0, false, fmt.Errorf("reclaim payout webhook: %w", err)
	}
	if len(res.Rows) > 0 {
		return common.AsInt64(res.Rows[0][0]), false, nil
	}

	res, err = qs.Query(ctx, qPayoutWebhookExists, provider, ev.RawEventID)
	if err != nil {
		return 0, false, fmt.Errorf("check payout webhook exists: %w", err)
	}
	if len(res.Rows) > 0 {
		return 0, true, nil // processed or freshly in flight — duplicate
	}

	var accountID, transferID any
	if ev.ExternalAccountID != "" {
		accountID = ev.ExternalAccountID
	}
	if ev.ProviderTransferID != "" {
		transferID = ev.ProviderTransferID
	}
	res, err = qs.Query(ctx, qPayoutLogWebhook,
		provider, ev.RawEventID, string(ev.Type), accountID, transferID, string(rawBody))
	if err != nil {
		// Lost the unique-index race to a concurrent delivery.
		if again, e2 := qs.Query(ctx, qPayoutWebhookExists, provider, ev.RawEventID); e2 == nil && len(again.Rows) > 0 {
			return 0, true, nil
		}
		return 0, false, fmt.Errorf("log payout webhook: %w", err)
	}
	if len(res.Rows) == 0 {
		return 0, false, fmt.Errorf("log payout webhook: no id returned")
	}
	return common.AsInt64(res.Rows[0][0]), false, nil
}

func (r *SQLWebhookLog) UpdateStatus(ctx context.Context, logID int64, status, message string) error {
	var msg any
	if message != "" {
		msg = message
	}
	if _, err := r.queryService(ctx).Query(ctx, qPayoutWebhookStatus, status, msg, logID); err != nil {
		return fmt.Errorf("update payout webhook status: %w", err)
	}
	return nil
}

// verify gates Claim on the schema check: PostgreSQL plus the UNIQUE
// (provider, event_id) race guard. Success-only caching — transient
// failures retry on the next call. MySQL consumers supply their own
// WebhookLog.
func (r *SQLWebhookLog) verify(ctx context.Context, qs port.QueryService) error {
	r.verifyMu.Lock()
	defer r.verifyMu.Unlock()
	if r.verified {
		return nil
	}
	res, err := qs.Query(ctx, qPayoutWebhookVerify)
	if err != nil {
		return fmt.Errorf("payout webhook log requires PostgreSQL (pg_indexes probe failed): %w", err)
	}
	if len(res.Rows) == 0 || !indexDefCovers(common.AsString(res.Rows[0][0]), "(provider, event_id)", "") {
		return fmt.Errorf("payout_webhook_log: unique index payout_webhook_log_uq missing or malformed; apply schema/basis/37_payout_webhook_log.yml")
	}
	r.verified = true
	return nil
}

// VerifySchema runs the mandatory check eagerly at boot; Claim also runs
// it lazily.
func (r *SQLWebhookLog) VerifySchema(ctx context.Context) error {
	return r.verify(ctx, r.queryService(ctx))
}

var _ WebhookLog = (*SQLWebhookLog)(nil)
