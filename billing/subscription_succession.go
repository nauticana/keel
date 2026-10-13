package billing

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/port"
)

// endingColumns is the select list the live-row queries share; parseEndingRow
// reads it in this order.
const endingColumns = `ps.partner_id, ps.plan_id, ps.begda, COALESCE(ps.successor_plan_id, ''), sp.activation_mode`

// endingRow is a live subscription about to end.
type endingRow struct {
	partnerID int64
	planID    string
	begda     time.Time
	successor string
	mode      ActivationMode
}

func parseEndingRow(row []any) endingRow {
	return endingRow{
		partnerID: common.AsInt64(row[0]),
		planID:    common.AsString(row[1]),
		begda:     common.AsTime(row[2]),
		successor: common.AsString(row[3]),
		mode:      ActivationMode(common.AsString(row[4])),
	}
}

// successorPlan is the plan that starts when a subscription ends: its scheduled
// successor, else fallback after a paid plan, else none.
func successorPlan(successor string, mode ActivationMode, fallback string) string {
	if successor != "" {
		return successor
	}
	if mode != ActivateFree {
		return fallback
	}
	return ""
}

// planModes memoizes activation modes within one operation.
type planModes map[string]ActivationMode

func (s *AbstractBillingService) planMode(ctx context.Context, cache planModes, planID string) (ActivationMode, error) {
	if mode, ok := cache[planID]; ok {
		return mode, nil
	}
	pol, err := s.loadPlanPolicy(ctx, planID)
	if err != nil {
		return "", err
	}
	cache[planID] = pol.mode
	return pol.mode, nil
}

// nextPlan validates the plan that starts when r ends; "" when none.
func (s *AbstractBillingService) nextPlan(ctx context.Context, cache planModes, r endingRow) (string, error) {
	next := successorPlan(r.successor, r.mode, s.FallbackPlanID)
	if next == "" {
		return "", nil
	}
	mode, err := s.planMode(ctx, cache, next)
	if err != nil {
		return "", err
	}
	if mode != ActivateFree {
		return "", fmt.Errorf("%w: %s", ErrNotFreePlan, next)
	}
	return next, nil
}

// endLive ends the live rows the query selects in one transaction.
func (s *AbstractBillingService) endLive(ctx context.Context, query string, arg any) (int, error) {
	res, err := s.qs.Query(ctx, query, arg)
	if err != nil {
		return 0, err
	}
	rows := make([]endingRow, len(res.Rows))
	for i, row := range res.Rows {
		rows[i] = parseEndingRow(row)
	}
	return s.endRows(ctx, planModes{}, rows)
}

// endRows closes each row and starts its next plan in one transaction. The
// ends commit even when a next plan cannot start, so a partner never keeps a
// subscription the provider has already ended; those failures are returned
// joined after the commit. A row another caller already ended is skipped, so
// a redelivered cancellation starts nothing.
func (s *AbstractBillingService) endRows(ctx context.Context, cache planModes, rows []endingRow) (int, error) {
	if len(rows) == 0 {
		return 0, nil
	}
	tx, err := s.Repo.BeginTx(ctx, s.allQueries)
	if err != nil {
		return 0, err
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback(ctx)
		}
	}()
	ended := 0
	var succession []error
	for _, r := range rows {
		res, err := tx.Query(ctx, qLcEndRow, r.partnerID, r.planID, r.begda)
		if err != nil {
			return 0, err
		}
		if len(res.Rows) == 0 {
			continue
		}
		ended++
		next, err := s.nextPlan(ctx, cache, r)
		if err != nil {
			succession = append(succession, fmt.Errorf("partner %d: %w", r.partnerID, err))
			continue
		}
		if next == "" {
			continue
		}
		started, err := startFree(ctx, tx, r.partnerID, next)
		if err != nil {
			return 0, err
		}
		if !started {
			succession = append(succession, fmt.Errorf("partner %d: %w", r.partnerID, ErrSubscriptionPending))
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}
	committed = true
	return ended, errors.Join(succession...)
}

// startFree opens an active free row; false means the partner still holds a
// live or pending subscription, which is left in place.
func startFree(ctx context.Context, tx port.TxQueryService, partnerID int64, planID string) (bool, error) {
	res, err := tx.Query(ctx, qLcInsertFree, partnerID, planID, partnerID)
	if err != nil {
		return false, err
	}
	return len(res.Rows) > 0, nil
}
