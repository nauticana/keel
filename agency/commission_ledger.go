package agency

import (
	"context"
	"fmt"
	"time"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/port"
	"github.com/nauticana/keel/service"
)

const qPromoteHeld = "agency_promote_held"

var commissionLedgerQueries = map[string]string{
	qPromoteHeld: `
UPDATE agency_commission
   SET status = 'P'
 WHERE entry_type = 'E' AND status = 'H' AND earned_at <= ?`,
}

type BaseCommissionLedger struct {
	service.AbstractService
	now func() time.Time
}

func NewBaseCommissionLedger(db port.DatabaseRepository) *BaseCommissionLedger {
	return &BaseCommissionLedger{
		AbstractService: service.NewAbstractService(db, commissionLedgerQueries),
		now:             func() time.Time { return time.Now().UTC() },
	}
}

func (s *BaseCommissionLedger) PromoteHeld(ctx context.Context) error {
	holdDays := common.Config().CommissionHoldDays
	cutoff := s.now().AddDate(0, 0, -holdDays)
	if err := s.Exec(ctx, qPromoteHeld, cutoff); err != nil {
		return fmt.Errorf("agency: promote held commissions: %w", err)
	}
	return nil
}

var _ port.AgencyCommissionLedger = (*BaseCommissionLedger)(nil)
