package payout

import (
	"context"
	"fmt"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/port"
)

type sqlInstructionTx struct {
	tx port.TxQueryService
}

func (t *sqlInstructionTx) Queries() port.TxQueryService {
	return t.tx
}

func (t *sqlInstructionTx) Insert(ctx context.Context, instr *Instruction) (bool, error) {
	id := t.tx.GenID()
	res, err := t.tx.Query(ctx, qInstructionInsert, id, instr.PartnerID, instr.UserID, instr.Currency,
		instr.AmountMinor, instr.IdempotencyKey, instr.Status, instr.CreatedAt)
	if err != nil {
		return false, fmt.Errorf("insert payout instruction: %w", err)
	}
	if len(res.Rows) == 0 {
		return false, nil
	}
	instr.ID = id
	return true, nil
}

func (t *sqlInstructionTx) FindByKey(ctx context.Context, partnerID int64, idempotencyKey string) (*Instruction, error) {
	res, err := t.tx.Query(ctx, qInstructionByKey, partnerID, idempotencyKey)
	if err != nil {
		return nil, fmt.Errorf("find payout instruction: %w", err)
	}
	if len(res.Rows) == 0 {
		return nil, fmt.Errorf("%w: partner %d key %q", ErrInstructionNotFound, partnerID, idempotencyKey)
	}
	return t.Lock(ctx, common.AsInt64(res.Rows[0][0]))
}

func (t *sqlInstructionTx) Lock(ctx context.Context, id int64) (*Instruction, error) {
	res, err := t.tx.Query(ctx, qInstructionLock, id)
	if err != nil {
		return nil, fmt.Errorf("lock payout instruction %d: %w", id, err)
	}
	if len(res.Rows) == 0 {
		return nil, fmt.Errorf("%w: %d", ErrInstructionNotFound, id)
	}
	row := res.Rows[0]
	instr := &Instruction{
		ID:             common.AsInt64(row[0]),
		PartnerID:      common.AsInt64(row[1]),
		UserID:         common.AsInt64(row[2]),
		Currency:       common.AsString(row[3]),
		AmountMinor:    common.AsInt64(row[4]),
		IdempotencyKey: common.AsString(row[5]),
		Status:         common.AsString(row[6]),
		FailureReason:  common.AsString(row[7]),
		CreatedAt:      common.AsTime(row[8]),
	}
	legs, err := t.tx.Query(ctx, qInstructionLegs, id)
	if err != nil {
		return nil, fmt.Errorf("load payout instruction %d legs: %w", id, err)
	}
	for _, r := range legs.Rows {
		instr.Legs = append(instr.Legs, InstructionLeg{
			LegNo:             int(common.AsInt64(r[0])),
			Provider:          common.AsString(r[1]),
			BankInfoID:        common.AsInt64(r[2]),
			ProviderAccountID: common.AsString(r[3]),
			AmountMinor:       common.AsInt64(r[4]),
			IdempotencyKey:    common.AsString(r[5]),
			FundingID:         common.AsString(r[6]),
			PayoutID:          common.AsString(r[7]),
			Status:            common.AsString(r[8]),
			ReversedMinor:     common.AsInt64(r[9]),
			Attempts:          int(common.AsInt64(r[10])),
			FailureReason:     common.AsString(r[11]),
			CreatedAt:         common.AsTime(r[12]),
		})
	}
	return instr, nil
}

func (t *sqlInstructionTx) LockByTransfer(ctx context.Context, provider, providerTransferID string) (*Instruction, error) {
	res, err := t.tx.Query(ctx, qInstructionByTransfer, provider, providerTransferID, providerTransferID)
	if err != nil {
		return nil, fmt.Errorf("find payout instruction by transfer: %w", err)
	}
	switch len(res.Rows) {
	case 0:
		return nil, fmt.Errorf("%w: %s transfer %s", ErrInstructionNotFound, provider, providerTransferID)
	case 1:
		return t.Lock(ctx, common.AsInt64(res.Rows[0][0]))
	}
	return nil, fmt.Errorf("%w: %s transfer %s matches several instructions", ErrTransferConflict, provider, providerTransferID)
}

func (t *sqlInstructionTx) UpdateStatus(ctx context.Context, instr *Instruction) error {
	if _, err := t.tx.Query(ctx, qInstructionUpdateStatus, instr.Status, nullIfEmpty(instr.FailureReason), instr.ID); err != nil {
		return fmt.Errorf("update payout instruction %d: %w", instr.ID, err)
	}
	return nil
}

func (t *sqlInstructionTx) Destination(ctx context.Context, userID, partnerID int64) (*Destination, error) {
	res, err := t.tx.Query(ctx, qInstructionDestination, userID, partnerID)
	if err != nil {
		return nil, fmt.Errorf("load payout destination: %w", err)
	}
	if len(res.Rows) == 0 {
		return nil, nil
	}
	row := res.Rows[0]
	return &Destination{
		BankInfoID:        common.AsInt64(row[0]),
		Provider:          common.AsString(row[1]),
		ProviderAccountID: common.AsString(row[2]),
		Currency:          common.AsString(row[3]),
		Onboarded:         common.AsBool(row[4]),
	}, nil
}

func (t *sqlInstructionTx) InsertLeg(ctx context.Context, instructionID int64, leg *InstructionLeg) error {
	if _, err := t.tx.Query(ctx, qInstructionLegInsert, instructionID, leg.LegNo, leg.Provider, leg.BankInfoID,
		leg.ProviderAccountID, leg.AmountMinor, leg.IdempotencyKey, leg.Status, leg.ReversedMinor,
		leg.Attempts, leg.CreatedAt); err != nil {
		return fmt.Errorf("insert payout instruction %d leg %d: %w", instructionID, leg.LegNo, err)
	}
	return nil
}

func (t *sqlInstructionTx) UpdateLeg(ctx context.Context, instructionID int64, leg *InstructionLeg) error {
	if _, err := t.tx.Query(ctx, qInstructionLegUpdate, nullIfEmpty(leg.FundingID), nullIfEmpty(leg.PayoutID),
		leg.Status, leg.ReversedMinor, leg.Attempts, nullIfEmpty(leg.FailureReason),
		instructionID, leg.LegNo); err != nil {
		return fmt.Errorf("update payout instruction %d leg %d: %w", instructionID, leg.LegNo, err)
	}
	return nil
}

func (t *sqlInstructionTx) RecordEvent(ctx context.Context, instructionID int64, legNo int, ev *PayoutWebhookEvent) (bool, error) {
	res, err := t.tx.Query(ctx, qInstructionEventRecord, ev.Provider, ev.RawEventID, instructionID, legNo,
		string(ev.Type), ev.AmountMinor, ev.AmountReversedMinor)
	if err != nil {
		return false, fmt.Errorf("record payout event %s: %w", ev.RawEventID, err)
	}
	return len(res.Rows) == 0, nil
}

func (t *sqlInstructionTx) RecordResolution(ctx context.Context, resolution ReviewResolutionRecord) error {
	if _, err := t.tx.Query(ctx, qInstructionResolutionRecord, t.tx.GenID(), resolution.InstructionID,
		resolution.LegNo, resolution.Outcome, resolution.ActorID, resolution.Note,
		resolution.ProviderReference, resolution.ReversedMinor); err != nil {
		return fmt.Errorf("record payout instruction %d resolution: %w", resolution.InstructionID, err)
	}
	return nil
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

var _ InstructionTx = (*sqlInstructionTx)(nil)
