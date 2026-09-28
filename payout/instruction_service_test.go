package payout

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

const (
	testPartner = int64(7)
	testPayee   = int64(42)
)

type instructionFixture struct {
	store     *memInstructionStore
	provider  *fakeProvider
	allocator *fakeAllocator
	svc       *InstructionService
	now       time.Time
}

func newInstructionFixture(t *testing.T) *instructionFixture {
	t.Helper()
	f := &instructionFixture{
		store:     newMemInstructionStore(),
		provider:  &fakeProvider{code: ProviderCodeStripeConnect},
		allocator: &fakeAllocator{},
		now:       time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC),
	}
	f.provider.onRequest = func() {
		if f.store.inTx {
			t.Error("provider called inside a store transaction")
		}
	}
	f.store.setDestination(testPayee, testPartner, &Destination{
		BankInfoID: 5, Provider: ProviderCodeStripeConnect, ProviderAccountID: "acct_1", Currency: "USD", Onboarded: true,
	})
	f.svc = NewInstructionService(f.store, NewStaticProviderResolver(f.provider), f.allocator, nil)
	f.svc.Now = func() time.Time { return f.now }
	return f
}

func (f *instructionFixture) create(t *testing.T, key string, amount int64) *Instruction {
	t.Helper()
	instr, err := f.svc.Create(context.Background(), InstructionRequest{
		PartnerID: testPartner, UserID: testPayee, Currency: "usd", AmountMinor: amount, IdempotencyKey: key,
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	return instr
}

func (f *instructionFixture) settle(t *testing.T, amount int64) *Instruction {
	t.Helper()
	instr := f.create(t, "k-settle", amount)
	f.provider.result = &InstantPayoutResult{ProviderPayoutID: "acct_1:po_1", ProviderFundingID: "tr_1", Status: "paid"}
	if _, err := f.svc.Execute(context.Background(), instr.ID); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	return f.store.get(instr.ID)
}

func TestInstructionCreate_IdempotentByKey(t *testing.T) {
	f := newInstructionFixture(t)
	first := f.create(t, "k1", 1000)
	again := f.create(t, "k1", 1000)
	if again.ID != first.ID || first.Status != InstructionNew || first.Currency != "USD" {
		t.Fatalf("first=%+v again=%+v", first, again)
	}
	if len(f.allocator.allocated) != 1 {
		t.Fatalf("allocations=%v, want one for a replayed key", f.allocator.allocated)
	}
	_, err := f.svc.Create(context.Background(), InstructionRequest{
		PartnerID: testPartner, UserID: testPayee, Currency: "USD", AmountMinor: 999, IdempotencyKey: "k1",
	})
	if !errors.Is(err, ErrIdempotencyKeyReused) {
		t.Fatalf("err=%v, want ErrIdempotencyKeyReused", err)
	}
}

func TestInstructionCreate_AllocatorFailureRollsBack(t *testing.T) {
	f := newInstructionFixture(t)
	f.allocator.failNextErr = fmt.Errorf("earnings locked")
	if _, err := f.svc.Create(context.Background(), InstructionRequest{
		PartnerID: testPartner, UserID: testPayee, Currency: "USD", AmountMinor: 1000, IdempotencyKey: "k1",
	}); err == nil {
		t.Fatal("expected allocator failure")
	}
	if len(f.store.instructions) != 0 {
		t.Fatalf("instruction persisted without its allocation: %v", f.store.instructions)
	}
	if instr := f.create(t, "k1", 1000); instr.ID == 0 || len(f.allocator.allocated) != 1 {
		t.Fatalf("retry after rollback: %+v allocations=%v", instr, f.allocator.allocated)
	}
}

func TestInstructionCreate_Validation(t *testing.T) {
	f := newInstructionFixture(t)
	for _, req := range []InstructionRequest{
		{PartnerID: testPartner, UserID: testPayee, Currency: "USD", AmountMinor: 0, IdempotencyKey: "k"},
		{PartnerID: testPartner, UserID: testPayee, Currency: "XYZ", AmountMinor: 1, IdempotencyKey: "k"},
		{PartnerID: testPartner, UserID: testPayee, Currency: "USD", AmountMinor: 1},
		{UserID: testPayee, Currency: "USD", AmountMinor: 1, IdempotencyKey: "k"},
	} {
		if _, err := f.svc.Create(context.Background(), req); !errors.Is(err, ErrInvalidInstruction) {
			t.Errorf("%+v: err=%v, want ErrInvalidInstruction", req, err)
		}
	}
}

func TestInstructionExecute_PaidOutsideTransaction(t *testing.T) {
	f := newInstructionFixture(t)
	instr := f.settle(t, 1000)
	if instr.Status != InstructionSettled || len(instr.Legs) != 1 || instr.Legs[0].Status != LegSettled {
		t.Fatalf("instruction=%+v, want settled with one settled leg", instr)
	}
	leg := instr.Legs[0]
	if leg.PayoutID != "acct_1:po_1" || leg.FundingID != "tr_1" || leg.Provider != ProviderCodeStripeConnect || leg.BankInfoID != 5 {
		t.Fatalf("leg=%+v", leg)
	}
	req := f.provider.requests[0]
	if req.IdempotencyKey != fmt.Sprintf("payout-instruction-%d-1", instr.ID) || req.Amount != 1000 || req.ProviderAccountID != "acct_1" || req.Currency != "USD" {
		t.Fatalf("provider request=%+v", req)
	}
	if again, err := f.svc.Execute(context.Background(), instr.ID); err != nil || again.Status != InstructionSettled || len(f.provider.requests) != 1 {
		t.Fatalf("re-executing a settled instruction must not dispatch: %+v %v", again, err)
	}
}

func TestInstructionExecute_AmbiguousErrorRetriesSameKeyThenParks(t *testing.T) {
	f := newInstructionFixture(t)
	instr := f.create(t, "k1", 1000)
	f.provider.err = fmt.Errorf("connection reset")
	if _, err := f.svc.Execute(context.Background(), instr.ID); err == nil {
		t.Fatal("expected the provider error")
	}
	if got := f.store.get(instr.ID); got.Status != InstructionDispatching || got.Legs[0].Status != LegDispatching {
		t.Fatalf("ambiguous dispatch must stay dispatching: %+v", got)
	}
	_, _ = f.svc.Execute(context.Background(), instr.ID)
	if len(f.provider.requests) != 2 || f.provider.requests[0].IdempotencyKey != f.provider.requests[1].IdempotencyKey {
		t.Fatalf("retry must reuse the leg key: %+v", f.provider.requests)
	}
	if got := f.store.get(instr.ID); len(got.Legs) != 1 || got.Legs[0].Attempts != 2 {
		t.Fatalf("legs=%+v, want one leg with two attempts", got.Legs)
	}

	f.now = f.now.Add(21 * time.Hour)
	if _, err := f.svc.Execute(context.Background(), instr.ID); !errors.Is(err, ErrDispatchUnresolved) {
		t.Fatalf("err=%v, want ErrDispatchUnresolved", err)
	}
	if got := f.store.get(instr.ID); got.Status != InstructionReview || len(f.provider.requests) != 2 {
		t.Fatalf("status=%s requests=%d, want review without a third dispatch", got.Status, len(f.provider.requests))
	}
}

func TestInstructionExecute_RejectedOpensNewLegAndCancelReleases(t *testing.T) {
	f := newInstructionFixture(t)
	instr := f.create(t, "k1", 1000)
	f.provider.err = ErrInsufficientBalance
	if _, err := f.svc.Execute(context.Background(), instr.ID); !errors.Is(err, ErrInsufficientBalance) {
		t.Fatalf("err=%v", err)
	}
	if got := f.store.get(instr.ID); got.Status != InstructionFailed || got.Legs[0].Status != LegFailed {
		t.Fatalf("rejected dispatch: %+v", got)
	}
	_, _ = f.svc.Execute(context.Background(), instr.ID)
	got := f.store.get(instr.ID)
	if len(got.Legs) != 2 || f.provider.requests[1].IdempotencyKey != fmt.Sprintf("payout-instruction-%d-2", instr.ID) {
		t.Fatalf("second attempt must open leg 2 with its own key: %+v", got.Legs)
	}
	if err := f.svc.Cancel(context.Background(), instr.ID); err != nil {
		t.Fatalf("Cancel: %v", err)
	}
	if got := f.store.get(instr.ID); got.Status != InstructionCancelled {
		t.Fatalf("status=%s", got.Status)
	}
	if len(f.allocator.released) != 1 || f.allocator.released[0] != (allocatorRelease{instr.ID, 1000, ReleaseCancelled}) {
		t.Fatalf("released=%+v", f.allocator.released)
	}
	if err := f.svc.Cancel(context.Background(), instr.ID); !errors.Is(err, ErrInstructionNotCancellable) {
		t.Fatalf("second cancel err=%v", err)
	}
}

func TestInstructionExecute_ResumesFundedLeg(t *testing.T) {
	f := newInstructionFixture(t)
	resumer := &fakeResumingProvider{fakeProvider: f.provider, resumeResult: &InstantPayoutResult{
		ProviderPayoutID: "acct_1:po_9", ProviderFundingID: "tr_9", Status: "pending",
	}}
	f.svc.Providers = NewStaticProviderResolver(resumer)
	instr := f.create(t, "k1", 1000)
	f.provider.result = &InstantPayoutResult{ProviderFundingID: "tr_9", Status: "pending"}
	f.provider.err = fmt.Errorf("payout leg failed")
	_, _ = f.svc.Execute(context.Background(), instr.ID)
	if got := f.store.get(instr.ID); got.Legs[0].FundingID != "tr_9" || got.Status != InstructionDispatching {
		t.Fatalf("funding id must persist with the leg still dispatching: %+v", got)
	}
	if _, err := f.svc.Execute(context.Background(), instr.ID); err != nil {
		t.Fatalf("resume: %v", err)
	}
	if len(resumer.resumedFunding) != 1 || resumer.resumedFunding[0] != "tr_9" || len(f.provider.requests) != 1 {
		t.Fatalf("resume must run only the missing leg: resumed=%v requests=%d", resumer.resumedFunding, len(f.provider.requests))
	}
	if got := f.store.get(instr.ID); got.Status != InstructionPending || got.Legs[0].PayoutID != "acct_1:po_9" {
		t.Fatalf("after resume: %+v", got)
	}
}

func TestInstructionExecute_DestinationMustMatchPartnerProvider(t *testing.T) {
	f := newInstructionFixture(t)
	f.store.setDestination(testPayee, testPartner, &Destination{
		BankInfoID: 5, Provider: ProviderCodeWise, ProviderAccountID: "555", Currency: "USD", Onboarded: true,
	})
	instr := f.create(t, "k1", 1000)
	if _, err := f.svc.Execute(context.Background(), instr.ID); !errors.Is(err, ErrDestinationNotPayable) {
		t.Fatalf("err=%v, want ErrDestinationNotPayable", err)
	}
	if got := f.store.get(instr.ID); got.Status != InstructionNew || len(got.Legs) != 0 || len(f.provider.requests) != 0 {
		t.Fatalf("no leg or dispatch expected: %+v", got)
	}
}

func TestInstructionApplyTransferEvent_PaidAndDedupe(t *testing.T) {
	f := newInstructionFixture(t)
	instr := f.create(t, "k1", 1000)
	f.provider.result = &InstantPayoutResult{ProviderPayoutID: "acct_1:po_1", ProviderFundingID: "tr_1", Status: "pending"}
	if _, err := f.svc.Execute(context.Background(), instr.ID); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	ev := &PayoutWebhookEvent{Type: PayoutEventTransferPaid, Provider: ProviderCodeStripeConnect, ProviderTransferID: "acct_1:po_1", RawEventID: "evt_1"}
	if err := f.svc.ApplyTransferEvent(context.Background(), ev); err != nil {
		t.Fatalf("paid: %v", err)
	}
	if got := f.store.get(instr.ID); got.Status != InstructionSettled {
		t.Fatalf("status=%s", got.Status)
	}
	commits := f.store.commits
	failed := &PayoutWebhookEvent{Type: PayoutEventTransferFailed, Provider: ProviderCodeStripeConnect, ProviderTransferID: "acct_1:po_1", RawEventID: "evt_1"}
	if err := f.svc.ApplyTransferEvent(context.Background(), failed); err != nil {
		t.Fatalf("replayed id: %v", err)
	}
	if got := f.store.get(instr.ID); got.Status != InstructionSettled || f.store.commits != commits+1 {
		t.Fatalf("a replayed event id must not apply: %+v", got)
	}
}

func TestInstructionApplyTransferEvent_FailureAfterSettlementIsReturn(t *testing.T) {
	f := newInstructionFixture(t)
	instr := f.settle(t, 1000)
	err := f.svc.ApplyTransferEvent(context.Background(), &PayoutWebhookEvent{
		Type: PayoutEventTransferFailed, Provider: ProviderCodeStripeConnect,
		ProviderTransferID: "acct_1:po_1", RawEventID: "evt_failed_after_paid",
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := f.store.get(instr.ID); got.Status != InstructionFailed || got.Legs[0].Status != LegReturned {
		t.Fatalf("failure after settlement: %+v", got)
	}
}

func TestInstructionApplyTransferEvent_ReversalBoundedAndDeduplicated(t *testing.T) {
	f := newInstructionFixture(t)
	instr := f.settle(t, 1000)
	reverse := func(eventID string, total int64) error {
		return f.svc.ApplyTransferEvent(context.Background(), &PayoutWebhookEvent{
			Type: PayoutEventTransferReversed, Provider: ProviderCodeStripeConnect, ProviderTransferID: "tr_1",
			RawEventID: eventID, AmountMinor: 1000, AmountReversedMinor: total,
		})
	}
	if err := reverse("evt_r1", 300); err != nil {
		t.Fatalf("partial reversal: %v", err)
	}
	_ = reverse("evt_r1", 300)
	_ = reverse("evt_r2", 300)
	if len(f.allocator.released) != 1 || f.allocator.released[0] != (allocatorRelease{instr.ID, 300, ReleaseReversed}) {
		t.Fatalf("released=%+v, want a single 300 release", f.allocator.released)
	}
	if got := f.store.get(instr.ID); got.Status != InstructionSettled || got.Legs[0].ReversedMinor != 300 {
		t.Fatalf("partial reversal state: %+v", got)
	}
	if err := reverse("evt_r3", 1200); !errors.Is(err, ErrReversalExceedsLeg) {
		t.Fatalf("err=%v, want ErrReversalExceedsLeg", err)
	}
	if err := reverse("evt_r3", 1000); err != nil {
		t.Fatalf("event id of a rejected reversal must stay retryable: %v", err)
	}
	got := f.store.get(instr.ID)
	if got.Status != InstructionReversed || got.Legs[0].Status != LegReversed || got.Legs[0].ReversedMinor != 1000 {
		t.Fatalf("full reversal state: %+v", got)
	}
	if len(f.allocator.released) != 2 || f.allocator.released[1].amountMinor != 700 {
		t.Fatalf("released=%+v, want the 700 remainder", f.allocator.released)
	}
}

func TestInstructionApplyTransferEvent_ReturnedAfterPaidReopens(t *testing.T) {
	f := newInstructionFixture(t)
	instr := f.settle(t, 1000)
	if err := f.svc.ApplyTransferEvent(context.Background(), &PayoutWebhookEvent{
		Type: PayoutEventTransferReturned, Provider: ProviderCodeStripeConnect, ProviderTransferID: "acct_1:po_1", RawEventID: "evt_ret",
	}); err != nil {
		t.Fatalf("returned: %v", err)
	}
	if got := f.store.get(instr.ID); got.Status != InstructionFailed || got.Legs[0].Status != LegReturned {
		t.Fatalf("returned state: %+v", got)
	}
	if err := f.svc.ApplyTransferEvent(context.Background(), &PayoutWebhookEvent{
		Type: PayoutEventTransferPaid, Provider: ProviderCodeStripeConnect, ProviderTransferID: "acct_1:po_1", RawEventID: "evt_late",
	}); !errors.Is(err, ErrTransferConflict) {
		t.Fatalf("paid after returned err=%v, want ErrTransferConflict", err)
	}
}

func TestInstructionApplyTransferEvent_Guards(t *testing.T) {
	f := newInstructionFixture(t)
	f.settle(t, 1000)
	if err := f.svc.ApplyTransferEvent(context.Background(), &PayoutWebhookEvent{
		Type: PayoutEventTransferPaid, ProviderTransferID: "acct_1:po_1",
	}); err == nil {
		t.Fatal("an event without a provider code must be rejected")
	}
	if err := f.svc.ApplyTransferEvent(context.Background(), &PayoutWebhookEvent{
		Type: PayoutEventTransferPaid, Provider: ProviderCodeWise, ProviderTransferID: "acct_1:po_1",
	}); !errors.Is(err, ErrInstructionNotFound) {
		t.Fatalf("same transfer id on another provider err=%v, want ErrInstructionNotFound", err)
	}
}

func TestInstructionExecute_UsesEachPartnersProvider(t *testing.T) {
	f := newInstructionFixture(t)
	wise := &fakeProvider{code: ProviderCodeWise, result: &InstantPayoutResult{ProviderPayoutID: "9001", ProviderFundingID: "9001", Status: "pending"}}
	f.provider.result = &InstantPayoutResult{ProviderPayoutID: "9001", ProviderFundingID: "9001", Status: "pending"}
	const otherPartner = int64(8)
	f.svc.Providers = newFakeResolver(map[int64]PayoutProvider{testPartner: f.provider, otherPartner: wise})
	f.store.setDestination(testPayee, otherPartner, &Destination{
		BankInfoID: 6, Provider: ProviderCodeWise, ProviderAccountID: "555", Currency: "USD", Onboarded: true,
	})
	a := f.create(t, "k1", 1000)
	b, err := f.svc.Create(context.Background(), InstructionRequest{
		PartnerID: otherPartner, UserID: testPayee, Currency: "USD", AmountMinor: 500, IdempotencyKey: "k1",
	})
	if err != nil || b.ID == a.ID {
		t.Fatalf("same key on another partner must be a new instruction: %+v %v", b, err)
	}
	for _, id := range []int64{a.ID, b.ID} {
		if _, err := f.svc.Execute(context.Background(), id); err != nil {
			t.Fatalf("Execute %d: %v", id, err)
		}
	}
	if len(f.provider.requests) != 1 || len(wise.requests) != 1 || wise.requests[0].ProviderAccountID != "555" {
		t.Fatalf("dispatch routing: stripe=%v wise=%v", f.provider.requests, wise.requests)
	}
	if err := f.svc.ApplyTransferEvent(context.Background(), &PayoutWebhookEvent{
		Type: PayoutEventTransferPaid, Provider: ProviderCodeWise, ProviderTransferID: "9001", RawEventID: "w1",
	}); err != nil {
		t.Fatalf("wise paid: %v", err)
	}
	if f.store.get(b.ID).Status != InstructionSettled || f.store.get(a.ID).Status != InstructionPending {
		t.Fatalf("event must settle only the Wise leg: a=%s b=%s", f.store.get(a.ID).Status, f.store.get(b.ID).Status)
	}
}

func TestInstructionReconcile_PollsPendingLeg(t *testing.T) {
	f := newInstructionFixture(t)
	instr := f.create(t, "k1", 1000)
	f.provider.result = &InstantPayoutResult{ProviderPayoutID: "acct_1:po_1", ProviderFundingID: "tr_1", Status: "pending"}
	_, _ = f.svc.Execute(context.Background(), instr.ID)
	f.provider.status = &InstantPayoutResult{Status: "paid"}
	if err := f.svc.ReconcileInFlight(context.Background(), f.now, 10); err != nil {
		t.Fatalf("ReconcileInFlight: %v", err)
	}
	if got := f.store.get(instr.ID); got.Status != InstructionSettled {
		t.Fatalf("status=%s, want settled from the polled status", got.Status)
	}
}
