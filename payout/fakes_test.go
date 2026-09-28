package payout

import (
	"context"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/nauticana/keel/port"
)

// Shared in-memory doubles for payout tests.

type fakeProvider struct {
	AbstractProvider
	code     string
	event    *PayoutWebhookEvent
	result   *InstantPayoutResult
	err      error
	status   *InstantPayoutResult
	requests []InstantPayoutInput
	// onRequest runs inside RequestInstantPayout, e.g. to assert no store transaction is open.
	onRequest func()
}

func (f *fakeProvider) Code() string {
	if f.code == "" {
		return ProviderCodeAirwallex
	}
	return f.code
}

func (f *fakeProvider) StartOnboarding(context.Context, StartOnboardingInput) (*PayoutOnboardingSession, error) {
	return nil, ErrNotImplemented
}

func (f *fakeProvider) VerifyAndParseWebhook(map[string][]string, []byte) (*PayoutWebhookEvent, error) {
	return f.event, nil
}

func (f *fakeProvider) RequestInstantPayout(_ context.Context, in InstantPayoutInput) (*InstantPayoutResult, error) {
	f.requests = append(f.requests, in)
	if f.onRequest != nil {
		f.onRequest()
	}
	if f.result == nil && f.err == nil {
		return nil, ErrNotImplemented
	}
	return f.result, f.err
}

func (f *fakeProvider) GetPayoutStatus(context.Context, string) (*InstantPayoutResult, error) {
	if f.status == nil {
		return nil, ErrNotImplemented
	}
	return f.status, nil
}

var _ PayoutProvider = (*fakeProvider)(nil)

// fakeResumingProvider adds the PayoutResumer capability.
type fakeResumingProvider struct {
	*fakeProvider
	resumedFunding []string
	resumeResult   *InstantPayoutResult
}

func (f *fakeResumingProvider) ResumePayout(_ context.Context, _ InstantPayoutInput, fundingID string) (*InstantPayoutResult, error) {
	f.resumedFunding = append(f.resumedFunding, fundingID)
	return f.resumeResult, nil
}

var _ PayoutResumer = (*fakeResumingProvider)(nil)

// fakeResolver maps partners to providers for multi-provider tests.
type fakeResolver struct {
	byPartner map[int64]PayoutProvider
	byCode    map[string]PayoutProvider
}

func newFakeResolver(byPartner map[int64]PayoutProvider) *fakeResolver {
	r := &fakeResolver{byPartner: byPartner, byCode: map[string]PayoutProvider{}}
	for _, p := range byPartner {
		r.byCode[p.Code()] = p
	}
	return r
}

func (r *fakeResolver) ForPartner(_ context.Context, partnerID int64) (PayoutProvider, error) {
	if p, ok := r.byPartner[partnerID]; ok {
		return p, nil
	}
	return nil, ErrProviderNotConfigured
}

func (r *fakeResolver) ByCode(code string) (PayoutProvider, error) {
	if p, ok := r.byCode[code]; ok {
		return p, nil
	}
	return nil, ErrUnknownProvider
}

var _ ProviderResolver = (*fakeResolver)(nil)

// fakeWebhookLog mirrors SQLWebhookLog's Claim semantics: P/R rows are
// duplicates, F rows are re-claimed.
type fakeWebhookLog struct {
	status map[string]string // key → last processing status
	ids    map[string]int64
	next   int64
}

func newFakeWebhookLog() *fakeWebhookLog {
	return &fakeWebhookLog{status: map[string]string{}, ids: map[string]int64{}}
}

func (f *fakeWebhookLog) Claim(_ context.Context, provider string, ev *PayoutWebhookEvent, _ []byte) (int64, bool, error) {
	k := provider + "/" + ev.RawEventID
	switch f.status[k] {
	case WebhookStatusProcessed, WebhookStatusReceived:
		return 0, true, nil
	case WebhookStatusFailed:
		f.status[k] = WebhookStatusReceived
		return f.ids[k], false, nil
	}
	f.next++
	f.ids[k] = f.next
	f.status[k] = WebhookStatusReceived
	return f.next, false, nil
}

func (f *fakeWebhookLog) UpdateStatus(_ context.Context, logID int64, status, _ string) error {
	for k, id := range f.ids {
		if id == logID {
			f.status[k] = status
		}
	}
	return nil
}

var _ WebhookLog = (*fakeWebhookLog)(nil)

type fakeSink struct {
	events   []*PayoutWebhookEvent
	failNext bool
}

func (f *fakeSink) ApplyTransferEvent(_ context.Context, ev *PayoutWebhookEvent) error {
	if f.failNext {
		f.failNext = false
		return fmt.Errorf("ledger temporarily unavailable")
	}
	f.events = append(f.events, ev)
	return nil
}

var _ TransferEventSink = (*fakeSink)(nil)

type allocatorRelease struct {
	instructionID int64
	amountMinor   int64
	reason        ReleaseReason
}

type fakeAllocator struct {
	allocated   []int64
	released    []allocatorRelease
	failNextErr error
}

func (a *fakeAllocator) Allocate(_ context.Context, _ port.TxQueryService, instr *Instruction) error {
	if err := a.failNextErr; err != nil {
		a.failNextErr = nil
		return err
	}
	a.allocated = append(a.allocated, instr.ID)
	return nil
}

func (a *fakeAllocator) Release(_ context.Context, _ port.TxQueryService, instr *Instruction, amountMinor int64, reason ReleaseReason) error {
	a.released = append(a.released, allocatorRelease{instr.ID, amountMinor, reason})
	return nil
}

var _ Allocator = (*fakeAllocator)(nil)

// memInstructionStore is a transactional in-memory InstructionStore: a
// failed InTx restores the pre-transaction state, like a rollback.
type memInstructionStore struct {
	mu           sync.Mutex
	instructions map[int64]*Instruction
	events       map[string]bool
	resolutions  []ReviewResolutionRecord
	destinations map[[2]int64]*Destination
	nextID       int64
	inTx         bool
	commits      int
}

func newMemInstructionStore() *memInstructionStore {
	return &memInstructionStore{
		instructions: map[int64]*Instruction{},
		events:       map[string]bool{},
		destinations: map[[2]int64]*Destination{},
		nextID:       100,
	}
}

func (s *memInstructionStore) setDestination(userID, partnerID int64, d *Destination) {
	s.destinations[[2]int64{userID, partnerID}] = d
}

func (s *memInstructionStore) get(id int64) *Instruction {
	s.mu.Lock()
	defer s.mu.Unlock()
	return cloneInstruction(s.instructions[id])
}

func (s *memInstructionStore) InTx(ctx context.Context, fn func(InstructionTx) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	snapshotInstructions := make(map[int64]*Instruction, len(s.instructions))
	for id, instr := range s.instructions {
		snapshotInstructions[id] = cloneInstruction(instr)
	}
	snapshotEvents := make(map[string]bool, len(s.events))
	for k, v := range s.events {
		snapshotEvents[k] = v
	}
	snapshotResolutions := append([]ReviewResolutionRecord(nil), s.resolutions...)
	snapshotNext := s.nextID
	s.inTx = true
	err := fn(&memInstructionTx{s: s})
	s.inTx = false
	if err != nil {
		s.instructions, s.events, s.resolutions, s.nextID = snapshotInstructions, snapshotEvents, snapshotResolutions, snapshotNext
		return err
	}
	s.commits++
	return nil
}

func (s *memInstructionStore) InFlight(_ context.Context, _ time.Time, limit int, partnerIDs []int64) ([]int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var ids []int64
	for id, instr := range s.instructions {
		inScope := len(partnerIDs) == 0 || slices.Contains(partnerIDs, instr.PartnerID)
		if inScope && (instr.Status == InstructionDispatching || instr.Status == InstructionPending) && len(ids) < limit {
			ids = append(ids, id)
		}
	}
	return ids, nil
}

var _ InstructionStore = (*memInstructionStore)(nil)

type memInstructionTx struct {
	s *memInstructionStore
}

func (t *memInstructionTx) Queries() port.TxQueryService { return nil }

func (t *memInstructionTx) Insert(_ context.Context, instr *Instruction) (bool, error) {
	for _, existing := range t.s.instructions {
		if existing.PartnerID == instr.PartnerID && existing.IdempotencyKey == instr.IdempotencyKey {
			return false, nil
		}
	}
	t.s.nextID++
	instr.ID = t.s.nextID
	t.s.instructions[instr.ID] = cloneInstruction(instr)
	return true, nil
}

func (t *memInstructionTx) FindByKey(ctx context.Context, partnerID int64, key string) (*Instruction, error) {
	for id, existing := range t.s.instructions {
		if existing.PartnerID == partnerID && existing.IdempotencyKey == key {
			return t.Lock(ctx, id)
		}
	}
	return nil, ErrInstructionNotFound
}

func (t *memInstructionTx) Lock(_ context.Context, id int64) (*Instruction, error) {
	instr, ok := t.s.instructions[id]
	if !ok {
		return nil, ErrInstructionNotFound
	}
	return cloneInstruction(instr), nil
}

func (t *memInstructionTx) LockByTransfer(ctx context.Context, provider, transferID string) (*Instruction, error) {
	for id, instr := range t.s.instructions {
		if instr.legByTransfer(provider, transferID) != nil {
			return t.Lock(ctx, id)
		}
	}
	return nil, ErrInstructionNotFound
}

func (t *memInstructionTx) UpdateStatus(_ context.Context, instr *Instruction) error {
	stored, ok := t.s.instructions[instr.ID]
	if !ok {
		return ErrInstructionNotFound
	}
	stored.Status, stored.FailureReason = instr.Status, instr.FailureReason
	return nil
}

func (t *memInstructionTx) Destination(_ context.Context, userID, partnerID int64) (*Destination, error) {
	d := t.s.destinations[[2]int64{userID, partnerID}]
	if d == nil {
		return nil, nil
	}
	c := *d
	return &c, nil
}

func (t *memInstructionTx) InsertLeg(_ context.Context, instructionID int64, leg *InstructionLeg) error {
	stored, ok := t.s.instructions[instructionID]
	if !ok {
		return ErrInstructionNotFound
	}
	stored.Legs = append(stored.Legs, *leg)
	return nil
}

func (t *memInstructionTx) UpdateLeg(_ context.Context, instructionID int64, leg *InstructionLeg) error {
	stored, ok := t.s.instructions[instructionID]
	if !ok {
		return ErrInstructionNotFound
	}
	target := stored.leg(leg.LegNo)
	if target == nil {
		return fmt.Errorf("leg %d not found", leg.LegNo)
	}
	*target = *leg
	return nil
}

func (t *memInstructionTx) RecordEvent(_ context.Context, _ int64, _ int, ev *PayoutWebhookEvent) (bool, error) {
	k := ev.Provider + "/" + ev.RawEventID
	if t.s.events[k] {
		return true, nil
	}
	t.s.events[k] = true
	return false, nil
}

func (t *memInstructionTx) RecordResolution(_ context.Context, resolution ReviewResolutionRecord) error {
	t.s.resolutions = append(t.s.resolutions, resolution)
	return nil
}

var _ InstructionTx = (*memInstructionTx)(nil)

func cloneInstruction(in *Instruction) *Instruction {
	if in == nil {
		return nil
	}
	c := *in
	c.Legs = append([]InstructionLeg(nil), in.Legs...)
	return &c
}
