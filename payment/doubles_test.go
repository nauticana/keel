package payment

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/model"
	"github.com/nauticana/keel/port"
)

// Shared in-memory doubles for payment tests.

type memRefundBalance struct {
	id                            int64
	provider, paymentID, currency string
	captured, refunded            int64
}

type memRefundRequest struct {
	id, balanceID, requester, approver int64
	reason, key, status                string
	amount                             int64
	providerAmount                     *int64
	providerRefundID, lastError        string
	attempts                           int64
	firstAttemptAt                     *time.Time
}

// memRefundStore mirrors the refund named queries over maps. openTx lets
// doubles assert that nothing slow runs while a transaction is open.
type memRefundStore struct {
	mu       sync.Mutex
	nextID   int64
	balances map[int64]*memRefundBalance
	requests map[int64]*memRefundRequest
	openTx   int
	lockedIn []bool
	now      time.Time
}

func newMemRefundStore() *memRefundStore {
	return &memRefundStore{now: time.Now(), balances: map[int64]*memRefundBalance{}, requests: map[int64]*memRefundRequest{}}
}

func (m *memRefundStore) GenID() int64 { m.nextID++; return m.nextID }

func (m *memRefundStore) Query(_ context.Context, name string, args ...any) (*model.QueryResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.query(false, name, args...)
}

func optionalString(v any) string {
	if v == nil {
		return ""
	}
	return common.AsString(v)
}

func (m *memRefundStore) query(inTx bool, name string, args ...any) (*model.QueryResult, error) {
	res := &model.QueryResult{}
	switch name {
	case qRefundByID, qRefundByKey, qRefundByPayment:
		for id := int64(1); id <= m.nextID; id++ {
			r, ok := m.requests[id]
			if !ok {
				continue
			}
			b := m.balances[r.balanceID]
			if (name == qRefundByID && r.id == args[0]) || (name == qRefundByKey && r.key == args[0]) ||
				(name == qRefundByPayment && b.provider == args[0] && b.paymentID == args[1]) {
				var approver, providerAmount any
				if r.approver != 0 {
					approver = r.approver
				}
				if r.providerAmount != nil {
					providerAmount = *r.providerAmount
				}
				var firstAttempt any
				if r.firstAttemptAt != nil {
					firstAttempt = *r.firstAttemptAt
				}
				res.Rows = append(res.Rows, []any{r.id, b.provider, b.paymentID, b.currency, r.requester, approver,
					r.reason, r.amount, providerAmount, r.key, r.status, r.providerRefundID, r.lastError, r.attempts, nil, nil, nil, firstAttempt})
			}
		}
	case qRefundBalanceID, qRefundLockBalance:
		if name == qRefundLockBalance {
			m.lockedIn = append(m.lockedIn, inTx)
		}
		for _, b := range m.balances {
			if b.provider == args[0] && b.paymentID == args[1] {
				res.Rows = append(res.Rows, []any{b.id, b.currency, b.captured, b.refunded})
			}
		}
	case qRefundInsertBalance:
		for _, b := range m.balances {
			if b.provider == args[1] && b.paymentID == args[2] {
				return res, nil
			}
		}
		id := args[0].(int64)
		m.balances[id] = &memRefundBalance{id: id, provider: args[1].(string), paymentID: args[2].(string),
			currency: args[3].(string), captured: args[4].(int64)}
	case qRefundTotals:
		sums := map[string]int64{}
		for _, r := range m.requests {
			if r.balanceID == args[0] && (r.status == "P" || r.status == "A" || r.status == "S") {
				amount := r.amount
				if r.providerAmount != nil {
					amount = *r.providerAmount
				}
				sums[r.status] += amount
			}
		}
		for status, sum := range sums {
			res.Rows = append(res.Rows, []any{status, sum})
		}
	case qRefundInsert:
		for _, r := range m.requests {
			if r.key == args[5] {
				return res, nil
			}
		}
		id := args[0].(int64)
		m.requests[id] = &memRefundRequest{id: id, balanceID: args[1].(int64), requester: args[2].(int64),
			reason: optionalString(args[3]), amount: args[4].(int64), key: args[5].(string), status: "P"}
		res.Rows = [][]any{{id}}
	case qRefundApprove:
		if r := m.requests[args[1].(int64)]; r != nil && r.status == "P" && r.requester != args[2] {
			r.status, r.approver = "A", args[0].(int64)
			res.Rows = [][]any{{r.id}}
		}
	case qRefundReject:
		if r := m.requests[args[2].(int64)]; r != nil && (r.status == "P" || r.status == "A") {
			r.status, r.approver, r.lastError = "F", args[0].(int64), optionalString(args[1])
			res.Rows = [][]any{{r.id}}
		}
	case qRefundClaim:
		window := time.Duration(args[1].(float64) * float64(time.Second))
		if r := m.requests[args[0].(int64)]; r != nil && r.status == "A" && (r.firstAttemptAt == nil || r.firstAttemptAt.After(m.now.Add(-window))) {
			if r.firstAttemptAt == nil {
				first := m.now
				r.firstAttemptAt = &first
			}
			r.attempts++
			r.lastError = ""
			res.Rows = [][]any{{r.id}}
		}
	case qRefundRecordAccepted:
		if r := m.requests[args[3].(int64)]; r != nil && (r.status == "A" || r.status == "F") {
			amount := args[1].(int64)
			r.status, r.providerRefundID, r.providerAmount, r.lastError = "S", args[0].(string), &amount, optionalString(args[2])
		}
	case qRefundRecordDeclined:
		if r := m.requests[args[2].(int64)]; r != nil && r.status == "A" {
			r.status, r.providerRefundID, r.lastError = "F", optionalString(args[0]), args[1].(string)
		}
	case qRefundRecordError:
		if r := m.requests[args[1].(int64)]; r != nil && r.status == "A" {
			r.lastError = args[0].(string)
		}
	case qRefundApplyCumulative:
		m.balances[args[1].(int64)].refunded = args[0].(int64)
	default:
		return nil, fmt.Errorf("memRefundStore: unexpected query %s", name)
	}
	return res, nil
}

type memRefundTx struct {
	store *memRefundStore
	done  bool
}

func (t *memRefundTx) Query(_ context.Context, name string, args ...any) (*model.QueryResult, error) {
	t.store.mu.Lock()
	defer t.store.mu.Unlock()
	return t.store.query(true, name, args...)
}

func (t *memRefundTx) GenID() int64 { return t.store.GenID() }

func (t *memRefundTx) finish() error {
	if !t.done {
		t.done = true
		t.store.mu.Lock()
		t.store.openTx--
		t.store.mu.Unlock()
	}
	return nil
}

func (t *memRefundTx) Commit(context.Context) error   { return t.finish() }
func (t *memRefundTx) Rollback(context.Context) error { return t.finish() }

type memRefundRepo struct {
	port.DatabaseRepository
	store *memRefundStore
}

func (r memRefundRepo) GetQueryService(context.Context, map[string]string) port.QueryService {
	return r.store
}

func (r memRefundRepo) BeginTx(context.Context, map[string]string) (port.TxQueryService, error) {
	r.store.mu.Lock()
	r.store.openTx++
	r.store.mu.Unlock()
	return &memRefundTx{store: r.store}, nil
}

type fakeRefundClient struct {
	store   *memRefundStore
	calls   []RefundRequest
	respond func(RefundRequest) (RefundResult, error)
	txOpen  bool
}

func (f *fakeRefundClient) CreateRefund(_ context.Context, req RefundRequest) (RefundResult, error) {
	f.store.mu.Lock()
	f.txOpen = f.txOpen || f.store.openTx > 0
	f.store.mu.Unlock()
	f.calls = append(f.calls, req)
	if f.respond != nil {
		return f.respond(req)
	}
	return RefundResult{RefundID: fmt.Sprintf("re_%d", len(f.calls)), Status: RefundSucceeded, AmountMinor: req.AmountMinor, Currency: req.Currency}, nil
}

type fakeCaptureReader struct {
	captured map[string]CapturedPayment
	calls    int
}

func (f *fakeCaptureReader) CapturedAmount(_ context.Context, paymentID string) (CapturedPayment, error) {
	f.calls++
	c, ok := f.captured[paymentID]
	if !ok {
		return CapturedPayment{}, ErrRefundCapturedAmountAbsent
	}
	return c, nil
}

var (
	_ port.TxQueryService = (*memRefundTx)(nil)
	_ RefundClient        = (*fakeRefundClient)(nil)
	_ CaptureReader       = (*fakeCaptureReader)(nil)
)
