package erasure

import (
	"context"
	crand "crypto/rand"
	"encoding/hex"
	"fmt"
	"strconv"
	"sync"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/data"
	"github.com/nauticana/keel/port"
	"github.com/nauticana/keel/user"
)

// Service records erasure requests and legal holds, executes requests through
// the application's classifiers and guards the pseudonym mapping.
type Service struct {
	DB          port.DatabaseRepository
	Accounts    AccountEraser
	Classifiers []Classifier

	once         sync.Once
	setupErr     error
	qs           port.QueryService
	byTable      map[string]Classifier
	classifierQS map[string]port.QueryService
}

func (s *Service) setup(ctx context.Context) error {
	s.once.Do(func() {
		s.qs = s.DB.GetQueryService(ctx, queries)
		s.byTable = make(map[string]Classifier, len(s.Classifiers))
		s.classifierQS = make(map[string]port.QueryService, len(s.Classifiers))
		for _, c := range s.Classifiers {
			table := c.Table()
			if table == "" || table == accountTable || s.byTable[table] != nil {
				s.setupErr = fmt.Errorf("%w: table %q is empty, reserved or repeated", ErrInvalidClassifier, table)
				return
			}
			s.byTable[table] = c
			s.classifierQS[table] = s.DB.GetQueryService(ctx, c.Queries())
		}
	})
	return s.setupErr
}

// Request opens an erasure request for userID, or returns the one already
// open, with the plan of what its execution will do. A user under legal hold
// gets a held request that runs once every hold is released.
func (s *Service) Request(ctx context.Context, userID, requestedBy int) (*Plan, error) {
	if err := s.setup(ctx); err != nil {
		return nil, err
	}
	items, err := s.classify(ctx, userID)
	if err != nil {
		return nil, err
	}
	tx, err := s.DB.BeginTx(ctx, queries)
	if err != nil {
		return nil, err
	}
	committed := false
	defer func() {
		if !committed {
			_ = data.RollbackDetached(tx)
		}
	}()
	if res, err := tx.Query(ctx, qLockUser, userID); err != nil {
		return nil, err
	} else if len(res.Rows) == 0 {
		return nil, ErrUserNotFound
	}
	open, err := tx.Query(ctx, qOpenRequest, userID)
	if err != nil {
		return nil, err
	}
	if len(open.Rows) == 0 {
		status := StatusPending
		if held, err := isHeld(ctx, tx, userID); err != nil {
			return nil, err
		} else if held {
			status = StatusHeld
		}
		id := tx.GenID()
		if _, err := tx.Query(ctx, qInsertRequest, id, userID, status, requestedBy); err != nil {
			return nil, err
		}
		if open, err = tx.Query(ctx, qGetRequest, id); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	committed = true
	return &Plan{Request: requestFrom(open.Rows[0]), Items: items}, nil
}

func (s *Service) Get(ctx context.Context, requestID int64) (*Request, error) {
	if err := s.setup(ctx); err != nil {
		return nil, err
	}
	res, err := s.qs.Query(ctx, qGetRequest, requestID)
	if err != nil {
		return nil, err
	}
	if len(res.Rows) == 0 {
		return nil, ErrNotFound
	}
	req := requestFrom(res.Rows[0])
	return &req, nil
}

// Cancel withdraws a request that has not started.
func (s *Service) Cancel(ctx context.Context, requestID int64) error {
	if _, err := s.Get(ctx, requestID); err != nil {
		return err
	}
	res, err := s.qs.Query(ctx, qCancelRequest, requestID)
	if err != nil {
		return err
	}
	if len(res.Rows) == 0 {
		return ErrNotCancellable
	}
	return nil
}

func (s *Service) Audit(ctx context.Context, requestID int64) ([]AuditEntry, error) {
	if err := s.setup(ctx); err != nil {
		return nil, err
	}
	res, err := s.qs.Query(ctx, qListAudit, requestID)
	if err != nil {
		return nil, err
	}
	entries := make([]AuditEntry, 0, len(res.Rows))
	for _, r := range res.Rows {
		entries = append(entries, AuditEntry{
			Table: common.AsString(r[0]), Key: common.AsString(r[1]), Action: Action(common.AsString(r[2])),
			Reason: common.AsString(r[3]), ExecutedAt: common.AsTime(r[4]),
		})
	}
	return entries, nil
}

// PlaceHold puts the user's data under legal hold until ReleaseHold.
func (s *Service) PlaceHold(ctx context.Context, userID int, reason string, placedBy int) (int64, error) {
	if reason == "" || len(reason) > maxReasonLength {
		return 0, ErrReasonRequired
	}
	if err := s.setup(ctx); err != nil {
		return 0, err
	}
	id := s.qs.GenID()
	if _, err := s.qs.Query(ctx, qPlaceHold, id, userID, reason, placedBy); err != nil {
		return 0, err
	}
	return id, nil
}

func (s *Service) ReleaseHold(ctx context.Context, holdID int64, releasedBy int) error {
	if err := s.setup(ctx); err != nil {
		return err
	}
	res, err := s.qs.Query(ctx, qReleaseHold, releasedBy, holdID)
	if err != nil {
		return err
	}
	if len(res.Rows) == 0 {
		return ErrHoldNotFound
	}
	return nil
}

// Holds lists the user's unreleased holds.
func (s *Service) Holds(ctx context.Context, userID int) ([]LegalHold, error) {
	if err := s.setup(ctx); err != nil {
		return nil, err
	}
	res, err := s.qs.Query(ctx, qListHolds, userID)
	if err != nil {
		return nil, err
	}
	holds := make([]LegalHold, 0, len(res.Rows))
	for _, r := range res.Rows {
		holds = append(holds, LegalHold{
			ID: common.AsInt64(r[0]), UserID: int(common.AsInt64(r[1])), Reason: common.AsString(r[2]),
			PlacedBy: int(common.AsInt64(r[3])), PlacedAt: common.AsTime(r[4]),
		})
	}
	return holds, nil
}

// ResolvePseudonym re-identifies a pseudonym and records who asked and why.
// Authorizing actorID is the caller's job; this is the only read path.
func (s *Service) ResolvePseudonym(ctx context.Context, pseudonym string, actorID int, reason string) (int, error) {
	if reason == "" || len(reason) > maxReasonLength {
		return 0, ErrReasonRequired
	}
	if err := s.setup(ctx); err != nil {
		return 0, err
	}
	tx, err := s.DB.BeginTx(ctx, queries)
	if err != nil {
		return 0, err
	}
	committed := false
	defer func() {
		if !committed {
			_ = data.RollbackDetached(tx)
		}
	}()
	res, err := tx.Query(ctx, qResolvePseudonym, pseudonym)
	if err != nil {
		return 0, err
	}
	if len(res.Rows) == 0 {
		return 0, ErrUnknownPseudonym
	}
	userID := int(common.AsInt64(res.Rows[0][0]))
	if _, err := tx.Query(ctx, qInsertLookup, tx.GenID(), userID, actorID, reason); err != nil {
		return 0, err
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}
	committed = true
	return userID, nil
}

// Execute runs a request: every classified row is deleted, anonymized or held,
// each in its own transaction with its audit row, then the account itself is
// erased. Rows audited by an earlier run are skipped, so a failed run is
// resumed by calling Execute again. Returns user.ErrLegalHold while held.
func (s *Service) Execute(ctx context.Context, requestID int64, userID int) error {
	if err := s.setup(ctx); err != nil {
		return err
	}
	req, err := s.Get(ctx, requestID)
	if err != nil {
		return err
	}
	if req.UserID != userID {
		return ErrRequestUser
	}
	if req.Status != StatusPending && req.Status != StatusActive && req.Status != StatusHeld {
		return ErrNotExecutable
	}
	if s.Accounts == nil {
		return fmt.Errorf("erasure: no AccountEraser configured")
	}
	if held, err := isHeld(ctx, s.qs, userID); err != nil {
		return err
	} else if held {
		return user.ErrLegalHold
	}
	items, err := s.classify(ctx, userID)
	if err != nil {
		return err
	}
	pseudonym, retained := "", false
	for _, item := range items {
		if err := ctx.Err(); err != nil {
			return err
		}
		retained = retained || item.Action == ActionHold
		if pseudonym, err = s.apply(ctx, requestID, userID, item, pseudonym); err != nil {
			return fmt.Errorf("erasure %s %s: %w", item.Table, item.Key, err)
		}
	}
	if err := s.Accounts.DeleteAccount(userID, fmt.Sprintf("erasure request %d", requestID)); err != nil {
		return err
	}
	account := Item{Table: accountTable, Key: strconv.Itoa(userID), Action: ActionAnonymize}
	if _, err := s.qs.Query(ctx, qInsertAudit, requestID, account.Table, account.Key, string(account.Action), nil); err != nil {
		return err
	}
	if retained {
		return nil
	}
	// Nothing retained can be linked back, so the pseudonym becomes anonymous.
	_, err = s.qs.Query(ctx, qDropPseudonym, userID)
	return err
}

// apply handles one item and returns the user's pseudonym once it was needed.
func (s *Service) apply(ctx context.Context, requestID int64, userID int, item Item, pseudonym string) (string, error) {
	tx, err := s.DB.BeginTx(ctx, queries)
	if err != nil {
		return pseudonym, err
	}
	committed := false
	defer func() {
		if !committed {
			_ = data.RollbackDetached(tx)
		}
	}()
	if held, err := isHeld(ctx, tx, userID); err != nil {
		return pseudonym, err
	} else if held {
		return pseudonym, user.ErrLegalHold
	}
	var reason any
	if item.Reason != "" {
		reason = item.Reason
	}
	res, err := tx.Query(ctx, qInsertAudit, requestID, item.Table, item.Key, string(item.Action), reason)
	if err != nil {
		return pseudonym, err
	}
	if len(res.Rows) == 0 {
		return pseudonym, nil
	}
	if item.Action != ActionHold {
		if item.Action == ActionAnonymize && pseudonym == "" {
			if pseudonym, err = ensurePseudonym(ctx, tx, userID); err != nil {
				return "", err
			}
		}
		catalog, ok := tx.(port.TxQueryCatalog)
		if !ok {
			return pseudonym, ErrTxCatalog
		}
		c := s.byTable[item.Table]
		standIn := ""
		if item.Action == ActionAnonymize {
			standIn = pseudonym
		}
		if err := c.Erase(ctx, catalog.QueryService("erasure."+item.Table, c.Queries()), userID, item, standIn); err != nil {
			return pseudonym, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return pseudonym, err
	}
	committed = true
	return pseudonym, nil
}

func (s *Service) classify(ctx context.Context, userID int) ([]Item, error) {
	var items []Item
	for _, c := range s.Classifiers {
		table := c.Table()
		found, err := c.Classify(ctx, s.classifierQS[table], userID)
		if err != nil {
			return nil, fmt.Errorf("erasure: classify %s: %w", table, err)
		}
		for _, it := range found {
			it.Table = table
			if !it.valid() {
				return nil, fmt.Errorf("%w: %s %q action %q", ErrInvalidItem, table, it.Key, it.Action)
			}
			items = append(items, it)
		}
	}
	return items, nil
}

func isHeld(ctx context.Context, qs port.QueryService, userID int) (bool, error) {
	res, err := qs.Query(ctx, qActiveHold, userID)
	if err != nil {
		return false, err
	}
	return len(res.Rows) > 0, nil
}

func ensurePseudonym(ctx context.Context, tx port.QueryService, userID int) (string, error) {
	b := make([]byte, 16)
	if _, err := crand.Read(b); err != nil {
		return "", err
	}
	if _, err := tx.Query(ctx, qEnsurePseudonym, userID, hex.EncodeToString(b)); err != nil {
		return "", err
	}
	res, err := tx.Query(ctx, qGetPseudonym, userID)
	if err != nil {
		return "", err
	}
	if len(res.Rows) == 0 {
		return "", fmt.Errorf("erasure: pseudonym of user %d not stored", userID)
	}
	return common.AsString(res.Rows[0][0]), nil
}

func requestFrom(r []any) Request {
	return Request{
		ID: common.AsInt64(r[0]), UserID: int(common.AsInt64(r[1])), Status: common.AsString(r[2]),
		RequestedBy: int(common.AsInt64(r[3])), RequestedAt: common.AsTime(r[4]), Attempts: int(common.AsInt64(r[5])),
		CompletedAt: common.AsTime(r[6]), LastError: common.AsString(r[7]),
	}
}
