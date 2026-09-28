package approval

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/data"
	"github.com/nauticana/keel/pgsql"
	"github.com/nauticana/keel/port"
)

const (
	maxObjectType = 50
	maxNote       = 500
)

// Service runs maker-checker approval over application records. Separation
// of maker and checker is enforced unless the partner's approval_policy
// allows a single person to act as both.
type Service struct {
	DB port.DatabaseRepository
	// OnDecided runs inside Decide's transaction after the decision is
	// written, so the application moves its parent record atomically with it.
	OnDecided func(ctx context.Context, tx port.TxQueryService, req *Request) error

	once sync.Once
	qs   port.QueryService
}

func (s *Service) query(ctx context.Context) port.QueryService {
	s.once.Do(func() { s.qs = s.DB.GetQueryService(ctx, queries) })
	return s.qs
}

func (s *Service) transact(ctx context.Context, fn func(port.TxQueryService) error) error {
	tx, err := s.DB.BeginTx(ctx, queries)
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			_ = data.RollbackDetached(tx)
		}
	}()
	if err := fn(tx); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	committed = true
	return nil
}

// Submit opens a pending request for the record. A record has at most one
// open request; a rejected or approved record is submitted again as a new one.
func (s *Service) Submit(ctx context.Context, partnerID int64, objectType string, objectID, makerID int64) (*Request, error) {
	objectType = strings.TrimSpace(objectType)
	if partnerID <= 0 || objectID <= 0 || makerID <= 0 || objectType == "" || len(objectType) > maxObjectType {
		return nil, fmt.Errorf("approval: partner, object type, object id and maker are required")
	}
	var id int64
	err := s.transact(ctx, func(tx port.TxQueryService) error {
		open, err := tx.Query(ctx, qOpenFor, partnerID, objectType, objectID)
		if err != nil {
			return err
		}
		if len(open.Rows) > 0 {
			return fmt.Errorf("%w: request %d", ErrAlreadyOpen, common.AsInt64(open.Rows[0][0]))
		}
		id = tx.GenID()
		if _, err := tx.Query(ctx, qInsertRequest, id, partnerID, objectType, objectID, makerID); err != nil {
			if pgsql.IsUniqueViolation(err) {
				return fmt.Errorf("%w: %s %d", ErrAlreadyOpen, objectType, objectID)
			}
			return err
		}
		_, err = tx.Query(ctx, qInsertEvent, tx.GenID(), id, EventSubmitted, makerID, nil)
		return err
	})
	if err != nil {
		return nil, err
	}
	return s.Get(ctx, partnerID, id)
}

// Decide approves or rejects a pending request. The checker must differ from
// the maker (ErrSameActor) unless the partner allows a single person.
func (s *Service) Decide(ctx context.Context, partnerID, id, checkerID int64, approved bool, note string) (*Request, error) {
	if checkerID <= 0 {
		return nil, fmt.Errorf("approval: checker is required")
	}
	if len(note) > maxNote {
		return nil, fmt.Errorf("approval: note exceeds %d bytes", maxNote)
	}
	err := s.transact(ctx, func(tx port.TxQueryService) error {
		res, err := tx.Query(ctx, qLock, partnerID, id)
		if err != nil {
			return err
		}
		if len(res.Rows) == 0 {
			return fmt.Errorf("%w: %d", ErrNotFound, id)
		}
		req := requestFromRow(res.Rows[0])
		if req.Status != StatusPending {
			return fmt.Errorf("%w: %d is %s", ErrInvalidState, id, req.Status)
		}
		if checkerID == req.MakerID {
			allowed, err := s.allowsSinglePerson(ctx, tx, partnerID)
			if err != nil {
				return err
			}
			if !allowed {
				return fmt.Errorf("%w: %d", ErrSameActor, id)
			}
		}
		status, event := StatusRejected, EventRejected
		if approved {
			status, event = StatusApproved, EventApproved
		}
		if _, err := tx.Query(ctx, qSetDecision, status, checkerID, nullableNote(note), id); err != nil {
			return err
		}
		if _, err := tx.Query(ctx, qInsertEvent, tx.GenID(), id, event, checkerID, nullableNote(note)); err != nil {
			return err
		}
		req.Status, req.CheckerID, req.DecisionNote = status, checkerID, note
		if s.OnDecided != nil {
			return s.OnDecided(ctx, tx, req)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return s.Get(ctx, partnerID, id)
}

// Get returns one request of the partner.
func (s *Service) Get(ctx context.Context, partnerID, id int64) (*Request, error) {
	res, err := s.query(ctx).Query(ctx, qGet, partnerID, id)
	if err != nil {
		return nil, err
	}
	if len(res.Rows) == 0 {
		return nil, fmt.Errorf("%w: %d", ErrNotFound, id)
	}
	return requestFromRow(res.Rows[0]), nil
}

// Latest returns the record's most recent request, whose Status is the
// record's approval state.
func (s *Service) Latest(ctx context.Context, partnerID int64, objectType string, objectID int64) (*Request, error) {
	res, err := s.query(ctx).Query(ctx, qLatestFor, partnerID, objectType, objectID)
	if err != nil {
		return nil, err
	}
	if len(res.Rows) == 0 {
		return nil, fmt.Errorf("%w: %s %d", ErrNotFound, objectType, objectID)
	}
	return requestFromRow(res.Rows[0]), nil
}

// Pending lists the partner's open requests, oldest first.
func (s *Service) Pending(ctx context.Context, partnerID int64) ([]*Request, error) {
	res, err := s.query(ctx).Query(ctx, qPending, partnerID)
	if err != nil {
		return nil, err
	}
	out := make([]*Request, 0, len(res.Rows))
	for _, r := range res.Rows {
		out = append(out, requestFromRow(r))
	}
	return out, nil
}

// Events returns the audit trail of a partner's request.
func (s *Service) Events(ctx context.Context, partnerID, id int64) ([]*Event, error) {
	if _, err := s.Get(ctx, partnerID, id); err != nil {
		return nil, err
	}
	res, err := s.query(ctx).Query(ctx, qEvents, id)
	if err != nil {
		return nil, err
	}
	out := make([]*Event, 0, len(res.Rows))
	for _, r := range res.Rows {
		out = append(out, eventFromRow(r))
	}
	return out, nil
}

// AllowsSinglePerson reports whether the partner lets the maker decide their own request.
func (s *Service) AllowsSinglePerson(ctx context.Context, partnerID int64) (bool, error) {
	return s.allowsSinglePerson(ctx, s.query(ctx), partnerID)
}

func (s *Service) allowsSinglePerson(ctx context.Context, qs port.QueryService, partnerID int64) (bool, error) {
	res, err := qs.Query(ctx, qAllowSingle, partnerID)
	if err != nil {
		return false, err
	}
	return len(res.Rows) > 0 && common.AsBool(res.Rows[0][0]), nil
}

func nullableNote(note string) any {
	if note == "" {
		return nil
	}
	return note
}
