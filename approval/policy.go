package approval

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/port"
)

// Policy is the separation-of-duties rule of one owner for one review kind:
// an approval_request object type or a document_type id. PartnerID 0 is the
// platform, whose row applies to every partner without its own.
type Policy struct {
	PartnerID         int64
	ObjectType        string
	AllowSinglePerson bool
	ChangedBy         int64
}

// SetPolicy records the next policy of the owner and closes the previous
// row. ChangedBy must be one of the owner's Administrators. Requiring
// separation is in force at once; allowing a single person is in force at
// once only when the owner has no other administrator, otherwise it waits
// for ConfirmPolicy and separation stays required meanwhile.
func (s *Service) SetPolicy(ctx context.Context, p Policy) error {
	p.ObjectType = strings.TrimSpace(p.ObjectType)
	if p.PartnerID < 0 || p.ObjectType == "" || len(p.ObjectType) > maxObjectType || p.ChangedBy <= 0 {
		return fmt.Errorf("approval: object type and the changing administrator are required")
	}
	admins, err := s.administrators(ctx, p.PartnerID, p.ChangedBy)
	if err != nil {
		return err
	}
	inForce := !p.AllowSinglePerson || !slices.ContainsFunc(admins, func(id int64) bool { return id != p.ChangedBy })
	return s.transact(ctx, func(tx port.TxQueryService) error {
		if _, err := tx.Query(ctx, qClosePolicy, ownerArg(p.PartnerID), p.ObjectType); err != nil {
			return err
		}
		_, err := tx.Query(ctx, qInsertPolicy, tx.GenID(), ownerArg(p.PartnerID), p.ObjectType, p.AllowSinglePerson, p.ChangedBy, inForce)
		return err
	})
}

// ConfirmPolicy puts the owner's pending policy for objectType in force.
// confirmerID must be an administrator of the owner other than the one who
// set it (ErrPolicyConfirmation); ErrNoPendingPolicy when nothing waits.
func (s *Service) ConfirmPolicy(ctx context.Context, partnerID int64, objectType string, confirmerID int64) error {
	if partnerID < 0 || confirmerID <= 0 {
		return fmt.Errorf("approval: owner and confirming administrator are required")
	}
	if _, err := s.administrators(ctx, partnerID, confirmerID); err != nil {
		return err
	}
	return s.transact(ctx, func(tx port.TxQueryService) error {
		res, err := tx.Query(ctx, qLockPendingPolicy, ownerArg(partnerID), strings.TrimSpace(objectType))
		if err != nil {
			return err
		}
		if len(res.Rows) == 0 {
			return fmt.Errorf("%w: %s", ErrNoPendingPolicy, objectType)
		}
		if common.AsInt64(res.Rows[0][1]) == confirmerID {
			return fmt.Errorf("%w: %d set it", ErrPolicyConfirmation, confirmerID)
		}
		_, err = tx.Query(ctx, qConfirmPolicy, confirmerID, common.AsInt64(res.Rows[0][0]))
		return err
	})
}

// administrators returns the owner's administrators after checking that
// userID is one of them.
func (s *Service) administrators(ctx context.Context, partnerID, userID int64) ([]int64, error) {
	if s.Administrators == nil {
		return nil, ErrNotAdministrator
	}
	admins, err := s.Administrators(ctx, partnerID)
	if err != nil {
		return nil, err
	}
	if !slices.Contains(admins, userID) {
		return nil, fmt.Errorf("%w: %d", ErrNotAdministrator, userID)
	}
	return admins, nil
}

func ownerArg(partnerID int64) any {
	if partnerID == 0 {
		return nil
	}
	return partnerID
}

// AllowsSinglePerson reports whether one person may both submit and decide a
// record, or upload and review a document, of objectType for the partner:
// the partner's policy in force, else the platform's, else no.
func (s *Service) AllowsSinglePerson(ctx context.Context, partnerID int64, objectType string) (bool, error) {
	return s.allowsSinglePerson(ctx, s.query(ctx), partnerID, objectType)
}

func (s *Service) allowsSinglePerson(ctx context.Context, qs port.QueryService, partnerID int64, objectType string) (bool, error) {
	res, err := qs.Query(ctx, qAllowSingle, objectType, partnerID)
	if err != nil {
		return false, err
	}
	return len(res.Rows) > 0 && common.AsBool(res.Rows[0][0]), nil
}
