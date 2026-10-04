package agency

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/data"
	"github.com/nauticana/keel/model"
	"github.com/nauticana/keel/port"
)

const (
	maxDelegationRoles  = 32
	maxDelegationRoleID = 10

	roleGranted       = "G"
	roleExpiryChanged = "E"
	roleRemoved       = "R"
)

// SetDelegationRoles replaces the role set the client grants its agency. Only
// the client partner may call it; an empty set removes access without revoking.
func (s *BaseAgencyService) SetDelegationRoles(ctx context.Context, clientPartnerID, callerPartnerID int64, grants []model.AgencyRoleGrant, callerUserID int64) error {
	if clientPartnerID <= 0 || callerPartnerID != clientPartnerID || callerUserID <= 0 {
		return port.ErrNotClientOwner
	}
	wanted, earliest, err := normalizeRoleGrants(grants)
	if err != nil {
		return err
	}
	if err = s.validateRoleGrants(ctx, wanted, earliest); err != nil {
		return err
	}

	tx, err := s.db.BeginTx(ctx, baseAgencyQueries)
	if err != nil {
		return fmt.Errorf("agency: begin delegation-roles transaction: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = data.RollbackDetached(tx)
		}
	}()
	locked, err := tx.Query(ctx, qDelegationLock, clientPartnerID)
	if err != nil {
		return fmt.Errorf("agency: lock delegation: %w", err)
	}
	if len(locked.Rows) == 0 {
		return port.ErrAgencyNotFound
	}
	delegationID := common.AsInt64(locked.Rows[0][0])
	current, err := tx.Query(ctx, qDelegationRoles, delegationID)
	if err != nil {
		return fmt.Errorf("agency: current delegation roles: %w", err)
	}
	existing := make(map[string]*time.Time, len(current.Rows))
	for _, row := range current.Rows {
		existing[common.AsString(row[0])] = optionalTime(row[1])
	}

	for _, role := range sortedRoles(existing) {
		if _, kept := wanted[role]; kept {
			continue
		}
		if _, err = tx.Query(ctx, qDeleteDelegationRole, delegationID, role); err != nil {
			return fmt.Errorf("agency: remove delegation role %q: %w", role, err)
		}
		if err = recordRoleChange(ctx, tx, delegationID, callerUserID, role, roleRemoved, existing[role], nil); err != nil {
			return err
		}
	}
	for _, role := range sortedRoles(wanted) {
		expiresAt := wanted[role]
		oldExpiry, had := existing[role]
		switch {
		case !had:
			if _, err = tx.Query(ctx, qInsertDelegationRole, delegationID, role, timeArg(expiresAt), callerUserID); err != nil {
				return fmt.Errorf("agency: grant delegation role %q: %w", role, err)
			}
			err = recordRoleChange(ctx, tx, delegationID, callerUserID, role, roleGranted, nil, expiresAt)
		case !sameExpiry(oldExpiry, expiresAt):
			if _, err = tx.Query(ctx, qUpdateRoleExpiry, timeArg(expiresAt), delegationID, role); err != nil {
				return fmt.Errorf("agency: change delegation role %q expiry: %w", role, err)
			}
			err = recordRoleChange(ctx, tx, delegationID, callerUserID, role, roleExpiryChanged, oldExpiry, expiresAt)
		}
		if err != nil {
			return err
		}
	}
	if err = tx.Commit(ctx); err != nil {
		return fmt.Errorf("agency: commit delegation roles: %w", err)
	}
	committed = true
	return nil
}

// ActiveFor lists the agency's delegations that grant at least one unexpired
// role, each carrying only those roles.
func (s *BaseAgencyService) ActiveFor(ctx context.Context, agencyPartnerID int64) ([]model.AgencyDelegation, error) {
	rows, err := s.QueryRows(ctx, qActiveDelegationsFor, agencyPartnerID)
	if err != nil {
		return nil, fmt.Errorf("agency: active delegations: %w", err)
	}
	out := []model.AgencyDelegation{}
	for _, row := range rows {
		if n := len(out); n == 0 || out[n-1].ID != common.AsInt64(row[0]) {
			out = append(out, scanDelegation(row))
		}
		last := &out[len(out)-1]
		last.Roles = append(last.Roles, scanRoleGrant(row[7], row[8]))
	}
	return out, nil
}

// HasRole returns nil only when the agency currently holds role for the client.
func (s *BaseAgencyService) HasRole(ctx context.Context, agencyPartnerID, clientPartnerID int64, role string) error {
	role = strings.TrimSpace(role)
	if agencyPartnerID <= 0 || clientPartnerID <= 0 || role == "" {
		return port.ErrDelegationNoAccess
	}
	row, err := s.QueryFirst(ctx, qHasDelegationRole, agencyPartnerID, clientPartnerID, role)
	if err != nil {
		return fmt.Errorf("agency: delegation role check: %w", err)
	}
	if row == nil {
		return port.ErrDelegationNoAccess
	}
	return nil
}

// expireDelegationRoles ends every open role at the database clock, keeping
// the rows so the granted set stays readable after revocation.
func expireDelegationRoles(ctx context.Context, tx port.TxQueryService, delegationID, actorUserID int64) error {
	expired, err := tx.Query(ctx, qExpireDelegationRoles, delegationID, delegationID)
	if err != nil {
		return fmt.Errorf("agency: expire delegation roles: %w", err)
	}
	for _, row := range expired.Rows {
		if err = recordRoleChange(ctx, tx, delegationID, actorUserID, common.AsString(row[0]),
			roleExpiryChanged, optionalTime(row[1]), optionalTime(row[2])); err != nil {
			return err
		}
	}
	return nil
}

func (s *BaseAgencyService) validateRoleGrants(ctx context.Context, wanted map[string]*time.Time, earliest *time.Time) error {
	if len(wanted) > 0 {
		rows, err := s.QueryRows(ctx, qKnownDelegationRoles)
		if err != nil {
			return fmt.Errorf("agency: delegation role catalogue: %w", err)
		}
		known := make(map[string]bool, len(rows))
		for _, row := range rows {
			known[common.AsString(row[0])] = true
		}
		for role := range wanted {
			if !known[role] {
				return port.ErrInvalidDelegationRole
			}
		}
	}
	if earliest != nil {
		future, err := s.QueryFirst(ctx, qExpiryInFuture, *earliest)
		if err != nil {
			return fmt.Errorf("agency: delegation expiry check: %w", err)
		}
		if future == nil || !common.AsBool(future[0]) {
			return port.ErrDelegationExpiryPast
		}
	}
	return nil
}

// normalizeRoleGrants trims roles, rejects blank, oversized, duplicate, and
// excessive input, and truncates expiries to PostgreSQL's microseconds so a
// repeated call is a no-op. It also returns the earliest expiry.
func normalizeRoleGrants(grants []model.AgencyRoleGrant) (map[string]*time.Time, *time.Time, error) {
	if len(grants) > maxDelegationRoles {
		return nil, nil, port.ErrTooManyDelegationRoles
	}
	wanted := make(map[string]*time.Time, len(grants))
	var earliest *time.Time
	for _, grant := range grants {
		role := strings.TrimSpace(grant.Role)
		if role == "" || len(role) > maxDelegationRoleID {
			return nil, nil, port.ErrInvalidDelegationRole
		}
		if _, dup := wanted[role]; dup {
			return nil, nil, port.ErrDuplicateDelegationRole
		}
		var expiresAt *time.Time
		if grant.ExpiresAt != nil {
			utc := grant.ExpiresAt.UTC().Truncate(time.Microsecond)
			expiresAt = &utc
			if earliest == nil || utc.Before(*earliest) {
				earliest = expiresAt
			}
		}
		wanted[role] = expiresAt
	}
	return wanted, earliest, nil
}

func recordRoleChange(ctx context.Context, tx port.TxQueryService, delegationID, actorUserID int64, role, changeType string, oldExpiry, newExpiry *time.Time) error {
	if _, err := tx.Query(ctx, qInsertDelegationEvent, tx.GenID(), delegationID, actorUserID,
		role, changeType, timeArg(oldExpiry), timeArg(newExpiry)); err != nil {
		return fmt.Errorf("agency: record delegation role change: %w", err)
	}
	return nil
}

func scanRoleGrant(role, expiresAt any) model.AgencyRoleGrant {
	return model.AgencyRoleGrant{Role: common.AsString(role), ExpiresAt: optionalTime(expiresAt)}
}

func sortedRoles(roles map[string]*time.Time) []string {
	out := make([]string, 0, len(roles))
	for role := range roles {
		out = append(out, role)
	}
	sort.Strings(out)
	return out
}

func timeArg(t *time.Time) any {
	if t == nil {
		return nil
	}
	return *t
}

func optionalTime(value any) *time.Time {
	t := common.AsTime(value)
	if t.IsZero() {
		return nil
	}
	return &t
}

func sameExpiry(a, b *time.Time) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return a.Equal(*b)
}
