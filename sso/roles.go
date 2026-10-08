package sso

import (
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/port"
)

// claimValues returns the values a source asserts for a claim name.
type claimValues func(claim string) []string

// assertedClaims reads an assertion; a claim the issuer truncated maps to nothing.
func assertedClaims(a *port.IdentityAssertion) claimValues {
	return func(claim string) []string {
		if slices.Contains(a.Overage, claim) {
			return nil
		}
		return a.Claims[claim]
	}
}

// syncRoles makes the roles this connection's mapping granted the user equal
// the roles the claims now map to. Roles granted any other way are neither
// ended nor duplicated.
func syncRoles(ctx context.Context, tx port.QueryService, conn *connection, userID int, values claimValues) error {
	res, err := tx.Query(ctx, qRoleMappings, conn.PartnerID, conn.ID)
	if err != nil {
		return fmt.Errorf("sso: role mappings: %w", err)
	}
	wanted := map[string]bool{}
	for _, row := range res.Rows {
		claim, value, role := common.AsString(row[0]), common.AsString(row[1]), common.AsString(row[2])
		if slices.Contains(values(claim), value) {
			wanted[role] = true
		}
	}
	if res, err = tx.Query(ctx, qMappedGrants, conn.PartnerID, conn.ID, userID); err != nil {
		return fmt.Errorf("sso: mapped grants: %w", err)
	}
	mapped := map[string]bool{}
	for _, row := range res.Rows {
		role := common.AsString(row[0])
		mapped[role] = true
		if wanted[role] {
			continue
		}
		if _, err := tx.Query(ctx, qEndRole, userID, role, row[1]); err != nil {
			return fmt.Errorf("sso: end role %s: %w", role, err)
		}
	}
	if res, err = tx.Query(ctx, qOpenRoles, userID); err != nil {
		return fmt.Errorf("sso: open roles: %w", err)
	}
	held := map[string]bool{}
	for _, row := range res.Rows {
		held[common.AsString(row[0])] = true
	}
	for role := range wanted {
		if mapped[role] || held[role] {
			continue
		}
		granted, err := tx.Query(ctx, qGrantRole, userID, role)
		if err != nil {
			return fmt.Errorf("sso: grant role %s: %w", role, err)
		}
		if len(granted.Rows) == 0 {
			continue // no longer partner-scoped
		}
		begda, ok := granted.Rows[0][0].(time.Time)
		if !ok {
			return fmt.Errorf("sso: grant role %s: no start time", role)
		}
		if _, err := tx.Query(ctx, qRecordGrant, userID, role, begda, conn.PartnerID, conn.ID); err != nil {
			return fmt.Errorf("sso: record grant %s: %w", role, err)
		}
	}
	return nil
}
