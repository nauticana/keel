package service

import (
	"context"
	"errors"
	"fmt"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/model"
	"github.com/nauticana/keel/port"
)

// ObjectTable is the authorization object of generic table grants.
const ObjectTable = "TABLE"

// Access authorizes a service operation for the caller bound to the context,
// so an HTTP endpoint, a tool call and a worker are held to the same grant.
type Access struct {
	DB port.DatabaseRepository
	// Role is the role a worker acts under when its context carries no caller;
	// set it only in a worker's composition. Such a worker may act in any tenant.
	Role string
}

// Caller resolves who acts: the signed-in user, else the worker role when no
// caller is bound at all. Any other caller is refused.
func (a Access) Caller(ctx context.Context) (common.CallerSession, model.Principal, error) {
	caller, err := common.CallerSessionFromContext(ctx)
	switch {
	case err == nil && caller.UserID > 0:
		return caller, model.UserPrincipal(int(caller.UserID)), nil
	case errors.Is(err, common.ErrUnauthenticated) && a.Role != "":
		return common.CallerSession{}, model.RolePrincipal(a.Role), nil
	case err != nil:
		return common.CallerSession{}, model.Principal{}, err
	}
	return common.CallerSession{}, model.Principal{}, fmt.Errorf("%w: no signed-in user", ErrForbidden)
}

// Tenant returns the caller when it may act in partnerID; another tenant
// answers as not found, the same as a missing record.
func (a Access) Tenant(ctx context.Context, partnerID int64) (common.CallerSession, error) {
	caller, _, err := a.tenant(ctx, partnerID)
	return caller, err
}

func (a Access) tenant(ctx context.Context, partnerID int64) (common.CallerSession, model.Principal, error) {
	caller, principal, err := a.Caller(ctx)
	if err == nil && (partnerID <= 0 || (principal.Kind == model.PrincipalUser && caller.PartnerID != partnerID)) {
		err = ErrNotFound
	}
	if err != nil {
		return common.CallerSession{}, model.Principal{}, err
	}
	return caller, principal, nil
}

// Table is Action for the generic TABLE grant of action on table.
func (a Access) Table(ctx context.Context, partnerID int64, action, table string) (common.CallerSession, error) {
	return a.Action(ctx, partnerID, ObjectTable, action, table)
}

// Action returns the caller when it may act in partnerID and holds object/action on scope.
func (a Access) Action(ctx context.Context, partnerID int64, object, action, scope string) (common.CallerSession, error) {
	caller, principal, err := a.tenant(ctx, partnerID)
	if err == nil {
		err = a.require(ctx, principal, object, action, scope)
	}
	if err != nil {
		return common.CallerSession{}, err
	}
	return caller, nil
}

// Platform returns the caller when it holds object/action on scope for a row
// no tenant owns; the service still decides which rows it may see.
func (a Access) Platform(ctx context.Context, object, action, scope string) (common.CallerSession, error) {
	caller, principal, err := a.Caller(ctx)
	if err == nil {
		err = a.require(ctx, principal, object, action, scope)
	}
	if err != nil {
		return common.CallerSession{}, err
	}
	return caller, nil
}

func (a Access) require(ctx context.Context, principal model.Principal, object, action, scope string) error {
	if a.DB == nil {
		return fmt.Errorf("%w: no repository to read grants from", ErrForbidden)
	}
	if allowed, _ := a.DB.CheckActionPermission(ctx, principal, object, action, scope); !allowed {
		return fmt.Errorf("%w: %s %s on %s", ErrForbidden, object, action, scope)
	}
	return nil
}
