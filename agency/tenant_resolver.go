package agency

import (
	"context"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/nauticana/keel/clock"
	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/model"
	"github.com/nauticana/keel/port"
)

const (
	qTenantUserActive = "agency_tenant_user_active"
	qTenantOwn        = "agency_tenant_own"
	qTenantPartner    = "agency_tenant_partner"

	tenantCacheEntries = 4096
)

var tenantQueries = map[string]string{
	qTenantUserActive: `SELECT 1 FROM user_account WHERE id = ? AND status = 'A'`,
	qTenantOwn: `
SELECT p.id, p.caption
  FROM partner_user u
  JOIN business_partner p ON p.id = u.partner_id
 WHERE u.user_id = ?
   AND u.begda <= CURRENT_TIMESTAMP
   AND (u.endda IS NULL OR u.endda > CURRENT_TIMESTAMP)
 ORDER BY p.id`,
	qTenantPartner: `SELECT id, caption FROM business_partner WHERE id = ?`,
}

// TenantResolver answers which partners a caller may act in: the user's own
// partners, the clients delegated to any agency partner among them when the
// user holds AGENCY/MANAGE_CLIENTS, or the one partner an API key is bound to.
type TenantResolver struct {
	DB port.DatabaseRepository
	// Delegations is optional; without it no tenant is delegated.
	Delegations port.AgencyDelegationResolver
	// Levels are the delegation role codes that grant acting, lowest first. A
	// delegation acts at the highest it holds; roles not listed grant nothing.
	Levels []string
	// LevelRoles maps a level to the authorization role a delegated caller
	// acts as, in place of the user's own roles.
	LevelRoles map[string]string
	// NeverDelegated are grant scopes no delegation reaches at any level.
	NeverDelegated []string
	// CacheTTL bounds how long a revoked membership or delegation keeps
	// resolving; zero disables the cache.
	CacheTTL time.Duration
	Clock    clock.Clock

	once  sync.Once
	qs    port.QueryService
	mu    sync.Mutex
	cache map[model.TenantCaller]tenantEntry
}

type tenantEntry struct {
	tenants []model.Tenant
	expires time.Time
}

func (s *TenantResolver) init(ctx context.Context) {
	s.once.Do(func() {
		s.qs = s.DB.GetQueryService(ctx, tenantQueries)
		s.cache = map[model.TenantCaller]tenantEntry{}
	})
}

func (s *TenantResolver) now() time.Time {
	if s.Clock == nil {
		return time.Now()
	}
	return s.Clock.Now()
}

// Authorized lists the caller's tenants, own first, served from the cache
// while it is fresh.
func (s *TenantResolver) Authorized(ctx context.Context, caller model.TenantCaller) ([]model.Tenant, error) {
	if !validCaller(caller) {
		return nil, ErrTenantCaller
	}
	s.init(ctx)
	if tenants, ok := s.cached(caller); ok {
		return tenants, nil
	}
	return s.AuthorizedFresh(ctx, caller)
}

// AuthorizedFresh reads current memberships and delegations past the cache;
// use it before an irreversible action.
func (s *TenantResolver) AuthorizedFresh(ctx context.Context, caller model.TenantCaller) ([]model.Tenant, error) {
	if !validCaller(caller) {
		return nil, ErrTenantCaller
	}
	s.init(ctx)
	tenants, err := s.load(ctx, caller)
	if err != nil {
		return nil, err
	}
	s.store(caller, tenants)
	return tenants, nil
}

// Resolve picks the requested tenant, or the only one when requested is 0.
func (s *TenantResolver) Resolve(ctx context.Context, caller model.TenantCaller, requested int64) (model.Tenant, error) {
	if requested < 0 {
		return model.Tenant{}, ErrTenantNotFound
	}
	tenants, err := s.Authorized(ctx, caller)
	if err != nil {
		return model.Tenant{}, err
	}
	if requested == 0 {
		switch len(tenants) {
		case 0:
			return model.Tenant{}, ErrTenantNotFound
		case 1:
			return tenants[0], nil
		}
		return model.Tenant{}, &TenantChoiceError{Choices: slices.Clone(tenants)}
	}
	for _, tenant := range tenants {
		if tenant.PartnerID == requested {
			return tenant, nil
		}
	}
	return model.Tenant{}, ErrTenantNotFound
}

// DelegationPrincipal is the role principal a delegated level acts as.
func (s *TenantResolver) DelegationPrincipal(level string) (model.Principal, bool) {
	role, ok := s.LevelRoles[level]
	if !ok || role == "" {
		return model.Principal{}, false
	}
	return model.RolePrincipal(role), true
}

// Delegable reports whether any delegation may reach a grant scope.
func (s *TenantResolver) Delegable(scope string) bool {
	return !slices.Contains(s.NeverDelegated, scope)
}

func validCaller(caller model.TenantCaller) bool {
	return (caller.UserID > 0) != (caller.APIKeyPartnerID > 0) && caller.UserID >= 0 && caller.APIKeyPartnerID >= 0
}

func (s *TenantResolver) load(ctx context.Context, caller model.TenantCaller) ([]model.Tenant, error) {
	if caller.APIKeyPartnerID > 0 {
		res, err := s.qs.Query(ctx, qTenantPartner, caller.APIKeyPartnerID)
		if err != nil {
			return nil, fmt.Errorf("agency: load partner %d: %w", caller.APIKeyPartnerID, err)
		}
		if len(res.Rows) == 0 {
			return nil, ErrTenantCaller
		}
		return []model.Tenant{tenantRow(res.Rows[0], model.TenantAPIKey)}, nil
	}
	active, err := s.qs.Query(ctx, qTenantUserActive, caller.UserID)
	if err != nil {
		return nil, fmt.Errorf("agency: check user %d: %w", caller.UserID, err)
	}
	if len(active.Rows) == 0 {
		return nil, ErrTenantCaller
	}
	res, err := s.qs.Query(ctx, qTenantOwn, caller.UserID)
	if err != nil {
		return nil, fmt.Errorf("agency: own partners of user %d: %w", caller.UserID, err)
	}
	tenants := make([]model.Tenant, 0, len(res.Rows))
	for _, row := range res.Rows {
		tenants = append(tenants, tenantRow(row, model.TenantOwn))
	}
	delegated, err := s.delegated(ctx, caller.UserID, tenants)
	if err != nil {
		return nil, err
	}
	return append(tenants, delegated...), nil
}

func tenantRow(row []any, relationship string) model.Tenant {
	return model.Tenant{PartnerID: common.AsInt64(row[0]), Name: common.AsString(row[1]), Relationship: relationship}
}

// delegated lists the clients each own agency partner manages. Own membership
// wins; when several agencies share a client, the highest level wins.
func (s *TenantResolver) delegated(ctx context.Context, userID int64, own []model.Tenant) ([]model.Tenant, error) {
	if s.Delegations == nil || len(own) == 0 {
		return nil, nil
	}
	if allowed, _ := s.DB.CheckActionPermission(ctx, model.UserPrincipal(int(userID)), "AGENCY", "MANAGE_CLIENTS", "agency_clients"); !allowed {
		return nil, nil
	}
	ownPartners := make(map[int64]bool, len(own))
	for _, tenant := range own {
		ownPartners[tenant.PartnerID] = true
	}
	var out []model.Tenant
	byPartner := make(map[int64]int)
	for _, agency := range own {
		delegations, err := s.Delegations.ActiveFor(ctx, agency.PartnerID)
		if err != nil {
			return nil, fmt.Errorf("agency: delegations of %d: %w", agency.PartnerID, err)
		}
		for _, d := range delegations {
			level := s.level(d.Roles)
			if level == "" || ownPartners[d.ClientPartnerID] {
				continue
			}
			tenant := model.Tenant{
				PartnerID: d.ClientPartnerID, Name: d.ClientName, Relationship: model.TenantDelegated,
				Level: level, DelegationID: d.ID, AgencyPartnerID: agency.PartnerID,
			}
			if i, ok := byPartner[d.ClientPartnerID]; ok {
				if slices.Index(s.Levels, level) > slices.Index(s.Levels, out[i].Level) {
					out[i] = tenant
				}
				continue
			}
			byPartner[d.ClientPartnerID] = len(out)
			out = append(out, tenant)
		}
	}
	return out, nil
}

// level is the highest configured level among roles ActiveFor returned
// unexpired.
func (s *TenantResolver) level(roles []model.AgencyRoleGrant) string {
	best := -1
	for _, role := range roles {
		if i := slices.Index(s.Levels, role.Role); i > best {
			best = i
		}
	}
	if best < 0 {
		return ""
	}
	return s.Levels[best]
}

func (s *TenantResolver) cached(caller model.TenantCaller) ([]model.Tenant, bool) {
	if s.CacheTTL <= 0 {
		return nil, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.cache[caller]
	if !ok || !s.now().Before(entry.expires) {
		return nil, false
	}
	return slices.Clone(entry.tenants), true
}

func (s *TenantResolver) store(caller model.TenantCaller, tenants []model.Tenant) {
	if s.CacheTTL <= 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	if len(s.cache) >= tenantCacheEntries {
		for key, entry := range s.cache {
			if !now.Before(entry.expires) {
				delete(s.cache, key)
			}
		}
		if len(s.cache) >= tenantCacheEntries {
			clear(s.cache)
		}
	}
	s.cache[caller] = tenantEntry{tenants: slices.Clone(tenants), expires: now.Add(s.CacheTTL)}
}
