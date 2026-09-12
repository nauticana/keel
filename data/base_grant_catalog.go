package data

import (
	"fmt"
	"regexp"
	"strings"
	"sync"

	"github.com/nauticana/keel/model"
	"github.com/nauticana/keel/port"
)

// QCheckGlobalRole returns 1 row when the caller holds any GlobalRoleIDs role,
// bypassing partner-scoped row filters.
const QCheckGlobalRole = "check_global_role"

const (
	qCheckPermissionPrefix   = "check_permission:"
	qReadAuthorizationPrefix = "read_authorization:"
)

// GlobalRoleIDs names the roles with a cross-partner mandate, and seeds every
// catalog built after it. DefaultGrantCatalog is built at package init, so a
// downstream appending here at boot must set BaseGrantCatalog.GlobalRoles or
// build its own catalog — the append alone comes too late.
var GlobalRoleIDs = []string{
	"SUPER",
	"BUSINESS_ADMIN",
	"SECURITY_ADMIN",
	"SECURITY_OPER",
	"APP_ADMIN",
}

// GrantSource locates one principal kind's role grants. keel generates the
// authorization SQL from it, so no kind can drift from the others. Table must
// carry role_id, begda and endda — that is convention, not a parameter.
type GrantSource struct {
	Table   string   // assignment table, e.g. "user_permission"
	Subject string   // column in Table identifying the principal
	Filters []string // extra equality columns, bound from Principal.Scope in order
}

// Names are spliced into generated SQL, so anything else is rejected.
var sqlIdentifier = regexp.MustCompile(`^[a-z_][a-z0-9_]*$`)

// BaseGrantCatalog is the shipped GrantCatalog: usable as constructed, knowing
// only the human kind. Safe for concurrent use.
type BaseGrantCatalog struct {
	// GlobalRoles gates the partner-scope bypass; empty means nobody bypasses.
	GlobalRoles []string

	mu      sync.RWMutex
	sources map[model.PrincipalKind]GrantSource
}

var _ port.GrantCatalog = (*BaseGrantCatalog)(nil)

// DefaultGrantCatalog is used by any data layer given no catalog of its own.
var DefaultGrantCatalog = NewGrantCatalog()

// NewGrantCatalog returns a catalog holding the human kind and GlobalRoleIDs.
func NewGrantCatalog() *BaseGrantCatalog {
	return &BaseGrantCatalog{
		GlobalRoles: append([]string(nil), GlobalRoleIDs...),
		sources: map[model.PrincipalKind]GrantSource{
			model.PrincipalUser: {Table: "user_permission", Subject: "user_id"},
		},
	}
}

// Register adds where a kind's grants live. Call it at boot: a repository that
// has already built its QueryService does not pick up a later registration.
func (c *BaseGrantCatalog) Register(kind model.PrincipalKind, src GrantSource) error {
	if strings.TrimSpace(string(kind)) == "" {
		return fmt.Errorf("data: principal kind is required")
	}
	if !sqlIdentifier.MatchString(src.Table) {
		return fmt.Errorf("data: principal kind %q: invalid assignment table %q", kind, src.Table)
	}
	if !sqlIdentifier.MatchString(src.Subject) {
		return fmt.Errorf("data: principal kind %q: invalid subject column %q", kind, src.Subject)
	}
	for _, f := range src.Filters {
		if !sqlIdentifier.MatchString(f) {
			return fmt.Errorf("data: principal kind %q: invalid filter column %q", kind, f)
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sources[kind] = GrantSource{Table: src.Table, Subject: src.Subject, Filters: append([]string(nil), src.Filters...)}
	return nil
}

// Source returns the registered source for kind.
func (c *BaseGrantCatalog) Source(kind model.PrincipalKind) (GrantSource, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	src, ok := c.sources[kind]
	src.Filters = append([]string(nil), src.Filters...)
	return src, ok
}

func (c *BaseGrantCatalog) CheckQuery(kind model.PrincipalKind) string {
	return qCheckPermissionPrefix + string(kind)
}

func (c *BaseGrantCatalog) ReadQuery(kind model.PrincipalKind) string {
	return qReadAuthorizationPrefix + string(kind)
}

func (c *BaseGrantCatalog) Queries() map[string]string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make(map[string]string, len(c.sources)*2+1)
	for kind, src := range c.sources {
		out[c.CheckQuery(kind)] = src.checkPermissionSQL()
		out[c.ReadQuery(kind)] = src.readAuthorizationSQL()
	}
	out[QCheckGlobalRole] = globalRoleSQL(c.GlobalRoles, c.sources[model.PrincipalUser])
	return out
}

// Args returns the bind arguments in generated-SQL order: subject, then one per
// filter. An arity mismatch errors, so a misconfigured principal fails closed
// instead of matching another scope's grants.
func (c *BaseGrantCatalog) Args(p model.Principal) ([]any, error) {
	src, ok := c.Source(p.Kind)
	if !ok {
		return nil, fmt.Errorf("data: principal kind %q is not registered", p.Kind)
	}
	if !p.Valid() {
		return nil, fmt.Errorf("data: principal kind %q has no id", p.Kind)
	}
	if len(p.Scope) != len(src.Filters) {
		return nil, fmt.Errorf("data: principal kind %q expects %d scope value(s), got %d", p.Kind, len(src.Filters), len(p.Scope))
	}
	return append([]any{p.ID}, p.Scope...), nil
}

// filterClause renders Filters as AND predicates.
func (src GrantSource) filterClause(alias string) string {
	var b strings.Builder
	for _, f := range src.Filters {
		b.WriteString("\n   AND " + alias + f + " = ?")
	}
	return b.String()
}

func (src GrantSource) checkPermissionSQL() string {
	return `
SELECT a.low_limit, a.high_limit, a.bypass_scope
  FROM ` + src.Table + ` p, authorization_role_permission a
 WHERE p.role_id = a.role_id
   AND p.begda <= CURRENT_TIMESTAMP
   AND (p.endda IS NULL OR p.endda >= CURRENT_TIMESTAMP)
   AND a.is_active IS TRUE
   AND a.authorization_object_id = ?
   AND a.action = ?
   AND p.` + src.Subject + ` = ?` + src.filterClause("p.") + `
   AND (a.low_limit = ? OR a.low_limit = '*')
`
}

func (src GrantSource) readAuthorizationSQL() string {
	return `
SELECT authorization_object_id, action, low_limit, high_limit
  FROM authorization_role_permission
 WHERE role_id IN (
       SELECT role_id
         FROM ` + src.Table + `
        WHERE ` + src.Subject + ` = ?` + src.filterClause("") + `
          AND begda <= CURRENT_TIMESTAMP
          AND (endda IS NULL OR endda >= CURRENT_TIMESTAMP) )
   AND is_active IS TRUE
`
}

// globalRoleSQL inlines the role allowlist: role ids are framework constants,
// and `?` cannot expand to a variable-length IN list portably.
func globalRoleSQL(roles []string, src GrantSource) string {
	if len(roles) == 0 || src.Table == "" {
		return `SELECT 1 WHERE FALSE` // no roles → nobody bypasses
	}
	quoted := make([]string, len(roles))
	for i, r := range roles {
		quoted[i] = "'" + strings.ReplaceAll(r, "'", "''") + "'"
	}
	return `
SELECT 1
  FROM ` + src.Table + `
 WHERE ` + src.Subject + ` = ?
   AND role_id IN (` + strings.Join(quoted, ",") + `)
   AND begda <= CURRENT_TIMESTAMP
   AND (endda IS NULL OR endda >= CURRENT_TIMESTAMP)
 LIMIT 1
`
}
