package pgsql

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/nauticana/keel/data"
	"github.com/nauticana/keel/model"
)

// errSentinel short-circuits the data-layer Query / Exec call so the
// rest of Get / Delete doesn't try to scan or commit. Tests only care
// about the SQL string + args fed to the driver, not the result.
var errSentinel = errors.New("sentinel: pgxQuerier short-circuit")

// captureQuerier records the SQL string and args of the last Query /
// Exec / QueryRow call. The driver methods return errSentinel so the
// surrounding TableServicePgsql call exits before touching pgx.Rows
// internals — keeping the test pure-Go with no real DB or pgx-Row stub
// machinery.
type captureQuerier struct {
	sql  string
	args []any
}

func (q *captureQuerier) Exec(_ context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	q.sql = sql
	q.args = args
	return pgconn.CommandTag{}, errSentinel
}
func (q *captureQuerier) Query(_ context.Context, sql string, args ...any) (pgx.Rows, error) {
	q.sql = sql
	q.args = args
	return nil, errSentinel
}
func (q *captureQuerier) QueryRow(_ context.Context, sql string, args ...any) pgx.Row {
	q.sql = sql
	q.args = args
	return nil
}

// stubAuthQuery satisfies data.QueryService for the two queries the
// TableServicePgsql calls: QCheckAuthorization (CheckPermission) and
// QCheckGlobalRole (IsGlobalRole). Each instance is configured per-test
// with the rows it should return for either lookup.
type stubAuthQuery struct {
	permRows   [][]any // result for QCheckAuthorization
	globalRows [][]any // result for QCheckGlobalRole — 1 row = global; 0 rows = not global
}

func (s *stubAuthQuery) GenID() int64 { return 0 }
func (s *stubAuthQuery) Query(_ context.Context, queryName string, _ ...any) (*model.QueryResult, error) {
	switch queryName {
	case data.QCheckAuthorization:
		return &model.QueryResult{Rows: s.permRows}, nil
	case data.QCheckGlobalRole:
		return &model.QueryResult{Rows: s.globalRows}, nil
	}
	return &model.QueryResult{}, nil
}

// userAccountTable builds the minimal *model.TableDefinition needed to
// drive TableServicePgsql.Get / Delete in this test file. Mirrors the
// shape AbstractRepository.Init would produce for the real user_account
// table (id PK + the columns the SELECT enumerates).
func userAccountTable(partnerUserScoped bool) *model.TableDefinition {
	idCol := &model.TableColumn{ColumnName: "id", PascalName: "Id", IsKey: true}
	emailCol := &model.TableColumn{ColumnName: "email", PascalName: "Email"}
	nameCol := &model.TableColumn{ColumnName: "first_name", PascalName: "FirstName"}
	return &model.TableDefinition{
		TableName:         "user_account",
		Columns:           []*model.TableColumn{idCol, emailCol, nameCol},
		Keys:              []*model.TableColumn{idCol},
		PartnerUserScoped: partnerUserScoped,
	}
}

// newService constructs an initialised TableServicePgsql against the
// capture / stub doubles so the test can inspect the SQL it would emit.
func newService(t *testing.T, table *model.TableDefinition, auth *stubAuthQuery) (*TableServicePgsql, *captureQuerier) {
	t.Helper()
	qc := &captureQuerier{}
	s := &TableServicePgsql{
		AbstractTableService: data.AbstractTableService{
			Table:     table,
			AuthQuery: auth,
		},
		Client: qc,
		Schema: "public",
	}
	if err := s.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}
	return s, qc
}

// wildcardSelectGrant returns the [low_limit, high_limit] row a SUPER
// (or any wildcard-grant) holder would have in user_permission ×
// authorization_role_permission for TABLE SELECT user_account.
func wildcardSelectGrant() [][]any {
	return [][]any{{"*", ""}}
}

// explicitSelectGrant returns the per-table-grant row a PARTNER_ADMIN
// holds for TABLE SELECT user_account (low_limit = table name).
func explicitSelectGrant() [][]any {
	return [][]any{{"user_account", ""}}
}

// TestGet_PartnerAdmin_InjectsPartnerUserScope verifies that a Get
// against the user_account table by a partner-scoped role appends the
// `id IN (SELECT user_id FROM partner_user WHERE partner_id = $N)`
// subquery to the WHERE clause. This is the core of A1 — without it
// PARTNER_ADMIN can enumerate every user globally via the /list
// endpoint despite the menu surface being closed.
func TestGet_PartnerAdmin_InjectsPartnerUserScope(t *testing.T) {
	auth := &stubAuthQuery{
		permRows:   explicitSelectGrant(),
		globalRows: nil, // not a global role
	}
	s, qc := newService(t, userAccountTable(true), auth)

	const partnerID int64 = 42
	const userID = 7
	if _, err := s.Get(context.Background(), partnerID, userID, nil, ""); !errors.Is(err, errSentinel) {
		t.Fatalf("Get returned %v, want sentinel", err)
	}
	if !strings.Contains(qc.sql, "partner_user") {
		t.Fatalf("expected partner_user subquery in SQL, got:\n%s", qc.sql)
	}
	if !strings.Contains(qc.sql, `"id" IN (SELECT user_id FROM "partner_user" WHERE partner_id = $1)`) {
		t.Fatalf("expected id-IN subquery in SQL, got:\n%s", qc.sql)
	}
	if len(qc.args) != 1 || qc.args[0] != partnerID {
		t.Fatalf("expected one arg = %d (partner id), got args=%v", partnerID, qc.args)
	}
}

// TestGet_SuperUser_BypassesPartnerUserScope verifies that a Get by a
// caller whose role is in GlobalRoleIDs reads every user_account row
// without the partner_user filter — SUPER and BUSINESS_ADMIN manage
// cross-partner data legitimately.
func TestGet_SuperUser_BypassesPartnerUserScope(t *testing.T) {
	auth := &stubAuthQuery{
		permRows:   wildcardSelectGrant(),
		globalRows: [][]any{{1}}, // present in global role set
	}
	s, qc := newService(t, userAccountTable(true), auth)

	if _, err := s.Get(context.Background(), 42, 1, nil, ""); !errors.Is(err, errSentinel) {
		t.Fatalf("Get returned %v, want sentinel", err)
	}
	if strings.Contains(qc.sql, "partner_user") {
		t.Fatalf("did not expect partner_user subquery for global role, got:\n%s", qc.sql)
	}
	if len(qc.args) != 0 {
		t.Fatalf("expected no args (no scope), got args=%v", qc.args)
	}
}

// TestGet_ByID_PartnerAdmin_InjectsScope verifies the by-PK fast path
// also carries the scope — preventing a PARTNER_ADMIN who knows a
// user_id from another partner from round-tripping that row via the
// /{id} endpoint.
func TestGet_ByID_PartnerAdmin_InjectsScope(t *testing.T) {
	auth := &stubAuthQuery{
		permRows:   explicitSelectGrant(),
		globalRows: nil,
	}
	s, qc := newService(t, userAccountTable(true), auth)

	const partnerID int64 = 42
	const targetID = 999
	where := map[string]any{"id": targetID}
	if _, err := s.Get(context.Background(), partnerID, 7, where, ""); !errors.Is(err, errSentinel) {
		t.Fatalf("Get returned %v, want sentinel", err)
	}
	if !strings.Contains(qc.sql, "partner_user") {
		t.Fatalf("expected partner_user subquery on by-key path, got:\n%s", qc.sql)
	}
	// args[0] = id, args[1] = partner_id appended by the scope branch.
	if len(qc.args) != 2 {
		t.Fatalf("expected 2 args (id + partner_id), got %d: %v", len(qc.args), qc.args)
	}
	if qc.args[0] != targetID || qc.args[1] != partnerID {
		t.Fatalf("args=%v, want [id=%d, partner=%d]", qc.args, targetID, partnerID)
	}
}

// TestGet_NonScopedTable_NoSubquery verifies the new branch is gated on
// the PartnerUserScoped flag — a table without it (the common case)
// should never see partner_user appended.
func TestGet_NonScopedTable_NoSubquery(t *testing.T) {
	auth := &stubAuthQuery{
		permRows:   explicitSelectGrant(),
		globalRows: nil,
	}
	s, qc := newService(t, userAccountTable(false), auth)

	if _, err := s.Get(context.Background(), 42, 7, nil, ""); !errors.Is(err, errSentinel) {
		t.Fatalf("Get returned %v, want sentinel", err)
	}
	if strings.Contains(qc.sql, "partner_user") {
		t.Fatalf("did not expect partner_user subquery on unscoped table, got:\n%s", qc.sql)
	}
}

// TestDelete_PartnerAdmin_InjectsPartnerUserScope verifies defence-in-depth
// — the same gate applied to Get also fires on Delete so a crafted DELETE
// with a known foreign-partner user_id is rejected by the SQL itself.
func TestDelete_PartnerAdmin_InjectsPartnerUserScope(t *testing.T) {
	auth := &stubAuthQuery{
		permRows:   explicitSelectGrant(), // DELETE check uses same query template
		globalRows: nil,
	}
	s, qc := newService(t, userAccountTable(true), auth)

	const partnerID int64 = 42
	where := map[string]any{"id": 999}
	if err := s.Delete(context.Background(), partnerID, 7, where); !errors.Is(err, errSentinel) {
		t.Fatalf("Delete returned %v, want sentinel", err)
	}
	if !strings.Contains(qc.sql, "partner_user") {
		t.Fatalf("expected partner_user subquery on Delete, got:\n%s", qc.sql)
	}
}

// TestIsGlobalRole_QueryShape verifies that QCheckGlobalRole's SQL
// embeds the configured role-id allowlist as inlined literals. The
// query is built once at package init from data.GlobalRoleIDs; this
// asserts the wiring rather than re-testing buildGlobalRoleQuery (which
// has its own unit test next door).
func TestIsGlobalRole_QueryShape(t *testing.T) {
	sql, ok := data.AuthorizationQueries[data.QCheckGlobalRole]
	if !ok {
		t.Fatal("QCheckGlobalRole missing from AuthorizationQueries")
	}
	for _, role := range data.GlobalRoleIDs {
		if !strings.Contains(sql, "'"+role+"'") {
			t.Errorf("expected %q in QCheckGlobalRole SQL:\n%s", role, sql)
		}
	}
}
