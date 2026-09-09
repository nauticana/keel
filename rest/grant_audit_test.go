package rest

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/nauticana/keel/logger"
	"github.com/nauticana/keel/model"
	"github.com/nauticana/keel/port"
)

type auditLogger struct {
	logger.ApplicationLogger
	warnings []string
}

func (l *auditLogger) Warning(s string) { l.warnings = append(l.warnings, s) }

var _ logger.ApplicationLogger = (*auditLogger)(nil)

type auditQuery struct {
	port.QueryService
	rows  [][]any
	err   error
	calls int
}

func (q *auditQuery) Query(_ context.Context, name string, _ ...any) (*model.QueryResult, error) {
	q.calls++
	if name != qTableGrants {
		return nil, errors.New("unexpected query")
	}
	return &model.QueryResult{Rows: q.rows}, q.err
}

var _ port.QueryService = (*auditQuery)(nil)

type auditTable struct {
	port.TableService
	name string
}

func (t auditTable) GetTable() *model.TableDefinition {
	return &model.TableDefinition{TableName: t.name}
}

var _ port.TableService = auditTable{}

func TestGrantAudit(t *testing.T) {
	for _, tc := range []struct {
		name     string
		grants   [][]any
		warnings int
	}{
		{"missing master grant", [][]any{{"child"}, {"unexposed"}}, 2},
		{"wildcard", [][]any{{"*"}, {"unexposed"}}, 1},
		{"master and nested grants", [][]any{{"master"}, {"child"}, {"grandchild"}}, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			journal := &auditLogger{}
			qs := &auditQuery{rows: tc.grants}
			svc := &RestService{Journal: journal, qs: qs, RestApis: map[string]*RestAPI{"root": {APIName: "root", Relations: RelationAPI{DataService: auditTable{name: "master"}, ChildServices: map[string]RelationAPI{"child": {DataService: auditTable{name: "child"}, ChildServices: map[string]RelationAPI{"grandchild": {DataService: auditTable{name: "grandchild"}}}}}}}}}
			if err := svc.auditGrants(context.Background()); err != nil {
				t.Fatal(err)
			}
			if len(journal.warnings) != tc.warnings {
				t.Fatalf("warnings=%v", journal.warnings)
			}
			for _, w := range journal.warnings {
				if strings.Contains(w, "child") {
					t.Errorf("nested table incorrectly warned: %s", w)
				}
			}
		})
	}
}
func TestGrantAuditDisabled(t *testing.T) {
	q := &auditQuery{}
	s := &RestService{qs: q}
	if err := s.auditGrants(context.Background()); err != nil || q.calls != 0 {
		t.Fatalf("calls=%d err=%v", q.calls, err)
	}
}

type auditInitDB struct {
	port.DatabaseRepository
	qs port.QueryService
}

func (d auditInitDB) GetQueryService(context.Context, map[string]string) port.QueryService {
	return d.qs
}

func (d auditInitDB) GetTableDefinitions() map[string]*model.TableDefinition { return nil }

var _ port.DatabaseRepository = auditInitDB{}

type auditInitQuery struct{ port.QueryService }

func (auditInitQuery) Query(_ context.Context, name string, _ ...any) (*model.QueryResult, error) {
	if name == qTableGrants {
		return nil, errors.New("audit unavailable")
	}
	return &model.QueryResult{}, nil
}

var _ port.QueryService = auditInitQuery{}

func TestGrantAuditFailureDoesNotPreventInit(t *testing.T) {
	journal := &auditLogger{}
	s := &RestService{Journal: journal}
	if _, _, err := s.Init(context.Background(), auditInitDB{qs: auditInitQuery{}}); err != nil {
		t.Fatal(err)
	}
	if len(journal.warnings) != 1 || !strings.Contains(journal.warnings[0], "audit unavailable") {
		t.Fatalf("audit failure not reported: %v", journal.warnings)
	}
}
