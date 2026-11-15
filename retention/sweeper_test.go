package retention

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/nauticana/keel/model"
)

var now = time.Date(2026, 11, 15, 0, 0, 0, 0, time.UTC)

func surveyTable() *model.TableDefinition {
	id := &model.TableColumn{ColumnName: "id", DataType: model.DT_BIGINT}
	return &model.TableDefinition{TableName: "survey", Keys: []*model.TableColumn{id}, Columns: []*model.TableColumn{
		id, {ColumnName: "created_at", DataType: model.DT_TIME}}}
}

func newRepo(ages ...time.Duration) *fakeRepository {
	f := &fakeRepository{tables: map[string]*model.TableDefinition{"survey": surveyTable()}, rows: map[string][]time.Time{}, fail: map[string]error{}}
	for _, age := range ages {
		f.rows["survey"] = append(f.rows["survey"], now.Add(-age))
	}
	return f
}

func TestSweepDeletesExpiredRowsInBatches(t *testing.T) {
	day := 24 * time.Hour
	repo := newRepo(200*day, 190*day, 181*day, 10*day, 179*day)
	s := &Sweeper{DB: repo, Policies: []Policy{{Table: "survey", AgeColumn: "created_at", Window: 180 * day, Batch: 2}}, Now: func() time.Time { return now }}
	deleted, err := s.Sweep(context.Background())
	if err != nil || deleted["survey"] != 3 || len(repo.rows["survey"]) != 2 {
		t.Fatalf("deleted=%v err=%v left=%d, want 3 deleted and 2 kept", deleted, err, len(repo.rows["survey"]))
	}
	if repo.calls != 2 {
		t.Fatalf("ran %d batches, want 2 (a short batch ends the policy)", repo.calls)
	}
	if sql := repo.queries["survey"]; !strings.Contains(sql, "WHERE (id) IN") || !strings.Contains(sql, "FROM survey WHERE created_at < ? LIMIT ?") {
		t.Fatalf("query = %s", sql)
	}
}

func TestSweepRefusesInvalidPolicies(t *testing.T) {
	for name, p := range map[string]Policy{
		"unknown table":       {Table: "nope", AgeColumn: "created_at", Window: time.Hour},
		"unknown column":      {Table: "survey", AgeColumn: "updated_at", Window: time.Hour},
		"non-time column":     {Table: "survey", AgeColumn: "id", Window: time.Hour},
		"zero window":         {Table: "survey", AgeColumn: "created_at"},
		"negative batch":      {Table: "survey", AgeColumn: "created_at", Window: time.Hour, Batch: -1},
		"injected identifier": {Table: "survey", AgeColumn: "created_at; drop", Window: time.Hour},
		"second policy":       {Table: "survey", AgeColumn: "created_at", Window: time.Hour},
	} {
		repo := newRepo(time.Hour)
		repo.tables["survey"].Columns = append(repo.tables["survey"].Columns, &model.TableColumn{ColumnName: "created_at; drop", DataType: model.DT_TIME})
		s := &Sweeper{DB: repo, Policies: []Policy{p, {Table: "survey", AgeColumn: "created_at", Window: time.Minute}}}
		if _, err := s.Sweep(context.Background()); !errors.Is(err, ErrPolicy) || repo.calls != 0 {
			t.Fatalf("%s: err=%v calls=%d, want ErrPolicy before any delete", name, err, repo.calls)
		}
	}
}

func TestSweepNeedsADatabaseAndATableKey(t *testing.T) {
	policies := []Policy{{Table: "survey", AgeColumn: "created_at", Window: time.Hour}}
	if _, err := (&Sweeper{Policies: policies}).Sweep(context.Background()); !errors.Is(err, ErrPolicy) {
		t.Fatalf("no database: %v, want ErrPolicy", err)
	}
	repo := newRepo(time.Hour)
	repo.tables["survey"].Keys = nil
	if _, err := (&Sweeper{DB: repo, Policies: policies}).Sweep(context.Background()); !errors.Is(err, ErrPolicy) || repo.calls != 0 {
		t.Fatalf("keyless table: err=%v calls=%d, want ErrPolicy before any delete", err, repo.calls)
	}
}

func TestSweepReportsFailureAndContinues(t *testing.T) {
	repo := newRepo(48 * time.Hour)
	leadID := &model.TableColumn{ColumnName: "id", DataType: model.DT_BIGINT}
	repo.tables["lead"] = &model.TableDefinition{TableName: "lead", Keys: []*model.TableColumn{leadID}, Columns: []*model.TableColumn{
		leadID, {ColumnName: "created_at", DataType: model.DT_TIME}}}
	repo.fail["lead"] = errors.New("boom")
	s := &Sweeper{DB: repo, Now: func() time.Time { return now }, Policies: []Policy{
		{Table: "lead", AgeColumn: "created_at", Window: time.Hour},
		{Table: "survey", AgeColumn: "created_at", Window: time.Hour}}}
	deleted, err := s.Sweep(context.Background())
	if err == nil || !strings.Contains(err.Error(), "lead") || deleted["survey"] != 1 {
		t.Fatalf("deleted=%v err=%v, want lead reported and survey swept", deleted, err)
	}
}
