package rest

import (
	"bytes"
	"context"
	"log"
	"strings"
	"testing"

	"github.com/nauticana/keel/model"
	"github.com/nauticana/keel/port"
)

type staleLookupDB struct{ port.DatabaseRepository }

func (staleLookupDB) GetForeignKey(string) *model.ForeignKey { return nil }

type lookupRowsQS struct{}

func (lookupRowsQS) Query(context.Context, string, ...any) (*model.QueryResult, error) {
	return &model.QueryResult{Rows: [][]any{{"dropped_fk", "D", "caption"}}}, nil
}
func (lookupRowsQS) GenID() int64 { return 0 }

func TestGetTableCache_SkipsUnknownConstraint(t *testing.T) {
	var logs bytes.Buffer
	previousOutput := log.Writer()
	previousFlags := log.Flags()
	previousPrefix := log.Prefix()
	log.SetOutput(&logs)
	log.SetFlags(0)
	log.SetPrefix("")
	t.Cleanup(func() {
		log.SetOutput(previousOutput)
		log.SetFlags(previousFlags)
		log.SetPrefix(previousPrefix)
	})

	s := &RestService{db: staleLookupDB{}, qs: lookupRowsQS{}}
	cache, err := s.GetTableCache(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(cache) != 0 {
		t.Fatalf("cache = %v, want empty", cache)
	}
	if got := logs.String(); !strings.Contains(got, "unknown constraint dropped_fk") {
		t.Fatalf("warning log = %q", got)
	}
}
