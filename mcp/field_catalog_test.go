package mcp

import (
	"context"
	"errors"
	"testing"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/model"
)

// catalogQuerier returns canned rows per query name; a single arg filters by
// column 0 (the point-lookup id), mimicking a WHERE id = $1 query.
type catalogQuerier struct {
	rows map[string][][]any
	err  error
}

func (q catalogQuerier) Query(_ context.Context, name string, args ...any) (*model.QueryResult, error) {
	if q.err != nil {
		return nil, q.err
	}
	if len(args) == 1 {
		id := common.AsString(args[0])
		var out [][]any
		for _, r := range q.rows[name] {
			if len(r) > 0 && common.AsString(r[0]) == id {
				out = append(out, r)
			}
		}
		return &model.QueryResult{Rows: out}, nil
	}
	return &model.QueryResult{Rows: q.rows[name]}, nil
}

func (q catalogQuerier) GenID() int64 { return 0 }

func attrCatalog(qs catalogQuerier) *BaseFieldCatalog {
	attrMap := func(row []any) model.FieldDescriptor {
		return model.FieldDescriptor{
			Name:  "attr." + common.AsString(row[0]),
			Kind:  "attribute",
			Label: common.AsString(row[1]),
		}
	}
	return NewFieldCatalog(qs,
		DescriptorProvider{Static: []model.FieldDescriptor{
			{Name: "phone", Kind: "core"},
			{Name: "name", Kind: "core"},
		}},
		DescriptorProvider{Prefix: "attr.", ListQuery: "qAttrs", GetQuery: "qAttr", Map: attrMap},
	)
}

func TestFieldCatalog_ListMergesStaticAndDynamic(t *testing.T) {
	qs := catalogQuerier{rows: map[string][][]any{"qAttrs": {{"wifi", "Wi-Fi"}, {"parking", "Parking"}}}}
	got, err := attrCatalog(qs).ListFields(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 4 {
		t.Fatalf("want 4 fields (2 core + 2 attr), got %d", len(got))
	}
	if got[2].Name != "attr.wifi" || got[2].Kind != "attribute" {
		t.Errorf("unexpected dynamic field: %+v", got[2])
	}
}

func TestFieldCatalog_DescribeCoreByScan(t *testing.T) {
	fd, err := attrCatalog(catalogQuerier{}).DescribeField(context.Background(), "phone")
	if err != nil || fd == nil || fd.Kind != "core" {
		t.Fatalf("want core field phone, got %+v err %v", fd, err)
	}
}

func TestFieldCatalog_DescribePrefixedByPointQuery(t *testing.T) {
	qs := catalogQuerier{rows: map[string][][]any{"qAttr": {{"wifi", "Wi-Fi"}, {"parking", "Parking"}}}}
	fd, err := attrCatalog(qs).DescribeField(context.Background(), "attr.parking")
	if err != nil || fd == nil {
		t.Fatalf("want attr.parking, got %+v err %v", fd, err)
	}
	if fd.Name != "attr.parking" || fd.Label != "Parking" {
		t.Errorf("wrong descriptor: %+v", fd)
	}
}

func TestFieldCatalog_DescribeUnknownReturnsNil(t *testing.T) {
	qs := catalogQuerier{rows: map[string][][]any{"qAttr": {{"wifi", "Wi-Fi"}}}}
	c := attrCatalog(qs)
	if fd, err := c.DescribeField(context.Background(), "attr.missing"); err != nil || fd != nil {
		t.Errorf("unknown attr should be (nil,nil), got %+v err %v", fd, err)
	}
	if fd, err := c.DescribeField(context.Background(), "nope"); err != nil || fd != nil {
		t.Errorf("unknown core should be (nil,nil), got %+v err %v", fd, err)
	}
}

func TestFieldCatalog_ListPropagatesError(t *testing.T) {
	_, err := attrCatalog(catalogQuerier{err: errors.New("db down")}).ListFields(context.Background())
	if err == nil {
		t.Fatal("want error propagated from querier")
	}
}
