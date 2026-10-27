package data

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/nauticana/keel/model"
)

func TestExtractValueBindsJSONExactly(t *testing.T) {
	var s AbstractTableService
	id := &model.TableColumn{ColumnName: "user_id", PascalName: "UserId", DataType: model.DT_BIGINT}
	qty := &model.TableColumn{ColumnName: "qty", PascalName: "Qty", DataType: model.DT_INT}
	price := &model.TableColumn{ColumnName: "price", PascalName: "Price", DataType: model.DT_FLOAT}
	note := &model.TableColumn{ColumnName: "note", PascalName: "Note", DataType: model.DT_STRING}
	for _, tc := range []struct {
		col  *model.TableColumn
		in   any
		want any
	}{
		{id, "9007199254740993", int64(9007199254740993)},
		{id, json.Number("9007199254740993"), int64(9007199254740993)},
		{id, "", nil},
		{id, int64(4), int64(4)},
		{qty, json.Number("12"), int64(12)},
		{price, json.Number("0.1"), "0.1"},
		{note, json.Number("42"), "42"},
		{note, "", ""},
		{id, float64(42), int64(42)},
		{id, nil, nil},
	} {
		got, err := s.ExtractValue(map[string]any{tc.col.ColumnName: tc.in}, tc.col)
		if err != nil || got != tc.want {
			t.Errorf("%s %#v = %#v, %v; want %#v", tc.col.ColumnName, tc.in, got, err, tc.want)
		}
	}
	for _, bad := range []any{"abc", json.Number("1.5"), "9223372036854775808", float64(1.5), float64(1 << 54)} {
		var appErr *model.AppError
		if _, err := s.ExtractValue(map[string]any{"user_id": bad}, id); !errors.As(err, &appErr) || appErr.Status != 400 {
			t.Errorf("%#v: %v, want a 400", bad, err)
		}
	}
	seven := int64(7)
	for _, item := range []any{struct{ UserId int64 }{7}, struct{ UserId *int64 }{&seven}} {
		if got, err := s.ExtractValue(item, id); err != nil || got == nil {
			t.Errorf("struct field %#v = %#v, %v", item, got, err)
		}
	}
	if _, err := s.ExtractValue(struct{ UserId *int64 }{}, id); err != nil {
		t.Errorf("nil pointer field: %v", err)
	}
}
