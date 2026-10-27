package model

import "testing"

func TestUnsequencedSurrogateKeyIsBigint(t *testing.T) {
	for dataType, want := range map[string]bool{DT_BIGINT: true, DT_INT: false, DT_STRING: false} {
		key := &TableColumn{ColumnName: "id", DataType: dataType}
		if got := (&TableDefinition{Keys: []*TableColumn{key}}).UnsequencedSurrogateKey() != nil; got != want {
			t.Errorf("%s key: %v, want %v", dataType, got, want)
		}
	}
}
