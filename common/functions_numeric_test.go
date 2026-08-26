package common

import (
	"math"
	"testing"
)

func TestAsInt64OK_AllIntegerWidths(t *testing.T) {
	cases := []any{int(7), int8(7), int16(7), int32(7), int64(7), uint(7), uint8(7), uint16(7), uint32(7), uint64(7), float32(7), float64(7)}
	for _, v := range cases {
		got, ok := AsInt64OK(v)
		if !ok || got != 7 {
			t.Errorf("AsInt64OK(%T) = %d, %v", v, got, ok)
		}
		if got, ok := AsInt32OK(v); !ok || got != 7 {
			t.Errorf("AsInt32OK(%T) = %d, %v", v, got, ok)
		}
		if got, ok := AsFloat64OK(v); !ok || got != 7 {
			t.Errorf("AsFloat64OK(%T) = %v, %v", v, got, ok)
		}
	}
	if _, ok := AsInt64OK(nil); ok {
		t.Error("nil must not be ok")
	}
	if _, ok := AsInt64OK("7"); ok {
		t.Error("string must not be ok")
	}
	if got := AsInt64(int16(-1)); got != -1 {
		t.Errorf("AsInt64(int16(-1)) = %d", got)
	}
	if _, ok := AsInt64OK(uint64(math.MaxInt64) + 1); ok {
		t.Error("uint64 above MaxInt64 must not wrap and report ok")
	}
	if got, ok := AsFloat64OK(uint64(math.MaxInt64) + 1); !ok || got <= 0 {
		t.Errorf("AsFloat64OK(large uint64) = %v, %v; want positive, true", got, ok)
	}
}
