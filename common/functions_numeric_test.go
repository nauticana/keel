package common

import (
	"encoding/json"
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
	if _, ok := AsInt64OK("7x"); ok {
		t.Error("a non-decimal string must not be ok")
	}
	if got := AsInt64(int16(-1)); got != -1 {
		t.Errorf("AsInt64(int16(-1)) = %d", got)
	}
	if _, ok := AsInt64OK(uint64(math.MaxInt64) + 1); ok {
		t.Error("uint64 above MaxInt64 must not wrap and report ok")
	}
	if _, ok := AsFloat64OK(uint64(math.MaxUint64)); ok {
		t.Error("AsFloat64OK must reject an inexact uint64 conversion")
	}
	if _, ok := AsFloat64OK(int64(1)<<53 + 1); ok {
		t.Error("AsFloat64OK must reject an inexact int64 conversion")
	}
	if got, ok := AsFloat64OK(uint64(1)<<53 + 2); !ok || got != float64(uint64(1)<<53+2) {
		t.Errorf("AsFloat64OK(exact wide uint64) = %v, %v", got, ok)
	}
	for _, n := range []json.Number{"9007199254740993", "18446744073709551615", "-9223372036854775809", "1x"} {
		if _, ok := AsFloat64OK(n); ok {
			t.Errorf("AsFloat64OK(json.Number %s) must be refused", n)
		}
	}
	if got, ok := AsFloat64OK(json.Number("9007199254740994")); !ok || got != 9007199254740994 {
		t.Errorf("AsFloat64OK(exact json.Number) = %v, %v", got, ok)
	}
}

func TestAsInt64OKRefusesLossyFloats(t *testing.T) {
	for _, v := range []any{json.Number("9007199254740993"), "9007199254740993"} {
		if got, ok := AsInt64OK(v); !ok || got != 1<<53+1 {
			t.Errorf("AsInt64OK(%#v) = %d, %v", v, got, ok)
		}
	}
	for _, v := range []any{float64(1 << 53), float64(-(1 << 53)), 1.5, math.NaN(), math.Inf(1), json.Number("1.5"), json.Number("1e3"), "9223372036854775808"} {
		if got, ok := AsInt64OK(v); ok {
			t.Errorf("AsInt64OK(%#v) = %d must not be ok", v, got)
		}
	}
	if got, ok := AsInt64OK(float64(1<<53 - 1)); !ok || got != 1<<53-1 {
		t.Errorf("largest exact float = %d, %v", got, ok)
	}
	if _, ok := AsInt32OK(int64(math.MaxInt32) + 1); ok {
		t.Error("AsInt32OK must refuse a value above MaxInt32 instead of wrapping")
	}
	if got, ok := AsFloat64OK(json.Number("1.5")); !ok || got != 1.5 {
		t.Errorf("AsFloat64OK(json.Number) = %v, %v", got, ok)
	}
}
