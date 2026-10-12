package pgsql

import (
	"errors"
	"math/big"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
)

func TestNormalizeValue_Numeric(t *testing.T) {
	huge, _ := new(big.Int).SetString("123456789012345678901234567890", 10)
	cases := []struct {
		in   pgtype.Numeric
		want float64
	}{
		{pgtype.Numeric{Int: big.NewInt(350), Exp: -2, Valid: true}, 3.5},
		{pgtype.Numeric{Int: big.NewInt(-411234567), Exp: -7, Valid: true}, -41.1234567},
		{pgtype.Numeric{Int: big.NewInt(12), Exp: 3, Valid: true}, 12000},
		{pgtype.Numeric{Int: big.NewInt(1), Exp: -30, Valid: true}, 1e-30},
		{pgtype.Numeric{Int: huge, Exp: -10, Valid: true}, 12345678901234567890.1234567890},
		{pgtype.Numeric{Valid: true}, 0},
	}
	for _, c := range cases {
		got, err := normalizeValue(c.in)
		if err != nil {
			t.Fatalf("%v: %v", c.in, err)
		}
		f, ok := got.(float64)
		if !ok || f != c.want {
			t.Errorf("%v: got %T %v, want %v", c.in, got, got, c.want)
		}
		// The fast path must agree with an exact decimal parse.
		if c.in.Int != nil {
			exact, _ := strconv.ParseFloat(c.in.Int.String()+"e"+strconv.Itoa(int(c.in.Exp)), 64)
			if f != exact {
				t.Errorf("%v: got %v, exact parse %v", c.in, f, exact)
			}
		}
	}
}

func TestNormalizeValue_NonFiniteNumericRejected(t *testing.T) {
	for _, n := range []pgtype.Numeric{
		{NaN: true, Valid: true},
		{InfinityModifier: pgtype.Infinity, Valid: true},
		{InfinityModifier: pgtype.NegativeInfinity, Valid: true},
	} {
		if _, err := normalizeValue(n); !errors.Is(err, ErrNonFiniteNumeric) {
			t.Errorf("%+v: err = %v, want ErrNonFiniteNumeric", n, err)
		}
	}
}

func TestNormalizeValue_NullWrappersToNil(t *testing.T) {
	for _, v := range []any{pgtype.Numeric{}, pgtype.Time{}} {
		if got, err := normalizeValue(v); got != nil || err != nil {
			t.Errorf("%T: got %v, %v; want nil", v, got, err)
		}
	}
}

func TestNormalizeValue_TimeToString(t *testing.T) {
	tm := pgtype.Time{Microseconds: int64(9*3600+5*60+7) * 1_000_000, Valid: true}
	if got, _ := normalizeValue(tm); got != "09:05:07" {
		t.Errorf("got %v, want 09:05:07", got)
	}
}

func TestNormalizeValue_PassThrough(t *testing.T) {
	when := time.Date(2026, 5, 18, 0, 0, 0, 0, time.UTC)
	for _, c := range []any{"hello", int64(42), 3.14, true, nil, when} {
		if got, err := normalizeValue(c); err != nil || got != c {
			t.Errorf("%T: got %v, %v", c, got, err)
		}
	}
}

func TestScanResult_NormalizesInPlace(t *testing.T) {
	rows := &fakeRows{
		cols: []string{"id", "lat"},
		rows: [][]any{
			{int64(1), pgtype.Numeric{Int: big.NewInt(415), Exp: -1, Valid: true}},
			{int64(2), pgtype.Numeric{}},
		},
	}
	qr, err := scanResult(rows)
	if err != nil {
		t.Fatal(err)
	}
	if len(qr.Columns) != 2 || qr.Columns[1] != "lat" || len(qr.Rows) != 2 {
		t.Fatalf("result = %+v", qr)
	}
	if qr.Rows[0][1] != 41.5 || qr.Rows[1][1] != nil {
		t.Errorf("rows = %v", qr.Rows)
	}
}

func TestScanResult_NonFiniteNamesColumn(t *testing.T) {
	rows := &fakeRows{cols: []string{"id", "rate"}, rows: [][]any{{int64(1), pgtype.Numeric{NaN: true, Valid: true}}}}
	_, err := scanResult(rows)
	if !errors.Is(err, ErrNonFiniteNumeric) || !strings.Contains(err.Error(), "rate") {
		t.Fatalf("err = %v", err)
	}
}
