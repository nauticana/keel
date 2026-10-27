package model

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"
)

var (
	ErrRowOutOfRange = errors.New("row out of range")
	ErrNullValue     = errors.New("null value")
	ErrCoercion      = errors.New("value cannot be converted")
)

// Coerce converts a query value to T: int64, int32, int, float64, bool, string,
// time.Time, []byte, any, or a pointer to one, where NULL is nil. NULL into a
// non-pointer is ErrNullValue; a fractional float into an integer, an integer
// overflow or an unconvertible type is ErrCoercion.
func Coerce[T any](v any) (T, error) {
	var out T
	if v == nil {
		switch any(&out).(type) {
		case *any, **any, **int64, **int32, **int, **float64, **bool, **string, **time.Time, **[]byte:
			return out, nil
		}
		return out, ErrNullValue
	}
	ok := true
	var err error
	switch p := any(&out).(type) {
	case *int64:
		*p, ok = Int64Of(v)
	case *string:
		*p, ok = StringOf(v)
	case *time.Time:
		*p, ok = TimeOf(v)
	case *int32:
		var n int64
		if n, ok = Int64Of(v); ok && n >= math.MinInt32 && n <= math.MaxInt32 {
			*p = int32(n)
		} else {
			ok = false
		}
	case *int:
		var n int64
		if n, ok = Int64Of(v); ok && n >= math.MinInt && n <= math.MaxInt {
			*p = int(n)
		} else {
			ok = false
		}
	case *float64:
		*p, ok = Float64Of(v)
	case *bool:
		*p, ok = BoolOf(v)
	case *[]byte:
		switch b := v.(type) {
		case []byte:
			*p = b
		case string:
			*p = []byte(b)
		default:
			ok = false
		}
	case *any:
		*p = v
	case **int64:
		*p, err = coercePtr[int64](v)
	case **int32:
		*p, err = coercePtr[int32](v)
	case **int:
		*p, err = coercePtr[int](v)
	case **float64:
		*p, err = coercePtr[float64](v)
	case **bool:
		*p, err = coercePtr[bool](v)
	case **string:
		*p, err = coercePtr[string](v)
	case **time.Time:
		*p, err = coercePtr[time.Time](v)
	case **[]byte:
		*p, err = coercePtr[[]byte](v)
	case **any:
		*p, err = coercePtr[any](v)
	default:
		ok = false
	}
	if err != nil {
		var zero T
		return zero, err
	}
	if !ok {
		var zero T
		return zero, fmt.Errorf("%w: %T into %T", ErrCoercion, v, out)
	}
	return out, nil
}

func coercePtr[E any](v any) (*E, error) {
	if v == nil {
		return nil, nil
	}
	e, err := Coerce[E](v)
	if err != nil {
		return nil, err
	}
	return &e, nil
}

// Int64Of converts any integer width, a decimal string or json.Number exactly,
// and a float only when it is a whole number below 2^53, since a larger one
// has already lost digits.
func Int64Of(v any) (int64, bool) {
	switch n := v.(type) {
	case int:
		return int64(n), true
	case int8:
		return int64(n), true
	case int16:
		return int64(n), true
	case int32:
		return int64(n), true
	case int64:
		return n, true
	case uint:
		return int64(n), uint64(n) <= math.MaxInt64
	case uint8:
		return int64(n), true
	case uint16:
		return int64(n), true
	case uint32:
		return int64(n), true
	case uint64:
		return int64(n), n <= math.MaxInt64
	case string:
		i, err := strconv.ParseInt(n, 10, 64)
		return i, err == nil
	case json.Number:
		i, err := strconv.ParseInt(string(n), 10, 64)
		return i, err == nil
	case float64:
		return exactInt64(n)
	case float32:
		return exactInt64(float64(n))
	}
	return 0, false
}

func exactInt64(f float64) (int64, bool) {
	if f != math.Trunc(f) || math.Abs(f) >= 1<<53 {
		return 0, false
	}
	return int64(f), true
}

// Float64Of converts a float, a json.Number, or an integer a float64 holds exactly.
func Float64Of(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case float32:
		return float64(n), true
	case uint64:
		f := float64(n)
		return f, f < math.Exp2(64) && uint64(f) == n
	case uint:
		return Float64Of(uint64(n))
	case json.Number:
		if !strings.ContainsAny(string(n), ".eE") {
			if i, err := n.Int64(); err == nil {
				return Float64Of(i)
			}
			if u, err := strconv.ParseUint(string(n), 10, 64); err == nil {
				return Float64Of(u)
			}
			return 0, false
		}
		f, err := n.Float64()
		return f, err == nil
	case string:
		return 0, false
	}
	if i, ok := Int64Of(v); ok {
		f := float64(i)
		return f, f >= -math.Exp2(63) && f < math.Exp2(63) && int64(f) == i
	}
	return 0, false
}

// BoolOf converts a bool, an integer (non-zero is true), or "1", "true", "0", "false".
func BoolOf(v any) (bool, bool) {
	switch b := v.(type) {
	case bool:
		return b, true
	case int:
		return b != 0, true
	case int8:
		return b != 0, true
	case int16:
		return b != 0, true
	case int32:
		return b != 0, true
	case int64:
		return b != 0, true
	case uint:
		return b != 0, true
	case uint8:
		return b != 0, true
	case uint16:
		return b != 0, true
	case uint32:
		return b != 0, true
	case uint64:
		return b != 0, true
	case string:
		return boolText(b)
	case []byte:
		return boolText(string(b))
	}
	return false, false
}

func boolText(s string) (bool, bool) {
	switch s {
	case "1", "true":
		return true, true
	case "0", "false":
		return false, true
	}
	return false, false
}

// StringOf converts any non-nil value: []byte as text, time.Time as RFC 3339 UTC,
// anything else through fmt.
func StringOf(v any) (string, bool) {
	switch s := v.(type) {
	case nil:
		return "", false
	case string:
		return s, true
	case []byte:
		return string(s), true
	case time.Time:
		return s.UTC().Format(time.RFC3339), true
	}
	return fmt.Sprintf("%v", v), true
}

// TimeOf converts a time.Time, or a string in RFC 3339 or "2006-01-02 15:04:05".
func TimeOf(v any) (time.Time, bool) {
	switch t := v.(type) {
	case time.Time:
		return t, true
	case string:
		if p, err := time.Parse(time.RFC3339, t); err == nil {
			return p, true
		}
		if p, err := time.Parse("2006-01-02 15:04:05", t); err == nil {
			return p, true
		}
	}
	return time.Time{}, false
}
