package common

import (
	"encoding/json"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"strconv"
)

// apiJSON keeps encoding/json's v1 behavior for keel's own API, except that
// the 64-bit integer types (int, int64, uint, uint64) travel as strings: a
// JavaScript client parses a JSON number into a float64 and loses the digits
// of an id above 2^53. Input accepts a string or a number for those types, and
// a number decoded into any is a json.Number. int32 and narrower stay numbers.
var apiJSON = jsonv2.JoinOptions(
	json.DefaultOptionsV1(),
	jsonv2.WithMarshalers(jsonv2.JoinMarshalers(
		marshalInteger(func(v int64) string { return strconv.FormatInt(v, 10) }),
		marshalInteger(func(v int) string { return strconv.Itoa(v) }),
		marshalInteger(func(v uint64) string { return strconv.FormatUint(v, 10) }),
		marshalInteger(func(v uint) string { return strconv.FormatUint(uint64(v), 10) }),
	)),
	jsonv2.WithUnmarshalers(jsonv2.JoinUnmarshalers(
		unmarshalInteger(func(s string) (int64, error) { return strconv.ParseInt(s, 10, 64) }),
		unmarshalInteger(func(s string) (int, error) {
			n, err := strconv.ParseInt(s, 10, strconv.IntSize)
			return int(n), err
		}),
		unmarshalInteger(func(s string) (uint64, error) { return strconv.ParseUint(s, 10, 64) }),
		unmarshalInteger(func(s string) (uint, error) {
			n, err := strconv.ParseUint(s, 10, strconv.IntSize)
			return uint(n), err
		}),
		jsonv2.UnmarshalFromFunc(func(dec *jsontext.Decoder, v *any) error {
			if dec.PeekKind() != '0' {
				return errors.ErrUnsupported
			}
			tok, err := dec.ReadToken()
			if err != nil {
				return err
			}
			*v = json.Number(tok.String())
			return nil
		}),
	)),
)

func marshalInteger[T int | int64 | uint | uint64](format func(T) string) *jsonv2.Marshalers {
	return jsonv2.MarshalToFunc(func(enc *jsontext.Encoder, v T) error {
		return enc.WriteToken(jsontext.String(format(v)))
	})
}

// unmarshalInteger accepts a string or a number; null leaves the value
// unchanged, as encoding/json does.
func unmarshalInteger[T int | int64 | uint | uint64](parse func(string) (T, error)) *jsonv2.Unmarshalers {
	return jsonv2.UnmarshalFromFunc(func(dec *jsontext.Decoder, v *T) error {
		tok, err := dec.ReadToken()
		if err != nil {
			return err
		}
		switch tok.Kind() {
		case 'n':
			return nil
		case '"', '0':
		default:
			return fmt.Errorf("%T expected, got %v", *v, tok.Kind())
		}
		n, err := parse(tok.String())
		if err != nil {
			return fmt.Errorf("%T %q: %w", *v, tok.String(), err)
		}
		*v = n
		return nil
	})
}

// EncodeJSON writes v as keel's API JSON: 64-bit integers as strings.
func EncodeJSON(w io.Writer, v any) error {
	return jsonv2.MarshalWrite(w, v, apiJSON)
}

// MarshalJSON returns v as keel's API JSON.
func MarshalJSON(v any) ([]byte, error) {
	return jsonv2.Marshal(v, apiJSON)
}

// DecodeJSON reads exactly one JSON value from data into v. A 64-bit integer
// accepts a string or a number, and a number decoded into any is a json.Number.
func DecodeJSON(data []byte, v any) error {
	return jsonv2.Unmarshal(data, v, apiJSON)
}

// DecodeStrictJSON is DecodeJSON that also refuses members v does not declare.
func DecodeStrictJSON(data []byte, v any) error {
	return jsonv2.Unmarshal(data, v, apiJSON, jsonv2.RejectUnknownMembers(true))
}
