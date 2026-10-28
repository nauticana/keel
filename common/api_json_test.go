package common

import (
	"bytes"
	"encoding/json"
	"math"
	"strings"
	"testing"
)

type apiRow struct {
	ID      int64    `json:"id"`
	UserID  int      `json:"userId"`
	Opt     *int64   `json:"opt,omitempty"`
	IDs     []int64  `json:"ids"`
	Big     uint64   `json:"big"`
	Small   int32    `json:"small"`
	Amount  float64  `json:"amount"`
	Tagged  int64    `json:"tagged,string"`
	Nil     []string `json:"nil"`
	Unnamed string
}

const above53 = int64(1)<<53 + 1

func TestEncodeJSONWritesWideIntegersAsStrings(t *testing.T) {
	opt := above53
	var buf bytes.Buffer
	err := EncodeJSON(&buf, map[string]any{
		"row":  apiRow{ID: above53, UserID: 7, Opt: &opt, IDs: []int64{above53}, Big: math.MaxUint64, Small: 3, Amount: 1.5, Tagged: 5},
		"rows": []map[string]any{{"user_id": above53, "count": int32(4), "n": json.Number("12")}},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := `{"row":{"id":"9007199254740993","userId":"7","opt":"9007199254740993","ids":["9007199254740993"],"big":"18446744073709551615","small":3,"amount":1.5,"tagged":"5","nil":null,"Unnamed":""},"rows":[{"count":4,"n":12,"user_id":"9007199254740993"}]}`
	if buf.String() != want {
		t.Fatalf("got  %s\nwant %s", buf.String(), want)
	}
}

func TestDecodeJSONReadsWideIntegersExactly(t *testing.T) {
	var r apiRow
	err := DecodeJSON([]byte(`{"id":"9007199254740993","userid":9007199254740993,"opt":"5","ids":["1",2],"big":"18446744073709551615","small":3,"tagged":"6","unnamed":"x"}`), &r)
	if err != nil {
		t.Fatal(err)
	}
	if r.ID != above53 || r.UserID != int(above53) || *r.Opt != 5 || r.IDs[0] != 1 || r.IDs[1] != 2 || r.Big != math.MaxUint64 || r.Small != 3 || r.Tagged != 6 || r.Unnamed != "x" {
		t.Fatalf("%+v", r)
	}
	r = apiRow{ID: 9}
	if err := DecodeJSON([]byte(`{"id":null}`), &r); err != nil || r.ID != 9 {
		t.Fatalf("null must leave the value: %d %v", r.ID, err)
	}
	for _, bad := range []string{`{"id":"1.5"}`, `{"id":1.5}`, `{"id":"x"}`, `{"id":true}`, `{"id":"9223372036854775808"}`, `{"big":"-1"}`, `{"id":1} {}`, `{"id":1`} {
		if err := DecodeJSON([]byte(bad), &r); err == nil {
			t.Errorf("%s must be refused", bad)
		}
	}
}

func TestDecodeJSONKeepsUntypedNumbers(t *testing.T) {
	var v any
	if err := DecodeJSON([]byte(`[{"id":9007199254740993,"f":1.5,"nested":{"n":[2]}},"s"]`), &v); err != nil {
		t.Fatal(err)
	}
	row := v.([]any)[0].(map[string]any)
	if row["id"] != json.Number("9007199254740993") || row["f"] != json.Number("1.5") ||
		row["nested"].(map[string]any)["n"].([]any)[0] != json.Number("2") || v.([]any)[1] != "s" {
		t.Fatalf("%#v", v)
	}
}

func TestDecodeStrictJSONRefusesUnknownMembers(t *testing.T) {
	var r struct {
		ID int64 `json:"id"`
	}
	if err := DecodeStrictJSON([]byte(`{"id":"1"}`), &r); err != nil || r.ID != 1 {
		t.Fatalf("%d %v", r.ID, err)
	}
	if err := DecodeStrictJSON([]byte(`{"id":"1","admin":true}`), &r); err == nil || !strings.Contains(err.Error(), "admin") {
		t.Fatalf("unknown member: %v", err)
	}
}

func TestDecodeJSONRefusesDuplicateNames(t *testing.T) {
	for _, body := range []string{`{"role":"user","role":"admin"}`, `{"a":{"x":1,"x":2}}`} {
		var v map[string]any
		if err := DecodeJSON([]byte(body), &v); err == nil {
			t.Errorf("%s: decoded %v", body, v)
		}
	}
	var r struct {
		ID int64 `json:"id"`
	}
	if err := DecodeStrictJSON([]byte(`{"id":"1","id":"2"}`), &r); err == nil {
		t.Errorf("strict: decoded %d", r.ID)
	}
}
