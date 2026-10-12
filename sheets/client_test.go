package sheets

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nauticana/keel/common"
)

const testToken = "ya29.secret-token"

func server(t *testing.T, handle func(w http.ResponseWriter, r *http.Request)) *Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+testToken {
			t.Errorf("authorization = %q", r.Header.Get("Authorization"))
		}
		handle(w, r)
	}))
	t.Cleanup(srv.Close)
	return &Client{BaseURL: srv.URL + "/"}
}

func TestReadEscapesTheRangeAndReturnsRows(t *testing.T) {
	c := server(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.EscapedPath() != "/spreadsheets/S%2F1/values/%27Bob%27%27s%27%21A1:C9" {
			t.Errorf("path = %s", r.URL.EscapedPath())
		}
		if r.URL.Query().Get("valueRenderOption") != "FORMATTED_VALUE" {
			t.Errorf("query = %s", r.URL.RawQuery)
		}
		_, _ = io.WriteString(w, `{"range":"x","values":[["id","name"],["7"]]}`)
	})
	rows, err := c.Read(context.Background(), testToken, "S/1", QuoteSheet("Bob's")+"!A1:C9")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 || rows[0][1] != "name" || len(rows[1]) != 1 {
		t.Fatalf("rows = %v", rows)
	}
}

func TestReadOfAnEmptySheetIsNoRows(t *testing.T) {
	c := server(t, func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, `{"range":"x"}`) })
	rows, err := c.Read(context.Background(), testToken, "S", QuoteSheet("Leads"))
	if err != nil || len(rows) != 0 {
		t.Fatalf("rows %v err %v", rows, err)
	}
}

func TestReadMalformedJSON(t *testing.T) {
	c := server(t, func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, `{"values":[[1,`) })
	if _, err := c.Read(context.Background(), testToken, "S", "A1"); !errors.Is(err, ErrMalformedResponse) {
		t.Fatalf("err = %v", err)
	}
}

func TestProviderStatusIsTypedAndKeepsTheTokenOut(t *testing.T) {
	c := server(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "30")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = io.WriteString(w, `{"error":{"code":429}}`)
	})
	_, err := c.Read(context.Background(), testToken, "S", "A1")
	var se *common.HTTPStatusError
	if !errors.As(err, &se) || !se.RateLimited() || se.Header.Get("Retry-After") != "30" {
		t.Fatalf("err = %v", err)
	}
	if strings.Contains(err.Error(), testToken) {
		t.Fatalf("error leaks the token: %v", err)
	}
}

func TestWriteSendsRawValuesInOneBatch(t *testing.T) {
	var got struct {
		ValueInputOption string `json:"valueInputOption"`
		Data             []struct {
			Range  string     `json:"range"`
			Values [][]string `json:"values"`
		} `json:"data"`
	}
	calls := 0
	c := server(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method != http.MethodPost || r.URL.Path != "/spreadsheets/S/values:batchUpdate" {
			t.Errorf("%s %s", r.Method, r.URL.Path)
		}
		_ = json.NewDecoder(r.Body).Decode(&got)
		_, _ = io.WriteString(w, `{}`)
	})
	err := c.Write(context.Background(), testToken, "S", []Cell{{A1: CellA1("Leads", 2, 7), Value: "=HYPERLINK()"}, {A1: "'Leads'!D7", Value: "x"}})
	if err != nil {
		t.Fatal(err)
	}
	if calls != 1 || got.ValueInputOption != "RAW" || len(got.Data) != 2 || got.Data[0].Range != "'Leads'!C7" || got.Data[0].Values[0][0] != "=HYPERLINK()" {
		t.Fatalf("calls %d body %+v", calls, got)
	}
}

func TestAppendInsertsRows(t *testing.T) {
	var got struct {
		Values [][]string `json:"values"`
	}
	c := server(t, func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/values/'Leads':append") || r.URL.Query().Get("insertDataOption") != "INSERT_ROWS" || r.URL.Query().Get("valueInputOption") != "RAW" {
			t.Errorf("%s ? %s", r.URL.Path, r.URL.RawQuery)
		}
		_ = json.NewDecoder(r.Body).Decode(&got)
		_, _ = io.WriteString(w, `{}`)
	})
	if err := c.Append(context.Background(), testToken, "S", QuoteSheet("Leads"), [][]string{{"1", "a"}, {"2", "b"}}); err != nil {
		t.Fatal(err)
	}
	if len(got.Values) != 2 || got.Values[1][1] != "b" {
		t.Fatalf("values = %v", got.Values)
	}
}

func TestEmptyWritesMakeNoCall(t *testing.T) {
	c := &Client{BaseURL: "http://127.0.0.1:1"}
	if err := c.Write(context.Background(), "", "", nil); err != nil {
		t.Fatal(err)
	}
	if err := c.Append(context.Background(), "", "", "", nil); err != nil {
		t.Fatal(err)
	}
}

func TestBlankArgumentsAreRefusedBeforeAnyCall(t *testing.T) {
	c := &Client{BaseURL: "http://127.0.0.1:1"}
	ctx := context.Background()
	for name, err := range map[string]error{
		"token":  func() error { _, err := c.Read(ctx, " ", "S", "A1"); return err }(),
		"id":     func() error { _, err := c.Read(ctx, testToken, "", "A1"); return err }(),
		"range":  func() error { _, err := c.Read(ctx, testToken, "S", ""); return err }(),
		"cell":   c.Write(ctx, testToken, "S", []Cell{{A1: "A1"}, {A1: ""}}),
		"append": c.Append(ctx, testToken, "S", "", [][]string{{"x"}}),
	} {
		if !errors.Is(err, ErrInvalidArgument) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}

func TestCanceledContextStopsTheCall(t *testing.T) {
	c := server(t, func(w http.ResponseWriter, r *http.Request) { t.Error("request sent after cancel") })
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.Read(ctx, testToken, "S", "A1"); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v", err)
	}
}

func TestZeroClientUsesTheGoogleEndpoint(t *testing.T) {
	if got := (&Client{}).valuesURL("S", "A1"); got != APIBaseURL+"/spreadsheets/S/values/A1" {
		t.Fatalf("got %s", got)
	}
}
