package handler

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/idempotency"
	"github.com/nauticana/keel/keeltest"
)

type requestRow struct {
	digest, state, fence string
	response             []byte
}

// requestRows answers the store's queries as the table would, without expiry.
func requestRows() (*idempotency.RequestStore, map[string]*requestRow) {
	rows := map[string]*requestRow{}
	held := func(key, fence any) *requestRow {
		row := rows[key.(string)]
		if row == nil || row.state != "I" || row.fence != fence {
			return nil
		}
		return row
	}
	q := keeltest.NewQueries()
	q.Answer("keel_idempotent_request_claim", func(a []any) [][]any {
		if rows[a[0].(string)] != nil {
			return nil
		}
		rows[a[0].(string)] = &requestRow{digest: a[1].(string), state: "I", fence: a[2].(string)}
		return [][]any{{a[0]}}
	})
	q.Answer("keel_idempotent_request_find", func(a []any) [][]any {
		row := rows[a[0].(string)]
		if row == nil {
			return nil
		}
		var response any
		if row.response != nil {
			response = row.response
		}
		return [][]any{{row.digest, row.state, response}}
	})
	q.Answer("keel_idempotent_request_complete", func(a []any) [][]any {
		row := held(a[1], a[2])
		if row == nil {
			return nil
		}
		row.state, row.response = "C", a[0].([]byte)
		return [][]any{{a[1]}}
	})
	q.Answer("keel_idempotent_request_unknown", func(a []any) [][]any {
		row := held(a[0], a[1])
		if row == nil {
			return nil
		}
		row.state = "U"
		return [][]any{{a[0]}}
	})
	q.Answer("keel_idempotent_request_release", func(a []any) [][]any {
		if held(a[0], a[1]) == nil {
			return nil
		}
		delete(rows, a[0].(string))
		return [][]any{{a[0]}}
	})
	return &idempotency.RequestStore{DB: &keeltest.Database{Queries: q}}, rows
}

func TestIdempotencyHandler(t *testing.T) {
	store, _ := requestRows()
	h := &IdempotencyHandler{UserService: wsUsers{}, Requests: store}
	runs, status, response := 0, http.StatusCreated, "made"
	var reenter func()
	route := h.Wrap(map[string]func(http.ResponseWriter, *http.Request){"/api/x": func(w http.ResponseWriter, r *http.Request) {
		runs++
		if body, _ := io.ReadAll(r.Body); string(body) == "panic" {
			panic("boom")
		}
		if reenter != nil {
			reenter()
		}
		w.Header().Set("Location", "/x/1")
		w.Header().Set("Set-Cookie", "s=1")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(response))
	}})["/api/x"]
	send := func(ctx context.Context, method, path, body string, keys ...string) *httptest.ResponseRecorder {
		r := httptest.NewRequestWithContext(ctx, method, path, strings.NewReader(body))
		if ctx == context.Background() {
			r.Header.Set("Authorization", "Bearer ok")
		}
		r.Header["Idempotency-Key"] = keys
		w := httptest.NewRecorder()
		route(w, r)
		return w
	}
	bg := context.Background()
	want := func(name string, w *httptest.ResponseRecorder, code, ranTotal int, replayed bool) {
		t.Helper()
		if w.Code != code || runs != ranTotal || (w.Header().Get(IdempotencyReplayedHeader) == "true") != replayed {
			t.Fatalf("%s: status=%d runs=%d headers=%v body=%s", name, w.Code, runs, w.Header(), w.Body)
		}
	}

	want("first", send(bg, "POST", "/api/x", "a", "k1"), 201, 1, false)
	w := send(bg, "POST", "/api/x", "a", `"k1"`)
	want("replay", w, 201, 1, true)
	if w.Body.String() != "made" || w.Header().Get("Location") != "/x/1" || w.Header().Get("Set-Cookie") != "" {
		t.Fatalf("replayed %v %s", w.Header(), w.Body)
	}
	w = send(bg, "POST", "/api/x", "b", "k1")
	want("other body", w, 422, 1, false)
	if !strings.Contains(w.Body.String(), "idempotency_key_reused") {
		t.Fatal(w.Body)
	}
	want("other route", send(bg, "POST", "/api/x?id=2", "a", "k1"), 201, 2, false)
	key := context.WithValue(context.WithValue(bg, common.ApiKeyID, int64(9)), common.PartnerID, int64(3))
	want("other caller", send(key, "POST", "/api/x", "a", "k1"), 201, 3, false)
	want("other partner", send(context.WithValue(key, common.PartnerID, int64(4)), "POST", "/api/x", "a", "k1"), 201, 4, false)
	want("no caller", send(context.WithValue(bg, common.Scopes, "x"), "POST", "/api/x", "a", "k1"), 401, 4, false)
	want("no key", send(bg, "POST", "/api/x", "a"), 201, 5, false)
	want("safe method", send(bg, "GET", "/api/x", "", "k1"), 201, 6, false)
	for _, bad := range [][]string{{""}, {`""`}, {"a b"}, {"a,b"}, {"a", "b"}, {strings.Repeat("a", 256)}} {
		want("bad key", send(bg, "POST", "/api/x", "a", bad...), 400, 6, false)
	}

	reenter = func() {
		reenter = nil
		want("concurrent", send(bg, "POST", "/api/x", "a", "k2"), 409, 7, false)
	}
	want("holder", send(bg, "POST", "/api/x", "a", "k2"), 201, 7, false)

	for i, refused := range []int{401, 403, 429} {
		status = refused
		want("refused", send(bg, "POST", "/api/x", "a", "k3"), refused, 8+i, false)
	}
	status = 503
	want("server error", send(bg, "POST", "/api/x", "a", "k3"), 503, 11, false)
	want("server error replay", send(bg, "POST", "/api/x", "a", "k3"), 503, 11, true)

	status, response = 200, strings.Repeat("x", maxReplayBody+1)
	w = send(bg, "POST", "/api/x", "a", "k4")
	want("large", w, 200, 12, false)
	if w.Body.Len() != maxReplayBody+1 {
		t.Fatalf("large body cut to %d", w.Body.Len())
	}
	want("large retry", send(bg, "POST", "/api/x", "a", "k4"), 409, 12, false)

	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("panic swallowed")
			}
		}()
		send(bg, "POST", "/api/x", "panic", "k5")
	}()
	w = send(bg, "POST", "/api/x", "panic", "k5")
	want("after panic", w, 409, 13, false)
	if !strings.Contains(w.Body.String(), "idempotency_outcome_unknown") {
		t.Fatal(w.Body)
	}
	if w := send(bg, "POST", "/api/x", string(bytes.Repeat([]byte("a"), 64<<20)), "k6"); w.Code != 413 {
		t.Fatalf("oversize body: %d", w.Code)
	}
	h.Requests = nil
	if w := send(bg, "POST", "/api/x", "a", "k7"); w.Code != 500 || runs != 13 {
		t.Fatalf("without a store: %d runs=%d", w.Code, runs)
	}
}
