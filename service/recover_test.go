package service

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/config"
	"github.com/nauticana/keel/logger"
)

type errorJournal struct {
	logger.ApplicationLogger
	errors []string
}

func (j *errorJournal) Error(msg string) { j.errors = append(j.errors, msg) }
func (j *errorJournal) Access(string)    {}

// A panicking handler is answered through the full chain: a 500 problem with
// the request id and CORS headers, and the connection stays usable.
func TestHttpBackend_PanicIsAnswered(t *testing.T) {
	const app = "https://app.example.com"
	journal := &errorJournal{}
	h := &HttpBackend{Origin: app, Journal: journal}
	h.Handle(map[string]func(http.ResponseWriter, *http.Request){
		common.PublicPrefix + "/boom": func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/plain")
			panic("handler wiring bug")
		},
		common.PublicPrefix + "/ok": func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) },
	})
	srv := httptest.NewServer(h.handler)
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodGet, srv.URL+common.PublicPrefix+"/boom", nil)
	req.Header.Set("Origin", app)
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("connection dropped: %v", err)
	}
	var problem common.ProblemDetail
	if err := json.NewDecoder(resp.Body).Decode(&problem); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError || problem.Status != http.StatusInternalServerError {
		t.Fatalf("status = %d, problem = %+v", resp.StatusCode, problem)
	}
	if resp.Header.Get("Access-Control-Allow-Origin") != app {
		t.Fatalf("CORS header missing: %v", resp.Header)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/problem+json" {
		t.Fatalf("Content-Type = %q", ct)
	}
	if problem.RequestID == "" || problem.Detail != common.InternalErrorDetail || strings.Contains(problem.Detail, "wiring") {
		t.Fatalf("problem = %+v", problem)
	}
	if header := config.Config().RequestIDHeader; header != "" && resp.Header.Get(header) != problem.RequestID {
		t.Fatalf("request id %q, header %q", problem.RequestID, resp.Header.Get(header))
	}
	var panicLines []string
	for _, line := range journal.errors {
		if strings.Contains(line, "handler wiring bug") {
			panicLines = append(panicLines, line)
		}
	}
	if len(panicLines) != 1 || !strings.Contains(panicLines[0], "goroutine") || !strings.Contains(panicLines[0], problem.RequestID) {
		t.Fatalf("journal = %q", journal.errors)
	}

	next, err := srv.Client().Get(srv.URL + common.PublicPrefix + "/ok")
	if err != nil || next.StatusCode != http.StatusNoContent {
		t.Fatalf("request after the panic: status=%v err=%v", next, err)
	}
	next.Body.Close()
}

func TestRecoverMiddleware_ReraisesWhenItCannotAnswer(t *testing.T) {
	h := &HttpBackend{Journal: &errorJournal{}}
	for name, handler := range map[string]http.HandlerFunc{
		"after the response began": func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("partial"))
			panic("late")
		},
		"abort": func(http.ResponseWriter, *http.Request) { panic(http.ErrAbortHandler) },
	} {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Fatal("panic was swallowed")
				}
			}()
			h.RecoverMiddleware(handler).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/x", nil))
		})
	}
}

// Without a UserService a gated request is refused 401, not a panic, and the
// misconfiguration is logged once when the chain is built.
func TestSSOMiddleware_NilUserService(t *testing.T) {
	journal := &errorJournal{}
	h := &HttpBackend{Journal: journal}
	called := false
	gate := h.SSOMiddleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
	for range 2 {
		req := httptest.NewRequest(http.MethodGet, common.RestPrefix+"/thing", nil)
		req.Header.Set("Authorization", "Bearer token")
		rec := httptest.NewRecorder()
		gate.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized || called {
			t.Fatalf("status = %d, called = %v", rec.Code, called)
		}
	}
	if len(journal.errors) != 1 {
		t.Fatalf("journal = %q, want one line", journal.errors)
	}
}
