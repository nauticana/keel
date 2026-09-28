package payment

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/nauticana/keel/model"
	"github.com/nauticana/keel/port"
)

func stripeStub(t *testing.T, routes map[string]string) (*StripeChargeClient, *[]string) {
	t.Helper()
	var calls []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.Path)
		body, ok := routes[r.Method+" "+r.URL.Path]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"error":{"code":"resource_missing"}}`))
			return
		}
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return newTestChargeClient(srv), &calls
}

func TestDetachPaymentMethod(t *testing.T) {
	ctx := context.Background()
	c, calls := stripeStub(t, map[string]string{
		"GET /setup_intents/seti_1":                  `{"id":"seti_1","payment_method":"pm_1"}`,
		"GET /payment_methods/pm_1":                  `{"id":"pm_1","customer":"cus_1"}`,
		"POST /payment_methods/pm_1/detach":          `{"id":"pm_1","customer":null}`,
		"GET /payment_methods/pm_detached":           `{"id":"pm_detached","customer":null}`,
		"GET /setup_intents/seti_without_pm":         `{"id":"seti_without_pm","payment_method":null}`,
		"GET /setup_intents/seti_malformed":          `{"id":"seti_malformed"}`,
		"GET /payment_methods/pm_malformed":          `{"id":"pm_malformed"}`,
		"GET /payment_methods/pm_sticky":             `{"id":"pm_sticky","customer":"cus_1"}`,
		"POST /payment_methods/pm_sticky/detach":     `{"id":"pm_sticky","customer":"cus_1"}`,
		"GET /payment_methods/pm_bad_detach":         `{"id":"pm_bad_detach","customer":"cus_1"}`,
		"POST /payment_methods/pm_bad_detach/detach": `{"id":"pm_bad_detach"}`,
	})
	if err := c.DetachPaymentMethod(ctx, "seti_1"); err != nil {
		t.Fatal(err)
	}
	if last := (*calls)[len(*calls)-1]; last != "POST /payment_methods/pm_1/detach" {
		t.Fatalf("a SetupIntent token must detach its method: %v", *calls)
	}
	for _, token := range []string{"pm_detached", "pm_gone", "seti_without_pm", "seti_gone"} {
		*calls = nil
		if err := c.DetachPaymentMethod(ctx, token); err != nil {
			t.Errorf("%s: an absent or detached method is success: %v", token, err)
		}
		for _, call := range *calls {
			if call[:4] == "POST" {
				t.Errorf("%s: nothing to detach, got %s", token, call)
			}
		}
	}
	for _, token := range []string{"seti_malformed", "pm_malformed", "pm_sticky", "pm_bad_detach"} {
		if err := c.DetachPaymentMethod(ctx, token); err == nil {
			t.Errorf("%s: malformed provider response must fail", token)
		}
	}
	if err := c.DetachPaymentMethod(ctx, "cus_1"); err == nil {
		t.Error("an unsupported Stripe token must fail")
	}
}

type upmQueries struct {
	port.QueryService
	rows    map[int64]string // id → provider_token, all owned by user 7
	deleted []int64
}

func (q *upmQueries) Query(_ context.Context, name string, args ...any) (*model.QueryResult, error) {
	id, user := args[0].(int64), args[1].(int)
	switch name {
	case qUPMToken:
		if token, ok := q.rows[id]; ok && user == 7 {
			return &model.QueryResult{Rows: [][]any{{token}}}, nil
		}
		return &model.QueryResult{}, nil
	case qUPMDelete:
		q.deleted = append(q.deleted, id)
		return &model.QueryResult{}, nil
	}
	return nil, errors.New("unexpected query " + name)
}

type upmRepo struct {
	port.DatabaseRepository
	qs *upmQueries
}

func (r upmRepo) GetQueryService(context.Context, map[string]string) port.QueryService { return r.qs }

type detacherFunc func(context.Context, string) error

func (f detacherFunc) DetachPaymentMethod(ctx context.Context, token string) error {
	return f(ctx, token)
}

func TestUserPaymentMethodRemove(t *testing.T) {
	ctx := context.Background()
	qs := &upmQueries{rows: map[int64]string{1: "seti_1", 2: "pm_2"}}
	var detached []string
	fail := false
	s := &UserPaymentMethodService{DB: upmRepo{qs: qs}, Detacher: detacherFunc(func(_ context.Context, token string) error {
		if fail {
			return errors.New("provider down")
		}
		detached = append(detached, token)
		return nil
	})}
	if err := s.Remove(ctx, 7, 1); err != nil || len(detached) != 1 || detached[0] != "seti_1" || len(qs.deleted) != 1 {
		t.Fatalf("remove: %v detached=%v deleted=%v", err, detached, qs.deleted)
	}
	if err := s.Remove(ctx, 8, 2); !errors.Is(err, ErrPaymentMethodNotFound) {
		t.Errorf("another user's method: %v", err)
	}
	fail = true
	if err := s.Remove(ctx, 7, 2); err == nil || len(qs.deleted) != 1 {
		t.Errorf("a failed detach must keep the row: %v deleted=%v", err, qs.deleted)
	}
	if err := (&UserPaymentMethodService{DB: upmRepo{qs: qs}}).Remove(ctx, 7, 2); err == nil {
		t.Error("Remove without a Detacher must fail")
	}
}
