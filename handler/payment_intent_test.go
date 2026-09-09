package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/nauticana/keel/model"
	"github.com/nauticana/keel/payment"
	"github.com/nauticana/keel/user"
)

type intentUsers struct{ user.UserService }

func (intentUsers) ParseJWT(token string) (*model.UserSession, error) {
	if token != "ok" {
		return nil, errors.New("bad token")
	}
	return &model.UserSession{Id: 7, PartnerId: 2, Email: "session@example.com"}, nil
}

type fakeIntents struct{ got payment.IntentRequest }

func (f *fakeIntents) CreateSetupIntent(_ context.Context, req payment.IntentRequest) (*payment.IntentResult, error) {
	f.got = req
	return &payment.IntentResult{IntentID: "seti_1", ClientSecret: "cs", CustomerID: "cus_1", EphemeralKey: "ek"}, nil
}
func (f *fakeIntents) CreatePaymentIntent(context.Context, payment.IntentRequest) (*payment.IntentResult, error) {
	return nil, errors.New("not used")
}

var _ payment.IntentClient = (*fakeIntents)(nil)

func TestCreateSetupIntent_RequiresJWTAndInjectsUser(t *testing.T) {
	intents := &fakeIntents{}
	h := &AbstractPaymentHandler{AbstractHandler: AbstractHandler{UserService: intentUsers{}}, Intents: intents}

	rec := httptest.NewRecorder()
	h.CreateSetupIntent(rec, httptest.NewRequest(http.MethodPost, "/api/billing/setup-intent", strings.NewReader(`{}`)))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous status=%d", rec.Code)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/billing/setup-intent", strings.NewReader(`{"customerId":"cus_attacker","email":"attacker@example.com"}`))
	req.Header.Set("Authorization", "Bearer ok")
	rec = httptest.NewRecorder()
	h.CreateSetupIntent(rec, req)
	if rec.Code != http.StatusOK || intents.got.CustomerID != "" || intents.got.Email != "session@example.com" || intents.got.Metadata["user_id"] != "7" {
		t.Fatalf("status=%d got=%+v body=%s", rec.Code, intents.got, rec.Body.String())
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("Cache-Control = %q", rec.Header().Get("Cache-Control"))
	}
	var out struct {
		Data map[string]string `json:"data"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if out.Data["clientSecret"] != "cs" || out.Data["ephemeralKey"] != "ek" || out.Data["customerId"] != "cus_1" {
		t.Fatalf("data=%v", out.Data)
	}

	h.CustomerID = func(_ context.Context, userID int) (string, error) { return "cus_stored_" + strconv.Itoa(userID), nil }
	req = httptest.NewRequest(http.MethodPost, "/api/billing/setup-intent", nil)
	req.Header.Set("Authorization", "Bearer ok")
	rec = httptest.NewRecorder()
	h.CreateSetupIntent(rec, req)
	if rec.Code != http.StatusOK || intents.got.CustomerID != "cus_stored_7" {
		t.Fatalf("empty body with resolver: status=%d got=%+v", rec.Code, intents.got)
	}
	h.CustomerID = func(context.Context, int) (string, error) { return "", errors.New("db down") }
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/billing/setup-intent", nil)
	req.Header.Set("Authorization", "Bearer ok")
	h.CreateSetupIntent(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("resolver failure status=%d", rec.Code)
	}
}
