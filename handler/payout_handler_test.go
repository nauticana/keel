package handler

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nauticana/keel/keeltest"
	"github.com/nauticana/keel/model"
	"github.com/nauticana/keel/payout"
)

type stubPayoutProvider struct{ payout.PayoutProvider }

func (stubPayoutProvider) Code() string { return payout.ProviderCodeStripeConnect }

func payoutRequest(method, target, body string) *http.Request {
	r := httptest.NewRequest(method, target, strings.NewReader(body))
	r.Header.Set("Authorization", "Bearer token")
	return r
}

func TestPayoutHandlerNeverSendsInternalErrorText(t *testing.T) {
	users := stubSessionUsers{session: &model.UserSession{Id: 5, PartnerId: 9}}
	unconfigured := &PayoutHandler{AbstractHandler: AbstractHandler{UserService: users}, PayoutService: &payout.OnboardingService{}}
	w := httptest.NewRecorder()
	unconfigured.StartOnboarding(w, payoutRequest(http.MethodPost, "/payout/onboard/start", ""))
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "payout_provider_not_configured") || strings.Contains(w.Body.String(), "resolver") {
		t.Fatalf("no provider: %d %s", w.Code, w.Body.String())
	}

	// The schema probe finds no index: an internal failure on every endpoint.
	h := &PayoutHandler{AbstractHandler: AbstractHandler{UserService: users}, PayoutService: &payout.OnboardingService{
		DB: keeltest.NewDatabase(), Providers: payout.NewStaticProviderResolver(stubPayoutProvider{})}}
	for name, call := range map[string]func(http.ResponseWriter, *http.Request){
		"start": h.StartOnboarding, "reusable": h.ListReusable, "link": h.LinkReusable, "status": h.Status,
	} {
		w := httptest.NewRecorder()
		call(w, payoutRequest(http.MethodPost, "/", `{"providerAccountId":"acct_1"}`))
		if w.Code != http.StatusInternalServerError || strings.Contains(w.Body.String(), "user_bank_info") {
			t.Fatalf("%s: %d %s, want a sanitized 500", name, w.Code, w.Body.String())
		}
	}

	w = httptest.NewRecorder()
	h.ReplaceBank(w, payoutRequest(http.MethodPost, "/", `{}`))
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "payout_invalid_bank_info") {
		t.Fatalf("empty bank info: %d %s", w.Code, w.Body.String())
	}
}

func TestPayoutWebhookRefusalIsGenericAndBodyIsBounded(t *testing.T) {
	h := &PayoutHandler{PayoutService: &payout.OnboardingService{Providers: payout.NewStaticProviderResolver(stubPayoutProvider{})}}
	w := httptest.NewRecorder()
	h.Webhook(w, httptest.NewRequest(http.MethodPost, "/webhook/payout/ZZ", strings.NewReader(`{}`)))
	if w.Code != http.StatusUnauthorized || strings.Contains(w.Body.String(), "unknown") || strings.Contains(w.Body.String(), "ZZ") {
		t.Fatalf("unknown provider: %d %s", w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	h.Webhook(w, httptest.NewRequest(http.MethodPost, "/webhook/payout/SC", strings.NewReader(strings.Repeat("a", MaxWebhookBodyBytes+1))))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("oversized body: %d, want 400", w.Code)
	}
}
