package handler

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nauticana/keel/oauth/client"
	"github.com/nauticana/keel/port"
)

type shopifySecrets struct{}

func (shopifySecrets) GetSecret(context.Context, string) (string, error) { return "app-secret", nil }

type shopifyComplianceSpy struct {
	dataRequest    port.ShopifyCustomerDataRequest
	customerRedact port.ShopifyCustomerRedact
	shopRedact     port.ShopifyShopRedact
	err            error
}

func (s *shopifyComplianceSpy) CustomerDataRequest(_ context.Context, req port.ShopifyCustomerDataRequest) error {
	s.dataRequest = req
	return s.err
}

func (s *shopifyComplianceSpy) CustomerRedact(_ context.Context, req port.ShopifyCustomerRedact) error {
	s.customerRedact = req
	return s.err
}

func (s *shopifyComplianceSpy) ShopRedact(_ context.Context, req port.ShopifyShopRedact) error {
	s.shopRedact = req
	return s.err
}

func shopifyWebhook(topic, body, secret string) *http.Request {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(body))
	r := httptest.NewRequest(http.MethodPost, "/public/webhook/shopify", strings.NewReader(body))
	r.Header.Set(client.ShopifyWebhookTopicHeader, topic)
	r.Header.Set(client.ShopifyWebhookHMACHeader, base64.StdEncoding.EncodeToString(mac.Sum(nil)))
	return r
}

func TestShopifyComplianceHandler(t *testing.T) {
	const dataRequest = `{"shop_id":9,"shop_domain":"s.myshopify.com","customer":{"id":5,"email":"a@b.c"},"orders_requested":[1,2],"data_request":{"id":77}}`
	for name, tc := range map[string]struct {
		topic, body, secret string
		serviceErr          error
		status              int
	}{
		"data request":    {port.ShopifyTopicCustomerDataRequest, dataRequest, "app-secret", nil, http.StatusOK},
		"customer redact": {port.ShopifyTopicCustomerRedact, `{"shop_id":9,"orders_to_redact":[3]}`, "app-secret", nil, http.StatusOK},
		"shop redact":     {port.ShopifyTopicShopRedact, `{"shop_id":9,"shop_domain":"s.myshopify.com"}`, "app-secret", nil, http.StatusOK},
		"bad signature":   {port.ShopifyTopicShopRedact, `{}`, "forged", nil, http.StatusUnauthorized},
		"unknown topic":   {"orders/create", `{}`, "app-secret", nil, http.StatusNotFound},
		"bad payload":     {port.ShopifyTopicShopRedact, `[`, "app-secret", nil, http.StatusBadRequest},
		"unknown shop":    {port.ShopifyTopicShopRedact, `{}`, "app-secret", port.ErrShopifyShopUnknown, http.StatusNotFound},
		"service error":   {port.ShopifyTopicShopRedact, `{}`, "app-secret", errors.New("db down"), http.StatusInternalServerError},
	} {
		spy := &shopifyComplianceSpy{err: tc.serviceErr}
		h := &ShopifyComplianceHandler{Service: spy, Secrets: shopifySecrets{}, SecretName: "shopify_api_secret"}
		w := httptest.NewRecorder()
		h.Handle(w, shopifyWebhook(tc.topic, tc.body, tc.secret))
		if w.Code != tc.status {
			t.Errorf("%s: status %d, want %d", name, w.Code, tc.status)
		}
		if name == "data request" && (spy.dataRequest.Customer.ID != 5 || len(spy.dataRequest.OrdersRequested) != 2 || spy.dataRequest.DataRequest.ID != 77) {
			t.Errorf("payload = %+v", spy.dataRequest)
		}
		if name == "bad signature" && spy.shopRedact != (port.ShopifyShopRedact{}) {
			t.Error("service reached despite bad signature")
		}
	}

	w := httptest.NewRecorder()
	h := &ShopifyComplianceHandler{Service: &shopifyComplianceSpy{}, Secrets: shopifySecrets{}}
	h.Handle(w, httptest.NewRequest(http.MethodGet, "/public/webhook/shopify", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET: status %d", w.Code)
	}
}
