package handler

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/oauth/client"
	"github.com/nauticana/keel/port"
	"github.com/nauticana/keel/secret"
)

// ShopifyComplianceHandler is the HTTP bridge for Shopify's mandatory privacy
// webhooks. SecretName is the keystore key of the app's client secret. Mount
// Handle on a public route; one route serves all three topics.
type ShopifyComplianceHandler struct {
	AbstractHandler
	Service    port.ShopifyComplianceService
	Secrets    secret.SecretProvider
	SecretName string
}

func (h *ShopifyComplianceHandler) Handle(w http.ResponseWriter, r *http.Request) {
	r = EnsureRequestID(r)
	if !h.RequireMethod(w, r, http.MethodPost) {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, MaxWebhookBodyBytes)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		h.WriteRequestError(r, w, http.StatusBadRequest, "Bad Request", "failed to read body")
		return
	}
	appSecret, err := h.Secrets.GetSecret(r.Context(), h.SecretName)
	if err != nil {
		h.WriteRequestError(r, w, http.StatusInternalServerError, "Internal Server Error", "shopify app secret unavailable: "+err.Error())
		return
	}
	if err := client.VerifyShopifyWebhook(body, r.Header.Get(client.ShopifyWebhookHMACHeader), appSecret); err != nil {
		h.WriteRequestError(r, w, http.StatusUnauthorized, "Unauthorized", "invalid webhook signature")
		return
	}
	err = h.dispatch(r, body)
	switch {
	case err == nil:
		common.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	case errors.Is(err, errShopifyTopicUnknown), errors.Is(err, port.ErrShopifyShopUnknown):
		h.WriteRequestError(r, w, http.StatusNotFound, "Not Found", err.Error())
	case errors.Is(err, errShopifyPayloadInvalid):
		h.WriteRequestError(r, w, http.StatusBadRequest, "Bad Request", err.Error())
	default:
		h.WriteRequestError(r, w, http.StatusInternalServerError, "Internal Server Error", err.Error())
	}
}

var (
	errShopifyTopicUnknown   = errors.New("unknown shopify compliance topic")
	errShopifyPayloadInvalid = errors.New("invalid shopify compliance payload")
)

func (h *ShopifyComplianceHandler) dispatch(r *http.Request, body []byte) error {
	ctx := r.Context()
	switch r.Header.Get(client.ShopifyWebhookTopicHeader) {
	case port.ShopifyTopicCustomerDataRequest:
		var req port.ShopifyCustomerDataRequest
		if json.Unmarshal(body, &req) != nil {
			return errShopifyPayloadInvalid
		}
		return h.Service.CustomerDataRequest(ctx, req)
	case port.ShopifyTopicCustomerRedact:
		var req port.ShopifyCustomerRedact
		if json.Unmarshal(body, &req) != nil {
			return errShopifyPayloadInvalid
		}
		return h.Service.CustomerRedact(ctx, req)
	case port.ShopifyTopicShopRedact:
		var req port.ShopifyShopRedact
		if json.Unmarshal(body, &req) != nil {
			return errShopifyPayloadInvalid
		}
		return h.Service.ShopRedact(ctx, req)
	}
	return errShopifyTopicUnknown
}
