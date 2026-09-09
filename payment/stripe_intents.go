package payment

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
)

const stripeAPIVersion = "2024-06-20"

func (c *StripeCheckoutClient) CreateSetupIntent(ctx context.Context, req IntentRequest) (*IntentResult, error) {
	form := url.Values{}
	form.Set("usage", "off_session")
	return c.createIntent(ctx, "/setup_intents", req, form)
}

func (c *StripeCheckoutClient) CreatePaymentIntent(ctx context.Context, req IntentRequest) (*IntentResult, error) {
	if req.Amount <= 0 || req.Currency == "" {
		return nil, fmt.Errorf("stripe: payment intent needs amount and currency")
	}
	form := url.Values{}
	form.Set("amount", strconv.FormatInt(req.Amount, 10))
	form.Set("currency", req.Currency)
	form.Set("automatic_payment_methods[enabled]", "true")
	return c.createIntent(ctx, "/payment_intents", req, form)
}

func (c *StripeCheckoutClient) createIntent(ctx context.Context, path string, req IntentRequest, form url.Values) (*IntentResult, error) {
	customerID := req.CustomerID
	if customerID == "" {
		customer := url.Values{}
		if req.Email != "" {
			customer.Set("email", req.Email)
		}
		setMetadata(customer, req.Metadata)
		id, err := c.postID(ctx, "/customers", customer)
		if err != nil {
			return nil, err
		}
		customerID = id
	}
	ephemeral, err := c.postVersionedField(ctx, "/ephemeral_keys", url.Values{"customer": {customerID}}, "secret")
	if err != nil {
		return nil, err
	}
	form.Set("customer", customerID)
	setMetadata(form, req.Metadata)
	body, err := c.Post(ctx, path, form)
	if err != nil {
		return nil, err
	}
	var parsed struct {
		ID           string `json:"id"`
		ClientSecret string `json:"client_secret"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil || parsed.ClientSecret == "" {
		return nil, fmt.Errorf("stripe: no client_secret in %s response", path)
	}
	return &IntentResult{IntentID: parsed.ID, ClientSecret: parsed.ClientSecret, CustomerID: customerID, EphemeralKey: ephemeral}, nil
}

func (c *StripeCheckoutClient) postVersionedField(ctx context.Context, path string, form url.Values, field string) (string, error) {
	status, body, err := c.requestRawWithHeaders(ctx, http.MethodPost, path, form.Encode(), "", http.Header{
		"Stripe-Version": {c.apiVersion()},
	})
	if err != nil {
		return "", err
	}
	if status < 200 || status >= 300 {
		return "", fmt.Errorf("stripe: status %d: %s", status, string(body))
	}
	return responseStringField(path, field, body)
}

func (c *StripeCheckoutClient) postID(ctx context.Context, path string, form url.Values) (string, error) {
	return c.postField(ctx, path, form, "id")
}

func (c *StripeCheckoutClient) postField(ctx context.Context, path string, form url.Values, field string) (string, error) {
	body, err := c.Post(ctx, path, form)
	if err != nil {
		return "", err
	}
	return responseStringField(path, field, body)
}

func responseStringField(path, field string, body []byte) (string, error) {
	var parsed map[string]any
	if err := json.Unmarshal(body, &parsed); err != nil {
		return "", fmt.Errorf("stripe: parse %s response: %w", path, err)
	}
	value, _ := parsed[field].(string)
	if value == "" {
		return "", fmt.Errorf("stripe: no %s in %s response", field, path)
	}
	return value, nil
}

func setMetadata(form url.Values, metadata map[string]string) {
	for k, v := range metadata {
		form.Set("metadata["+k+"]", v)
	}
}

var _ IntentClient = (*StripeCheckoutClient)(nil)
