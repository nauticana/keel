package payment

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// PaymentMethodDetacher removes a saved payment method from its provider
// customer, so it is no longer offered or chargeable. A method that is already
// detached or no longer exists is success.
type PaymentMethodDetacher interface {
	DetachPaymentMethod(ctx context.Context, providerToken string) error
}

// DetachPaymentMethod accepts a PaymentMethod id (pm_…) or the SetupIntent id
// (seti_…) that UserPaymentMethodService records, resolving it to its method.
func (c *StripeChargeClient) DetachPaymentMethod(ctx context.Context, providerToken string) error {
	if c == nil || c.Stripe == nil {
		return fmt.Errorf("detach: stripe client is required")
	}
	if providerToken == "" {
		return fmt.Errorf("detach: provider token is required")
	}
	if !strings.HasPrefix(providerToken, "pm_") && !strings.HasPrefix(providerToken, "seti_") {
		return fmt.Errorf("detach: unsupported Stripe token %q", providerToken)
	}
	methodID := providerToken
	if strings.HasPrefix(providerToken, "seti_") {
		var intent struct {
			PaymentMethod json.RawMessage `json:"payment_method"`
		}
		found, err := c.stripeGet(ctx, "/setup_intents/"+url.PathEscape(providerToken), &intent)
		if err != nil || !found {
			return err
		}
		methodID, found, err = stripeNullableID(intent.PaymentMethod, "payment_method")
		if err != nil || !found {
			return err
		}
	}
	var method struct {
		Customer json.RawMessage `json:"customer"`
	}
	found, err := c.stripeGet(ctx, "/payment_methods/"+url.PathEscape(methodID), &method)
	if err != nil || !found {
		return err
	}
	_, attached, err := stripeNullableID(method.Customer, "customer")
	if err != nil || !attached {
		return err
	}
	status, body, err := c.Stripe.PostRaw(ctx, "/payment_methods/"+url.PathEscape(methodID)+"/detach", url.Values{}, "")
	if err != nil {
		return fmt.Errorf("detach: %w", err)
	}
	if status < 200 || status >= 300 {
		return fmt.Errorf("detach: stripe %d: %s", status, body)
	}
	if err := json.Unmarshal(body, &method); err != nil {
		return fmt.Errorf("detach: parse response: %w", err)
	}
	if _, attached, err = stripeNullableID(method.Customer, "customer"); err != nil {
		return err
	}
	if attached {
		return fmt.Errorf("detach: %s is still attached", methodID)
	}
	return nil
}

// stripeGet decodes a Stripe object into out; found is false on 404.
func (c *StripeChargeClient) stripeGet(ctx context.Context, path string, out any) (found bool, err error) {
	status, body, err := c.Stripe.requestRaw(ctx, http.MethodGet, path, "", "")
	if err != nil {
		return false, fmt.Errorf("detach: %w", err)
	}
	if status == http.StatusNotFound {
		return false, nil
	}
	if status < 200 || status >= 300 {
		return false, fmt.Errorf("detach: stripe %d: %s", status, body)
	}
	if err := json.Unmarshal(body, out); err != nil {
		return false, fmt.Errorf("detach: parse %s: %w", path, err)
	}
	return true, nil
}

func stripeNullableID(raw json.RawMessage, field string) (string, bool, error) {
	if len(raw) == 0 {
		return "", false, fmt.Errorf("detach: stripe response missing %s", field)
	}
	if string(raw) == "null" {
		return "", false, nil
	}
	var id string
	if err := json.Unmarshal(raw, &id); err != nil || id == "" {
		return "", false, fmt.Errorf("detach: stripe response has invalid %s", field)
	}
	return id, true, nil
}

var _ PaymentMethodDetacher = (*StripeChargeClient)(nil)
