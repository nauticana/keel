package googleads

import (
	"context"
	"encoding/json"
	"fmt"
)

// MaxConversionsPerUpload is the API's limit on conversions in one
// uploadClickConversions request.
const MaxConversionsPerUpload = 2000

// DateTimeLayout formats ConversionDateTime ("yyyy-mm-dd hh:mm:ss+hh:mm").
const DateTimeLayout = "2006-01-02 15:04:05-07:00"

// ClickConversion is one offline conversion in the API's JSON shape. It needs
// one click id (GCLID, GBRAID or WBRAID) or, for enhanced conversions for
// leads, UserIdentifiers. ConversionValue is a decimal string written as a
// JSON number (common.FormatMinorUnits renders one from minor units); it is
// never a float.
type ClickConversion struct {
	ConversionAction   string           `json:"conversionAction"`
	ConversionDateTime string           `json:"conversionDateTime"`
	ConversionValue    json.Number      `json:"conversionValue,omitempty"`
	CurrencyCode       string           `json:"currencyCode,omitempty"`
	OrderID            string           `json:"orderId,omitempty"`
	GCLID              string           `json:"gclid,omitempty"`
	GBRAID             string           `json:"gbraid,omitempty"`
	WBRAID             string           `json:"wbraid,omitempty"`
	UserIdentifiers    []UserIdentifier `json:"userIdentifiers,omitempty"`
	Consent            *Consent         `json:"consent,omitempty"`
}

// UserIdentifier carries one hashed match key; see HashEmail and HashPhone.
type UserIdentifier struct {
	HashedEmail       string `json:"hashedEmail,omitempty"`
	HashedPhoneNumber string `json:"hashedPhoneNumber,omitempty"`
}

// Consent values are "GRANTED" or "DENIED".
type Consent struct {
	AdUserData        string `json:"adUserData,omitempty"`
	AdPersonalization string `json:"adPersonalization,omitempty"`
}

// UploadClickConversions uploads conversions with partial failure on: the
// returned Failures name each refused conversion by Index, and the rest are
// accepted. An error means the request as a whole failed.
func (c *Client) UploadClickConversions(ctx context.Context, token, customerID string, conversions []ClickConversion) ([]Failure, error) {
	id, err := CustomerID(customerID)
	if err != nil {
		return nil, err
	}
	switch {
	case len(conversions) == 0:
		return nil, ErrNoConversions
	case len(conversions) > MaxConversionsPerUpload:
		return nil, ErrTooManyConversions
	}
	body, err := c.post(ctx, "upload click conversions", token, "/customers/"+id+":uploadClickConversions",
		map[string]any{"conversions": conversions, "partialFailure": true})
	if err != nil {
		return nil, err
	}
	var resp struct {
		PartialFailureError *rpcStatus `json:"partialFailureError"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("googleads: decode conversion upload: %w", err)
	}
	st := resp.PartialFailureError
	if st == nil || (st.Code == 0 && st.Message == "" && len(st.Details) == 0) {
		return nil, nil
	}
	failures, _ := st.failures()
	if len(failures) == 0 {
		failures = []Failure{{Index: -1, Message: st.Message}}
	}
	return failures, nil
}
