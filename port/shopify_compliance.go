package port

import (
	"context"
	"errors"
)

const (
	ShopifyTopicCustomerDataRequest = "customers/data_request"
	ShopifyTopicCustomerRedact      = "customers/redact"
	ShopifyTopicShopRedact          = "shop/redact"
)

// ErrShopifyShopUnknown lets an implementation refuse a shop it has never
// connected; the HTTP bridge answers it 404.
var ErrShopifyShopUnknown = errors.New("shopify shop unknown")

type ShopifyCustomer struct {
	ID    int64  `json:"id"`
	Email string `json:"email"`
	Phone string `json:"phone"`
}

type ShopifyDataRequestRef struct {
	ID int64 `json:"id"`
}

type ShopifyCustomerDataRequest struct {
	ShopID          int64                 `json:"shop_id"`
	ShopDomain      string                `json:"shop_domain"`
	Customer        ShopifyCustomer       `json:"customer"`
	OrdersRequested []int64               `json:"orders_requested"`
	DataRequest     ShopifyDataRequestRef `json:"data_request"`
}

type ShopifyCustomerRedact struct {
	ShopID         int64           `json:"shop_id"`
	ShopDomain     string          `json:"shop_domain"`
	Customer       ShopifyCustomer `json:"customer"`
	OrdersToRedact []int64         `json:"orders_to_redact"`
}

type ShopifyShopRedact struct {
	ShopID     int64  `json:"shop_id"`
	ShopDomain string `json:"shop_domain"`
}

// ShopifyComplianceService answers Shopify's mandatory privacy webhooks. A nil
// error acknowledges the request; any other error makes Shopify redeliver.
type ShopifyComplianceService interface {
	CustomerDataRequest(ctx context.Context, req ShopifyCustomerDataRequest) error
	CustomerRedact(ctx context.Context, req ShopifyCustomerRedact) error
	ShopRedact(ctx context.Context, req ShopifyShopRedact) error
}
