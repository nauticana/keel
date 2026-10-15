// Package commerce reads a connected store's orders into a provider-neutral shape.
package commerce

import (
	"context"
	"errors"
	"time"
)

// FinancialStatus is an order's payment state.
type FinancialStatus string

const (
	StatusPending           FinancialStatus = "pending"
	StatusAuthorized        FinancialStatus = "authorized"
	StatusPaid              FinancialStatus = "paid"
	StatusPartiallyPaid     FinancialStatus = "partially_paid"
	StatusPartiallyRefunded FinancialStatus = "partially_refunded"
	StatusRefunded          FinancialStatus = "refunded"
	StatusVoided            FinancialStatus = "voided"
	StatusExpired           FinancialStatus = "expired" // an authorization that lapsed uncaptured
)

// Order is one store order's money and payment state; it carries no customer
// data. Amounts are minor units of Currency, as the store reports them.
type Order struct {
	ID       string
	Name     string // the store's display number, e.g. "#1001"
	Currency string
	// SubtotalMinor is the line items after discounts, before shipping and
	// returns; it includes tax when TaxesIncluded.
	SubtotalMinor  int64
	DiscountsMinor int64
	ShippingMinor  int64
	TaxMinor       int64
	TotalMinor     int64
	RefundedMinor  int64 // refunded so far
	TaxesIncluded  bool
	// Status is empty when the store reports none.
	Status      FinancialStatus
	Test        bool
	OrderedAt   time.Time
	ProcessedAt time.Time
	CancelledAt time.Time // zero unless cancelled
	UpdatedAt   time.Time
}

// OrderPage is one page of orders, oldest update first; Next is "" on the last page.
type OrderPage struct {
	Orders []Order
	Next   string
}

// OrderReader reads a store's orders updated at or after updatedSince. token
// and endpoint are the connection's access token and API endpoint; after is
// the previous page's Next, "" for the first page.
type OrderReader interface {
	Orders(ctx context.Context, token, endpoint string, updatedSince time.Time, after string) (OrderPage, error)
}

var (
	// ErrThrottled: the store kept refusing for rate; retry the page later.
	ErrThrottled = errors.New("commerce: store throttled the request")
	// ErrAccessDenied: the token is invalid or lacks the orders scope.
	ErrAccessDenied = errors.New("commerce: store denied access")
	// ErrRejected: the store refused the request or returned an unusable order.
	ErrRejected = errors.New("commerce: store rejected the request")
)
