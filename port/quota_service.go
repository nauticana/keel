package port

import (
	"context"
	"time"
)

type QuotaService interface {
	CheckQuota(ctx context.Context, partnerId int64, resource string, cnt int64) (bool, error)
	// ConsumeQuota atomically checks and records `amount` units in one
	// transaction, failing closed on any storage error. resetAt is the next
	// period boundary (zero for all-time quotas) for use in Retry-After.
	ConsumeQuota(ctx context.Context, partnerID int64, resource string, amount int64, description string) (allowed bool, resetAt time.Time, err error)
	CheckAddon(ctx context.Context, partnerId int64, resource string) (bool, error)
	GetPartnerQuota(ctx context.Context, partnerID int64, resource string, def int64) (int64, error)
	LogUsage(ctx context.Context, partnerID int64, quotaName string, amount int64, description string) error
	ReportAddonUsage(ctx context.Context, partnerID int64, addonID string, amount int64, notes string) error
	// InvalidatePartner drops the partner's cached limits and add-ons after its
	// subscription changed, here and, when the service has a bus, in every
	// other process.
	InvalidatePartner(ctx context.Context, partnerID int64)
}

// PlanQuotaService supports subscription changes without widening the quota
// enforcement contract.
type PlanQuotaService interface {
	InvalidatePartner(ctx context.Context, partnerID int64)
	PlanOverages(ctx context.Context, partnerID int64, planID string) ([]QuotaOverage, error)
}

// QuotaOverage is a live-counted resource a partner holds beyond a plan's
// limit; Limit 0 means the plan does not offer the resource.
type QuotaOverage struct {
	Resource string `json:"resource"`
	Caption  string `json:"caption"` // subscription_resource.caption
	Count    int64  `json:"count"`
	Limit    int64  `json:"limit"`
}
