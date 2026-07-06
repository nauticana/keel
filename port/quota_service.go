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
}
