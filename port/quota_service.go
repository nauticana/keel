package port

import "context"

type QuotaService interface {
	CheckQuota(ctx context.Context, partnerId int64, resource string, cnt int64) (bool, error)
	CheckAddon(ctx context.Context, partnerId int64, resource string) (bool, error)
	LogUsage(ctx context.Context, partnerID int64, quotaName string, amount int64, description string) error
	ReportAddonUsage(ctx context.Context, partnerID int64, addonID string, amount int64, notes string) error
}
