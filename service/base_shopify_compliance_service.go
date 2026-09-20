package service

import (
	"context"
	"fmt"

	"github.com/nauticana/keel/logger"
	"github.com/nauticana/keel/port"
)

// BaseShopifyComplianceService records each request in the journal (ids only,
// never customer contact data) and acknowledges it — the complete answer for an
// app that stores no Shopify customer data. Embed it and override the topics
// the app holds data for. Journal is required.
type BaseShopifyComplianceService struct {
	Journal logger.ApplicationLogger
}

var _ port.ShopifyComplianceService = (*BaseShopifyComplianceService)(nil)

func (s *BaseShopifyComplianceService) CustomerDataRequest(_ context.Context, req port.ShopifyCustomerDataRequest) error {
	s.record(port.ShopifyTopicCustomerDataRequest, req.ShopID, req.ShopDomain,
		fmt.Sprintf("customer=%d data_request=%d orders=%d", req.Customer.ID, req.DataRequest.ID, len(req.OrdersRequested)))
	return nil
}

func (s *BaseShopifyComplianceService) CustomerRedact(_ context.Context, req port.ShopifyCustomerRedact) error {
	s.record(port.ShopifyTopicCustomerRedact, req.ShopID, req.ShopDomain,
		fmt.Sprintf("customer=%d orders=%d", req.Customer.ID, len(req.OrdersToRedact)))
	return nil
}

func (s *BaseShopifyComplianceService) ShopRedact(_ context.Context, req port.ShopifyShopRedact) error {
	s.record(port.ShopifyTopicShopRedact, req.ShopID, req.ShopDomain, "")
	return nil
}

func (s *BaseShopifyComplianceService) record(topic string, shopID int64, shopDomain, detail string) {
	s.Journal.Info(fmt.Sprintf("shopify compliance %s shop_id=%d shop_domain=%q %s", topic, shopID, shopDomain, detail))
}
