package service

import (
	"context"
	"strings"
	"testing"

	"github.com/nauticana/keel/logger"
	"github.com/nauticana/keel/port"
)

type infoJournal struct {
	logger.ApplicationLogger
	lines []string
}

func (j *infoJournal) Info(line string) { j.lines = append(j.lines, line) }

func TestBaseShopifyComplianceRecordsWithoutContactData(t *testing.T) {
	journal := &infoJournal{}
	s := &BaseShopifyComplianceService{Journal: journal}
	ctx := context.Background()
	customer := port.ShopifyCustomer{ID: 5, Email: "a@b.c", Phone: "+15550100"}
	if err := s.CustomerDataRequest(ctx, port.ShopifyCustomerDataRequest{ShopID: 9, Customer: customer}); err != nil {
		t.Fatal(err)
	}
	if err := s.CustomerRedact(ctx, port.ShopifyCustomerRedact{ShopID: 9, Customer: customer}); err != nil {
		t.Fatal(err)
	}
	if err := s.ShopRedact(ctx, port.ShopifyShopRedact{ShopID: 9, ShopDomain: "s.myshopify.com"}); err != nil {
		t.Fatal(err)
	}
	if len(journal.lines) != 3 {
		t.Fatalf("recorded %d lines, want 3", len(journal.lines))
	}
	for _, line := range journal.lines {
		if strings.Contains(line, customer.Email) || strings.Contains(line, customer.Phone) {
			t.Fatalf("contact data leaked into journal: %s", line)
		}
	}
}
