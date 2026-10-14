package billing

import (
	"context"
	"testing"

	"github.com/nauticana/keel/model"
	"github.com/nauticana/keel/payment"
)

func TestPartnerCustomerService(t *testing.T) {
	svc, qs := newSvc(map[string][][]any{qBillCustomerToken: {{"cus_first"}}})
	s := &PartnerCustomerService{Store: svc, Provider: payment.ProviderStripe}
	session := &model.UserSession{Id: 7, PartnerId: 2}

	id, err := s.CustomerID(context.Background(), session)
	if err != nil || id != "cus_first" {
		t.Fatalf("id=%q err=%v", id, err)
	}
	if args := lastCall(t, qs, qBillCustomerToken).args; args[0] != int64(2) || args[1] != payment.ProviderStripe {
		t.Fatalf("lookup args = %v", args)
	}
	if err := s.LinkCustomer(context.Background(), session, "cus_1"); err != nil {
		t.Fatal(err)
	}
	if args := lastCall(t, qs, qBillLinkCustomer).args; args[0] != int64(2) || args[2] != "cus_1" {
		t.Fatalf("link args = %v", args)
	}

	for _, bad := range []*model.UserSession{nil, {Id: 7}} {
		if _, err := s.CustomerID(context.Background(), bad); err == nil {
			t.Fatalf("resolved a customer for session %+v", bad)
		}
		if err := s.LinkCustomer(context.Background(), bad, "cus_1"); err == nil {
			t.Fatalf("linked a customer for session %+v", bad)
		}
	}
	if err := s.LinkCustomer(context.Background(), session, ""); err == nil {
		t.Fatal("linked an empty customer")
	}
}
