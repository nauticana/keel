package billing

import (
	"context"
	"errors"
	"testing"

	"github.com/nauticana/keel/payment"
)

type fakeSubStore struct {
	sub      *ProviderSubscription
	prices   map[string]string
	customer string
}

func (f *fakeSubStore) CustomerToken(context.Context, int64, string) (string, error) {
	return f.customer, nil
}
func (f *fakeSubStore) ActiveProviderSubscription(context.Context, int64) (*ProviderSubscription, error) {
	return f.sub, nil
}
func (f *fakeSubStore) ProviderPriceID(_ context.Context, planID string, _ BillingTerms) (string, error) {
	if p := f.prices[planID]; p != "" {
		return p, nil
	}
	return "", ErrPriceNotFound
}

type fakeLifecycle struct {
	SubscriptionLifecycle
	cancelled CancelMode
	changedTo string
}

func (f *fakeLifecycle) CancelByPartner(_ context.Context, _ int64, mode CancelMode) error {
	f.cancelled = mode
	return nil
}
func (f *fakeLifecycle) ChangePlan(_ context.Context, _ int64, planID string, _ BillingTerms) error {
	f.changedTo = planID
	return nil
}

type fakeSubClient struct {
	err                            error
	cancelled, from, to, proration string
}

func (f *fakeSubClient) CancelSubscriptionAtPeriodEnd(_ context.Context, id string) error {
	f.cancelled = id
	return f.err
}
func (f *fakeSubClient) ChangeSubscriptionPrice(_ context.Context, _, from, to, proration string) error {
	f.from, f.to, f.proration = from, to, proration
	return f.err
}

type fakePortal struct {
	payment.CheckoutClient
	customer, returnURL string
}

func (f *fakePortal) CreatePortalSession(_ context.Context, customer, returnURL string) (string, error) {
	f.customer, f.returnURL = customer, returnURL
	return "https://portal", nil
}

func newSubService(store *fakeSubStore, client *fakeSubClient) (*ProviderSubscriptionService, *fakeLifecycle, *fakePortal) {
	life, portal := &fakeLifecycle{}, &fakePortal{}
	return &ProviderSubscriptionService{
		Store: store, Lifecycle: life, Client: client, Portal: portal,
		Provider: payment.ProviderStripe, ProrationBehavior: "always_invoice",
		PortalReturnURL: func() string { return "https://app.example.com/" },
	}, life, portal
}

var annualSub = &ProviderSubscription{ID: "sub_1", PlanID: "STANDARD", Terms: BillingTerms{BillingCycle: PeriodAnnual, TermType: PeriodAnnual, TermCount: 1}}

func TestProviderSubscriptionService_Cancel(t *testing.T) {
	client := &fakeSubClient{}
	s, life, _ := newSubService(&fakeSubStore{sub: annualSub}, client)
	if err := s.CancelAtPeriodEnd(context.Background(), 7); err != nil {
		t.Fatal(err)
	}
	if client.cancelled != "sub_1" || life.cancelled != CancelAtPeriodEnd {
		t.Fatalf("provider=%q local=%q", client.cancelled, life.cancelled)
	}

	failing, failLife, _ := newSubService(&fakeSubStore{sub: annualSub}, &fakeSubClient{err: errors.New("stripe down")})
	if err := failing.CancelAtPeriodEnd(context.Background(), 7); err == nil || failLife.cancelled != "" {
		t.Fatalf("provider failure: err=%v local=%q", err, failLife.cancelled)
	}

	unmanaged, _, _ := newSubService(&fakeSubStore{}, &fakeSubClient{})
	if err := unmanaged.CancelAtPeriodEnd(context.Background(), 7); !errors.Is(err, ErrNoProviderSubscription) {
		t.Fatalf("err = %v", err)
	}
}

func TestProviderSubscriptionService_ChangePlan(t *testing.T) {
	store := &fakeSubStore{sub: annualSub, prices: map[string]string{"STANDARD": "price_s", "PRO": "price_p"}}
	client := &fakeSubClient{}
	s, life, _ := newSubService(store, client)
	if err := s.ChangePlan(context.Background(), 7, "PRO"); err != nil {
		t.Fatal(err)
	}
	if client.from != "price_s" || client.to != "price_p" || client.proration != "always_invoice" || life.changedTo != "PRO" {
		t.Fatalf("client=%+v local=%q", client, life.changedTo)
	}

	unpriced, unpricedLife, _ := newSubService(store, &fakeSubClient{})
	if err := unpriced.ChangePlan(context.Background(), 7, "GOLD"); !errors.Is(err, ErrPriceNotFound) || unpricedLife.changedTo != "" {
		t.Fatalf("unpriced plan: err=%v local=%q", err, unpricedLife.changedTo)
	}
}

func TestProviderSubscriptionService_PortalURL(t *testing.T) {
	s, _, portal := newSubService(&fakeSubStore{customer: "cus_1"}, &fakeSubClient{})
	url, err := s.PortalURL(context.Background(), 7)
	if err != nil || url != "https://portal" || portal.customer != "cus_1" || portal.returnURL != "https://app.example.com/" {
		t.Fatalf("url=%q err=%v portal=%+v", url, err, portal)
	}
	none, _, _ := newSubService(&fakeSubStore{}, &fakeSubClient{})
	if _, err := none.PortalURL(context.Background(), 7); !errors.Is(err, ErrNoProviderCustomer) {
		t.Fatalf("err = %v", err)
	}
}

func TestActiveProviderSubscriptionAndPrice(t *testing.T) {
	svc, _ := newSvc(map[string][][]any{
		qBillActiveProvSub: {{"sub_1", "STANDARD", "A", "A", int64(1)}},
		qBillProviderPrice: {{""}},
	})
	sub, err := svc.ActiveProviderSubscription(context.Background(), 7)
	if err != nil || sub == nil || sub.ID != "sub_1" || sub.Terms.TermType != PeriodAnnual {
		t.Fatalf("sub=%+v err=%v", sub, err)
	}
	if _, err := svc.ProviderPriceID(context.Background(), "STANDARD", sub.Terms); !errors.Is(err, ErrPriceNotFound) {
		t.Fatalf("empty price id: err = %v", err)
	}

	none, _ := newSvc(map[string][][]any{})
	if _, err := none.ActiveProviderSubscription(context.Background(), 7); !errors.Is(err, ErrNoSubscription) {
		t.Fatalf("no subscription: err = %v", err)
	}
	manual, _ := newSvc(map[string][][]any{qBillActiveProvSub: {{"", "FREE", "A", "A", int64(1)}}})
	if sub, err := manual.ActiveProviderSubscription(context.Background(), 7); sub != nil || err != nil {
		t.Fatalf("manual subscription: sub=%+v err=%v", sub, err)
	}
}
