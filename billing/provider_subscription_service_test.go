package billing

import (
	"context"
	"errors"
	"testing"

	"github.com/nauticana/keel/payment"
	"github.com/nauticana/keel/port"
)

type fakeSubStore struct {
	sub      *ProviderSubscription
	prices   map[string]string
	modes    map[string]ActivationMode
	customer string
}

func (f *fakeSubStore) CustomerToken(context.Context, int64, string) (string, error) {
	return f.customer, nil
}
func (f *fakeSubStore) CurrentSubscription(context.Context, int64) (*ProviderSubscription, error) {
	if f.sub == nil {
		return nil, ErrNoSubscription
	}
	return f.sub, nil
}
func (f *fakeSubStore) PlanActivationMode(_ context.Context, planID string) (ActivationMode, error) {
	if m, ok := f.modes[planID]; ok {
		return m, nil
	}
	if f.prices[planID] != "" {
		return ActivateCreateActive, nil
	}
	return "", ErrPlanNotFound
}
func (f *fakeSubStore) ProviderPriceID(_ context.Context, planID string, _ BillingTerms) (string, error) {
	if p := f.prices[planID]; p != "" {
		return p, nil
	}
	return "", ErrPriceNotFound
}

type fakeLifecycle struct {
	SubscriptionLifecycle
	cancelled   CancelMode
	changedTo   string
	scheduledTo string
	resumed     bool
	overages    []port.QuotaOverage
}

func (f *fakeLifecycle) CheckChange(context.Context, int64, string) ([]port.QuotaOverage, error) {
	return f.overages, nil
}

func (f *fakeLifecycle) ResumeRenewal(context.Context, int64) error {
	f.resumed = true
	return nil
}

func (f *fakeLifecycle) ScheduleChange(_ context.Context, _ int64, planID string) error {
	f.scheduledTo = planID
	return nil
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

	unmanaged, _, _ := newSubService(&fakeSubStore{sub: &ProviderSubscription{PlanID: "STANDARD"}}, &fakeSubClient{})
	if err := unmanaged.CancelAtPeriodEnd(context.Background(), 7); !errors.Is(err, ErrNoProviderSubscription) {
		t.Fatalf("err = %v", err)
	}
}

func TestProviderSubscriptionService_ChangePlan(t *testing.T) {
	store := &fakeSubStore{sub: annualSub, prices: map[string]string{"STANDARD": "price_s", "PRO": "price_p"}}
	client := &fakeSubClient{}
	s, life, _ := newSubService(store, client)
	outcome, err := s.ChangePlan(context.Background(), 7, "PRO")
	if err != nil {
		t.Fatal(err)
	}
	if outcome != ChangeApplied || client.from != "price_s" || client.to != "price_p" || client.proration != "always_invoice" || life.changedTo != "PRO" {
		t.Fatalf("outcome=%q client=%+v local=%q", outcome, client, life.changedTo)
	}

	unpricedStore := &fakeSubStore{sub: annualSub, prices: store.prices, modes: map[string]ActivationMode{"GOLD": ActivateCreateActive}}
	unpriced, unpricedLife, _ := newSubService(unpricedStore, &fakeSubClient{})
	if _, err := unpriced.ChangePlan(context.Background(), 7, "GOLD"); !errors.Is(err, ErrPriceNotFound) || unpricedLife.changedTo != "" {
		t.Fatalf("unpriced plan: err=%v local=%q", err, unpricedLife.changedTo)
	}

	manual, manualLife, _ := newSubService(&fakeSubStore{sub: &ProviderSubscription{PlanID: "STANDARD"}, prices: store.prices}, &fakeSubClient{})
	if _, err := manual.ChangePlan(context.Background(), 7, "PRO"); !errors.Is(err, ErrNoProviderSubscription) || manualLife.changedTo != "" {
		t.Fatalf("paid change without provider subscription: err=%v local=%q", err, manualLife.changedTo)
	}
}

// Re-selecting the current plan undoes a scheduled downgrade: the provider
// resumes renewal on the current price and the local schedule is cleared.
func TestProviderSubscriptionService_ReselectCurrentPlanResumesRenewal(t *testing.T) {
	client := &fakeSubClient{}
	s, life, _ := newSubService(&fakeSubStore{sub: annualSub, prices: map[string]string{"STANDARD": "price_s"}}, client)
	outcome, err := s.ChangePlan(context.Background(), 7, "STANDARD")
	if err != nil {
		t.Fatal(err)
	}
	if outcome != ChangeApplied || client.from != "price_s" || client.to != "price_s" || client.proration != "" || !life.resumed || life.changedTo != "" {
		t.Fatalf("outcome=%q client=%+v resumed=%v changed=%q", outcome, client, life.resumed, life.changedTo)
	}

	failing, failLife, _ := newSubService(&fakeSubStore{sub: annualSub, prices: map[string]string{"STANDARD": "price_s"}}, &fakeSubClient{err: errors.New("stripe down")})
	if _, err := failing.ChangePlan(context.Background(), 7, "STANDARD"); err == nil || failLife.resumed {
		t.Fatalf("provider failure: err=%v resumed=%v", err, failLife.resumed)
	}

	manualClient := &fakeSubClient{}
	manual, manualLife, _ := newSubService(&fakeSubStore{sub: &ProviderSubscription{PlanID: "FREE"}, modes: map[string]ActivationMode{"FREE": ActivateFree}}, manualClient)
	if _, err := manual.ChangePlan(context.Background(), 7, "FREE"); err != nil || !manualLife.resumed || manualClient.to != "" {
		t.Fatalf("not provider-held: err=%v resumed=%v client=%+v", err, manualLife.resumed, manualClient)
	}
}

// A downgrade below what the partner holds is refused before the provider
// is touched, so it bills nothing.
func TestProviderSubscriptionService_RefusesOverTargetLimit(t *testing.T) {
	client := &fakeSubClient{}
	store := &fakeSubStore{sub: annualSub, prices: map[string]string{"STANDARD": "price_s", "BASIC": "price_b"}}
	s, life, _ := newSubService(store, client)
	life.overages = []port.QuotaOverage{{Resource: "MAX_LOCATIONS", Count: 3, Limit: 1}}
	_, err := s.ChangePlan(context.Background(), 7, "BASIC")
	var over *OverTargetLimitError
	if !errors.As(err, &over) || !errors.Is(err, ErrOverTargetLimit) || over.Overages[0].Count != 3 {
		t.Fatalf("err = %v", err)
	}
	if client.to != "" || life.changedTo != "" {
		t.Fatalf("refused change reached provider=%q local=%q", client.to, life.changedTo)
	}
	if got, _ := s.CheckChange(context.Background(), 7, "BASIC"); len(got) != 1 {
		t.Fatalf("preview = %v", got)
	}
}

func TestProviderSubscriptionService_ChangeToFree(t *testing.T) {
	free := map[string]ActivationMode{"FREE": ActivateFree}

	client := &fakeSubClient{}
	s, life, _ := newSubService(&fakeSubStore{sub: annualSub, modes: free}, client)
	outcome, err := s.ChangePlan(context.Background(), 7, "FREE")
	if err != nil {
		t.Fatal(err)
	}
	if outcome != ChangeScheduled || client.cancelled != "sub_1" || life.scheduledTo != "FREE" || life.changedTo != "" || client.to != "" {
		t.Fatalf("provider-held: outcome=%q cancelled=%q scheduled=%q changed=%q", outcome, client.cancelled, life.scheduledTo, life.changedTo)
	}

	failing, failLife, _ := newSubService(&fakeSubStore{sub: annualSub, modes: free}, &fakeSubClient{err: errors.New("stripe down")})
	if _, err := failing.ChangePlan(context.Background(), 7, "FREE"); err == nil || failLife.scheduledTo != "" {
		t.Fatalf("provider failure: err=%v scheduled=%q", err, failLife.scheduledTo)
	}

	manualClient := &fakeSubClient{}
	manual, manualLife, _ := newSubService(&fakeSubStore{sub: &ProviderSubscription{PlanID: "STANDARD"}, modes: free}, manualClient)
	outcome, err = manual.ChangePlan(context.Background(), 7, "FREE")
	if err != nil {
		t.Fatal(err)
	}
	if outcome != ChangeApplied || manualLife.changedTo != "FREE" || manualLife.scheduledTo != "" || manualClient.cancelled != "" {
		t.Fatalf("not provider-held: outcome=%q changed=%q scheduled=%q", outcome, manualLife.changedTo, manualLife.scheduledTo)
	}

	none, noneLife, _ := newSubService(&fakeSubStore{modes: free}, &fakeSubClient{})
	if outcome, err := none.ChangePlan(context.Background(), 7, "FREE"); err != nil || outcome != ChangeApplied || noneLife.changedTo != "FREE" {
		t.Fatalf("no subscription: err=%v outcome=%q changed=%q", err, outcome, noneLife.changedTo)
	}

	unknown, _, _ := newSubService(&fakeSubStore{sub: annualSub}, &fakeSubClient{})
	if _, err := unknown.ChangePlan(context.Background(), 7, "GONE"); !errors.Is(err, ErrPlanNotFound) {
		t.Fatalf("unknown plan: err = %v", err)
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

func TestCurrentSubscriptionAndPrice(t *testing.T) {
	svc, _ := newSvc(map[string][][]any{
		qBillActiveProvSub: {{"sub_1", "STANDARD", "A", "A", int64(1)}},
		qBillProviderPrice: {{""}},
	})
	sub, err := svc.CurrentSubscription(context.Background(), 7)
	if err != nil || sub == nil || sub.ID != "sub_1" || sub.Terms.TermType != PeriodAnnual {
		t.Fatalf("sub=%+v err=%v", sub, err)
	}
	if _, err := svc.ProviderPriceID(context.Background(), "STANDARD", sub.Terms); !errors.Is(err, ErrPriceNotFound) {
		t.Fatalf("empty price id: err = %v", err)
	}

	none, _ := newSvc(map[string][][]any{})
	if _, err := none.CurrentSubscription(context.Background(), 7); !errors.Is(err, ErrNoSubscription) {
		t.Fatalf("no subscription: err = %v", err)
	}
	manual, _ := newSvc(map[string][][]any{qBillActiveProvSub: {{"", "FREE", "A", "A", int64(1)}}})
	if sub, err := manual.CurrentSubscription(context.Background(), 7); err != nil || sub.ID != "" || sub.PlanID != "FREE" {
		t.Fatalf("manual subscription: sub=%+v err=%v", sub, err)
	}
}
