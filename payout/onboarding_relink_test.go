package payout

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nauticana/keel/model"
	"github.com/nauticana/keel/port"
)

// bankInfoDB answers the onboarding queries with one user_bank_info row.
type bankInfoDB struct {
	port.DatabaseRepository
	accountID, onboardedAt string
	writes                 int
}

func (d *bankInfoDB) GetQueryService(context.Context, map[string]string) port.QueryService { return d }
func (d *bankInfoDB) GenID() int64                                                         { return 0 }

func (d *bankInfoDB) Query(_ context.Context, name string, _ ...any) (*model.QueryResult, error) {
	switch name {
	case qPayoutVerifyActiveIdx:
		return &model.QueryResult{Rows: [][]any{{"CREATE UNIQUE INDEX user_bank_info_active_uq ON user_bank_info (user_id, partner_id) WHERE (status = 'A')"}}}, nil
	case qPayoutBankInfo:
		var onboarded any
		if d.onboardedAt != "" {
			onboarded = d.onboardedAt
		}
		return &model.QueryResult{Rows: [][]any{{int64(1), "US", "USD", "Ada", "", ProviderCodeStripeConnect, d.accountID, "a@example.com", false, onboarded, int16(2)}}}, nil
	case qPayoutWriteExternal:
		d.writes++
		return &model.QueryResult{Rows: [][]any{{int64(1)}}}, nil
	}
	return &model.QueryResult{}, nil
}

func TestStartOnboardingRelinksUnfinishedAccount(t *testing.T) {
	db := &bankInfoDB{accountID: "acct_1"}
	provider := &fakeProvider{code: ProviderCodeStripeConnect, session: &PayoutOnboardingSession{URL: "https://stripe/onb", ExternalAccountID: "acct_1"}}
	svc := &OnboardingService{DB: db, Providers: NewStaticProviderResolver(provider)}
	out, err := svc.StartOnboarding(context.Background(), 7, 3)
	if err != nil || out.URL != "https://stripe/onb" {
		t.Fatalf("out=%+v err=%v, want a fresh link", out, err)
	}
	if len(provider.onboardings) != 1 || provider.onboardings[0].ExternalAccountID != "acct_1" || db.writes != 0 {
		t.Fatalf("inputs=%+v writes=%d, want the existing account relinked without a write", provider.onboardings, db.writes)
	}
}

func TestStartOnboardingRefusesOnboardedAccount(t *testing.T) {
	db := &bankInfoDB{accountID: "acct_1", onboardedAt: "2026-11-01"}
	provider := &fakeProvider{code: ProviderCodeStripeConnect, session: &PayoutOnboardingSession{}}
	svc := &OnboardingService{DB: db, Providers: NewStaticProviderResolver(provider)}
	if _, err := svc.StartOnboarding(context.Background(), 7, 3); !errors.Is(err, ErrAlreadyOnboarded) || len(provider.onboardings) != 0 {
		t.Fatalf("err=%v calls=%d, want ErrAlreadyOnboarded before the provider", err, len(provider.onboardings))
	}
}

func TestStripeConnectRelinkSkipsAccountCreation(t *testing.T) {
	var paths []string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		_, _ = w.Write([]byte(`{"url":"https://stripe/onb","expires_at":1700000000}`))
	}))
	defer ts.Close()
	p, _ := NewStripeConnectProvider("sk_test", "whsec", nil)
	p.apiBase = ts.URL
	sess, err := p.StartOnboarding(context.Background(), StartOnboardingInput{ExternalAccountID: "acct_9", ReturnURL: "https://app/return"})
	if err != nil || sess.ExternalAccountID != "acct_9" || strings.Join(paths, ",") != "/v1/account_links" {
		t.Fatalf("sess=%+v err=%v paths=%v, want only an account link for acct_9", sess, err, paths)
	}
}
