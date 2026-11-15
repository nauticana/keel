package payment

import (
	"context"
	"errors"
	"net/url"
	"testing"

	"github.com/nauticana/keel/model"
	"github.com/nauticana/keel/port"
)

type cannedStripeGet string

func (b cannedStripeGet) Get(context.Context, string, url.Values) ([]byte, error) {
	return []byte(b), nil
}

type insertRecorder struct {
	port.DatabaseRepository
	args []any
}

func (r *insertRecorder) GetQueryService(context.Context, map[string]string) port.QueryService {
	return r
}

func (r *insertRecorder) Query(_ context.Context, _ string, args ...any) (*model.QueryResult, error) {
	r.args = args
	return &model.QueryResult{}, nil
}

func (r *insertRecorder) GenID() int64 { return 0 }

func TestStripeSetupIntentCard_WalletMethodType(t *testing.T) {
	for wallet, want := range map[string]string{
		``:                                 MethodTypeCard,
		`,"wallet":null`:                   MethodTypeCard,
		`,"wallet":{"type":"apple_pay"}`:   MethodTypeApplePay,
		`,"wallet":{"type":"google_pay"}`:  MethodTypeGooglePay,
		`,"wallet":{"type":"samsung_pay"}`: MethodTypeWallet,
	} {
		c := &StripeSetupIntentCardClient{Client: cannedStripeGet(`{"payment_method":{"type":"card","card":{"last4":"4242","brand":"visa","exp_month":4,"exp_year":2030` + wallet + `}}}`)}
		card, ok := c.GetSetupIntentCard(context.Background(), "seti_1")
		if !ok || card.MethodType != want || card.Last4 != "4242" || card.ExpYear != 2030 {
			t.Errorf("wallet %q: %+v, %v", wallet, card, ok)
		}
	}
}

func TestRecordFromSetupIntent_MethodType(t *testing.T) {
	for name, client := range map[string]SetupIntentCardClient{
		"apple pay": &StripeSetupIntentCardClient{Client: cannedStripeGet(`{"payment_method":{"type":"card","card":{"last4":"1111","wallet":{"type":"apple_pay"}}}}`)},
		"no client": nil,
	} {
		db := &insertRecorder{}
		s := &UserPaymentMethodService{DB: db, CardClient: client}
		if err := s.RecordFromSetupIntent(context.Background(), 7, ProviderStripe, "seti_1", ""); err != nil {
			t.Fatal(err)
		}
		want := MethodTypeCard
		if client != nil {
			want = MethodTypeApplePay
		}
		if db.args[1] != want {
			t.Errorf("%s: method_type = %v, want %s", name, db.args[1], want)
		}
	}
}

func TestRecordFromSetupIntent_NonCardMethods(t *testing.T) {
	for body, want := range map[string][]any{
		`{"payment_method":{"type":"us_bank_account","us_bank_account":{"bank_name":"STRIPE TEST BANK","last4":"6789"}}}`: {MethodTypeBank, "6789", "STRIPE TEST BANK"},
		`{"payment_method":{"type":"sepa_debit","sepa_debit":{"bank_code":"37040044","last4":"3000"}}}`:                   {MethodTypeBank, "3000", ""},
		`{"payment_method":{"type":"link","link":{"email":"a@b"}}}`:                                                       {MethodTypeLink, "", ""},
		`{"payment_method":{"type":"cashapp","cashapp":{}}}`:                                                              nil,
	} {
		db := &insertRecorder{}
		s := &UserPaymentMethodService{DB: db, CardClient: &StripeSetupIntentCardClient{Client: cannedStripeGet(body)}}
		err := s.RecordFromSetupIntent(context.Background(), 7, ProviderStripe, "seti_1", "")
		if want == nil {
			if !errors.Is(err, ErrUnsupportedPaymentMethod) || db.args != nil {
				t.Fatalf("%s: err = %v, recorded %v", body, err, db.args)
			}
			continue
		}
		if err != nil || db.args[1] != want[0] || db.args[4] != want[1] || db.args[5] != want[2] {
			t.Fatalf("%s: err = %v, recorded %v", body, err, db.args)
		}
	}
}
