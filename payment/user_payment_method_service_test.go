package payment

import (
	"context"
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
		c := &StripeSetupIntentCardClient{Client: cannedStripeGet(`{"payment_method":{"card":{"last4":"4242","brand":"visa","exp_month":4,"exp_year":2030` + wallet + `}}}`)}
		card, ok := c.GetSetupIntentCard(context.Background(), "seti_1")
		if !ok || card.MethodType != want || card.Last4 != "4242" || card.ExpYear != 2030 {
			t.Errorf("wallet %q: %+v, %v", wallet, card, ok)
		}
	}
}

func TestRecordFromSetupIntent_MethodType(t *testing.T) {
	for name, client := range map[string]SetupIntentCardClient{
		"apple pay": &StripeSetupIntentCardClient{Client: cannedStripeGet(`{"payment_method":{"card":{"last4":"1111","wallet":{"type":"apple_pay"}}}}`)},
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
