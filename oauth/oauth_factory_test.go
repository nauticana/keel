package oauth

import (
	"context"
	"errors"
	"testing"

	"github.com/nauticana/keel/config"
	"github.com/nauticana/keel/model"
	"github.com/nauticana/keel/oauth/authserver"
	"github.com/nauticana/keel/port"
)

type factoryDB struct {
	port.DatabaseRepository
}

func (d *factoryDB) GetQueryService(context.Context, map[string]string) port.QueryService {
	return d
}

func (d *factoryDB) BeginTx(context.Context, map[string]string) (port.TxQueryService, error) {
	return d, nil
}

func (d *factoryDB) Query(context.Context, string, ...any) (*model.QueryResult, error) {
	return &model.QueryResult{Rows: [][]any{{int64(1)}}}, nil
}

func (d *factoryDB) GenID() int64                   { return 0 }
func (d *factoryDB) Commit(context.Context) error   { return nil }
func (d *factoryDB) Rollback(context.Context) error { return nil }

func TestOAuthFactoryWiresPendingClientLimit(t *testing.T) {
	previous := config.Config()
	t.Cleanup(func() { config.SetConfig(previous) })
	config.SetConfig(&config.KeelConfig{
		OAuthASMode:            "local",
		OAuthIssuer:            "https://as.example",
		OAuthScopesSupported:   "read",
		OAuthMaxPendingClients: 1,
	})

	setup, err := NewOAuthFromConfig(context.Background(), &factoryDB{}, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	request := port.ClientRegistration{RedirectURIs: []string{"https://app.example/cb"}}
	if _, err := setup.AS.Register(context.Background(), request); !errors.Is(err, authserver.ErrOAuthClientLimit) {
		t.Fatalf("pending registration err = %v", err)
	}
	request.TokenAuthMethod = "client_secret_basic"
	if _, err := setup.AS.Register(context.Background(), request); !errors.Is(err, authserver.ErrOAuthInvalidRequest) {
		t.Fatalf("confidential registration err = %v", err)
	}
}
