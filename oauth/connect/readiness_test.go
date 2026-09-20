package connect

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nauticana/keel/model"
	"github.com/nauticana/keel/oauth/client"
)

type fakeLister struct {
	providers []string
	err       error
	partner   int64
}

func (f *fakeLister) ConnectedProviders(_ context.Context, partnerID int64) ([]string, error) {
	f.partner = partnerID
	return f.providers, f.err
}

var testSources = []Source{
	{ID: "reviews", Collected: true},
	{ID: "search_stats", Provider: "gsc", Collected: true},
	{ID: "listing_metric", Provider: "gbp", Collected: true},
	{ID: "citations"},
	{ID: "listing_photo", Provider: "gsc"},
}

func TestReadinessResolverDistinguishesStates(t *testing.T) {
	lister := &fakeLister{providers: []string{"gsc"}}
	r, err := NewReadinessResolver(lister, testSources)
	if err != nil {
		t.Fatal(err)
	}
	got, err := r.Resolve(context.Background(), 7)
	if err != nil {
		t.Fatal(err)
	}
	want := SourceReadiness{
		"reviews":        SourceReady,
		"search_stats":   SourceReady,
		"listing_metric": SourceNotConnected,
		"citations":      SourceNotCollected,
		"listing_photo":  SourceNotCollected, // connected, but nothing collects it
	}
	if !reflect.DeepEqual(got, want) || lister.partner != 7 {
		t.Fatalf("readiness = %v (partner %d)", got, lister.partner)
	}
	if got.Ready("listing_metric") || got.Ready("citations") || !got.Ready("reviews") {
		t.Fatal("Ready disagrees with states")
	}
	if !got.Ready("uncatalogued") {
		t.Fatal("an uncatalogued source must not read as unavailable")
	}
	if _, known := got.State("uncatalogued"); known {
		t.Fatal("uncatalogued source reported as known")
	}
}

func TestReadinessResolverSurfacesLookupFailure(t *testing.T) {
	r, _ := NewReadinessResolver(&fakeLister{err: errors.New("db down")}, testSources)
	got, err := r.Resolve(context.Background(), 1)
	if err == nil || got != nil {
		t.Fatalf("got %v, err %v", got, err)
	}
}

func TestNewReadinessResolverValidatesCatalog(t *testing.T) {
	if _, err := NewReadinessResolver(nil, testSources); err == nil {
		t.Fatal("nil lister accepted")
	}
	if _, err := NewReadinessResolver(&fakeLister{}, []Source{{ID: ""}}); err == nil {
		t.Fatal("empty id accepted")
	}
	if _, err := NewReadinessResolver(&fakeLister{}, []Source{{ID: "a"}, {ID: "a"}}); err == nil {
		t.Fatal("duplicate id accepted")
	}
}

func TestConnectedProvidersScopesEntity(t *testing.T) {
	s, qs := newTestStore(t)
	qs.next[qConnectedProviders] = &model.QueryResult{Rows: [][]any{{"gsc"}, {"shopify"}}}
	got, err := s.ConnectedProviders(client.WithEntity(context.Background(), 5), 9)
	if err != nil || !reflect.DeepEqual(got, []string{"gsc", "shopify"}) {
		t.Fatalf("providers = %v, %v", got, err)
	}
	call, _ := qs.last(qConnectedProviders)
	if !reflect.DeepEqual(call.args, []any{int64(9), int64(5)}) {
		t.Fatalf("args = %v", call.args)
	}
}

func TestResolveAccess(t *testing.T) {
	ctx := context.Background()

	t.Run("no active connection", func(t *testing.T) {
		s, _ := newTestStore(t)
		if _, _, err := s.ResolveAccess(ctx, 1, "shopify"); !errors.Is(err, ErrNoActiveConnection) {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("api key returns stored credential", func(t *testing.T) {
		s, qs := newTestStore(t)
		sealed, _ := s.seal("api-key")
		qs.next[qActiveConnection] = &model.QueryResult{Rows: [][]any{{"K", sealed, "https://shop/admin", int64(2)}}}
		token, endpoint, err := s.ResolveAccess(ctx, 1, "shopify")
		if err != nil || token != "api-key" || endpoint != "https://shop/admin" {
			t.Fatalf("got %q %q %v", token, endpoint, err)
		}
	})

}

// oauthStore is a store whose active connection is an OAuth row at rev, with a
// claimable lease and a Refresher that counts exchanges.
func oauthStore(t *testing.T, rev int64) (*CredentialStoreDB, *fakeQS, *atomic.Int32) {
	t.Helper()
	s, qs := newTestStore(t)
	s.claimBackoff = time.Millisecond
	sealed, _ := s.seal("refresh-tok")
	qs.next[qActiveConnection] = &model.QueryResult{Rows: [][]any{{"O", "unused", "https://api", rev}}}
	qs.next[qClaim] = &model.QueryResult{Rows: [][]any{{sealed}}}
	exchanges := &atomic.Int32{}
	s.Refresh = func(_ context.Context, _, refresh string) (RefreshResult, error) {
		exchanges.Add(1)
		return RefreshResult{AccessToken: "access-for-" + refresh, ExpiresIn: time.Hour}, nil
	}
	return s, qs, exchanges
}

func setRev(qs *fakeQS, rev int64) {
	qs.next[qActiveConnection] = &model.QueryResult{Rows: [][]any{{"O", "unused", "https://api", rev}}}
}

func TestResolveAccessOAuthClaimsThenServesFromCache(t *testing.T) {
	ctx := context.Background()
	s, qs, exchanges := oauthStore(t, 3)

	token, endpoint, err := s.ResolveAccess(ctx, 1, "gsc")
	if err != nil || token != "access-for-refresh-tok" || endpoint != "https://api" {
		t.Fatalf("got %q %q %v", token, endpoint, err)
	}
	claim, _ := qs.last(qClaim)
	if claim.args[4] != 3 {
		t.Fatalf("claimed at rev %v, want 3", claim.args[4])
	}
	if done, _ := qs.last(qCompleteCAS); done.args[3] != 4 {
		t.Fatalf("completed on rev %v, want the claimed rev 4", done.args[3])
	}

	setRev(qs, 5) // claim + completion each bumped rev
	if token, _, err = s.ResolveAccess(ctx, 1, "gsc"); err != nil || token != "access-for-refresh-tok" {
		t.Fatalf("cached: got %q %v", token, err)
	}
	if exchanges.Load() != 1 || qs.count(qClaim) != 1 {
		t.Fatalf("exchanges=%d claims=%d, want 1 each", exchanges.Load(), qs.count(qClaim))
	}

	setRev(qs, 7) // refreshed or reauthorized elsewhere
	if _, _, err = s.ResolveAccess(ctx, 1, "gsc"); err != nil || exchanges.Load() != 2 {
		t.Fatalf("after rev moved: exchanges=%d err=%v", exchanges.Load(), err)
	}
}

func TestResolveAccessCacheIsScopedToEntity(t *testing.T) {
	s, _, exchanges := oauthStore(t, 1)
	if _, _, err := s.ResolveAccess(context.Background(), 1, "gsc"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.ResolveAccess(client.WithEntity(context.Background(), 9), 1, "gsc"); err != nil {
		t.Fatal(err)
	}
	if exchanges.Load() != 2 {
		t.Fatalf("exchanges = %d, want one per entity", exchanges.Load())
	}
}

func TestResolveAccessSkipsCacheWhenTokenExpiresInsideSkew(t *testing.T) {
	s, qs, exchanges := oauthStore(t, 1)
	s.Refresh = func(context.Context, string, string) (RefreshResult, error) {
		exchanges.Add(1)
		return RefreshResult{AccessToken: "short", ExpiresIn: accessExpirySkew}, nil
	}
	for range 2 {
		if _, _, err := s.ResolveAccess(context.Background(), 1, "gsc"); err != nil {
			t.Fatal(err)
		}
		setRev(qs, 3)
	}
	if exchanges.Load() != 2 {
		t.Fatalf("exchanges = %d, want 2", exchanges.Load())
	}
}

func TestResolveAccessLeaseHeldElsewhere(t *testing.T) {
	s, qs, exchanges := oauthStore(t, 3)
	delete(qs.next, qClaim) // every claim loses
	_, _, err := s.ResolveAccess(context.Background(), 1, "gsc")
	if !errors.Is(err, ErrRefreshInProgress) {
		t.Fatalf("err = %v", err)
	}
	if exchanges.Load() != 0 || qs.count(qClaim) != claimAttempts {
		t.Fatalf("exchanges=%d claims=%d", exchanges.Load(), qs.count(qClaim))
	}
	if qs.count(qMarkErroredCAS) != 0 {
		t.Fatal("a lost claim must not mark the credential errored")
	}
}

func TestResolveAccessRetriesAfterLostClaim(t *testing.T) {
	s, qs, exchanges := oauthStore(t, 3)
	won := qs.next[qClaim]
	delete(qs.next, qClaim)
	claims := 0
	qs.hook = func(name string) {
		if name != qClaim {
			return
		}
		if claims++; claims == 2 {
			qs.next[qClaim] = won
		}
	}
	token, _, err := s.ResolveAccess(context.Background(), 1, "gsc")
	if err != nil || token != "access-for-refresh-tok" || exchanges.Load() != 1 {
		t.Fatalf("got %q %v exchanges=%d", token, err, exchanges.Load())
	}
}

func TestResolveAccessStopsOnContextCancel(t *testing.T) {
	s, qs, _ := oauthStore(t, 3)
	delete(qs.next, qClaim)
	s.claimBackoff = time.Hour
	ctx, cancel := context.WithCancel(context.Background())
	qs.hook = func(name string) {
		if name == qClaim {
			cancel()
		}
	}
	if _, _, err := s.ResolveAccess(ctx, 1, "gsc"); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v", err)
	}
}

func TestResolveAccessConcurrentCallersShareOneExchange(t *testing.T) {
	s, _, exchanges := oauthStore(t, 3)
	release := make(chan struct{})
	refresh := s.Refresh
	s.Refresh = func(ctx context.Context, provider, token string) (RefreshResult, error) {
		<-release
		return refresh(ctx, provider, token)
	}
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			token, _, err := s.ResolveAccess(context.Background(), 1, "gsc")
			if err == nil && token != "access-for-refresh-tok" {
				err = errors.New("token = " + token)
			}
			errs <- err
		}()
	}
	time.Sleep(20 * time.Millisecond) // let callers pile onto the flight
	close(release)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if exchanges.Load() != 1 {
		t.Fatalf("exchanges = %d, want 1", exchanges.Load())
	}
}

func TestResolveAccessExchangeFailureMarksErroredOnClaimedRev(t *testing.T) {
	s, qs, _ := oauthStore(t, 3)
	s.Refresh = func(context.Context, string, string) (RefreshResult, error) {
		return RefreshResult{}, errors.New("invalid_grant")
	}
	if _, _, err := s.ResolveAccess(context.Background(), 1, "gsc"); err == nil || errors.Is(err, ErrRefreshInProgress) {
		t.Fatalf("err = %v", err)
	}
	if marked, ok := qs.last(qMarkErroredCAS); !ok || marked.args[3] != 4 {
		t.Fatalf("markErrored = %+v", marked)
	}
}

func TestResolveAccessOAuthWithoutRefresherReturnsStoredCredential(t *testing.T) {
	s, qs := newTestStore(t)
	sealed, _ := s.seal("long-lived")
	qs.next[qActiveConnection] = &model.QueryResult{Rows: [][]any{{"O", sealed, "https://api", int64(1)}}}
	token, _, err := s.ResolveAccess(context.Background(), 1, "meta")
	if err != nil || token != "long-lived" || qs.count(qClaim) != 0 {
		t.Fatalf("got %q %v claims=%d", token, err, qs.count(qClaim))
	}
}
