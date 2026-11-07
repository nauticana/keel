package service

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/model"
	"github.com/nauticana/keel/user"
)

func TestConsumeQuotaAttributesCaller(t *testing.T) {
	svc, _, tx := newQuotaSvc([][]any{{"API_CALLS", int64(-1), "D"}})
	ctx := common.WithCallerSession(context.Background(), common.CallerSession{
		UserID:    11,
		APIKeyID:  22,
		Principal: &model.TokenPrincipal{Subject: "user:11", Claims: map[string]any{"client_id": "mcp-client"}},
	})
	if allowed, _, err := svc.ConsumeQuota(ctx, 7, "API_CALLS", 3, "tool call"); err != nil || !allowed {
		t.Fatalf("allowed=%v err=%v", allowed, err)
	}
	args := tx.calls[tx.callIndex(qAddUsage)].args
	want := []any{int64(7), "API_CALLS", int64(3), "tool call", int64(11), int64(22), "mcp-client"}
	if len(args) != len(want) {
		t.Fatalf("args = %v", args)
	}
	for i := range want {
		if args[i] != want[i] {
			t.Fatalf("arg %d = %v, want %v (args %v)", i, args[i], want[i], args)
		}
	}
}

func TestLogUsageWithoutCallerBindsNulls(t *testing.T) {
	svc, qs, _ := newQuotaSvc(nil)
	if err := svc.LogUsage(context.Background(), 7, "REPORTS", 1, "worker"); err != nil {
		t.Fatal(err)
	}
	args := qs.calls[qs.callIndex(qAddUsage)].args
	if args[4] != nil || args[5] != nil || args[6] != nil {
		t.Fatalf("a worker without a caller must record NULL actors: %v", args)
	}
}

type ssoUsers struct{ user.UserService }

func (ssoUsers) ParseJWT(string) (*model.UserSession, error) {
	return &model.UserSession{Id: 9, PartnerId: 4}, nil
}

func TestSSOMiddlewareBindsSessionUser(t *testing.T) {
	var got any
	h := (&HttpBackend{UserService: ssoUsers{}}).SSOMiddleware(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		got = r.Context().Value(common.UserID)
	}))
	req := httptest.NewRequest(http.MethodGet, common.RestPrefix+"/v1/thing", nil)
	req.Header.Set("Authorization", "Bearer token")
	h.ServeHTTP(httptest.NewRecorder(), req)
	if got != int64(9) {
		t.Fatalf("context user = %v, want 9", got)
	}
}

func TestRecordUsageOnce(t *testing.T) {
	svc, qs, _ := newQuotaSvc(nil)
	ctx := context.Background()
	qs.rows[qAddUsageOnce] = [][]any{{int64(1)}}
	if recorded, err := svc.RecordUsageOnce(ctx, 7, "AI_CREDITS", "lic:1-10", 3, "report"); err != nil || !recorded {
		t.Fatalf("recorded=%v err=%v", recorded, err)
	}
	args := qs.calls[qs.callIndex(qAddUsageOnce)].args
	if len(args) != 8 || args[0] != int64(7) || args[2] != int64(3) || args[7] != "lic:1-10" {
		t.Fatalf("args = %v", args)
	}
	qs.rows[qAddUsageOnce] = nil
	if recorded, err := svc.RecordUsageOnce(ctx, 7, "AI_CREDITS", "lic:1-10", 3, "report"); err != nil || recorded {
		t.Fatalf("replay: recorded=%v err=%v, want false", recorded, err)
	}
	for _, c := range []struct {
		key    string
		amount int64
	}{{"", 1}, {" \t\n", 1}, {strings.Repeat("k", MaxUsageKeyLen+1), 1}, {"k", 0}, {"k", -1}} {
		if _, err := svc.RecordUsageOnce(ctx, 7, "AI_CREDITS", c.key, c.amount, ""); !errors.Is(err, ErrUsageKey) {
			t.Fatalf("key %q amount %d: err = %v", c.key, c.amount, err)
		}
	}
}
