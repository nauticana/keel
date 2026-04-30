package push

import (
	"context"
	"testing"
)

// TestNoOpPushProvider_DiscardsDispatch is a table-driven walk of
// the inputs Dispatch must tolerate without surfacing an error.
// NoOpPushProvider is wired into every consumer that doesn't have
// FCM credentials configured (local dev, non-mobile services), so
// any non-nil return here would fail-stop those services on every
// notification path — the opposite of the no-op contract.
//
// Cases cover the corners: empty strings, nil data, oversized
// payloads, and zero/negative user IDs (which a misconfigured
// caller might pass before a real provider would reject them).
func TestNoOpPushProvider_DiscardsDispatch(t *testing.T) {
	p := NoOpPushProvider{}
	ctx := context.Background()

	cases := []struct {
		name   string
		userID int
		title  string
		body   string
		data   map[string]string
	}{
		{"normal", 42, "Hello", "world", map[string]string{"k": "v"}},
		{"empty title", 1, "", "body", nil},
		{"empty body", 1, "title", "", nil},
		{"empty title and body", 1, "", "", nil},
		{"nil data", 1, "title", "body", nil},
		{"empty data map", 1, "title", "body", map[string]string{}},
		{"multi-key data", 1, "title", "body", map[string]string{"a": "1", "b": "2", "c": "3"}},
		{"unicode title", 1, "héllo 世界 🚀", "body", nil},
		{"large body", 1, "title", string(make([]byte, 4096)), nil},
		{"zero userID", 0, "title", "body", nil},
		{"negative userID", -1, "title", "body", nil},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := p.Dispatch(ctx, tc.userID, tc.title, tc.body, tc.data); err != nil {
				t.Errorf("NoOp must never error; got %v", err)
			}
		})
	}
}
