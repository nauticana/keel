package notify

import (
	"context"
	"errors"
	"slices"
	"testing"
)

func newQueue(store *memStore) *Queue {
	return &Queue{
		DB: memRepo{store: store},
		Channels: func(string) []string {
			return []string{"inbox", "email"}
		},
		ForcedChannels: func(notificationType string) []string {
			if notificationType == "security" {
				return []string{"sms", "email"}
			}
			return nil
		},
	}
}

func channelsOf(store *memStore, ids []int64) []string {
	var out []string
	for _, id := range ids {
		out = append(out, store.rows[id].channel)
	}
	return out
}

func TestEnqueue_ChannelsWithoutPreferences(t *testing.T) {
	store := newMemStore()
	ids, err := newQueue(store).Enqueue(context.Background(), 7, "order", Message{PartnerID: 3, Title: "Shipped", Data: map[string]string{"order": "9"}})
	if err != nil {
		t.Fatal(err)
	}
	if got := channelsOf(store, ids); !slices.Equal(got, []string{"inbox", "email"}) {
		t.Fatalf("channels = %v", got)
	}
	r := store.rows[ids[0]]
	if r.userID != 7 || r.partnerID != int64(3) || r.data != `{"order":"9"}` || r.status != StatusPending {
		t.Fatalf("row = %+v", r)
	}
	if store.commits != 1 {
		t.Fatalf("commits = %d, want 1", store.commits)
	}
}

func TestEnqueue_PreferencesOptOutAndIn(t *testing.T) {
	store := newMemStore()
	q := newQueue(store)
	ctx := context.Background()
	if err := q.SetPreference(ctx, 7, "order", "email", false); err != nil {
		t.Fatal(err)
	}
	if err := q.SetPreference(ctx, 7, "order", "push", true); err != nil {
		t.Fatal(err)
	}
	ids, err := q.Enqueue(ctx, 7, "order", Message{Title: "Shipped"})
	if err != nil {
		t.Fatal(err)
	}
	if got := channelsOf(store, ids); !slices.Equal(got, []string{"push", "inbox"}) {
		t.Fatalf("channels = %v, want push (opted in) and inbox; email opted out", got)
	}
	if store.rows[ids[0]].partnerID != nil {
		t.Fatal("zero partner must be stored NULL")
	}
}

func TestEnqueue_ForcedChannelIgnoresOptOut(t *testing.T) {
	store := newMemStore()
	q := newQueue(store)
	ctx := context.Background()
	for _, c := range []string{"sms", "email", "inbox"} {
		if err := q.SetPreference(ctx, 7, "security", c, false); err != nil {
			t.Fatal(err)
		}
	}
	ids, err := q.Enqueue(ctx, 7, "security", Message{Title: "New sign-in"})
	if err != nil {
		t.Fatal(err)
	}
	if got := channelsOf(store, ids); !slices.Equal(got, []string{"sms", "email"}) {
		t.Fatalf("channels = %v, want the forced sms and email only", got)
	}
}

func TestEnqueue_AllOptedOutQueuesNothing(t *testing.T) {
	store := newMemStore()
	q := &Queue{DB: memRepo{store: store}, Channels: func(string) []string { return []string{"email"} }}
	ctx := context.Background()
	_ = q.SetPreference(ctx, 7, "digest", "email", false)
	ids, err := q.Enqueue(ctx, 7, "digest", Message{Title: "Weekly"})
	if err != nil || len(ids) != 0 || len(store.rows) != 0 {
		t.Fatalf("ids=%v rows=%d err=%v, want nothing queued", ids, len(store.rows), err)
	}
}

func TestEnqueue_RejectsInvalidMessage(t *testing.T) {
	store := newMemStore()
	q := newQueue(store)
	for _, tc := range []struct {
		user int
		typ  string
		msg  Message
	}{{0, "order", Message{Title: "x"}}, {7, "", Message{Title: "x"}}, {7, "order", Message{}}} {
		if _, err := q.Enqueue(context.Background(), tc.user, tc.typ, tc.msg); !errors.Is(err, ErrInvalidMessage) {
			t.Fatalf("Enqueue(%d, %q, %+v) err = %v, want ErrInvalidMessage", tc.user, tc.typ, tc.msg, err)
		}
	}
	if store.commits != 0 || store.rollbacks != 3 {
		t.Fatalf("commits=%d rollbacks=%d, want 0/3", store.commits, store.rollbacks)
	}
}

func TestEnqueue_InsertFailureRollsBack(t *testing.T) {
	store := newMemStore()
	store.failOn = qInsert
	if _, err := newQueue(store).Enqueue(context.Background(), 7, "order", Message{Title: "x"}); err == nil {
		t.Fatal("want insert error")
	}
	if store.commits != 0 || store.rollbacks != 1 {
		t.Fatalf("commits=%d rollbacks=%d, want 0/1", store.commits, store.rollbacks)
	}
}

func TestPreferences_ListsExplicitChoices(t *testing.T) {
	store := newMemStore()
	q := newQueue(store)
	ctx := context.Background()
	_ = q.SetPreference(ctx, 7, "order", "email", false)
	_ = q.SetPreference(ctx, 7, "order", "email", true)
	_ = q.SetPreference(ctx, 8, "order", "sms", true)
	prefs, err := q.Preferences(ctx, 7)
	if err != nil {
		t.Fatal(err)
	}
	if len(prefs) != 1 || prefs[0] != (Preference{NotificationType: "order", Channel: "email", Enabled: true}) {
		t.Fatalf("prefs = %+v", prefs)
	}
	if err := q.SetPreference(ctx, 7, "order", "", true); !errors.Is(err, ErrInvalidChannel) {
		t.Fatalf("err = %v, want ErrInvalidChannel", err)
	}
}

type fakeRecipients struct{ email, phone string }

func (r fakeRecipients) EmailFor(int) (string, error) { return r.email, nil }
func (r fakeRecipients) PhoneFor(int) (string, error) { return r.phone, nil }

func TestEnqueue_SkipsUnaddressableChannels(t *testing.T) {
	store := newMemStore()
	q := newQueue(store)
	q.Addressable = RecipientAddressable(fakeRecipients{phone: "+15550100"})
	ids, err := q.Enqueue(context.Background(), 7, "security", Message{Title: "Sign-in"})
	if err != nil {
		t.Fatal(err)
	}
	if got := channelsOf(store, ids); !slices.Equal(got, []string{"inbox", "sms"}) {
		t.Fatalf("channels = %v, want inbox and sms; forced email has no address", got)
	}
}
