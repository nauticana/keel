package messaging

import (
	"context"
	"testing"

	"github.com/nauticana/keel/common"
)

func TestNoOpModeIsExplicit(t *testing.T) {
	publisher, err := NewMessagePublisher(context.Background(), "noop", nil)
	if err != nil || publisher == nil {
		t.Fatalf("publisher=%v err=%v", publisher, err)
	}
	if err := publisher.Publish(context.Background(), "topic", []byte("payload"), nil); err != nil {
		t.Fatal(err)
	}
	if _, err := NewMessageSubscriber(context.Background(), "noop", nil); err == nil {
		t.Fatal("subscriber has no noop mode")
	}
}

func TestMisconfigurationStillFails(t *testing.T) {
	old := *common.ProjectID
	*common.ProjectID = ""
	t.Cleanup(func() { *common.ProjectID = old })
	for _, mode := range []string{"", "unknown", "gcp"} {
		if _, err := NewMessagePublisher(context.Background(), mode, nil); err == nil {
			t.Fatalf("publisher mode=%q unexpectedly succeeded", mode)
		}
	}
}
