package messaging

import "testing"

func TestConsumerConfigNamesDurable(t *testing.T) {
	for subscription, want := range map[string][2]string{
		"ride.completed": {"ride_completed", "ride.completed"},
		"orders":         {"orders", ""},
	} {
		cfg := consumerConfig(subscription)
		if cfg.Durable != want[0] || cfg.FilterSubject != want[1] {
			t.Errorf("%s: durable %q filter %q, want %q %q", subscription, cfg.Durable, cfg.FilterSubject, want[0], want[1])
		}
	}
}
