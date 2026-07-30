package metrics

import (
	"context"
	"testing"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/port"
	"github.com/prometheus/client_golang/prometheus"
)

func TestPrometheusRecorderRecordsCounterAndHistogram(t *testing.T) {
	registry := prometheus.NewRegistry()
	recorder, err := NewPrometheusRecorder(registry)
	if err != nil {
		t.Fatal(err)
	}
	ctx := common.WithRequestID(context.Background(), "req-123")
	labels := map[string]string{"provider": "stripe", "outcome": "processed"}

	if err := recorder.RecordMetric(ctx, port.MetricMeasurement{
		Name: "keel_test_total", Help: "Test counter.", Kind: port.MetricCounter, Value: 1, Labels: labels,
	}); err != nil {
		t.Fatal(err)
	}
	if err := recorder.RecordMetric(ctx, port.MetricMeasurement{
		Name: "keel_test_duration_seconds", Help: "Test duration.", Kind: port.MetricHistogram, Value: 0.25, Labels: labels,
	}); err != nil {
		t.Fatal(err)
	}

	families, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	if len(families) != 2 {
		t.Fatalf("metric families = %d, want 2", len(families))
	}
	foundRequestIDExemplar := false
	for _, family := range families {
		if len(family.Metric) != 1 {
			t.Fatalf("%s metrics = %d, want 1", family.GetName(), len(family.Metric))
		}
		metric := family.Metric[0]
		if exemplar := metric.GetCounter().GetExemplar(); exemplar != nil {
			for _, label := range exemplar.Label {
				if label.GetName() == "request_id" && label.GetValue() == "req-123" {
					foundRequestIDExemplar = true
				}
			}
		}
		if metric.Histogram != nil {
			for _, bucket := range metric.Histogram.Bucket {
				if bucket.Exemplar != nil {
					for _, label := range bucket.Exemplar.Label {
						if label.GetName() == "request_id" && label.GetValue() == "req-123" {
							foundRequestIDExemplar = true
						}
					}
				}
			}
		}
	}
	if !foundRequestIDExemplar {
		t.Fatal("request id exemplar was not recorded")
	}
}

func TestPrometheusRecorderRejectsLabelShapeChanges(t *testing.T) {
	recorder, err := NewPrometheusRecorder(prometheus.NewRegistry())
	if err != nil {
		t.Fatal(err)
	}
	first := port.MetricMeasurement{
		Name: "keel_shape_total", Help: "Shape test.", Kind: port.MetricCounter, Value: 1,
		Labels: map[string]string{"provider": "stripe"},
	}
	if err := recorder.RecordMetric(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	first.Labels["outcome"] = "processed"
	if err := recorder.RecordMetric(context.Background(), first); err == nil {
		t.Fatal("expected a label-shape error")
	}
}

func TestPrometheusRecorderRequiresOwnedRegisterer(t *testing.T) {
	if _, err := NewPrometheusRecorder(nil); err == nil {
		t.Fatal("expected nil registerer to fail")
	}
}
