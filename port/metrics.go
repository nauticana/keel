package port

import (
	"context"
	"time"
)

// MetricKind identifies how a MetricsRecorder aggregates one measurement.
type MetricKind string

const (
	MetricCounter   MetricKind = "counter"
	MetricHistogram MetricKind = "histogram"
)

// MetricMeasurement is one low-cardinality metric sample. Counter values must
// be non-negative. Histogram values are recorded as-is.
type MetricMeasurement struct {
	Name   string
	Help   string
	Kind   MetricKind
	Value  float64
	Labels map[string]string
}

// MetricsRecorder is the pluggable metrics boundary used by framework
// services. Implementations must be safe for concurrent use.
type MetricsRecorder interface {
	RecordMetric(ctx context.Context, measurement MetricMeasurement) error
}

// DurationSeconds converts a duration to the unit used by Prometheus duration
// histograms.
func DurationSeconds(duration time.Duration) float64 {
	return duration.Seconds()
}
