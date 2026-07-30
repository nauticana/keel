// Package metrics provides adapters from port.MetricsRecorder to monitoring
// backends.
package metrics

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"sync"
	"unicode/utf8"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/port"
	"github.com/prometheus/client_golang/prometheus"
)

type collectorKey struct {
	kind port.MetricKind
	name string
}

type registeredCollector struct {
	labelNames []string
	counter    *prometheus.CounterVec
	histogram  *prometheus.HistogramVec
}

// PrometheusRecorder records MetricsRecorder measurements in a Prometheus
// registry. Collectors are registered on first use so downstream services can
// add measurements without rebuilding a central catalogue.
//
// Request ids are attached as exemplars when present in ctx. They are never
// ordinary labels: putting a unique id in a label would create an unbounded
// time-series cardinality.
type PrometheusRecorder struct {
	registerer prometheus.Registerer

	mu         sync.Mutex
	collectors map[collectorKey]*registeredCollector
}

// NewPrometheusRecorder constructs a recorder for a registerer owned by the
// downstream runtime. Keel does not create a registry or expose a scrape
// endpoint.
func NewPrometheusRecorder(registerer prometheus.Registerer) (*PrometheusRecorder, error) {
	if registerer == nil {
		return nil, fmt.Errorf("metrics: Prometheus registerer is required")
	}
	return &PrometheusRecorder{
		registerer: registerer,
		collectors: make(map[collectorKey]*registeredCollector),
	}, nil
}

// RecordMetric records one counter increment or histogram observation.
func (r *PrometheusRecorder) RecordMetric(ctx context.Context, measurement port.MetricMeasurement) error {
	if measurement.Name == "" {
		return fmt.Errorf("metrics: metric name is required")
	}
	if measurement.Help == "" {
		return fmt.Errorf("metrics: help is required for %s", measurement.Name)
	}
	if measurement.Kind == port.MetricCounter && measurement.Value < 0 {
		return fmt.Errorf("metrics: counter %s cannot decrease", measurement.Name)
	}

	labelNames := slices.Sorted(maps.Keys(measurement.Labels))
	collector, err := r.collector(measurement, labelNames)
	if err != nil {
		return err
	}
	labelValues := make([]string, len(labelNames))
	for i, name := range labelNames {
		labelValues[i] = measurement.Labels[name]
	}
	exemplar := prometheus.Labels{}
	if requestID := common.RequestIDFromContext(ctx); requestID != "" && utf8.RuneCountInString(requestID) <= 100 {
		exemplar["request_id"] = requestID
	}

	switch measurement.Kind {
	case port.MetricCounter:
		counter, err := collector.counter.GetMetricWithLabelValues(labelValues...)
		if err != nil {
			return fmt.Errorf("metrics: bind counter %s: %w", measurement.Name, err)
		}
		if len(exemplar) > 0 {
			counter.(prometheus.ExemplarAdder).AddWithExemplar(measurement.Value, exemplar)
		} else {
			counter.Add(measurement.Value)
		}
	case port.MetricHistogram:
		observer, err := collector.histogram.GetMetricWithLabelValues(labelValues...)
		if err != nil {
			return fmt.Errorf("metrics: bind histogram %s: %w", measurement.Name, err)
		}
		if len(exemplar) > 0 {
			observer.(prometheus.ExemplarObserver).ObserveWithExemplar(measurement.Value, exemplar)
		} else {
			observer.Observe(measurement.Value)
		}
	default:
		return fmt.Errorf("metrics: unsupported metric kind %q", measurement.Kind)
	}
	return nil
}

func (r *PrometheusRecorder) collector(measurement port.MetricMeasurement, labelNames []string) (*registeredCollector, error) {
	key := collectorKey{kind: measurement.Kind, name: measurement.Name}
	r.mu.Lock()
	defer r.mu.Unlock()

	if collector := r.collectors[key]; collector != nil {
		if !slices.Equal(collector.labelNames, labelNames) {
			return nil, fmt.Errorf("metrics: %s label names changed from %v to %v", measurement.Name, collector.labelNames, labelNames)
		}
		return collector, nil
	}

	collector := &registeredCollector{labelNames: slices.Clone(labelNames)}
	var prometheusCollector prometheus.Collector
	switch measurement.Kind {
	case port.MetricCounter:
		collector.counter = prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: measurement.Name,
			Help: measurement.Help,
		}, labelNames)
		prometheusCollector = collector.counter
	case port.MetricHistogram:
		collector.histogram = prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name: measurement.Name,
			Help: measurement.Help,
		}, labelNames)
		prometheusCollector = collector.histogram
	default:
		return nil, fmt.Errorf("metrics: unsupported metric kind %q", measurement.Kind)
	}
	if err := r.registerer.Register(prometheusCollector); err != nil {
		var alreadyRegistered prometheus.AlreadyRegisteredError
		if errors.As(err, &alreadyRegistered) {
			return nil, fmt.Errorf("metrics: %s is already registered outside this recorder", measurement.Name)
		}
		return nil, fmt.Errorf("metrics: register %s: %w", measurement.Name, err)
	}
	r.collectors[key] = collector
	return collector, nil
}

var _ port.MetricsRecorder = (*PrometheusRecorder)(nil)
