package metrics

import (
	"log"
	"net/http"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/nauticana/keel/config"
	"github.com/nauticana/keel/port"
)

var (
	fromFlagsOnce sync.Once
	fromFlagsRec  port.MetricsRecorder
)

// NewRecorderFromFlags builds the process-wide recorder selected by the
// framework flags, once per process; repeated calls return the same instance.
// Today the only backend is Prometheus: a PrometheusRecorder over the default
// registry, with /metrics served on the metrics_addr flag from a dedicated
// goroutine so worker binaries and HTTP servers share one wiring. An empty
// metrics_addr disables metrics and returns nil; callers must treat a nil
// recorder as a no-op. Call after the configuration is loaded.
func NewRecorderFromFlags() port.MetricsRecorder {
	cfg := config.Config()
	if cfg == nil || cfg.MetricsAddr == "" {
		return nil
	}
	fromFlagsOnce.Do(func() {
		recorder, err := NewPrometheusRecorder(prometheus.DefaultRegisterer)
		if err != nil {
			log.Printf("metrics: %v", err)
			return
		}
		fromFlagsRec = recorder
		addr := cfg.MetricsAddr
		go func() {
			mux := http.NewServeMux()
			mux.Handle("/metrics", promhttp.Handler())
			log.Printf("metrics listening on %s", addr)
			if err := http.ListenAndServe(addr, mux); err != nil {
				log.Printf("metrics listener %s: %v", addr, err)
			}
		}()
	})
	return fromFlagsRec
}
