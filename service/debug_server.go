package service

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"runtime/pprof"
	"strconv"
	"time"

	"github.com/nauticana/keel/config"
	"github.com/nauticana/keel/logger"
)

// DebugServer serves the runtime profiles at /debug/pprof/{name}, for example
// goroutine, heap or goroutineleak, on 127.0.0.1:debug_port. It never binds a
// public interface: profiles expose memory contents.
type DebugServer struct {
	Journal logger.ApplicationLogger
}

// Start serves until ctx ends; a debug_port of 0 disables it.
func (d *DebugServer) Start(ctx context.Context) {
	port := config.Config().DebugPort
	if port == 0 {
		return
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /debug/pprof/{name}", d.serveProfile)
	srv := &http.Server{Addr: net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			d.Journal.Error("debug listener: " + err.Error())
		}
	}()
	context.AfterFunc(ctx, func() { _ = srv.Close() })
}

// serveProfile writes a named profile; ?debug=1 or 2 selects the text forms.
func (d *DebugServer) serveProfile(w http.ResponseWriter, r *http.Request) {
	profile := pprof.Lookup(r.PathValue("name"))
	if profile == nil {
		http.NotFound(w, r)
		return
	}
	debug, _ := strconv.Atoi(r.URL.Query().Get("debug"))
	if debug > 0 {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	} else {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename=%q`, profile.Name()))
	}
	if err := profile.WriteTo(w, debug); err != nil {
		d.Journal.Warning("debug profile " + profile.Name() + ": " + err.Error())
	}
}

var _ http.HandlerFunc = (&DebugServer{}).serveProfile
