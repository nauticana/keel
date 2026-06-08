package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/logger"
	"github.com/nauticana/keel/port"
)

// FeatureAllowed reports whether a partner's plan includes a feature. Features
// are modeled as quota flags (subscription_quota.max_value -1 = included), so
// CheckQuota short-circuits on Limit < 0. Any error is treated as not-allowed
// (fail-closed).
func FeatureAllowed(ctx context.Context, quota port.QuotaService, partnerID int64, feature string) bool {
	allowed, err := quota.CheckQuota(ctx, partnerID, feature, 1)
	return err == nil && allowed
}

// FeatureGate gates premium data/endpoints by plan entitlement (the cap<0
// feature-flag convention). The project injects which features exist and,
// optionally, a (feature → response field) strip so a premium child collection
// is removed from a GET/LIST response for non-entitled partners.
type FeatureGate struct {
	AbstractHandler
	Quota   port.QuotaService
	Journal logger.ApplicationLogger

	// Features are reported by ListFeatures (the entitlements the session
	// partner's plan includes).
	Features []string

	// StripFeature + StripRecordKey configure FilterResponseField: when the
	// partner's plan does NOT include StripFeature, StripRecordKey is removed
	// from each record in the response envelope. Empty StripRecordKey disables
	// the strip (pass-through).
	StripFeature   string
	StripRecordKey string
}

// ListFeatures handles GET .../features — the features the session partner's
// plan includes. The frontend uses it to hide UI; the server is the gate.
func (g *FeatureGate) ListFeatures(w http.ResponseWriter, r *http.Request) {
	session, ok := g.RequireSession(w, r)
	if !ok {
		return
	}
	features := []string{}
	for _, f := range g.Features {
		if FeatureAllowed(r.Context(), g.Quota, session.PartnerId, f) {
			features = append(features, f)
		}
	}
	common.WriteJSON(w, http.StatusOK, map[string]any{"features": features})
}

// FilterResponseField wraps a GET/LIST handler: for a partner whose plan does
// not include StripFeature, it removes StripRecordKey from each record in the
// {data, …} response envelope. Entitled partners pass through without buffering.
func (g *FeatureGate) FilterResponseField(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if g.StripRecordKey == "" {
			next(w, r)
			return
		}
		session, ok := g.RequireSession(w, r)
		if !ok {
			return
		}
		if FeatureAllowed(r.Context(), g.Quota, session.PartnerId, g.StripFeature) {
			next(w, r)
			return
		}
		buf := &bufferingWriter{header: http.Header{}, status: http.StatusOK}
		next(buf, r)

		out, changed := stripEnvelopeField(buf.body.Bytes(), g.StripRecordKey)
		for k, vals := range buf.header {
			if k == "Content-Length" { // recomputed by the server on Write
				continue
			}
			for _, v := range vals {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(buf.status)
		if changed {
			w.Write(out)
		} else {
			w.Write(buf.body.Bytes())
		}
	}
}

// bufferingWriter captures a handler's response so it can be post-processed.
type bufferingWriter struct {
	header http.Header
	status int
	body   bytes.Buffer
	wrote  bool
}

func (b *bufferingWriter) Header() http.Header { return b.header }

func (b *bufferingWriter) WriteHeader(status int) {
	if !b.wrote {
		b.status = status
		b.wrote = true
	}
}

func (b *bufferingWriter) Write(p []byte) (int, error) {
	b.wrote = true
	return b.body.Write(p)
}

// stripEnvelopeField removes `field` from each record in the {data, …}
// envelope (data may be a record, an array, or a paginated {items:[…]} map).
// Returns (newBody, changed); on any parse error returns the original bytes so
// a response is never corrupted.
func stripEnvelopeField(body []byte, field string) ([]byte, bool) {
	var env map[string]any
	if json.Unmarshal(body, &env) != nil {
		return body, false
	}
	data, ok := env["data"]
	if !ok {
		return body, false
	}
	changed := false
	switch d := data.(type) {
	case map[string]any:
		if items, ok := d["items"].([]any); ok {
			changed = stripFieldRows(items, field)
		} else {
			changed = deleteField(d, field)
		}
	case []any:
		changed = stripFieldRows(d, field)
	}
	if !changed {
		return body, false
	}
	out, err := json.Marshal(env)
	if err != nil {
		return body, false
	}
	return out, true
}

func stripFieldRows(rows []any, field string) bool {
	changed := false
	for _, row := range rows {
		if m, ok := row.(map[string]any); ok && deleteField(m, field) {
			changed = true
		}
	}
	return changed
}

func deleteField(rec map[string]any, field string) bool {
	if _, ok := rec[field]; ok {
		delete(rec, field)
		return true
	}
	return false
}
