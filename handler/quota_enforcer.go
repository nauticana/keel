package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/nauticana/keel/logger"
	"github.com/nauticana/keel/port"
)

// ResourceExtractor describes how to count the new units of one quota'd
// resource in a request body, plus the human label used in the 402 message.
type ResourceExtractor struct {
	ResourceID string
	Label      string
	Count      func(body []byte) int64
}

// QuotaEnforcer is HTTP middleware that pre-checks a resource-creating request
// against the partner's plan quotas (keel's CheckQuota) and rejects with 402
// before the wrapped handler runs. The project supplies Extractors (how to
// count each resource in its own payload shape); the plumbing is generic.
type QuotaEnforcer struct {
	AbstractHandler
	Quota      port.QuotaService
	Journal    logger.ApplicationLogger
	Extractors []ResourceExtractor

	// After is an optional hook fired on a background context AFTER the
	// wrapped handler returns (the response is already written, so it is
	// best-effort — e.g. reconcile metered add-on billing). nil = skip.
	After func(ctx context.Context, partnerID int64, body []byte)
}

// Enforce wraps next with the quota pre-check + optional post-write hook.
func (e *QuotaEnforcer) Enforce(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session, ok := e.RequireSession(w, r)
		if !ok {
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			e.WriteError(w, http.StatusBadRequest, "Bad Request", "could not read request body")
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body)) // restore for the wrapped handler

		for _, ex := range e.Extractors {
			delta := ex.Count(body)
			if delta == 0 {
				continue
			}
			allowed, err := e.Quota.CheckQuota(r.Context(), session.PartnerId, ex.ResourceID, delta)
			if err != nil {
				if e.Journal != nil {
					e.Journal.Error(fmt.Sprintf("quota check failed (partner %d, %s): %s", session.PartnerId, ex.ResourceID, err.Error()))
				}
				e.WriteError(w, http.StatusInternalServerError, "Internal Server Error", "could not verify plan limits")
				return
			}
			if !allowed {
				e.WriteError(w, http.StatusPaymentRequired, "Plan Limit Reached",
					fmt.Sprintf("Your plan does not allow %d more %s. Upgrade to add more.", delta, ex.Label))
				return
			}
		}

		next(w, r)

		if e.After != nil {
			e.After(context.Background(), session.PartnerId, body)
		}
	}
}

// CountOpCodeRows counts rows in the named child collection of a relation-API
// POST body (a single record or an array of records) whose op_code is in
// opCodes. childField == "" counts the top-level records themselves (a new
// parent). This is the building block a project's Extractor.Count uses.
func CountOpCodeRows(body []byte, childField string, opCodes ...string) int64 {
	records := relationRecords(body)
	want := make(map[string]bool, len(opCodes))
	for _, c := range opCodes {
		want[c] = true
	}
	var n int64
	for _, rec := range records {
		if childField == "" {
			if want[rowOpCode(rec)] {
				n++
			}
			continue
		}
		arr, ok := rec[childField].([]any)
		if !ok {
			continue
		}
		for _, row := range arr {
			if m, ok := row.(map[string]any); ok && want[rowOpCode(m)] {
				n++
			}
		}
	}
	return n
}

// PayloadTouchesChild reports whether the body's named child collection has any
// row with an op_code in opCodes — used to gate writes to a feature-protected
// child (e.g. a 403 on a premium child collection).
func PayloadTouchesChild(body []byte, childField string, opCodes ...string) bool {
	return CountOpCodeRows(body, childField, opCodes...) > 0
}

// relationRecords normalizes a relation-API POST body (record | array) into a
// slice of records. Returns nil on parse error.
func relationRecords(body []byte) []map[string]any {
	var raw any
	if json.Unmarshal(body, &raw) != nil {
		return nil
	}
	switch v := raw.(type) {
	case []any:
		out := make([]map[string]any, 0, len(v))
		for _, item := range v {
			if m, ok := item.(map[string]any); ok {
				out = append(out, m)
			}
		}
		return out
	case map[string]any:
		return []map[string]any{v}
	}
	return nil
}

func rowOpCode(rec map[string]any) string {
	if v, ok := rec["op_code"].(string); ok {
		return v
	}
	return ""
}
