package worker

import (
	"context"
	"fmt"

	"github.com/nauticana/keel/logger"
)

// AbstractBillingReconciler is the daily backstop billing worker. It iterates
// the partners a project considers active and runs a reconcile function for
// each — re-sync add-on quantities, reconcile local subscription status vs the
// provider, enforce scheduled cancels, or (under self-scheduled billing) run
// the period billing. It is NOT a charge cron by itself; the injected
// Reconcile decides what each pass does. Run is meant to be driven by a systemd
// timer (or any scheduler), never a push-triggered CI cron.
type AbstractBillingReconciler struct {
	// Partners lists the partner ids to reconcile this pass.
	Partners func(ctx context.Context) ([]int64, error)
	// Reconcile runs one partner's reconciliation. A returned error is logged
	// and the pass continues with the next partner (best-effort).
	Reconcile func(ctx context.Context, partnerID int64) error
	Journal   logger.ApplicationLogger
}

// Run executes one reconciliation pass over all partners. Per-partner errors
// are logged and do not abort the pass; a context cancellation stops it.
func (w *AbstractBillingReconciler) Run(ctx context.Context) error {
	if w.Partners == nil || w.Reconcile == nil {
		return nil
	}
	partners, err := w.Partners(ctx)
	if err != nil {
		return err
	}
	for _, pid := range partners {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := w.Reconcile(ctx, pid); err != nil && w.Journal != nil {
			w.Journal.Error(fmt.Sprintf("billing reconcile failed for partner %d: %s", pid, err.Error()))
		}
	}
	return nil
}
