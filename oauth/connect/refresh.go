package connect

import (
	"context"
	"strconv"

	"github.com/nauticana/keel/logger"
	"github.com/nauticana/keel/oauth/client"
)

// RefreshStale refreshes every stale active credential (per
// Store.ListActiveCredentials). Each is claimed atomically, so this is safe to
// run on multiple replicas — a credential another replica claimed counts as
// skipped, not refreshed. Returns refreshed/skipped/failed counts, plus a non-nil
// error only when the worklist itself couldn't be read (per-credential failures
// are counted, not returned).
func RefreshStale(ctx context.Context, store Store, journal logger.ApplicationLogger) (refreshed, skipped, failed int, err error) {
	creds, err := store.ListActiveCredentials(ctx)
	if err != nil {
		if journal != nil {
			journal.Error("connect: list active credentials: " + err.Error())
		}
		return 0, 0, 0, err
	}
	for _, c := range creds {
		cctx := client.WithEntity(ctx, c.EntityID)
		done, rerr := store.RefreshDue(cctx, c.PartnerID, c.Provider, c.Rev)
		switch {
		case rerr != nil:
			failed++
			if journal != nil {
				journal.Error("connect: refresh partner " + strconv.FormatInt(c.PartnerID, 10) + " provider " + c.Provider + ": " + rerr.Error())
			}
		case done:
			refreshed++
		default:
			skipped++
		}
	}
	return refreshed, skipped, failed, nil
}
