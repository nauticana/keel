package service

import (
	"context"
	"fmt"
	"strconv"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/data"
	"github.com/nauticana/keel/port"
)

const (
	qGetPartnerSubscription = "get_partner_subscription"
	qGetResourceUsage       = "get_resource_usage"
	qGetPartnerQuota        = "get_partner_quota"
	qGetPartnerAddon        = "get_partner_addon"
	qAddUsage               = "add_usage"
	qLockQuota              = "lock_quota"
)

var quotaQueries = map[string]string{
	qGetPartnerSubscription: `
SELECT a.resource_id, max(a.max_value) AS limit_value, a.period_type
  FROM subscription_quota a, partner_plan_subscription b
 WHERE b.status = 'A'
   AND b.partner_id = ?
   AND b.begda <= CURRENT_TIMESTAMP
   AND (b.endda IS NULL or b.endda >= CURRENT_TIMESTAMP)
   AND a.plan_id = b.plan_id
 GROUP BY a.resource_id, a.period_type
 ORDER BY a.resource_id
`,

	qGetResourceUsage: "SELECT COALESCE(SUM(amount), 0) FROM usage_ledger WHERE partner_id = ? AND resource_name = ? AND usage_time >= ?",

	// Active addons for a partner. GROUP BY addon_id is essential —
	// without it, COUNT(*) collapses every row into a single tally and
	// the per-addon presence check downstream breaks.
	qGetPartnerAddon: `
SELECT addon_id, COUNT(*) AS active_count
  FROM partner_addon_subscription
 WHERE partner_id = ?
   AND status = 'A'
   AND begda <= CURRENT_TIMESTAMP
   AND (endda IS NULL OR endda >= CURRENT_TIMESTAMP)
 GROUP BY addon_id
`,

	// ON CONFLICT merge: the PK (partner_id, usage_time) collides for
	// same-microsecond writers; summing amounts preserves SUM(amount).
	qAddUsage: `
INSERT INTO usage_ledger (partner_id, resource_name, amount, notes) VALUES (?, ?, ?, ?)
ON CONFLICT (partner_id, usage_time) DO UPDATE SET amount = usage_ledger.amount + EXCLUDED.amount
`,

	// Tx-scoped advisory lock keyed "partnerID:resource" — serializes
	// ConsumeQuota per partner+resource without locking any table row.
	qLockQuota: "SELECT pg_advisory_xact_lock(hashtextextended(?, 0))",

	qGetPartnerQuota: `
SELECT MAX(a.max_value)
  FROM subscription_quota a, partner_plan_subscription b
 WHERE b.status = 'A'
   AND b.partner_id = ?
   AND b.begda <= CURRENT_TIMESTAMP
   AND (b.endda IS NULL OR b.endda >= CURRENT_TIMESTAMP)
   AND a.plan_id = b.plan_id
   AND a.resource_id = ?
`,
}

// defaultResourceCountQueries holds keel's built-in per-resource live-count SQL,
// keyed by RESOURCE ID (not an internal query name like the entries above). Each
// query is bound with a single partnerID param and must return one row / one
// column = the partner's current usage. Consumers extend or override these via
// QuotaServiceDb.Queries. Shipping MAX_DOMAINS here — rather than a hardcoded
// branch in CheckQuota — keeps every resource (keel's own included) on one path.
var defaultResourceCountQueries = map[string]string{
	"MAX_DOMAINS": "SELECT COUNT(*) FROM partner_domain WHERE partner_id = ?",
}

// cacheTTL is the per-partner soft expiry on cached quota / addon rows.
// Long enough that a busy request loop hits the cache; short enough
// that a plan change becomes visible within an hour without manual
// invalidation.
var cacheTTL = 1 * time.Hour

// QuotaItem is the cache entry for a single (partner, resource) pair.
// Limit < 0 signals "unlimited" — a sentinel preserved across cache
// hydrations to avoid a comparison branch on every check.
type QuotaItem struct {
	Limit     int64
	Period    string
	ExpiresAt time.Time
}

// QuotaMap and AddonMap collapse the "(partner_id, name) → entry"
// double-key pattern into nested maps so the per-partner row count
// stays modest and lookups don't sweep the whole cache.
type QuotaMap = map[string]QuotaItem
type AddonMap = map[string]bool

type QuotaServiceDb struct {
	Repo data.DatabaseRepository

	// Queries injects per-resource live-count SQL keyed by RESOURCE ID (e.g.
	// "MEDIA"). Each query is bound with a single partnerID param and must
	// return one row / one column = current usage. Merged over
	// defaultResourceCountQueries (consumer entries win). A resource without a
	// count query falls back to the usage_ledger sum, windowed by period_type.
	// Set at construction; read once at init().
	Queries map[string]string

	// initOnce guards the lazy field initialization (maps, query service)
	// from a startup-time race where two callers each see nil and both
	// initialize. Replaces the broken double-checked-locking pattern.
	initOnce sync.Once

	mu         sync.RWMutex
	quotaCache map[int64]QuotaMap
	addonCache map[int64]AddonMap
	qs         data.QueryService
	// resourceQueries is the merged default+injected resource→count-SQL map.
	// Its keys are the routing table CheckQuota uses to choose live-count vs
	// usage_ledger for a given resource.
	resourceQueries map[string]string
	// txQueries is the full query map handed to BeginTx — transactions carry
	// their own named-SQL map, separate from the shared query service.
	txQueries map[string]string

	// quotaSF / addonSF collapse concurrent fresh-load fan-out: when N
	// callers hit a cold partner cache for the same partner_id at once,
	// only one issues the SELECT and the other N-1 share its result.
	// Without singleflight every concurrent first-caller refetched the
	// partner's complete quota set and the merge into quotaCache blew
	// away whichever entry the other goroutine had just written.
	quotaSF singleflight.Group
	addonSF singleflight.Group
}

// init lazily wires the query service and cache maps. Idempotent under
// concurrency thanks to sync.Once.
func (s *QuotaServiceDb) init(ctx context.Context) {
	s.initOnce.Do(func() {
		s.quotaCache = make(map[int64]QuotaMap)
		s.addonCache = make(map[int64]AddonMap)

		// Merge keel's default resource-count queries with any injected by the
		// consumer (injected entries win).
		s.resourceQueries = make(map[string]string, len(defaultResourceCountQueries)+len(s.Queries))
		for k, v := range defaultResourceCountQueries {
			s.resourceQueries[k] = v
		}
		for k, v := range s.Queries {
			s.resourceQueries[k] = v
		}

		// The query service spans the infra queries (quotaQueries) plus every
		// resource-count query, keyed by resource id — these never collide with
		// the infra query names.
		all := make(map[string]string, len(quotaQueries)+len(s.resourceQueries))
		for k, v := range quotaQueries {
			all[k] = v
		}
		for k, v := range s.resourceQueries {
			all[k] = v
		}
		s.qs = s.Repo.GetQueryService(ctx, all)
		s.txQueries = all
	})
}

// quotaItem returns the cached (partnerID, quotaName) entry, refreshing the
// partner's quota set on miss/expiry. ok=false means not in plan.
func (s *QuotaServiceDb) quotaItem(ctx context.Context, partnerID int64, quotaName string, now time.Time) (QuotaItem, bool, error) {
	s.mu.RLock()
	partnerMap := s.quotaCache[partnerID]
	qItem, ok := partnerMap[quotaName]
	s.mu.RUnlock()

	if !ok || now.After(qItem.ExpiresAt) {
		key := strconv.FormatInt(partnerID, 10)
		_, err, _ := s.quotaSF.Do(key, func() (any, error) {
			res, err := s.qs.Query(ctx, qGetPartnerSubscription, partnerID)
			if err != nil {
				return nil, err
			}
			fresh := QuotaMap{}
			for _, row := range res.Rows {
				resourceName := common.AsString(row[0])
				fresh[resourceName] = QuotaItem{
					Limit:     common.AsInt64(row[1]),
					Period:    common.AsString(row[2]),
					ExpiresAt: now.Add(cacheTTL),
				}
			}
			s.mu.Lock()
			if s.quotaCache[partnerID] == nil {
				s.quotaCache[partnerID] = QuotaMap{}
			}
			for k, v := range fresh {
				s.quotaCache[partnerID][k] = v
			}
			s.mu.Unlock()
			return nil, nil
		})
		if err != nil {
			return QuotaItem{}, false, err
		}
		s.mu.RLock()
		qItem, ok = s.quotaCache[partnerID][quotaName]
		s.mu.RUnlock()
	}
	return qItem, ok, nil
}

// periodStart / nextReset are the UTC window boundaries for a quota period:
// 'D' daily, 'M' monthly, anything else all-time (zero time).
func periodStart(period string, now time.Time) time.Time {
	switch period {
	case "M":
		return time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
	case "D":
		return time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	default:
		return time.Time{}
	}
}

func nextReset(period string, now time.Time) time.Time {
	switch period {
	case "M":
		return time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC).AddDate(0, 1, 0)
	case "D":
		return time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC).AddDate(0, 0, 1)
	default:
		return time.Time{}
	}
}

// CheckQuota returns true when (partnerID, quotaName) has remaining
// allowance for `amount` more units in the current period. Cache hits
// short-circuit the DB; misses load all of the partner's quotas in a
// single round-trip and populate the per-resource entries.
//
// Period boundaries are computed in UTC so cross-region replicas /
// workers agree on "start of day" and "start of month" — the previous
// implementation used the server's local time zone and would disagree
// across regions.
func (s *QuotaServiceDb) CheckQuota(ctx context.Context, partnerID int64, quotaName string, amount int64) (bool, error) {
	s.init(ctx)

	now := time.Now().UTC()
	qItem, ok, err := s.quotaItem(ctx, partnerID, quotaName, now)
	if err != nil {
		return false, err
	}
	if !ok {
		// Partner has no plan or the requested resource is not in the
		// plan. Reject rather than allow — fail-closed.
		return false, nil
	}
	if qItem.Limit < 0 {
		return true, nil
	}

	var usage int64
	if _, hasCount := s.resourceQueries[quotaName]; hasCount {
		// Live-count resource: run its count query (registered under the
		// resource id), bound with a single partnerID param.
		res, err := s.qs.Query(ctx, quotaName, partnerID)
		if err != nil {
			return false, fmt.Errorf("failed to count usage for resource %s, partner: %d", quotaName, partnerID)
		}
		if len(res.Rows) > 0 {
			usage = common.AsInt64(res.Rows[0][0])
		}
	} else {
		res, err := s.qs.Query(ctx, qGetResourceUsage, partnerID, quotaName, periodStart(qItem.Period, now))
		if err != nil {
			return false, fmt.Errorf("failed to get resource usage for partner: %d", partnerID)
		}
		if len(res.Rows) > 0 {
			usage = common.AsInt64(res.Rows[0][0])
		}
	}

	if usage+amount > qItem.Limit {
		return false, nil
	}
	return true, nil
}

// ConsumeQuota atomically checks and records usage under a per-(partner,
// resource) advisory lock: bursts cannot overshoot and a failed write denies.
// Live-count resources insert their counted entity outside this tx, so
// overshoot there is only narrowed, not eliminated.
func (s *QuotaServiceDb) ConsumeQuota(ctx context.Context, partnerID int64, resource string, amount int64, description string) (bool, time.Time, error) {
	s.init(ctx)

	now := time.Now().UTC()
	qItem, ok, err := s.quotaItem(ctx, partnerID, resource, now)
	if err != nil {
		return false, time.Time{}, err
	}
	if !ok {
		return false, time.Time{}, nil // no plan / resource not in plan — fail closed
	}
	resetAt := nextReset(qItem.Period, now)

	tx, err := s.Repo.BeginTx(ctx, s.txQueries)
	if err != nil {
		return false, time.Time{}, fmt.Errorf("consume quota %s for partner %d: begin: %w", resource, partnerID, err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback(ctx)
		}
	}()

	lockKey := strconv.FormatInt(partnerID, 10) + ":" + resource
	if _, err := tx.Query(ctx, qLockQuota, lockKey); err != nil {
		return false, time.Time{}, fmt.Errorf("consume quota %s for partner %d: lock: %w", resource, partnerID, err)
	}

	if qItem.Limit >= 0 {
		var usage int64
		if _, hasCount := s.resourceQueries[resource]; hasCount {
			res, err := tx.Query(ctx, resource, partnerID)
			if err != nil {
				return false, time.Time{}, fmt.Errorf("consume quota %s for partner %d: count: %w", resource, partnerID, err)
			}
			if len(res.Rows) > 0 {
				usage = common.AsInt64(res.Rows[0][0])
			}
		} else {
			res, err := tx.Query(ctx, qGetResourceUsage, partnerID, resource, periodStart(qItem.Period, now))
			if err != nil {
				return false, time.Time{}, fmt.Errorf("consume quota %s for partner %d: usage: %w", resource, partnerID, err)
			}
			if len(res.Rows) > 0 {
				usage = common.AsInt64(res.Rows[0][0])
			}
		}
		if usage+amount > qItem.Limit {
			return false, resetAt, nil
		}
	}

	if _, err := tx.Query(ctx, qAddUsage, partnerID, resource, amount, description); err != nil {
		return false, time.Time{}, fmt.Errorf("consume quota %s for partner %d: record: %w", resource, partnerID, err)
	}
	if err := tx.Commit(ctx); err != nil {
		return false, time.Time{}, fmt.Errorf("consume quota %s for partner %d: commit: %w", resource, partnerID, err)
	}
	committed = true
	return true, resetAt, nil
}

// CheckAddon returns true when the partner has an active subscription
// for the named addon. Caches the per-addon presence as a bool so
// repeated checks for the same addon are O(1) after the first DB hit.
//
// Two correctness fixes vs the old implementation:
//
//   - The DB query now has GROUP BY addon_id so each addon produces its
//     own COUNT row, not a single global tally that was always read as
//     the result for whichever addon happened to be passed in.
//   - The "is the requested addon present?" decision is read from the
//     populated cache map by name, not from the loop's last iterator
//     value. Order of rows from the DB no longer matters.
func (s *QuotaServiceDb) CheckAddon(ctx context.Context, partnerID int64, addonName string) (bool, error) {
	s.init(ctx)

	s.mu.RLock()
	partnerMap, partnerKnown := s.addonCache[partnerID]
	allowed, ok := partnerMap[addonName]
	s.mu.RUnlock()
	if partnerKnown && ok {
		return allowed, nil
	}

	key := strconv.FormatInt(partnerID, 10)
	_, err, _ := s.addonSF.Do(key, func() (any, error) {
		res, err := s.qs.Query(ctx, qGetPartnerAddon, partnerID)
		if err != nil {
			return nil, err
		}
		fresh := AddonMap{}
		for _, row := range res.Rows {
			resourceName := common.AsString(row[0])
			active := common.AsInt32(row[1]) > 0
			fresh[resourceName] = active
		}
		s.mu.Lock()
		if s.addonCache[partnerID] == nil {
			s.addonCache[partnerID] = AddonMap{}
		}
		for k, v := range fresh {
			s.addonCache[partnerID][k] = v
		}
		s.mu.Unlock()
		return nil, nil
	})
	if err != nil {
		return false, err
	}
	s.mu.Lock()
	// Ensure a definitive false is cached for the requested addon when
	// the partner has no active subscription for it — otherwise every
	// CheckAddon call would re-query the DB.
	if s.addonCache[partnerID] == nil {
		s.addonCache[partnerID] = AddonMap{}
	}
	if _, present := s.addonCache[partnerID][addonName]; !present {
		s.addonCache[partnerID][addonName] = false
	}
	allowed = s.addonCache[partnerID][addonName]
	s.mu.Unlock()

	return allowed, nil
}

func (s *QuotaServiceDb) LogUsage(ctx context.Context, partnerID int64, quotaName string, amount int64, description string) error {
	s.init(ctx)
	_, err := s.qs.Query(ctx, qAddUsage, partnerID, quotaName, amount, description)
	if err != nil {
		return fmt.Errorf("failed to add usage %s amount of %d to partner %d", quotaName, amount, partnerID)
	}
	return nil
}

func (s *QuotaServiceDb) ReportAddonUsage(ctx context.Context, partnerID int64, addonID string, amount int64, notes string) error {
	return s.LogUsage(ctx, partnerID, addonID, amount, notes)
}

func (s *QuotaServiceDb) GetPartnerQuota(ctx context.Context, partnerID int64, resource string, def int64) (int64, error) {
	s.init(ctx)
	res, err := s.qs.Query(ctx, qGetPartnerQuota, partnerID, resource)
	if err != nil {
		return 0, fmt.Errorf("get partner quota %s: %w", resource, err)
	}
	if len(res.Rows) == 0 || res.Rows[0][0] == nil {
		return def, nil // no active plan / resource absent → caller's default
	}
	return common.AsInt64(res.Rows[0][0]), nil // configured value, incl. 0 and the -1 unlimited sentinel
}

var _ port.QuotaService = (*QuotaServiceDb)(nil)
