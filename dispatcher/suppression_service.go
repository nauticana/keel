package dispatcher

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/port"
)

// Why a contact is suppressed. The values are stored as-is; an app may record
// its own, but these cover the cases the law and the carriers impose.
const (
	SuppressUnsubscribed = "UNSUBSCRIBED"
	SuppressBounced      = "BOUNCED"
	SuppressComplained   = "COMPLAINED"
	SuppressBlocked      = "BLOCKED"
)

// AllPartners records a suppression that applies to every tenant — a hard
// bounce or a complaint is about the contact, not about who is sending.
const AllPartners int64 = 0

const (
	qSuppressionLookup  = "notification_suppression_lookup"
	qSuppressionInsert  = "notification_suppression_insert"
	qSuppressionRelease = "notification_suppression_release"
)

var suppressionQueries = map[string]string{
	// A fleet-wide entry outranks a tenant one: it is the stronger statement.
	qSuppressionLookup: `
SELECT reason FROM notification_suppression
 WHERE channel = ? AND contact = ? AND partner_id IN (0, ?)
 ORDER BY partner_id
 LIMIT 1`,

	qSuppressionInsert: `
INSERT INTO notification_suppression (channel, contact, partner_id, reason)
VALUES (?, ?, ?, ?)
ON CONFLICT (channel, contact, partner_id)
DO UPDATE SET reason = EXCLUDED.reason, created_at = CURRENT_TIMESTAMP`,

	qSuppressionRelease: `
DELETE FROM notification_suppression
 WHERE channel = ? AND contact = ? AND partner_id = ?`,
}

// SuppressionService is the table-backed port.NotificationSuppressor over
// notification_suppression. Which events suppress a contact is the app's;
// keeping the list and consulting it is not.
type SuppressionService struct {
	DB port.DatabaseRepository

	once sync.Once
	qs   port.QueryService
}

var _ port.NotificationSuppressor = (*SuppressionService)(nil)

func (s *SuppressionService) queries(ctx context.Context) (port.QueryService, error) {
	s.once.Do(func() {
		if s.DB != nil {
			s.qs = s.DB.GetQueryService(ctx, suppressionQueries)
		}
	})
	if s.qs == nil {
		return nil, fmt.Errorf("suppression: no database configured")
	}
	return s.qs, nil
}

// normalizeContact matches how a contact is stored, so a differently-cased
// address cannot slip past its own suppression entry.
func normalizeContact(contact string) string {
	return strings.ToLower(strings.TrimSpace(contact))
}

func (s *SuppressionService) Suppressed(ctx context.Context, channel, contact string, partnerID int64) (bool, string, error) {
	contact = normalizeContact(contact)
	if channel == "" || contact == "" {
		return false, "", nil
	}
	qs, err := s.queries(ctx)
	if err != nil {
		return false, "", err
	}
	res, err := qs.Query(ctx, qSuppressionLookup, channel, contact, partnerID)
	if err != nil {
		return false, "", fmt.Errorf("suppression: lookup %s: %w", channel, err)
	}
	if len(res.Rows) == 0 {
		return false, "", nil
	}
	return true, common.AsString(res.Rows[0][0]), nil
}

// Suppress adds or updates an entry. partnerID AllPartners suppresses the
// contact on that channel for every tenant.
func (s *SuppressionService) Suppress(ctx context.Context, channel, contact string, partnerID int64, reason string) error {
	contact = normalizeContact(contact)
	if channel == "" || contact == "" || reason == "" {
		return fmt.Errorf("suppression: channel, contact and reason required")
	}
	qs, err := s.queries(ctx)
	if err != nil {
		return err
	}
	if _, err := qs.Query(ctx, qSuppressionInsert, channel, contact, partnerID, reason); err != nil {
		return fmt.Errorf("suppression: record %s: %w", channel, err)
	}
	return nil
}

// Release removes one entry — a re-subscribe, or a bounce the app has resolved.
// It removes exactly the scope given: releasing a tenant entry leaves a
// fleet-wide one in force.
func (s *SuppressionService) Release(ctx context.Context, channel, contact string, partnerID int64) error {
	qs, err := s.queries(ctx)
	if err != nil {
		return err
	}
	if _, err := qs.Query(ctx, qSuppressionRelease, channel, normalizeContact(contact), partnerID); err != nil {
		return fmt.Errorf("suppression: release %s: %w", channel, err)
	}
	return nil
}
