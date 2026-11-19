package entitlement

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	// FormatVersion is the document format this package writes and reads; a verifier refuses any other.
	FormatVersion = 1
	// Unlimited is the quota value that sets no limit.
	Unlimited = int64(-1)
	// MaxGraceDays bounds a document's grace period.
	MaxGraceDays = 365

	maxText     = 200
	maxQuotaKey = 64
	maxQuotas   = 64
)

// Document is what a license grants. Identifiers are strings so every reader keeps their digits. A quota is a
// count the installation may hold of one resource the product names; Unlimited sets no limit, and a resource the
// document does not name admits nothing. Times are whole seconds in UTC.
type Document struct {
	Format         int              `json:"format"`
	LicenseID      string           `json:"license_id"`
	Product        string           `json:"product"`
	CustomerID     string           `json:"customer_id"`
	CustomerName   string           `json:"customer_name"`
	InstallationID string           `json:"installation_id"`
	Plan           string           `json:"plan"`
	Quotas         map[string]int64 `json:"quotas"`
	IssuedAt       time.Time        `json:"issued_at"`
	ExpiresAt      time.Time        `json:"expires_at"`
	GraceDays      int              `json:"grace_days"`
}

// Validate refuses a document a verifier would not accept.
func (d Document) Validate() error {
	if d.Format != FormatVersion {
		return fmt.Errorf("%w: format %d", ErrUnsupported, d.Format)
	}
	for name, value := range map[string]string{"license_id": d.LicenseID, "product": d.Product, "customer_id": d.CustomerID,
		"customer_name": d.CustomerName, "installation_id": d.InstallationID, "plan": d.Plan} {
		if strings.TrimSpace(value) != value || value == "" || utf8.RuneCountInString(value) > maxText {
			return fmt.Errorf("%w: %s must be 1 to %d characters without surrounding space", ErrInvalid, name, maxText)
		}
	}
	if len(d.Quotas) > maxQuotas {
		return fmt.Errorf("%w: more than %d quotas", ErrInvalid, maxQuotas)
	}
	for key, value := range d.Quotas {
		if key == "" || len(key) > maxQuotaKey || strings.ContainsFunc(key, func(r rune) bool {
			return !(r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '_')
		}) {
			return fmt.Errorf("%w: quota key %q must be 1 to %d letters, digits, or underscores", ErrInvalid, key, maxQuotaKey)
		}
		if value < Unlimited {
			return fmt.Errorf("%w: quota %s is %d", ErrInvalid, key, value)
		}
	}
	switch {
	case d.IssuedAt.IsZero() || d.ExpiresAt.IsZero():
		return fmt.Errorf("%w: issued_at and expires_at are required", ErrInvalid)
	case !d.ExpiresAt.After(d.IssuedAt):
		return fmt.Errorf("%w: expires_at must follow issued_at", ErrInvalid)
	case d.GraceDays < 0 || d.GraceDays > MaxGraceDays:
		return fmt.Errorf("%w: grace_days must be 0 to %d", ErrInvalid, MaxGraceDays)
	}
	return nil
}

// Encode returns the canonical form a signature covers: the document validated, its times in UTC whole seconds,
// its fields in declaration order, and its quotas sorted by key.
func (d Document) Encode() ([]byte, error) {
	d.IssuedAt, d.ExpiresAt = d.IssuedAt.UTC().Truncate(time.Second), d.ExpiresAt.UTC().Truncate(time.Second)
	if d.Quotas == nil {
		d.Quotas = map[string]int64{}
	}
	if err := d.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(d)
}

// GraceEndsAt is when the grace period after expiry ends.
func (d Document) GraceEndsAt() time.Time {
	return d.ExpiresAt.AddDate(0, 0, d.GraceDays)
}

// StateAt is the license's state at now: active before expiry, in grace from expiry until grace ends, then expired.
// A clock behind the issue time still reads active, so a skewed clock never stops an installation.
func (d Document) StateAt(now time.Time) State {
	switch {
	case now.Before(d.ExpiresAt):
		return StateActive
	case now.Before(d.GraceEndsAt()):
		return StateGrace
	}
	return StateExpired
}

// RenewalDue reports whether now is within window of expiry, or past it.
func (d Document) RenewalDue(now time.Time, window time.Duration) bool {
	return !now.Before(d.ExpiresAt.Add(-window))
}

// Admits reports whether the installation may hold count of the resource named by key: the document names it and
// count is within its quota.
func (d Document) Admits(key string, count int64) bool {
	limit, ok := d.Quotas[key]
	return ok && count >= 0 && (limit == Unlimited || count <= limit)
}
