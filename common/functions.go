package common

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	maps0 "maps"
	"math"
	"math/big"
	"regexp"
	"strings"
	"time"
	"unicode"

	"github.com/nauticana/keel/model"
)

// The As* helpers are model's converters with lenient sentinels: -1 for a
// number, false, "" or the zero time when v is NULL or does not convert. The
// OK forms tell a NULL from a real -1.

func AsFloat64(v any) float64 {
	if f, ok := model.Float64Of(v); ok {
		return f
	}
	return -1
}

func AsFloat64OK(v any) (float64, bool) { return model.Float64Of(v) }

func AsInt32(v any) int32 {
	if n, ok := AsInt32OK(v); ok {
		return n
	}
	return -1
}

func AsInt32OK(v any) (int32, bool) {
	if n, ok := model.Int64Of(v); ok && n >= math.MinInt32 && n <= math.MaxInt32 {
		return int32(n), true
	}
	return 0, false
}

func AsInt64(v any) int64 {
	if n, ok := model.Int64Of(v); ok {
		return n
	}
	return -1
}

func AsInt64OK(v any) (int64, bool) { return model.Int64Of(v) }

func AsBool(v any) bool {
	b, _ := model.BoolOf(v)
	return b
}

func AsString(v any) string {
	s, _ := model.StringOf(v)
	return s
}

// AsTime returns the zero time when v is NULL or does not parse; AsTimeOK tells them apart.
func AsTime(v any) time.Time {
	t, _ := model.TimeOf(v)
	return t
}

func AsTimeOK(v any) (time.Time, bool) { return model.TimeOf(v) }

func PascalCase(s string) string {
	words := strings.Split(s, "_")
	for i, word := range words {
		if len(word) > 0 {
			runes := []rune(word)
			runes[0] = unicode.ToUpper(runes[0])
			words[i] = string(runes)
		}
	}
	return strings.Join(words, "")
}

func TitleCase(s string) string {
	words := strings.Split(s, "_")
	for i, word := range words {
		if len(word) > 0 {
			runes := []rune(word)
			runes[0] = unicode.ToUpper(runes[0])
			words[i] = string(runes)
		}
	}
	return strings.Join(words, " ")
}

func SplitCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if v := strings.TrimSpace(p); v != "" {
			out = append(out, v)
		}
	}
	return out
}

var dbTimestampLayouts = []string{
	time.RFC3339,
	"2006-01-02 15:04:05.999999",
	"2006-01-02 15:04:05",
	"2006-01-02T15:04:05",
}

// ParseDBTimestamp parses the textual timestamp layouts Postgres/pgx return,
// trying each in order, so callers don't each re-implement the fallback.
func ParseDBTimestamp(s string) (time.Time, error) {
	for _, layout := range dbTimestampLayouts {
		if t, err := time.Parse(layout, s); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("unrecognised timestamp: %q", s)
}

// NullIfEmpty returns nil for a blank string so COALESCE-style UPSERTs preserve
// existing non-NULL values instead of overwriting them with empty data.
func NullIfEmpty(s string) any {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	return s
}

var slugInvalid = regexp.MustCompile(`[^a-z0-9]+`)

// Slugify lowercases, replaces each run of characters outside [a-z0-9] with a
// single hyphen, and trims leading/trailing hyphens — a URL-safe slug from a
// display name.
func Slugify(name string) string {
	s := strings.ToLower(name)
	s = slugInvalid.ReplaceAllString(s, "-")
	return strings.Trim(s, "-")
}

// GenerateNumericCode returns a cryptographically random zero-padded numeric code
// of the given length (e.g. 6 → "042315"), for email/SMS verification. digits
// must be 1..18.
func GenerateNumericCode(digits int) (string, error) {
	if digits < 1 || digits > 18 {
		return "", fmt.Errorf("GenerateNumericCode: digits must be 1..18, got %d", digits)
	}
	bound := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(digits)), nil)
	n, err := rand.Int(rand.Reader, bound)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%0*d", digits, n.Int64()), nil
}

// Sha256Hex returns the hex-encoded SHA-256 of s. Used for content drift
// detection / change keys (not for passwords — use a KDF for those).
func Sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// MergeMaps returns a new map combining all inputs; later maps win on key
// collisions. Inputs are never mutated — use it to assemble a worker's
// GetOLTPQueries() from several named-query sets without aliasing (and
// accidentally mutating) the shared source maps.
func MergeMaps[K comparable, V any](maps ...map[K]V) map[K]V {
	out := make(map[K]V)
	for _, m := range maps {
		maps0.Copy(out, m)
	}
	return out
}

func TruncateRunes(value string, limit int) string {
	if limit <= 0 {
		return ""
	}
	runes := []rune(value)
	if len(runes) <= limit {
		return value
	}
	return string(runes[:limit])
}
