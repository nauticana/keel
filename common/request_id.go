package common

import (
	crand "crypto/rand"
	"fmt"
	"math/big"
	"sync/atomic"
)

// NewRequestID returns a 12-character opaque correlation id drawn uniformly
// from crypto/rand. On an RNG failure it returns a process-unique fallback, so
// the id is never empty.
func NewRequestID() string {
	const alphabet = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	out := make([]byte, 12)
	max := big.NewInt(int64(len(alphabet)))
	for i := range out {
		n, err := crand.Int(crand.Reader, max)
		if err != nil {
			return fmt.Sprintf("%s-%d", fallbackPrefix, fallbackCounter.Add(1))
		}
		out[i] = alphabet[n.Int64()]
	}
	return string(out)
}

var fallbackCounter atomic.Uint64

var fallbackPrefix = func() string {
	var b [4]byte
	if _, err := crand.Read(b[:]); err == nil {
		return fmt.Sprintf("nokey%x", b)
	}
	return "nokey0000"
}()

// ValidRequestID reports whether an inbound id is safe to adopt: 1 to 128
// characters of letters, digits and "-._:".
func ValidRequestID(id string) bool {
	if id == "" || len(id) > 128 {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-', c == '.', c == '_', c == ':':
		default:
			return false
		}
	}
	return true
}
