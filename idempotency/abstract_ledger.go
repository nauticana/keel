package idempotency

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
	"unicode/utf8"
)

const MaxKeyLength = 200

var (
	ErrEmptyKey          = errors.New("idempotency: key is required")
	ErrKeyTooLong        = errors.New("idempotency: key is too long")
	ErrNilResult         = errors.New("idempotency: completed result is required")
	ErrInvalidTransition = errors.New("idempotency: key state does not allow transition")
	ErrEmptyFence        = errors.New("idempotency: fence is required")
)

// AbstractLedger supplies claim timing and validation shared by ledger implementations. It is incomplete and
// must be embedded.
type AbstractLedger struct {
	// Lease > 0 lets Begin take over an in-flight key not renewed within the lease; zero never takes over.
	Lease time.Duration
}

func (AbstractLedger) validateKey(key string) error {
	if key == "" {
		return ErrEmptyKey
	}
	if utf8.RuneCountInString(key) > MaxKeyLength {
		return fmt.Errorf("%w: maximum %d characters", ErrKeyTooLong, MaxKeyLength)
	}
	return nil
}

func (AbstractLedger) validateResult(result []byte) error {
	if result == nil {
		return ErrNilResult
	}
	return nil
}

func (AbstractLedger) validateFence(fence string) error {
	if fence == "" {
		return ErrEmptyFence
	}
	return nil
}

func newFence() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("idempotency: fence entropy unavailable: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}

func cloneBytes(value []byte) []byte {
	if value == nil {
		return nil
	}
	return append([]byte{}, value...)
}
