// Package limiter is admission control: token buckets, fair concurrency slots, and partner×fleet fixed-window
// rate limits kept locally or shared across replicas through cache.MultiScopeAdmitter.
package limiter

import "errors"

var (
	ErrRateLimited    = errors.New("limiter: rate limited")
	ErrInvalidSubject = errors.New("limiter: subject and positive weight are required")
	ErrClosed         = errors.New("limiter: closed")
)
