package limiter

import (
	"fmt"
	"math"
	"net/http"
	"strconv"
	"time"

	"github.com/nauticana/keel/port"
)

// LimitError attaches the rejecting scope and retry advice to a limit sentinel. It carries Retry-After as a
// response header, which handler.JSON writes for any error in the chain.
type LimitError struct {
	Err   error
	Scope string
	After time.Duration
}

var _ port.RetryAfterError = (*LimitError)(nil)

func (e *LimitError) Error() string {
	return fmt.Sprintf("%v: scope %s, retry after %s", e.Err, e.Scope, e.After)
}

func (e *LimitError) Unwrap() error { return e.Err }

func (e *LimitError) RetryAfter() time.Duration { return e.After }

// ErrorHeaders rounds a sub-second wait up: Retry-After carries whole seconds.
func (e *LimitError) ErrorHeaders() http.Header {
	if e.After <= 0 {
		return nil
	}
	return http.Header{"Retry-After": []string{strconv.FormatInt(int64(math.Ceil(e.After.Seconds())), 10)}}
}
