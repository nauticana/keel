// SnowflakeGenerator produces 64-bit Snowflake-style identifiers that fit in a
// signed BIGINT while remaining collision-free across up to 1024 writer nodes.
//
// Bit layout (MSB -> LSB, 63 usable bits, sign bit always 0):
//
//	[41 bits: ms since EpochMs2026][10 bits: nodeID][12 bits: sequence]
//
// A single node can emit 4096 ids per millisecond (~4M/s) with strict
// monotonicity. The 41-bit timestamp spans roughly 69 years from 2026.
package data

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

// EpochMs2026 is 2026-01-01T00:00:00Z in Unix milliseconds.
const EpochMs2026 int64 = 1767225600000

const (
	nodeBits  = 10
	seqBits   = 12
	maxNodeID = (1 << nodeBits) - 1
	maxSeq    = (1 << seqBits) - 1
	nodeShift = seqBits
	timeShift = seqBits + nodeBits
)

// SnowflakeGenerator is the concrete 64-bit id generator.
//
// In the typical deployment NextID is a pure function of the wall
// clock + a per-millisecond sequence — the on-disk state-file
// persistence below is opt-in and OFF by default. Operators who
// genuinely care about cross-restart monotonicity in the face of a
// wall-clock rewind (NTP correction, container scheduler shift)
// enable the file via WithStatePath; everyone else gets timestamp +
// nodeID + sequence as the only inputs.
type SnowflakeGenerator struct {
	nodeID  int64
	epochMs int64

	// statePath, when non-empty, is the on-disk file the generator
	// writes lastMs into. Set via WithStatePath (additive, opt-in).
	// Persistence prevents the clock-rewind id-collision class:
	// without it, a node restarting with its wall-clock pulled back
	// (NTP correction, container scheduler shift) would mint ids
	// from a `lastMs` that's earlier than the previous run, possibly
	// producing the same (ts, nodeID, seq) tuple twice (P1-67).
	statePath string

	mu     sync.Mutex
	lastMs int64
	seq    int64
	now    func() time.Time

	// lastPersistedMs is the highest watermark the state file has
	// observed. NextID writes the file only when the current
	// millisecond watermark advances by ≥ statePersistEveryMs (per-
	// second debounce, v0.4.5 perf). At full clip the previous
	// implementation issued ~1000 atomic-rename pairs/sec; this
	// caps it at ~1/sec while still bounding cross-restart drift
	// to that same window.
	lastPersistedMs int64

	// stateErrorReporter, when non-nil, is invoked once with the
	// first persistence failure we encounter. Subsequent failures
	// are silently ignored to avoid flooding the journal — the file
	// write is best-effort by design and a permanent failure
	// (read-only volume, full disk) means we lose monotonicity-
	// across-restart but mint correct ids in-process. Wire via
	// WithStateErrorReporter at startup.
	stateErrOnce sync.Once
	stateErrFn   func(error)
}

// statePersistEveryMs throttles the state-file rewrite cadence.
// Sized so a crashing node that's been minting ids steadily can
// rewind by at most this many ms — the corresponding window of
// potential id-tuple collision after a wall-clock rewind. 1s is
// the smallest interval that meaningfully reduces I/O without
// inflating the recovery risk surface.
const statePersistEveryMs int64 = 1000

// NewSnowflakeGenerator returns a SnowflakeGenerator bound to nodeID (0..1023)
// and a custom epoch in Unix ms.
func NewSnowflakeGenerator(nodeID int64, epochMs int64) (*SnowflakeGenerator, error) {
	if nodeID < 0 || nodeID > maxNodeID {
		return nil, fmt.Errorf("idgen: nodeID %d out of range [0, %d]", nodeID, maxNodeID)
	}
	if epochMs <= 0 {
		return nil, errors.New("idgen: epochMs must be positive")
	}
	return &SnowflakeGenerator{
		nodeID:  nodeID,
		epochMs: epochMs,
		now:     time.Now,
	}, nil
}

// WithStatePath enables on-disk persistence of the generator's
// lastMs watermark. The file is read at attach-time to seed lastMs
// and rewritten lazily after every NextID. If the watermark is
// ahead of the current wall clock — typical when a node restarts
// after a wall-clock rewind — NextID pegs to the persisted value
// so monotonicity across restarts is preserved.
//
// Returns the receiver for fluent construction:
//
//	gen, _ := data.NewSnowflakeGenerator(node, data.EpochMs2026)
//	gen.WithStatePath("/var/lib/myapp/snowflake.state")
//
// Most deployments DO NOT need this — id uniqueness in a single-
// writer process is guaranteed by the in-memory mutex + sequence,
// and modern container clocks are kept monotonic by the kernel.
// Only enable when a specific deployment is at real risk of
// wall-clock rewind across restarts.
func (s *SnowflakeGenerator) WithStatePath(path string) *SnowflakeGenerator {
	if path == "" {
		return s
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.statePath = path
	if v, err := readSnowflakeState(path); err == nil {
		s.lastMs = v
		s.lastPersistedMs = v
	}
	return s
}

// WithStateErrorReporter installs a callback invoked exactly once
// with the first state-file persistence error. Pre-v0.5 every
// failure was silently dropped — a read-only volume or full disk
// would degrade the cross-restart monotonicity guarantee invisibly.
// The reporter fires only once per generator so a permanently
// broken disk doesn't flood the journal.
//
// Wire via the application's logger at startup:
//
//	gen.WithStateErrorReporter(func(err error) {
//	    journal.Error("snowflake state-file: " + err.Error())
//	})
func (s *SnowflakeGenerator) WithStateErrorReporter(fn func(error)) *SnowflakeGenerator {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stateErrFn = fn
	return s
}

// readSnowflakeState parses the persisted lastMs from path. Returns
// 0, error when the file is missing or malformed; callers treat that
// as "no prior state, start fresh".
func readSnowflakeState(path string) (int64, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	v, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
	if err != nil {
		return 0, err
	}
	return v, nil
}

// writeSnowflakeState writes the new lastMs to disk via temp-file
// rename so a crash mid-write can't truncate the state file. Best
// effort — caller proceeds even on failure (worst case is a
// recently-restarted node loses some monotonicity guarantee, which
// is the same as before this hook existed). The first error per
// generator is reported through stateErrFn (if installed) so a
// permanently-broken disk surfaces in the operator's logs instead
// of degrading silently.
func (s *SnowflakeGenerator) writeSnowflakeState(path string, lastMs int64) {
	if path == "" {
		return
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(strconv.FormatInt(lastMs, 10)), 0640); err != nil {
		s.reportStateErr(err)
		return
	}
	if err := os.Rename(tmp, path); err != nil {
		s.reportStateErr(err)
	}
}

func (s *SnowflakeGenerator) reportStateErr(err error) {
	if s.stateErrFn == nil {
		return
	}
	s.stateErrOnce.Do(func() {
		s.stateErrFn(err)
	})
}

// NextID returns a new 63-bit positive id. Safe for concurrent use.
func (s *SnowflakeGenerator) NextID() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()

	nowMs := s.now().UnixMilli()
	if nowMs < s.lastMs {
		// Clock drift backwards: hold the line at lastMs to preserve
		// monotonicity rather than risk collision.
		nowMs = s.lastMs
	}

	if nowMs == s.lastMs {
		s.seq = (s.seq + 1) & maxSeq
		if s.seq == 0 {
			// Sequence exhausted in this ms — yield until the wall
			// clock crosses the next millisecond. The previous
			// time.Sleep(100µs) imposed a 100µs latency floor on
			// every contender holding the mutex; runtime.Gosched
			// hands the scheduler a chance to run another goroutine
			// without committing to any specific wait, which gets
			// us the same "don't burn the CPU" property at much
			// lower latency under contention (P2-18).
			for nowMs <= s.lastMs {
				runtime.Gosched()
				nowMs = s.now().UnixMilli()
				if nowMs < s.lastMs {
					nowMs = s.lastMs
				}
			}
		}
	} else {
		s.seq = 0
	}
	if s.statePath != "" && nowMs-s.lastPersistedMs >= statePersistEveryMs {
		// Debounce state-file writes to once per statePersistEveryMs
		// (v0.4.5 perf). The previous implementation rewrote on every
		// millisecond advance — up to ~1000 atomic-rename pairs/sec
		// at saturation. Per-second persistence gives us bounded
		// cross-restart drift (≤ statePersistEveryMs) at ~1000× lower
		// I/O.
		s.writeSnowflakeState(s.statePath, nowMs)
		s.lastPersistedMs = nowMs
	}
	s.lastMs = nowMs

	delta := nowMs - s.epochMs
	if delta < 0 {
		delta = 0
	}
	return (delta << timeShift) | (s.nodeID << nodeShift) | s.seq
}

// DecomposeBigintID extracts (timestampMs, nodeID, seq) from an id produced with
// the given epochMs. Useful for diagnostics and tests.
func (s *SnowflakeGenerator) DecomposeBigintID(id int64, epochMs int64) (timestampMs, nodeID, seq int64) {
	seq = id & maxSeq
	nodeID = (id >> nodeShift) & maxNodeID
	timestampMs = (id >> timeShift) + epochMs
	return
}
