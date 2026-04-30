package logger

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	cwltypes "github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"
)

// CloudWatch buffering knobs. The default flush thresholds keep the
// per-call hot path zero-network and amortize the per-PUT cost / rate
// limit across many log lines.
const (
	cwBatchSize       = 100
	cwBatchMaxBytes   = 256 * 1024 // CloudWatch caps each PutLogEvents at 1 MiB; stay well under
	cwFlushInterval   = 2 * time.Second
	cwShutdownTimeout = 10 * time.Second
)

// LoggerAWS pushes log records to CloudWatch Logs.
//
// Hot-path semantics: Info/Warning/Error/Access enqueue an event
// in-process. A background goroutine batches events together and
// flushes either every cwFlushInterval or whenever the buffer
// threshold is reached. Close() drains the buffer with a bounded
// timeout. This replaces the previous one-PUT-per-line model that
// hammered CloudWatch's 5 req/s/stream limit and serialized every
// caller's hot-path on a network round-trip.
type LoggerAWS struct {
	client    *cloudwatchlogs.Client
	logGroup  string
	logStream string

	// mu guards the buffer and seqToken read/write.
	mu       sync.Mutex
	buf      []cwltypes.InputLogEvent
	bufBytes int
	seqToken *string

	// flushMu serializes the network-side flush so the producer-side
	// threshold trigger and the 2s timer cannot fire two PutLogEvents
	// concurrently and race AWS's SequenceToken machinery (MAJOR 5b).
	// Held across the AWS call only; mu still scopes buf access.
	flushMu sync.Mutex

	wg          sync.WaitGroup
	stop        chan struct{}
	initialized bool
	closed      bool
}

// Initialize wires up the CloudWatch client and creates the per-host
// log stream. The stream name carries the unix-second timestamp so
// concurrent restarts on the same host don't collide; if a previous
// process happened to land the same name (unlikely but possible),
// AWS responds with ResourceAlreadyExistsException and we treat that
// as success. The flush goroutine starts here.
//
// Re-init is rejected: a second Initialize call would otherwise
// orphan the previous flush goroutine since `l.stop` would be
// overwritten before the goroutine could read it (MAJOR 5a). Callers
// that need to re-bind to a new stream must Close first.
func (l *LoggerAWS) Initialize(root string, destination string) error {
	l.mu.Lock()
	if l.initialized {
		l.mu.Unlock()
		return fmt.Errorf("cloudwatch logger: already initialized; call Close() before re-Initialize")
	}
	l.mu.Unlock()

	cfg, err := config.LoadDefaultConfig(context.Background())
	if err != nil {
		return fmt.Errorf("failed to load AWS config: %w", err)
	}
	client := cloudwatchlogs.NewFromConfig(cfg)
	logGroup := "/" + destination
	hostname, _ := os.Hostname()
	logStream := fmt.Sprintf("%s-%s-%d", destination, hostname, time.Now().Unix())

	_, err = client.CreateLogStream(context.Background(), &cloudwatchlogs.CreateLogStreamInput{
		LogGroupName:  &logGroup,
		LogStreamName: &logStream,
	})
	if err != nil {
		var alreadyExists *cwltypes.ResourceAlreadyExistsException
		if !errors.As(err, &alreadyExists) {
			return fmt.Errorf("failed to create CloudWatch log stream: %w", err)
		}
	}

	l.mu.Lock()
	l.client = client
	l.logGroup = logGroup
	l.logStream = logStream
	l.stop = make(chan struct{})
	l.initialized = true
	l.mu.Unlock()
	l.wg.Add(1)
	go l.flushLoop()
	return nil
}

// Close drains any buffered events with a bounded timeout, then
// stops the flush goroutine. Idempotent.
func (l *LoggerAWS) Close() {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return
	}
	l.closed = true
	if l.stop != nil {
		close(l.stop)
	}
	l.mu.Unlock()
	l.wg.Wait()
	l.flushOnce()
}

func (l *LoggerAWS) Access(msg string)  { l.put("ACCESS", msg) }
func (l *LoggerAWS) Info(msg string)    { l.put("INFO", msg) }
func (l *LoggerAWS) Warning(msg string) { l.put("WARN", msg) }
func (l *LoggerAWS) Error(msg string)   { l.put("ERROR", msg) }
func (l *LoggerAWS) Fatal(msg string) {
	l.put("FATAL", msg)
	// Drain before exit so the fatal record makes it to CloudWatch.
	l.Close()
	os.Exit(1)
}

// put enqueues one event onto the in-memory buffer. Triggers a sync
// flush when the buffer reaches the size or byte threshold so a
// burst doesn't queue indefinitely waiting for the timer tick.
func (l *LoggerAWS) put(level, msg string) {
	entry := fmt.Sprintf("[%s] %s", level, msg)
	now := time.Now().UnixMilli()
	event := cwltypes.InputLogEvent{Message: &entry, Timestamp: &now}
	// CloudWatch's per-event size includes the message bytes plus a
	// 26-byte overhead. Approximate.
	approxBytes := len(entry) + 26

	l.mu.Lock()
	l.buf = append(l.buf, event)
	l.bufBytes += approxBytes
	flushNow := len(l.buf) >= cwBatchSize || l.bufBytes >= cwBatchMaxBytes
	l.mu.Unlock()

	if flushNow {
		l.flushOnce()
	}
}

// flushLoop periodically flushes the buffer until stop fires.
func (l *LoggerAWS) flushLoop() {
	defer l.wg.Done()
	ticker := time.NewTicker(cwFlushInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			l.flushOnce()
		case <-l.stop:
			return
		}
	}
}

// flushOnce sends whatever's currently in the buffer to CloudWatch
// in a single PutLogEvents call. The producer-side threshold trigger
// (called inline from put()) and the 2s timer can both invoke this
// concurrently — without flushMu the two PutLogEvents calls would
// each consume the same SequenceToken and AWS would reject one with
// InvalidSequenceTokenException, dropping a whole batch (MAJOR 5b).
//
// flushMu spans the network call; l.mu is dropped before the call to
// keep the put() hot path unblocked while a flush is in flight.
func (l *LoggerAWS) flushOnce() {
	if l.client == nil {
		return
	}
	l.flushMu.Lock()
	defer l.flushMu.Unlock()

	l.mu.Lock()
	if len(l.buf) == 0 {
		l.mu.Unlock()
		return
	}
	batch := l.buf
	l.buf = nil
	l.bufBytes = 0
	seq := l.seqToken
	l.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), cwShutdownTimeout)
	defer cancel()

	out, err := l.client.PutLogEvents(ctx, &cloudwatchlogs.PutLogEventsInput{
		LogGroupName:  &l.logGroup,
		LogStreamName: &l.logStream,
		LogEvents:     batch,
		SequenceToken: seq,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "cloudwatch flush failed: %v (dropped %d events)\n", err, len(batch))
		return
	}
	l.mu.Lock()
	l.seqToken = out.NextSequenceToken
	l.mu.Unlock()
}
