package logger

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/nauticana/keel/common"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/monitor/ingestion/azlogs"
)

// Azure Monitor ingestion buffering knobs. As with the CloudWatch
// backend, the per-call hot path is zero-network; a background goroutine
// batches records and flushes on a threshold or a timer. The byte cap
// stays well under the Logs Ingestion API's 1 MB-per-call limit.
const (
	azBatchSize       = 100
	azBatchMaxBytes   = 768 * 1024
	azFlushInterval   = 2 * time.Second
	azShutdownTimeout = 10 * time.Second
)

// LoggerAzure pushes log records to Azure Monitor / Log Analytics via the
// Logs Ingestion API, the Azure parity of the CloudWatch (LoggerAWS)
// backend. Records are POSTed to a Data Collection Endpoint (DCE) and
// routed by a Data Collection Rule (DCR) into a custom table.
//
// The DCR stream is expected to carry these columns (the DCR transform
// maps them onto the destination table; TimeGenerated is the standard
// Log Analytics timestamp column):
//
//	TimeGenerated (datetime), Severity (string), Message (string), LogName (string)
//
// Hot-path semantics mirror LoggerAWS: Info/Warning/Error/Access enqueue
// in-process; a background goroutine flushes every azFlushInterval or when
// the buffer threshold is reached; Close() drains with a bounded timeout.
// Unlike CloudWatch there is no sequence-token state and no remote stream
// to create — the DCE/DCR/table are provisioned out of band — so the flush
// path is a single stateless Upload call.
type LoggerAzure struct {
	client  *azlogs.Client
	ruleID  string
	stream  string
	logName string

	// mu guards the record buffer.
	mu       sync.Mutex
	buf      []azLogEntry
	bufBytes int

	// flushMu serializes the network-side Upload so the producer-side
	// threshold trigger and the timer tick cannot issue two concurrent
	// Uploads. Held across the Upload call only; mu still scopes buf.
	flushMu sync.Mutex

	wg          sync.WaitGroup
	stop        chan struct{}
	initialized bool
	closed      bool
}

// azLogEntry mirrors the expected DCR stream schema. Field names must
// match the stream columns declared in the Data Collection Rule.
type azLogEntry struct {
	TimeGenerated string `json:"TimeGenerated"`
	Severity      string `json:"Severity"`
	Message       string `json:"Message"`
	LogName       string `json:"LogName"`
}

// Initialize builds the ingestion client from --azure_logs_endpoint and
// authenticates with DefaultAzureCredential, then starts the flush
// goroutine. The DCR immutable id and stream name are validated up front
// so a misconfiguration fails at boot, not on the first dropped batch.
//
// Re-init is rejected (matching LoggerAWS): a second Initialize would
// orphan the running flush goroutine. Callers re-binding to a new stream
// must Close first.
func (l *LoggerAzure) Initialize(root string, destination string) error {
	l.mu.Lock()
	if l.initialized {
		l.mu.Unlock()
		return fmt.Errorf("azure logger: already initialized; call Close() before re-Initialize")
	}
	l.mu.Unlock()

	endpoint := *common.AzureLogsEndpoint
	ruleID := *common.AzureLogsRuleID
	stream := *common.AzureLogsStream
	if endpoint == "" || ruleID == "" || stream == "" {
		return fmt.Errorf("azure logger: --azure_logs_endpoint, --azure_logs_dcr and --azure_logs_stream are required")
	}

	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return fmt.Errorf("failed to create Azure credential: %w", err)
	}
	client, err := azlogs.NewClient(endpoint, cred, nil)
	if err != nil {
		return fmt.Errorf("failed to create Azure logs ingestion client: %w", err)
	}

	l.mu.Lock()
	l.client = client
	l.ruleID = ruleID
	l.stream = stream
	l.logName = destination
	l.stop = make(chan struct{})
	l.initialized = true
	l.mu.Unlock()
	l.wg.Add(1)
	go l.flushLoop()
	return nil
}

// Close drains buffered records with a bounded timeout, then stops the
// flush goroutine. Idempotent.
func (l *LoggerAzure) Close() {
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

// Access records carry the "_access" log name so they can be split from
// server records by a query on LogName — matching the server/access split
// of the file and stdout (gcp) backends.
func (l *LoggerAzure) Access(msg string)  { l.enqueue("INFO", l.logName+"_access", msg) }
func (l *LoggerAzure) Info(msg string)    { l.enqueue("INFO", l.logName+"_server", msg) }
func (l *LoggerAzure) Warning(msg string) { l.enqueue("WARNING", l.logName+"_server", msg) }
func (l *LoggerAzure) Error(msg string)   { l.enqueue("ERROR", l.logName+"_server", msg) }
func (l *LoggerAzure) Fatal(msg string) {
	l.enqueue("CRITICAL", l.logName+"_server", msg)
	// Drain before exit so the fatal record reaches Log Analytics.
	l.Close()
	os.Exit(1)
}

// enqueue appends one record to the buffer, triggering a synchronous flush
// when the size or byte threshold is reached so a burst doesn't wait for
// the timer tick.
func (l *LoggerAzure) enqueue(severity, logName, msg string) {
	entry := azLogEntry{
		TimeGenerated: time.Now().UTC().Format(time.RFC3339Nano),
		Severity:      severity,
		Message:       msg,
		LogName:       logName,
	}
	approxBytes := len(msg) + 96 // message + fixed-field overhead, approximate

	l.mu.Lock()
	l.buf = append(l.buf, entry)
	l.bufBytes += approxBytes
	flushNow := len(l.buf) >= azBatchSize || l.bufBytes >= azBatchMaxBytes
	l.mu.Unlock()

	if flushNow {
		l.flushOnce()
	}
}

// flushLoop periodically flushes until stop fires.
func (l *LoggerAzure) flushLoop() {
	defer l.wg.Done()
	ticker := time.NewTicker(azFlushInterval)
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

// flushOnce uploads the buffered records in a single Upload call. flushMu
// serializes the network side; mu is dropped before the call so the
// enqueue() hot path stays unblocked while an upload is in flight. A
// failed upload logs to stderr and drops the batch rather than blocking
// the process.
func (l *LoggerAzure) flushOnce() {
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
	l.mu.Unlock()

	payload, err := json.Marshal(batch)
	if err != nil {
		fmt.Fprintf(os.Stderr, "azure logs marshal failed: %v (dropped %d records)\n", err, len(batch))
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), azShutdownTimeout)
	defer cancel()

	if _, err := l.client.Upload(ctx, l.ruleID, l.stream, payload, nil); err != nil {
		fmt.Fprintf(os.Stderr, "azure logs upload failed: %v (dropped %d records)\n", err, len(batch))
	}
}
