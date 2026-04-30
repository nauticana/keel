package logger

import (
	"bytes"
	"encoding/json"
	"os"
	"sync"
	"time"
)

// LoggerGcp emits one structured-JSON record per call to stdout.
// "GCP" in the name reflects the deployment model — Google Cloud
// Logging's stdout-ingestion agent picks these up automatically when
// running on GKE / Cloud Run / Compute Engine. It does NOT use the
// Cloud Logging client SDK, which would couple keel to the GCP
// runtime.
type LoggerGcp struct {
	// LogServer / LogAccess are the value of the structured logName
	// field — usually "<service>_server" / "<service>_access".
	// Initialize fills these from (root, destination) so deployment
	// configuration stays in flag-land.
	LogServer string
	LogAccess string

	// mu serializes writes to stdout so concurrent goroutines never
	// produce interleaved JSON records. json.Encoder.Encode emits
	// the document in multiple calls to the underlying writer; without
	// the mutex two callers' bytes can splice into one corrupted
	// record (P1-25).
	mu sync.Mutex
}

// gcpLogEntry mirrors Cloud Logging's structured-payload schema.
// `severity`, `message`, `logName` are the standard names the
// ingestion agent recognizes; adding `time` lets the agent stop
// guessing the timestamp.
type gcpLogEntry struct {
	Severity string `json:"severity"`
	Message  string `json:"message"`
	LogName  string `json:"logName"`
	Time     string `json:"time"`
}

func (l *LoggerGcp) Initialize(root string, destination string) error {
	l.LogServer = destination + "_server"
	l.LogAccess = destination + "_access"
	_ = root
	return nil
}

func (l *LoggerGcp) Close() {}

func (l *LoggerGcp) write(severity string, logName string, message string) {
	entry := gcpLogEntry{
		Severity: severity,
		Message:  message,
		LogName:  logName,
		Time:     time.Now().UTC().Format(time.RFC3339Nano),
	}
	// Encode OUTSIDE the mutex (v0.4.4 perf). The previous
	// implementation held l.mu across json.NewEncoder(...).Encode,
	// which under high request load serialized the encoding pass
	// across every logging goroutine — not just the stdout write
	// the mutex actually needs to gate. Marshal to a buffer first
	// (concurrent), then take the mutex for a single
	// os.Stdout.Write call (atomic on most kernels for sub-PIPE_BUF
	// payloads, hence safe to interleave at the OS layer too —
	// but the mutex is still cheap insurance).
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	if err := enc.Encode(entry); err != nil {
		return
	}
	l.mu.Lock()
	_, _ = os.Stdout.Write(buf.Bytes())
	l.mu.Unlock()
}

func (l *LoggerGcp) Info(log string)    { l.write("INFO", l.LogServer, log) }
func (l *LoggerGcp) Warning(log string) { l.write("WARNING", l.LogServer, log) }
func (l *LoggerGcp) Error(log string)   { l.write("ERROR", l.LogServer, log) }
func (l *LoggerGcp) Fatal(log string) {
	l.write("CRITICAL", l.LogServer, log)
	os.Exit(1)
}
func (l *LoggerGcp) Access(log string) { l.write("INFO", l.LogAccess, log) }
