package logger

import (
	"bufio"
	"fmt"
	"os"
	"sync"
	"time"
)

const (
	lgAccess     = "ACCESS"
	lgInfo       = "INFO"
	lgWarning    = "WARNING"
	lgError      = "ERROR"
	lgFatal      = "FATAL"
	lgExt        = ".log"
	lgSep        = " | "
	lgFileServer = "server"
	lgFileAccess = "access"
	lgTimeFormat = "2006-01-02 15:04:05.000 "
	lgFileDate   = "_20060102_150405"
	eol          = "\n"
	lvInfo       = 3
	lvWarning    = 2
	lvError      = 1
)

var sep = string(os.PathSeparator)

// LoggerFile writes log lines to two append-only files (server + access).
//
// Concurrency: every Write/Flush goes through serverMu / accessMu so
// concurrent goroutines can't interleave bytes inside a single log
// record. Without these, callers from a multiplexed HTTP server would
// produce corrupted lines whose timestamps belong to one request and
// payloads to another.
//
// Durability: O_APPEND — never O_TRUNC — so a process restart in the
// same second-resolution timestamp does NOT clobber the prior run's
// lines. Close() flushes both buffered writers before closing the
// underlying files.
type LoggerFile struct {
	serverName      string
	rootFolder      string
	serverLog       *os.File
	accessLog       *os.File
	serverLogWriter *bufio.Writer
	accessLogWriter *bufio.Writer
	logLevel        int

	serverMu sync.Mutex
	accessMu sync.Mutex
}

// Initialize prepares the log directory and opens the two log files.
// Files are opened O_APPEND so the same name across restarts in the
// same second appends rather than truncates. Files are 0640 (owner +
// group readable) so server-process logs aren't world-readable by
// default.
func (l *LoggerFile) Initialize(root string, destination string) error {
	l.logLevel = lvInfo
	l.serverName = destination
	l.rootFolder = root
	serverLogFilename := l.rootFolder + sep + l.serverName + "_" + lgFileServer + time.Now().Format(lgFileDate) + lgExt
	accessLogFilename := l.rootFolder + sep + l.serverName + "_" + lgFileAccess + time.Now().Format(lgFileDate) + lgExt

	fmt.Printf("Log host  : %s\n", l.serverName)
	fmt.Printf("Log Folder: %s\n", l.rootFolder)
	fmt.Printf("Server Log: %s\n", serverLogFilename)
	fmt.Printf("Access Log: %s\n", accessLogFilename)

	if err := os.MkdirAll(l.rootFolder, 0755); err != nil {
		return fmt.Errorf("file logger: mkdir %s: %w", l.rootFolder, err)
	}

	var err error
	l.serverLog, err = os.OpenFile(serverLogFilename, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0640)
	if err != nil {
		return fmt.Errorf("file %s could not be created: %w", serverLogFilename, err)
	}
	l.serverLogWriter = bufio.NewWriter(l.serverLog)

	l.accessLog, err = os.OpenFile(accessLogFilename, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0640)
	if err != nil {
		return fmt.Errorf("file %s could not be created: %w", accessLogFilename, err)
	}
	l.accessLogWriter = bufio.NewWriter(l.accessLog)
	return nil
}

// Close flushes buffered writes to disk before closing the underlying
// files. Without this any log lines still in the bufio.Writer at
// shutdown are silently lost.
func (l *LoggerFile) Close() {
	l.serverMu.Lock()
	if l.serverLogWriter != nil {
		_ = l.serverLogWriter.Flush()
	}
	if l.serverLog != nil {
		_ = l.serverLog.Close()
	}
	l.serverMu.Unlock()

	l.accessMu.Lock()
	if l.accessLogWriter != nil {
		_ = l.accessLogWriter.Flush()
	}
	if l.accessLog != nil {
		_ = l.accessLog.Close()
	}
	l.accessMu.Unlock()
}

// writeServer is on the hot path. It does NOT mirror to stdout —
// the previous fmt.Printf duplicated every record to the terminal,
// which both halved the file logger's throughput (two writes per
// call, the second formatted) and corrupted operator output when
// stdout was already redirected to its own log sink (v0.4.5 perf).
// The Initialize banner Printf calls below are kept on purpose as
// one-time startup announcements.
func (l *LoggerFile) writeServer(level, msg string) {
	l.serverMu.Lock()
	defer l.serverMu.Unlock()
	_, _ = l.serverLogWriter.WriteString(time.Now().Format(lgTimeFormat))
	_, _ = l.serverLogWriter.WriteString(lgSep + l.serverName + lgSep + level + lgSep + msg + eol)
	_ = l.serverLogWriter.Flush()
}

func (l *LoggerFile) Info(log string) {
	if l.logLevel >= lvInfo {
		l.writeServer(lgInfo, log)
	}
}
func (l *LoggerFile) Warning(log string) {
	if l.logLevel >= lvWarning {
		l.writeServer(lgWarning, log)
	}
}
func (l *LoggerFile) Error(log string) {
	if l.logLevel >= lvError {
		l.writeServer(lgError, log)
	}
}
func (l *LoggerFile) Fatal(log string) { l.writeServer(lgFatal, log) }
func (l *LoggerFile) Access(log string) {
	l.accessMu.Lock()
	defer l.accessMu.Unlock()
	_, _ = l.accessLogWriter.WriteString(time.Now().Format(lgTimeFormat))
	_, _ = l.accessLogWriter.WriteString(lgSep + l.serverName + lgSep + lgAccess + lgSep + log + eol)
	_ = l.accessLogWriter.Flush()
}
