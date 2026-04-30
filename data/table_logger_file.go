package data

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	"github.com/nauticana/keel/model"
	"github.com/nauticana/keel/port"
)

// ErrFindChangesUnsupported is returned by TableLoggerFile.FindChanges
// to make the gap visible to callers. The previous stub returned
// (nil, nil) which was indistinguishable from "no matching rows" and
// silently produced false negatives.
//
// Consumers that need queryable change history should swap in a
// database-backed TableLogger; the file impl is meant for low-volume
// audit / forensic scenarios where reads are operator-driven.
var ErrFindChangesUnsupported = errors.New("file table logger: FindChanges is not implemented; use a database-backed TableLogger for queryable change history")

// TableLoggerFile writes one JSON file per change-log row. Used in
// dev / single-host deployments where standing up an audit-DB schema
// would be overkill.
//
// Layout: <RootPath>/YYYYMMDD/<id>.json
//
// IDs come from the injected BigintGenerator (snowflake) so two
// concurrent writes in the same nanosecond can't collide on the
// filename. Date-partitioned subdirectories keep each directory
// under a few thousand files even on busy hosts (P1-47).
type TableLoggerFile struct {
	RootPath string
	IDs      port.BigintGenerator

	// fallbackSeq is used only when IDs is nil, to give a sane id
	// progression even in dev tests that didn't wire the generator.
	// Real deployments must supply IDs — see Init().
	fallbackSeq int64
}

func (l *TableLoggerFile) Init() error {
	if l.RootPath == "" {
		return fmt.Errorf("file table logger: RootPath is required")
	}
	if err := os.MkdirAll(l.RootPath, 0750); err != nil {
		return fmt.Errorf("file table logger: mkdir %s: %w", l.RootPath, err)
	}
	return nil
}

// nextID returns a fresh change-log id. Prefers the injected
// IdGenerator (snowflake) so ids are k-sortable AND unique across
// multiple writers; falls back to a process-local atomic counter
// composed with the unix-second timestamp for tests / dev.
func (l *TableLoggerFile) nextID() int64 {
	if l.IDs != nil {
		return l.IDs.NextID()
	}
	now := time.Now().Unix()
	seq := atomic.AddInt64(&l.fallbackSeq, 1)
	return now<<16 | (seq & 0xffff)
}

// dateDir returns the YYYYMMDD partition directory under RootPath
// for the current UTC day, creating it lazily on first use.
func (l *TableLoggerFile) dateDir() (string, error) {
	day := time.Now().UTC().Format("20060102")
	dir := filepath.Join(l.RootPath, day)
	if err := os.MkdirAll(dir, 0750); err != nil {
		return "", err
	}
	return dir, nil
}

func (l *TableLoggerFile) LogChange(change *model.TableChangeLog) error {
	change.ID = l.nextID()
	if change.DataHash == "" && change.OldData != nil {
		bytes, err := json.Marshal(change.OldData)
		if err != nil {
			return fmt.Errorf("file table logger: hash old data: %w", err)
		}
		hasher := sha256.New()
		hasher.Write(bytes)
		change.DataHash = hex.EncodeToString(hasher.Sum(nil))
	}
	dir, err := l.dateDir()
	if err != nil {
		return fmt.Errorf("file table logger: partition dir: %w", err)
	}
	filename := fmt.Sprintf("%d.json", change.ID)
	filePath := filepath.Join(dir, filename)
	fileContent, err := json.MarshalIndent(change, "", "  ")
	if err != nil {
		return err
	}
	// 0640: owner+group readable. Change rows can carry PII; default
	// 0644 made every change-log world-readable.
	return os.WriteFile(filePath, fileContent, 0640)
}

// GetChange reads a single change-log row by id. Walks every date
// partition in case the caller's id isn't from the current day.
// Acceptable cost for the file logger's expected workload (low
// volume + operator-driven reads).
func (l *TableLoggerFile) GetChange(id int64) (*model.TableChangeLog, error) {
	target := fmt.Sprintf("%d.json", id)
	entries, err := os.ReadDir(l.RootPath)
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		candidate := filepath.Join(l.RootPath, entry.Name(), target)
		if data, readErr := os.ReadFile(candidate); readErr == nil {
			change := &model.TableChangeLog{}
			if err := json.Unmarshal(data, change); err != nil {
				return nil, err
			}
			return change, nil
		}
	}
	return nil, fmt.Errorf("file table logger: change %d not found", id)
}

// FindChanges returns ErrFindChangesUnsupported. The file logger is
// not the right tool for query-style audit reads; consumers needing
// that should plug a DB-backed TableLogger.
func (l *TableLoggerFile) FindChanges(tableName string, userId int, key string, action string, begda time.Time, endda time.Time) ([]*model.TableChangeLog, error) {
	return nil, ErrFindChangesUnsupported
}

func (l *TableLoggerFile) Close() {}
