package secret

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// SecretProviderLocal reads secrets from a JSON file on disk. Lazy
// loaded on first GetSecret; refreshed only by this process's own
// PutSecret. Operators rotating a secret by hand must restart the
// process to pick up the new value (acceptable trade-off for a
// development-grade backend).
type SecretProviderLocal struct {
	Filename string

	once    sync.Once
	mu      sync.RWMutex
	loadErr error
	secrets map[string]string
}

// load parses the secrets file once. Wrapped in sync.Once so two
// concurrent first-callers don't both read+parse, and so the parse
// error is sticky — a malformed file shouldn't be retried into
// success on every call.
//
// Warns to stderr when the file's mode bits make it readable beyond
// the owner (P2-10). Operators occasionally drop a `0644` secrets
// file onto a shared host; surfacing the warning early gets that
// fixed before a second user on the box reads the credentials.
func (s *SecretProviderLocal) load() {
	if info, statErr := os.Stat(s.Filename); statErr == nil {
		if mode := info.Mode().Perm(); mode&0077 != 0 {
			fmt.Fprintf(os.Stderr, "warning: secrets file %s has mode %#o — restrict to owner-only (chmod 0600)\n",
				s.Filename, mode)
		}
	}
	data, err := os.ReadFile(s.Filename)
	if err != nil {
		s.loadErr = fmt.Errorf("failed to read secrets file %s: %w", s.Filename, err)
		return
	}
	parsed := map[string]string{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		s.loadErr = fmt.Errorf("failed to parse secrets file %s: %w", s.Filename, err)
		return
	}
	// Trim trailing whitespace on every value so the provider's
	// output matches AWS / GSM, which also trim (P1-27).
	for k, v := range parsed {
		parsed[k] = strings.TrimSpace(v)
	}
	s.secrets = parsed
}

func (s *SecretProviderLocal) GetSecret(ctx context.Context, path string) (string, error) {
	s.once.Do(s.load)
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.loadErr != nil {
		return "", s.loadErr
	}
	value, ok := s.secrets[path]
	if !ok {
		return "", fmt.Errorf("secret not found: %s", path)
	}
	return value, nil
}

// PutSecret merges into the file's current contents, so keys an operator added
// since load survive, and replaces the file atomically with mode 0600. A missing
// file is created. Writers in other processes are not coordinated.
func (s *SecretProviderLocal) PutSecret(ctx context.Context, path string, value string) error {
	if err := validatePut(path, value); err != nil {
		return err
	}
	s.once.Do(s.load)
	s.mu.Lock()
	defer s.mu.Unlock()

	onDisk := map[string]string{}
	data, err := os.ReadFile(s.Filename)
	switch {
	case errors.Is(err, fs.ErrNotExist):
	case err != nil:
		return fmt.Errorf("failed to read secrets file %s: %w", s.Filename, err)
	default:
		if err := json.Unmarshal(data, &onDisk); err != nil {
			return fmt.Errorf("failed to parse secrets file %s: %w", s.Filename, err)
		}
	}
	onDisk[path] = value
	if err := writeFileAtomic(s.Filename, onDisk); err != nil {
		return fmt.Errorf("failed to write secrets file %s: %w", s.Filename, err)
	}
	for k, v := range onDisk {
		onDisk[k] = strings.TrimSpace(v)
	}
	s.secrets, s.loadErr = onDisk, nil
	return nil
}

func writeFileAtomic(filename string, secrets map[string]string) error {
	data, err := json.MarshalIndent(secrets, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(filename), filepath.Base(filename)+".*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(append(data, '\n')); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), filename)
}

var _ SecretRWProvider = (*SecretProviderLocal)(nil)
