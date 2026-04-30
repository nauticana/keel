package secret

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
)

// SecretProviderLocal reads secrets from a JSON file on disk. Lazy
// loaded on first GetSecret; not refreshed once loaded. Operators
// rotating a secret must restart the process to pick up the new
// value (acceptable trade-off for a development-grade backend).
type SecretProviderLocal struct {
	Filename string

	once    sync.Once
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
	if s.loadErr != nil {
		return "", s.loadErr
	}
	value, ok := s.secrets[path]
	if !ok {
		return "", fmt.Errorf("secret not found: %s", path)
	}
	return value, nil
}
