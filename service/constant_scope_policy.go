package service

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/port"
)

const qConstantScopes = "select_constant_scopes"

var constantScopeQueries = map[string]string{
	qConstantScopes: `SELECT value FROM constant_value WHERE constant_id = ?`,
}

// ConstantScopePolicy is an APIKeyService.ScopePolicy allowing the
// constant_value codes of Constant. A blank request takes Default. The catalog
// is read on first success; an unreadable or empty one, or one lacking
// Default, refuses every key.
type ConstantScopePolicy struct {
	DB       port.DatabaseRepository
	Constant string
	Default  string

	mu     sync.Mutex
	qs     port.QueryService
	scopes map[string]bool
}

// Policy trims the scopes, drops duplicates, and refuses an unknown one with ErrInvalidScopes.
func (p *ConstantScopePolicy) Policy(ctx context.Context, _, _ int64, scopes string) (string, error) {
	catalog, err := p.load(ctx)
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(scopes) == "" {
		scopes = p.Default
	}
	var out []string
	for _, scope := range strings.Split(scopes, ",") {
		scope = strings.TrimSpace(scope)
		if !catalog[scope] {
			return "", fmt.Errorf("%w: unknown scope %q", ErrInvalidScopes, scope)
		}
		if !slices.Contains(out, scope) {
			out = append(out, scope)
		}
	}
	return strings.Join(out, ","), nil
}

func (p *ConstantScopePolicy) load(ctx context.Context) (map[string]bool, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.scopes != nil {
		return p.scopes, nil
	}
	if p.qs == nil {
		p.qs = p.DB.GetQueryService(ctx, constantScopeQueries)
	}
	res, err := p.qs.Query(ctx, qConstantScopes, p.Constant)
	if err != nil {
		return nil, fmt.Errorf("api key scope catalog %s: %w", p.Constant, err)
	}
	scopes := make(map[string]bool, len(res.Rows))
	for _, row := range res.Rows {
		if len(row) != 1 || common.AsString(row[0]) == "" {
			return nil, fmt.Errorf("api key scope catalog %s returned a malformed row %v", p.Constant, row)
		}
		scopes[common.AsString(row[0])] = true
	}
	if len(scopes) == 0 || (p.Default != "" && !scopes[p.Default]) {
		return nil, fmt.Errorf("api key scope catalog %s is empty or lacks %q", p.Constant, p.Default)
	}
	p.scopes = scopes
	return scopes, nil
}
