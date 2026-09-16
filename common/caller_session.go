package common

import (
	"context"
	"errors"
	"strings"

	"github.com/nauticana/keel/model"
)

var ErrUnauthenticated = errors.New("no authenticated principal, subject, or api key in context")

var ErrCallerIdentityConflict = errors.New("authenticated principal and subject disagree")

// CallerSession is what keel's middleware established for a request, readable anywhere a context flows —
// handlers, services, and workers alike.
type CallerSession struct {
	Principal *model.TokenPrincipal
	Subject   string
	PartnerID int64
	APIKeyID  int64
	Scopes    []string
	RequestID string
}

// CallerSessionFromContext fails closed: an unauthenticated context is an error, never an empty session.
func CallerSessionFromContext(ctx context.Context) (CallerSession, error) {
	if ctx == nil {
		return CallerSession{}, ErrUnauthenticated
	}
	s := CallerSession{RequestID: RequestIDFromContext(ctx)}
	s.Principal, _ = ctx.Value(AuthPrincipal).(*model.TokenPrincipal)
	s.Subject, _ = ctx.Value(Subject).(string)
	s.PartnerID, _ = ctx.Value(PartnerID).(int64)
	s.APIKeyID, _ = ctx.Value(ApiKeyID).(int64)
	if raw, ok := ctx.Value(Scopes).(string); ok {
		s.Scopes = strings.FieldsFunc(raw, func(r rune) bool { return r == ' ' || r == ',' })
	}
	if s.Principal != nil {
		if s.Subject != "" && s.Principal.Subject != "" && s.Subject != s.Principal.Subject {
			return CallerSession{}, ErrCallerIdentityConflict
		}
		if s.Subject == "" {
			s.Subject = s.Principal.Subject
		}
		// The validated token principal is authoritative. A separate context value must never broaden its scopes.
		s.Scopes = append([]string(nil), s.Principal.Scopes...)
	}
	if strings.TrimSpace(s.Subject) == "" && s.APIKeyID <= 0 {
		return CallerSession{}, ErrUnauthenticated
	}
	return s, nil
}

// WithCallerSession binds a session where no middleware runs, such as a worker acting on a claimed job.
func WithCallerSession(ctx context.Context, s CallerSession) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	if s.Principal != nil {
		ctx = context.WithValue(ctx, AuthPrincipal, s.Principal)
		s.Scopes = s.Principal.Scopes
	}
	if s.Subject != "" {
		ctx = context.WithValue(ctx, Subject, s.Subject)
	}
	if s.PartnerID > 0 {
		ctx = context.WithValue(ctx, PartnerID, s.PartnerID)
	}
	if s.APIKeyID > 0 {
		ctx = context.WithValue(ctx, ApiKeyID, s.APIKeyID)
	}
	if len(s.Scopes) > 0 {
		ctx = context.WithValue(ctx, Scopes, strings.Join(s.Scopes, " "))
	}
	return WithRequestID(ctx, s.RequestID)
}

func (s CallerSession) HasScope(scope string) bool {
	for _, granted := range s.Scopes {
		if granted == scope {
			return true
		}
	}
	return false
}
