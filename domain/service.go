package domain

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/publicsuffix"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/config"
	"github.com/nauticana/keel/data"
	"github.com/nauticana/keel/model"
	"github.com/nauticana/keel/pgsql"
	"github.com/nauticana/keel/port"
)

const (
	maxHistory   = 500
	maxLastError = 500
	codeDigits   = 6
)

// Service is the only writer of domain verification evidence. Verifiers are
// wired explicitly; a method without one is refused.
type Service struct {
	DB        port.DatabaseRepository
	Verifiers []DomainVerifier
	// AccessToken returns a current provider grant for re-checking a
	// provider-attested verification. Nil leaves that evidence point-in-time.
	AccessToken func(ctx context.Context, v *Verification) (string, error)
	// OnLapsed runs after a re-check lapses evidence, for example to notify
	// the partner's administrators.
	OnLapsed func(ctx context.Context, v *Verification) error

	once sync.Once
	qs   port.QueryService
}

func (s *Service) query(ctx context.Context) port.QueryService {
	s.once.Do(func() { s.qs = s.DB.GetQueryService(ctx, queries) })
	return s.qs
}

func (s *Service) verifier(method string) (DomainVerifier, error) {
	for _, v := range s.Verifiers {
		if v.Method() == method {
			return v, nil
		}
	}
	return nil, fmt.Errorf("%w: %q", ErrUnknownMethod, method)
}

// Challenge issues a challenge for a challenge-based method (EC, DT, HF) and
// returns its secret once. recipient is the address that receives an email
// code; it must be on the domain's registrable domain.
func (s *Service) Challenge(ctx context.Context, partnerID, userID int64, domainURL, method, recipient string) (*Challenge, error) {
	if !isChallengeMethod(method) {
		return nil, fmt.Errorf("%w: %q has no challenge", ErrUnknownMethod, method)
	}
	if _, err := s.verifier(method); err != nil {
		return nil, err
	}
	name, err := s.authorize(ctx, s.query(ctx), partnerID, userID, domainURL)
	if err != nil {
		return nil, err
	}
	cfg := config.Config()
	ch := &Challenge{Method: method, DomainURL: domainURL, DomainName: name}
	ttl := cfg.DomainChallengeTTL
	var recipientArg any
	if method == MethodEmailCode {
		recipient = strings.ToLower(strings.TrimSpace(recipient))
		if strings.ContainsAny(recipient, " \r\n,;<>") {
			return nil, ErrRecipient
		}
		if err := MailboxOnDomain(recipient, domainURL); err != nil {
			return nil, err
		}
		if ch.Token, err = common.GenerateNumericCode(codeDigits); err != nil {
			return nil, err
		}
		ch.Recipient, recipientArg, ttl = recipient, recipient, cfg.DomainCodeTTL
	} else if ch.Token, err = randomToken(); err != nil {
		return nil, err
	}
	switch method {
	case MethodDNSTXT:
		ch.RecordName, ch.RecordValue = name, TXTValue(ch.Token)
	case MethodHTTPFile:
		ch.FileURL, ch.FileBody = FileURL(name), ch.Token
	}
	res, err := s.query(ctx).Query(ctx, qIssueChallenge, partnerID, domainURL, method, common.Sha256Hex(ch.Token),
		recipientArg, userID, seconds(ttl), seconds(cfg.DomainChallengeCooldown))
	if err != nil {
		return nil, err
	}
	if len(res.Rows) == 0 {
		return nil, ErrCooldown
	}
	ch.ExpiresAt = common.AsTime(res.Rows[0][0])
	return ch, nil
}

// Confirm checks the open challenge of a challenge-based method and records
// the verification when it holds. response is the code for EC and ignored
// otherwise. Each call counts against domain_challenge_attempts.
func (s *Service) Confirm(ctx context.Context, partnerID, userID int64, domainURL, method, response string) (*Verification, error) {
	if !isChallengeMethod(method) {
		return nil, fmt.Errorf("%w: %q has no challenge", ErrUnknownMethod, method)
	}
	v, err := s.verifier(method)
	if err != nil {
		return nil, err
	}
	name, err := s.authorize(ctx, s.query(ctx), partnerID, userID, domainURL)
	if err != nil {
		return nil, err
	}
	maxAttempts := config.Config().DomainChallengeAttempts
	res, err := s.query(ctx).Query(ctx, qAttemptChallenge, maxAttempts+1, partnerID, domainURL, method)
	if err != nil {
		return nil, err
	}
	if len(res.Rows) == 0 {
		return nil, ErrNoChallenge
	}
	if common.AsInt64(res.Rows[0][0]) > int64(maxAttempts) {
		return nil, ErrTooManyTries
	}
	tokenHash := common.AsString(res.Rows[0][1])
	ref, err := v.Verify(ctx, DomainProof{PartnerID: partnerID, Domain: name, TokenHash: tokenHash, Response: response})
	if err != nil {
		return nil, err
	}
	return s.record(ctx, partnerID, userID, domainURL, &Evidence{method: method, domainName: name, tokenHash: tokenHash, ref: ref})
}

// Verify checks a method that needs no challenge (VE, GH, GM, GS, GB, GW,
// ME) for an existing partner domain and records it. The caller fills
// proof's identity fields from a verified session or token, and AccessToken
// from the acting user's provider grant.
func (s *Service) Verify(ctx context.Context, partnerID, userID int64, domainURL, method string, proof DomainProof) (*Verification, error) {
	if _, err := s.authorize(ctx, s.query(ctx), partnerID, userID, domainURL); err != nil {
		return nil, err
	}
	ev, err := s.check(ctx, domainURL, method, proof, partnerID)
	if err != nil {
		return nil, err
	}
	return s.record(ctx, partnerID, userID, domainURL, ev)
}

// Check runs a method that needs no challenge without recording it, for a
// flow that proves the domain before the partner exists. Record the result
// with RecordTx in the transaction that creates the partner.
func (s *Service) Check(ctx context.Context, domainURL, method string, proof DomainProof) (*Evidence, error) {
	return s.check(ctx, domainURL, method, proof, 0)
}

func (s *Service) check(ctx context.Context, domainURL, method string, proof DomainProof, partnerID int64) (*Evidence, error) {
	if isChallengeMethod(method) {
		return nil, fmt.Errorf("%w: %q needs a challenge", ErrUnknownMethod, method)
	}
	v, err := s.verifier(method)
	if err != nil {
		return nil, err
	}
	name, err := verifiableName(domainURL)
	if err != nil {
		return nil, err
	}
	proof.PartnerID, proof.Domain, proof.TokenHash, proof.Response = partnerID, name, "", ""
	ref, err := v.Verify(ctx, proof)
	if err != nil {
		return nil, err
	}
	return &Evidence{method: method, domainName: name, ref: ref}, nil
}

func (s *Service) record(ctx context.Context, partnerID, userID int64, domainURL string, ev *Evidence) (*Verification, error) {
	tx, err := s.DB.BeginTx(ctx, queries)
	if err != nil {
		return nil, err
	}
	committed := false
	defer func() {
		if !committed {
			_ = data.RollbackDetached(tx)
		}
	}()
	v, err := s.RecordTx(ctx, tx, partnerID, userID, domainURL, ev)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	committed = true
	return v, nil
}

// RecordTx records evidence in the caller's transaction, whose query map
// includes TxQueries. The partner domain and the user's membership must exist
// in that transaction. Re-proving a method that is already current refreshes
// that row; otherwise a row is appended. A pending challenge of the method is
// consumed.
func (s *Service) RecordTx(ctx context.Context, tx port.TxQueryService, partnerID, userID int64, domainURL string, ev *Evidence) (*Verification, error) {
	if ev == nil || ev.method == "" {
		return nil, ErrUnknownMethod
	}
	name, err := s.authorize(ctx, tx, partnerID, userID, domainURL)
	if err != nil {
		return nil, err
	}
	if name != ev.domainName {
		return nil, fmt.Errorf("%w: evidence is for %s, not %s", ErrInvalidDomain, ev.domainName, name)
	}
	if isIdentityMethod(ev.method) {
		if _, err := tx.Query(ctx, qLockName, name); err != nil {
			return nil, err
		}
		other, err := tx.Query(ctx, qOtherHolders, name, identityMethods, partnerID)
		if err != nil {
			return nil, err
		}
		if len(other.Rows) > 0 {
			return nil, ErrDomainHeld
		}
	}
	same, err := tx.Query(ctx, qCurrentSame, partnerID, domainURL, ev.method)
	if err != nil {
		return nil, err
	}
	if len(same.Rows) > 0 {
		_, err = tx.Query(ctx, qRefresh, nullable(ev.tokenHash), nullable(ev.ref), partnerID, domainURL, ev.method)
	} else {
		_, err = tx.Query(ctx, qInsert, partnerID, domainURL, name, ev.method, userID, nullable(ev.tokenHash), nullable(ev.ref))
	}
	if err != nil {
		if pgsql.IsUniqueViolation(err) {
			return nil, fmt.Errorf("domain verification: concurrent verification of %s: %w", ev.method, err)
		}
		return nil, err
	}
	if _, err := tx.Query(ctx, qDeleteChallenge, partnerID, domainURL, ev.method); err != nil {
		return nil, err
	}
	res, err := tx.Query(ctx, qGetCurrent, partnerID, domainURL, ev.method)
	if err != nil {
		return nil, err
	}
	if len(res.Rows) == 0 {
		return nil, ErrNoVerification
	}
	return verificationFromRow(res.Rows[0]), nil
}

// Current returns the partner's current evidence for the domain by any of
// methods. No methods means nothing is honored.
func (s *Service) Current(ctx context.Context, partnerID int64, domainURL string, methods []string) ([]*Verification, error) {
	if partnerID <= 0 || len(methods) == 0 {
		return nil, nil
	}
	return s.list(ctx, qCurrent, partnerID, domainURL, methods)
}

// Domains returns the partner's current evidence for all its domains by any
// of methods.
func (s *Service) Domains(ctx context.Context, partnerID int64, methods []string) ([]*Verification, error) {
	if partnerID <= 0 || len(methods) == 0 {
		return nil, nil
	}
	return s.list(ctx, qPartnerCurrent, partnerID, methods)
}

// History returns the partner's verifications of the domain, newest first.
func (s *Service) History(ctx context.Context, partnerID int64, domainURL string, limit int) ([]*Verification, error) {
	if partnerID <= 0 {
		return nil, nil
	}
	if limit <= 0 || limit > maxHistory {
		limit = maxHistory
	}
	return s.list(ctx, qHistory, partnerID, domainURL, limit)
}

func (s *Service) list(ctx context.Context, name string, args ...any) ([]*Verification, error) {
	res, err := s.query(ctx).Query(ctx, name, args...)
	if err != nil {
		return nil, err
	}
	out := make([]*Verification, 0, len(res.Rows))
	for _, r := range res.Rows {
		out = append(out, verificationFromRow(r))
	}
	return out, nil
}

// Holders lists the partners with current evidence for domain by any of
// methods. domain may be a host or URL; it is normalized first.
func (s *Service) Holders(ctx context.Context, domain string, methods []string) ([]int64, error) {
	name, ok := DomainName(domain)
	if !ok || len(methods) == 0 {
		return nil, nil
	}
	res, err := s.query(ctx).Query(ctx, qHolders, name, methods)
	if err != nil {
		return nil, err
	}
	out := make([]int64, 0, len(res.Rows))
	for _, r := range res.Rows {
		out = append(out, common.AsInt64(r[0]))
	}
	return out, nil
}

// IdentityHolder returns the one partner whose current evidence for domain
// uses an identity method, or ErrNotHeld.
func (s *Service) IdentityHolder(ctx context.Context, domain string) (int64, error) {
	holders, err := s.Holders(ctx, domain, identityMethods)
	if err != nil {
		return 0, err
	}
	if len(holders) != 1 {
		return 0, ErrNotHeld
	}
	return holders[0], nil
}

// Cancel withdraws the partner's current evidence for the domain by method,
// or by every method when method is empty, and returns the cancelled methods.
func (s *Service) Cancel(ctx context.Context, partnerID, userID int64, domainURL, method string) ([]string, error) {
	if _, err := s.authorize(ctx, s.query(ctx), partnerID, userID, domainURL); err != nil {
		return nil, err
	}
	res, err := s.query(ctx).Query(ctx, qCancel, userID, partnerID, domainURL, method, method)
	if err != nil {
		return nil, err
	}
	if len(res.Rows) == 0 {
		return nil, ErrNoVerification
	}
	out := make([]string, 0, len(res.Rows))
	for _, r := range res.Rows {
		out = append(out, common.AsString(r[0]))
	}
	return out, nil
}

// RecheckSummary counts one Recheck pass.
type RecheckSummary struct {
	Checked int // rows examined
	Held    int // evidence still holds
	Failing int // negative verdict within the grace period
	Lapsed  int // negative verdict past the grace period
	Errored int // check could not complete; no verdict
}

// Recheck re-verifies up to limit current rows older than
// domain_recheck_interval. A negative verdict lapses the evidence once it has
// failed for domain_recheck_grace; a check that cannot complete is recorded
// without a verdict. Errors from individual rows are joined.
func (s *Service) Recheck(ctx context.Context, limit int) (RecheckSummary, error) {
	var sum RecheckSummary
	if limit <= 0 {
		return sum, fmt.Errorf("domain verification: recheck limit must be positive")
	}
	methods := s.recheckable()
	if len(methods) == 0 {
		return sum, nil
	}
	cfg := config.Config()
	qs := s.query(ctx)
	res, err := qs.Query(ctx, qDue, methods, seconds(cfg.DomainRecheckInterval), limit)
	if err != nil {
		return sum, err
	}
	var errs []error
	for _, row := range res.Rows {
		if ctx.Err() != nil {
			errs = append(errs, ctx.Err())
			break
		}
		v := verificationFromRow(row)
		sum.Checked++
		if err := s.recheckOne(ctx, qs, v, common.AsString(row[13]), &sum); err != nil {
			errs = append(errs, fmt.Errorf("%d %s %s: %w", v.PartnerID, v.DomainURL, v.Method, err))
		}
	}
	return sum, errors.Join(errs...)
}

func (s *Service) recheckable() []string {
	var out []string
	for _, v := range s.Verifiers {
		m := v.Method()
		if m == MethodDNSTXT || m == MethodHTTPFile || (s.AccessToken != nil && slices.Contains(grantMethods, m)) {
			out = append(out, m)
		}
	}
	return out
}

func (s *Service) recheckOne(ctx context.Context, qs port.QueryService, v *Verification, tokenHash string, sum *RecheckSummary) error {
	verifier, err := s.verifier(v.Method)
	if err != nil {
		return err
	}
	proof := DomainProof{PartnerID: v.PartnerID, Domain: v.DomainName, TokenHash: tokenHash}
	var checkErr error
	if slices.Contains(grantMethods, v.Method) {
		proof.AccessToken, checkErr = s.AccessToken(ctx, v)
	}
	if checkErr == nil {
		_, checkErr = verifier.Verify(ctx, proof)
	}
	key := []any{v.PartnerID, v.DomainURL, v.VerifiedAt}
	switch {
	case checkErr == nil:
		sum.Held++
		_, err = qs.Query(ctx, qCheckHeld, key...)
		return err
	case errors.Is(checkErr, ErrDomainNotProven):
		res, err := qs.Query(ctx, qCheckFailed, append([]any{truncate(checkErr.Error()), seconds(config.Config().DomainRecheckGrace)}, key...)...)
		if err != nil {
			return err
		}
		if len(res.Rows) == 0 || common.AsTime(res.Rows[0][0]).IsZero() {
			sum.Failing++
			return nil
		}
		sum.Lapsed++
		v.LapsedAt = common.AsTime(res.Rows[0][0])
		if s.OnLapsed != nil {
			return s.OnLapsed(ctx, v)
		}
		return nil
	default:
		sum.Errored++
		if _, err := qs.Query(ctx, qCheckError, append([]any{truncate(checkErr.Error())}, key...)...); err != nil {
			return errors.Join(checkErr, err)
		}
		return checkErr
	}
}

// authorize requires a current member of the partner and returns the
// normalized name of one of the partner's domains.
func (s *Service) authorize(ctx context.Context, qs querier, partnerID, userID int64, domainURL string) (string, error) {
	if partnerID <= 0 || userID <= 0 {
		return "", ErrNotMember
	}
	member, err := qs.Query(ctx, qMember, partnerID, userID)
	if err != nil {
		return "", err
	}
	if len(member.Rows) == 0 {
		return "", ErrNotMember
	}
	res, err := qs.Query(ctx, qDomain, partnerID, domainURL)
	if err != nil {
		return "", err
	}
	if len(res.Rows) == 0 {
		return "", ErrDomainNotFound
	}
	return verifiableName(domainURL)
}

type querier interface {
	Query(ctx context.Context, name string, args ...any) (*model.QueryResult, error)
}

// MailboxOnDomain reports whether email can prove the domain by a mailbox
// method (EC, VE): a non-public address sharing the domain's registrable
// domain. Use it to validate a signup before sending a code.
func MailboxOnDomain(email, domainURL string) error {
	name, err := verifiableName(domainURL)
	if err != nil {
		return err
	}
	at := DomainFromEmail(strings.TrimSpace(email))
	if at == "" || IsPublicDomain(at) || !DomainsMatch(at, name) {
		return ErrRecipient
	}
	return nil
}

// verifiableName refuses names nobody can own: public suffixes and free
// mailbox providers.
func verifiableName(domainURL string) (string, error) {
	name, ok := DomainName(domainURL)
	if !ok || IsPublicDomain(name) {
		return "", ErrInvalidDomain
	}
	if suffix, _ := publicsuffix.PublicSuffix(name); suffix == name {
		return "", ErrInvalidDomain
	}
	return name, nil
}

// TXTValue is the DNS TXT record value that proves token.
func TXTValue(token string) string {
	return config.Config().DomainVerificationLabel + "=" + token
}

// FileURL is where a host serves the HTTP file challenge.
func FileURL(name string) string {
	return "https://" + name + "/.well-known/" + config.Config().DomainVerificationLabel + ".txt"
}

func randomToken() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func seconds(d time.Duration) int { return int(d / time.Second) }

func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func truncate(s string) string {
	if len(s) <= maxLastError {
		return s
	}
	return strings.ToValidUTF8(s[:maxLastError], "")
}
