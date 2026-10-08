package user

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/nauticana/keel/port"
	"golang.org/x/crypto/bcrypt"
)

type revokedOAuth struct {
	port.OAuthTokenStore
	users []int64
}

func (r *revokedOAuth) RevokeForUser(_ context.Context, userID int64) error {
	r.users = append(r.users, userID)
	return nil
}

func memberStore() *memStore {
	store := newMemStore(7)
	store.members[[2]int64{7, 11}] = true
	return store
}

func TestEndMembershipEndsRolesAndRevokesSessions(t *testing.T) {
	store := memberStore()
	svc := newLocalUserService(t, store)
	oauth := &revokedOAuth{}
	svc.OAuthTokens = oauth
	token, _ := svc.CreateRefreshToken(7, SignInPassword, 0)
	if session, err := svc.ValidateRefreshToken(token); err != nil || session.PartnerId != 11 {
		t.Fatalf("refresh before = %+v, %v", session, err)
	} else {
		token = session.NewRefreshToken
	}

	if err := svc.EndMembership(11, 7, "left"); err != nil {
		t.Fatal(err)
	}
	if len(store.endedRoles) != 1 || store.endedRoles[0] != 7 {
		t.Fatalf("role assignments ended for %v", store.endedRoles)
	}
	if _, err := svc.ValidateRefreshToken(token); !errors.Is(err, ErrInvalidRefreshToken) {
		t.Fatalf("refresh after the membership ended: %v", err)
	}
	if _, ok := store.cutoffs[7]; !ok {
		t.Fatal("access tokens issued so far must be rejected")
	}
	if len(oauth.users) != 1 || oauth.users[0] != 7 {
		t.Fatalf("authorization-server tokens = %v", oauth.users)
	}
	for _, c := range [][2]int64{{11, 7}, {12, 7}, {0, 7}, {11, 0}} {
		if err := svc.EndMembership(c[0], int(c[1]), "again"); !errors.Is(err, ErrNoMembership) {
			t.Errorf("EndMembership(%d, %d) = %v", c[0], c[1], err)
		}
	}
}

func TestEndMembershipRollsBackOnFailure(t *testing.T) {
	store := memberStore()
	store.failQuery[qEndPermissions] = errDatabaseDown
	svc := newLocalUserService(t, store)
	if err := svc.EndMembership(11, 7, "left"); !errors.Is(err, errDatabaseDown) {
		t.Fatalf("err = %v", err)
	}
	if store.commits != 0 || store.rollbacks != 1 {
		t.Fatalf("commits %d rollbacks %d", store.commits, store.rollbacks)
	}
}

// An ended row is read-only: the end statements may only touch open rows,
// and rows are never deleted.
func TestEndStatementsTouchOnlyOpenRows(t *testing.T) {
	for _, name := range []string{qEndMembership, qEndPermissions} {
		sql := LocalUserQueries[name]
		if !strings.Contains(sql, "endda IS NULL") || !strings.Contains(sql, "SET endda = CURRENT_TIMESTAMP") || strings.Contains(strings.ToUpper(sql), "DELETE") {
			t.Errorf("%s = %s", name, sql)
		}
	}
}

// A locked or expired account must not renew its session.
func TestRefreshRefusesUnavailableAccount(t *testing.T) {
	for _, status := range []string{UserStatusAdminLock, UserStatusExpired, UserStatusDeleted} {
		store := memberStore()
		store.addAccount(7, "a@acme.com", UserStatusActive)
		svc := newLocalUserService(t, store)
		token, _ := svc.CreateRefreshToken(7, SignInPassword, 0)
		store.accounts[7].status = status
		if _, err := svc.ValidateRefreshToken(token); !errors.Is(err, ErrInvalidRefreshToken) || !errors.Is(err, ErrAccountUnavailable) {
			t.Errorf("status %s: %v", status, err)
		}
		if store.tokens[sha256Hex(token)].revoked || len(store.tokens) != 1 {
			t.Errorf("status %s: a refused refresh must not rotate the token", status)
		}
		store.accounts[7].status = UserStatusActive
		if _, err := svc.ValidateRefreshToken(token); err != nil {
			t.Errorf("status %s: refresh after unlock: %v", status, err)
		}
	}
}

func TestEffectivePoliciesPreferThePartnerRow(t *testing.T) {
	store := newMemStore()
	store.policies[0] = map[string]int{"MAX_ATTEMPTS": 5, PolicySSORequired: 0}
	store.policies[11] = map[string]int{PolicySSORequired: 1, "MIN_PASSWORD_LENGTH": 12}
	svc := newLocalUserService(t, store)
	for partner, want := range map[int64]map[string]int{
		11: {"MAX_ATTEMPTS": 5, PolicySSORequired: 1, "MIN_PASSWORD_LENGTH": 12},
		12: {"MAX_ATTEMPTS": 5, PolicySSORequired: 0},
		0:  {"MAX_ATTEMPTS": 5, PolicySSORequired: 0},
	} {
		got, err := svc.EffectivePolicies(partner)
		if err != nil || len(got) != len(want) {
			t.Fatalf("partner %d = %v, %v", partner, got, err)
		}
		for policy, value := range want {
			if got[policy] != value {
				t.Errorf("partner %d %s = %d, want %d", partner, policy, got[policy], value)
			}
		}
	}
	sql := LocalUserQueries[qEffectivePolicies]
	for _, want := range []string{"DISTINCT ON (policy_type)", "partner_id = ? OR partner_id IS NULL", "ORDER BY policy_type, partner_id NULLS LAST"} {
		if !strings.Contains(sql, want) {
			t.Errorf("effective policy query lacks %q", want)
		}
	}
}

// User 7 belongs to partner 11; user 8 has no partner.
func TestSSORequiredLevels(t *testing.T) {
	store := memberStore()
	store.users[8] = true
	svc := newLocalUserService(t, store)
	all := []string{SignInPassword, SignInOTP, SignInExternal, SignInTenant}
	admitted := func(user int) string {
		out := ""
		for _, method := range all {
			err := svc.CheckSignInMethod(user, method)
			if err == nil {
				out += method
			} else if !errors.Is(err, ErrSSORequired) {
				t.Fatalf("user %d %s: %v", user, method, err)
			}
		}
		return out
	}
	if got := admitted(7); got != "POET" {
		t.Fatalf("no policy admits %q", got)
	}
	store.policies[11] = map[string]int{PolicySSORequired: SSOAnyIdentity}
	if got := admitted(7); got != "ET" {
		t.Fatalf("any-identity SSO admits %q", got)
	}
	if got := admitted(8); got != "POET" {
		t.Fatalf("another partner's policy must not apply: %q", got)
	}
	// A personal Google or Apple account does not satisfy the partner's own IdP.
	store.policies[11][PolicySSORequired] = SSOPartnerIdentity
	if got := admitted(7); got != "T" {
		t.Fatalf("partner-identity SSO admits %q", got)
	}
	store.policies[11][PolicySSORequired] = 9
	if got := admitted(7); got != "T" {
		t.Fatalf("an unknown level gets the strictest reading: %q", got)
	}
	// Global requirement, with the partner's own row exempting it.
	store.policies = map[int64]map[string]int{0: {PolicySSORequired: SSOAnyIdentity}, 11: {PolicySSORequired: 0}}
	if admitted(8) != "ET" || admitted(7) != "POET" {
		t.Fatalf("global %q, exempted partner %q", admitted(8), admitted(7))
	}
	for _, c := range []struct {
		user   int
		method string
	}{{7, "magic"}, {7, ""}, {0, SignInPassword}} {
		if err := svc.CheckSignInMethod(c.user, c.method); err == nil || errors.Is(err, ErrSSORequired) {
			t.Errorf("CheckSignInMethod(%d, %q) = %v", c.user, c.method, err)
		}
	}
	store.failQuery[qUserPolicies] = errDatabaseDown
	if err := svc.CheckSignInMethod(7, SignInPassword); !errors.Is(err, errDatabaseDown) {
		t.Fatalf("a policy lookup failure must refuse the sign-in: %v", err)
	}
}

func TestSignInLifetimeSurvivesRotation(t *testing.T) {
	store := memberStore()
	svc := newLocalUserService(t, store)
	if _, err := svc.CreateRefreshToken(7, SignInPassword, -time.Hour); err == nil {
		t.Fatal("a negative lifetime must be refused")
	}
	maxDuration := time.Duration(1<<63 - 1)
	if _, err := svc.CreateRefreshToken(7, SignInPassword, maxDuration); err != nil {
		t.Fatalf("a large positive lifetime must not overflow: %v", err)
	}
	for _, row := range store.tokens {
		if want := int64(maxDuration/time.Second + 1); row.maxAge != want {
			t.Fatalf("rounded lifetime = %v", row.maxAge)
		}
	}
	token, err := svc.CreateRefreshToken(7, SignInPassword, 10*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	for range 3 {
		store.clock += 3 * time.Hour
		session, err := svc.ValidateRefreshToken(token)
		if err != nil {
			t.Fatalf("refresh inside the sign-in lifetime: %v", err)
		}
		token = session.NewRefreshToken
	}
	store.clock += 3 * time.Hour
	if _, err := svc.ValidateRefreshToken(token); !errors.Is(err, ErrInvalidRefreshToken) {
		t.Fatalf("refresh after the sign-in lifetime: %v", err)
	}

	token, _ = svc.CreateRefreshToken(7, SignInPassword, 0)
	store.clock += 1000 * time.Hour
	if _, err := svc.ValidateRefreshToken(token); err != nil {
		t.Fatalf("no lifetime renews without limit: %v", err)
	}
}

func TestSessionMaxHoursEndsARenewedSession(t *testing.T) {
	store := memberStore()
	store.policies[0] = map[string]int{PolicySessionMaxHours: 100}
	store.policies[11] = map[string]int{PolicySessionMaxHours: 10}
	svc := newLocalUserService(t, store)
	token, _ := svc.CreateRefreshToken(7, SignInPassword, 0)
	for range 3 {
		store.clock += 3 * time.Hour
		session, err := svc.ValidateRefreshToken(token)
		if err != nil {
			t.Fatalf("refresh inside the partner's lifetime: %v", err)
		}
		token = session.NewRefreshToken
	}
	store.clock += 3 * time.Hour
	if _, err := svc.ValidateRefreshToken(token); !errors.Is(err, ErrInvalidRefreshToken) {
		t.Fatalf("refresh after the partner's SESSION_MAX_HOURS: %v", err)
	}
	delete(store.policies, 11)
	session, err := svc.ValidateRefreshToken(token)
	if err != nil {
		t.Fatalf("the global limit applies without a partner row: %v", err)
	}
	token = session.NewRefreshToken
	store.policies[0][PolicySessionMaxHours] = 0
	store.clock += 1000 * time.Hour
	if session, err = svc.ValidateRefreshToken(token); err != nil {
		t.Fatalf("0 is unlimited: %v", err)
	}
	token = session.NewRefreshToken
	store.failQuery[qEffectivePolicies] = errDatabaseDown
	if _, err := svc.ValidateRefreshToken(token); !errors.Is(err, errDatabaseDown) {
		t.Fatalf("a policy lookup failure must refuse the refresh: %v", err)
	}
}

// A partner's own password rules apply to its users over the global rules.
func TestPasswordRulesFollowThePartner(t *testing.T) {
	store := memberStore() // user 7 belongs to partner 11
	store.users[8] = true  // user 8 has no partner
	store.policies[11] = map[string]int{"MIN_PASSWORD_LENGTH": 14, "MAX_ATTEMPTS": 2, "AUTO_UNLOCK_MINUTES": 60}
	svc := newLocalUserService(t, store)
	global := svc.GetPasswordPolicy()

	partner, err := svc.policyFor(7)
	if err != nil || partner.MinPasswordLength != 14 || partner.MaxAttempts != 2 || partner.AutoUnlock != int64(time.Hour) {
		t.Fatalf("partner rules = %+v, %v", partner, err)
	}
	if partner.MinPasswordDigit != global.MinPasswordDigit || partner.PasswordExpire != global.PasswordExpire {
		t.Fatalf("rules the partner does not set stay global: %+v", partner)
	}
	if got, err := svc.policyFor(8); err != nil || got != global {
		t.Fatalf("a user without a partner follows the global rules: %+v, %v", got, err)
	}

	const tenChars = "Abcdefgh1j"
	if err := svc.SetPassword(8, tenChars); err != nil {
		t.Fatalf("global length: %v", err)
	}
	if err := svc.SetPassword(7, tenChars); err == nil {
		t.Fatal("the partner's longer minimum must apply")
	}

	locked := time.Now().Add(-30 * time.Minute)
	if err := svc.checkAccountStatus(8, UserStatusSelfLocked, locked); err != nil {
		t.Fatalf("global auto-unlock has passed: %v", err)
	}
	if err := svc.checkAccountStatus(7, UserStatusSelfLocked, locked); !errors.Is(err, ErrAccountUnavailable) {
		t.Fatalf("the partner's longer lock must still hold: %v", err)
	}
}

// A failed policy lookup refuses the operation instead of applying the
// weaker global rules.
func TestPasswordPolicyLookupFailsClosed(t *testing.T) {
	store := memberStore()
	store.failQuery[qUserPolicies] = errDatabaseDown
	svc := newLocalUserService(t, store)
	if _, err := svc.policyFor(7); !errors.Is(err, errDatabaseDown) {
		t.Fatalf("policyFor: %v", err)
	}
	if err := svc.SetPassword(7, "Abcdefgh1jklmnop"); !errors.Is(err, errDatabaseDown) {
		t.Fatalf("SetPassword: %v", err)
	}
	if err := svc.checkAccountStatus(7, UserStatusSelfLocked, time.Now().Add(-time.Hour)); !errors.Is(err, errDatabaseDown) {
		t.Fatalf("a self-locked account must not unlock on a failed lookup: %v", err)
	}
	if _, err := svc.bumpLoginAttempts(7, "test"); !errors.Is(err, errDatabaseDown) {
		t.Fatalf("bumpLoginAttempts: %v", err)
	}
	if store.count(qSetLockStatus) != 0 {
		t.Fatal("a failed lookup must not lock the account either")
	}
}

// Turning SSO on ends sessions that signed in another way, at their next refresh.
func TestRequiredSSOEndsOtherSessionsAtRefresh(t *testing.T) {
	store := memberStore()
	svc := newLocalUserService(t, store)
	issue := func() map[string]string {
		tokens := map[string]string{}
		for name, method := range map[string]string{"password": SignInPassword, "otp": SignInOTP, "unknown": "", "external": SignInExternal, "tenant": SignInTenant} {
			tokens[name], _ = svc.CreateRefreshToken(7, method, 0)
		}
		return tokens
	}
	check := func(level int, survivors ...string) {
		t.Helper()
		tokens := issue()
		store.policies[11] = map[string]int{PolicySSORequired: level}
		for name, token := range tokens {
			session, err := svc.ValidateRefreshToken(token)
			want := false
			for _, s := range survivors {
				want = want || s == name
			}
			switch {
			case want && err != nil:
				t.Errorf("level %d: %s session refused: %v", level, name, err)
			case !want && (!errors.Is(err, ErrInvalidRefreshToken) || !errors.Is(err, ErrSSORequired)):
				t.Errorf("level %d: %s session = %v", level, name, err)
			case want:
				if again, err := svc.ValidateRefreshToken(session.NewRefreshToken); err != nil || again.SignInMethod != session.SignInMethod {
					t.Errorf("level %d: the method must survive rotation: %v", level, err)
				}
			}
		}
		delete(store.policies, 11)
	}
	check(SSOAnyIdentity, "external", "tenant")
	check(SSOPartnerIdentity, "tenant")
}

// A login whose session partner cannot be loaded must fail, not produce a
// session with partner 0.
func TestPasswordLoginFailsWhenThePartnerCannotBeLoaded(t *testing.T) {
	hash, err := bcrypt.GenerateFromPassword([]byte("Abcdefgh1j"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	store := memberStore()
	store.loginRow = []any{int64(7), "rider", "F", "L", "a@acme.com", UserStatusActive, time.Now(), string(hash), int16(0), nil, nil, nil}
	svc := newLocalUserService(t, store)
	if _, err := svc.GetUserByLogin("rider", "Abcdefgh1j"); err != nil {
		t.Fatalf("login: %v", err)
	}
	store.failQuery[qPartnerUserByid] = errDatabaseDown
	if session, err := svc.GetUserByLogin("rider", "Abcdefgh1j"); !errors.Is(err, errDatabaseDown) || session != nil {
		t.Fatalf("login with a failed partner lookup = %+v, %v", session, err)
	}
}
