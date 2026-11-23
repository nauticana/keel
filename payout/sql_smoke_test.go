package payout

import (
	"testing"

	"github.com/nauticana/keel/pgsql/sqlsmoke"
)

func TestNamedQueriesPrepare(t *testing.T) {
	sqlsmoke.Test(t, map[string]map[string]string{
		"onboarding":  onboardingQueries,
		"instruction": instructionQueries,
		"resolver":    providerResolverQueries,
		"webhook":     payoutWebhookQueries,
	}, "../schema/basis_pgsql.sql")
}
