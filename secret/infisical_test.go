package secret

import (
	"context"
	"strings"
	"testing"

	"github.com/nauticana/keel/common"
)

// TestInfisicalRequiredFlags verifies the fail-fast boot behavior:
// missing project id or environment is a configuration error, never a
// silent default — matching the AWS / Azure providers. These cases never
// reach the network (the validation runs before UniversalAuthLogin).
func TestInfisicalRequiredFlags(t *testing.T) {
	orig := struct{ proj, env string }{*common.InfisicalProjectID, *common.InfisicalEnvironment}
	t.Cleanup(func() {
		*common.InfisicalProjectID = orig.proj
		*common.InfisicalEnvironment = orig.env
	})

	tests := []struct {
		name    string
		proj    string
		env     string
		wantSub string
	}{
		{"missing project id", "", "prod", "--infisical_project_id is required"},
		{"missing environment", "proj-123", "  ", "--infisical_environment is required"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			*common.InfisicalProjectID = tc.proj
			*common.InfisicalEnvironment = tc.env
			_, err := NewSecretProviderInfisical(context.Background())
			if err == nil {
				t.Fatalf("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("error %q does not contain %q", err, tc.wantSub)
			}
		})
	}
}
