package secret

import (
	"context"
	"strings"
	"testing"
)

// The validation runs before UniversalAuthLogin, so these never reach the network.
func TestInfisicalRequiredSettings(t *testing.T) {
	tests := []struct{ name, proj, env, wantSub string }{
		{"missing project id", "", "prod", "--infisical_project_id is required"},
		{"missing environment", "proj-123", "  ", "--infisical_environment is required"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewSecretProviderFor(context.Background(), Settings{Mode: "infisical", InfisicalProjectID: tc.proj, InfisicalEnvironment: tc.env})
			if err == nil || !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("error %v does not contain %q", err, tc.wantSub)
			}
		})
	}
}
