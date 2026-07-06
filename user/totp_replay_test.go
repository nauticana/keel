package user

import (
	"testing"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

// TestMatchTOTPStep verifies the replay-guard helper: a valid code resolves to
// a monotonic 30s timestep, an adjacent-window code is accepted (±1 skew), and
// a garbage code is rejected.
func TestMatchTOTPStep(t *testing.T) {
	key, err := totp.Generate(totp.GenerateOpts{Issuer: "keel", AccountName: "u@example.com"})
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	secret := key.Secret()
	now := time.Unix(1_700_000_000, 0)

	code, err := totp.GenerateCode(secret, now)
	if err != nil {
		t.Fatalf("code: %v", err)
	}

	step, ok := matchTOTPStep(code, secret, now)
	if !ok {
		t.Fatal("current code should validate")
	}
	if want := now.Unix() / 30; step != want {
		t.Fatalf("step=%d, want %d", step, want)
	}

	// The same code one window later resolves to the SAME step — so a replay
	// guard keyed on step (> last) rejects reuse.
	step2, ok := matchTOTPStep(code, secret, now.Add(30*time.Second))
	if !ok {
		t.Fatal("code should still validate within skew window")
	}
	if step2 != step {
		t.Fatalf("replayed code changed step: %d vs %d", step2, step)
	}

	// A distinct new-window code advances the step.
	future := now.Add(60 * time.Second)
	code3, _ := totp.GenerateCode(secret, future)
	step3, ok := matchTOTPStep(code3, secret, future)
	if !ok || step3 <= step {
		t.Fatalf("new-window code should advance step: step3=%d ok=%v", step3, ok)
	}

	if _, ok := matchTOTPStep("000000", secret, now); ok {
		// Guard against a fluke where 000000 happens to be valid.
		if v, _ := totp.ValidateCustom("000000", secret, now, totp.ValidateOpts{Period: 30, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1}); !v {
			t.Fatal("garbage code should not validate")
		}
	}
}
