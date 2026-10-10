package user

import (
	"context"

	"github.com/nauticana/keel/model"
)

// SignInNotifier reaches the account holder during sign-in.
type SignInNotifier interface {
	// NewDeviceSignIn tells the user about a sign-in from a device not seen before.
	NewDeviceSignIn(ctx context.Context, account *model.UserSession, device SessionDevice) error
	// StepUpCode delivers the one-time code a new-device sign-in must present.
	StepUpCode(ctx context.Context, account *model.UserSession, code string) error
}
