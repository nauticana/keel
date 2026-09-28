package erasure

// AccountEraser anonymizes the user_account row and revokes the user's
// sessions; user.UserService satisfies it.
type AccountEraser interface {
	DeleteAccount(userID int, reason string) error
}
