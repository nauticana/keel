package user

// AccountRegistration is the account part of a signup. Password is plain
// text on input; SendConfirmation stores only its bcrypt hash.
type AccountRegistration struct {
	FirstName string `json:"firstName"`
	LastName  string `json:"lastName"`
	UserName  string `json:"userName"`
	Email     string `json:"email"`
	Password  string `json:"password"`
}
