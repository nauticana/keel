package model

import "fmt"

type PasswordPolicy struct {
	PasswordExpire     int
	MinPasswordLength  int
	MinPasswordUpper   int
	MinPasswordLower   int
	MinPasswordDigit   int
	MinPasswordSpecial int
	MaxAttempts        int
	AutoUnlock         int64
	AutoLogout         int64
}

// PasswordPolicyView is the client-safe subset (composition rules only;
// lockout/expiry stay server-only).
type PasswordPolicyView struct {
	MinLength int32 `json:"minLength"`
	MinUpper  int32 `json:"minUpper"`
	MinLower  int32 `json:"minLower"`
	MinDigit  int32 `json:"minDigit"`
}

func (p PasswordPolicy) ClientView() PasswordPolicyView {
	return PasswordPolicyView{
		MinLength: int32(p.MinPasswordLength),
		MinUpper:  int32(p.MinPasswordUpper),
		MinLower:  int32(p.MinPasswordLower),
		MinDigit:  int32(p.MinPasswordDigit),
	}
}

func (p *PasswordPolicy) Check(password string) error {
	if len(password) < p.MinPasswordLength {
		return fmt.Errorf("password must be at least %d characters long", p.MinPasswordLength)
	}
	cntL, cntU, cntS, cntD := 0, 0, 0, 0
	for _, char := range password {
		switch {
		case char >= 'A' && char <= 'Z':
			cntU++
		case char >= 'a' && char <= 'z':
			cntL++
		case char >= '0' && char <= '9':
			cntD++
		default:
			cntS++
		}
	}
	if cntL < p.MinPasswordLower {
		return fmt.Errorf("password must contain at least %d lowercase characters", p.MinPasswordLower)
	}
	if cntU < p.MinPasswordUpper {
		return fmt.Errorf("password must contain at least %d uppercase characters", p.MinPasswordUpper)
	}
	if cntD < p.MinPasswordDigit {
		return fmt.Errorf("password must contain at least %d digits", p.MinPasswordDigit)
	}
	return nil
}
