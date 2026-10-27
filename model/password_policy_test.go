package model

import "testing"

func TestPasswordPolicyCheck(t *testing.T) {
	p := PasswordPolicy{MinPasswordLength: 6, MinPasswordUpper: 1, MinPasswordLower: 1, MinPasswordDigit: 1, MinPasswordSpecial: 2}
	for password, ok := range map[string]bool{
		"Ab1!?x":  true,
		"Ab1!x":   false, // 5 characters
		"Ab1!xyz": false, // one special
		"Ab1é!x":  true,  // é is special, 6 characters in 7 bytes
		"Ab1ééé":  true,
		"ab1!?x":  false, // no uppercase
	} {
		if err := p.Check(password); (err == nil) != ok {
			t.Errorf("Check(%q) = %v, want ok=%v", password, err, ok)
		}
	}
	short := PasswordPolicy{MinPasswordLength: 4}
	if short.Check("ééé") == nil {
		t.Error("3 characters of 6 bytes must fail a length of 4")
	}
	if v := p.ClientView(); v.MinSpecial != 2 || v.MinLength != 6 {
		t.Errorf("ClientView = %+v", v)
	}
}
