package googleads

import (
	"strings"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/dispatcher"
)

// NormalizeEmail applies Google's rule for hashed e-mail: trimmed and
// lower-cased, with the dots before the @ removed for gmail.com and
// googlemail.com. It returns "" for something that is not an address.
func NormalizeEmail(email string) string {
	email = strings.ToLower(strings.TrimSpace(email))
	local, domain, ok := strings.Cut(email, "@")
	if !ok || local == "" || domain == "" || strings.Contains(domain, "@") {
		return ""
	}
	if domain == "gmail.com" || domain == "googlemail.com" {
		local = strings.ReplaceAll(local, ".", "")
	}
	return local + "@" + domain
}

// HashEmail is the hex SHA-256 of NormalizeEmail, or "" when there is no address.
func HashEmail(email string) string {
	if n := NormalizeEmail(email); n != "" {
		return common.Sha256Hex(n)
	}
	return ""
}

// HashPhone is the hex SHA-256 of the E.164 number, '+' included. region is
// the ISO country for a national-format number; "" accepts only numbers that
// carry their country code.
func HashPhone(phone, region string) (string, error) {
	e164, err := dispatcher.ToE164(phone, region)
	if err != nil {
		return "", ErrInvalidPhone // the parser's message would carry the number
	}
	return common.Sha256Hex(e164), nil
}
