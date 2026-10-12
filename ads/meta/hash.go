package meta

import (
	"strconv"
	"strings"
	"time"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/dispatcher"
)

// HashEmail is the hex SHA-256 of the trimmed, lower-cased address, or "" when
// email is not an address.
func HashEmail(email string) string {
	email = strings.ToLower(strings.TrimSpace(email))
	local, domain, ok := strings.Cut(email, "@")
	if !ok || local == "" || domain == "" || strings.Contains(domain, "@") {
		return ""
	}
	return common.Sha256Hex(email)
}

// HashPhone is the hex SHA-256 of the E.164 digits with the country code and
// without the '+', as Meta requires. region is the ISO country for a
// national-format number; "" accepts only numbers that carry their country code.
func HashPhone(phone, region string) (string, error) {
	e164, err := dispatcher.ToE164(phone, region)
	if err != nil {
		return "", ErrInvalidPhone // the parser's message would carry the number
	}
	return common.Sha256Hex(strings.TrimPrefix(e164, "+")), nil
}

// ClickID formats the fbc match key from the time the click was first seen
// and the fbclid URL parameter.
func ClickID(clickTime time.Time, fbclid string) string {
	return "fb.1." + strconv.FormatInt(clickTime.UnixMilli(), 10) + "." + fbclid
}
