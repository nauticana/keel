package dispatcher

import "testing"

func TestValidateHeaders(t *testing.T) {
	ok := []map[string]string{
		nil,
		{"List-Unsubscribe": "<https://x.test/u?token=abc>"},
		{"List-Unsubscribe": "<mailto:u@x.test>, <https://x.test/u>", "List-Unsubscribe-Post": "List-Unsubscribe=One-Click"},
		{"X-Custom_Header.9": "fine"},
		{"X-Tabbed": "value\twith\ttabs"},
	}
	for i, h := range ok {
		if err := validateHeaders(h); err != nil {
			t.Errorf("case %d: valid headers rejected: %v", i, err)
		}
	}

	bad := map[string]map[string]string{
		"empty name":       {"": "x"},
		"space in name":    {"Foo Bar": "x"},
		"colon in name":    {"Foo:Bar": "x"},
		"non-ascii name":   {"Föo": "x"},
		"control in name":  {"Foo\tBar": "x"},
		"protected From":   {"From": "evil@x.test"},
		"protected Subject": {"Subject": "hijack"},
		"protected c-type": {"Content-Type": "text/html"},
		"protected (case)": {"cOnTeNt-TrAnSfEr-EnCoDiNg": "base64"},
		"crlf in value":    {"X-Foo": "a\r\nBcc: evil@x.test"},
		"nul in value":     {"X-Foo": "a\x00b"},
		"c0 ctrl in value":  {"X-Foo": "a\x01b"},
		"del in value":     {"X-Foo": "a\x7fb"},
		"protected Resent-From": {"Resent-From": "evil@x.test"},
		"protected Resent-Bcc":  {"Resent-Bcc": "evil@x.test"},
	}
	for name, h := range bad {
		if err := validateHeaders(h); err == nil {
			t.Errorf("%s: expected rejection, got nil", name)
		}
	}

	// Line length: name + ": " + value must be <= 998 octets.
	long := make([]byte, 997)
	for i := range long {
		long[i] = 'a'
	}
	if err := validateHeaders(map[string]string{"X-Long": string(long)}); err == nil {
		t.Error("over-998 header line should be rejected, not truncated")
	}
}
