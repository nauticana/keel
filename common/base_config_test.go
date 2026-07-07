package common

import (
	"strings"
	"testing"
	"time"
)

func baseRows() map[string]ConfigRow {
	m := make(map[string]ConfigRow, len(baseFlagIDs))
	for _, id := range baseFlagIDs {
		m[id] = ConfigRow{}
	}
	return m
}

func TestApplyBase_MalformedValuesFailLoudly(t *testing.T) {
	m := baseRows()
	m[http_api_port] = ConfigRow{Value: "eight-thousand"}
	m[valkey_cluster] = ConfigRow{Value: "flase"}
	m[outbound_max_rps] = ConfigRow{Value: "1,5"}
	m[smtp_deadline] = ConfigRow{Value: "30s"}

	err := (&BaseConfig{}).ApplyBase(m)
	if err == nil {
		t.Fatal("ApplyBase: want error for malformed values, got nil")
	}
	for _, want := range []string{
		"http_api_port", "eight-thousand",
		"valkey_cluster", "flase",
		"outbound_max_rps", "1,5",
		"smtp_deadline", "30s",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error should mention %q; got: %v", want, err)
		}
	}
}

func TestApplyBase_ExplicitZeroAndEmptyAreValid(t *testing.T) {
	m := baseRows()
	m[hc_port] = ConfigRow{Value: "0"}
	m[session_timeout] = ConfigRow{Default: "300"}

	c := &BaseConfig{}
	if err := c.ApplyBase(m); err != nil {
		t.Fatalf("ApplyBase: %v", err)
	}
	if c.HCPort != 0 {
		t.Errorf("HCPort = %d, want 0", c.HCPort)
	}
	if c.SessionTimeout != 300 {
		t.Errorf("SessionTimeout = %d, want 300 (from default)", c.SessionTimeout)
	}
	if c.SmtpDeadline != 0 {
		t.Errorf("SmtpDeadline = %v, want 0 for empty value", c.SmtpDeadline)
	}
}

func TestApplyBase_MissingFlagRows(t *testing.T) {
	m := baseRows()
	delete(m, mail_mode)
	err := (&BaseConfig{}).ApplyBase(m)
	if err == nil || !strings.Contains(err.Error(), "mail_mode") {
		t.Fatalf("want missing-flag error naming mail_mode, got: %v", err)
	}
}

func TestParseErr_DownstreamAccumulateAndClear(t *testing.T) {
	c := &BaseConfig{}
	if got := c.ParseValueD("60", ""); got != 60*time.Second {
		t.Errorf("ParseValueD = %v, want 60s", got)
	}
	_ = c.ParseValueI("abc", "")
	if err := c.ParseErr(); err == nil || !strings.Contains(err.Error(), "abc") {
		t.Fatalf("want parse error mentioning abc, got: %v", err)
	}
	if err := c.ParseErr(); err != nil {
		t.Fatalf("ParseErr should clear after reporting, got: %v", err)
	}
}
