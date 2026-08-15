package config

import (
	"strings"
	"testing"
	"time"
)

// Every flag KeelConfig.Apply reads. A flag added there but not here fails
// these tests with a missing-flag error.
var keelTestFlagIDs = []string{
	http_api_port, https_port, tls_cert, tls_key, max_tls_version, metrics_addr,
	session_timeout, otp_ttl_seconds, mail_mode, smtp_host, smtp_port,
	smtp_user, smtp_from, cors_origin, google_client_id, apple_client_id,
	oauth_issuer, oauth_jwks_url, oauth_audience, oauth_resource,
	oauth_resources, oauth_scopes_supported, oauth_as_mode,
	oauth_signing_key_secret, oauth_access_token_ttl, oauth_refresh_token_ttl,
	oauth_code_ttl, oauth_max_auth_redirects, outbound_max_redirects,
	outbound_max_rps, trusted_proxy_cidr, nats_url, nats_name,
	nats_creds_secret, storage_mode, storage_bucket, s3_endpoint, s3_credential_mode,
	storage_public_base_url, storage_account_url, messaging_mode,
	max_request_size, http_read_timeout, http_write_timeout,
	http_idle_timeout, hc_port, push_mode, redis_url, valkey_url,
	valkey_cluster, sms_provider, sms_service_sid, payout_provider,
	payout_return_url, payout_webhook_url, airwallex_api_base,
	airwallex_transfer_method, airwallex_transfer_reason, wise_api_base,
	wise_profile_id, sqs_ack_deadline, sqs_nack_backoff_seconds, nats_backoff,
	nats_connect_timeout, nats_fetch_timeout, nats_ack_wait, nats_max_deliver,
	nats_max_ack_pending, smtp_dial_timeout, smtp_deadline, quota_cache_ttl,
	oauth_jwks_cache_ttl, social_jwks_cache_ttl, oauth_state_ttl_seconds,
	oauth_connect_lease_seconds, otp_token_ttl, social_nonce_ttl,
	registration_confirmation_ttl, max_registration_attempts,
	verify_2fa_window, verify_2fa_per_ip, max_list_page_size,
	default_list_page_size, post_write_timeout, stripe_webhook_tolerance,
	stripe_max_retries, webhook_claim_lease_seconds,
	default_outbound_timeout, snowflake_state_persist_ms,
	memory_cache_sweep_interval, default_commission_rate_bp,
	commission_hold_days, agency_payout_min_minor,
}

func keelRows() ConfigRows {
	m := make(ConfigRows, len(keelTestFlagIDs))
	for _, id := range keelTestFlagIDs {
		m[id] = ConfigRow{}
	}
	m[default_commission_rate_bp] = ConfigRow{Default: "2000"}
	m[commission_hold_days] = ConfigRow{Default: "14"}
	m[agency_payout_min_minor] = ConfigRow{Default: "2500"}
	m[webhook_claim_lease_seconds] = ConfigRow{Default: "900"}
	return m
}

func applyKeelForTest(c *KeelConfig, rows ConfigRows) error {
	return c.Apply(rows)
}

func TestApplyKeel_MalformedValuesFailLoudly(t *testing.T) {
	m := keelRows()
	m[http_api_port] = ConfigRow{Value: "eight-thousand"}
	m[valkey_cluster] = ConfigRow{Value: "flase"}
	m[outbound_max_rps] = ConfigRow{Value: "1,5"}
	m[smtp_deadline] = ConfigRow{Value: "30s"}

	err := applyKeelForTest(&KeelConfig{}, m)
	if err == nil {
		t.Fatal("ApplyKeel: want error for malformed values, got nil")
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

func TestApplyKeel_ExplicitZeroAndEmptyAreValid(t *testing.T) {
	m := keelRows()
	m[hc_port] = ConfigRow{Value: "0"}
	m[session_timeout] = ConfigRow{Default: "300"}

	c := &KeelConfig{}
	if err := applyKeelForTest(c, m); err != nil {
		t.Fatalf("ApplyKeel: %v", err)
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

func TestApplyKeel_MissingFlagRows(t *testing.T) {
	m := keelRows()
	delete(m, mail_mode)
	err := applyKeelForTest(&KeelConfig{}, m)
	if err == nil || !strings.Contains(err.Error(), "mail_mode") {
		t.Fatalf("want missing-flag error naming mail_mode, got: %v", err)
	}
}

func TestApplyKeel_InvalidAgencyValuesFailLoudly(t *testing.T) {
	m := keelRows()
	m[default_commission_rate_bp] = ConfigRow{Value: "10001"}
	m[commission_hold_days] = ConfigRow{Value: "-1"}
	m[agency_payout_min_minor] = ConfigRow{Value: "-1"}
	err := applyKeelForTest(&KeelConfig{}, m)
	if err == nil {
		t.Fatal("ApplyKeel: want invalid agency flag error")
	}
	for _, flag := range []string{default_commission_rate_bp, commission_hold_days, agency_payout_min_minor} {
		if !strings.Contains(err.Error(), flag) {
			t.Errorf("error should mention %q; got %v", flag, err)
		}
	}
}

func TestParseErr_DownstreamAccumulateAndClear(t *testing.T) {
	c := &AbstractConfig{}
	rows := ConfigRows{"window": {Value: "60"}, "count": {Value: "abc"}}
	if got := c.Duration(rows, "window"); got != 60*time.Second {
		t.Errorf("Duration = %v, want 60s", got)
	}
	_ = c.Int(rows, "count")
	_ = c.String(rows, "absent")
	err := c.ParseErr()
	if err == nil || !strings.Contains(err.Error(), "abc") || !strings.Contains(err.Error(), "count") {
		t.Fatalf("want parse error naming flag count and value abc, got: %v", err)
	}
	if !strings.Contains(err.Error(), "absent") {
		t.Errorf("error should report the missing flag absent; got: %v", err)
	}
	if err := c.ParseErr(); err != nil {
		t.Fatalf("ParseErr should clear after reporting, got: %v", err)
	}
}

func TestApplyKeel_AirwallexTransferFlags(t *testing.T) {
	m := keelRows()
	m[airwallex_transfer_method] = ConfigRow{Value: "SWIFT", Default: "LOCAL"}
	m[airwallex_transfer_reason] = ConfigRow{Default: "professional_business_services"}

	c := &KeelConfig{}
	if err := applyKeelForTest(c, m); err != nil {
		t.Fatalf("ApplyKeel: %v", err)
	}
	if c.AirwallexXferMethod != "SWIFT" {
		t.Errorf("AirwallexXferMethod = %q, want SWIFT", c.AirwallexXferMethod)
	}
	if c.AirwallexXferReason != "professional_business_services" {
		t.Errorf("AirwallexXferReason = %q, want default", c.AirwallexXferReason)
	}
}
