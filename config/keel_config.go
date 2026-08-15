package config

import (
	"fmt"
	"time"
)

const (
	http_api_port                 = "http_api_port"
	https_port                    = "https_port"
	tls_cert                      = "tls_cert"
	tls_key                       = "tls_key"
	max_tls_version               = "max_tls_version"
	metrics_addr                  = "metrics_addr"
	session_timeout               = "session_timeout"
	otp_ttl_seconds               = "otp_ttl_seconds"
	mail_mode                     = "mail_mode"
	smtp_host                     = "smtp_host"
	smtp_port                     = "smtp_port"
	smtp_user                     = "smtp_user"
	smtp_from                     = "smtp_from"
	cors_origin                   = "cors_origin"
	google_client_id              = "google_client_id"
	apple_client_id               = "apple_client_id"
	oauth_issuer                  = "oauth_issuer"
	oauth_jwks_url                = "oauth_jwks_url"
	oauth_audience                = "oauth_audience"
	oauth_resource                = "oauth_resource"
	oauth_resources               = "oauth_resources"
	oauth_scopes_supported        = "oauth_scopes_supported"
	oauth_as_mode                 = "oauth_as_mode"
	oauth_signing_key_secret      = "oauth_signing_key_secret"
	oauth_access_token_ttl        = "oauth_access_token_ttl"
	oauth_refresh_token_ttl       = "oauth_refresh_token_ttl"
	oauth_code_ttl                = "oauth_code_ttl"
	oauth_max_auth_redirects      = "oauth_max_auth_redirects"
	outbound_max_redirects        = "outbound_max_redirects"
	outbound_max_rps              = "outbound_max_rps"
	trusted_proxy_cidr            = "trusted_proxy_cidr"
	nats_url                      = "nats_url"
	nats_name                     = "nats_name"
	nats_creds_secret             = "nats_creds_secret"
	storage_mode                  = "storage_mode"
	storage_bucket                = "storage_bucket"
	s3_endpoint                   = "s3_endpoint"
	s3_credential_mode            = "s3_credential_mode"
	storage_public_base_url       = "storage_public_base_url"
	storage_account_url           = "storage_account_url"
	messaging_mode                = "messaging_mode"
	max_request_size              = "max_request_size"
	http_read_timeout             = "http_read_timeout"
	http_write_timeout            = "http_write_timeout"
	http_idle_timeout             = "http_idle_timeout"
	hc_port                       = "hc_port"
	push_mode                     = "push_mode"
	redis_url                     = "redis_url"
	valkey_url                    = "valkey_url"
	valkey_cluster                = "valkey_cluster"
	sms_provider                  = "sms_provider"
	sms_service_sid               = "sms_service_sid"
	payout_provider               = "payout_provider"
	payout_return_url             = "payout_return_url"
	payout_webhook_url            = "payout_webhook_url"
	airwallex_api_base            = "airwallex_api_base"
	airwallex_transfer_method     = "airwallex_transfer_method"
	airwallex_transfer_reason     = "airwallex_transfer_reason"
	wise_api_base                 = "wise_api_base"
	wise_profile_id               = "wise_profile_id"
	sqs_ack_deadline              = "sqs_ack_deadline"
	sqs_nack_backoff_seconds      = "sqs_nack_backoff_seconds"
	nats_backoff                  = "nats_backoff"
	nats_connect_timeout          = "nats_connect_timeout"
	nats_fetch_timeout            = "nats_fetch_timeout"
	nats_ack_wait                 = "nats_ack_wait"
	nats_max_deliver              = "nats_max_deliver"
	nats_max_ack_pending          = "nats_max_ack_pending"
	smtp_dial_timeout             = "smtp_dial_timeout"
	smtp_deadline                 = "smtp_deadline"
	quota_cache_ttl               = "quota_cache_ttl"
	oauth_jwks_cache_ttl          = "oauth_jwks_cache_ttl"
	social_jwks_cache_ttl         = "social_jwks_cache_ttl"
	oauth_state_ttl_seconds       = "oauth_state_ttl_seconds"
	oauth_connect_lease_seconds   = "oauth_connect_lease_seconds"
	otp_token_ttl                 = "otp_token_ttl"
	social_nonce_ttl              = "social_nonce_ttl"
	registration_confirmation_ttl = "registration_confirmation_ttl"
	max_registration_attempts     = "max_registration_attempts"
	verify_2fa_window             = "verify_2fa_window"
	verify_2fa_per_ip             = "verify_2fa_per_ip"
	max_list_page_size            = "max_list_page_size"
	default_list_page_size        = "default_list_page_size"
	post_write_timeout            = "post_write_timeout"
	stripe_webhook_tolerance      = "stripe_webhook_tolerance"
	stripe_max_retries            = "stripe_max_retries"
	webhook_claim_lease_seconds   = "webhook_claim_lease_seconds"
	default_outbound_timeout      = "default_outbound_timeout"
	snowflake_state_persist_ms    = "snowflake_state_persist_ms"
	memory_cache_sweep_interval   = "memory_cache_sweep_interval"
	default_commission_rate_bp    = "default_commission_rate_bp"
	commission_hold_days          = "commission_hold_days"
	agency_payout_min_minor       = "agency_payout_min_minor"
)

var _ ApplicationConfig = (*KeelConfig)(nil)

// KeelConfig holds keel's repository-owned runtime configuration.
type KeelConfig struct {
	AbstractConfig
	// Name               data type        name in database              default            description
	HttpApiPort                 int           // http_api_port                 8080               HTTP server port
	HTTPSPort                   int           // https_port                    443                HTTPS server port
	TLSCert                     string        // tls_cert                      ""                 TLS certificate file path
	TLSKey                      string        // tls_key                       ""                 TLS private key file path
	MaxTLSVersion               string        // max_tls_version               none               TLS policy: none | tls10 | tls11 | tls12 | tls13
	MetricsAddr                 string        // metrics_addr                  ""                 Prometheus /metrics listen address; empty disables
	SessionTimeout              int           // session_timeout               300                Session timeout in seconds
	OTPTTLSeconds               int           // otp_ttl_seconds               300                OTP code time-to-live in seconds
	MailMode                    string        // mail_mode                     smtp               Mail delivery mode: smtp or api
	SmtpHost                    string        // smtp_host                     smtp.gmail.com     SMTP server host
	SmtpPort                    int           // smtp_port                     587                SMTP server port
	SmtpUser                    string        // smtp_user                     ""                 SMTP username
	SmtpFrom                    string        // smtp_from                     ""                 SMTP sender email address
	CORSOrigin                  string        // cors_origin                   ""                 Allowed CORS origin
	GoogleClientID              string        // google_client_id              ""                 Google OAuth client ID (verifies ID tokens against Google's JWKs)
	AppleClientID               string        // apple_client_id               ""                 Apple Sign-In client identifier
	OAuthIssuer                 string        // oauth_issuer                  ""                 OAuth 2.1 AS issuer URL trusted by the resource-server validator
	OAuthJWKSURL                string        // oauth_jwks_url                ""                 JWKS URL used to verify access-token signatures
	OAuthAudience               string        // oauth_audience                ""                 Expected access-token audience (RFC 8707)
	OAuthResource               string        // oauth_resource                ""                 Canonical resource URL advertised in protected-resource metadata
	OAuthResources              string        // oauth_resources               ""                 CSV of additional valid RFC 8707 resource indicators
	OAuthScopesSupported        string        // oauth_scopes_supported        ""                 Comma-separated scopes advertised in protected-resource metadata
	OAuthASMode                 string        // oauth_as_mode                 local              OAuth 2.1 AS provider: local | external | disabled
	OAuthSigningKeySecret       string        // oauth_signing_key_secret      ""                 Secret NAME holding the RS256 signing key PEM for the local AS
	OAuthAccessTokenTTL         time.Duration // oauth_access_token_ttl        3600               Access-token lifetime (seconds)
	OAuthRefreshTokenTTL        time.Duration // oauth_refresh_token_ttl       2592000            Refresh-token lifetime (seconds, default 30 days)
	OAuthCodeTTL                time.Duration // oauth_code_ttl                60                 Authorization-code lifetime (seconds)
	OAuthMaxAuthRedirects       int           // oauth_max_auth_redirects      2                  Max /authorize→login bounces before 508
	OutboundMaxRedirects        int           // outbound_max_redirects        10                 Max redirects the shared outbound HTTP client follows
	OutboundMaxRPS              float64       // outbound_max_rps              0                  Global rate cap on the shared outbound HTTP client (0 = unlimited)
	TrustedProxyCIDR            string        // trusted_proxy_cidr            ""                 CSV of CIDRs whose forwarded-for headers are honored
	NatsURL                     string        // nats_url                      ""                 NATS server URL
	NatsName                    string        // nats_name                     ""                 NATS client name surfaced in NATS observability
	NatsCredsSecret             string        // nats_creds_secret             ""                 Secret NAME holding the NATS .creds file content (Synadia Cloud); empty = no creds
	StorageMode                 string        // storage_mode                  ""                 Object storage: s3, gcs, or azure
	StorageBucket               string        // storage_bucket                ""                 Default object-storage bucket
	S3Endpoint                  string        // s3_endpoint                   ""                 S3-compatible endpoint override
	S3CredentialMode            string        // s3_credential_mode            chain              Worker storage S3/R2 credential source: chain | secret
	StoragePublicBaseURL        string        // storage_public_base_url       ""                 Public base URL for ObjectStorage.PublicURL
	StorageAccountURL           string        // storage_account_url           ""                 Azure Blob service endpoint
	MessagingMode               string        // messaging_mode                ""                 Messaging: gcp or aws
	MaxRequestSize              int64         // max_request_size              16777216           Maximum request body size (bytes)
	HttpReadTimeout             int           // http_read_timeout             15                 HTTP read timeout in seconds
	HttpWriteTimeout            int           // http_write_timeout            30                 HTTP write timeout in seconds
	HttpIdleTimeout             int           // http_idle_timeout             120                HTTP idle timeout in seconds
	HCPort                      int           // hc_port                       0                  Health check port override for workers
	PushMode                    string        // push_mode                     noop               Push provider: fcm or noop
	RedisURL                    string        // redis_url                     ""                 Single-node Redis connection (password in redis_password secret)
	ValkeyURL                   string        // valkey_url                    ""                 Valkey connection (password in valkey_password secret)
	ValkeyCluster               bool          // valkey_cluster                false              Use Redis-Cluster protocol
	SMSProvider                 string        // sms_provider                  twilio             SMS provider: twilio | telnyx (empty disables SMS)
	SMSServiceSID               string        // sms_service_sid               ""                 SMS sender-pool id: Twilio Messaging Service SID (MG...) or Telnyx Messaging Profile ID
	PayoutProvider              string        // payout_provider               AW                 Payout provider code: AW | SC | WI
	PayoutReturnURL             string        // payout_return_url             ""                 Deep-link the payout provider redirects back to after KYC
	PayoutWebhookURL            string        // payout_webhook_url            ""                 Public host the payout provider sends webhook events to
	AirwallexAPIBase            string        // airwallex_api_base            https://api-demo.airwallex.com  Airwallex REST API base URL
	AirwallexXferMethod         string        // airwallex_transfer_method     LOCAL              Airwallex payout rail: LOCAL | SWIFT
	AirwallexXferReason         string        // airwallex_transfer_reason     professional_business_services  Airwallex documented transfer reason code
	WiseAPIBase                 string        // wise_api_base                 https://api.sandbox.transferwise.tech  Wise Platform REST API base URL
	WiseProfileID               string        // wise_profile_id               ""                 Wise platform profile id (numeric)
	SqsAckDeadline              time.Duration // sqs_ack_deadline              10                 SQS ack/visibility window per message
	SqsNackBackoffSeconds       int           // sqs_nack_backoff_seconds      30                 Redelivery delay after Nak
	NatsBackoff                 time.Duration // nats_backoff                  5                  Wait between Nak and redelivery
	NatsConnectTimeout          time.Duration // nats_connect_timeout          10                 NATS initial dial/handshake cap
	NatsFetchTimeout            time.Duration // nats_fetch_timeout            2                  JetStream fetch wait
	NatsAckWait                 time.Duration // nats_ack_wait                 30                 Consumer ack-wait before redelivery
	NatsMaxDeliver              int           // nats_max_deliver              3                  Max redelivery attempts
	NatsMaxAckPending           int           // nats_max_ack_pending          256                In-flight unacked message cap
	SmtpDialTimeout             time.Duration // smtp_dial_timeout             10                 SMTP connect timeout
	SmtpDeadline                time.Duration // smtp_deadline                 30                 Overall SMTP send deadline
	QuotaCacheTTL               time.Duration // quota_cache_ttl               3600               Quota lookup cache expiry
	OAuthJWKSCacheTTL           time.Duration // oauth_jwks_cache_ttl          3600               OAuth JWKS cache expiry
	SocialJWKSCacheTTL          time.Duration // social_jwks_cache_ttl         3600               Google/Apple JWKS cache expiry
	OAuthStateTTLSeconds        int           // oauth_state_ttl_seconds       600                authorize->callback round-trip window (sec)
	OAuthConnectLeaseSeconds    int           // oauth_connect_lease_seconds   300                Credential refresh lease duration (sec)
	OTPTokenTTL                 time.Duration // otp_token_ttl                 300                OTP token validity window
	SocialNonceTTL              time.Duration // social_nonce_ttl              600                Social-login nonce validity
	RegistrationConfirmationTTL time.Duration // registration_confirmation_ttl 900                Registration confirmation-code validity
	MaxRegistrationAttempts     int           // max_registration_attempts     5                  Confirmation-code guess cap
	Verify2FAWindow             time.Duration // verify_2fa_window             600                2FA verify rate-limit window
	Verify2FAPerIP              int           // verify_2fa_per_ip             20                 2FA verify attempts per IP
	MaxListPageSize             int           // max_list_page_size            1000               List page-size clamp
	DefaultListPageSize         int           // default_list_page_size        100                Default list page size
	PostWriteTimeout            time.Duration // post_write_timeout            10                 Post-response write timeout
	StripeWebhookTolerance      time.Duration // stripe_webhook_tolerance      300                Stripe webhook timestamp tolerance
	StripeMaxRetries            int           // stripe_max_retries            3                  Stripe API retry count (429/5xx)
	WebhookClaimLeaseSeconds    int           // webhook_claim_lease_seconds   900                Payment-webhook claim lease (sec); must exceed the slowest dispatch or a live claim is redispatched
	DefaultOutboundTimeout      time.Duration // default_outbound_timeout      30                 Default outbound HTTP client timeout
	SnowflakeStatePersistMs     int64         // snowflake_state_persist_ms    1000               Snowflake state-persist cadence (ms)
	MemoryCacheSweepInterval    time.Duration // memory_cache_sweep_interval   60                 In-memory cache expiry sweep interval
	DefaultCommissionRateBP     int           // default_commission_rate_bp    2000               Program agency commission rate (2000 = 20.00%)
	CommissionHoldDays          int           // commission_hold_days          14                 Refund/dispute hold before an earning becomes payable
	AgencyPayoutMinMinor        int64         // agency_payout_min_minor       2500               Minimum net agency payout; smaller balances roll forward
}

// Apply parses Keel's flags; a missing catalog row aborts the load.
func (c *KeelConfig) Apply(m ConfigRows) error {
	c.HttpApiPort = c.Int(m, http_api_port)
	c.HTTPSPort = c.Int(m, https_port)
	c.TLSCert = c.String(m, tls_cert)
	c.TLSKey = c.String(m, tls_key)
	c.MaxTLSVersion = c.String(m, max_tls_version)
	c.MetricsAddr = c.String(m, metrics_addr)
	c.SessionTimeout = c.Int(m, session_timeout)
	c.OTPTTLSeconds = c.Int(m, otp_ttl_seconds)
	c.MailMode = c.String(m, mail_mode)
	c.SmtpHost = c.String(m, smtp_host)
	c.SmtpPort = c.Int(m, smtp_port)
	c.SmtpUser = c.String(m, smtp_user)
	c.SmtpFrom = c.String(m, smtp_from)
	c.CORSOrigin = c.String(m, cors_origin)
	c.GoogleClientID = c.String(m, google_client_id)
	c.AppleClientID = c.String(m, apple_client_id)
	c.OAuthIssuer = c.String(m, oauth_issuer)
	c.OAuthJWKSURL = c.String(m, oauth_jwks_url)
	c.OAuthAudience = c.String(m, oauth_audience)
	c.OAuthResource = c.String(m, oauth_resource)
	c.OAuthResources = c.String(m, oauth_resources)
	c.OAuthScopesSupported = c.String(m, oauth_scopes_supported)
	c.OAuthASMode = c.String(m, oauth_as_mode)
	c.OAuthSigningKeySecret = c.String(m, oauth_signing_key_secret)
	c.OAuthAccessTokenTTL = c.Duration(m, oauth_access_token_ttl)
	c.OAuthRefreshTokenTTL = c.Duration(m, oauth_refresh_token_ttl)
	c.OAuthCodeTTL = c.Duration(m, oauth_code_ttl)
	c.OAuthMaxAuthRedirects = c.Int(m, oauth_max_auth_redirects)
	c.OutboundMaxRedirects = c.Int(m, outbound_max_redirects)
	c.OutboundMaxRPS = c.Float(m, outbound_max_rps)
	c.TrustedProxyCIDR = c.String(m, trusted_proxy_cidr)
	c.NatsURL = c.String(m, nats_url)
	c.NatsName = c.String(m, nats_name)
	c.NatsCredsSecret = c.String(m, nats_creds_secret)
	c.StorageMode = c.String(m, storage_mode)
	c.StorageBucket = c.String(m, storage_bucket)
	c.S3Endpoint = c.String(m, s3_endpoint)
	c.S3CredentialMode = c.String(m, s3_credential_mode)
	c.StoragePublicBaseURL = c.String(m, storage_public_base_url)
	c.StorageAccountURL = c.String(m, storage_account_url)
	c.MessagingMode = c.String(m, messaging_mode)
	c.MaxRequestSize = c.Int64(m, max_request_size)
	c.HttpReadTimeout = c.Int(m, http_read_timeout)
	c.HttpWriteTimeout = c.Int(m, http_write_timeout)
	c.HttpIdleTimeout = c.Int(m, http_idle_timeout)
	c.HCPort = c.Int(m, hc_port)
	c.PushMode = c.String(m, push_mode)
	c.RedisURL = c.String(m, redis_url)
	c.ValkeyURL = c.String(m, valkey_url)
	c.ValkeyCluster = c.Bool(m, valkey_cluster)
	c.SMSProvider = c.String(m, sms_provider)
	c.SMSServiceSID = c.String(m, sms_service_sid)
	c.PayoutProvider = c.String(m, payout_provider)
	c.PayoutReturnURL = c.String(m, payout_return_url)
	c.PayoutWebhookURL = c.String(m, payout_webhook_url)
	c.AirwallexAPIBase = c.String(m, airwallex_api_base)
	c.AirwallexXferMethod = c.String(m, airwallex_transfer_method)
	c.AirwallexXferReason = c.String(m, airwallex_transfer_reason)
	c.WiseAPIBase = c.String(m, wise_api_base)
	c.WiseProfileID = c.String(m, wise_profile_id)
	c.SqsAckDeadline = c.Duration(m, sqs_ack_deadline)
	c.SqsNackBackoffSeconds = c.Int(m, sqs_nack_backoff_seconds)
	c.NatsBackoff = c.Duration(m, nats_backoff)
	c.NatsConnectTimeout = c.Duration(m, nats_connect_timeout)
	c.NatsFetchTimeout = c.Duration(m, nats_fetch_timeout)
	c.NatsAckWait = c.Duration(m, nats_ack_wait)
	c.NatsMaxDeliver = c.Int(m, nats_max_deliver)
	c.NatsMaxAckPending = c.Int(m, nats_max_ack_pending)
	c.SmtpDialTimeout = c.Duration(m, smtp_dial_timeout)
	c.SmtpDeadline = c.Duration(m, smtp_deadline)
	c.QuotaCacheTTL = c.Duration(m, quota_cache_ttl)
	c.OAuthJWKSCacheTTL = c.Duration(m, oauth_jwks_cache_ttl)
	c.SocialJWKSCacheTTL = c.Duration(m, social_jwks_cache_ttl)
	c.OAuthStateTTLSeconds = c.Int(m, oauth_state_ttl_seconds)
	c.OAuthConnectLeaseSeconds = c.Int(m, oauth_connect_lease_seconds)
	c.OTPTokenTTL = c.Duration(m, otp_token_ttl)
	c.SocialNonceTTL = c.Duration(m, social_nonce_ttl)
	c.RegistrationConfirmationTTL = c.Duration(m, registration_confirmation_ttl)
	c.MaxRegistrationAttempts = c.Int(m, max_registration_attempts)
	c.Verify2FAWindow = c.Duration(m, verify_2fa_window)
	c.Verify2FAPerIP = c.Int(m, verify_2fa_per_ip)
	c.MaxListPageSize = c.Int(m, max_list_page_size)
	c.DefaultListPageSize = c.Int(m, default_list_page_size)
	c.PostWriteTimeout = c.Duration(m, post_write_timeout)
	c.StripeWebhookTolerance = c.Duration(m, stripe_webhook_tolerance)
	c.StripeMaxRetries = c.Int(m, stripe_max_retries)
	c.WebhookClaimLeaseSeconds = c.Int(m, webhook_claim_lease_seconds)
	c.DefaultOutboundTimeout = c.Duration(m, default_outbound_timeout)
	c.SnowflakeStatePersistMs = c.Int64(m, snowflake_state_persist_ms)
	c.MemoryCacheSweepInterval = c.Duration(m, memory_cache_sweep_interval)
	c.DefaultCommissionRateBP = c.Int(m, default_commission_rate_bp)
	c.CommissionHoldDays = c.Int(m, commission_hold_days)
	c.AgencyPayoutMinMinor = c.Int64(m, agency_payout_min_minor)

	if c.DefaultCommissionRateBP <= 0 || c.DefaultCommissionRateBP > 10000 {
		c.parseErrs = append(c.parseErrs, fmt.Errorf("%s: must be between 1 and 10000", default_commission_rate_bp))
	}
	if c.CommissionHoldDays < 0 {
		c.parseErrs = append(c.parseErrs, fmt.Errorf("%s: cannot be negative", commission_hold_days))
	}
	if c.AgencyPayoutMinMinor < 0 {
		c.parseErrs = append(c.parseErrs, fmt.Errorf("%s: cannot be negative", agency_payout_min_minor))
	}
	if c.WebhookClaimLeaseSeconds <= 0 {
		c.parseErrs = append(c.parseErrs, fmt.Errorf("%s: must be positive — a zero lease makes every webhook claim instantly stealable", webhook_claim_lease_seconds))
	}
	return c.ParseErr()
}
