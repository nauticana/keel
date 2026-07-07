package common

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nauticana/keel/port"
)

// config holds the active runtime configuration behind an atomic pointer so
// the RELOAD swap synchronizes with lock-free readers: a reader sees either
// the complete old or the complete new instance, never a partial one.
var config atomic.Pointer[BaseConfig]

func init() { config.Store(&BaseConfig{}) }

// Config returns the active runtime configuration (never nil). main publishes
// it via SetConfig after Load; the RELOAD table action swaps it the same way.
// Defaults come from the application_config_flag catalog, so Load failing (or
// an unseeded catalog) must abort startup.
func Config() *BaseConfig { return config.Load() }

// SetConfig publishes a fully-loaded configuration. Only hand it instances
// that finished Load — never mutate an instance after publishing it.
func SetConfig(c *BaseConfig) { config.Store(c) }

// ReloadFunc, when set by main, rebuilds the app's config (which may embed
// BaseConfig) and reassigns common.Config(). The RELOAD table action invokes it.
// Nil means reload is unsupported for this binary.
var ReloadFunc func(ctx context.Context) error

// application_config_flag  — the flag catalog (one row per known flag)
//   id             varchar(80)  primary key
//   data_type      varchar(20)  string | int | int64 | float | duration (seconds) | bool
//   needs_restart  bool         true = only applied at process start
//   default_value  text         used when a node has no assigned_value
//   description    text
//
// application_config_value — per-node assignments
//   node_id        int          primary key; identifies the runtime node/process
//                               (matched against --node_id). Most single-node
//                               deployments use 0; multi-node deployments assign
//                               values per node. Missing rows fall back to
//                               application_config_flag.default_value.
//   flag_id        varchar(80)  primary key / FK -> application_config_flag.id
//   assigned_value text
//
// Values here are NON-SECRET only. Secrets stay in the keystore; store a secret
// NAME here (e.g. oauth_signing_key_secret) and resolve it via the SecretProvider.

// BaseConfig holds the framework's runtime configuration, loaded from the
// application_config_* tables at startup. Downstream apps extend it by
// EMBEDDING (not naming) and adding their own flags:
//
//	type MyConfig struct {
//	    common.BaseConfig
//	    MyAttr1 int
//	    MyAttr2 string
//	}
//	func (c *MyConfig) Load(ctx context.Context, db port.DatabaseRepository) error {
//	    m, err := c.LoadValues(ctx, db) // one query, shared
//	    if err != nil { return err }
//	    if err := c.ApplyBase(m); err != nil { return err } // framework flags
//	    c.MyAttr1 = c.ParseValueI(m["my_attr1"].Value, m["my_attr1"].Default)
//	    return c.ParseErr() // malformed app values abort the load too
//	}
//
// In main.go, after the DB is up (from bootstrap flags + secret provider):
//
//	cfg := &MyConfig{}
//	if err := cfg.Load(ctx, db); err != nil { log.Fatal(err) }
//	common.SetConfig(&cfg.BaseConfig)                 // keel reads common.Config().X
//	app.Config = cfg                                  // app packages read cfg.MyAttr1
//	common.ReloadFunc = func(ctx context.Context) error { // enable the RELOAD action
//	    fresh := &MyConfig{}
//	    if err := fresh.Load(ctx, db); err != nil { return err }
//	    common.SetConfig(&fresh.BaseConfig)
//	    app.Config = fresh
//	    return nil
//	}
//
// Config is loaded at startup and swapped wholesale on RELOAD. Settings consumed
// only at startup (listen ports, TLS) still need a restart — the admin accepts
// that; RELOAD covers the many per-request values (timeouts, TTLs, caps).
//
// There is intentionally no interface: main knows the concrete type at the Load
// call site, and field readers need the concrete struct anyway.
type BaseConfig struct {
	// Name                   data type        name in database              default            description
	HttpApiPort               int           // http_api_port                 8080               HTTP server port
	HTTPSPort                 int           // https_port                    443                HTTPS server port
	TLSCert                   string        // tls_cert                      ""                 TLS certificate file path
	TLSKey                    string        // tls_key                       ""                 TLS private key file path
	MaxTLSVersion             string        // max_tls_version               none               TLS policy: none | tls10 | tls11 | tls12 | tls13
	SessionTimeout            int           // session_timeout               300                Session timeout in seconds
	OTPTTLSeconds             int           // otp_ttl_seconds               300                OTP code time-to-live in seconds
	MailMode                  string        // mail_mode                     smtp               Mail delivery mode: smtp or api
	SmtpHost                  string        // smtp_host                     smtp.gmail.com     SMTP server host
	SmtpPort                  int           // smtp_port                     587                SMTP server port
	SmtpUser                  string        // smtp_user                     ""                 SMTP username
	SmtpFrom                  string        // smtp_from                     ""                 SMTP sender email address
	CORSOrigin                string        // cors_origin                   ""                 Allowed CORS origin
	GoogleClientID            string        // google_client_id              ""                 Google OAuth client ID (verifies ID tokens against Google's JWKs)
	AppleClientID             string        // apple_client_id               ""                 Apple Sign-In client identifier
	OAuthIssuer               string        // oauth_issuer                  ""                 OAuth 2.1 AS issuer URL trusted by the resource-server validator
	OAuthJWKSURL              string        // oauth_jwks_url                ""                 JWKS URL used to verify access-token signatures
	OAuthAudience             string        // oauth_audience                ""                 Expected access-token audience (RFC 8707)
	OAuthResource             string        // oauth_resource                ""                 Canonical resource URL advertised in protected-resource metadata
	OAuthResources            string        // oauth_resources               ""                 CSV of additional valid RFC 8707 resource indicators
	OAuthScopesSupported      string        // oauth_scopes_supported        ""                 Comma-separated scopes advertised in protected-resource metadata
	OAuthASMode               string        // oauth_as_mode                 local              OAuth 2.1 AS provider: local | external | disabled
	OAuthSigningKeySecret     string        // oauth_signing_key_secret      ""                 Secret NAME holding the RS256 signing key PEM for the local AS
	OAuthAccessTokenTTL       time.Duration // oauth_access_token_ttl        3600               Access-token lifetime (seconds)
	OAuthRefreshTokenTTL      time.Duration // oauth_refresh_token_ttl       2592000            Refresh-token lifetime (seconds, default 30 days)
	OAuthCodeTTL              time.Duration // oauth_code_ttl                60                 Authorization-code lifetime (seconds)
	OAuthMaxAuthRedirects     int           // oauth_max_auth_redirects      2                  Max /authorize→login bounces before 508
	OutboundMaxRedirects      int           // outbound_max_redirects        10                 Max redirects the shared outbound HTTP client follows
	OutboundMaxRPS            float64       // outbound_max_rps              0                  Global rate cap on the shared outbound HTTP client (0 = unlimited)
	TrustedProxyCIDR          string        // trusted_proxy_cidr            ""                 CSV of CIDRs whose forwarded-for headers are honored
	NatsURL                   string        // nats_url                      ""                 NATS server URL
	NatsName                  string        // nats_name                     ""                 NATS client name surfaced in NATS observability
	NatsCredsSecret           string        // nats_creds_secret             ""                 Secret NAME holding the NATS .creds file content (Synadia Cloud); empty = no creds
	StorageMode               string        // storage_mode                  ""                 Object storage: s3, gcs, or azure
	StorageBucket             string        // storage_bucket                ""                 Default object-storage bucket
	S3Endpoint                string        // s3_endpoint                   ""                 S3-compatible endpoint override
	S3CredentialMode          string        // s3_credential_mode            chain              Worker storage S3/R2 credential source: chain | secret
	StoragePublicBaseURL      string        // storage_public_base_url       ""                 Public base URL for ObjectStorage.PublicURL
	StorageAccountURL         string        // storage_account_url           ""                 Azure Blob service endpoint
	MessagingMode             string        // messaging_mode                ""                 Messaging: gcp or aws
	MaxRequestSize            int64         // max_request_size              16777216           Maximum request body size (bytes)
	HttpReadTimeout           int           // http_read_timeout             15                 HTTP read timeout in seconds
	HttpWriteTimeout          int           // http_write_timeout            30                 HTTP write timeout in seconds
	HttpIdleTimeout           int           // http_idle_timeout             120                HTTP idle timeout in seconds
	HCPort                    int           // hc_port                       0                  Health check port override for workers
	PushMode                  string        // push_mode                     noop               Push provider: fcm or noop
	RedisURL                  string        // redis_url                     ""                 Single-node Redis connection (password in redis_password secret)
	ValkeyURL                 string        // valkey_url                    ""                 Valkey connection (password in valkey_password secret)
	ValkeyCluster             bool          // valkey_cluster                false              Use Redis-Cluster protocol
	TwilioMessagingServiceSID string        // twilio_messaging_service_sid  ""                 Twilio Messaging Service SID (empty disables SMS)
	PayoutProvider            string        // payout_provider               AW                 Payout provider code: AW | SC | WI
	PayoutReturnURL           string        // payout_return_url             ""                 Deep-link the payout provider redirects back to after KYC
	PayoutWebhookURL          string        // payout_webhook_url            ""                 Public host the payout provider sends webhook events to
	AirwallexAPIBase          string        // airwallex_api_base            https://api-demo.airwallex.com  Airwallex REST API base URL
	WiseAPIBase               string        // wise_api_base                 https://api.sandbox.transferwise.tech  Wise Platform REST API base URL
	WiseProfileID             string        // wise_profile_id               ""                 Wise platform profile id (numeric)

	// Operational tunables (were hardcoded package constants). Durations are
	// stored as whole seconds. Defaults come from the catalog's default_value;
	// ApplyBase rejects a catalog that is missing any of these rows.
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
	DefaultOutboundTimeout      time.Duration // default_outbound_timeout      30                 Default outbound HTTP client timeout
	SnowflakeStatePersistMs     int64         // snowflake_state_persist_ms    1000               Snowflake state-persist cadence (ms)
	MemoryCacheSweepInterval    time.Duration // memory_cache_sweep_interval   60                 In-memory cache expiry sweep interval

	// parseErrs accumulates malformed-value errors from ParseValue* during a
	// load; ApplyBase / ParseErr drain it. Never inspect it directly.
	parseErrs []error
}

const qNodeConfigs = "node_configs"

// LEFT JOIN so every flag is returned even with no per-node value row — then
// ParseValue* falls back to the flag's default_value. A plain (INNER) join
// would drop unset flags and their defaults would never apply.
var acQueries = map[string]string{
	qNodeConfigs: `
SELECT a.id, b.assigned_value, a.default_value
  FROM application_config_flag a
  LEFT JOIN application_config_value b
    ON a.id = b.flag_id AND b.node_id = ?
`,
}

const (
	http_api_port                = "http_api_port"
	https_port                   = "https_port"
	tls_cert                     = "tls_cert"
	tls_key                      = "tls_key"
	max_tls_version              = "max_tls_version"
	session_timeout              = "session_timeout"
	otp_ttl_seconds              = "otp_ttl_seconds"
	mail_mode                    = "mail_mode"
	smtp_host                    = "smtp_host"
	smtp_port                    = "smtp_port"
	smtp_user                    = "smtp_user"
	smtp_from                    = "smtp_from"
	cors_origin                  = "cors_origin"
	google_client_id             = "google_client_id"
	apple_client_id              = "apple_client_id"
	oauth_issuer                 = "oauth_issuer"
	oauth_jwks_url               = "oauth_jwks_url"
	oauth_audience               = "oauth_audience"
	oauth_resource               = "oauth_resource"
	oauth_resources              = "oauth_resources"
	oauth_scopes_supported       = "oauth_scopes_supported"
	oauth_as_mode                = "oauth_as_mode"
	oauth_signing_key_secret     = "oauth_signing_key_secret"
	oauth_access_token_ttl       = "oauth_access_token_ttl"
	oauth_refresh_token_ttl      = "oauth_refresh_token_ttl"
	oauth_code_ttl               = "oauth_code_ttl"
	oauth_max_auth_redirects     = "oauth_max_auth_redirects"
	outbound_max_redirects       = "outbound_max_redirects"
	outbound_max_rps             = "outbound_max_rps"
	trusted_proxy_cidr           = "trusted_proxy_cidr"
	nats_url                     = "nats_url"
	nats_name                    = "nats_name"
	nats_creds_secret            = "nats_creds_secret"
	storage_mode                 = "storage_mode"
	storage_bucket               = "storage_bucket"
	s3_endpoint                  = "s3_endpoint"
	s3_credential_mode           = "s3_credential_mode"
	storage_public_base_url      = "storage_public_base_url"
	storage_account_url          = "storage_account_url"
	messaging_mode               = "messaging_mode"
	max_request_size             = "max_request_size"
	http_read_timeout            = "http_read_timeout"
	http_write_timeout           = "http_write_timeout"
	http_idle_timeout            = "http_idle_timeout"
	hc_port                      = "hc_port"
	push_mode                    = "push_mode"
	redis_url                    = "redis_url"
	valkey_url                   = "valkey_url"
	valkey_cluster               = "valkey_cluster"
	twilio_messaging_service_sid = "twilio_messaging_service_sid"
	payout_provider              = "payout_provider"
	payout_return_url            = "payout_return_url"
	payout_webhook_url           = "payout_webhook_url"
	airwallex_api_base           = "airwallex_api_base"
	wise_api_base                = "wise_api_base"
	wise_profile_id              = "wise_profile_id"

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
	default_outbound_timeout      = "default_outbound_timeout"
	snowflake_state_persist_ms    = "snowflake_state_persist_ms"
	memory_cache_sweep_interval   = "memory_cache_sweep_interval"
)

// ConfigRow is one flag's resolved (assigned value, catalog default) pair.
type ConfigRow struct {
	Value   string
	Default string
}

// Load fetches the config rows once and applies the framework flags. Any
// error — DB failure, empty catalog, missing framework rows — must abort
// startup (log.Fatal in main); running with a partial config is not supported.
func (c *BaseConfig) Load(ctx context.Context, db port.DatabaseRepository) error {
	m, err := c.LoadValues(ctx, db)
	if err != nil {
		return err
	}
	return c.ApplyBase(m)
}

// LoadValues reads this node's config rows into a flag_id → ConfigRow map.
// Downstream Load overrides fetch once and share the map with ApplyBase.
func (c *BaseConfig) LoadValues(ctx context.Context, db port.DatabaseRepository) (map[string]ConfigRow, error) {
	qs := db.GetQueryService(ctx, acQueries)
	res, err := qs.Query(ctx, qNodeConfigs, *NodeId)
	if err != nil {
		return nil, fmt.Errorf("load application config for node %d: %w", *NodeId, err)
	}
	m := make(map[string]ConfigRow, len(res.Rows))
	for _, row := range res.Rows {
		m[AsString(row[0])] = ConfigRow{Value: AsString(row[1]), Default: AsString(row[2])}
	}
	if len(m) == 0 {
		return nil, fmt.Errorf("application_config_flag catalog is empty — seed it (basis_seed.yml) before starting")
	}
	return m, nil
}

// baseFlagIDs is every framework flag ApplyBase expects in the catalog. A
// missing row means an unseeded/stale catalog and aborts startup.
var baseFlagIDs = []string{
	http_api_port, https_port, tls_cert, tls_key, max_tls_version,
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
	valkey_cluster, twilio_messaging_service_sid, payout_provider,
	payout_return_url, payout_webhook_url, airwallex_api_base, wise_api_base,
	wise_profile_id,

	sqs_ack_deadline, sqs_nack_backoff_seconds, nats_backoff,
	nats_connect_timeout, nats_fetch_timeout, nats_ack_wait, nats_max_deliver,
	nats_max_ack_pending, smtp_dial_timeout, smtp_deadline, quota_cache_ttl,
	oauth_jwks_cache_ttl, social_jwks_cache_ttl, oauth_state_ttl_seconds,
	oauth_connect_lease_seconds, otp_token_ttl, social_nonce_ttl,
	registration_confirmation_ttl, max_registration_attempts,
	verify_2fa_window, verify_2fa_per_ip, max_list_page_size,
	default_list_page_size, post_write_timeout, stripe_webhook_tolerance,
	stripe_max_retries, default_outbound_timeout, snowflake_state_persist_ms,
	memory_cache_sweep_interval,
}

// configMu serializes config loads (concurrent RELOADs, startup vs reload).
// It guards the ApplyBase mutation, not the readers: request handlers and
// workers read common.Config() lock-free, so a reload must NEVER mutate the
// published instance — build a fresh config, Load into it, then publish it
// with SetConfig (see the ReloadFunc example above).
var configMu sync.Mutex

// ApplyBase assigns every framework flag from the loaded map. Unknown (app)
// flags are ignored here — the downstream override handles those. A catalog
// missing any framework flag row is a seeding error.
func (c *BaseConfig) ApplyBase(m map[string]ConfigRow) error {
	configMu.Lock()
	defer configMu.Unlock()
	var missing []string
	for _, flg := range baseFlagIDs {
		r, ok := m[flg]
		if !ok {
			missing = append(missing, flg)
			continue
		}
		seen := len(c.parseErrs)
		switch flg {
		case http_api_port:
			c.HttpApiPort = c.ParseValueI(r.Value, r.Default)
		case https_port:
			c.HTTPSPort = c.ParseValueI(r.Value, r.Default)
		case tls_cert:
			c.TLSCert = c.ParseValueS(r.Value, r.Default)
		case tls_key:
			c.TLSKey = c.ParseValueS(r.Value, r.Default)
		case max_tls_version:
			c.MaxTLSVersion = c.ParseValueS(r.Value, r.Default)
		case session_timeout:
			c.SessionTimeout = c.ParseValueI(r.Value, r.Default)
		case otp_ttl_seconds:
			c.OTPTTLSeconds = c.ParseValueI(r.Value, r.Default)
		case mail_mode:
			c.MailMode = c.ParseValueS(r.Value, r.Default)
		case smtp_host:
			c.SmtpHost = c.ParseValueS(r.Value, r.Default)
		case smtp_port:
			c.SmtpPort = c.ParseValueI(r.Value, r.Default)
		case smtp_user:
			c.SmtpUser = c.ParseValueS(r.Value, r.Default)
		case smtp_from:
			c.SmtpFrom = c.ParseValueS(r.Value, r.Default)
		case cors_origin:
			c.CORSOrigin = c.ParseValueS(r.Value, r.Default)
		case google_client_id:
			c.GoogleClientID = c.ParseValueS(r.Value, r.Default)
		case apple_client_id:
			c.AppleClientID = c.ParseValueS(r.Value, r.Default)
		case oauth_issuer:
			c.OAuthIssuer = c.ParseValueS(r.Value, r.Default)
		case oauth_jwks_url:
			c.OAuthJWKSURL = c.ParseValueS(r.Value, r.Default)
		case oauth_audience:
			c.OAuthAudience = c.ParseValueS(r.Value, r.Default)
		case oauth_resource:
			c.OAuthResource = c.ParseValueS(r.Value, r.Default)
		case oauth_resources:
			c.OAuthResources = c.ParseValueS(r.Value, r.Default)
		case oauth_scopes_supported:
			c.OAuthScopesSupported = c.ParseValueS(r.Value, r.Default)
		case oauth_as_mode:
			c.OAuthASMode = c.ParseValueS(r.Value, r.Default)
		case oauth_signing_key_secret:
			c.OAuthSigningKeySecret = c.ParseValueS(r.Value, r.Default)
		case oauth_access_token_ttl:
			c.OAuthAccessTokenTTL = c.ParseValueD(r.Value, r.Default)
		case oauth_refresh_token_ttl:
			c.OAuthRefreshTokenTTL = c.ParseValueD(r.Value, r.Default)
		case oauth_code_ttl:
			c.OAuthCodeTTL = c.ParseValueD(r.Value, r.Default)
		case oauth_max_auth_redirects:
			c.OAuthMaxAuthRedirects = c.ParseValueI(r.Value, r.Default)
		case outbound_max_redirects:
			c.OutboundMaxRedirects = c.ParseValueI(r.Value, r.Default)
		case outbound_max_rps:
			c.OutboundMaxRPS = c.ParseValueF(r.Value, r.Default)
		case trusted_proxy_cidr:
			c.TrustedProxyCIDR = c.ParseValueS(r.Value, r.Default)
		case nats_url:
			c.NatsURL = c.ParseValueS(r.Value, r.Default)
		case nats_name:
			c.NatsName = c.ParseValueS(r.Value, r.Default)
		case nats_creds_secret:
			c.NatsCredsSecret = c.ParseValueS(r.Value, r.Default)
		case storage_mode:
			c.StorageMode = c.ParseValueS(r.Value, r.Default)
		case storage_bucket:
			c.StorageBucket = c.ParseValueS(r.Value, r.Default)
		case s3_endpoint:
			c.S3Endpoint = c.ParseValueS(r.Value, r.Default)
		case s3_credential_mode:
			c.S3CredentialMode = c.ParseValueS(r.Value, r.Default)
		case storage_public_base_url:
			c.StoragePublicBaseURL = c.ParseValueS(r.Value, r.Default)
		case storage_account_url:
			c.StorageAccountURL = c.ParseValueS(r.Value, r.Default)
		case messaging_mode:
			c.MessagingMode = c.ParseValueS(r.Value, r.Default)
		case max_request_size:
			c.MaxRequestSize = c.ParseValueBI(r.Value, r.Default)
		case http_read_timeout:
			c.HttpReadTimeout = c.ParseValueI(r.Value, r.Default)
		case http_write_timeout:
			c.HttpWriteTimeout = c.ParseValueI(r.Value, r.Default)
		case http_idle_timeout:
			c.HttpIdleTimeout = c.ParseValueI(r.Value, r.Default)
		case hc_port:
			c.HCPort = c.ParseValueI(r.Value, r.Default)
		case push_mode:
			c.PushMode = c.ParseValueS(r.Value, r.Default)
		case redis_url:
			c.RedisURL = c.ParseValueS(r.Value, r.Default)
		case valkey_url:
			c.ValkeyURL = c.ParseValueS(r.Value, r.Default)
		case valkey_cluster:
			c.ValkeyCluster = c.ParseValueB(r.Value, r.Default)
		case twilio_messaging_service_sid:
			c.TwilioMessagingServiceSID = c.ParseValueS(r.Value, r.Default)
		case payout_provider:
			c.PayoutProvider = c.ParseValueS(r.Value, r.Default)
		case payout_return_url:
			c.PayoutReturnURL = c.ParseValueS(r.Value, r.Default)
		case payout_webhook_url:
			c.PayoutWebhookURL = c.ParseValueS(r.Value, r.Default)
		case airwallex_api_base:
			c.AirwallexAPIBase = c.ParseValueS(r.Value, r.Default)
		case wise_api_base:
			c.WiseAPIBase = c.ParseValueS(r.Value, r.Default)
		case wise_profile_id:
			c.WiseProfileID = c.ParseValueS(r.Value, r.Default)
		case sqs_ack_deadline:
			c.SqsAckDeadline = c.ParseValueD(r.Value, r.Default)
		case sqs_nack_backoff_seconds:
			c.SqsNackBackoffSeconds = c.ParseValueI(r.Value, r.Default)
		case nats_backoff:
			c.NatsBackoff = c.ParseValueD(r.Value, r.Default)
		case nats_connect_timeout:
			c.NatsConnectTimeout = c.ParseValueD(r.Value, r.Default)
		case nats_fetch_timeout:
			c.NatsFetchTimeout = c.ParseValueD(r.Value, r.Default)
		case nats_ack_wait:
			c.NatsAckWait = c.ParseValueD(r.Value, r.Default)
		case nats_max_deliver:
			c.NatsMaxDeliver = c.ParseValueI(r.Value, r.Default)
		case nats_max_ack_pending:
			c.NatsMaxAckPending = c.ParseValueI(r.Value, r.Default)
		case smtp_dial_timeout:
			c.SmtpDialTimeout = c.ParseValueD(r.Value, r.Default)
		case smtp_deadline:
			c.SmtpDeadline = c.ParseValueD(r.Value, r.Default)
		case quota_cache_ttl:
			c.QuotaCacheTTL = c.ParseValueD(r.Value, r.Default)
		case oauth_jwks_cache_ttl:
			c.OAuthJWKSCacheTTL = c.ParseValueD(r.Value, r.Default)
		case social_jwks_cache_ttl:
			c.SocialJWKSCacheTTL = c.ParseValueD(r.Value, r.Default)
		case oauth_state_ttl_seconds:
			c.OAuthStateTTLSeconds = c.ParseValueI(r.Value, r.Default)
		case oauth_connect_lease_seconds:
			c.OAuthConnectLeaseSeconds = c.ParseValueI(r.Value, r.Default)
		case otp_token_ttl:
			c.OTPTokenTTL = c.ParseValueD(r.Value, r.Default)
		case social_nonce_ttl:
			c.SocialNonceTTL = c.ParseValueD(r.Value, r.Default)
		case registration_confirmation_ttl:
			c.RegistrationConfirmationTTL = c.ParseValueD(r.Value, r.Default)
		case max_registration_attempts:
			c.MaxRegistrationAttempts = c.ParseValueI(r.Value, r.Default)
		case verify_2fa_window:
			c.Verify2FAWindow = c.ParseValueD(r.Value, r.Default)
		case verify_2fa_per_ip:
			c.Verify2FAPerIP = c.ParseValueI(r.Value, r.Default)
		case max_list_page_size:
			c.MaxListPageSize = c.ParseValueI(r.Value, r.Default)
		case default_list_page_size:
			c.DefaultListPageSize = c.ParseValueI(r.Value, r.Default)
		case post_write_timeout:
			c.PostWriteTimeout = c.ParseValueD(r.Value, r.Default)
		case stripe_webhook_tolerance:
			c.StripeWebhookTolerance = c.ParseValueD(r.Value, r.Default)
		case stripe_max_retries:
			c.StripeMaxRetries = c.ParseValueI(r.Value, r.Default)
		case default_outbound_timeout:
			c.DefaultOutboundTimeout = c.ParseValueD(r.Value, r.Default)
		case snowflake_state_persist_ms:
			c.SnowflakeStatePersistMs = c.ParseValueBI(r.Value, r.Default)
		case memory_cache_sweep_interval:
			c.MemoryCacheSweepInterval = c.ParseValueD(r.Value, r.Default)
		}
		for i := seen; i < len(c.parseErrs); i++ {
			c.parseErrs[i] = fmt.Errorf("%s: %w", flg, c.parseErrs[i])
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("application_config_flag catalog is missing framework flags: %s — re-seed basis_seed.yml", strings.Join(missing, ", "))
	}
	return c.ParseErr()
}

// ParseValue* coerce a stored text value (or the catalog default when the
// value is empty) to the target type. Exported so downstream ApplyOwn can
// reuse them. An empty value parses to the type's zero value; a malformed
// non-empty value records an error that fails the load — ApplyBase surfaces
// framework flags, ParseErr surfaces the downstream ones — so a typo'd
// assigned_value aborts startup/RELOAD instead of silently becoming 0.
func (c *BaseConfig) ParseValueS(val, def any) string {
	if AsString(val) == "" {
		return AsString(def)
	}
	return AsString(val)
}

func (c *BaseConfig) parseText(val, def any) string {
	return strings.TrimSpace(c.ParseValueS(val, def))
}

func (c *BaseConfig) parseInt(val, def any, kind string) int64 {
	s := c.parseText(val, def)
	if s == "" {
		return 0
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		c.parseErrs = append(c.parseErrs, fmt.Errorf("malformed value %q (want %s)", s, kind))
	}
	return n
}

func (c *BaseConfig) ParseValueF(val, def any) float64 {
	s := c.parseText(val, def)
	if s == "" {
		return 0
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		c.parseErrs = append(c.parseErrs, fmt.Errorf("malformed value %q (want float)", s))
	}
	return f
}

func (c *BaseConfig) ParseValueI(val, def any) int {
	return int(c.parseInt(val, def, "int"))
}

func (c *BaseConfig) ParseValueBI(val, def any) int64 {
	return c.parseInt(val, def, "int64")
}

func (c *BaseConfig) ParseValueB(val, def any) bool {
	s := strings.ToLower(c.parseText(val, def))
	switch s {
	case "true", "1", "yes", "y", "on":
		return true
	case "", "false", "0", "no", "n", "off":
		return false
	}
	c.parseErrs = append(c.parseErrs, fmt.Errorf("malformed value %q (want bool)", s))
	return false
}

// ParseValueD reads a duration stored as whole seconds.
func (c *BaseConfig) ParseValueD(val, def string) time.Duration {
	return time.Duration(c.parseInt(val, def, "duration seconds")) * time.Second
}

// ParseErr returns the parse failures accumulated by ParseValue* since the
// last call and clears them. Downstream Load overrides return it after their
// own ParseValue* calls so a malformed app value also aborts the load.
func (c *BaseConfig) ParseErr() error {
	if len(c.parseErrs) == 0 {
		return nil
	}
	err := fmt.Errorf("application config: %w", errors.Join(c.parseErrs...))
	c.parseErrs = nil
	return err
}
