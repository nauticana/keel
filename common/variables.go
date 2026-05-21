package common

import "flag"

type ContextKey string

const (
	RestPrefix   = "/api"
	PubapiPrefix = "/pubapi"
	PublicPrefix = "/public"
	// APIVersion is the major version segment appended to the REST
	// prefix on the wire (e.g. `/api/v1/...`). The keel HTTP routers
	// emit `RestPrefix + APIVersion + "/" + <resource>` so a single
	// bump touches every mounted route, including the table-action
	// handlers built by rest.RestService.loadTableActions.
	APIVersion              = "/v1"
	PartnerID    ContextKey = "partnerID"
	ApiKeyID     ContextKey = "apiKeyID"
	Scopes       ContextKey = "scopes"
	// RequestID is the context-key under which request-id middleware
	// stores the per-request opaque token. handler.WriteError reads
	// from this when emitting 5xx envelopes so the user-visible
	// request_id matches whatever appears in access / app logs.
	// Middlewares writing the value should `context.WithValue(ctx,
	// common.RequestID, "<token>")` before calling the next handler
	// (P2-09).
	RequestID ContextKey = "requestID"
)

var (
	LogType     = flag.String("log_type", "local", "Log type: local, gcp, aws, or azure")
	LogRoot     = flag.String("log_root", "/opt/app/log", "Log folder")
	// Azure Monitor Logs Ingestion settings, used when --log_type=azure.
	// Logs are POSTed to a Data Collection Endpoint (DCE) which routes
	// them through a Data Collection Rule (DCR) into a custom Log
	// Analytics table. Authentication uses azidentity.DefaultAzureCredential
	// (the same chain as storage/azure.go and the azure secret provider),
	// so a managed identity with the "Monitoring Metrics Publisher" role on
	// the DCR needs no secret material in the environment. All three are
	// required when --log_type=azure.
	AzureLogsEndpoint = flag.String("azure_logs_endpoint", "", "Azure Monitor Data Collection Endpoint URL (e.g. https://my-dce-xxxx.region.ingest.monitor.azure.com)")
	AzureLogsRuleID   = flag.String("azure_logs_dcr", "", "Azure Monitor Data Collection Rule immutable ID (e.g. dcr-xxxxxxxx)")
	AzureLogsStream   = flag.String("azure_logs_stream", "", "Azure Monitor DCR stream name (e.g. Custom-AppLogs_CL)")
	HttpApiPort = flag.Int("http_api_port", 8080, "HTTP server port")
	HTTPSPort   = flag.Int("https_port", 443, "HTTPS server port")
	TLSCert     = flag.String("tls_cert", "", "TLS certificate file path")
	TLSKey      = flag.String("tls_key", "", "TLS private key file path")
	// MaxTLSVersion controls the TLS policy applied by the HTTP backend.
	//   "none"  — no TLS enforcement; plain HTTP is accepted on all paths
	//             (dev / test / demo deployments).
	//   "tls10" / "tls11" / "tls12" / "tls13" — TLS required; the TLS
	//             listener is configured with MinVersion set to the given
	//             value, and the plain-HTTP listener only accepts /health
	//             and /ready requests (for in-VPC health checkers).
	// When not "none", --tls_cert and --tls_key must be set.
	MaxTLSVersion    = flag.String("max_tls_version", "none", "TLS policy: none | tls10 | tls11 | tls12 | tls13")
	// Keystore is the JSON file path consulted by the local secret
	// provider. AWS-Secrets-Manager / GSM consumers ignore this flag.
	// Previously this same flag was overloaded as the AWS region for
	// secret_mode=aws — see AWSRegion below for the v0.4.1 split.
	Keystore = flag.String("keystore", "/opt/app/sec/secrets.json", "Local secret provider: JSON file path")
	// AWSRegion is the region for AWS Secrets Manager. Required when
	// --secret_mode=aws. Falling back to the AWS SDK's default chain
	// would silently pick "us-east-1" or whatever AWS_REGION sits in
	// the environment, which is the wrong behavior for a multi-region
	// deployment. Empty + secret_mode=aws is a configuration error.
	AWSRegion = flag.String("aws_region", "", "AWS region for Secrets Manager / SNS / SQS / S3 / CloudWatch")
	SessionTimeout   = flag.Int("session_timeout", 300, "Session timeout in seconds")
	// OTPTTLSeconds caps how long an OTP code minted by GenerateOTP
	// remains valid in the user_otp table. Default 300s (5 min) is the
	// industry-standard sweet spot — long enough for SMS / email
	// delivery latency + the user reading + typing, short enough that a
	// stale leaked code is useless. Brute-force is gated by
	// per-row attempt limits in user_service_local, not by the TTL.
	// Token TTL (the opaque session id bound to the OTP) auto-tracks
	// this value with a small buffer in OTPHandler — never set this
	// higher than ~9 min without revisiting OTPHandler.OTPTokenTTL.
	OTPTTLSeconds    = flag.Int("otp_ttl_seconds", 300, "OTP code time-to-live in seconds")
	NodeId           = flag.Int("node_id", 0, "Node ID for bigint ID generator")
	DBhost           = flag.String("db_host", "localhost", "Database hostname")
	DBport           = flag.Int("db_port", 5432, "Database port number")
	DBname           = flag.String("db_name", "app", "Database name")
	DBuser           = flag.String("db_user", "app", "Database user")
	DBschema         = flag.String("db_schema", "public", "Database schema name")
	DBsslmode        = flag.String("db_sslmode", "disable", "Database SSL mode (disable, require, verify-ca, verify-full)")
	DBPoolMax        = flag.Int("db_pool_max", 4, "Maximum database pool connections")
	MailMode         = flag.String("mail_mode", "smtp", "Mail delivery mode: smtp or api")
	SmtpHost         = flag.String("smtp_host", "smtp.gmail.com", "SMTP server host")
	SmtpPort         = flag.Int("smtp_port", 587, "SMTP server port")
	SmtpUser         = flag.String("smtp_user", "", "SMTP username")
	SmtpFrom         = flag.String("smtp_from", "", "SMTP sender email address")
	CORSOrigin       = flag.String("cors_origin", "", "Allowed CORS origin")
	GoogleClientID   = flag.String("google_client_id", "", "Google OAuth client ID (shared by login and any Google API integration). Required to verify ID tokens against Google's JWKs.")
	// Apple Sign-In identifier — the `aud` claim that Apple-issued ID
	// tokens MUST carry. For native iOS / iPadOS / macOS clients this is
	// the app's bundle id (`com.example.app`); for web clients (Sign in
	// with Apple JS) it is the Service ID configured in the Apple
	// Developer portal. Required when handler/social_handler.go is
	// mounted with provider="apple". Empty disables Apple sign-in.
	AppleClientID = flag.String("apple_client_id", "", "Apple Sign-In client identifier (bundle id for native, Service ID for web)")
	// TrustedProxyCIDR limits which inbound socket addresses the
	// X-Forwarded-For / X-Real-IP headers will be honored from. CSV of
	// CIDRs — e.g. "10.0.0.0/8,172.16.0.0/12,127.0.0.1/32". Empty (the
	// default) disables proxy-header trust entirely; the connection
	// RemoteAddr is used. Set this to your reverse proxy / load-balancer
	// network range so client IPs surfaced to rate-limit and consent
	// audit are authentic.
	TrustedProxyCIDR = flag.String("trusted_proxy_cidr", "", "REQUIRED for production deployments behind a load balancer. CSV of CIDRs whose X-Forwarded-For / X-Real-IP headers are honored — typically your LB / reverse-proxy network range. Empty = trust nothing (peer RemoteAddr only); audit attribution and rate-limit keys then point at the LB. Production binaries should call handler.MustRequireTrustedProxyCIDR() after flag.Parse().")
	SecretMode       = flag.String("secret_mode", "local", "Secret provider: local, gsm, aws, or azure")
	ProjectID        = flag.String("gcp_project_id", "", "Google Cloud project ID")
	// AzureKeyVaultURL is the vault endpoint consulted when
	// --secret_mode=azure, e.g. "https://my-vault.vault.azure.net/".
	// Authentication uses azidentity.DefaultAzureCredential (the same
	// chain as storage/azure.go), so on Azure VMs/AKS a system- or
	// user-assigned managed identity needs the "Key Vault Secrets User"
	// role and no secret material lands in the environment. Empty +
	// secret_mode=azure is a configuration error.
	AzureKeyVaultURL = flag.String("azure_keyvault_url", "", "Azure Key Vault URL for Secrets (e.g. https://my-vault.vault.azure.net/)")
	NatsURL          = flag.String("nats_url", "", "NATS server URL")
	StorageMode      = flag.String("storage_mode", "", "Object storage: s3 or gcs")
	StorageBucket    = flag.String("storage_bucket", "", "Default object-storage bucket. Apps that store PII should set this per deployment site so blobs stay in the customer's data-residency region.")
	MessagingMode    = flag.String("messaging_mode", "", "Messaging: gcp or aws")
	MaxRequestSize   = flag.Int64("max_request_size", 16777216, "Maximum request body size (16MB)")
	HttpReadTimeout  = flag.Int("http_read_timeout", 15, "HTTP read timeout in seconds")
	HttpWriteTimeout = flag.Int("http_write_timeout", 30, "HTTP write timeout in seconds")
	HttpIdleTimeout  = flag.Int("http_idle_timeout", 120, "HTTP idle timeout in seconds")
	HCPort           = flag.Int("hc_port", 0, "Health check port override for workers")
	PushMode         = flag.String("push_mode", "noop", "Push provider: fcm or noop")

	// Cache backend selection. Set exactly one of --redis_url / --valkey_url.
	// Both forms accept either `host:port` or `redis[s]://host:port/db` —
	// passwords MUST NOT be embedded in the URL; they live in the secret
	// provider under `redis_password` / `valkey_password`.
	//
	// --valkey_cluster makes the client speak Redis-Cluster protocol.
	// Required for Memorystore for Valkey (cluster-mode-only) and ElastiCache
	// for Valkey clusters; ignored when --redis_url is the active flag (the
	// Redis path is single-node by construction).
	RedisURL      = flag.String("redis_url", "", "Single-node Redis connection (host:port or redis[s]://host:port/db). Password lives in the `redis_password` secret. Mutually exclusive with --valkey_url.")
	ValkeyURL     = flag.String("valkey_url", "", "Valkey connection (host:port or redis[s]://host:port/db). Password lives in the `valkey_password` secret. Mutually exclusive with --redis_url.")
	ValkeyCluster = flag.Bool("valkey_cluster", false, "Use Redis-Cluster protocol (required for Memorystore for Valkey cluster-mode-only and ElastiCache for Valkey clusters). Applies only when --valkey_url is set.")

	// TwilioMessagingServiceSID identifies the Twilio Messaging Service used by
	// the SMS dispatcher. Not a credential — Twilio account SID + auth token
	// live in the `twilio_account_sid` / `twilio_auth_token` secrets. One
	// Messaging Service per environment; add senders (regional long codes,
	// short codes, alphanumeric senders) inside the Twilio console. Empty
	// value disables SMS dispatch (NewTwilioSMSDispatcher returns an error
	// so callers can skip registering the channel).
	TwilioMessagingServiceSID = flag.String("twilio_messaging_service_sid", "", "Twilio Messaging Service SID (MGxxxxxxxx...). Empty disables SMS.")

	// Payout provider selection. Picks the active payout.PayoutProvider
	// implementation for out-bound payouts. One impl is active per
	// deployment; per-partner override is a future refinement on
	// business_partner_config.payout_provider. Codes follow the basis
	// constant_header `payout_provider` (CHAR(2)):
	//   AW = Airwallex (default), SC = Stripe Connect, WI = Wise
	PayoutProvider = flag.String("payout_provider", "AW", "Payout provider code: AW (Airwallex), SC (Stripe Connect), WI (Wise)")

	// PayoutReturnURL is the deep-link the provider redirects the user
	// back to after their hosted-KYC flow completes (e.g.
	// "myapp://onboarding/return" for a mobile app, or
	// "https://app.example.com/onboarding/return" for a web build).
	PayoutReturnURL = flag.String("payout_return_url", "", "Deep-link the payout provider redirects back to after hosted KYC")

	// PayoutWebhookURL is the public URL the provider POSTs webhook
	// events to. The path suffix /api/v1/webhook/payout/<code> is
	// appended by the calling application's router; the value here is
	// the public-host portion only, e.g. "https://api.example.com".
	PayoutWebhookURL = flag.String("payout_webhook_url", "", "Public host the payout provider sends webhook events to")

	// AirwallexAPIBase is the Airwallex REST API root. Defaults to the
	// demo host so a fresh install can't accidentally hit production.
	// Set to "https://api.airwallex.com" once the integration is
	// contract-live. The previous behaviour was a hardcoded constant
	// inside payout/airwallex.go — replaced with this flag so production
	// deployments can flip the value without a recompile.
	AirwallexAPIBase = flag.String("airwallex_api_base", "https://api-demo.airwallex.com", "Airwallex REST API base URL")

	// WiseAPIBase is the Wise Platform REST API root. Defaults to the
	// sandbox. Production set this to "https://api.wise.com".
	WiseAPIBase = flag.String("wise_api_base", "https://api.sandbox.transferwise.tech", "Wise Platform REST API base URL")

	// WiseProfileID is the Wise platform profile id (numeric) the
	// transfers + recipient creates are scoped to. Required when
	// --payout_provider=WI; the Wise API rejects /v1/accounts and
	// /v1/transfers requests with no profile id. Empty value is a
	// configuration error — the Wise provider's StartOnboarding /
	// RequestInstantPayout will reject calls at runtime.
	WiseProfileID = flag.String("wise_profile_id", "", "Wise platform profile id (numeric)")
)
