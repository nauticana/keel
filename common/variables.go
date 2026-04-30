package common

import "flag"

type ContextKey string

const (
	RestPrefix              = "/api"
	PubapiPrefix            = "/pubapi"
	PublicPrefix            = "/public"
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
	LogType     = flag.String("log_type", "local", "Log type: local, gcp, or aws")
	LogRoot     = flag.String("log_root", "/opt/app/log", "Log folder")
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
	SecretMode       = flag.String("secret_mode", "local", "Secret provider: local, gsm, or aws")
	ProjectID        = flag.String("gcp_project_id", "", "Google Cloud project ID")
	NatsURL          = flag.String("nats_url", "", "NATS server URL")
	StorageMode      = flag.String("storage_mode", "", "Object storage: s3 or gcs")
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
)
