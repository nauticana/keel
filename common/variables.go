package common

import (
	"flag"
)

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
	APIVersion            = "/v1"
	PartnerID  ContextKey = "partnerID"
	ApiKeyID   ContextKey = "apiKeyID"
	Scopes     ContextKey = "scopes"
	// RequestID is the context-key under which request-id middleware
	// stores the per-request opaque token. handler.WriteError reads
	// from this when emitting 5xx envelopes so the user-visible
	// request_id matches whatever appears in access / app logs.
	// Middlewares writing the value should `context.WithValue(ctx,
	// common.RequestID, "<token>")` before calling the next handler
	// (P2-09).
	RequestID ContextKey = "requestID"
	// Subject and AuthPrincipal carry the OAuth 2.1 access-token identity
	// injected by oauth/resource.Middleware. Subject is the `sub`
	// string; AuthPrincipal holds the full *port.Principal. The same
	// middleware also sets Scopes (space-delimited) and PartnerID (when a
	// resolver maps the subject), so HasScope / partner helpers work
	// uniformly across X-API-Key, JWT, and OAuth requests.
	Subject       ContextKey = "subject"
	AuthPrincipal ContextKey = "authPrincipal"
)

// Bootstrap flags only. Everything consumed before (or in order to get) the
// DB connection stays a --flag: the log sink, the secret provider, the DB
// itself, and --node_id. Every other runtime setting lives in the
// application_config_* tables and is read via common.Config() (BaseConfig).
var (
	LogType = flag.String("log_type", "local", "Log type: local, gcp, aws, or azure")
	LogRoot = flag.String("log_root", "/opt/app/log", "Log folder")
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
	AWSRegion = flag.String("aws_region", "", "AWS region for Secrets Manager")
	// NodeId identifies this runtime node/process. It seeds the bigint ID
	// generator and selects this node's application_config_value rows.
	NodeId    = flag.Int("node_id", 0, "Node ID for the bigint ID generator and per-node config rows")
	DBhost    = flag.String("db_host", "localhost", "Database hostname")
	DBport    = flag.Int("db_port", 5432, "Database port number")
	DBname    = flag.String("db_name", "app", "Database name")
	DBuser    = flag.String("db_user", "app", "Database user")
	DBschema  = flag.String("db_schema", "public", "Database schema name")
	DBsslmode = flag.String("db_sslmode", "disable", "Database SSL mode (disable, require, verify-ca, verify-full)")
	DBPoolMax = flag.Int("db_pool_max", 4, "Maximum database pool connections")

	SecretMode = flag.String("secret_mode", "local", "Secret provider: local, gsm, aws, azure, or infisical")
	// ProjectID is the GCP project consulted by the GSM secret provider
	// (bootstrap) and GCP Pub/Sub messaging.
	ProjectID = flag.String("gcp_project_id", "", "Google Cloud project ID")
	// AzureKeyVaultURL is the vault endpoint consulted when
	// --secret_mode=azure, e.g. "https://my-vault.vault.azure.net/".
	// Authentication uses azidentity.DefaultAzureCredential (the same
	// chain as storage/azure.go), so on Azure VMs/AKS a system- or
	// user-assigned managed identity needs the "Key Vault Secrets User"
	// role and no secret material lands in the environment. Empty +
	// secret_mode=azure is a configuration error.
	AzureKeyVaultURL = flag.String("azure_keyvault_url", "", "Azure Key Vault URL for Secrets (e.g. https://my-vault.vault.azure.net/)")
	// Infisical backend (--secret_mode=infisical), the production-grade
	// managed-secrets option for deployments not on AWS/GCP/Azure. These
	// three are non-secret location knobs only. The machine-identity
	// credential is read by the Infisical SDK from
	// INFISICAL_UNIVERSAL_AUTH_CLIENT_ID / _CLIENT_SECRET — keel never
	// carries it in a flag, mirroring the ambient-credential pattern of the
	// GSM/AWS/Azure backends (Google ADC, AWS default chain,
	// azidentity.DefaultAzureCredential). Empty project id or environment +
	// secret_mode=infisical is a configuration error.
	InfisicalProjectID   = flag.String("infisical_project_id", "", "Infisical project (workspace) ID. Required when --secret_mode=infisical.")
	InfisicalEnvironment = flag.String("infisical_environment", "prod", "Infisical environment slug (dev, staging, prod). Used when --secret_mode=infisical.")
	InfisicalHost        = flag.String("infisical_host", "https://app.infisical.com", "Infisical API host. Override for self-hosted instances.")
)
