package secret

// Settings selects a secret store and locates it. The fields mirror the
// bootstrap flags of the same names.
type Settings struct {
	Mode                 string // local, gsm, aws, azure or infisical
	Keystore             string
	GCPProjectID         string
	GCPSecretRegion      string // empty: global secrets
	AWSRegion            string // empty: the SDK region chain, else us-east-1
	AzureKeyVaultURL     string
	InfisicalProjectID   string
	InfisicalEnvironment string
	InfisicalHost        string
}
