package config

type BackendConfig struct {
	ClientID                      string
	ClientCertificatePassword     string
	ClientCertificatePath         string
	ClientSecret                  string
	CustomResourceManagerEndpoint string
	MetadataHost                  string
	Environment                   string
	MsiEndpoint                   string
	OIDCToken                     string
	OIDCTokenFilePath             string
	OIDCRequestURL                string
	OIDCRequestToken              string
	ResourceGroupName             string
	SasToken                      string
	SubscriptionID                string
	TenantID                      string
	UseMsi                        bool
	UseOIDC                       bool
	UseAzureADAuthentication      bool
}
