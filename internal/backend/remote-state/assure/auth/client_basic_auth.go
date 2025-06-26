package auth

import (
	"context"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/opentofu/opentofu/internal/httpclient"
	"github.com/opentofu/opentofu/internal/tfdiags"
)

type ClientBasicAuthConfig struct {
	ClientID     string
	ClientSecret string
}

type clientBasicAuth struct{}

func (cred *clientBasicAuth) Construct(config *Config) (azcore.TokenCredential, error) {
	// TODO pass through http client maybe????
	client := httpclient.New(context.TODO())
	// TODO determine if we need to do more here...
	return azidentity.NewClientSecretCredential(
		config.StorageAddresses.TenantID,
		config.ClientBasicAuthConfig.ClientID,
		config.ClientBasicAuthConfig.ClientSecret,
		&azidentity.ClientSecretCredentialOptions{
			ClientOptions: clientOptions(client),
		},
	)
}
func (cred *clientBasicAuth) Validate(config *Config) tfdiags.Diagnostics {
	var diags tfdiags.Diagnostics
	diags = diags.Append(tfdiags.Sourceless(
		tfdiags.Error,
		"Client Secret Auth is unimplemented",
		"This authentication method has yet to be implemented",
	))
	return diags
}
