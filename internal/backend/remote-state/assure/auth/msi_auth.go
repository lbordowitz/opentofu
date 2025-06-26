package auth

import (
	"context"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/opentofu/opentofu/internal/httpclient"
	"github.com/opentofu/opentofu/internal/tfdiags"
)

type MSIAuthConfig struct {
	UseMsi      bool
	MsiEndpoint string
}

type managedIdentityAuth struct{}

func (cred *managedIdentityAuth) Construct(config *Config) (azcore.TokenCredential, error) {
	// TODO pass through http client maybe????
	client := httpclient.New(context.TODO())
	// TODO is this correct?
	return azidentity.NewManagedIdentityCredential(
		&azidentity.ManagedIdentityCredentialOptions{
			ClientOptions: clientOptions(client),
		},
	)
}
func (cred *managedIdentityAuth) Validate(config *Config) tfdiags.Diagnostics {
	var diags tfdiags.Diagnostics
	diags = diags.Append(tfdiags.Sourceless(
		tfdiags.Error,
		"Managed Identity Auth is unimplemented",
		"This authentication method has yet to be implemented",
	))
	return diags
}
