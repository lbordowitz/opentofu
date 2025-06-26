package auth

import (
	"context"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/hashicorp/hcl/v2"
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
	diags = diags.Append(hcl.Diagnostic{
		Severity: tfdiags.Warning.ToHCL(),
		Summary:  "Managed Identity Auth is unimplemented",
		Detail:   "This authentication method has yet to be implemented",
	})
	return diags
}
