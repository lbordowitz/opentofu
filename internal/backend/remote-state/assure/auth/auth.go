package auth

import (
	"context"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/hashicorp/hcl/v2"
	"github.com/opentofu/opentofu/internal/tfdiags"
)

type Config struct {
	*ClientBasicAuthConfig
	*ClientCertificateAuthConfig
	*OIDCAuthConfig
	*MSIAuthConfig
	*StorageAddresses
}

type AuthMethod interface {
	Construct(config *Config) (azcore.TokenCredential, error)
	Validate(config *Config) tfdiags.Diagnostics
}

func GetAuthCredentials(ctx context.Context, config *Config) (azcore.TokenCredential, error) {
	var authMethods []AuthMethod = []AuthMethod{
		&clientCertAuth{},
		&clientBasicAuth{},
		&oidcAuth{},
		&managedIdentityAuth{},
		&azureCLICredentialAuth{},
	}
	var diags tfdiags.Diagnostics
	for _, authMethod := range authMethods {
		if d := authMethod.Validate(config); d.HasErrors() {
			diags = diags.Append(d)
			continue
		}
		return authMethod.Construct(config)
	}
	diags = diags.Append(hcl.Diagnostic{
		Severity: hcl.DiagError,
		Summary:  "No valid azure auth methods found",
		Detail:   "Please see above warnings for details about what each auth method needs to properly work.",
	})
	return nil, diags.Err()
}
