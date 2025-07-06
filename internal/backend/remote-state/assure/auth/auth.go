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
	Construct(ctx context.Context, config *Config) (azcore.TokenCredential, error)
	Validate(config *Config) tfdiags.Diagnostics
	// AugmentConfig should be called to ensure the config has all proper storage names
	// when attempting to get the storage account's access keys. It will return an error if
	// the expected storage names, IDs, and addresses are not present.
	AugmentConfig(config *Config) error
}

func GetAuthMethod(config *Config) (AuthMethod, error) {
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
		return authMethod, nil
	}
	diags = diags.Append(hcl.Diagnostic{
		Severity: hcl.DiagError,
		Summary:  "No valid azure auth methods found",
		Detail:   "Please see above warnings for details about what each auth method needs to properly work.",
	})
	return nil, diags.ErrWithWarnings()
}
