package auth

import (
	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/opentofu/opentofu/internal/tfdiags"
)

type MSIAuthConfig struct {
	UseMsi      bool
	MsiEndpoint string
}

// TODO azidentity.NewManagedIdentityCredential()

type managedIdentityAuth struct{}

func (cred *managedIdentityAuth) Construct(config *Config) (azcore.TokenCredential, error) {
	return nil, nil
}
func (cred *managedIdentityAuth) Validate(config *Config) tfdiags.Diagnostics {
	return nil
}
