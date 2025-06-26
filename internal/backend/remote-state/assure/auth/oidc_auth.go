package auth

import (
	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/opentofu/opentofu/internal/tfdiags"
)

type OIDCAuthConfig struct {
	UseOIDC           bool
	OIDCToken         string
	OIDCTokenFilePath string
	OIDCRequestURL    string
	OIDCRequestToken  string
}

// TODO azidentity.NewClientAssertionCredential() -> OIDC, plus OIDC via token request
// This auth method is probably going to be the most difficult.

type oidcAuth struct{}

func (cred *oidcAuth) Construct(config *Config) (azcore.TokenCredential, error) {
	return nil, nil
}
func (cred *oidcAuth) Validate(config *Config) tfdiags.Diagnostics {
	var diags tfdiags.Diagnostics
	diags = diags.Append(tfdiags.Sourceless(
		tfdiags.Error,
		"OIDC Auth is unimplemented",
		"This authentication method has yet to be implemented",
	))
	return diags
}
