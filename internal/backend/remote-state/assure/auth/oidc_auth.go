package auth

import (
	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/hashicorp/hcl/v2"
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
	diags = diags.Append(hcl.Diagnostic{
		Severity: tfdiags.Warning.ToHCL(),
		Summary:  "OIDC Auth is unimplemented",
		Detail:   "This authentication method has yet to be implemented",
	})
	return diags
}
