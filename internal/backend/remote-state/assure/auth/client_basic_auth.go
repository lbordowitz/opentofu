package auth

import (
	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/opentofu/opentofu/internal/tfdiags"
)

type ClientBasicAuthConfig struct {
	ClientID     string
	ClientSecret string
}

// TODO azidentity.NewClientSecretCredential()

type clientBasicAuth struct{}

func (cred *clientBasicAuth) Construct(config *Config) (azcore.TokenCredential, error) {
	return nil, nil
}
func (cred *clientBasicAuth) Validate(config *Config) tfdiags.Diagnostics {
	return nil
}
