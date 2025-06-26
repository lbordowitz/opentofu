package auth

import (
	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/opentofu/opentofu/internal/tfdiags"
)

type ClientCertificateAuthConfig struct {
	ClientCertificatePassword string
	ClientCertificatePath     string
}

// TODO azidentity.NewClientCertificateCredential()

type clientCertAuth struct{}

func (cred *clientCertAuth) Construct(config *Config) (azcore.TokenCredential, error) {
	return nil, nil
}
func (cred *clientCertAuth) Validate(config *Config) tfdiags.Diagnostics {
	return nil
}
