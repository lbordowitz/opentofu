package auth

import (
	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/opentofu/opentofu/internal/tfdiags"
)

type ClientCertificateAuthConfig struct {
	ClientCertificatePassword string
	ClientCertificatePath     string
}

type clientCertAuth struct{}

func (cred *clientCertAuth) Construct(config *Config) (azcore.TokenCredential, error) {
	// TODO pass through http client maybe????
	// client := httpclient.New(context.TODO())
	// TODO this is 100% incorrect, we should be providing the x509 certificates themselves!
	// Figure out some file handling thing, maybe go to the go helpers and copy some of their logic.
	// return azidentity.NewClientCertificateCredential(
	// 	config.StorageAddresses.TenantID,
	// 	config.ClientBasicAuthConfig.ClientID,
	// 	config.ClientCertificateAuthConfig.ClientCertificatePath,
	// 	config.ClientCertificateAuthConfig.ClientCertificatePassword,
	// 	&azidentity.ClientCertificateCredentialOptions{
	// 		ClientOptions: clientOptions(client),
	// 	},
	// )
	return nil, nil
}
func (cred *clientCertAuth) Validate(config *Config) tfdiags.Diagnostics {
	var diags tfdiags.Diagnostics
	diags = diags.Append(tfdiags.Sourceless(
		tfdiags.Error,
		"Certificate Auth is unimplemented",
		"This authentication method has yet to be implemented",
	))
	return diags
}
