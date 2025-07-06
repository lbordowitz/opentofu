package auth

import (
	"context"
	"crypto/x509"
	"fmt"
	"io"
	"os"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/opentofu/opentofu/internal/httpclient"
	"github.com/opentofu/opentofu/internal/tfdiags"
	"golang.org/x/crypto/pkcs12"
)

type ClientCertificateAuthConfig struct {
	ClientCertificatePassword string
	ClientCertificatePath     string
}

type clientCertAuth struct{}

func (cred *clientCertAuth) Construct(ctx context.Context, config *Config) (azcore.TokenCredential, error) {
	client := httpclient.New(ctx)

	privateKey, certificate, err := decodePFXCertificate(
		config.ClientCertificateAuthConfig.ClientCertificatePath,
		config.ClientCertificateAuthConfig.ClientCertificatePassword,
	)
	if err != nil {
		return nil, err
	}

	return azidentity.NewClientCertificateCredential(
		config.StorageAddresses.TenantID,
		config.ClientBasicAuthConfig.ClientID,
		[]*x509.Certificate{certificate},
		privateKey,
		&azidentity.ClientCertificateCredentialOptions{
			ClientOptions: clientOptions(client),
		},
	)
}

func (cred *clientCertAuth) Validate(config *Config) tfdiags.Diagnostics {
	var diags tfdiags.Diagnostics
	if config.StorageAddresses.TenantID == "" {
		diags = diags.Append(tfdiags.Sourceless(
			tfdiags.Error,
			"Tenant ID is empty",
			"In order to use Client Certificate credentials, a tenant ID is necessary",
		))
	}
	if config.ClientBasicAuthConfig.ClientID == "" {
		diags = diags.Append(tfdiags.Sourceless(
			tfdiags.Error,
			"Client ID is empty",
			"In order to use Client Certificate credentials, a client ID is necessary",
		))
	}
	if config.ClientCertificateAuthConfig.ClientCertificatePath == "" {
		diags = diags.Append(tfdiags.Sourceless(
			tfdiags.Error,
			"Client Certificate Path is empty",
			"In order to use Client Certificate credentials, the path to a client certificate is necessary",
		))
	} else {
		_, _, err := decodePFXCertificate(
			config.ClientCertificateAuthConfig.ClientCertificatePath,
			config.ClientCertificateAuthConfig.ClientCertificatePassword,
		)
		if err != nil {
			diags = diags.Append(tfdiags.Sourceless(
				tfdiags.Error,
				"Error obtaining and decoding certificate details",
				fmt.Sprintf("In order to use Client Certificate credentials, a valid certificate is required. The following error was encountered: %s", err.Error()),
			))

		}
	}
	return diags
}

func (cred *clientCertAuth) AugmentConfig(config *Config) error {
	return checkNamesForAccessKeyCredentials(*config.StorageAddresses)
}

func decodePFXCertificate(pfxFileName string, password string) (privateKey interface{}, certificate *x509.Certificate, err error) {
	// open file, read file contents, decode cert
	f, err := os.Open(pfxFileName)
	if err != nil {
		err = fmt.Errorf("problem opening file at %s: %w", pfxFileName, err)
		return
	}
	contents, err := io.ReadAll(f)
	if err != nil {
		err = fmt.Errorf("problem reading file: %w", err)
		return
	}
	return pkcs12.Decode(contents, password)
}
