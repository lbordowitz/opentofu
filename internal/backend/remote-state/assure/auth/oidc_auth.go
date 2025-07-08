package auth

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/opentofu/opentofu/internal/httpclient"
	"github.com/opentofu/opentofu/internal/tfdiags"
)

type OIDCAuthConfig struct {
	UseOIDC           bool
	OIDCToken         string
	OIDCTokenFilePath string
	OIDCRequestURL    string
	OIDCRequestToken  string
}

type oidcAuth struct{}

func (cred *oidcAuth) Construct(ctx context.Context, config *Config) (azcore.TokenCredential, error) {
	client := httpclient.New(ctx)
	token, err := consolidateToken(config.OIDCAuthConfig)
	if err != nil {
		return nil, err
	}
	return azidentity.NewClientAssertionCredential(
		config.TenantID,
		config.ClientID,
		// TODO use a separate function for obtaining an access token with request url and request token
		func(innerContext context.Context) (string, error) {
			return token, nil
		},
		&azidentity.ClientAssertionCredentialOptions{
			ClientOptions: clientOptions(client),
		},
	)
}

func consolidateToken(config *OIDCAuthConfig) (string, error) {
	token := config.OIDCToken
	if config.OIDCTokenFilePath != "" {
		// read token from file. Use as token if provided is empty, or check that they're the same
		f, err := os.Open(config.OIDCTokenFilePath)
		if err != nil {
			return "", fmt.Errorf("error opening token file: %w", err)
		}
		defer f.Close()
		b, err := io.ReadAll(f)
		if err != nil {
			return "", fmt.Errorf("error reading token file: %w", err)
		}
		file_token := string(b)
		if token != "" && token != file_token {
			return "", fmt.Errorf("token provided directly and through file do not match; either make them the same value or only provide one")
		}
		token = file_token
	}
	return token, nil
}

func (cred *oidcAuth) Validate(config *Config) tfdiags.Diagnostics {
	var diags tfdiags.Diagnostics
	if !config.UseOIDC {
		diags = diags.Append(tfdiags.Sourceless(
			tfdiags.Error,
			"Use OIDC is not set",
			"In order to use OpenID Connect credentials, use_oidc or the environment variable ARM_USE_OIDC must be set to true",
		))
	}
	if config.TenantID == "" {
		diags = diags.Append(tfdiags.Sourceless(
			tfdiags.Error,
			"Tenant ID is empty",
			"In order to use OpenID Connect credentials, a tenant ID is necessary",
		))
	}
	if config.ClientID == "" {
		diags = diags.Append(tfdiags.Sourceless(
			tfdiags.Error,
			"Client ID is empty",
			"In order to use OpenID Connect credentials, a client ID is necessary",
		))
	}
	/*
		TODO Validate for oidc_request_url and oidc_request_token
		This will change how the below diagnostic works
	*/
	if config.OIDCToken == "" && config.OIDCTokenFilePath == "" {
		diags = diags.Append(tfdiags.Sourceless(
			tfdiags.Error,
			"Both OIDC Token and OIDC Token File Path are empty",
			"In order to use OpenID Connect credentials, the access token must be provided, either directly or through a file",
		))
	}
	if _, err := consolidateToken(config.OIDCAuthConfig); err != nil {
		diags = diags.Append(tfdiags.Sourceless(
			tfdiags.Error,
			"There was a problem reconciling tokens",
			fmt.Sprintf("In order to use OpenID Connect credentials, the access token provided must be readable and consistent, but the following error was encountered: %s", err.Error()),
		))
	}
	return diags
}

func (cred *oidcAuth) AugmentConfig(config *Config) error {
	return checkNamesForAccessKeyCredentials(*config.StorageAddresses)
}
