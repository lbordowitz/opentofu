package assure

import (
	"context"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
)

/*
TODO: provide auth credentials from config, in the following order:
    azidentity.NewClientCertificateCredential()
    azidentity.NewClientSecretCredential()
    azidentity.NewClientAssertionCredential() -> OIDC, plus OIDC via token request
    azidentity.NewManagedIdentityCredential()
    azidentity.NewAzureCLICredential()
*/

func getAuthCredentials(ctx context.Context, config *BackendConfig) (*azidentity.AzureCLICredential, error) {
	return azidentity.NewAzureCLICredential(nil)
}
