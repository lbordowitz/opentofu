package auth

import (
	"context"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/opentofu/opentofu/internal/backend/remote-state/assure/config"
)

/*
TODO: provide auth credentials from config, in the following order:
    azidentity.NewClientCertificateCredential()
    azidentity.NewClientSecretCredential()
    azidentity.NewClientAssertionCredential() -> OIDC, plus OIDC via token request
    azidentity.NewManagedIdentityCredential()
    azidentity.NewAzureCLICredential()
*/

func GetAuthCredentials(ctx context.Context, config *config.BackendConfig) (*azidentity.AzureCLICredential, error) {
	return azidentity.NewAzureCLICredential(nil)
}

type Subscription struct {
	Id        string `json:"id"`
	Name      string `json:"name"`
	IsDefault bool   `json:"isDefault"`
}

type Profile struct {
	Subscriptions []Subscription `json:"subscriptions"`
}
