package assure

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

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

type Subscription struct {
	Id        string `json:"id"`
	Name      string `json:"name"`
	IsDefault bool   `json:"isDefault"`
}

type Profile struct {
	Subscriptions []Subscription `json:"subscriptions"`
}

// TODO make sure this is compatible with Windows, probably refactor a bunch, too.
func getCliAzureSubscriptionID(ctx context.Context) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}

	file, err := os.Open(filepath.Join(home, ".azure", "azureProfile.json"))
	if err != nil {
		return "", err
	}
	raw_file, err := io.ReadAll(file)
	if err != nil {
		return "", err
	}
	// Trim BOM
	raw_file = bytes.TrimPrefix(raw_file, []byte("\xef\xbb\xbf"))

	var profile Profile
	err = json.Unmarshal(raw_file, &profile)
	if err != nil {
		return "", err
	}

	for _, sub := range profile.Subscriptions {
		if sub.IsDefault {
			return sub.Id, nil
		}
	}

	return "", fmt.Errorf("no default subscription found in azureProfile.json")
}
