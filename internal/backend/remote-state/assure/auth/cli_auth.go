package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/opentofu/opentofu/internal/tfdiags"
)

type azureCLICredentialAuth struct{}

func (cred *azureCLICredentialAuth) Construct(_ context.Context, config *Config) (azcore.TokenCredential, error) {
	// TODO is this enough?
	return azidentity.NewAzureCLICredential(&azidentity.AzureCLICredentialOptions{
		Subscription: config.StorageAddresses.SubscriptionID,
		TenantID:     config.StorageAddresses.TenantID,
	})
}
func (cred *azureCLICredentialAuth) Validate(config *Config) tfdiags.Diagnostics {
	// TODO determine if there's anything here we need to validate
	return nil
}

type Subscription struct {
	Id        string `json:"id"`
	Name      string `json:"name"`
	IsDefault bool   `json:"isDefault"`
}

type Profile struct {
	Subscriptions []Subscription `json:"subscriptions"`
}

// getCliAzureSubscriptionID obtains the subscription ID currently active in the
// Azure profile. This assumes the user has an Azure profile saved to their
// home directory, which is usually provided by the Azure command line tool when
// using `az login`.
// # TODO make sure this is compatible with Windows
// # TODO do we want to obtain anything else from the profile setting? Tenant ID, perhaps?
func GetCliAzureSubscriptionID() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}

	azureProfileFilePath := filepath.Join(home, ".azure", "azureProfile.json")
	file, err := os.Open(azureProfileFilePath)
	if err != nil {
		return "", fmt.Errorf("error opening azure profile at %s: %w", azureProfileFilePath, err)
	}
	rawFile, err := io.ReadAll(file)
	if err != nil {
		return "", fmt.Errorf("error reading azure profile at %s: %w", azureProfileFilePath, err)
	}
	// Trim BOM
	rawFile = bytes.TrimPrefix(rawFile, []byte("\xef\xbb\xbf"))

	var profile Profile
	err = json.Unmarshal(rawFile, &profile)
	if err != nil {
		return "", fmt.Errorf("json error for azure profile at %s: %w", azureProfileFilePath, err)
	}

	for _, sub := range profile.Subscriptions {
		if sub.IsDefault {
			return sub.Id, nil
		}
	}

	return "", fmt.Errorf("no default subscription found in azureProfile.json")
}
