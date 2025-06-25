package auth

import (
	"context"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/storage/armstorage"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/container"
)

func NewResourceClient(authCred azcore.TokenCredential, subscriptionID string) (*armresources.ResourceGroupsClient, error) {
	resourcesClientFactory, err := armresources.NewClientFactory(subscriptionID, authCred, nil)
	if err != nil {
		return nil, fmt.Errorf("error getting resource client factory: %w", err)
	}
	return resourcesClientFactory.NewResourceGroupsClient(), nil
}

func NewStorageAccountsClient(authCred azcore.TokenCredential, subscriptionID string) (*armstorage.AccountsClient, error) {
	storageClientFactory, err := armstorage.NewClientFactory(subscriptionID, authCred, nil)
	if err != nil {
		return nil, fmt.Errorf("error getting storage client factory: %w", err)
	}
	return storageClientFactory.NewAccountsClient(), nil
}

type StorageContainerNames struct {
	SubscriptionID   string
	StorageAccount   string
	ResourceGroup    string
	StorageContainer string
}

type StorageCredentials struct {
	StorageAccessKey string
	AuthCred         azcore.TokenCredential
}

func NewContainerClientWithSharedKeyCredential(ctx context.Context, names StorageContainerNames, creds StorageCredentials) (*container.Client, error) {
	containerClient, _, err := NewContainerClientWithSharedKeyCredentialAndKey(ctx, names, creds)
	return containerClient, err
}

func NewContainerClientWithSharedKeyCredentialAndKey(ctx context.Context, names StorageContainerNames, creds StorageCredentials) (*container.Client, string, error) {
	if creds.StorageAccessKey == "" {
		// Lookup the key with an account client
		accountsClient, err := NewStorageAccountsClient(creds.AuthCred, names.SubscriptionID)
		if err != nil {
			return nil, "", err
		}
		keys, err := accountsClient.ListKeys(ctx, names.ResourceGroup, names.StorageAccount, nil)
		if err != nil {
			return nil, "", fmt.Errorf("error listing access keys on the storage account: %w", err)
		}
		if len(keys.Keys) == 0 || keys.Keys[0] == nil || keys.Keys[0].Value == nil {
			return nil, "", fmt.Errorf("malformed structure returned from the ListKeys function")
		}

		creds.StorageAccessKey = *keys.Keys[0].Value
	}

	sharedKeyCredential, err := container.NewSharedKeyCredential(names.StorageAccount, creds.StorageAccessKey)
	if err != nil {
		return nil, "", fmt.Errorf("error creating credential from shared access key: %w", err)
	}
	// TODO we may want to do further error and name checking on this URL
	containerURL := fmt.Sprintf("https://%s.blob.core.windows.net/%s", names.StorageAccount, names.StorageContainer)

	containerClient, err := container.NewClientWithSharedKeyCredential(containerURL, sharedKeyCredential, nil)
	if err != nil {
		return nil, "", fmt.Errorf("error obtaining container client from access key: %w", err)
	}
	return containerClient, creds.StorageAccessKey, nil
}
