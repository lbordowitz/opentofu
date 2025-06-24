package assure

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/storage/armstorage"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/container"
)

// verify that we are doing ACC tests or the Azure tests specifically
func testAccAzureBackend(t *testing.T) {
	skip := os.Getenv("TF_ACC") == "" && os.Getenv("TF_AZURE_TEST") == ""
	if skip {
		t.Log("azure backend tests require setting TF_ACC or TF_AZURE_TEST")
		t.Skip()
	}
}

// these kind of tests can only run when within Azure (e.g. MSI)
// func testAccAzureBackendRunningInAzure(t *testing.T) {
// 	testAccAzureBackend(t)

// 	if os.Getenv("TF_RUNNING_IN_AZURE") == "" {
// 		t.Skip("Skipping test since not running in Azure")
// 	}
// }

type resourceNames struct {
	subscriptionID          string
	resourceGroup           string
	location                string
	storageAccountName      string
	storageContainerName    string
	storageKeyName          string
	storageAccountAccessKey string
	// useAzureADAuth          bool
}

func testResourceNames(rString string, keyName string) resourceNames {
	return resourceNames{
		subscriptionID:       os.Getenv("ARM_SUBSCRIPTION_ID"),
		resourceGroup:        fmt.Sprintf("acctestRG-backend-%s-%s", strings.Replace(time.Now().Local().Format("060102150405.00"), ".", "", 1), rString),
		location:             os.Getenv("ARM_LOCATION"),
		storageAccountName:   fmt.Sprintf("acctestsa%s", rString),
		storageContainerName: "acctestcont",
		storageKeyName:       keyName,
		// useAzureADAuth:       false,
	}
}

func createTestResources(t *testing.T, res *resourceNames, authCred *azidentity.AzureCLICredential) (*armresources.ResourceGroupsClient, *container.Client, error) {
	resourcesClientFactory, err := armresources.NewClientFactory(res.subscriptionID, authCred, nil)
	//TODO check error here
	if err != nil {
		return nil, nil, err
	}
	resourceGroupClient := resourcesClientFactory.NewResourceGroupsClient()

	// TODO check error here
	resourceGroupClient.CreateOrUpdate(t.Context(), res.resourceGroup, armresources.ResourceGroup{Location: &res.location}, nil)
	storageClientFactory, err := armstorage.NewClientFactory(res.subscriptionID, authCred, nil)
	if err != nil {
		return nil, nil, err
	}
	accountsClient := storageClientFactory.NewAccountsClient()
	future, err := accountsClient.BeginCreate(t.Context(), res.resourceGroup, res.storageAccountName, armstorage.AccountCreateParameters{
		Kind:     to.Ptr(armstorage.KindStorageV2),
		Location: &res.location,
		SKU: &armstorage.SKU{
			Name: to.Ptr(armstorage.SKUNameStandardLRS),
			Tier: to.Ptr(armstorage.SKUTierStandard),
		},
	}, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create test storage account: %v", err)
	}
	_, err = future.PollUntilDone(t.Context(), nil)
	if err != nil {
		return nil, nil, fmt.Errorf("failed waiting for the creation of storage account: %v", err)
	}
	// TODO this is copied from backend.go as well.
	// TODO CHECK ERROR!!!
	keys, err := accountsClient.ListKeys(t.Context(), res.resourceGroup, res.storageAccountName, nil)
	if err != nil {
		return nil, nil, err
	}
	// TODO lots of sketchy pointer stuff here, double-check it
	res.storageAccountAccessKey = *keys.Keys[0].Value

	sharedKeyCredential, err := container.NewSharedKeyCredential(res.storageAccountName, res.storageAccountAccessKey)
	if err != nil {
		return nil, nil, err
	}
	containerURL := fmt.Sprintf("https://%s.blob.core.windows.net/%s", res.storageAccountName, res.storageContainerName)

	// containerClient, err := container.NewClient(containerURL, authCred, nil)
	containerClient, err := container.NewClientWithSharedKeyCredential(containerURL, sharedKeyCredential, nil)

	// TODO check error here
	containerClient.Create(t.Context(), nil)
	return resourceGroupClient, containerClient, err
}

func destroyTestResources(t *testing.T, resourceGroupClient *armresources.ResourceGroupsClient, res resourceNames) {
	future, err := resourceGroupClient.BeginDelete(context.Background(), res.resourceGroup, nil)
	if err != nil {
		t.Fatalf("Error deleting Resource Group: %v", err)
	}
	_, err = future.PollUntilDone(context.Background(), nil)
	if err != nil {
		t.Fatalf("Error waiting for the deletion of Resource Group: %v", err)
	}
}
