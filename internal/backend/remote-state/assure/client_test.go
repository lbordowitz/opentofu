package assure

import (
	"context"
	"fmt"
	"testing"
	"time"

	msgraph "github.com/microsoftgraph/msgraph-sdk-go"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization/v2"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/storage/armstorage"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/container"
	"github.com/google/uuid"
	"github.com/opentofu/opentofu/internal/legacy/helper/acctest"
	"github.com/opentofu/opentofu/internal/states/remote"
)

func TestRemoteClient_impl(t *testing.T) {
	var _ remote.Client = new(RemoteClient)
	var _ remote.ClientLocker = new(RemoteClient)
}

func TestPutMaintainsMetadata(t *testing.T) {
	testAccAzureBackend(t)
	rs := acctest.RandString(4)
	res := testResourceNames(rs, "testState")

	// TODO copied out of backend.go, maybe we should refactor it to make it DRY? Do some sort of client helper function?
	// TODO check error
	authCred, _ := getAuthCredentials(t.Context(), nil)

	// TODO consider moving the resource creation code into a helper function.
	//BEGIN TEST RESOURCE CREATION
	resourcesClientFactory, err := armresources.NewClientFactory(res.subscriptionID, authCred, nil)
	if err != nil {
		t.Fatal(err)
	}
	resourceGroupClient := resourcesClientFactory.NewResourceGroupsClient()

	// TODO check error here
	resourceGroupClient.CreateOrUpdate(t.Context(), res.resourceGroup, armresources.ResourceGroup{Location: &res.location}, nil)
	storageClientFactory, err := armstorage.NewClientFactory(res.subscriptionID, authCred, nil)
	if err != nil {
		t.Fatal(err)
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
		t.Fatalf("failed to create test storage account: %v", err)
	}
	_, err = future.PollUntilDone(t.Context(), nil)
	if err != nil {
		t.Fatalf("failed waiting for the creation of storage account: %v", err)
	}
	// TODO this is copied from backend.go as well.
	// TODO do we need to ensure this is properly url encoded? That the account name is a proper account name?
	containerURL := fmt.Sprintf("https://%s.blob.core.windows.net/%s", res.storageAccountName, res.storageContainerName)
	containerClient, _ := container.NewClient(containerURL, authCred, nil)

	// TODO check error here
	containerClient.Create(t.Context(), nil)

	// TODO REMOVE THIS from here...
	authZFactory, err := armauthorization.NewClientFactory(res.subscriptionID, authCred, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Get information about the current principal
	// TODO is any of this even correct?
	// TODO double-check scopes
	graphClient, err := msgraph.NewGraphServiceClientWithCredentials(authCred, []string{"Files.Read"})
	user, err := graphClient.Me().Get(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	principalType := armauthorization.PrincipalType(*user.GetUserType())

	storageBlobDataContributorRoleID := "ba92f5b4-2d11-453d-a403-e96b0029c9fe"

	authZClient := authZFactory.NewRoleAssignmentsClient()
	_, err = authZClient.Create(
		t.Context(),
		res.roleScope(),
		uuid.New().String(),
		armauthorization.RoleAssignmentCreateParameters{
			Properties: &armauthorization.RoleAssignmentProperties{
				PrincipalID:      user.GetId(),
				PrincipalType:    &principalType,
				RoleDefinitionID: to.Ptr(res.roleInSub(storageBlobDataContributorRoleID)),
			},
		},
		&armauthorization.RoleAssignmentsClientCreateOptions{},
	)
	if err != nil {
		t.Fatal(err)
	}
	// ... to here

	// END TEST RESOURCE CREATE
	t.Cleanup(func() {
		future, err := resourceGroupClient.BeginDelete(context.Background(), res.resourceGroup, nil)
		if err != nil {
			t.Fatalf("Error deleting Resource Group: %v", err)
		}
		_, err = future.PollUntilDone(context.Background(), nil)
		if err != nil {
			t.Fatalf("Error waiting for the deletion of Resource Group: %v", err)
		}
	})

	headerName := "acceptancetest"
	expectedValue := "f3b56bad-33ad-4b93-a600-7a66e9cbd1eb"

	blobClient := containerClient.NewBlockBlobClient(res.storageKeyName)

	// PUT
	_, err = blobClient.UploadBuffer(t.Context(), []byte{}, nil)
	if err != nil {
		t.Fatalf("Error Creating Block Blob: %+v", err)
	}

	// GET PROPERTIES
	blobReference, err := blobClient.GetProperties(t.Context(), nil)
	if err != nil {
		t.Fatalf("Error loading Metadata: %+v", err)
	}
	// CHANGE + SET METADATA
	// Metadata should be empty; this is a new blob.
	blobReference.Metadata = make(map[string]*string)
	blobReference.Metadata[headerName] = &expectedValue
	_, err = blobClient.SetMetadata(t.Context(), blobReference.Metadata, nil)
	if err != nil {
		t.Fatalf("Error setting Metadata: %+v", err)
	}

	// UPDATE WITH REMOTE CLIENT PUT
	remoteClient := RemoteClient{
		blobClient: blobClient,
		timeout:    time.Duration(180) * time.Second,
	}
	bytes := []byte(acctest.RandString(20))
	err = remoteClient.Put(bytes)
	if err != nil {
		t.Fatalf("Error putting data: %+v", err)
	}
	// CHECK METADATA AGAIN, SEE THAT IT IS NOT SQUOOSHED

	blobReference, err = blobClient.GetProperties(t.Context(), nil)
	if err != nil {
		t.Fatalf("Error loading Metadata: %+v", err)
	}

	if *blobReference.Metadata[headerName] != expectedValue {
		t.Fatalf("%q was not set to %q in the Metadata: %+v", headerName, expectedValue, blobReference.Metadata)
	}
}

/*


	_, err = client.PutBlockBlob(t.Context(), res.storageAccountName, res.storageContainerName, res.storageKeyName, blobs.PutBlockBlobInput{})
	if err != nil {
		t.Fatalf("Error Creating Block Blob: %+v", err)
	}

	blobReference, err := client.GetProperties(t.Context(), res.storageAccountName, res.storageContainerName, res.storageKeyName, blobs.GetPropertiesInput{})
	if err != nil {
		t.Fatalf("Error loading MetaData: %+v", err)
	}

	blobReference.MetaData[headerName] = expectedValue
	opts := blobs.SetMetaDataInput{
		MetaData: blobReference.MetaData,
	}
	_, err = client.SetMetaData(t.Context(), res.storageAccountName, res.storageContainerName, res.storageKeyName, opts)
	if err != nil {
		t.Fatalf("Error setting MetaData: %+v", err)
	}

	// update the metadata using the Backend
	remoteClient := RemoteClient{
		keyName:       res.storageKeyName,
		containerName: res.storageContainerName,
		accountName:   res.storageAccountName,

		giovanniBlobClient: *client,
	}

	bytes := []byte(acctest.RandString(20))
	err = remoteClient.Put(bytes)
	if err != nil {
		t.Fatalf("Error putting data: %+v", err)
	}

	// Verify it still exists
	blobReference, err = client.GetProperties(t.Context(), res.storageAccountName, res.storageContainerName, res.storageKeyName, blobs.GetPropertiesInput{})
	if err != nil {
		t.Fatalf("Error loading MetaData: %+v", err)
	}

	if blobReference.MetaData[headerName] != expectedValue {
		t.Fatalf("%q was not set to %q in the MetaData: %+v", headerName, expectedValue, blobReference.MetaData)
	}
}
*/
