package assure

import (
	"testing"
	"time"

	"github.com/opentofu/opentofu/internal/backend"
	"github.com/opentofu/opentofu/internal/backend/remote-state/assure/auth"
	"github.com/opentofu/opentofu/internal/encryption"
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

	authMethod, err := auth.GetAuthMethod(emptyAuthConfig())
	if err != nil {
		t.Fatal(err)
	}
	authCred, err := authMethod.Construct(t.Context(), emptyAuthConfig())
	if err != nil {
		t.Fatal(err)
	}

	resourceGroupClient, containerClient, err := createTestResources(t, &res, authCred)

	t.Cleanup(func() {
		destroyTestResources(t, resourceGroupClient, res)
	})
	if err != nil {
		t.Fatal(err)
	}

	headerName := "acceptancetest"
	expectedValue := "f3b56bad-33ad-4b93-a600-7a66e9cbd1eb"

	blobClient := containerClient.NewBlockBlobClient(res.storageKeyName)

	// PUT
	_, err = blobClient.UploadBuffer(t.Context(), []byte{}, nil)
	if err != nil {
		t.Fatalf("Error Creating Block Blob: %+v", err)
	}

	remoteClient := RemoteClient{
		blobClient: blobClient,
		timeout:    time.Duration(180) * time.Second,
	}

	// GET PROPERTIES
	blobReference, err := remoteClient.getBlobProperties()
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

	// UPDATE WITH PUT
	bytes := []byte(acctest.RandString(20))
	err = remoteClient.Put(bytes)
	if err != nil {
		t.Fatalf("Error putting data: %+v", err)
	}
	// CHECK METADATA AGAIN, SEE THAT IT IS NOT SQUOOSHED
	blobReference, err = remoteClient.getBlobProperties()
	if err != nil {
		t.Fatalf("Error loading Metadata: %+v", err)
	}

	if metaval, ok := blobReference.Metadata[headerName]; !ok || *metaval != expectedValue {
		t.Fatalf("%q was not set to %q in the Metadata: %+v", headerName, expectedValue, blobReference.Metadata)
	}
}

func TestRemoteClientAccessKeyBasic(t *testing.T) {
	testAccAzureBackend(t)
	rs := acctest.RandString(4)
	res := testResourceNames(rs, "testState")

	authMethod, err := auth.GetAuthMethod(emptyAuthConfig())
	if err != nil {
		t.Fatal(err)
	}
	authCred, err := authMethod.Construct(t.Context(), emptyAuthConfig())
	if err != nil {
		t.Fatal(err)
	}

	resourceGroupClient, _, err := createTestResources(t, &res, authCred)

	t.Cleanup(func() {
		destroyTestResources(t, resourceGroupClient, res)
	})
	if err != nil {
		t.Fatal(err)
	}

	b1 := backend.TestBackendConfig(t, New(encryption.StateEncryptionDisabled()), backend.TestWrapConfig(map[string]interface{}{
		"storage_account_name": res.storageAccountName,
		"container_name":       res.storageContainerName,
		"key":                  res.storageKeyName,
		"access_key":           res.storageAccountAccessKey,
	})).(*Backend)

	s1, err := b1.StateMgr(t.Context(), backend.DefaultStateName)
	if err != nil {
		t.Fatal(err)
	}

	remote.TestClient(t, s1.(*remote.State).Client)

	b2 := backend.TestBackendConfig(t, New(encryption.StateEncryptionDisabled()), backend.TestWrapConfig(map[string]interface{}{
		"storage_account_name": res.storageAccountName,
		"container_name":       res.storageContainerName,
		"key":                  res.storageKeyName,
		"access_key":           res.storageAccountAccessKey,
	})).(*Backend)

	s2, err := b2.StateMgr(t.Context(), backend.DefaultStateName)
	if err != nil {
		t.Fatal(err)
	}

	remote.TestRemoteLocks(t, s1.(*remote.State).Client, s2.(*remote.State).Client)
}
