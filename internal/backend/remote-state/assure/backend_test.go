package assure

import (
	"context"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/container"
	"github.com/opentofu/opentofu/internal/backend"
	"github.com/opentofu/opentofu/internal/backend/remote-state/assure/auth"
	"github.com/opentofu/opentofu/internal/encryption"
	"github.com/opentofu/opentofu/internal/legacy/helper/acctest"
)

func TestBackend_impl(t *testing.T) {
	var _ backend.Backend = new(Backend)
}

func TestBackendConfig(t *testing.T) {
	// This test just instantiates the client. Shouldn't make any actual
	// requests nor incur any costs.

	config := map[string]interface{}{
		"storage_account_name": "tfaccount",
		"container_name":       "tfcontainer",
		"key":                  "state",
		"snapshot":             false,
		// Access Key must be Base64
		"access_key": "QUNDRVNTX0tFWQ0K",
	}

	b := backend.TestBackendConfig(t, New(encryption.StateEncryptionDisabled()), backend.TestWrapConfig(config)).(*Backend)

	if b.containerName != "tfcontainer" {
		t.Fatalf("Incorrect bucketName was populated")
	}
	if b.keyName != "state" {
		t.Fatalf("Incorrect keyName was populated")
	}
	if b.snapshot != false {
		t.Fatalf("Incorrect snapshot was populated")
	}
}

func TestBackendConfig_Timeout(t *testing.T) {
	config := map[string]any{
		"storage_account_name": "tfaccount",
		"container_name":       "tfcontainer",
		"key":                  "state",
		"snapshot":             false,
		// Access Key must be Base64
		"access_key": "QUNDRVNTX0tFWQ0K",
	}
	testCases := []struct {
		name           string
		timeoutSeconds any
		expectError    bool
	}{
		{
			name:           "string timeout",
			timeoutSeconds: "Nonsense",
			expectError:    true,
		},
		{
			name:           "negative timeout",
			timeoutSeconds: -10,
			expectError:    true,
		},
		{
			// 0 is a valid timeout value, it disables the timeout
			name:           "zero timeout",
			timeoutSeconds: 0,
		},
		{
			name:           "positive timeout",
			timeoutSeconds: 10,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config["timeout_seconds"] = tc.timeoutSeconds
			b, _, errors := backend.TestBackendConfigWarningsAndErrors(t, New(encryption.StateEncryptionDisabled()), backend.TestWrapConfig(config))
			if tc.expectError {
				if len(errors) == 0 {
					t.Fatalf("Expected an error")
				}
				return
			}
			if !tc.expectError && len(errors) > 0 {
				t.Fatalf("Expected no errors, got: %v", errors)
			}
			be, ok := b.(*Backend)
			if !ok || be == nil {
				t.Fatalf("Expected initialized Backend, got %T", b)
			}
			if int(be.timeout.Seconds()) != tc.timeoutSeconds {
				t.Fatalf("Expected timeoutSeconds to be %d, got %d", tc.timeoutSeconds, int(be.timeout.Seconds()))
			}
		})
	}
}

type mockClient struct{}

func (p mockClient) NewListBlobsFlatPager(params *container.ListBlobsFlatOptions) *runtime.Pager[container.ListBlobsFlatResponse] {
	env_name := "env-name"
	blobDetails := make([]*container.BlobItem, 5000)
	for i := range blobDetails {
		blobDetails[i] = &container.BlobItem{}
		blobDetails[i].Name = &env_name
	}

	returnMarker := "next-token"

	// This function will be called first with an empty parameter, putting the returnMarker as "next-token".
	// On the second call, the returnMarker won't be empty, then finishing the pagination function;
	if *params.Marker != "" {
		returnMarker = ""
	}

	return runtime.NewPager(runtime.PagingHandler[container.ListBlobsFlatResponse]{
		More: func(resp container.ListBlobsFlatResponse) bool {
			return *resp.Marker == ""
		},
		Fetcher: func(context.Context, *container.ListBlobsFlatResponse) (container.ListBlobsFlatResponse, error) {
			return container.ListBlobsFlatResponse{
				ListBlobsFlatSegmentResponse: container.ListBlobsFlatSegmentResponse{
					Segment: &container.BlobFlatListSegment{
						BlobItems: blobDetails,
					},
					Marker:     params.Marker,
					NextMarker: &returnMarker,
				},
			}, nil
		},
	})
}

func TestBackendPagination(t *testing.T) {
	ctx := context.Background()
	client := &mockClient{}
	result, err := getPaginatedResults(ctx, client, "env")
	if err != nil {
		t.Fatalf("error getting paginated results %q", err)
	}

	// default is always on the list + 10k generated blobs from the mocked ListBlobs
	if len(result) != 10001 {
		t.Fatalf("expected len 10001, got %d instead", len(result))
	}
}

// TestAccBackendAccessKeyBasic tests if the backend functions when using basic access key.
// The call to backend.TestBackendStates tests workspace creation, list and deletion.
func TestAccBackendAccessKeyBasic(t *testing.T) {
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
		"disable_cli":          true,
	})).(*Backend)

	backend.TestBackendStates(t, b1)

	b2 := backend.TestBackendConfig(t, New(encryption.StateEncryptionDisabled()), backend.TestWrapConfig(map[string]interface{}{
		"storage_account_name": res.storageAccountName,
		"container_name":       res.storageContainerName,
		"key":                  res.storageKeyName,
		"access_key":           res.storageAccountAccessKey,
		"disable_cli":          true,
	})).(*Backend)

	// TestBackendStateForceUnlock runs the both the TestBackendStateLocks test and the --force-unlock tests
	backend.TestBackendStateForceUnlock(t, b1, b2)
}

// TestAccBackendSASToken tests if the backend functions when using a SAS token.
// The call to backend.TestBackendStates tests workspace creation, list and deletion.
func TestAccBackendSASToken(t *testing.T) {
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

	keycred, err := azblob.NewSharedKeyCredential(res.storageAccountName, res.storageAccountAccessKey)
	if err != nil {
		t.Fatal(err)
	}

	sasToken, err := getSASToken(keycred)
	if err != nil {
		t.Fatal(err)
	}

	b1 := backend.TestBackendConfig(t, New(encryption.StateEncryptionDisabled()), backend.TestWrapConfig(map[string]interface{}{
		"storage_account_name": res.storageAccountName,
		"container_name":       res.storageContainerName,
		"key":                  res.storageKeyName,
		"sas_token":            sasToken,
		"disable_cli":          true,
	})).(*Backend)

	backend.TestBackendStates(t, b1)

	b2 := backend.TestBackendConfig(t, New(encryption.StateEncryptionDisabled()), backend.TestWrapConfig(map[string]interface{}{
		"storage_account_name": res.storageAccountName,
		"container_name":       res.storageContainerName,
		"key":                  res.storageKeyName,
		"sas_token":            sasToken,
		"disable_cli":          true,
	})).(*Backend)

	// TestBackendStateForceUnlock runs the both the TestBackendStateLocks test and the --force-unlock tests
	backend.TestBackendStateForceUnlock(t, b1, b2)
}
