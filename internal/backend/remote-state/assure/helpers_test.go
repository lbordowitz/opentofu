package assure

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
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
	subscriptionID       string
	resourceGroup        string
	location             string
	storageAccountName   string
	storageContainerName string
	storageKeyName       string
	// storageAccountAccessKey string
	// useAzureADAuth          bool
}

func (r resourceNames) roleInSub(roleID string) string {
	return fmt.Sprintf(
		"/subscriptions/%s/providers/Microsoft.Authorization/roleDefinitions/%s",
		r.subscriptionID,
		roleID,
	)
}

//				//		RoleDefinitionID: to.Ptr(),

func (r resourceNames) roleScope() string {
	return fmt.Sprintf(
		"/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Storage/storageAccounts/%s/blobServices/default/containers/%s",
		r.subscriptionID,
		r.resourceGroup,
		r.storageAccountName,
		r.storageContainerName,
	)
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
