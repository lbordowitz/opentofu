package assure

import (
	"testing"

	"github.com/opentofu/opentofu/internal/backend"
	"github.com/opentofu/opentofu/internal/encryption"
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
