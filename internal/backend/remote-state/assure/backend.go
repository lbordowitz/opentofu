// Copyright (c) The OpenTofu Authors
// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2023 HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package assure

import (
	"context"
	"fmt"
	"time"

	"github.com/opentofu/opentofu/internal/backend"
	"github.com/opentofu/opentofu/internal/backend/remote-state/assure/auth"
	"github.com/opentofu/opentofu/internal/backend/remote-state/assure/config"
	"github.com/opentofu/opentofu/internal/encryption"
	"github.com/opentofu/opentofu/internal/legacy/helper/schema"

	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/container"
)

const defaultTimeout = 300 // 5 minutes

// New creates a new backend for Azure remote state.
func New(enc encryption.StateEncryption) backend.Backend {
	s := &schema.Backend{
		Schema: map[string]*schema.Schema{
			"storage_account_name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The name of the storage account.",
			},

			"container_name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The container name.",
			},

			"key": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The blob key.",
			},

			"metadata_host": {
				Type:        schema.TypeString,
				Required:    true,
				DefaultFunc: schema.EnvDefaultFunc("ARM_METADATA_HOST", ""),
				Description: "The Metadata URL which will be used to obtain the Cloud Environment.",
			},

			"environment": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The Azure cloud environment.",
				DefaultFunc: schema.EnvDefaultFunc("ARM_ENVIRONMENT", "public"),
			},

			"access_key": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The access key.",
				DefaultFunc: schema.EnvDefaultFunc("ARM_ACCESS_KEY", ""),
			},

			"sas_token": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "A SAS Token used to interact with the Blob Storage Account.",
				DefaultFunc: schema.EnvDefaultFunc("ARM_SAS_TOKEN", ""),
			},

			"snapshot": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Enable/Disable automatic blob snapshotting",
				DefaultFunc: schema.EnvDefaultFunc("ARM_SNAPSHOT", false),
			},

			"resource_group_name": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The resource group name.",
			},

			"client_id": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The Client ID.",
				DefaultFunc: schema.EnvDefaultFunc("ARM_CLIENT_ID", ""),
			},

			"endpoint": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "A custom Endpoint used to access the Azure Resource Manager API's.",
				DefaultFunc: schema.EnvDefaultFunc("ARM_ENDPOINT", ""),
			},

			"timeout_seconds": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "The timeout in seconds for initializing a client or retrieving a Blob or a Metadata from Azure.",
				DefaultFunc: schema.EnvDefaultFunc("ARM_TIMEOUT_SECONDS", defaultTimeout),
				ValidateFunc: func(v interface{}, _ string) ([]string, []error) {
					value, ok := v.(int)
					if !ok || value < 0 {
						return nil, []error{fmt.Errorf("timeout_seconds expected to be a non-negative integer")}
					}
					return nil, nil
				},
			},

			"subscription_id": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The Subscription ID.",
				DefaultFunc: schema.EnvDefaultFunc("ARM_SUBSCRIPTION_ID", ""),
			},

			"tenant_id": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The Tenant ID.",
				DefaultFunc: schema.EnvDefaultFunc("ARM_TENANT_ID", ""),
			},

			// Service Principal (Client Certificate) specific
			"client_certificate_password": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The password associated with the Client Certificate specified in `client_certificate_path`",
				DefaultFunc: schema.EnvDefaultFunc("ARM_CLIENT_CERTIFICATE_PASSWORD", ""),
			},
			"client_certificate_path": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The path to the PFX file used as the Client Certificate when authenticating as a Service Principal",
				DefaultFunc: schema.EnvDefaultFunc("ARM_CLIENT_CERTIFICATE_PATH", ""),
			},

			// Service Principal (Client Secret) specific
			"client_secret": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The Client Secret.",
				DefaultFunc: schema.EnvDefaultFunc("ARM_CLIENT_SECRET", ""),
			},

			// Managed Service Identity specific
			"use_msi": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Should Managed Service Identity be used?",
				DefaultFunc: schema.EnvDefaultFunc("ARM_USE_MSI", false),
			},
			"msi_endpoint": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The Managed Service Identity Endpoint.",
				DefaultFunc: schema.EnvDefaultFunc("ARM_MSI_ENDPOINT", ""),
			},

			// OIDC auth specific fields
			"use_oidc": {
				Type:        schema.TypeBool,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc("ARM_USE_OIDC", false),
				Description: "Allow OIDC to be used for authentication",
			},
			"oidc_token": {
				Type:        schema.TypeString,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc("ARM_OIDC_TOKEN", ""),
				Description: "A generic JWT token that can be used for OIDC authentication. Should not be used in conjunction with `oidc_request_token`.",
			},
			"oidc_token_file_path": {
				Type:        schema.TypeString,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc("ARM_OIDC_TOKEN_FILE_PATH", ""),
				Description: "Path to file containing a generic JWT token that can be used for OIDC authentication. Should not be used in conjunction with `oidc_request_token`.",
			},
			"oidc_request_url": {
				Type:        schema.TypeString,
				Optional:    true,
				DefaultFunc: schema.MultiEnvDefaultFunc([]string{"ARM_OIDC_REQUEST_URL", "ACTIONS_ID_TOKEN_REQUEST_URL"}, ""),
				Description: "The URL of the OIDC provider from which to request an ID token. Needs to be used in conjunction with `oidc_request_token`. This is meant to be used for Github Actions.",
			},
			"oidc_request_token": {
				Type:        schema.TypeString,
				Optional:    true,
				DefaultFunc: schema.MultiEnvDefaultFunc([]string{"ARM_OIDC_REQUEST_TOKEN", "ACTIONS_ID_TOKEN_REQUEST_TOKEN"}, ""),
				Description: "The bearer token to use for the request to the OIDC providers `oidc_request_url` URL to fetch an ID token. Needs to be used in conjunction with `oidc_request_url`. This is meant to be used for Github Actions.",
			},

			// Feature Flags
			"use_azuread_auth": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Should OpenTofu use AzureAD Authentication to access the Blob?",
				DefaultFunc: schema.EnvDefaultFunc("ARM_USE_AZUREAD", false),
			},
		},
	}

	result := &Backend{Backend: s, encryption: enc}
	result.Backend.ConfigureFunc = result.configure
	return result
}

type Backend struct {
	*schema.Backend
	encryption encryption.StateEncryption

	// The fields below are set from configure
	containerClient *container.Client
	containerName   string // TODO do we really need this?
	keyName         string
	accountName     string // TODO do we really need this?
	snapshot        bool
	timeout         time.Duration
}

func (b *Backend) configure(ctx context.Context) error {
	if b.containerName != "" {
		return nil
	}

	// Grab the resource data
	data := schema.FromContextBackendConfig(ctx)
	b.containerName = data.Get("container_name").(string)
	b.accountName = data.Get("storage_account_name").(string)
	b.keyName = data.Get("key").(string)
	b.snapshot = data.Get("snapshot").(bool)
	b.timeout = time.Duration(data.Get("timeout_seconds").(int)) * time.Second

	config := config.BackendConfig{
		AccessKey:                     data.Get("access_key").(string),
		ClientID:                      data.Get("client_id").(string),
		ClientCertificatePassword:     data.Get("client_certificate_password").(string),
		ClientCertificatePath:         data.Get("client_certificate_path").(string),
		ClientSecret:                  data.Get("client_secret").(string),
		CustomResourceManagerEndpoint: data.Get("endpoint").(string),
		MetadataHost:                  data.Get("metadata_host").(string),
		Environment:                   data.Get("environment").(string),
		MsiEndpoint:                   data.Get("msi_endpoint").(string),
		OIDCToken:                     data.Get("oidc_token").(string),
		OIDCTokenFilePath:             data.Get("oidc_token_file_path").(string),
		OIDCRequestURL:                data.Get("oidc_request_url").(string),
		OIDCRequestToken:              data.Get("oidc_request_token").(string),
		ResourceGroupName:             data.Get("resource_group_name").(string),
		SasToken:                      data.Get("sas_token").(string),
		StorageAccountName:            data.Get("storage_account_name").(string),
		SubscriptionID:                data.Get("subscription_id").(string),
		TenantID:                      data.Get("tenant_id").(string),
		UseMsi:                        data.Get("use_msi").(bool),
		UseOIDC:                       data.Get("use_oidc").(bool),
		UseAzureADAuthentication:      data.Get("use_azuread_auth").(bool),
	}

	authCred, err := auth.GetAuthCredentials(ctx, &config)
	if err != nil {
		return fmt.Errorf("error getting auth credentials: %w", err)
	}

	// TODO: check if this is correct, maybe we'll add it in!
	/*
		if config.UseAzureADAuthentication {
			// TODO check err
			bootstrapContainerClient, err := container.NewClient(containerURL, authCred, nil)
			if err != nil {
				return err
			}
			b.containerClient = bootstrapContainerClient
			return nil
		}
	*/

	// use auth cred to bootstrap Storage Account Shared Key Auth
	subscriptionID := config.SubscriptionID
	if subscriptionID == "" {
		subscriptionID, err = auth.GetCliAzureSubscriptionID()
		if err != nil {
			return err
		}
	}

	containerClient, err := auth.NewContainerClientWithSharedKeyCredential(
		ctx,
		auth.StorageContainerNames{
			SubscriptionID:   subscriptionID,
			StorageAccount:   b.accountName,
			ResourceGroup:    config.ResourceGroupName,
			StorageContainer: b.containerName,
		},
		auth.StorageCredentials{
			StorageAccessKey: config.AccessKey,
			AuthCred:         authCred,
		},
	)
	if err != nil {
		return err
	}

	b.containerClient = containerClient
	return nil
}
