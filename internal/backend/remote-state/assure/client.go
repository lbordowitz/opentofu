// Copyright (c) The OpenTofu Authors
// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2023 HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package assure

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/blob"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/blockblob"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/lease"
	"github.com/hashicorp/go-uuid"
	"github.com/opentofu/opentofu/internal/states/remote"
	"github.com/opentofu/opentofu/internal/states/statemgr"
)

const (
	leaseHeader = "x-ms-lease-id"
	// Must be lower case
	lockInfoMetaKey = "terraformlockid"
)

type RemoteClient struct {
	blobClient    *blockblob.Client
	accountName   string
	containerName string
	keyName       string
	leaseID       *string
	snapshot      bool
	timeout       time.Duration
}

func (c *RemoteClient) Get() (*remote.Payload, error) {
	// Get should time out after the timeoutSeconds
	ctx, ctxCancel := c.getContextWithTimeout()
	defer ctxCancel()
	resp, err := c.blobClient.DownloadStream(ctx, &blob.DownloadStreamOptions{
		AccessConditions: c.leaseAccessCondition(),
	})
	if err != nil {
		if notFoundError(err) {
			return nil, nil
		}
		return nil, err
	}
	defer resp.Body.Close()
	// TODO check error here
	data, _ := io.ReadAll(resp.Body)

	payload := &remote.Payload{
		Data: data,
	}

	// If there was no data, then return nil
	if len(data) == 0 {
		return nil, nil
	}

	return payload, nil
}

func (c *RemoteClient) Put(data []byte) error {
	ctx, ctxCancel := c.getContextWithTimeout()
	defer ctxCancel()
	if c.snapshot {
		snapshotInput := &blob.CreateSnapshotOptions{AccessConditions: c.leaseAccessCondition()}
		log.Printf("[DEBUG] Snapshotting existing Blob %q (Container %q / Account %q)", c.keyName, c.containerName, c.accountName)
		if _, err := c.blobClient.CreateSnapshot(ctx, snapshotInput); err != nil {
			return fmt.Errorf("error snapshotting Blob %q (Container %q / Account %q): %w", c.keyName, c.containerName, c.accountName, err)
		}

		log.Print("[DEBUG] Created blob snapshot")
	}

	properties, err := c.getBlobProperties()
	if err != nil {
		if !notFoundError(err) {
			return err
		}
	}

	putOptions := &blockblob.UploadBufferOptions{
		Metadata:         properties.Metadata,
		AccessConditions: c.leaseAccessCondition(),
		HTTPHeaders:      httpHeaders(),
	}
	_, err = c.blobClient.UploadBuffer(ctx, data, putOptions)

	return err
}

func (c *RemoteClient) Delete() error {
	ctx, ctxCancel := c.getContextWithTimeout()
	defer ctxCancel()
	_, err := c.blobClient.Delete(ctx, &blob.DeleteOptions{AccessConditions: c.leaseAccessCondition()})
	if err != nil {
		if !notFoundError(err) {
			return err
		}
	}
	return nil
}

func (c *RemoteClient) Lock(info *statemgr.LockInfo) (string, error) {
	stateName := fmt.Sprintf("%s/%s", c.containerName, c.keyName)
	info.Path = stateName

	if info.ID == "" {
		lockID, err := uuid.GenerateUUID()
		if err != nil {
			return "", err
		}

		info.ID = lockID
	}

	// TODO double-check this function
	getLockInfoErr := func(err error) error {
		lockInfo, infoErr := c.getLockInfo()
		if infoErr != nil {
			err = errors.Join(err, infoErr)
		}

		return &statemgr.LockError{
			Err:  err,
			Info: lockInfo,
		}
	}

	leaseOptions := &lease.BlobClientOptions{
		LeaseID: &info.ID,
	}
	ctx, ctxCancel := c.getContextWithTimeout()
	defer ctxCancel()

	// obtain properties to see if the blob lease is already in use. If the blob doesn't exist, create it
	properties, err := c.getBlobProperties()
	if err != nil {
		// error if we had issues getting the blob
		if !notFoundError(err) {
			return "", err
		}
		// if we don't find the blob, we need to build it
		_, err = c.blobClient.UploadBuffer(ctx, []byte{}, &blockblob.UploadBufferOptions{
			HTTPHeaders: httpHeaders(),
		})

		if err != nil {
			return "", getLockInfoErr(err)
		}
	}

	// if the blob is already locked then error
	// TODO double-check pointer stuff here
	if *properties.LeaseStatus == lease.StatusTypeLocked {
		return "", getLockInfoErr(fmt.Errorf("state blob is already locked"))
	}

	// TODO check error
	leaseClient, _ := lease.NewBlobClient(c.blobClient, leaseOptions)
	leaseResp, err := leaseClient.AcquireLease(ctx, -1, nil)

	if err != nil {
		return "", getLockInfoErr(err)
	}

	info.ID = *leaseResp.LeaseID
	c.setLeaseID(leaseResp.LeaseID)

	if err := c.writeLockInfo(info); err != nil {
		return "", err
	}

	return info.ID, nil
}

func (c *RemoteClient) getLockInfo() (*statemgr.LockInfo, error) {
	properties, err := c.getBlobProperties()
	if err != nil {
		return nil, err
	}

	raw := properties.Metadata[lockInfoMetaKey]
	if raw == nil || *raw == "" {
		return nil, fmt.Errorf("blob metadata %q was empty", lockInfoMetaKey)
	}

	data, err := base64.StdEncoding.DecodeString(*raw)
	if err != nil {
		return nil, err
	}

	lockInfo := &statemgr.LockInfo{}
	err = json.Unmarshal(data, lockInfo)
	if err != nil {
		return nil, err
	}

	return lockInfo, nil
}

// writes info to blob meta data, deletes metadata entry if info is nil
func (c *RemoteClient) writeLockInfo(info *statemgr.LockInfo) error {
	ctx, ctxCancel := c.getContextWithTimeout()
	defer ctxCancel()
	properties, err := c.getBlobProperties()
	if err != nil {
		return err
	}

	if info == nil {
		delete(properties.Metadata, lockInfoMetaKey)
	} else {
		value := base64.StdEncoding.EncodeToString(info.Marshal())
		properties.Metadata[lockInfoMetaKey] = &value
	}

	_, err = c.blobClient.SetMetadata(ctx, properties.Metadata, &blob.SetMetadataOptions{
		AccessConditions: c.leaseAccessCondition(),
	})

	return err
}

func (c *RemoteClient) Unlock(id string) error {
	lockErr := &statemgr.LockError{}

	lockInfo, err := c.getLockInfo()
	if err != nil {
		lockErr.Err = fmt.Errorf("failed to retrieve lock info: %w", err)
		return lockErr
	}
	lockErr.Info = lockInfo

	if lockInfo.ID != id {
		lockErr.Err = fmt.Errorf("lock id %q does not match existing lock", id)
		return lockErr
	}

	c.setLeaseID(&lockInfo.ID)
	if err := c.writeLockInfo(nil); err != nil {
		lockErr.Err = fmt.Errorf("failed to delete lock info from metadata: %w", err)
		return lockErr
	}

	ctx, ctxCancel := c.getContextWithTimeout()
	defer ctxCancel()
	leaseClient, _ := lease.NewBlobClient(c.blobClient, nil)
	// TODO check error more properly here
	_, err = leaseClient.ReleaseLease(ctx, nil)
	if err != nil {
		lockErr.Err = err
		return lockErr
	}

	c.leaseID = nil

	return nil
}

// getBlobProperties wraps the GetProperties method of the blobClient with timeout
func (c *RemoteClient) getBlobProperties() (blob.GetPropertiesResponse, error) {
	ctx, ctxCancel := c.getContextWithTimeout()
	defer ctxCancel()
	return c.blobClient.GetProperties(ctx, &blob.GetPropertiesOptions{AccessConditions: c.leaseAccessCondition()})
}

// getContextWithTimeout returns a context with timeout based on the timeoutSeconds
func (c *RemoteClient) getContextWithTimeout() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), c.timeout)
}

// setLeaseID takes a string leaseID and sets the leaseID field of the RemoteClient
// if passed leaseID is empty, it sets the leaseID field to nil
func (c *RemoteClient) setLeaseID(leaseID *string) {
	if leaseID == nil || *leaseID == "" {
		c.leaseID = nil
	} else {
		c.leaseID = leaseID
	}
}

func (c *RemoteClient) leaseAccessCondition() *blob.AccessConditions {
	return &blob.AccessConditions{
		LeaseAccessConditions: &blob.LeaseAccessConditions{
			LeaseID: c.leaseID,
		},
	}
}

func notFoundError(err error) bool {
	var respErr azcore.ResponseError
	return errors.As(err, &respErr) && respErr.StatusCode == 404
}

func httpHeaders() *blob.HTTPHeaders {
	contentType := "application/json"
	return &blob.HTTPHeaders{
		BlobContentType: &contentType,
	}
}
