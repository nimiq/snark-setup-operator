// Based on: https://github.com/microsoft/avml/blob/main/src/blobstore.rs

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

use crate::{
    error::UtilsError,
    utils::{
        MaxRetriesHandler,
        DEFAULT_CHUNK_SIZE, //DEFAULT_CHUNK_TIMEOUT_IN_SECONDS,
        DEFAULT_MAX_RETRIES,
        DEFAULT_NUM_PARALLEL_CHUNKS,
    },
};
use anyhow::Result;
use azure_storage::prelude::*;
use azure_storage_blobs::{
    blob::{BlobBlockType, BlockList},
    container::PublicAccess,
    prelude::*,
};
use byteorder::{LittleEndian, WriteBytesExt};
use futures_retry::FutureRetry;
use std::cmp;
use std::convert::TryFrom;
use std::fs::File;
use std::io::prelude::*;
use url::Url;

/// Converts the block index into an block_id
fn to_id(count: u64) -> Result<Vec<u8>> {
    let mut bytes = vec![];
    bytes.write_u64::<LittleEndian>(count)?;
    Ok(bytes)
}

pub async fn upload_sas(file_path: &String, sas_url: &String) -> Result<()> {
    let blob_client = BlobClient::from_sas_url(&Url::parse(sas_url)?)?;

    upload_with_client(&blob_client, file_path).await
}

pub async fn upload_access_key(
    file_path: &String,
    access_key: &String,
    account: &String,
    container: &String,
    blob_name: &String,
) -> Result<()> {
    let storage_credentials = StorageCredentials::access_key(account, access_key);
    let container_client =
        BlobServiceClient::new(account, storage_credentials).container_client(container);

    if !container_client.exists().await? {
        container_client
            .create()
            .public_access(PublicAccess::Container)
            .await?;
    }

    upload_with_client(&container_client.blob_client(blob_name), file_path).await
}

pub async fn upload_with_client(blob_client: &BlobClient, file_path: &String) -> Result<()> {
    let block_size = DEFAULT_CHUNK_SIZE;

    let mut file = File::open(file_path)?;
    let size = u64::try_from(file.metadata()?.len())?;
    let mut sent = 0;
    let mut blocks = BlockList { blocks: Vec::new() };
    let mut futures = vec![];
    while sent < size {
        let send_size = cmp::min(block_size, size - sent);
        let block_id = to_id(sent as u64)?;
        let mut data = vec![0; send_size as usize];
        file.read_exact(&mut data)?;

        let client = blob_client.clone();
        let block_id_for_spawn = block_id.clone();
        let jh = tokio::spawn(FutureRetry::new(
            move || {
                let data = data.clone();
                let client = client.clone();
                let block_id_for_spawn = block_id_for_spawn.clone();
                async move {
                    client
                        .put_block(block_id_for_spawn, data)
                        // .with_timeout(DEFAULT_CHUNK_TIMEOUT_IN_SECONDS)
                        .await
                        .map_err(|e| e.into())
                }
            },
            MaxRetriesHandler::new(DEFAULT_MAX_RETRIES),
        ));
        futures.push(jh);

        blocks
            .blocks
            .push(BlobBlockType::Uncommitted(block_id.into()));
        sent += send_size;
        if futures.len() == DEFAULT_NUM_PARALLEL_CHUNKS {
            futures::future::try_join_all(futures)
                .await
                .map_err(|e| UtilsError::RetryFailedError(e.to_string()))?;
            futures = vec![];
        }
    }

    futures::future::try_join_all(futures)
        .await
        .map_err(|e| UtilsError::RetryFailedError(e.to_string()))?;

    blob_client.put_block_list(blocks).await?;

    Ok(())
}
