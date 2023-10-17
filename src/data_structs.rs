use std::fmt::{self, Display};

use anyhow::Result;
use nimiq_keys::{PublicKey, Signature};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::VerifyTranscriptError;

pub type ParticipantId = PublicKey;

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct SignedData {
    pub data: Value,
    pub signature: Signature,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ContributionMetadata {
    pub contributed_time: Option<chrono::DateTime<chrono::Utc>>,
    pub contributed_lock_holder_time: Option<chrono::DateTime<chrono::Utc>>,
    pub verified_time: Option<chrono::DateTime<chrono::Utc>>,
    pub verified_lock_holder_time: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Contribution {
    pub metadata: Option<ContributionMetadata>,

    pub contributor_id: Option<ParticipantId>,
    pub contributed_location: Option<String>,
    pub contributed_data: Option<SignedData>,
    pub verifier_id: Option<ParticipantId>,
    pub verified_location: Option<String>,
    pub verified: bool,
    pub verified_data: Option<SignedData>,
}

impl Contribution {
    pub fn verified_data(&self) -> Result<SignedVerifiedDataParsed> {
        let verified_data = self
            .verified_data
            .as_ref()
            .ok_or(VerifyTranscriptError::VerifiedDataIsNoneError)?;
        let verified_data_parsed = SignedVerifiedDataParsed {
            data: serde_json::from_value(verified_data.data.clone())?,
            signature: verified_data.signature.clone(),
        };

        Ok(verified_data_parsed)
    }

    pub fn contributed_data(&self) -> Result<SignedContributedDataParsed> {
        let contributed_data = self
            .contributed_data
            .as_ref()
            .ok_or(VerifyTranscriptError::ContributorDataIsNoneError)?;
        let contributed_data_parsed = SignedContributedDataParsed {
            data: serde_json::from_value(contributed_data.data.clone())?,
            signature: contributed_data.signature.clone(),
        };
        Ok(contributed_data_parsed)
    }

    pub fn contributor_id(&self) -> Result<ParticipantId> {
        let contributor_id = self
            .contributor_id
            .as_ref()
            .ok_or(VerifyTranscriptError::ContributorIDIsNoneError)?
            .to_owned();

        Ok(contributor_id)
    }

    pub fn verifier_id(&self) -> Result<ParticipantId> {
        let verifier_id = self
            .verifier_id
            .as_ref()
            .ok_or(VerifyTranscriptError::VerifierIDIsNoneError)?
            .to_owned();

        Ok(verifier_id)
    }

    pub fn contributed_location(&self) -> Result<&String> {
        let contributed_location = self
            .contributed_location
            .as_ref()
            .ok_or(VerifyTranscriptError::ContributedLocationIsNoneError)?;

        Ok(contributed_location)
    }

    pub fn verified_location(&self) -> Result<&String> {
        let verified_location = self
            .verified_location
            .as_ref()
            .ok_or(VerifyTranscriptError::VerifiedLocationIsNoneError)?;

        Ok(verified_location)
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ChunkMetadata {
    pub lock_holder_time: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Chunk {
    pub unique_chunk_id: UniqueChunkId,
    pub parameters: Parameters,
    pub lock_holder: Option<ParticipantId>,
    pub contributions: Vec<Contribution>,
    pub metadata: Option<ChunkMetadata>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Parameters {
    pub proving_system: String,
    pub curve_kind: String,
    pub chunk_size: usize,
    pub batch_size: usize,
    pub power: usize,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Setup {
    pub setup_id: String,
    pub chunks: Vec<Chunk>,
    pub parameters: Parameters,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Ceremony {
    pub round: u64,
    pub version: u64,
    pub max_locks: u64,
    pub shutdown_signal: bool,
    pub contributor_ids: Vec<ParticipantId>,
    pub verifier_ids: Vec<ParticipantId>,
    pub setups: Vec<Setup>,
    pub attestations: Option<Vec<Attestation>>,
    #[serde(default = "phase_default")]
    pub phase: String,
}

fn phase_default() -> String {
    "phase1".to_string()
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Hash)]
#[serde(rename_all = "camelCase")]
pub struct UniqueChunkId {
    pub setup_id: String,
    pub chunk_id: String,
}

impl Display for UniqueChunkId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}-{}", self.setup_id, self.chunk_id)
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ChunkInfo {
    pub parameters: Parameters,
    pub unique_chunk_id: UniqueChunkId,
    pub lock_holder: Option<ParticipantId>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ChunkDownloadInfo {
    pub unique_chunk_id: UniqueChunkId,
    pub lock_holder: Option<ParticipantId>,
    pub last_response_url: Option<String>,
    pub last_challenge_url: Option<String>,
    pub previous_challenge_url: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct FilteredChunks {
    pub chunks: Vec<ChunkInfo>,
    pub locked_chunks: Vec<UniqueChunkId>,
    pub num_non_contributed: usize,
    pub num_chunks: usize,
    pub max_locks: u64,
    pub shutdown_signal: bool,
    pub phase: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Response<T> {
    pub result: T,
    pub status: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ProcessorData {
    pub name: String,
    pub brand: String,
    pub frequency: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ContributedData {
    pub challenge_hash: String,
    pub response_hash: String,
    pub contribution_duration: Option<u64>,
    pub processor_data: Option<Vec<ProcessorData>>,
}

#[derive(Debug, Clone)]
pub struct SignedContributedDataParsed {
    pub data: ContributedData,
    pub signature: Signature,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct VerifiedData {
    pub challenge_hash: String,
    pub response_hash: String,
    pub new_challenge_hash: String,
    pub verification_duration: Option<u64>,
}
#[derive(Debug, Clone)]
pub struct SignedVerifiedDataParsed {
    pub data: VerifiedData,
    pub signature: Signature,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ContributionUploadUrl {
    pub unique_chunk_id: UniqueChunkId,
    pub participant_id: ParticipantId,
    pub write_url: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Attestation {
    pub id: String,
    pub signature: Signature,
    pub public_key: PublicKey,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct NimiqSetupKeys {
    pub encrypted_seed: String,
    pub encrypted_private_key: String,
    pub encrypted_extra_entropy: Option<String>,
    pub attestation: Attestation,
    pub public_key: PublicKey,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct UnlockBody {
    pub error: Option<String>,
}
