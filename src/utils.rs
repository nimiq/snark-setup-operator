pub const NIMIQ_SETUP_PERSONALIZATION: &[u8] = b"NIMIQSET";
pub const DEFAULT_MAX_RETRIES: usize = 5;
pub const ONE_MB: usize = 1024 * 1024;
pub const DEFAULT_CHUNK_SIZE: u64 = 1 * (ONE_MB as u64);
pub const DEFAULT_NUM_PARALLEL_CHUNKS: usize = 50;
pub const DEFAULT_CHUNK_TIMEOUT_IN_SECONDS: u64 = 300;
pub const BEACON_HASH_LENGTH: usize = 32;

use crate::blobstore::{upload_access_key, upload_sas};
use crate::data_structs::{
    Attestation, Ceremony, NimiqSetupKeys, Parameters, ParticipantId, ProcessorData, Response,
};
use crate::error::{UtilsError, VerifyTranscriptError};
use age::{
    armor::{ArmoredWriter, Format},
    EncryptError, Encryptor,
};
use anyhow::Result;
use ark_ec::pairing::Pairing;
use nimiq_keys::Signature;
use phase1::{ContributionMode, Phase1Parameters, ProvingSystem};
use reqwest::header::{AUTHORIZATION, CONTENT_LENGTH, CONTENT_TYPE, RANGE};
use secrecy::{ExposeSecret, SecretString, SecretVec};
use serde::Serialize;
use std::{
    fs::{copy, remove_file, File, OpenOptions},
    io::{Read, Write},
    path::Path,
};
use tracing::warn;

pub const PHASE2_INIT_FILENAME: &str = "phase2_init";
pub const COMBINED_FILENAME: &str = "combined";
pub const RESPONSE_FILENAME: &str = "response";
pub const RESPONSE_PREFIX_FOR_AGGREGATION: &str = "response";
pub const RESPONSE_LIST_FILENAME: &str = "response_list";
pub const COMBINED_HASH_FILENAME: &str = "combined.hash";
pub const COMBINED_VERIFIED_POK_AND_CORRECTNESS_FILENAME: &str =
    "combined_verified_pok_and_correctness";
pub const COMBINED_VERIFIED_POK_AND_CORRECTNESS_HASH_FILENAME: &str =
    "combined_verified_pok_and_correctness.hash";
pub const COMBINED_VERIFIED_POK_AND_CORRECTNESS_NEW_CHALLENGE_FILENAME: &str =
    "combined_new_verified_pok_and_correctness_new_challenge";
pub const COMBINED_VERIFIED_POK_AND_CORRECTNESS_NEW_CHALLENGE_HASH_FILENAME: &str =
    "combined_verified_pok_and_correctness_new_challenge.hash";
pub const NEW_CHALLENGE_FILENAME: &str = "new_challenge";
pub const NEW_CHALLENGE_HASH_FILENAME: &str = "new_challenge.hash";
pub const INITIAL_CHALLENGE_FILENAME: &str = "initial_challenge";
pub const INITIAL_CHALLENGE_HASH_FILENAME: &str = "initial_challenge.hash";
pub const COMBINED_NEW_CHALLENGE_FILENAME: &str = "combined_new_challenge";
pub const COMBINED_NEW_CHALLENGE_HASH_FILENAME: &str = "combined_new_challenge.hash";
pub const NEW_CHALLENGE_LIST_FILENAME: &str = "new_challenge_list";
pub const CHALLENGE_FILENAME: &str = "challenge";
pub const CHALLENGE_HASH_FILENAME: &str = "challenge.hash";
pub const RESPONSE_HASH_FILENAME: &str = "response.hash";
pub const NEW_CHALLENGE_PREFIX_FOR_NEXT_ROUND: &str = "new_challenge";
pub const VERIFYING_KEY: &str = "verifying_key.bin";
pub const PROVING_KEY: &str = "proving_key.bin";

#[macro_export]
macro_rules! setup_filename {
    ($file_name:expr, $setup_id:expr) => {
        &format!("setup{}_{}", $setup_id, $file_name)
    };
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Phase {
    Phase1,
    Phase2,
}

pub fn string_to_phase(str: &str) -> Result<Phase> {
    match str.to_lowercase().as_ref() {
        "phase1" => Ok(Phase::Phase1),
        "phase2" => Ok(Phase::Phase2),
        "" => Err(UtilsError::NoPhaseError.into()),
        x => Err(UtilsError::UnknownPhaseError(x.to_string()).into()),
    }
}

pub fn copy_file_if_exists(file_path: &str, dest_path: &str) -> Result<()> {
    if Path::new(file_path).exists() {
        copy(file_path, dest_path)?;
    }
    Ok(())
}

pub fn download_file(url: &str, file_path: &str) -> Result<()> {
    remove_file_if_exists(file_path)?;
    let mut resp = reqwest::blocking::get(url)?.error_for_status()?;
    let mut out = File::create(file_path)?;
    resp.copy_to(&mut out)?;
    Ok(())
}

pub async fn download_file_from_azure_async(
    url: &str,
    expected_length: u64,
    file_path: &str,
) -> Result<()> {
    remove_file_if_exists(file_path)?;
    let mut out = File::create(file_path)?;
    let num_chunks = (expected_length + DEFAULT_CHUNK_SIZE - 1) / DEFAULT_CHUNK_SIZE;
    let mut futures = vec![];
    for chunk_index in 0..num_chunks {
        let url = url.to_string();
        futures.push(tokio::spawn(FutureRetry::new(
            move || {
                let url = url.clone();
                async move {
                    let start = chunk_index * DEFAULT_CHUNK_SIZE;
                    let end = if chunk_index == num_chunks - 1 {
                        expected_length - 1
                    } else {
                        (chunk_index + 1) * DEFAULT_CHUNK_SIZE - 1
                    };
                    let client = reqwest::Client::new();
                    // PITODO: Make sure this works with Azure.
                    let mut resp = client
                        .get(&url)
                        .header(CONTENT_TYPE, "application/octet-stream")
                        .header(RANGE, format!("bytes={}-{}", start, end))
                        .header(CONTENT_LENGTH, 0)
                        .timeout(std::time::Duration::from_secs(
                            DEFAULT_CHUNK_TIMEOUT_IN_SECONDS,
                        ))
                        .send()
                        .await?
                        .error_for_status()?;
                    let mut bytes = Vec::with_capacity((end - start + 1) as usize);
                    while let Some(chunk) = resp.chunk().await? {
                        bytes.write_all(&chunk)?;
                    }

                    Ok::<Vec<u8>, anyhow::Error>(bytes)
                }
            },
            MaxRetriesHandler::new(DEFAULT_MAX_RETRIES),
        )));
    }
    let bytes_list = futures::future::try_join_all(futures)
        .await?
        .into_iter()
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| UtilsError::RetryFailedError(e.0.to_string()))?
        .into_iter()
        .map(|(v, _)| v);
    for bytes in bytes_list {
        out.write_all(&bytes)?;
    }
    out.sync_all()?;
    Ok(())
}

pub async fn download_file_direct_async(url: &str, file_path: &str) -> Result<()> {
    let url = url.to_string();
    let file_path = file_path.to_string();
    FutureRetry::new(
        || async {
            remove_file_if_exists(&file_path)?;
            let mut resp = reqwest::get(&url).await?.error_for_status()?;
            let mut out = File::create(&file_path)?;
            while let Some(chunk) = resp.chunk().await? {
                out.write_all(&chunk)?;
            }
            out.sync_all()?;
            Ok(())
        },
        MaxRetriesHandler::new(DEFAULT_MAX_RETRIES),
    )
    .await
    .map_err(|e| UtilsError::RetryFailedError(e.0.to_string()))?;
    Ok(())
}

pub async fn upload_file_to_azure_async(file_path: &String, url: &String) -> Result<()> {
    upload_sas(file_path, url).await?;
    Ok(())
}

pub async fn upload_file_to_azure_with_access_key_async(
    file_path: &String,
    access_key: &String,
    account: &String,
    container: &String,
    path: &String,
) -> Result<()> {
    upload_access_key(file_path, access_key, account, container, path).await?;
    Ok(())
}

pub async fn upload_file_direct_async(
    authorization: &str,
    file_path: &str,
    url: &str,
) -> Result<()> {
    let mut file = File::open(file_path)?;
    let mut contents = Vec::new();
    file.read_to_end(&mut contents)?;

    let client = reqwest::Client::new();
    client
        .post(url)
        .header(AUTHORIZATION, authorization)
        .header(CONTENT_TYPE, "application/octet-stream")
        .body(contents)
        .send()
        .await?
        .error_for_status()?;
    Ok(())
}

pub fn remove_file_if_exists(file_path: &str) -> Result<()> {
    if Path::new(file_path).exists() {
        remove_file(file_path)?;
    }
    Ok(())
}

pub async fn get_content_length(url: &str) -> Result<u64> {
    let client = reqwest::Client::new();
    let result = client.head(url).send().await?.error_for_status()?;
    Ok(result.headers()["content-length"]
        .to_str()?
        .parse::<u64>()?)
}

pub async fn get_ceremony(url: &str) -> Result<Ceremony> {
    let response = reqwest::get(url).await?.error_for_status()?;
    let data = response.text().await?;
    let ceremony: Ceremony = serde_json::from_str::<Response<Ceremony>>(&data)?.result;
    Ok(ceremony)
}

use crate::transcript_data_structs::Transcript;
use blake2::{Blake2s, Digest};
use futures_retry::{ErrorHandler, FutureRetry, RetryPolicy};
use nimiq_keys::KeyPair;
use rand::rngs::OsRng;
use rand::RngCore;

pub fn verify_signed_data<T: Serialize>(
    data: &T,
    signature: &Signature,
    id: &ParticipantId,
) -> Result<()> {
    let serialized_data = serde_json::to_string(data)?;

    if !id.verify(&signature, serialized_data.as_bytes()) {
        Err(VerifyTranscriptError::InvalidSignature)?;
    }

    Ok(())
}

pub fn read_hash_from_file(file_name: &str) -> Result<String> {
    let mut hash = vec![];
    File::open(file_name)
        .map_err(|e| {
            eprintln!("Filename {}", file_name);
            e
        })
        .expect("Should have opened hash file.")
        .read_to_end(&mut hash)
        .expect("Should have read hash file.");
    let hash_hex = hex::encode(&hash);
    Ok(hash_hex)
}

pub fn proving_system_from_str(proving_system_str: &str) -> Result<ProvingSystem> {
    let proving_system = match proving_system_str {
        "groth16" => ProvingSystem::Groth16,
        "marlin" => ProvingSystem::Marlin,
        _ => {
            return Err(VerifyTranscriptError::UnsupportedProvingSystemError(
                proving_system_str.to_string(),
            )
            .into());
        }
    };
    Ok(proving_system)
}

pub fn check_challenge_hashes_same(a: &str, b: &str) -> Result<()> {
    if a != b {
        return Err(VerifyTranscriptError::WrongChallengeHash(a.to_string(), b.to_string()).into());
    }

    Ok(())
}

pub fn check_response_hashes_same(a: &str, b: &str) -> Result<()> {
    if a != b {
        return Err(VerifyTranscriptError::WrongResponseHash(a.to_string(), b.to_string()).into());
    }

    Ok(())
}

pub fn check_new_challenge_hashes_same(a: &str, b: &str) -> Result<()> {
    if a != b {
        return Err(
            VerifyTranscriptError::WrongNewChallengeHash(a.to_string(), b.to_string()).into(),
        );
    }

    Ok(())
}

pub fn get_authorization_value(key_pair: &KeyPair, method: &str, path: &str) -> Result<String> {
    let public_key = key_pair.public.clone();
    let message = format!("{} /{}", method.to_lowercase(), path.to_lowercase());
    let signature: Signature = key_pair.sign(message.as_bytes());
    let authorization = format!("Nimiq {}:{}", public_key, signature.to_string());
    Ok(authorization)
}

pub fn create_parameters_for_chunk<E: Pairing>(
    ceremony_parameters: &Parameters,
    chunk_index: usize,
) -> Result<Phase1Parameters<E>> {
    let proving_system = proving_system_from_str(ceremony_parameters.proving_system.as_str())?;
    let parameters = Phase1Parameters::<E>::new_chunk(
        ContributionMode::Chunked,
        chunk_index,
        ceremony_parameters.chunk_size,
        proving_system,
        ceremony_parameters.power,
        ceremony_parameters.batch_size,
    );
    Ok(parameters)
}

pub fn create_full_parameters<E: Pairing>(
    ceremony_parameters: &Parameters,
) -> Result<Phase1Parameters<E>> {
    let proving_system = proving_system_from_str(ceremony_parameters.proving_system.as_str())?;
    let parameters = Phase1Parameters::<E>::new_full(
        proving_system,
        ceremony_parameters.power,
        ceremony_parameters.batch_size,
    );
    Ok(parameters)
}

pub fn sign_json(key_pair: &KeyPair, value: &serde_json::Value) -> Result<Signature> {
    let message = serde_json::to_string(value)?;
    let signature: Signature = key_pair.sign(message.as_bytes());
    Ok(signature)
}

#[derive(Debug, Clone, Copy)]
pub enum UploadMode {
    Auto,
    Azure,
    Direct,
}

pub fn upload_mode_from_str(upload_mode: &str) -> Result<UploadMode> {
    match upload_mode {
        "auto" => Ok(UploadMode::Auto),
        "azure" => Ok(UploadMode::Azure),
        "direct" => Ok(UploadMode::Direct),
        _ => Err(UtilsError::UnknownUploadModeError(upload_mode.to_string()).into()),
    }
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum ParticipationMode {
    Contribute,
    Verify,
}

pub fn participation_mode_from_str(participation_mode: &str) -> Result<ParticipationMode> {
    match participation_mode {
        "contribute" => Ok(ParticipationMode::Contribute),
        "verify" => Ok(ParticipationMode::Verify),
        _ => Err(UtilsError::UnknownParticipationModeError(participation_mode.to_string()).into()),
    }
}

fn decrypt(passphrase: &SecretString, encrypted: &str) -> Result<Vec<u8>> {
    let decoded = SecretVec::new(hex::decode(encrypted)?);
    let decryptor = age::Decryptor::new(decoded.expose_secret().as_slice())?;
    let mut output = vec![];
    if let age::Decryptor::Passphrase(decryptor) = decryptor {
        let mut reader = decryptor.decrypt(passphrase, None)?;
        reader.read_to_end(&mut output)?;
    } else {
        return Err(UtilsError::UnsupportedDecryptorError.into());
    }

    Ok(output)
}

pub fn encrypt(encryptor: Encryptor, secret: &[u8]) -> Result<String> {
    let mut encrypted_output = vec![];
    let mut writer = encryptor
        .wrap_output(ArmoredWriter::wrap_output(
            &mut encrypted_output,
            Format::Binary,
        )?)
        .map_err(|e| match e {
            EncryptError::Io(e) => e,
        })?;
    std::io::copy(&mut std::io::Cursor::new(secret), &mut writer)?;
    writer.finish()?;
    let encrypted_secret = hex::encode(&encrypted_output);
    Ok(encrypted_secret.to_string())
}

pub fn read_keys(
    keys_file: &str,
    should_use_stdin: bool,
    should_collect_extra_entropy: bool,
) -> Result<(SecretVec<u8>, SecretVec<u8>, Attestation)> {
    let mut contents = String::new();
    {
        std::fs::File::open(&keys_file)?.read_to_string(&mut contents)?;
    }
    let mut keys: NimiqSetupKeys = serde_json::from_str(&contents)?;
    let description = "Enter your Nimiq setup passphrase";
    let passphrase = if should_use_stdin {
        println!("{}:", description);
        SecretString::new(rpassword::read_password()?)
    } else {
        age::cli_common::read_secret(description, "Passphrase", None)
            .map_err(|_| UtilsError::CouldNotReadPassphraseError)?
    };
    let nimiq_seed_from_file = SecretVec::new(decrypt(&passphrase, &keys.encrypted_seed)?);
    let nimiq_key_pair_from_file =
        SecretVec::new(decrypt(&passphrase, &keys.encrypted_private_key)?);

    if should_collect_extra_entropy && keys.encrypted_extra_entropy.is_none() && !should_use_stdin {
        let description = "Enter some extra entropy (this should only be done at the first time you run the contribute binary!)";
        let entered_entropy = age::cli_common::read_secret(description, "Entropy", None)
            .map_err(|_| UtilsError::CouldNotReadEntropyError)?;
        let encryptor = age::Encryptor::with_user_passphrase(passphrase.clone());

        let mut rng = OsRng;
        let mut extra_entropy = vec![0u8; 64];
        rng.fill_bytes(&mut extra_entropy[..]);

        let extra_entropy = SecretVec::new(extra_entropy);
        let mut hasher = Blake2s::with_params(&[], &[], NIMIQ_SETUP_PERSONALIZATION);
        hasher.update(extra_entropy.expose_secret());
        hasher.update(entered_entropy.expose_secret());
        let combined_entropy = SecretVec::<u8>::new(hasher.finalize().as_slice().to_vec());
        let encrypted_extra_entropy = encrypt(encryptor, combined_entropy.expose_secret())?;
        keys.encrypted_extra_entropy = Some(encrypted_extra_entropy);
        let mut file = OpenOptions::new().write(true).open(&keys_file)?;
        file.write_all(&serde_json::to_vec(&keys)?)?;
        file.sync_all()?;
    }

    let nimiq_seed = match keys.encrypted_extra_entropy {
        None => nimiq_seed_from_file,
        Some(encrypted_entropy) => {
            let entropy = SecretVec::new(decrypt(&passphrase, &encrypted_entropy)?);
            let mut hasher = Blake2s::with_params(&[], &[], NIMIQ_SETUP_PERSONALIZATION);
            hasher.update(nimiq_seed_from_file.expose_secret());
            hasher.update(entropy.expose_secret());
            SecretVec::<u8>::new(hasher.finalize().as_slice().to_vec())
        }
    };

    Ok((nimiq_seed, nimiq_key_pair_from_file, keys.attestation))
}

pub fn collect_processor_data() -> Result<Vec<ProcessorData>> {
    cfg_if::cfg_if! {
        if #[cfg(not(target_arch = "aarch64"))] {
            use sysinfo::{ProcessorExt, System, SystemExt};
            let s = System::new();
            let processors = s
                .get_processors()
                .iter()
                .map(|p| ProcessorData {
                    name: p.get_name().to_string(),
                    brand: p.get_brand().to_string(),
                    frequency: p.get_frequency().to_string(),
                })
                .collect();
            Ok(processors)
        } else {
            Ok(vec![])
        }
    }
}

pub struct MaxRetriesHandler {
    max_attempts: usize,
}
impl MaxRetriesHandler {
    pub fn new(max_attempts: usize) -> Self {
        MaxRetriesHandler { max_attempts }
    }
}

impl ErrorHandler<anyhow::Error> for MaxRetriesHandler {
    type OutError = anyhow::Error;

    fn handle(&mut self, attempt: usize, e: anyhow::Error) -> RetryPolicy<Self::OutError> {
        warn!(
            "Failed: {}, retry {}/{}",
            e.to_string(),
            attempt,
            self.max_attempts,
        );
        if attempt >= self.max_attempts {
            RetryPolicy::ForwardError(e)
        } else {
            RetryPolicy::WaitRetry(
                chrono::Duration::seconds(5)
                    .to_std()
                    .expect("Should have converted to standard duration"),
            )
        }
    }
}

pub fn challenge_size<E: Pairing>(parameters: &Phase1Parameters<E>) -> u64 {
    parameters.accumulator_size as u64
}

pub fn response_size<E: Pairing>(parameters: &Phase1Parameters<E>) -> u64 {
    parameters.contribution_size as u64
}

pub fn load_transcript() -> Result<Transcript> {
    let filename = "transcript";
    if !std::path::Path::new(filename).exists() {
        let mut file = File::create(filename)?;
        file.write_all(
            serde_json::to_string_pretty(&Transcript {
                rounds: vec![],
                beacon_hash: None,
                final_hashes: None,
            })?
            .as_bytes(),
        )?;
        file.sync_all()?;
    }
    let mut file = File::open(filename)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    let transcript: Transcript = serde_json::from_str::<Transcript>(&contents)?;
    Ok(transcript)
}

pub fn save_transcript(transcript: &Transcript) -> Result<()> {
    let filename = "transcript";
    let mut file = File::create(filename)?;
    file.write_all(serde_json::to_string_pretty(transcript)?.as_bytes())?;
    file.sync_all()?;

    Ok(())
}

pub fn backup_transcript(transcript: &Transcript) -> Result<()> {
    let filename = format!(
        "transcript_{}",
        chrono::Utc::now()
            .timestamp_nanos_opt()
            .expect("Invalid time")
    );
    let mut file = File::create(filename)?;
    file.write_all(serde_json::to_string_pretty(transcript)?.as_bytes())?;
    file.sync_all()?;

    Ok(())
}

pub fn format_attestation(attestation_message: &str, public_key: &str, signature: &str) -> String {
    format!("{} {} {}", attestation_message, public_key, signature)
}

pub fn extract_signature_from_attestation(attestation: &str) -> Result<(String, String, String)> {
    let attestation = attestation.to_string();
    let attestation_parts = attestation.split(" ").collect::<Vec<_>>();
    if attestation_parts.len() < 3 {
        return Err(UtilsError::AttestationTooShort(attestation_parts.len()).into());
    }
    Ok((
        attestation_parts[0..=attestation_parts.len() - 3].join(" "),
        attestation_parts[attestation_parts.len() - 2].to_string(),
        attestation_parts[attestation_parts.len() - 1].to_string(),
    ))
}

pub fn write_attestation_to_file(attestation: &Attestation, path: &str) -> Result<()> {
    let mut file = File::create(path)?;
    file.write_all(
        format_attestation(
            &attestation.id,
            &attestation.public_key.to_hex(),
            &attestation.signature.to_hex(),
        )
        .as_bytes(),
    )?;
    file.sync_all()?;
    Ok(())
}

pub fn trim_newline(s: &mut String) {
    if s.ends_with('\n') {
        s.pop();
        if s.ends_with('\r') {
            s.pop();
        }
    }
}

pub fn compute_hash_from_file(fname: &str) -> Result<String> {
    let challenge_contents = std::fs::read(fname)?;
    Ok(hex::encode(setup_utils::calculate_hash(
        &challenge_contents,
    )))
}
