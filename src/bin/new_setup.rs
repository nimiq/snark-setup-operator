use anyhow::{anyhow, Result};
use ark_bls12_377::Bls12_377;
use ark_bw6_761::BW6_761;
use ark_ec::pairing::Pairing;
use ark_ff::FftField;
use ark_mnt4_753::MNT4_753;
use ark_mnt6_753::MNT6_753;
use gumdrop::Options;
use nimiq_keys::{KeyPair, PrivateKey, PublicKey};
use phase1::{ContributionMode, Phase1Parameters, ProvingSystem};
#[allow(unused_imports)]
use phase1_cli::*;
#[allow(unused_imports)]
use phase2_cli::*;
use reqwest::header::AUTHORIZATION;
use secrecy::ExposeSecret;
use snark_setup_operator::data_structs::{
    Ceremony, Chunk, ChunkMetadata, Contribution, ContributionMetadata, Parameters, Response,
    Setup, SignedData, UniqueChunkId, VerifiedData,
};
use snark_setup_operator::error::UtilsError;
use snark_setup_operator::setup_filename;
use snark_setup_operator::utils::{
    compute_hash_from_file, get_authorization_value, proving_system_from_str, read_hash_from_file,
    read_keys, remove_file_if_exists, string_to_phase, upload_file_to_azure_with_access_key_async,
    upload_mode_from_str, Phase, UploadMode, NEW_CHALLENGE_FILENAME, NEW_CHALLENGE_HASH_FILENAME,
    NEW_CHALLENGE_LIST_FILENAME, PHASE2_INIT_FILENAME,
};
use std::fs::File;
use std::io::Write;
use std::ops::Neg;
use std::path::Path;
use tracing::info;
use url::Url;

#[derive(Debug, Options, Clone)]
pub struct NewSetupOpts {
    help: bool,
    #[options(help = "the server url", required)]
    pub server_url: String,
    #[options(
        help = "the encrypted keys for the Nimiq setup",
        default = "nimiq.keys"
    )]
    pub keys_file: String,
    #[options(help = "log2 of chunk size", required)]
    pub chunk_size: usize,
    #[options(help = "powers", required)]
    pub powers: usize,
    #[options(help = "proving system", default = "groth16")]
    pub proving_system: String,
    #[options(help = "curve", default = "bw6")]
    pub curve: String,
    #[options(help = "read passphrase from stdin. THIS IS UNSAFE as it doesn't use pinentry!")]
    pub unsafe_passphrase: bool,

    #[options(
        help = "current ceremony version. This is to avoid unintentional creation of setups.",
        required
    )]
    pub version: u64,

    #[options(help = "the upload mode", required)]
    pub upload_mode: String,
    #[options(help = "storage account in azure mode")]
    pub storage_account: Option<String>,
    #[options(help = "container name in azure mode")]
    pub container: Option<String>,
    #[options(help = "access key in azure mode")]
    pub access_key: Option<String>,
    #[options(help = "output dir in direct mode")]
    pub output_dir: Option<String>,

    #[options(help = "file with prepared circuit. Only used for phase 2")]
    pub circuit_filename: Option<String>,
}

async fn upload_chunk<E: Pairing>(
    opts: &NewSetupOpts,
    phase: Phase,
    setup: &mut Setup,
    chunk_index: usize,
    deployer: PublicKey,
) -> Result<()> {
    let unique_chunk_id = UniqueChunkId {
        setup_id: setup.setup_id.to_string(),
        chunk_id: chunk_index.to_string(),
    };

    info!("Working on chunk {}", unique_chunk_id);
    let proving_system = proving_system_from_str(&opts.proving_system)?;

    let parameters = Phase1Parameters::<E>::new_chunk(
        ContributionMode::Chunked,
        chunk_index,
        setup.parameters.chunk_size,
        proving_system,
        setup.parameters.power,
        setup.parameters.chunk_size,
    );
    if phase == Phase::Phase1 {
        remove_file_if_exists(setup_filename!(NEW_CHALLENGE_FILENAME, setup.setup_id))?;
        remove_file_if_exists(setup_filename!(NEW_CHALLENGE_HASH_FILENAME, setup.setup_id))?;
        phase1_cli::new_challenge(
            setup_filename!(NEW_CHALLENGE_FILENAME, setup.setup_id),
            setup_filename!(NEW_CHALLENGE_HASH_FILENAME, setup.setup_id),
            &parameters,
        );
    }

    let phase2_new_challenge_fname = format!(
        "{}.{}",
        setup_filename!(NEW_CHALLENGE_FILENAME, setup.setup_id),
        unique_chunk_id.chunk_id
    );
    let challenge_filename = if phase == Phase::Phase1 {
        setup_filename!(NEW_CHALLENGE_FILENAME, setup.setup_id).to_string()
    } else {
        phase2_new_challenge_fname
    };
    let new_challenge_hash_from_file = if phase == Phase::Phase1 {
        read_hash_from_file(setup_filename!(NEW_CHALLENGE_HASH_FILENAME, setup.setup_id))?
    } else {
        compute_hash_from_file(&challenge_filename)?
    };

    let round = 0;
    let path = format!("{}.{}.0", round, unique_chunk_id);
    let upload_mode = upload_mode_from_str(&opts.upload_mode)?;
    let location = match upload_mode {
        UploadMode::Azure => {
            let access_key = opts
                .access_key
                .as_ref()
                .ok_or(UtilsError::MissingOptionErr)?;
            let storage_account = opts
                .storage_account
                .as_ref()
                .ok_or(UtilsError::MissingOptionErr)?;
            let container = opts
                .container
                .as_ref()
                .ok_or(UtilsError::MissingOptionErr)?;
            upload_file_to_azure_with_access_key_async(
                &challenge_filename.to_string(),
                &access_key,
                &storage_account,
                &container,
                &path,
            )
            .await?;
            format!(
                "https://{}.blob.core.windows.net/{}/{}",
                storage_account, container, path,
            )
        }
        UploadMode::Direct => {
            let output_path = Path::new(
                &opts
                    .output_dir
                    .as_ref()
                    .ok_or(UtilsError::MissingOptionErr)?,
            )
            .join(path);
            std::fs::copy(challenge_filename, output_path)?;
            format!(
                "{}/chunks/{}/{}/contribution/0",
                opts.server_url, round, unique_chunk_id
            )
        }
        UploadMode::Auto => {
            return Err(anyhow!(
                "Unsupported upload mode Auto in the creation of a new setup"
            ))
        }
    };

    setup.chunks.push(Chunk {
            parameters: setup.parameters.clone(),
            unique_chunk_id,
            lock_holder: None,
            metadata: Some(ChunkMetadata {
                lock_holder_time: None
            }),
            contributions: vec![
                Contribution {
                    metadata: Some(ContributionMetadata {
                        contributed_time: None,
                        contributed_lock_holder_time: None,
                        verified_time: None,
                        verified_lock_holder_time: None,
                    }),
                    contributor_id: None,
                    contributed_location: None,
                    verifier_id: Some(deployer.clone()),
                    verified: true,
                    verified_data: Some(SignedData {
                        data: serde_json::to_value(VerifiedData {
                            challenge_hash: "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000".to_string(),
                            response_hash: "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000".to_string(),
                            new_challenge_hash: new_challenge_hash_from_file,
                            verification_duration: None,
                        })?,
                        signature: Default::default(),
                    }),
                    contributed_data: None,
                    verified_location: Some(location),
                }
            ],
        });

    Ok(())
}

fn save_ceremony_to_file(ceremony: &Ceremony) -> Result<()> {
    let filename = format!(
        "ceremony_{}",
        chrono::Utc::now()
            .timestamp_nanos_opt()
            .expect("Invalid time")
    );
    info!("Saving ceremony to {} ", filename);
    let mut file = File::create(filename)?;
    file.write_all(serde_json::to_string_pretty(&ceremony)?.as_bytes())?;
    file.sync_all()?;

    Ok(())
}

async fn run<E: Pairing>(opts: &NewSetupOpts, key_pair: &[u8]) -> Result<()>
where
    E::G1Affine: Neg<Output = E::G1Affine>,
{
    if opts.powers > E::ScalarField::TWO_ADICITY as usize {
        return Err(anyhow!(
            "Cannot create radix-2 domain for number of powers (maximum powers {}).",
            E::ScalarField::TWO_ADICITY
        ));
    }

    let server_url = Url::parse(opts.server_url.as_str())?.join("ceremony")?;
    let data = reqwest::get(server_url.as_str())
        .await?
        .error_for_status()?
        .text()
        .await?;
    let mut ceremony: Ceremony = serde_json::from_str::<Response<Ceremony>>(&data)?.result;
    let phase = string_to_phase(&ceremony.phase)?;
    let key_pair = KeyPair::from(PrivateKey::from_bytes(key_pair)?);
    let public_key = key_pair.public.clone();
    // We can only create setups in the beginning.
    if ceremony.version != opts.version || !ceremony.verifier_ids.contains(&public_key) {
        return Err(anyhow!("Can only create a setup at version {} and the verifiers list must contain the public key matching the private key", ceremony.version));
    }

    let proving_system = proving_system_from_str(&opts.proving_system)?;
    let chunk_size = 1 << opts.chunk_size;
    let parameters = Phase1Parameters::<E>::new_chunk(
        ContributionMode::Chunked,
        0,
        chunk_size,
        proving_system,
        opts.powers,
        chunk_size,
    );
    let mut setup = Setup {
        setup_id: ceremony.setups.len().to_string(),
        chunks: vec![],
        parameters: Parameters {
            proving_system: opts.proving_system.clone(),
            curve_kind: opts.curve.clone(),
            chunk_size,
            batch_size: chunk_size,
            power: opts.powers,
        },
    };
    // phase 1 new_challenge creates one chunk per call, phase 2 new_challenge creates all chunks
    // and returns how many have been created
    let num_chunks = if phase == Phase::Phase1 {
        match proving_system {
            ProvingSystem::Groth16 => (parameters.powers_g1_length + chunk_size - 1) / chunk_size,
            ProvingSystem::Marlin => (parameters.powers_length + chunk_size - 1) / chunk_size,
        }
    } else {
        phase2_cli::new_challenge::<E>(
            setup_filename!(NEW_CHALLENGE_FILENAME, setup.setup_id),
            setup_filename!(NEW_CHALLENGE_HASH_FILENAME, setup.setup_id),
            setup_filename!(NEW_CHALLENGE_LIST_FILENAME, setup.setup_id),
            chunk_size,
            setup_filename!(PHASE2_INIT_FILENAME, setup.setup_id),
            opts.powers,
            &opts
                .circuit_filename
                .as_ref()
                .expect("circuit filename not found when running phase2"),
        )
    };

    for chunk_index in 0..num_chunks {
        upload_chunk::<E>(opts, phase.clone(), &mut setup, chunk_index, public_key).await?;
    }

    ceremony.setups.push(setup);
    save_ceremony_to_file(&ceremony)?;
    info!("Updating ceremony");
    let client = reqwest::Client::new();
    let authorization = get_authorization_value(&key_pair, "PUT", "ceremony")?;
    client
        .put(server_url.as_str())
        .header(AUTHORIZATION, authorization)
        .json(&ceremony)
        .send()
        .await?
        .error_for_status()?;
    info!("Done!");

    Ok(())
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt().json().init();
    let opts: NewSetupOpts = NewSetupOpts::parse_args_default_or_exit();
    let (_, key_pair, _) = read_keys(&opts.keys_file, opts.unsafe_passphrase, false)
        .expect("Should have loaded Nimiq setup keys");
    match opts.curve.as_str() {
        "bw6" => {
            run::<BW6_761>(&opts, key_pair.expose_secret())
                .await
                .expect("Should have run the new setup generation");
        }
        "bls12_377" => {
            run::<Bls12_377>(&opts, key_pair.expose_secret())
                .await
                .expect("Should have run the new setup generation");
        }
        "mnt4_753" => {
            run::<MNT4_753>(&opts, key_pair.expose_secret())
                .await
                .expect("Should have run the new setup generation");
        }
        "mnt6_753" => {
            run::<MNT6_753>(&opts, key_pair.expose_secret())
                .await
                .expect("Should have run the new setup generation");
        }
        c => panic!("Unsupported curve {}", c),
    }
}
