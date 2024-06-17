use phase1::Phase1Parameters;
use serde_json::Value;
use snark_setup_operator::data_structs::{
    Attestation, ChunkDownloadInfo, ContributedData, ContributionUploadUrl, FilteredChunks,
    ParticipantId, SignedData, UniqueChunkId, UnlockBody, VerifiedData,
};
use snark_setup_operator::setup_filename;
use snark_setup_operator::utils::{
    collect_processor_data, create_parameters_for_chunk, download_file_direct_async,
    download_file_from_azure_async, get_authorization_value, get_content_length,
    participation_mode_from_str, read_hash_from_file, read_keys, remove_file_if_exists, sign_json,
    upload_file_direct_async, upload_file_to_azure_async, upload_mode_from_str,
    write_attestation_to_file, ParticipationMode, UploadMode, CHALLENGE_FILENAME,
    CHALLENGE_HASH_FILENAME, NEW_CHALLENGE_FILENAME, NEW_CHALLENGE_HASH_FILENAME,
    RESPONSE_FILENAME, RESPONSE_HASH_FILENAME,
};
use snark_setup_operator::{data_structs::Response, error::ContributeError};

use anyhow::Result;
use ark_bls12_377::Bls12_377;
use ark_bw6_761::BW6_761;
use ark_ec::pairing::Pairing;
use ark_mnt4_753::MNT4_753;
use ark_mnt6_753::MNT6_753;
use chrono::Duration;
use gumdrop::Options;
use indicatif::{ProgressBar, ProgressStyle};
use lazy_static::lazy_static;
use nimiq_keys::{KeyPair, PrivateKey};
use panic_control::{spawn_quiet, ThreadResultExt};
#[allow(unused_imports)]
use phase1_cli::*;
#[allow(unused_imports)]
use phase2_cli::*;
use rand::prelude::SliceRandom;
use reqwest::header::{AUTHORIZATION, CONTENT_LENGTH};
use secrecy::{ExposeSecret, SecretVec};
use setup_utils::converters::{batch_exp_mode_from_str, subgroup_check_mode_from_str};
use setup_utils::{
    derive_rng_from_seed, upgrade_correctness_check_config, BatchExpMode, SubgroupCheckMode,
    DEFAULT_CONTRIBUTE_CHECK_INPUT_CORRECTNESS, DEFAULT_VERIFY_CHECK_INPUT_CORRECTNESS,
    DEFAULT_VERIFY_CHECK_OUTPUT_CORRECTNESS,
};

use std::cmp::min;
use std::collections::{HashMap, HashSet};
use std::ops::{Deref, Neg};
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering::SeqCst};
use std::sync::RwLock;
use termcolor::{Color, ColorChoice, ColorSpec, StandardStream, WriteColor};
use tokio::time::Instant;
use tracing::{debug, error, info, warn};
use tracing_subscriber::EnvFilter;
use url::Url;

use snark_setup_operator::utils::{string_to_phase, Phase};

const DELAY_AFTER_ERROR_DURATION_SECS: i64 = 60;
const DELAY_WAIT_FOR_PIPELINE_SECS: i64 = 5;
const DELAY_POLL_CEREMONY_SECS: i64 = 5;
const DELAY_STATUS_UPDATE_FORCE_SECS: i64 = 300;
const DELAY_AFTER_ATTESTATION_ERROR_DURATION_SECS: i64 = 5;

lazy_static! {
    static ref PIPELINE: RwLock<HashMap<PipelineLane, Vec<UniqueChunkId>>> = {
        let mut map = HashMap::new();
        map.insert(PipelineLane::Download, Vec::new());
        map.insert(PipelineLane::Process, Vec::new());
        map.insert(PipelineLane::Upload, Vec::new());
        RwLock::new(map)
    };
    static ref SEED: RwLock<Option<SecretVec<u8>>> = RwLock::new(None);
    static ref EXITING: AtomicBool = AtomicBool::new(false);
    static ref SHOULD_UPDATE_STATUS: AtomicBool = AtomicBool::new(true);
    static ref EXIT_SIGNAL: AtomicU8 = AtomicU8::new(0);
    static ref SENT_SYSINFO: AtomicBool = AtomicBool::new(false);
}

#[derive(Debug, Options, Clone)]
pub struct ContributeOpts {
    pub help: bool,
    #[options(help = "phase to be run. Must be either phase1 or phase2")]
    pub phase: Option<String>,
    #[options(
        help = "the url of the coordinator API",
        default = "https://nimiq-setup-phase-2.azurefd.net"
    )]
    pub coordinator_url: String,
    #[options(
        help = "the encrypted keys for the Nimiq setup",
        default = "nimiq.keys"
    )]
    pub keys_file: String,
    #[options(
        help = "the attestation for the Nimiq setup",
        default = "nimiq.attestation.txt"
    )]
    pub attestation_path: String,
    #[options(
        help = "the log path of the Nimiq setup",
        default = "./snark-setup.log"
    )]
    pub log_path: String,
    #[options(
        help = "the storage upload mode",
        default = "auto",
        parse(try_from_str = "upload_mode_from_str")
    )]
    pub upload_mode: UploadMode,
    #[options(
        help = "participation mode",
        default = "contribute",
        parse(try_from_str = "participation_mode_from_str")
    )]
    pub participation_mode: ParticipationMode,
    #[options(help = "don't use pipelining")]
    pub disable_pipelining: bool,
    #[options(help = "maximum tasks in the download lane", default = "1")]
    pub max_in_download_lane: usize,
    #[options(help = "maximum tasks in the process lane", default = "1")]
    pub max_in_process_lane: usize,
    #[options(help = "maximum tasks in the upload lane", default = "1")]
    pub max_in_upload_lane: usize,
    #[options(
        help = "number of threads to leave free for other tasks",
        default = "0"
    )]
    pub free_threads: usize,
    #[options(
        help = "whether to always check whether incoming challenges are in correct subgroup and non-zero",
        default = "false"
    )]
    pub force_correctness_checks: bool,
    #[options(
        help = "which batch exponentiation version to use",
        default = "auto",
        parse(try_from_str = "batch_exp_mode_from_str")
    )]
    pub batch_exp_mode: BatchExpMode,
    #[options(
        help = "which subgroup check version to use",
        default = "auto",
        parse(try_from_str = "subgroup_check_mode_from_str")
    )]
    pub subgroup_check_mode: SubgroupCheckMode,
    #[options(help = "whether to skip ratio check", default = "false")]
    pub skip_ratio_check: bool,
    #[options(help = "whether to disable benchmarking data collection")]
    pub disable_sysinfo: bool,
    #[options(help = "do not try to keep the computer awake")]
    pub disable_keep_awake: bool,
    #[options(help = "exit when finished contributing for the first time")]
    pub exit_when_finished_contributing: bool,
    #[options(help = "read passphrase from stdin. THIS IS UNSAFE as it doesn't use pinentry!")]
    pub unsafe_passphrase: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum PipelineLane {
    Download,
    Process,
    Upload,
}

impl std::fmt::Display for PipelineLane {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[derive(Clone)]
pub struct Contribute {
    pub phase: Option<Phase>,
    pub server_url: Url,
    pub participant_id: ParticipantId,
    pub key_pair: KeyPair,
    pub upload_mode: UploadMode,
    pub participation_mode: ParticipationMode,
    pub max_in_download_lane: usize,
    pub max_in_process_lane: usize,
    pub max_in_upload_lane: usize,
    pub challenge_filename: String,
    pub challenge_hash_filename: String,
    pub response_filename: String,
    pub response_hash_filename: String,
    pub new_challenge_filename: String,
    pub new_challenge_hash_filename: String,
    pub disable_pipelining: bool,
    pub force_correctness_checks: bool,
    pub batch_exp_mode: BatchExpMode,
    pub subgroup_check_mode: SubgroupCheckMode,
    pub ratio_check: bool,
    pub disable_sysinfo: bool,
    pub exit_when_finished_contributing: bool,
    pub attestation: Attestation,

    task_index: Option<usize>,

    // This is the only mutable states we hold.
    pub chosen_unique_chunk_id: Option<UniqueChunkId>,
    pub lock_chunk: bool,
}

impl Contribute {
    pub fn new(opts: &ContributeOpts, key_pair: &[u8], attestation: &Attestation) -> Result<Self> {
        let key_pair = KeyPair::from(PrivateKey::from_bytes(key_pair)?);
        let phase = match &opts.phase {
            Some(phase) => Some(string_to_phase(phase)?),
            _ => None,
        };

        let contribute_params = Self {
            phase,
            server_url: Url::parse(&opts.coordinator_url)?,
            participant_id: key_pair.public.clone(),
            key_pair,
            upload_mode: opts.upload_mode,
            participation_mode: opts.participation_mode,
            max_in_download_lane: opts.max_in_download_lane,
            max_in_process_lane: opts.max_in_process_lane,
            max_in_upload_lane: opts.max_in_upload_lane,
            challenge_filename: "".to_string(),
            challenge_hash_filename: "".to_string(),
            response_filename: "".to_string(),
            response_hash_filename: "".to_string(),
            new_challenge_filename: "".to_string(),
            new_challenge_hash_filename: "".to_string(),
            disable_pipelining: opts.disable_pipelining,
            force_correctness_checks: opts.force_correctness_checks,
            batch_exp_mode: opts.batch_exp_mode,
            subgroup_check_mode: opts.subgroup_check_mode,
            ratio_check: !opts.skip_ratio_check,
            disable_sysinfo: opts.disable_sysinfo,
            exit_when_finished_contributing: opts.exit_when_finished_contributing,
            attestation: attestation.clone(),

            task_index: None,

            chosen_unique_chunk_id: None,
            lock_chunk: false,
        };
        Ok(contribute_params)
    }

    pub fn clone_with_index(&self, index: usize) -> Self {
        let mut cloned = self.clone();
        cloned.task_index = Some(index);

        cloned
    }

    async fn run_ceremony_initialization_and_get_max_locks(&self) -> Result<u64> {
        let ceremony = self.get_chunk_info().await?;
        self.release_locked_chunks(&ceremony).await?;

        Ok(ceremony.max_locks)
    }

    async fn wait_for_status_update_signal(&self) {
        loop {
            if SHOULD_UPDATE_STATUS.load(SeqCst) {
                SHOULD_UPDATE_STATUS.store(false, SeqCst);
                return;
            }
            tokio::time::sleep(
                Duration::seconds(DELAY_POLL_CEREMONY_SECS)
                    .to_std()
                    .expect("Should have converted duration to standard"),
            )
            .await;
        }
    }

    fn set_status_update_signal(&self) {
        SHOULD_UPDATE_STATUS.store(true, SeqCst);
    }

    async fn run_and_catch_errors(&self) -> Result<()> {
        let delay_after_error_duration =
            Duration::seconds(DELAY_AFTER_ERROR_DURATION_SECS).to_std()?;
        let delay_after_attestation_error_duration =
            Duration::seconds(DELAY_AFTER_ATTESTATION_ERROR_DURATION_SECS).to_std()?;
        let progress_bar = ProgressBar::new(0);
        let progress_style = ProgressStyle::default_bar()
            .template(
                "{spinner:.green} [{elapsed_precise}] [{bar:20.cyan/blue}] {pos}/{len} {wide_msg}",
            )
            .progress_chars("#>-");
        progress_bar.enable_steady_tick(1000);
        progress_bar.set_style(progress_style);
        progress_bar.println(
            "*** Contributing...\n*** If your keys are located in a USB drive, please unmount, otherwise you don't have to do anything.",
        );
        progress_bar.set_message("Getting initial data from the server...");
        let max_locks_from_ceremony;
        loop {
            let max_locks = self.run_ceremony_initialization_and_get_max_locks().await;
            match max_locks {
                Ok(max_locks) => {
                    max_locks_from_ceremony = max_locks;
                    break;
                }
                Err(e) => {
                    warn!("Got error from ceremony initialization: {}", e);
                    progress_bar.println(&format!("Got error from ceremony initialization: {}", e));
                    tokio::time::sleep(delay_after_error_duration).await;
                }
            }
        }
        if self.participation_mode == ParticipationMode::Contribute {
            loop {
                match self.add_attestation(&self.attestation).await {
                    Ok(_) => break,
                    Err(e) => {
                        warn!("Could not upload attestation, error was {}, retrying...", e);
                        progress_bar.println(&format!(
                            "Could not upload attestation, error was {}, retrying...",
                            e
                        ));
                        tokio::time::sleep(delay_after_attestation_error_duration).await;
                    }
                }
            }
        }
        let total_tasks = if self.disable_pipelining {
            1
        } else {
            std::cmp::min(
                self.max_in_download_lane + self.max_in_process_lane + self.max_in_upload_lane,
                max_locks_from_ceremony as usize,
            )
        };
        let mut futures = vec![];

        let updater = self.clone();
        let progress_bar_for_thread = progress_bar.clone();
        tokio::spawn(async move {
            loop {
                match updater
                    .status_updater(progress_bar_for_thread.clone())
                    .await
                {
                    Ok(true) => {
                        EXITING.store(true, SeqCst);
                        return;
                    }
                    Ok(false) => {}
                    Err(e) => {
                        warn!("Got error from updater: {}", e);
                        progress_bar_for_thread.println(&format!(
                            "Could not update status: {}",
                            e.to_string().trim()
                        ));
                    }
                }
                updater.wait_for_status_update_signal().await;
            }
        });
        // Force an update every 5 minutes.
        let cloned_for_update = self.clone();
        tokio::spawn(async move {
            loop {
                match cloned_for_update.get_chunk_info().await {
                    Err(err) => {
                        warn!("Cannot get locked chunks {}", err);
                    }
                    Ok(ceremony) => {
                        let mut found: Vec<UniqueChunkId> = vec![];
                        let v = match cloned_for_update.get_participant_locked_chunk_ids() {
                            Ok(lst) => lst,
                            Err(err) => {
                                warn!("Cannot get local chunks: {}", err);
                                vec![]
                            }
                        };
                        for chunk_id in &ceremony.locked_chunks {
                            if !v.iter().any(|x| chunk_id == x) {
                                found.push(chunk_id.clone());
                            }
                        }
                        for chunk_id in found {
                            warn!("Unlocking chunk that is not being processed {}\n", chunk_id);
                            let _ = cloned_for_update.unlock_chunk(&chunk_id, None).await;
                        }
                    }
                };
                SHOULD_UPDATE_STATUS.store(true, SeqCst);
                tokio::time::sleep(
                    Duration::seconds(DELAY_STATUS_UPDATE_FORCE_SECS)
                        .to_std()
                        .expect("Should have converted duration to standard"),
                )
                .await;
            }
        });
        for i in 0..total_tasks {
            let delay_duration = Duration::seconds(DELAY_AFTER_ERROR_DURATION_SECS).to_std()?;
            let mut cloned = self.clone_with_index(i);
            let progress_bar_for_thread = progress_bar.clone();
            let jh = tokio::spawn(async move {
                loop {
                    let result = cloned.run().await;
                    if EXITING.load(SeqCst) {
                        return;
                    }
                    match result {
                        Ok(_) => {}
                        Err(e) => {
                            warn!("Got error from run: {}, retrying...", e);
                            progress_bar_for_thread
                                .println(&format!("Got error from run: {}, retrying...", e));
                            if let Some(chunk_id) = cloned.chosen_unique_chunk_id.as_ref() {
                                if cloned
                                    .remove_chunk_id_from_lane_if_exists(
                                        &PipelineLane::Download,
                                        &chunk_id,
                                    )
                                    .expect("Should have removed chunk ID from lane")
                                {
                                    // ITODO
                                    if cloned.lock_chunk {
                                        let _ = cloned
                                            .unlock_chunk(&chunk_id, Some(e.to_string()))
                                            .await;
                                    }
                                }
                                if cloned
                                    .remove_chunk_id_from_lane_if_exists(
                                        &PipelineLane::Process,
                                        &chunk_id,
                                    )
                                    .expect("Should have removed chunk ID from lane")
                                {
                                    if cloned.lock_chunk {
                                        let _ = cloned
                                            .unlock_chunk(&chunk_id, Some(e.to_string()))
                                            .await;
                                    }
                                }
                                if cloned
                                    .remove_chunk_id_from_lane_if_exists(
                                        &PipelineLane::Upload,
                                        &chunk_id,
                                    )
                                    .expect("Should have removed chunk ID from lane")
                                {
                                    if cloned.lock_chunk {
                                        let _ = cloned
                                            .unlock_chunk(&chunk_id, Some(e.to_string()))
                                            .await;
                                    }
                                }
                                cloned.set_status_update_signal();
                            }
                        }
                    }
                    tokio::time::sleep(delay_duration).await;
                }
            });
            futures.push(jh);
        }

        futures::future::try_join_all(futures).await?;

        Ok(())
    }

    async fn wait_for_available_spot_in_lane(&self, lane: &PipelineLane) -> Result<()> {
        let max_in_lane = match *lane {
            PipelineLane::Download => self.max_in_download_lane,
            PipelineLane::Process => self.max_in_process_lane,
            PipelineLane::Upload => self.max_in_upload_lane,
        };
        loop {
            if EXITING.load(SeqCst) {
                return Err(ContributeError::GotExitSignalError.into());
            }
            {
                let pipeline = PIPELINE
                    .read()
                    .expect("Should have opened pipeline for reading");
                if pipeline
                    .get(lane)
                    .ok_or(ContributeError::LaneWasNullError(lane.to_string()))?
                    .len()
                    < max_in_lane
                {
                    return Ok(());
                }
            }
            tokio::time::sleep(Duration::seconds(DELAY_WAIT_FOR_PIPELINE_SECS).to_std()?).await;
        }
    }

    fn get_pipeline_snapshot(&self) -> Result<HashMap<PipelineLane, Vec<UniqueChunkId>>> {
        let pipeline = PIPELINE
            .read()
            .expect("Should have opened pipeline for reading");

        Ok(pipeline.clone())
    }

    async fn status_updater(&self, progress_bar: ProgressBar) -> Result<bool> {
        if EXIT_SIGNAL.load(SeqCst) > 0 {
            progress_bar.println("Exit detected, handling chunks in buffer. If there was a problem, please contact the coordinator for help. If you got notified by the coordinator, please destroy your keys. Press 10 times to force quit.");
            progress_bar.set_message("");
            progress_bar.set_length(0);
            progress_bar.finish();
            return Ok(true);
        }
        let chunk_info = self.get_chunk_info().await?;
        let num_chunks = chunk_info.num_chunks;
        progress_bar.set_length(num_chunks as u64);
        let num_non_contributed_chunks = min(chunk_info.num_non_contributed, num_chunks);

        let participant_locked_chunks = self.get_participant_locked_chunks_display()?;
        if participant_locked_chunks.len() > 0 {
            progress_bar.set_message(&format!(
                "{} {} {}...",
                match self.participation_mode {
                    ParticipationMode::Contribute => "Contributing to",
                    ParticipationMode::Verify => "Verifying",
                },
                if participant_locked_chunks.len() > 1 {
                    "chunks"
                } else {
                    "chunk"
                },
                participant_locked_chunks.join(", "),
            ));
            progress_bar.set_position((num_chunks - num_non_contributed_chunks) as u64);
        } else if num_non_contributed_chunks == 0 {
            info!("Don't turn this off yet, you are needed until the end of your round.");
            progress_bar.set_position(num_chunks as u64);
            if !self.exit_when_finished_contributing && !chunk_info.shutdown_signal {
                progress_bar.set_message(
                    "Don't turn this off yet, you are needed until the end of your round.",
                );
            } else if !matches!(self.participation_mode, ParticipationMode::Verify) {
                // We don't want the verifiers to be killed.
                progress_bar.set_message("\nSuccessfully contributed!");
                progress_bar.finish();

                let mut stdout = StandardStream::stdout(ColorChoice::Always);
                stdout.set_color(ColorSpec::new().set_fg(Some(Color::Red)))?;
                println!("**** IMPORTANT:");
                stdout.reset()?;
                println!("*** If your keys are located in a USB drive, please unmount and destroy it. Otherwise, make sure you destroy your keys.");
                println!("*** Please publish your nimiq.attestation file in https://github.com/nimiq/ceremony-attestations by creating a new issue!");
                println!("*** If you use precompiled binaries, be sure to mention you've verified the binary hashes posted on the release page match the downloaded files.\nThank you for participating!");

                return Ok(true);
            }
        } else {
            progress_bar.set_position((num_chunks - num_non_contributed_chunks) as u64);
            progress_bar.set_message(&format!("Waiting for an available chunk...",));
        }

        Ok(false)
    }

    fn choose_unique_chunk_id(&self, ceremony: &FilteredChunks) -> Result<UniqueChunkId> {
        let chunk_ids_from_pipeline: HashSet<UniqueChunkId> = {
            let mut chunk_ids = vec![];
            let pipeline = self.get_pipeline_snapshot()?;
            for lane in &[
                PipelineLane::Download,
                PipelineLane::Process,
                PipelineLane::Upload,
            ] {
                for chunk_id in pipeline
                    .get(lane)
                    .ok_or(ContributeError::LaneWasNullError(lane.to_string()))?
                {
                    chunk_ids.push(chunk_id.clone());
                }
            }
            chunk_ids.into_iter().collect()
        };
        let locked_chunk_ids_from_ceremony: HashSet<UniqueChunkId> = {
            ceremony
                .chunks
                .iter()
                .filter(|c| c.lock_holder == Some(self.participant_id.clone()))
                .map(|c| c.unique_chunk_id.clone())
                .collect()
        };
        for locked_chunk_id in locked_chunk_ids_from_ceremony {
            if !chunk_ids_from_pipeline.contains(&locked_chunk_id) {
                return Ok(locked_chunk_id);
            }
        }

        let incomplete_chunks = self.get_non_contributed_and_available_chunks(&ceremony)?;
        Ok(incomplete_chunks
            .choose(&mut rand::thread_rng())
            .ok_or(ContributeError::CouldNotChooseChunkError)?
            .clone())
    }

    fn add_chunk_id_to_download_lane(&self, unique_chunk_id: &UniqueChunkId) -> Result<bool> {
        let lane = &PipelineLane::Download;
        let max_in_lane = match *lane {
            PipelineLane::Download => self.max_in_download_lane,
            PipelineLane::Process => self.max_in_process_lane,
            PipelineLane::Upload => self.max_in_upload_lane,
        };
        let mut pipeline = PIPELINE
            .write()
            .expect("Should have opened pipeline for writing");

        let lane_list = pipeline
            .get_mut(lane)
            .ok_or(ContributeError::LaneWasNullError(lane.to_string()))?;
        if lane_list.contains(&unique_chunk_id) || lane_list.len() >= max_in_lane {
            return Ok(false);
        }
        lane_list.push(unique_chunk_id.clone());
        debug!(
            "Chunk ID {} added successfully to lane {}. Current pipeline is: {:?}",
            unique_chunk_id,
            lane,
            pipeline.deref()
        );
        Ok(true)
    }

    fn remove_chunk_id_from_lane_if_exists(
        &self,
        lane: &PipelineLane,
        unique_chunk_id: &UniqueChunkId,
    ) -> Result<bool> {
        let mut pipeline = PIPELINE
            .write()
            .expect("Should have opened pipeline for writing");

        let lane_list = pipeline
            .get_mut(lane)
            .ok_or(ContributeError::LaneWasNullError(lane.to_string()))?;
        if !lane_list.contains(&unique_chunk_id) {
            return Ok(false);
        }
        lane_list.retain(|c| c != unique_chunk_id);
        debug!(
            "Chunk ID {} removed successfully from lane {}. Current pipeline is: {:?}",
            unique_chunk_id,
            lane,
            pipeline.deref()
        );
        Ok(true)
    }

    async fn move_chunk_id_from_lane_to_lane(
        &self,
        from: &PipelineLane,
        to: &PipelineLane,
        unique_chunk_id: &UniqueChunkId,
    ) -> Result<bool> {
        let max_in_lane = match *to {
            PipelineLane::Download => self.max_in_download_lane,
            PipelineLane::Process => self.max_in_process_lane,
            PipelineLane::Upload => self.max_in_upload_lane,
        };
        {
            let mut pipeline = PIPELINE
                .write()
                .expect("Should have opened pipeline for writing");

            {
                let to_list = pipeline
                    .get_mut(to)
                    .ok_or(ContributeError::LaneWasNullError(to.to_string()))?;

                if to_list.len() >= max_in_lane {
                    return Ok(false);
                }
            }
            {
                let from_list = pipeline
                    .get_mut(from)
                    .ok_or(ContributeError::LaneWasNullError(from.to_string()))?;
                if !from_list.contains(&unique_chunk_id) {
                    return Err(ContributeError::LaneDidNotContainChunkWithIDError(
                        from.to_string(),
                        unique_chunk_id.to_string(),
                    )
                    .into());
                }
                from_list.retain(|c| c != unique_chunk_id);
            }

            {
                let to_list = pipeline
                    .get_mut(to)
                    .ok_or(ContributeError::LaneWasNullError(to.to_string()))?;

                if to_list.contains(&unique_chunk_id) {
                    return Err(ContributeError::LaneAlreadyContainsChunkWithIDError(
                        to.to_string(),
                        unique_chunk_id.to_string(),
                    )
                    .into());
                }
                to_list.push(unique_chunk_id.clone());
            }
            debug!(
                "Chunk ID {} moved successfully from lane {} to lane {}. Current pipeline is: {:?}",
                unique_chunk_id,
                from,
                to,
                pipeline.deref()
            );
            Ok(true)
        }
    }

    async fn wait_and_move_chunk_id_from_lane_to_lane(
        &self,
        from: &PipelineLane,
        to: &PipelineLane,
        unique_chunk_id: &UniqueChunkId,
    ) -> Result<()> {
        loop {
            if EXITING.load(SeqCst) {
                return Err(ContributeError::GotExitSignalError.into());
            }
            match self
                .move_chunk_id_from_lane_to_lane(from, to, unique_chunk_id)
                .await?
            {
                true => {
                    self.set_status_update_signal();
                    return Ok(());
                }
                false => {
                    tokio::time::sleep(Duration::seconds(DELAY_WAIT_FOR_PIPELINE_SECS).to_std()?)
                        .await;
                }
            }
        }
    }

    async fn contribute<P: Pairing>(
        &self,
        chunk: &ChunkDownloadInfo,
        phase: Phase,
        parameters: Phase1Parameters<P>,
    ) -> Result<(&String, Value)>
    where
        P::G1Affine: Neg<Output = P::G1Affine>,
    {
        let download_url = self.get_download_url_of_last_challenge(&chunk)?;
        match self.upload_mode {
            UploadMode::Auto => {
                if download_url.contains("blob.core.windows.net") {
                    download_file_from_azure_async(
                        &download_url,
                        get_content_length(&download_url).await?,
                        &self.challenge_filename,
                    )
                    .await?;
                } else {
                    download_file_direct_async(&download_url, &self.challenge_filename).await?;
                }
            }
            UploadMode::Azure => {
                download_file_from_azure_async(
                    &download_url,
                    get_content_length(&download_url).await?,
                    &self.challenge_filename,
                )
                .await?;
            }
            UploadMode::Direct => {
                download_file_direct_async(&download_url, &self.challenge_filename).await?;
            }
        }
        self.wait_and_move_chunk_id_from_lane_to_lane(
            &PipelineLane::Download,
            &PipelineLane::Process,
            &chunk.unique_chunk_id,
        )
        .await?;
        let seed = SEED.read().expect("Should have been able to read seed");
        let exposed_seed = seed
            .as_ref()
            .ok_or(ContributeError::SeedWasNoneError)
            .expect("Seed should not have been none")
            .expose_secret();
        let rng = derive_rng_from_seed(&exposed_seed[..]);
        let start = Instant::now();
        remove_file_if_exists(&self.response_filename)?;
        remove_file_if_exists(&self.response_hash_filename)?;
        let (
            challenge_filename,
            challenge_hash_filename,
            response_filename,
            response_hash_filename,
            force_correctness_checks,
            batch_exp_mode,
        ) = (
            self.challenge_filename.clone(),
            self.challenge_hash_filename.clone(),
            self.response_filename.clone(),
            self.response_hash_filename.clone(),
            self.force_correctness_checks.clone(),
            self.batch_exp_mode.clone(),
        );

        let h = if phase == Phase::Phase1 {
            spawn_quiet(move || {
                phase1_cli::contribute(
                    &challenge_filename,
                    &challenge_hash_filename,
                    &response_filename,
                    &response_hash_filename,
                    upgrade_correctness_check_config(
                        DEFAULT_CONTRIBUTE_CHECK_INPUT_CORRECTNESS,
                        force_correctness_checks,
                    ),
                    batch_exp_mode,
                    &parameters,
                    rng,
                );
            })
        } else {
            spawn_quiet(move || {
                phase2_cli::contribute::<P>(
                    &challenge_filename,
                    &challenge_hash_filename,
                    &response_filename,
                    &response_hash_filename,
                    upgrade_correctness_check_config(
                        DEFAULT_CONTRIBUTE_CHECK_INPUT_CORRECTNESS,
                        force_correctness_checks,
                    ),
                    batch_exp_mode,
                    rng,
                );
            })
        };

        let result = h.join();
        if !result.is_ok() {
            if let Some(panic_value) = result.panic_value_as_str() {
                error!("Contribute failed: {}", panic_value);
                return Err(
                    ContributeError::FailedRunningContributeError(panic_value.to_string()).into(),
                );
            } else {
                error!("Contribute failed: no panic value");
                return Err(ContributeError::FailedRunningContributeError(
                    "no panic value".to_string(),
                )
                .into());
            }
        }
        let duration = start.elapsed();
        let processor_data = if !self.disable_sysinfo && !SENT_SYSINFO.load(SeqCst) {
            let data = collect_processor_data()?;
            SENT_SYSINFO.store(true, SeqCst);
            Some(data)
        } else {
            None
        };
        let contributed_data = ContributedData {
            challenge_hash: read_hash_from_file(&self.challenge_hash_filename)?,
            response_hash: read_hash_from_file(&self.response_hash_filename)?,
            contribution_duration: Some(duration.as_millis() as u64),
            processor_data,
        };

        Ok((
            &self.response_filename,
            serde_json::to_value(contributed_data)?,
        ))
    }

    async fn verify<P: Pairing>(
        &self,
        chunk: &ChunkDownloadInfo,
        phase: Phase,
        parameters: Phase1Parameters<P>,
    ) -> Result<(&String, Value)>
    where
        P::G1Affine: Neg<Output = P::G1Affine>,
    {
        let challenge_download_url =
            self.get_download_url_of_last_challenge_for_verifying(&chunk)?;
        let response_download_url = self.get_download_url_of_last_response(&chunk)?;
        match self.upload_mode {
            UploadMode::Auto => {
                if challenge_download_url.contains("blob.core.windows.net") {
                    download_file_from_azure_async(
                        &challenge_download_url,
                        get_content_length(&challenge_download_url).await?,
                        &self.challenge_filename,
                    )
                    .await?;
                } else {
                    download_file_direct_async(&challenge_download_url, &self.challenge_filename)
                        .await?;
                }
                if response_download_url.contains("blob.core.windows.net") {
                    download_file_from_azure_async(
                        &response_download_url,
                        get_content_length(&response_download_url).await?,
                        &self.response_filename,
                    )
                    .await?;
                } else {
                    download_file_direct_async(&response_download_url, &self.response_filename)
                        .await?;
                }
            }
            UploadMode::Azure => {
                download_file_from_azure_async(
                    &challenge_download_url,
                    get_content_length(&challenge_download_url).await?,
                    &self.challenge_filename,
                )
                .await?;
                download_file_from_azure_async(
                    &response_download_url,
                    get_content_length(&response_download_url).await?,
                    &self.response_filename,
                )
                .await?;
            }
            UploadMode::Direct => {
                download_file_direct_async(&challenge_download_url, &self.challenge_filename)
                    .await?;
                download_file_direct_async(&response_download_url, &self.response_filename).await?;
            }
        }
        self.wait_and_move_chunk_id_from_lane_to_lane(
            &PipelineLane::Download,
            &PipelineLane::Process,
            &chunk.unique_chunk_id,
        )
        .await?;
        let start = Instant::now();
        remove_file_if_exists(&self.new_challenge_filename)?;
        remove_file_if_exists(&self.new_challenge_hash_filename)?;

        let (
            challenge_filename,
            challenge_hash_filename,
            response_filename,
            response_hash_filename,
            new_challenge_filename,
            new_challenge_hash_filename,
            force_correctness_checks,
            subgroup_check_mode,
            ratio_check,
        ) = (
            self.challenge_filename.clone(),
            self.challenge_hash_filename.clone(),
            self.response_filename.clone(),
            self.response_hash_filename.clone(),
            self.new_challenge_filename.clone(),
            self.new_challenge_hash_filename.clone(),
            self.force_correctness_checks.clone(),
            self.subgroup_check_mode.clone(),
            self.ratio_check.clone(),
        );
        let h = if phase == Phase::Phase1 {
            spawn_quiet(move || {
                phase1_cli::transform_pok_and_correctness(
                    &challenge_filename,
                    &challenge_hash_filename,
                    upgrade_correctness_check_config(
                        DEFAULT_VERIFY_CHECK_INPUT_CORRECTNESS,
                        force_correctness_checks,
                    ),
                    &response_filename,
                    &response_hash_filename,
                    upgrade_correctness_check_config(
                        DEFAULT_VERIFY_CHECK_OUTPUT_CORRECTNESS,
                        force_correctness_checks,
                    ),
                    &new_challenge_filename,
                    &new_challenge_hash_filename,
                    subgroup_check_mode,
                    ratio_check,
                    &parameters,
                );
            })
        } else {
            spawn_quiet(move || {
                phase2_cli::verify::<P>(
                    &challenge_filename,
                    &challenge_hash_filename,
                    upgrade_correctness_check_config(
                        DEFAULT_VERIFY_CHECK_INPUT_CORRECTNESS,
                        force_correctness_checks,
                    ),
                    &response_filename,
                    &response_hash_filename,
                    upgrade_correctness_check_config(
                        DEFAULT_VERIFY_CHECK_OUTPUT_CORRECTNESS,
                        force_correctness_checks,
                    ),
                    &new_challenge_filename,
                    &new_challenge_hash_filename,
                    subgroup_check_mode,
                    false,
                );
            })
        };
        let result = h.join();
        if !result.is_ok() {
            if let Some(panic_value) = result.panic_value_as_str() {
                error!("Verification failed: {}", panic_value);
                return Err(ContributeError::FailedRunningVerificationError(
                    panic_value.to_string(),
                )
                .into());
            } else {
                error!("Verification failed: no panic value");
                return Err(ContributeError::FailedRunningVerificationError(
                    "no panic value".to_string(),
                )
                .into());
            }
        }
        let duration = start.elapsed();
        let verified_data = VerifiedData {
            challenge_hash: read_hash_from_file(&self.challenge_hash_filename)?,
            response_hash: read_hash_from_file(&self.response_hash_filename)?,
            new_challenge_hash: read_hash_from_file(&self.new_challenge_hash_filename)?,
            verification_duration: Some(duration.as_millis() as u64),
        };

        Ok((
            &self.new_challenge_filename,
            serde_json::to_value(verified_data)?,
        ))
    }

    fn update_filenames(&mut self, setup_id: String) {
        let task_index = self
            .task_index
            .expect("Can only update filenames with task index");
        self.challenge_filename = format!(
            "task{}_{}",
            task_index,
            setup_filename!(CHALLENGE_FILENAME, setup_id)
        )
        .to_string();
        self.challenge_hash_filename = format!(
            "task{}_{}",
            task_index,
            setup_filename!(CHALLENGE_HASH_FILENAME, setup_id)
        )
        .to_string();
        self.response_filename = format!(
            "task{}_{}",
            task_index,
            setup_filename!(RESPONSE_FILENAME, setup_id)
        )
        .to_string();
        self.response_hash_filename = format!(
            "task{}_{}",
            task_index,
            setup_filename!(RESPONSE_HASH_FILENAME, setup_id)
        )
        .to_string();
        self.new_challenge_filename = format!(
            "task{}_{}",
            task_index,
            setup_filename!(NEW_CHALLENGE_FILENAME, setup_id)
        )
        .to_string();
        self.new_challenge_hash_filename = format!(
            "task{}_{}",
            task_index,
            setup_filename!(NEW_CHALLENGE_HASH_FILENAME, setup_id)
        )
        .to_string();
    }

    async fn run(&mut self) -> Result<()> {
        loop {
            self.lock_chunk = false;
            self.wait_for_available_spot_in_lane(&PipelineLane::Download)
                .await?;
            let chunk_info = self.get_chunk_info().await?;
            let phase = match &self.phase {
                Some(phase) => phase.clone(),
                _ => string_to_phase(&chunk_info.phase)?,
            };

            let num_non_contributed_chunks = chunk_info.num_non_contributed;

            let incomplete_chunks = self.get_non_contributed_and_available_chunks(&chunk_info)?;
            if incomplete_chunks.len() == 0 {
                if num_non_contributed_chunks == 0 {
                    for chunk_info in chunk_info.chunks.iter() {
                        remove_file_if_exists(setup_filename!(
                            CHALLENGE_FILENAME,
                            chunk_info.unique_chunk_id.setup_id
                        ))?;
                        remove_file_if_exists(setup_filename!(
                            CHALLENGE_HASH_FILENAME,
                            chunk_info.unique_chunk_id.setup_id
                        ))?;
                        remove_file_if_exists(setup_filename!(
                            RESPONSE_FILENAME,
                            chunk_info.unique_chunk_id.setup_id
                        ))?;
                        remove_file_if_exists(setup_filename!(
                            RESPONSE_HASH_FILENAME,
                            chunk_info.unique_chunk_id.setup_id
                        ))?;
                        remove_file_if_exists(setup_filename!(
                            NEW_CHALLENGE_FILENAME,
                            chunk_info.unique_chunk_id.setup_id
                        ))?;
                        remove_file_if_exists(setup_filename!(
                            NEW_CHALLENGE_HASH_FILENAME,
                            chunk_info.unique_chunk_id.setup_id
                        ))?;
                    }
                    return Ok(());
                } else {
                    tokio::time::sleep(Duration::seconds(DELAY_WAIT_FOR_PIPELINE_SECS).to_std()?)
                        .await;
                    continue;
                }
            }

            let unique_chunk_id = self.choose_unique_chunk_id(&chunk_info)?;
            self.update_filenames(unique_chunk_id.setup_id.clone());
            if !self.add_chunk_id_to_download_lane(&unique_chunk_id)? {
                continue;
            }
            self.chosen_unique_chunk_id = Some(unique_chunk_id.clone());
            self.lock_chunk(&unique_chunk_id).await?;
            self.lock_chunk = true;
            self.set_status_update_signal();

            // Get parameters.
            let parameters = chunk_info
                .chunks
                .iter()
                .find(|chunk| chunk.unique_chunk_id == unique_chunk_id)
                .map(|chunk| chunk.parameters.clone())
                .ok_or(ContributeError::CouldNotChooseChunkError)?;

            let (chunk_index, chunk) = self.get_chunk_download_info(&unique_chunk_id).await?;

            let (file_to_upload, contributed_or_verified_data) = match self.participation_mode {
                ParticipationMode::Contribute => {
                    remove_file_if_exists(&self.challenge_filename)?;
                    remove_file_if_exists(&self.challenge_hash_filename)?;
                    match parameters.curve_kind.as_str() {
                        "bw6" => {
                            let parameters =
                                create_parameters_for_chunk::<BW6_761>(&parameters, chunk_index)?;
                            self.contribute(&chunk, phase, parameters).await?
                        }
                        "bls12_377" => {
                            let parameters =
                                create_parameters_for_chunk::<Bls12_377>(&parameters, chunk_index)?;
                            self.contribute(&chunk, phase, parameters).await?
                        }
                        "mnt4_753" => {
                            let parameters =
                                create_parameters_for_chunk::<MNT4_753>(&parameters, chunk_index)?;
                            self.contribute(&chunk, phase, parameters).await?
                        }
                        "mnt6_753" => {
                            let parameters =
                                create_parameters_for_chunk::<MNT6_753>(&parameters, chunk_index)?;
                            self.contribute(&chunk, phase, parameters).await?
                        }
                        c => {
                            panic!("Unsupported curve: {}", c);
                        }
                    }
                }
                ParticipationMode::Verify => {
                    remove_file_if_exists(&self.challenge_filename)?;
                    remove_file_if_exists(&self.challenge_hash_filename)?;
                    remove_file_if_exists(&self.response_filename)?;
                    remove_file_if_exists(&self.response_hash_filename)?;
                    match parameters.curve_kind.as_str() {
                        "bw6" => {
                            let parameters =
                                create_parameters_for_chunk::<BW6_761>(&parameters, chunk_index)?;
                            self.verify(&chunk, phase, parameters).await?
                        }
                        "bls12_377" => {
                            let parameters =
                                create_parameters_for_chunk::<Bls12_377>(&parameters, chunk_index)?;
                            self.verify(&chunk, phase, parameters).await?
                        }
                        "mnt4_753" => {
                            let parameters =
                                create_parameters_for_chunk::<MNT4_753>(&parameters, chunk_index)?;
                            self.verify(&chunk, phase, parameters).await?
                        }
                        "mnt6_753" => {
                            let parameters =
                                create_parameters_for_chunk::<MNT6_753>(&parameters, chunk_index)?;
                            self.verify(&chunk, phase, parameters).await?
                        }
                        c => {
                            panic!("Unsupported curve: {}", c);
                        }
                    }
                }
            };

            self.wait_and_move_chunk_id_from_lane_to_lane(
                &PipelineLane::Process,
                &PipelineLane::Upload,
                &unique_chunk_id,
            )
            .await?;
            let upload_url = self.get_upload_url(&unique_chunk_id).await?;
            let authorization = get_authorization_value(
                &self.key_pair,
                "POST",
                &Url::parse(&upload_url)?.path().trim_start_matches("/"),
            )?;

            match self.upload_mode {
                UploadMode::Auto => {
                    if upload_url.contains("blob.core.windows.net") {
                        upload_file_to_azure_async(file_to_upload, &upload_url).await?
                    } else {
                        upload_file_direct_async(&authorization, file_to_upload, &upload_url)
                            .await?
                    }
                }
                UploadMode::Azure => {
                    upload_file_to_azure_async(file_to_upload, &upload_url).await?
                }
                UploadMode::Direct => {
                    upload_file_direct_async(&authorization, file_to_upload, &upload_url).await?
                }
            }
            let signed_data = SignedData {
                signature: sign_json(&self.key_pair, &contributed_or_verified_data)?,
                data: contributed_or_verified_data,
            };

            self.notify_contribution(&unique_chunk_id, serde_json::to_value(signed_data)?)
                .await?;

            self.remove_chunk_id_from_lane_if_exists(&PipelineLane::Upload, &unique_chunk_id)?;
            self.set_status_update_signal();
        }
    }

    fn get_participant_locked_chunks(&self) -> Result<Vec<(UniqueChunkId, PipelineLane)>> {
        let mut chunk_ids = vec![];
        let pipeline = self.get_pipeline_snapshot()?;
        for lane in &[
            PipelineLane::Download,
            PipelineLane::Process,
            PipelineLane::Upload,
        ] {
            for chunk_id in pipeline
                .get(lane)
                .ok_or(ContributeError::LaneWasNullError(lane.to_string()))?
            {
                chunk_ids.push((chunk_id.clone(), lane.clone()));
            }
        }
        Ok(chunk_ids)
    }

    fn get_participant_locked_chunks_display(&self) -> Result<Vec<String>> {
        Ok(self
            .get_participant_locked_chunks()?
            .iter()
            .map(|(chunk_id, lane)| format!("{} ({})", chunk_id, lane))
            .collect())
    }

    fn get_participant_locked_chunk_ids(&self) -> Result<Vec<UniqueChunkId>> {
        Ok(self
            .get_participant_locked_chunks()?
            .iter()
            .map(|(id, _)| id.clone())
            .collect())
    }

    async fn release_locked_chunks(&self, ceremony: &FilteredChunks) -> Result<()> {
        for chunk_id in &ceremony.locked_chunks {
            self.unlock_chunk(&chunk_id, None).await?;
        }
        Ok(())
    }

    fn get_non_contributed_and_available_chunks(
        &self,
        ceremony: &FilteredChunks,
    ) -> Result<Vec<UniqueChunkId>> {
        let mut non_contributed = vec![];

        for chunk in ceremony.chunks.iter() {
            if chunk.lock_holder.is_none() {
                non_contributed.push(chunk.unique_chunk_id.clone());
            }
        }

        Ok(non_contributed)
    }

    fn get_download_url_of_last_challenge(&self, chunk: &ChunkDownloadInfo) -> Result<String> {
        let url = chunk.last_challenge_url.clone().ok_or(
            ContributeError::VerifiedLocationWasNoneForChunkID(chunk.unique_chunk_id.to_string()),
        )?;
        Ok(url)
    }

    fn get_download_url_of_last_challenge_for_verifying(
        &self,
        chunk: &ChunkDownloadInfo,
    ) -> Result<String> {
        let url = chunk.previous_challenge_url.clone().ok_or(
            ContributeError::VerifiedLocationWasNoneForChunkID(chunk.unique_chunk_id.to_string()),
        )?;
        Ok(url)
    }

    fn get_download_url_of_last_response(&self, chunk: &ChunkDownloadInfo) -> Result<String> {
        let url = chunk.last_response_url.clone().ok_or(
            ContributeError::ContributedLocationWasNoneForChunkID(
                chunk.unique_chunk_id.to_string(),
            ),
        )?;
        Ok(url)
    }

    async fn get_chunk_download_info(
        &self,
        unique_chunk_id: &UniqueChunkId,
    ) -> Result<(usize, ChunkDownloadInfo)> {
        let get_path = format!("chunks/{}/info", unique_chunk_id);
        let get_chunk_url = self.server_url.join(&get_path)?;
        let client = reqwest::Client::new();
        let response = client
            .get(get_chunk_url.as_str())
            .header(CONTENT_LENGTH, 0)
            .send()
            .await?
            .error_for_status()?;
        let data = response.text().await?;
        let chunk: ChunkDownloadInfo =
            serde_json::from_str::<Response<ChunkDownloadInfo>>(&data)?.result;
        Ok((unique_chunk_id.chunk_id.parse::<usize>()?, chunk))
    }

    async fn get_chunk_info(&self) -> Result<FilteredChunks> {
        let get_path = match self.participation_mode {
            ParticipationMode::Contribute => format!("contributor/{}/chunks", self.participant_id),
            ParticipationMode::Verify => format!("verifier/{}/chunks", self.participant_id),
        };
        let ceremony_url = self.server_url.join(&get_path)?;
        let client = reqwest::Client::builder().gzip(true).build()?;
        let response = client
            .get(ceremony_url.as_str())
            .header(CONTENT_LENGTH, 0)
            .send()
            .await?
            .error_for_status()?;
        let data = response.text().await?;
        let ceremony = serde_json::from_str::<Response<FilteredChunks>>(&data)?.result;
        Ok(ceremony)
    }

    async fn lock_chunk(&self, unique_chunk_id: &UniqueChunkId) -> Result<()> {
        let lock_path = format!("chunks/{}/lock", unique_chunk_id);
        let lock_chunk_url = self.server_url.join(&lock_path)?;
        let client = reqwest::Client::new();
        let authorization = get_authorization_value(&self.key_pair, "POST", &lock_path)?;
        client
            .post(lock_chunk_url.as_str())
            .header(AUTHORIZATION, authorization)
            .header(CONTENT_LENGTH, 0)
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }

    async fn unlock_chunk(
        &self,
        unique_chunk_id: &UniqueChunkId,
        error: Option<String>,
    ) -> Result<()> {
        let unlock_path = format!("chunks/{}/unlock", unique_chunk_id);
        let unlock_chunk_url = self.server_url.join(&unlock_path)?;
        let client = reqwest::Client::new();
        let authorization = get_authorization_value(&self.key_pair, "POST", &unlock_path)?;
        client
            .post(unlock_chunk_url.as_str())
            .header(AUTHORIZATION, authorization)
            .json(&UnlockBody { error })
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }

    async fn get_upload_url(&self, unique_chunk_id: &UniqueChunkId) -> Result<String> {
        let upload_request_path = format!("chunks/{}/contribution", unique_chunk_id);
        let upload_request_url = self.server_url.join(&upload_request_path)?;
        let client = reqwest::Client::new();
        let authorization = get_authorization_value(&self.key_pair, "GET", &upload_request_path)?;
        let temp = client
            .get(upload_request_url.as_str())
            .header(AUTHORIZATION, authorization)
            .header(CONTENT_LENGTH, 0)
            .send()
            .await;
        if let Err(e) = temp.as_ref() {
            error!("Get upload url {:?}", e);
        }
        let response: Response<ContributionUploadUrl> = temp?.error_for_status()?.json().await?;

        Ok(response.result.write_url)
    }

    async fn notify_contribution(
        &self,
        unique_chunk_id: &UniqueChunkId,
        body: serde_json::Value,
    ) -> Result<()> {
        let notify_path = format!("chunks/{}/contribution", unique_chunk_id);
        let notify_url = self.server_url.join(&notify_path)?;
        let client = reqwest::Client::new();
        let authorization = get_authorization_value(&self.key_pair, "POST", &notify_path)?;
        let temp = client
            .post(notify_url.as_str())
            .header(AUTHORIZATION, authorization)
            .json(&body)
            .send()
            .await;
        if let Err(e) = temp.as_ref() {
            error!("Notify contribution {:?}", e);
            temp?.error_for_status()?;
        }

        Ok(())
    }

    async fn add_attestation(&self, attestation: &Attestation) -> Result<()> {
        let data = serde_json::to_value(&attestation)?;
        let signed_data = SignedData {
            signature: sign_json(&self.key_pair, &data)?,
            data,
        };
        let notify_path = format!("attest");
        let notify_url = self.server_url.join(&notify_path)?;
        let client = reqwest::Client::new();
        let authorization = get_authorization_value(&self.key_pair, "POST", &notify_path)?;
        client
            .post(notify_url.as_str())
            .header(AUTHORIZATION, authorization)
            .json(&signed_data)
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }
}

fn main() {
    ctrlc::set_handler(move || {
        println!("Got ctrl+c...");
        SHOULD_UPDATE_STATUS.store(true, SeqCst);
        EXIT_SIGNAL.fetch_add(1, SeqCst);
        if EXIT_SIGNAL.load(SeqCst) >= 10 {
            println!("Force quitting...");
            std::process::exit(0);
        }
    })
    .expect("Error setting Ctrl-C handler");

    let opts: ContributeOpts = ContributeOpts::parse_args_default_or_exit();
    if !opts.disable_keep_awake {
        let _ = keep_awake::inhibit("Nimiq setup contribute", "This will take a while");
    }

    let rt = if opts.free_threads > 0 {
        let max_threads = num_cpus::get();
        let threads = max_threads - opts.free_threads;
        rayon::ThreadPoolBuilder::new()
            .num_threads(threads)
            .build_global()
            .unwrap();
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .worker_threads(threads)
            .build()
            .unwrap()
    } else {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap()
    };
    rt.block_on(async {
        let log_path = std::path::Path::new(&opts.log_path);
        let appender = tracing_appender::rolling::never(
            log_path.parent().unwrap(),
            log_path.file_name().unwrap(),
        );
        let (non_blocking, _guard) = tracing_appender::non_blocking(appender);
        tracing_subscriber::fmt()
            .json()
            .with_env_filter(EnvFilter::from_default_env())
            .with_writer(non_blocking)
            .init();

        let (seed, key_pair, attestation) =
            read_keys(&opts.keys_file, opts.unsafe_passphrase, true)
                .expect("Should have loaded Nimiq setup keys");

        *SEED.write().expect("Should have been able to write seed") = Some(seed);

        write_attestation_to_file(&attestation, &opts.attestation_path)
            .expect("Should have written attestation to file");
        let contribute_struct = Contribute::new(&opts, key_pair.expose_secret(), &attestation)
            .expect("Should have been able to create a contribute.");

        match contribute_struct.run_and_catch_errors().await {
            Err(e) => panic!("Got error from contribute: {}", e.to_string()),
            _ => {}
        }
    });
}
