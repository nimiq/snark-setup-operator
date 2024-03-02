use ark_mnt4_753::MNT4_753;
use ark_mnt6_753::MNT6_753;
use snark_setup_operator::setup_filename;
use snark_setup_operator::{data_structs::Ceremony, error::ControlError};

use anyhow::Result;
use ark_bls12_377::Bls12_377;
use ark_bw6_761::BW6_761;
use ark_ec::pairing::Pairing;
use gumdrop::Options;
use nimiq_keys::{KeyPair, PrivateKey};
#[allow(unused_imports)]
use phase1_cli::*;
#[allow(unused_imports)]
use phase2_cli::*;
use reqwest::header::AUTHORIZATION;
use secrecy::ExposeSecret;
use setup_utils::{
    derive_rng_from_seed, from_slice, BatchExpMode, SubgroupCheckMode,
    DEFAULT_VERIFY_CHECK_INPUT_CORRECTNESS, DEFAULT_VERIFY_CHECK_OUTPUT_CORRECTNESS,
};
use snark_setup_operator::data_structs::{
    Chunk, ChunkMetadata, Contribution, ContributionMetadata, ParticipantId, Setup,
};
use snark_setup_operator::error::{NewRoundError, VerifyTranscriptError};
use snark_setup_operator::utils::{
    backup_transcript, create_full_parameters, create_parameters_for_chunk,
    download_file_direct_async, download_file_from_azure_async, get_authorization_value,
    get_ceremony, get_content_length, load_transcript, read_hash_from_file, read_keys,
    remove_file_if_exists, save_transcript, string_to_phase, Phase, BEACON_HASH_LENGTH,
    COMBINED_FILENAME, COMBINED_HASH_FILENAME, COMBINED_NEW_CHALLENGE_FILENAME,
    COMBINED_NEW_CHALLENGE_HASH_FILENAME, COMBINED_VERIFIED_POK_AND_CORRECTNESS_FILENAME,
    COMBINED_VERIFIED_POK_AND_CORRECTNESS_HASH_FILENAME,
    COMBINED_VERIFIED_POK_AND_CORRECTNESS_NEW_CHALLENGE_FILENAME,
    COMBINED_VERIFIED_POK_AND_CORRECTNESS_NEW_CHALLENGE_HASH_FILENAME, INITIAL_CHALLENGE_FILENAME,
    INITIAL_CHALLENGE_HASH_FILENAME, NEW_CHALLENGE_FILENAME, NEW_CHALLENGE_HASH_FILENAME,
    NEW_CHALLENGE_LIST_FILENAME, PHASE2_INIT_FILENAME, RESPONSE_FILENAME, RESPONSE_LIST_FILENAME,
    RESPONSE_PREFIX_FOR_AGGREGATION,
};
use std::ops::Neg;
use std::{
    collections::HashSet,
    fs::{copy, File},
    io::Write,
    process,
};
use tracing::info;
use url::Url;

#[derive(Debug, Options, Clone)]
pub struct AddParticipantOpts {
    help: bool,
    #[options(help = "participant ID", required)]
    pub participant_id: ParticipantId,
}

#[derive(Debug, Options, Clone)]
pub struct RemoveParticipantOpts {
    help: bool,
    #[options(help = "participant ID", required)]
    pub participant_id: ParticipantId,
}

#[derive(Debug, Options, Clone)]
pub struct SignalShutdownOpts {
    help: bool,
    #[options(help = "the signal")]
    pub shutdown_signal: bool,
}

#[derive(Debug, Options, Clone)]
pub struct UnlockParticipantOpts {
    help: bool,
    #[options(help = "participant ID")]
    pub participant_id: Option<ParticipantId>,
    #[options(help = "all participants")]
    pub all: bool,
}

#[derive(Debug, Options, Clone)]
pub struct NewRoundOpts {
    help: bool,
    #[options(help = "expected participants")]
    pub expected_participant: Vec<ParticipantId>,
    #[options(help = "new participants")]
    pub new_participant: Vec<ParticipantId>,
    #[options(help = "verify transcript")]
    pub verify_transcript: bool,
    #[options(help = "send shutdown signal")]
    pub do_not_send_shutdown_signal: bool,
    #[options(help = "delay time for shutdown signal", default = "1800")]
    pub shutdown_delay_time_in_secs: u64,
    #[options(help = "publish")]
    pub publish: bool,
}

#[derive(Debug, Options, Clone)]
pub struct ApplyBeaconOpts {
    help: bool,
    #[options(help = "beacon value", required)]
    pub beacon_hash: String,
    #[options(help = "expected participants")]
    pub expected_participant: Vec<ParticipantId>,
}

#[derive(Debug, Options, Clone)]
pub struct RemoveLastContributionOpts {
    help: bool,
    #[options(help = "expected participant ID")]
    pub participant_id: ParticipantId,
    #[options(help = "setup index")]
    pub setup_index: usize,
    #[options(help = "chunk index")]
    pub chunk_index: usize,
}

#[derive(Debug, Options, Clone)]
pub struct GetLastContributionPkOpts {
    help: bool,
    #[options(help = "setup index")]
    pub setup_index: usize,
    #[options(help = "chunk index")]
    pub chunk_index: usize,
}

#[derive(Debug, Options, Clone)]
pub struct ControlOpts {
    help: bool,
    #[options(
        help = "phase to be run. Must be either phase1 or phase2. Defaults to server choice"
    )]
    pub phase: Option<String>,
    #[options(
        help = "the url of the coordinator API",
        default = "http://localhost:8080"
    )]
    pub coordinator_url: String,
    #[options(
        help = "the encrypted keys for the Nimiq setup",
        default = "nimiq.keys"
    )]
    pub keys_file: String,
    #[options(help = "read passphrase from stdin. THIS IS UNSAFE as it doesn't use pinentry!")]
    pub unsafe_passphrase: bool,
    #[options(command, required)]
    pub command: Option<Command>,

    #[options(help = "files with prepared circuit (in order of setups). Only used for phase 2")]
    pub circuit_filenames: Vec<String>,
    #[options(help = "initial query filename. Used only for phase2")]
    pub initial_query_filename: Option<String>,
    #[options(help = "initial full filename. Used only for phase2")]
    pub initial_full_filename: Option<String>,
}

pub struct Phase2Params {
    pub chunk_size: usize,
    pub phase2_init_filename: String,
    pub circuit_filename: String,
    pub initial_query_filename: String,
    pub initial_full_filename: String,
}

pub struct Phase2Opts {
    pub setups: Vec<Phase2Params>,
}

impl Phase2Opts {
    pub async fn new(opts: &ControlOpts) -> Result<Self> {
        let server_url = Url::parse(&opts.coordinator_url)?.join("ceremony")?;
        let ceremony = get_ceremony(&server_url.as_str()).await?;

        if ceremony.setups.len() != opts.circuit_filenames.len() {
            panic!("circuit_filenames must be used and same length as setups when running phase2");
        }

        let mut setups = vec![];
        for (i, setup) in ceremony.setups.iter().enumerate() {
            setups.push(Phase2Params {
                chunk_size: setup.parameters.chunk_size,
                phase2_init_filename: setup_filename!(PHASE2_INIT_FILENAME, setup.setup_id)
                    .to_string(),
                circuit_filename: opts.circuit_filenames[i].to_string(),
                initial_query_filename: setup_filename!(
                    opts.initial_query_filename
                        .as_ref()
                        .expect("initial_query_filename needed when running phase2"),
                    setup.setup_id
                )
                .to_string(),
                initial_full_filename: setup_filename!(
                    opts.initial_full_filename
                        .as_ref()
                        .expect("initial_full_filename needed when running phase2"),
                    setup.setup_id
                )
                .to_string(),
            });
        }
        Ok(Self { setups })
    }
}

// The supported commands
#[derive(Debug, Options, Clone)]
pub enum Command {
    #[options(help = "adds a participant")]
    AddParticipant(AddParticipantOpts),
    RemoveParticipant(RemoveParticipantOpts),
    AddVerifier(AddParticipantOpts),
    RemoveVerifier(RemoveParticipantOpts),
    UnlockParticipantChunks(UnlockParticipantOpts),
    SignalShutdown(SignalShutdownOpts),
    NewRound(NewRoundOpts),
    ApplyBeacon(ApplyBeaconOpts),
    RemoveLastContribution(RemoveLastContributionOpts),
    GetLastContributionPk(GetLastContributionPkOpts),
}

pub struct Control {
    pub phase: Phase,
    pub server_url: Url,
    pub private_key: KeyPair,
    pub phase2_opts: Option<Phase2Opts>,
}

impl Control {
    pub async fn new(opts: &ControlOpts, private_key: &[u8]) -> Result<Self> {
        let server_url = Url::parse(&opts.coordinator_url)?.join("ceremony")?;
        let ceremony = get_ceremony(&server_url.as_str()).await?;
        let phase = match &opts.phase {
            Some(phase) => string_to_phase(&phase)?,
            _ => string_to_phase(&ceremony.phase)?,
        };
        let phase2_opts = match (&phase, opts.command.as_ref().expect("No command found")) {
            (Phase::Phase2, Command::NewRound(round_opts)) => {
                if round_opts.verify_transcript {
                    Some(Phase2Opts::new(opts).await?)
                } else {
                    None
                }
            }
            (Phase::Phase2, Command::ApplyBeacon(_round_opts)) => {
                Some(Phase2Opts::new(opts).await?)
            }
            (_, _) => None,
        };

        let private_key = KeyPair::from(PrivateKey::from_bytes(private_key)?);
        let control = Self {
            phase,
            server_url,
            private_key,
            phase2_opts,
        };
        Ok(control)
    }

    async fn add_participant(&self, participant_id: ParticipantId) -> Result<()> {
        let mut ceremony = self.get_ceremony().await?;
        if ceremony.contributor_ids.contains(&participant_id) {
            return Err(ControlError::ParticipantAlreadyExistsError(
                participant_id.clone(),
                ceremony.contributor_ids.clone(),
            )
            .into());
        }
        ceremony.contributor_ids.push(participant_id.clone());
        info!("participants after adding: {:?}", ceremony.contributor_ids);
        self.put_ceremony(&ceremony).await?;
        Ok(())
    }

    async fn add_verifier(&self, participant_id: ParticipantId) -> Result<()> {
        let mut ceremony = self.get_ceremony().await?;
        if ceremony.verifier_ids.contains(&participant_id) {
            return Err(ControlError::ParticipantAlreadyExistsError(
                participant_id.clone(),
                ceremony.verifier_ids.clone(),
            )
            .into());
        }
        ceremony.verifier_ids.push(participant_id.clone());
        info!("verifiers after adding: {:?}", ceremony.verifier_ids);
        self.put_ceremony(&ceremony).await?;
        Ok(())
    }

    async fn get_ceremony(&self) -> Result<Ceremony> {
        get_ceremony(&self.server_url.as_str()).await
    }

    fn backup_ceremony(&self, ceremony: &Ceremony) -> Result<()> {
        let filename = format!(
            "ceremony_{}",
            chrono::Utc::now()
                .timestamp_nanos_opt()
                .expect("Invalid time")
        );
        let mut file = File::create(filename)?;
        file.write_all(serde_json::to_string_pretty(ceremony)?.as_bytes())?;
        file.sync_all()?;

        Ok(())
    }

    async fn put_ceremony(&self, ceremony: &Ceremony) -> Result<()> {
        self.backup_ceremony(ceremony)?;
        let client = reqwest::Client::new();
        let authorization = get_authorization_value(&self.private_key, "PUT", "ceremony")?;
        client
            .put(self.server_url.as_str())
            .header(AUTHORIZATION, authorization)
            .json(ceremony)
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }

    async fn remove_participant(&self, participant_id: ParticipantId) -> Result<()> {
        let mut ceremony = self.get_ceremony().await?;
        self.backup_ceremony(&ceremony)?;
        if !ceremony.contributor_ids.contains(&participant_id) {
            return Err(ControlError::ParticipantDoesNotExistError(
                participant_id.clone(),
                ceremony.contributor_ids.clone(),
            )
            .into());
        }
        ceremony.contributor_ids.retain(|x| *x != participant_id);
        for setup in ceremony.setups.iter_mut() {
            for chunk in setup.chunks.iter_mut() {
                // If the participant is currently holding the lock, release it and continue.
                if chunk.lock_holder == Some(participant_id) {
                    info!(
                        "chunk {} is locked by the participant, releasing it",
                        chunk.unique_chunk_id
                    );
                    chunk.lock_holder = None;
                    continue;
                }
                // Otherwise, check if they contributed in the past and clean it up.
                let mut contribution_index = None;
                for (index, contribution) in chunk.contributions.iter().enumerate() {
                    // The first contribution is always the result of initialization, so no need to process it.
                    if index == 0 {
                        continue;
                    }
                    if contribution.contributor_id()? == participant_id {
                        contribution_index = Some(index);
                        break;
                    }
                }
                if let Some(contribution_index) = contribution_index {
                    info!("chunk {} has a contribution from the participant at index {}, deleting it and its descendants", chunk.unique_chunk_id, contribution_index);
                    chunk.lock_holder = None;
                    chunk.contributions.drain(contribution_index..);
                }
            }
        }
        self.put_ceremony(&ceremony).await?;
        Ok(())
    }

    async fn remove_verifier(&self, participant_id: ParticipantId) -> Result<()> {
        let mut ceremony = self.get_ceremony().await?;
        self.backup_ceremony(&ceremony)?;
        if !ceremony.verifier_ids.contains(&participant_id) {
            return Err(ControlError::ParticipantDoesNotExistError(
                participant_id.clone(),
                ceremony.verifier_ids.clone(),
            )
            .into());
        }
        ceremony.verifier_ids.retain(|x| *x != participant_id);
        for setup in ceremony.setups.iter_mut() {
            for chunk in setup.chunks.iter_mut() {
                // If the verifier is currently holding the lock, release it and continue.
                if chunk.lock_holder == Some(participant_id) {
                    info!(
                        "chunk {} is locked by the participant, releasing it",
                        chunk.unique_chunk_id
                    );
                    chunk.lock_holder = None;
                    continue;
                }
            }
        }
        self.put_ceremony(&ceremony).await?;
        Ok(())
    }

    /// If no participant ID is given, we unlock all.
    async fn unlock_participant(&self, participant_id: Option<ParticipantId>) -> Result<()> {
        let mut ceremony = self.get_ceremony().await?;
        let chunk_ids = ceremony
            .setups
            .iter_mut()
            .flat_map(|setup| {
                setup
                    .chunks
                    .iter_mut()
                    .filter_map(|c| {
                        if participant_id.is_none() || c.lock_holder == participant_id {
                            c.lock_holder = None;
                            Some(c.unique_chunk_id.clone())
                        } else {
                            None
                        }
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        info!("chunk IDs unlocked: {:?}", chunk_ids);
        self.put_ceremony(&ceremony).await?;
        Ok(())
    }

    async fn combine_and_verify_round<E: Pairing>(
        &self,
        ceremony: &Ceremony,
        setup: &Setup,
        setup_index: usize,
    ) -> Result<()>
    where
        E::G1Affine: Neg<Output = E::G1Affine>,
    {
        let mut response_list_file =
            File::create(setup_filename!(RESPONSE_LIST_FILENAME, setup.setup_id))?;
        info!("Verifying round {}", ceremony.round);

        for (unique_chunk_id, contribution) in setup.chunks.iter().map(|chunk| {
            (
                chunk.unique_chunk_id.clone(),
                chunk.contributions.iter().last().unwrap(),
            )
        }) {
            remove_file_if_exists(setup_filename!(RESPONSE_FILENAME, setup.setup_id))?;
            let contributed_location = contribution.contributed_location()?;
            info!("Downloading chunk {}", unique_chunk_id);
            if contributed_location.contains("blob.core.windows.net") {
                download_file_from_azure_async(
                    &contributed_location,
                    get_content_length(&contributed_location).await?,
                    setup_filename!(RESPONSE_FILENAME, setup.setup_id),
                )
                .await?;
            } else {
                download_file_direct_async(
                    &contributed_location,
                    setup_filename!(RESPONSE_FILENAME, setup.setup_id),
                )
                .await?;
            };
            info!("Downloaded chunk {}", unique_chunk_id);
            let response_filename = format!(
                "{}_{}",
                setup_filename!(RESPONSE_PREFIX_FOR_AGGREGATION, setup.setup_id),
                unique_chunk_id
            );
            copy(
                setup_filename!(RESPONSE_FILENAME, setup.setup_id),
                &response_filename,
            )?;
            response_list_file.write(format!("{}\n", response_filename).as_bytes())?;
        }

        drop(response_list_file);
        remove_file_if_exists(setup_filename!(COMBINED_FILENAME, setup.setup_id))?;
        let parameters = create_parameters_for_chunk::<E>(&setup.parameters, 0)?;
        info!("Combining");
        if self.phase == Phase::Phase1 {
            phase1_cli::combine(
                setup_filename!(RESPONSE_LIST_FILENAME, setup.setup_id),
                setup_filename!(COMBINED_FILENAME, setup.setup_id),
                &parameters,
            );
        } else {
            let phase2_opts = self
                .phase2_opts
                .as_ref()
                .expect("Phase 2 opts not found when running phase 2");
            phase2_cli::combine::<E>(
                &phase2_opts.setups[setup_index].initial_query_filename,
                &phase2_opts.setups[setup_index].initial_full_filename,
                setup_filename!(RESPONSE_LIST_FILENAME, setup.setup_id),
                setup_filename!(COMBINED_FILENAME, setup.setup_id),
                false,
            );
        }
        info!("Finished combining");
        let parameters = create_full_parameters::<E>(&setup.parameters)?;
        remove_file_if_exists(setup_filename!(COMBINED_HASH_FILENAME, setup.setup_id))?;
        info!("Verifying round {}", ceremony.round);
        if self.phase == Phase::Phase1 {
            phase1_cli::transform_ratios(
                setup_filename!(COMBINED_FILENAME, setup.setup_id),
                DEFAULT_VERIFY_CHECK_INPUT_CORRECTNESS,
                &parameters,
            );
        } else {
            let phase2_opts = self
                .phase2_opts
                .as_ref()
                .expect("phase 2 options not found running phase 2");
            remove_file_if_exists(setup_filename!(NEW_CHALLENGE_LIST_FILENAME, setup.setup_id))?;
            remove_file_if_exists(setup_filename!(
                setup_filename!(INITIAL_CHALLENGE_FILENAME, setup.setup_id),
                setup.setup_id
            ))?;
            remove_file_if_exists(setup_filename!(
                INITIAL_CHALLENGE_HASH_FILENAME,
                setup.setup_id
            ))?;
            remove_file_if_exists(setup_filename!(
                COMBINED_NEW_CHALLENGE_FILENAME,
                setup.setup_id
            ))?;
            remove_file_if_exists(setup_filename!(
                COMBINED_NEW_CHALLENGE_HASH_FILENAME,
                setup.setup_id
            ))?;
            phase2_cli::new_challenge::<E>(
                setup_filename!(NEW_CHALLENGE_FILENAME, setup.setup_id),
                setup_filename!(NEW_CHALLENGE_HASH_FILENAME, setup.setup_id),
                setup_filename!(NEW_CHALLENGE_LIST_FILENAME, setup.setup_id),
                phase2_opts.setups[setup_index].chunk_size,
                &phase2_opts.setups[setup_index].phase2_init_filename,
                &phase2_opts.setups[setup_index].circuit_filename,
            );
            phase2_cli::combine::<E>(
                phase2_opts.setups[setup_index]
                    .initial_query_filename
                    .as_ref(),
                phase2_opts.setups[setup_index]
                    .initial_full_filename
                    .as_ref(),
                setup_filename!(NEW_CHALLENGE_LIST_FILENAME, setup.setup_id),
                setup_filename!(INITIAL_CHALLENGE_FILENAME, setup.setup_id),
                true,
            );
            phase2_cli::verify::<E>(
                setup_filename!(INITIAL_CHALLENGE_FILENAME, setup.setup_id),
                setup_filename!(INITIAL_CHALLENGE_HASH_FILENAME, setup.setup_id),
                DEFAULT_VERIFY_CHECK_INPUT_CORRECTNESS,
                setup_filename!(COMBINED_FILENAME, setup.setup_id),
                setup_filename!(COMBINED_HASH_FILENAME, setup.setup_id),
                DEFAULT_VERIFY_CHECK_OUTPUT_CORRECTNESS,
                setup_filename!(COMBINED_NEW_CHALLENGE_FILENAME, setup.setup_id),
                setup_filename!(COMBINED_NEW_CHALLENGE_HASH_FILENAME, setup.setup_id),
                SubgroupCheckMode::Auto,
                true,
            );
        }

        info!("Verified round {}", ceremony.round);

        Ok(())
    }

    async fn new_round(
        &self,
        expected_participants: &[ParticipantId],
        new_participants: &[ParticipantId],
        verify_transcript: bool,
        send_shutdown_signal: bool,
        shutdown_delay_time_in_secs: u64,
        publish: bool,
    ) -> Result<()> {
        info!("Backing up transcript");
        let mut transcript = load_transcript()?;
        backup_transcript(&transcript)?;

        let mut ceremony = self.get_ceremony().await?;
        if let Some(round) = transcript.rounds.iter().last() {
            if round.round == ceremony.round {
                return Err(NewRoundError::RoundSameError(round.round).into());
            }
        }
        let expected_participants_set: HashSet<_> = expected_participants.iter().cloned().collect();
        let current_participants_set: HashSet<_> =
            ceremony.contributor_ids.iter().cloned().collect();
        if current_participants_set != expected_participants_set {
            return Err(NewRoundError::DifferentExpectedParticipantsError(
                current_participants_set,
                expected_participants_set,
            )
            .into());
        }
        info!("Backing up ceremony");
        self.backup_ceremony(&ceremony)?;
        transcript.rounds.push(ceremony.clone());
        if verify_transcript {
            info!("Verifying transcript");
            for (setup_index, setup) in ceremony.setups.iter().enumerate() {
                match setup.parameters.curve_kind.as_str() {
                    "bw6" => {
                        self.combine_and_verify_round::<BW6_761>(&ceremony, setup, setup_index)
                            .await?
                    }
                    "bls12_377" => {
                        self.combine_and_verify_round::<Bls12_377>(&ceremony, setup, setup_index)
                            .await?
                    }
                    "mnt4_753" => {
                        self.combine_and_verify_round::<MNT4_753>(&ceremony, setup, setup_index)
                            .await?
                    }
                    "mnt6_753" => {
                        self.combine_and_verify_round::<MNT6_753>(&ceremony, setup, setup_index)
                            .await?
                    }
                    _ => {
                        return Err(VerifyTranscriptError::UnsupportedCurveKindError(
                            setup.parameters.curve_kind.clone(),
                        )
                        .into())
                    }
                }
            }
            info!("Verified transcript");
        }
        for setup in ceremony.setups.iter_mut() {
            for i in 0..setup.chunks.len() {
                let c = &setup.chunks[i];
                let last_contribution = c.contributions.iter().last().unwrap();
                setup.chunks[i] = Chunk {
                    unique_chunk_id: c.unique_chunk_id.clone(),
                    parameters: c.parameters.clone(),
                    lock_holder: None,
                    metadata: Some(ChunkMetadata {
                        lock_holder_time: None,
                    }),
                    contributions: vec![Contribution {
                        metadata: Some(ContributionMetadata {
                            contributed_time: None,
                            contributed_lock_holder_time: None,
                            verified_time: None,
                            verified_lock_holder_time: None,
                        }),
                        verified: true,
                        verifier_id: last_contribution.verifier_id.clone(),
                        verified_location: last_contribution.verified_location.clone(),
                        verified_data: last_contribution.verified_data.clone(),
                        contributor_id: None,
                        contributed_location: None,
                        contributed_data: None,
                    }],
                }
            }
        }

        ceremony.round += 1;
        ceremony.contributor_ids = new_participants.to_vec();

        if publish {
            info!("Publishing new round");
            if send_shutdown_signal {
                self.signal_shutdown(true).await?;
                ceremony.version += 1;
            }
            save_transcript(&transcript)?;
            if send_shutdown_signal {
                // Sleep for some time to allow contributors to shut down.
                tokio::time::sleep(tokio::time::Duration::from_secs(
                    shutdown_delay_time_in_secs,
                ))
                .await;
                self.signal_shutdown(false).await?;
                ceremony.version += 1;
            }
            self.put_ceremony(&ceremony).await?;
        }
        Ok(())
    }

    async fn apply_beacon_to_setup<E: Pairing>(
        &self,
        ceremony: &Ceremony,
        setup: &Setup,
        setup_index: usize,
        beacon_hash: &[u8],
    ) -> Result<()>
    where
        E::G1Affine: Neg<Output = E::G1Affine>,
    {
        self.combine_and_verify_round::<E>(&ceremony, setup, setup_index)
            .await?;

        let parameters = create_full_parameters::<E>(&setup.parameters)?;
        remove_file_if_exists(setup_filename!(COMBINED_HASH_FILENAME, setup.setup_id))?;
        remove_file_if_exists(setup_filename!(
            COMBINED_VERIFIED_POK_AND_CORRECTNESS_FILENAME,
            setup.setup_id
        ))?;
        remove_file_if_exists(setup_filename!(
            COMBINED_VERIFIED_POK_AND_CORRECTNESS_HASH_FILENAME,
            setup.setup_id
        ))?;
        let rng = derive_rng_from_seed(&from_slice(&beacon_hash));
        if self.phase == Phase::Phase1 {
            phase1_cli::contribute(
                setup_filename!(COMBINED_FILENAME, setup.setup_id),
                setup_filename!(COMBINED_HASH_FILENAME, setup.setup_id),
                setup_filename!(
                    COMBINED_VERIFIED_POK_AND_CORRECTNESS_FILENAME,
                    setup.setup_id
                ),
                setup_filename!(
                    COMBINED_VERIFIED_POK_AND_CORRECTNESS_HASH_FILENAME,
                    setup.setup_id
                ),
                DEFAULT_VERIFY_CHECK_INPUT_CORRECTNESS,
                BatchExpMode::Auto,
                &parameters,
                rng,
            );
        } else {
            phase2_cli::contribute::<E>(
                setup_filename!(COMBINED_FILENAME, setup.setup_id),
                setup_filename!(COMBINED_HASH_FILENAME, setup.setup_id),
                setup_filename!(
                    COMBINED_VERIFIED_POK_AND_CORRECTNESS_FILENAME,
                    setup.setup_id
                ),
                setup_filename!(
                    COMBINED_VERIFIED_POK_AND_CORRECTNESS_HASH_FILENAME,
                    setup.setup_id
                ),
                DEFAULT_VERIFY_CHECK_INPUT_CORRECTNESS,
                BatchExpMode::Direct,
                rng,
            );
        }
        info!("applied beacon, verifying");
        remove_file_if_exists(setup_filename!(COMBINED_HASH_FILENAME, setup.setup_id))?;
        remove_file_if_exists(setup_filename!(
            COMBINED_VERIFIED_POK_AND_CORRECTNESS_HASH_FILENAME,
            setup.setup_id
        ))?;
        remove_file_if_exists(setup_filename!(
            COMBINED_VERIFIED_POK_AND_CORRECTNESS_NEW_CHALLENGE_FILENAME,
            setup.setup_id
        ))?;
        remove_file_if_exists(setup_filename!(
            COMBINED_VERIFIED_POK_AND_CORRECTNESS_NEW_CHALLENGE_HASH_FILENAME,
            setup.setup_id
        ))?;
        if self.phase == Phase::Phase1 {
            phase1_cli::transform_pok_and_correctness(
                setup_filename!(COMBINED_FILENAME, setup.setup_id),
                setup_filename!(COMBINED_HASH_FILENAME, setup.setup_id),
                DEFAULT_VERIFY_CHECK_INPUT_CORRECTNESS,
                setup_filename!(
                    COMBINED_VERIFIED_POK_AND_CORRECTNESS_FILENAME,
                    setup.setup_id
                ),
                setup_filename!(
                    COMBINED_VERIFIED_POK_AND_CORRECTNESS_HASH_FILENAME,
                    setup.setup_id
                ),
                DEFAULT_VERIFY_CHECK_OUTPUT_CORRECTNESS,
                setup_filename!(
                    COMBINED_VERIFIED_POK_AND_CORRECTNESS_NEW_CHALLENGE_FILENAME,
                    setup.setup_id
                ),
                setup_filename!(
                    COMBINED_VERIFIED_POK_AND_CORRECTNESS_NEW_CHALLENGE_HASH_FILENAME,
                    setup.setup_id
                ),
                SubgroupCheckMode::Auto,
                false, // ratio check
                &parameters,
            );
            phase1_cli::transform_ratios(
                setup_filename!(
                    COMBINED_VERIFIED_POK_AND_CORRECTNESS_NEW_CHALLENGE_FILENAME,
                    setup.setup_id
                ),
                DEFAULT_VERIFY_CHECK_INPUT_CORRECTNESS,
                &parameters,
            );
        } else {
            phase2_cli::verify::<E>(
                setup_filename!(COMBINED_FILENAME, setup.setup_id),
                setup_filename!(COMBINED_HASH_FILENAME, setup.setup_id),
                DEFAULT_VERIFY_CHECK_INPUT_CORRECTNESS,
                setup_filename!(
                    COMBINED_VERIFIED_POK_AND_CORRECTNESS_FILENAME,
                    setup.setup_id
                ),
                setup_filename!(
                    COMBINED_VERIFIED_POK_AND_CORRECTNESS_HASH_FILENAME,
                    setup.setup_id
                ),
                DEFAULT_VERIFY_CHECK_OUTPUT_CORRECTNESS,
                setup_filename!(
                    COMBINED_VERIFIED_POK_AND_CORRECTNESS_NEW_CHALLENGE_FILENAME,
                    setup.setup_id
                ),
                setup_filename!(
                    COMBINED_VERIFIED_POK_AND_CORRECTNESS_NEW_CHALLENGE_HASH_FILENAME,
                    setup.setup_id
                ),
                SubgroupCheckMode::Auto,
                false,
            );
        }
        Ok(())
    }

    async fn apply_beacon(
        &self,
        beacon_hash: &str,
        expected_participants: &[ParticipantId],
    ) -> Result<()> {
        let mut transcript = load_transcript()?;
        backup_transcript(&transcript)?;

        let ceremony = self.get_ceremony().await?;
        transcript.rounds.push(ceremony.clone());
        let beacon_hash = hex::decode(beacon_hash)?;
        if beacon_hash.len() != BEACON_HASH_LENGTH {
            return Err(
                VerifyTranscriptError::BeaconHashWrongLengthError(beacon_hash.len()).into(),
            );
        }
        let expected_participants_set: HashSet<_> = expected_participants.iter().cloned().collect();
        let current_participants_set: HashSet<_> =
            ceremony.contributor_ids.iter().cloned().collect();
        if current_participants_set != expected_participants_set {
            return Err(NewRoundError::DifferentExpectedParticipantsError(
                current_participants_set,
                expected_participants_set,
            )
            .into());
        }
        let mut final_hashes = vec![];
        for (setup_index, setup) in ceremony.setups.iter().enumerate() {
            // Generate combined file from transcript
            // Verify result if running phase 1
            match setup.parameters.curve_kind.as_str() {
                "bw6" => {
                    self.apply_beacon_to_setup::<BW6_761>(
                        &ceremony,
                        setup,
                        setup_index,
                        &beacon_hash,
                    )
                    .await?
                }
                "bls12_377" => {
                    self.apply_beacon_to_setup::<Bls12_377>(
                        &ceremony,
                        setup,
                        setup_index,
                        &beacon_hash,
                    )
                    .await?
                }
                "mnt4_753" => {
                    self.apply_beacon_to_setup::<MNT4_753>(
                        &ceremony,
                        setup,
                        setup_index,
                        &beacon_hash,
                    )
                    .await?
                }
                "mnt6_753" => {
                    self.apply_beacon_to_setup::<MNT6_753>(
                        &ceremony,
                        setup,
                        setup_index,
                        &beacon_hash,
                    )
                    .await?
                }
                _ => {
                    return Err(VerifyTranscriptError::UnsupportedCurveKindError(
                        setup.parameters.curve_kind.clone(),
                    )
                    .into())
                }
            }

            let response_hash_from_file = read_hash_from_file(setup_filename!(
                COMBINED_VERIFIED_POK_AND_CORRECTNESS_HASH_FILENAME,
                setup.setup_id
            ))?;
            final_hashes.push(response_hash_from_file);
        }
        transcript.final_hashes = Some(final_hashes);
        transcript.beacon_hash = Some(hex::encode(&beacon_hash));
        save_transcript(&transcript)?;
        Ok(())
    }

    async fn get_last_contribution_pk(
        &self,
        setup_index: usize,
        chunk_index: usize,
    ) -> Result<ParticipantId> {
        let ceremony = self.get_ceremony().await?;

        let participant_id_from_chunk = ceremony.setups[setup_index].chunks[chunk_index]
            .contributions
            .last()
            .unwrap()
            .contributor_id
            .as_ref()
            .unwrap()
            .clone();

        Ok(participant_id_from_chunk)
    }

    async fn remove_last_contribution(
        &self,
        expected_participant_id: &ParticipantId,
        setup_index: usize,
        chunk_index: usize,
    ) -> Result<()> {
        let mut ceremony = self.get_ceremony().await?;
        self.backup_ceremony(&ceremony)?;
        if !ceremony.contributor_ids.contains(&expected_participant_id) {
            return Err(ControlError::ParticipantDoesNotExistError(
                expected_participant_id.clone(),
                ceremony.contributor_ids.clone(),
            )
            .into());
        }
        let participant_id_from_chunk = ceremony.setups[setup_index].chunks[chunk_index]
            .contributions
            .last()
            .unwrap()
            .contributor_id
            .as_ref()
            .unwrap();
        if participant_id_from_chunk != expected_participant_id {
            return Err(ControlError::ParticipantUnexpected(
                chunk_index,
                expected_participant_id.clone(),
                participant_id_from_chunk.clone(),
            )
            .into());
        }
        ceremony.setups[setup_index].chunks[chunk_index].contributions = ceremony.setups
            [setup_index]
            .chunks[chunk_index]
            .contributions[..ceremony.setups[setup_index].chunks[chunk_index]
            .contributions
            .len()
            - 1]
            .to_vec();
        self.put_ceremony(&ceremony).await?;
        Ok(())
    }

    async fn signal_shutdown(&self, shutdown_signal: bool) -> Result<()> {
        let mut ceremony = self.get_ceremony().await?;
        ceremony.shutdown_signal = shutdown_signal;
        info!("shutdown signal: {}", ceremony.shutdown_signal);
        self.put_ceremony(&ceremony).await?;
        Ok(())
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt().json().init();

    let main_opts: ControlOpts = ControlOpts::parse_args_default_or_exit();
    let (_, private_key, _) = read_keys(&main_opts.keys_file, main_opts.unsafe_passphrase, false)
        .expect("Should have loaded Nimiq setup keys");

    let control = Control::new(&main_opts, private_key.expose_secret())
        .await
        .expect("Should have been able to create a control.");
    let command = main_opts.clone().command.unwrap_or_else(|| {
        eprintln!("No command was provided.");
        eprintln!("{}", ControlOpts::usage());
        process::exit(2)
    });

    (match command {
        Command::AddParticipant(opts) => control
            .add_participant(opts.participant_id)
            .await
            .expect("Should have run command successfully"),
        Command::RemoveParticipant(opts) => control
            .remove_participant(opts.participant_id)
            .await
            .expect("Should have run command successfully"),
        Command::AddVerifier(opts) => control
            .add_verifier(opts.participant_id)
            .await
            .expect("Should have run command successfully"),
        Command::RemoveVerifier(opts) => control
            .remove_verifier(opts.participant_id)
            .await
            .expect("Should have run command successfully"),
        Command::SignalShutdown(opts) => control
            .signal_shutdown(opts.shutdown_signal)
            .await
            .expect("Should have run command successfully"),
        Command::UnlockParticipantChunks(opts) => {
            // Make sure options are not in conflict.
            if opts.all == opts.participant_id.is_some() {
                panic!("Requires either a participant ID or the `all` option.");
            }
            control
                .unlock_participant(opts.participant_id)
                .await
                .expect("Should have run command successfully")
        }
        Command::NewRound(opts) => control
            .new_round(
                &opts.expected_participant,
                &opts.new_participant,
                opts.verify_transcript,
                !opts.do_not_send_shutdown_signal,
                opts.shutdown_delay_time_in_secs,
                opts.publish,
            )
            .await
            .expect("Should have run command successfully"),
        Command::ApplyBeacon(opts) => control
            .apply_beacon(&opts.beacon_hash, &opts.expected_participant)
            .await
            .expect("Should have run command successfully"),
        Command::RemoveLastContribution(opts) => {
            control
                .remove_last_contribution(&opts.participant_id, opts.setup_index, opts.chunk_index)
                .await
                .expect("Should have run command successfully");
        }
        Command::GetLastContributionPk(opts) => {
            let pk = control
                .get_last_contribution_pk(opts.setup_index, opts.chunk_index)
                .await
                .expect("Should have run command successfully");

            println!("Public key: {}", pk);
        }
    });
}
