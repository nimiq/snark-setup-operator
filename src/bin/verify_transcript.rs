use anyhow::Result;
use ark_bls12_377::Bls12_377;
use ark_bw6_761::BW6_761;
use ark_ec::pairing::Pairing;
use ark_mnt4_753::MNT4_753;
use ark_mnt6_753::MNT6_753;
use gumdrop::Options;
#[allow(unused_imports)]
use phase1_cli::*;
#[allow(unused_imports)]
use phase2_cli::*;
use setup_utils::converters::{batch_exp_mode_from_str, subgroup_check_mode_from_str};
use setup_utils::{
    derive_rng_from_seed, from_slice, upgrade_correctness_check_config, write_to_file,
    BatchExpMode, SubgroupCheckMode, DEFAULT_VERIFY_CHECK_INPUT_CORRECTNESS,
    DEFAULT_VERIFY_CHECK_OUTPUT_CORRECTNESS,
};
use snark_setup_operator::data_structs::Ceremony;
use snark_setup_operator::setup_filename;
use snark_setup_operator::transcript_data_structs::Transcript;
use snark_setup_operator::utils::{
    CHALLENGE_FILENAME, CHALLENGE_HASH_FILENAME, COMBINED_FILENAME, COMBINED_HASH_FILENAME,
    COMBINED_NEW_CHALLENGE_FILENAME, COMBINED_NEW_CHALLENGE_HASH_FILENAME,
    COMBINED_VERIFIED_POK_AND_CORRECTNESS_FILENAME,
    COMBINED_VERIFIED_POK_AND_CORRECTNESS_HASH_FILENAME,
    COMBINED_VERIFIED_POK_AND_CORRECTNESS_NEW_CHALLENGE_FILENAME,
    COMBINED_VERIFIED_POK_AND_CORRECTNESS_NEW_CHALLENGE_HASH_FILENAME, INITIAL_CHALLENGE_FILENAME,
    INITIAL_CHALLENGE_HASH_FILENAME, NEW_CHALLENGE_FILENAME, NEW_CHALLENGE_HASH_FILENAME,
    NEW_CHALLENGE_LIST_FILENAME, NEW_CHALLENGE_PREFIX_FOR_NEXT_ROUND, PHASE2_INIT_FILENAME,
    RESPONSE_FILENAME, RESPONSE_HASH_FILENAME, RESPONSE_LIST_FILENAME,
    RESPONSE_PREFIX_FOR_AGGREGATION,
};
use snark_setup_operator::{
    error::VerifyTranscriptError,
    utils::{
        check_challenge_hashes_same, check_new_challenge_hashes_same, check_response_hashes_same,
        copy_file_if_exists, create_full_parameters, create_parameters_for_chunk,
        download_file_direct_async, download_file_from_azure_async, get_content_length,
        read_hash_from_file, remove_file_if_exists, string_to_phase, verify_signed_data, Phase,
        BEACON_HASH_LENGTH,
    },
};
use std::ops::Neg;
use std::{
    collections::HashSet,
    fs::{copy, File},
    io::{Read, Write},
};
use tokio::runtime::Runtime;
use tracing::info;
use tracing_subscriber;

#[derive(Debug, Options, Clone)]
pub struct VerifyTranscriptOpts {
    help: bool,
    #[options(help = "the path of the transcript json file", default = "transcript")]
    pub transcript_path: String,
    #[options(help = "apply beacon")]
    pub apply_beacon: bool,
    #[options(help = "the beacon hash")]
    pub beacon_hash: String,
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
    #[options(help = "the round at which full checks begin", default = "0")]
    pub round_threshold: u64,

    #[options(help = "files with prepared circuit (in order of setups). Only used for phase 2")]
    pub circuit_filenames: Vec<String>,
    #[options(help = "initial query filename. Used only for phase2")]
    pub initial_query_filename: Option<String>,
    #[options(help = "initial full filename. Used only for phase2")]
    pub initial_full_filename: Option<String>,
}

pub struct TranscriptVerifier {
    pub phase: Phase,
    pub transcript: Transcript,
    pub apply_beacon: bool,
    pub beacon_hash: Vec<u8>,
    pub force_correctness_checks: bool,
    pub batch_exp_mode: BatchExpMode,
    pub subgroup_check_mode: SubgroupCheckMode,
    pub ratio_check: bool,
    pub round_threshold: u64,
    pub phase2_options: Option<Phase2Opts>,
}

pub struct Phase2Params {
    pub phase1_filename: String,
    pub circuit_filename: String,
    pub initial_query_filename: String,
    pub initial_full_filename: String,
}

pub struct Phase2Opts {
    pub setups: Vec<Phase2Params>,
}

impl Phase2Opts {
    pub fn new(opts: &VerifyTranscriptOpts, transcript: &Transcript) -> Result<Self> {
        let ceremony = transcript
            .rounds
            .get(0)
            .ok_or(VerifyTranscriptError::RoundWrongIndexError(0, 0))?;

        if ceremony.setups.len() != opts.circuit_filenames.len() {
            panic!("circuit_filenames must be used and same length as setups when running phase2");
        }

        let mut setups = vec![];
        for (i, setup) in ceremony.setups.iter().enumerate() {
            setups.push(Phase2Params {
                phase1_filename: setup_filename!(PHASE2_INIT_FILENAME, setup.setup_id).to_string(),
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

impl TranscriptVerifier {
    pub fn new(opts: &VerifyTranscriptOpts) -> Result<Self> {
        let mut transcript = String::new();
        File::open(&opts.transcript_path)
            .expect("Should have opened transcript file.")
            .read_to_string(&mut transcript)
            .expect("Should have read transcript file.");
        let transcript: Transcript = serde_json::from_str::<Transcript>(&transcript)?;

        let beacon_hash = hex::decode(&opts.beacon_hash)?;
        if beacon_hash.len() != BEACON_HASH_LENGTH {
            return Err(
                VerifyTranscriptError::BeaconHashWrongLengthError(beacon_hash.len()).into(),
            );
        }
        let beacon_value = hex::decode(
            &transcript
                .beacon_hash
                .as_ref()
                .expect("Beacon value should have been something"),
        )?;
        if beacon_hash.clone() != beacon_value {
            return Err(VerifyTranscriptError::BeaconHashWasDifferentError(
                hex::encode(&beacon_value),
                hex::encode(&beacon_hash),
            )
            .into());
        }
        let phase = string_to_phase(
            &transcript
                .rounds
                .last()
                .expect("No rounds in transcript")
                .phase,
        )?;
        let phase2_options = match phase {
            Phase::Phase1 => None,
            Phase::Phase2 => Some(Phase2Opts::new(&opts, &transcript)?),
        };
        let verifier = Self {
            phase,
            transcript,
            beacon_hash,
            apply_beacon: opts.apply_beacon,
            force_correctness_checks: opts.force_correctness_checks,
            batch_exp_mode: opts.batch_exp_mode,
            subgroup_check_mode: opts.subgroup_check_mode,
            ratio_check: !opts.skip_ratio_check,
            round_threshold: opts.round_threshold,
            phase2_options,
        };
        Ok(verifier)
    }

    fn verify_setup<E: Pairing>(&self, setup_id: usize, rt: &Runtime) -> Result<()>
    where
        E::G1Affine: Neg<Output = E::G1Affine>,
    {
        let mut current_parameters = None;
        let mut previous_round: Option<Ceremony> = None;
        for (round_index, ceremony) in self.transcript.rounds.iter().enumerate() {
            let setup = &ceremony.setups[setup_id];
            let round_index = round_index as u64;
            info!("verifying round {}", round_index);

            // These are the participant IDs we discover in the transcript.
            let mut participant_ids_from_poks = HashSet::new();

            remove_file_if_exists(setup_filename!(RESPONSE_LIST_FILENAME, setup.setup_id))?;
            let mut response_list_file =
                File::create(setup_filename!(RESPONSE_LIST_FILENAME, setup.setup_id))?;

            // Quick check - make sure the all chunks have the same number of contributions.
            // If the coordinator was honest, then each participant would have contributed
            // once to each chunk.
            if !ceremony.setups.iter().all(|setup| {
                setup.chunks.iter().all(|c| {
                    c.contributions.len() == ceremony.setups[0].chunks[0].contributions.len()
                })
            }) {
                return Err(
                    VerifyTranscriptError::NotAllChunksHaveSameNumberOfContributionsError.into(),
                );
            }

            match current_parameters.as_ref() {
                None => {
                    current_parameters = Some(setup.parameters.clone());
                }
                Some(existing_parameters) => {
                    if existing_parameters != &setup.parameters {
                        return Err(VerifyTranscriptError::ParametersDifferentBetweenRounds(
                            existing_parameters.clone(),
                            setup.parameters.clone(),
                        )
                        .into());
                    }
                }
            }

            if round_index != ceremony.round {
                return Err(VerifyTranscriptError::RoundWrongIndexError(
                    round_index,
                    ceremony.round,
                )
                .into());
            }

            if self.phase == Phase::Phase2 {
                remove_file_if_exists(setup_filename!(
                    NEW_CHALLENGE_LIST_FILENAME,
                    setup.setup_id
                ))?;
                let phase2_options = self
                    .phase2_options
                    .as_ref()
                    .expect("Phase2 options not used while running phase2 verification");
                let chunk_size = setup.parameters.chunk_size;
                phase2_cli::new_challenge::<E>(
                    setup_filename!(NEW_CHALLENGE_FILENAME, setup.setup_id),
                    setup_filename!(NEW_CHALLENGE_HASH_FILENAME, setup.setup_id),
                    setup_filename!(NEW_CHALLENGE_LIST_FILENAME, setup.setup_id),
                    chunk_size,
                    &phase2_options.setups[setup_id].phase1_filename,
                    &phase2_options.setups[setup_id].circuit_filename,
                );
                // Generate full initial contribution to later check consistency of final contribution
                // later
                phase2_cli::combine::<E>(
                    phase2_options.setups[setup_id]
                        .initial_query_filename
                        .as_ref(),
                    phase2_options.setups[setup_id]
                        .initial_full_filename
                        .as_ref(),
                    setup_filename!(NEW_CHALLENGE_LIST_FILENAME, setup.setup_id),
                    setup_filename!(INITIAL_CHALLENGE_FILENAME, setup.setup_id),
                    true,
                );
            }

            for (chunk_index, chunk) in setup.chunks.iter().enumerate() {
                let parameters = create_parameters_for_chunk::<E>(&setup.parameters, chunk_index)?;
                let mut current_new_challenge_hash = String::new();
                for (i, contribution) in chunk.contributions.iter().enumerate() {
                    // Clean up the previous contribution challenge and response.
                    //if self.phase == Phase::Phase1 {
                    remove_file_if_exists(setup_filename!(CHALLENGE_FILENAME, setup.setup_id))?;
                    remove_file_if_exists(setup_filename!(
                        CHALLENGE_HASH_FILENAME,
                        setup.setup_id
                    ))?;
                    remove_file_if_exists(setup_filename!(RESPONSE_FILENAME, setup.setup_id))?;
                    remove_file_if_exists(setup_filename!(RESPONSE_HASH_FILENAME, setup.setup_id))?;
                    copy_file_if_exists(
                        setup_filename!(NEW_CHALLENGE_FILENAME, setup.setup_id),
                        setup_filename!(CHALLENGE_FILENAME, setup.setup_id),
                    )?;
                    remove_file_if_exists(setup_filename!(NEW_CHALLENGE_FILENAME, setup.setup_id))?;
                    remove_file_if_exists(setup_filename!(
                        NEW_CHALLENGE_HASH_FILENAME,
                        setup.setup_id
                    ))?;

                    if i == 0 {
                        if round_index == 0 {
                            // This is the initialization pseudo-contribution, so we verify it was
                            // deterministically created by `new`.
                            let verified_data = contribution.verified_data()?;
                            if self.phase == Phase::Phase1 {
                                phase1_cli::new_challenge(
                                    setup_filename!(NEW_CHALLENGE_FILENAME, setup.setup_id),
                                    setup_filename!(NEW_CHALLENGE_HASH_FILENAME, setup.setup_id),
                                    &parameters,
                                );
                            } else {
                                // Initial challenge already generated by phase2_cli::new_challenge
                                let challenge_filename = format!(
                                    "{}.{}",
                                    setup_filename!(NEW_CHALLENGE_FILENAME, setup.setup_id),
                                    chunk.unique_chunk_id.chunk_id
                                );
                                copy_file_if_exists(
                                    &format!(
                                        "{}.{}",
                                        setup_filename!(NEW_CHALLENGE_FILENAME, setup.setup_id),
                                        chunk.unique_chunk_id.chunk_id
                                    ),
                                    setup_filename!(NEW_CHALLENGE_FILENAME, setup.setup_id),
                                )?;
                                let challenge_contents = std::fs::read(challenge_filename)
                                    .expect("should have read challenge");
                                let challenge_hash =
                                    setup_utils::calculate_hash(&challenge_contents);
                                write_to_file(
                                    setup_filename!(NEW_CHALLENGE_HASH_FILENAME, setup.setup_id),
                                    challenge_hash.as_slice(),
                                );
                            }
                            info!("About to read new challenge hash");
                            let new_challenge_hash_from_file = read_hash_from_file(
                                setup_filename!(NEW_CHALLENGE_HASH_FILENAME, setup.setup_id),
                            )?;
                            info!("Read new challenge hash");
                            check_new_challenge_hashes_same(
                                &verified_data.data.new_challenge_hash,
                                &new_challenge_hash_from_file,
                            )?;
                            current_new_challenge_hash =
                                verified_data.data.new_challenge_hash.clone();
                        } else {
                            check_new_challenge_hashes_same(
                                &contribution.verified_data()?.data.new_challenge_hash,
                                &previous_round.as_ref().unwrap().setups[setup_id].chunks
                                    [chunk_index]
                                    .contributions
                                    .iter()
                                    .last()
                                    .unwrap()
                                    .verified_data()?
                                    .data
                                    .new_challenge_hash,
                            )?;

                            let new_challenge_filename = format!(
                                "{}_{}",
                                setup_filename!(
                                    NEW_CHALLENGE_PREFIX_FOR_NEXT_ROUND,
                                    setup.setup_id
                                ),
                                chunk.unique_chunk_id
                            );
                            copy(
                                &new_challenge_filename,
                                setup_filename!(NEW_CHALLENGE_FILENAME, setup.setup_id),
                            )?;
                            remove_file_if_exists(&new_challenge_filename)?;
                            current_new_challenge_hash = contribution
                                .verified_data()?
                                .data
                                .new_challenge_hash
                                .clone();
                        }
                        continue;
                    }

                    let contributor_id = contribution.contributor_id()?;
                    if chunk_index == 0 {
                        participant_ids_from_poks.insert(contributor_id.clone());
                    }

                    // Verify the challenge and response hashes were signed by the participant.
                    let contributed_data = contribution.contributed_data()?;
                    verify_signed_data(
                        &contributed_data.data,
                        &contributed_data.signature,
                        &contributor_id,
                    )?;

                    // Verify that the challenge the participant attested they worked on is
                    // indeed the one we have as the expected computed challenge.
                    check_new_challenge_hashes_same(
                        &contributed_data.data.challenge_hash,
                        &current_new_challenge_hash,
                    )?;

                    let verified_data = contribution.verified_data()?;
                    let verifier_id = contribution.verifier_id()?;
                    // Verify the verifier challenge, response and new challenge hashes
                    // were signed by the verifier. This is not strictly necessary, but can help
                    // catch a malicious coordinator.
                    verify_signed_data(
                        &verified_data.data,
                        &verified_data.signature,
                        &verifier_id,
                    )?;

                    // Check that the verifier attested to work on the same challenge the participant
                    // attested to work on, and that the participant produced the same response as the
                    // one the verifier verified.
                    check_challenge_hashes_same(
                        &contributed_data.data.challenge_hash,
                        &verified_data.data.challenge_hash,
                    )?;
                    info!("About to check first response hashes");
                    check_response_hashes_same(
                        &contributed_data.data.response_hash,
                        &verified_data.data.response_hash,
                    )?;
                    info!("Checked first response hash");

                    let contributed_location = contribution.contributed_location()?;
                    // Download the response computed by the participant.
                    if contributed_location.contains("blob.core.windows.net") {
                        let length = rt.block_on(get_content_length(&contributed_location))?;
                        rt.block_on(download_file_from_azure_async(
                            &contributed_location,
                            length,
                            setup_filename!(RESPONSE_FILENAME, setup.setup_id),
                        ))?;
                    } else {
                        rt.block_on(download_file_direct_async(
                            &contributed_location,
                            setup_filename!(RESPONSE_FILENAME, setup.setup_id),
                        ))?;
                    };

                    // Run verification between challenge and response, and produce the next new
                    // challenge. Skip both subgroup and ratio checks if below round threshold.
                    let (subgroup_check, ratio_check) = match round_index < self.round_threshold {
                        true => (SubgroupCheckMode::No, false),
                        false => (self.subgroup_check_mode, self.ratio_check),
                    };
                    if self.phase == Phase::Phase1 {
                        phase1_cli::transform_pok_and_correctness(
                            setup_filename!(CHALLENGE_FILENAME, setup.setup_id),
                            setup_filename!(CHALLENGE_HASH_FILENAME, setup.setup_id),
                            upgrade_correctness_check_config(
                                DEFAULT_VERIFY_CHECK_INPUT_CORRECTNESS,
                                self.force_correctness_checks,
                            ),
                            setup_filename!(RESPONSE_FILENAME, setup.setup_id),
                            setup_filename!(RESPONSE_HASH_FILENAME, setup.setup_id),
                            upgrade_correctness_check_config(
                                DEFAULT_VERIFY_CHECK_OUTPUT_CORRECTNESS,
                                self.force_correctness_checks,
                            ),
                            setup_filename!(NEW_CHALLENGE_FILENAME, setup.setup_id),
                            setup_filename!(NEW_CHALLENGE_HASH_FILENAME, setup.setup_id),
                            subgroup_check,
                            ratio_check,
                            &parameters,
                        );
                    } else {
                        phase2_cli::verify::<E>(
                            setup_filename!(CHALLENGE_FILENAME, setup.setup_id),
                            setup_filename!(CHALLENGE_HASH_FILENAME, setup.setup_id),
                            upgrade_correctness_check_config(
                                DEFAULT_VERIFY_CHECK_INPUT_CORRECTNESS,
                                self.force_correctness_checks,
                            ),
                            setup_filename!(RESPONSE_FILENAME, setup.setup_id),
                            setup_filename!(RESPONSE_HASH_FILENAME, setup.setup_id),
                            upgrade_correctness_check_config(
                                DEFAULT_VERIFY_CHECK_OUTPUT_CORRECTNESS,
                                self.force_correctness_checks,
                            ),
                            setup_filename!(NEW_CHALLENGE_FILENAME, setup.setup_id),
                            setup_filename!(NEW_CHALLENGE_HASH_FILENAME, setup.setup_id),
                            subgroup_check,
                            false, // verify full contribution
                        );
                    }

                    let challenge_hash_from_file = read_hash_from_file(setup_filename!(
                        CHALLENGE_HASH_FILENAME,
                        setup.setup_id
                    ))?;
                    // Check that the challenge hash is indeed the one the participant and the verifier
                    // attested to work on.
                    check_challenge_hashes_same(
                        &verified_data.data.challenge_hash,
                        &challenge_hash_from_file,
                    )?;

                    let response_hash_from_file = read_hash_from_file(setup_filename!(
                        RESPONSE_HASH_FILENAME,
                        setup.setup_id
                    ))?;
                    // Check that the response hash is indeed the one the participant attested they produced
                    // and the verifier attested to work on.
                    info!("About to check second response hashes");
                    check_response_hashes_same(
                        &verified_data.data.response_hash,
                        &response_hash_from_file,
                    )?;
                    info!("Checked second response hash");

                    let new_challenge_hash_from_file = read_hash_from_file(setup_filename!(
                        NEW_CHALLENGE_HASH_FILENAME,
                        setup.setup_id
                    ))?;
                    // Check that the new challenge hash is indeed the one the verifier attested to
                    // produce.
                    check_new_challenge_hashes_same(
                        &verified_data.data.new_challenge_hash,
                        &new_challenge_hash_from_file,
                    )?;

                    // Carry the produced new challenge hash to the next contribution.
                    current_new_challenge_hash = verified_data.data.new_challenge_hash.clone();

                    // This is the last contribution which we'll combine with the other last
                    // contributions, so add that to the list.
                    if i == chunk.contributions.len() - 1 {
                        let response_filename = format!(
                            "{}_{}",
                            setup_filename!(RESPONSE_PREFIX_FOR_AGGREGATION, setup.setup_id),
                            chunk.unique_chunk_id
                        );
                        copy(
                            setup_filename!(RESPONSE_FILENAME, setup.setup_id),
                            &response_filename,
                        )?;
                        response_list_file.write(format!("{}\n", response_filename).as_bytes())?;
                        let new_challenge_filename = format!(
                            "{}_{}",
                            setup_filename!(NEW_CHALLENGE_PREFIX_FOR_NEXT_ROUND, setup.setup_id),
                            chunk.unique_chunk_id
                        );
                        copy(
                            setup_filename!(NEW_CHALLENGE_FILENAME, setup.setup_id),
                            &new_challenge_filename,
                        )?;
                    }
                }
                info!("chunk {} verified", chunk.unique_chunk_id);
            }

            drop(response_list_file);

            info!(
                "participants found in the transcript of round {}:\n{}",
                round_index,
                participant_ids_from_poks
                    .iter()
                    .map(|id| id.to_hex())
                    .collect::<Vec<_>>()
                    .join("\n")
            );
            let expected_contributor_ids: HashSet<_> =
                ceremony.contributor_ids.iter().cloned().collect();
            if expected_contributor_ids != participant_ids_from_poks {
                return Err(VerifyTranscriptError::NotAllParticipantsPresent(
                    expected_contributor_ids,
                    participant_ids_from_poks,
                )
                .into());
            }

            previous_round = Some(ceremony.clone());
            info!("Verified round {}", round_index);
        }

        info!("all rounds and chunks verified, aggregating");
        let setup = &self.transcript.rounds[0].setups[setup_id];
        remove_file_if_exists(setup_filename!(COMBINED_FILENAME, setup.setup_id))?;
        let current_parameters = current_parameters.unwrap();
        let parameters = create_parameters_for_chunk::<E>(&current_parameters, 0)?;
        // Combine the last contributions from each chunk into a single big contributions.
        if self.phase == Phase::Phase1 {
            phase1_cli::combine(
                setup_filename!(RESPONSE_LIST_FILENAME, setup.setup_id),
                setup_filename!(COMBINED_FILENAME, setup.setup_id),
                &parameters,
            );
        } else {
            let phase2_options = self
                .phase2_options
                .as_ref()
                .expect("Phase2 options not used while running phase2 verification");
            phase2_cli::combine::<E>(
                phase2_options.setups[setup_id]
                    .initial_query_filename
                    .as_ref(),
                phase2_options.setups[setup_id]
                    .initial_full_filename
                    .as_ref(),
                setup_filename!(RESPONSE_LIST_FILENAME, setup.setup_id),
                setup_filename!(COMBINED_FILENAME, setup.setup_id),
                false,
            );
        }
        info!("combined, applying beacon");
        let parameters = create_full_parameters::<E>(&current_parameters)?;
        remove_file_if_exists(setup_filename!(COMBINED_HASH_FILENAME, setup.setup_id))?;
        remove_file_if_exists(setup_filename!(
            COMBINED_VERIFIED_POK_AND_CORRECTNESS_FILENAME,
            setup.setup_id
        ))?;
        remove_file_if_exists(setup_filename!(
            COMBINED_VERIFIED_POK_AND_CORRECTNESS_HASH_FILENAME,
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
        if !self.apply_beacon {
            if self.phase == Phase::Phase1 {
                phase1_cli::transform_ratios(
                    setup_filename!(COMBINED_FILENAME, setup.setup_id),
                    upgrade_correctness_check_config(
                        DEFAULT_VERIFY_CHECK_INPUT_CORRECTNESS,
                        self.force_correctness_checks,
                    ),
                    &parameters,
                );
            } else {
                phase2_cli::verify::<E>(
                    setup_filename!(INITIAL_CHALLENGE_FILENAME, setup.setup_id),
                    setup_filename!(INITIAL_CHALLENGE_HASH_FILENAME, setup.setup_id),
                    upgrade_correctness_check_config(
                        DEFAULT_VERIFY_CHECK_INPUT_CORRECTNESS,
                        self.force_correctness_checks,
                    ),
                    setup_filename!(COMBINED_FILENAME, setup.setup_id),
                    setup_filename!(COMBINED_HASH_FILENAME, setup.setup_id),
                    upgrade_correctness_check_config(
                        DEFAULT_VERIFY_CHECK_OUTPUT_CORRECTNESS,
                        self.force_correctness_checks,
                    ),
                    setup_filename!(COMBINED_NEW_CHALLENGE_FILENAME, setup.setup_id),
                    setup_filename!(COMBINED_NEW_CHALLENGE_HASH_FILENAME, setup.setup_id),
                    self.subgroup_check_mode,
                    true,
                );
            }
        } else {
            let rng = derive_rng_from_seed(&from_slice(&self.beacon_hash));
            // Apply the random beacon.
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
                    upgrade_correctness_check_config(
                        DEFAULT_VERIFY_CHECK_INPUT_CORRECTNESS,
                        self.force_correctness_checks,
                    ),
                    self.batch_exp_mode,
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
                    upgrade_correctness_check_config(
                        DEFAULT_VERIFY_CHECK_INPUT_CORRECTNESS,
                        self.force_correctness_checks,
                    ),
                    self.batch_exp_mode,
                    rng,
                );
            }
            let final_hash_computed = hex::decode(&read_hash_from_file(setup_filename!(
                COMBINED_VERIFIED_POK_AND_CORRECTNESS_HASH_FILENAME,
                setup.setup_id
            ))?)?;
            let final_hash_expected =
                hex::decode(&self.transcript.final_hashes.as_ref().unwrap()[setup_id])?;
            if final_hash_computed != final_hash_expected {
                return Err(VerifyTranscriptError::BeaconHashWasDifferentError(
                    hex::encode(&final_hash_expected),
                    hex::encode(&final_hash_computed),
                )
                .into());
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
            // Verify the correctness of the random beacon.
            if self.phase == Phase::Phase1 {
                phase1_cli::transform_pok_and_correctness(
                    setup_filename!(COMBINED_FILENAME, setup.setup_id),
                    setup_filename!(COMBINED_HASH_FILENAME, setup.setup_id),
                    upgrade_correctness_check_config(
                        DEFAULT_VERIFY_CHECK_INPUT_CORRECTNESS,
                        self.force_correctness_checks,
                    ),
                    setup_filename!(
                        COMBINED_VERIFIED_POK_AND_CORRECTNESS_FILENAME,
                        setup.setup_id
                    ),
                    setup_filename!(
                        COMBINED_VERIFIED_POK_AND_CORRECTNESS_HASH_FILENAME,
                        setup.setup_id
                    ),
                    upgrade_correctness_check_config(
                        DEFAULT_VERIFY_CHECK_OUTPUT_CORRECTNESS,
                        self.force_correctness_checks,
                    ),
                    setup_filename!(
                        COMBINED_VERIFIED_POK_AND_CORRECTNESS_NEW_CHALLENGE_FILENAME,
                        setup.setup_id
                    ),
                    setup_filename!(
                        COMBINED_VERIFIED_POK_AND_CORRECTNESS_NEW_CHALLENGE_HASH_FILENAME,
                        setup.setup_id
                    ),
                    self.subgroup_check_mode,
                    self.ratio_check,
                    &parameters,
                );
            } else {
                phase2_cli::verify::<E>(
                    setup_filename!(COMBINED_FILENAME, setup.setup_id),
                    setup_filename!(COMBINED_HASH_FILENAME, setup.setup_id),
                    upgrade_correctness_check_config(
                        DEFAULT_VERIFY_CHECK_INPUT_CORRECTNESS,
                        self.force_correctness_checks,
                    ),
                    setup_filename!(
                        COMBINED_VERIFIED_POK_AND_CORRECTNESS_FILENAME,
                        setup.setup_id
                    ),
                    setup_filename!(
                        COMBINED_VERIFIED_POK_AND_CORRECTNESS_HASH_FILENAME,
                        setup.setup_id
                    ),
                    upgrade_correctness_check_config(
                        DEFAULT_VERIFY_CHECK_OUTPUT_CORRECTNESS,
                        self.force_correctness_checks,
                    ),
                    setup_filename!(
                        COMBINED_VERIFIED_POK_AND_CORRECTNESS_NEW_CHALLENGE_FILENAME,
                        setup.setup_id
                    ),
                    setup_filename!(
                        COMBINED_VERIFIED_POK_AND_CORRECTNESS_NEW_CHALLENGE_HASH_FILENAME,
                        setup.setup_id
                    ),
                    self.subgroup_check_mode,
                    false,
                );
            }
            // Verify the consistency of the entire combined contribution, making sure that the
            // correct ratios hold between elements.
            if self.phase == Phase::Phase1 {
                phase1_cli::transform_ratios(
                    setup_filename!(
                        COMBINED_VERIFIED_POK_AND_CORRECTNESS_NEW_CHALLENGE_FILENAME,
                        setup.setup_id
                    ),
                    upgrade_correctness_check_config(
                        DEFAULT_VERIFY_CHECK_INPUT_CORRECTNESS,
                        self.force_correctness_checks,
                    ),
                    &parameters,
                );
            } else {
                phase2_cli::verify::<E>(
                    setup_filename!(INITIAL_CHALLENGE_FILENAME, setup.setup_id),
                    setup_filename!(INITIAL_CHALLENGE_HASH_FILENAME, setup.setup_id),
                    upgrade_correctness_check_config(
                        DEFAULT_VERIFY_CHECK_INPUT_CORRECTNESS,
                        self.force_correctness_checks,
                    ),
                    setup_filename!(
                        COMBINED_VERIFIED_POK_AND_CORRECTNESS_NEW_CHALLENGE_FILENAME,
                        setup.setup_id
                    ),
                    setup_filename!(
                        COMBINED_VERIFIED_POK_AND_CORRECTNESS_NEW_CHALLENGE_HASH_FILENAME,
                        setup.setup_id
                    ),
                    upgrade_correctness_check_config(
                        DEFAULT_VERIFY_CHECK_OUTPUT_CORRECTNESS,
                        self.force_correctness_checks,
                    ),
                    setup_filename!(COMBINED_NEW_CHALLENGE_FILENAME, setup.setup_id),
                    setup_filename!(COMBINED_NEW_CHALLENGE_HASH_FILENAME, setup.setup_id),
                    self.subgroup_check_mode,
                    true,
                );
            }
        }
        Ok(())
    }

    fn run(&self) -> Result<()> {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();

        if self.transcript.rounds.is_empty() {
            return Ok(());
        }

        // Check that all rounds have the same number of setups.
        if !self
            .transcript
            .rounds
            .iter()
            .all(|ceremony| ceremony.setups.len() == self.transcript.rounds[0].setups.len())
        {
            return Err(VerifyTranscriptError::NotAllRoundsHaveSameNumberOfSetups.into());
        }

        let setups_len = self.transcript.rounds[0].setups.len();
        for i in 0..setups_len {
            let parameters = &self.transcript.rounds[0].setups[i].parameters;
            match parameters.curve_kind.as_str() {
                "bw6" => self.verify_setup::<BW6_761>(i, &rt)?,
                "bls12_377" => self.verify_setup::<Bls12_377>(i, &rt)?,
                "mnt4_753" => self.verify_setup::<MNT4_753>(i, &rt)?,
                "mnt6_753" => self.verify_setup::<MNT6_753>(i, &rt)?,
                _ => {
                    return Err(VerifyTranscriptError::UnsupportedCurveKindError(
                        parameters.curve_kind.clone(),
                    )
                    .into())
                }
            }
        }
        info!("Finished verification successfully!");
        Ok(())
    }
}

fn main() {
    tracing_subscriber::fmt().json().init();

    let opts: VerifyTranscriptOpts = VerifyTranscriptOpts::parse_args_default_or_exit();

    let verifier = TranscriptVerifier::new(&opts)
        .expect("Should have been able to create a transcript verifier");
    verifier.run().expect("Should have run successfully");
}
