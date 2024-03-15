use nimiq_keys::PublicKey;
// use rayon::iter::{IndexedParallelIterator, IntoParallelRefMutIterator, ParallelIterator};
use snark_setup_operator::{
    data_structs::{Ceremony, Contribution, ContributionMetadata, Response, UniqueChunkId},
    error::VerifyTranscriptError,
};

use anyhow::{Ok, Result};
use chrono::{DateTime, Duration, Utc};
use gumdrop::Options;
use std::collections::{HashMap, HashSet};
use tracing::{error, info, warn};
use url::Url;

#[derive(Debug)]
pub struct SetupContributionState {
    finished: bool,
    chunks_state: Vec<ChunkState>,
}

impl SetupContributionState {
    fn new(num_chunks: usize) -> Self {
        Self {
            finished: false,
            chunks_state: vec![ChunkState::EmptyState(); num_chunks],
        }
    }
}

#[derive(Debug, Clone)]
pub enum ChunkState {
    EmptyState(),
    RecordedState {
        last_contributor: PublicKey,
        metadata: ContributionMetadata,
    },
}
impl TryFrom<&Contribution> for ChunkState {
    type Error = anyhow::Error;

    fn try_from(contribution: &Contribution) -> Result<Self> {
        Ok(Self::RecordedState {
            last_contributor: contribution.contributor_id()?,
            metadata: contribution
                .metadata
                .clone()
                .ok_or(VerifyTranscriptError::ContributorDataIsNoneError)?,
        })
    }
}

impl ChunkState {
    fn update(&mut self, new_last_contribution: Option<&Contribution>) -> Result<()> {
        match (&self, new_last_contribution) {
            (ChunkState::EmptyState(), Some(new_last_contribution)) => {
                *self = new_last_contribution.try_into()?;
            }
            (
                ChunkState::RecordedState {
                    last_contributor,
                    metadata,
                },
                Some(new_last_contribution),
            ) => {
                let new_contribution_id = new_last_contribution.contributor_id().unwrap();

                // Update last contribution.
                *self = new_last_contribution.try_into()?;
            }
            (ChunkState::RecordedState { .. }, None) => {
                // All chunk contributions were deleted.
                *self = ChunkState::EmptyState();
            }
            (ChunkState::EmptyState(), None) => {}
        };

        Ok(())
    }
}

#[derive(Debug, Default)]
pub struct RoundState {
    /// The setup and chunks contribution state.
    pub setups_contribution_state: Vec<SetupContributionState>,

    /// Paxs that have started contributing and are not finished yet.
    pub paxs_last_contribution: HashMap<PublicKey, UniqueChunkId>,
    /// Paxs that have finished contributing to all chunks.
    pub paxs_finished_contribution: HashSet<PublicKey>,
}

impl RoundState {
    fn init(&mut self, ceremony: &Ceremony) {
        *self = Self::default();
        ceremony.setups.iter().for_each(|setup| {
            self.setups_contribution_state
                .push(SetupContributionState::new(setup.chunks.len()))
        });
    }

    fn reset(&mut self) {
        self.setups_contribution_state
            .iter_mut()
            .for_each(|setup_state| {
                *setup_state = SetupContributionState::new(setup_state.chunks_state.len())
            });

        self.paxs_last_contribution = HashMap::new();
        self.paxs_finished_contribution = HashSet::new();
    }

    /// Returns true if the current round is complete.
    /// It assumes that setups completion status has all the setups registered.
    fn is_round_complete(&self) -> bool {
        self.setups_contribution_state
            .iter()
            .all(|setup| setup.finished)
    }

    // Sanity check on the setups number and respective chunk number.
    // If the ceremony has a different setup, the current data must be overwritten.
    fn check_and_initialize_setups(&mut self, ceremony: &Ceremony, first_round: bool) {
        let equal_setup_and_chunk_sizes = ceremony.setups.len()
            == self.setups_contribution_state.len()
            && self
                .setups_contribution_state
                .iter()
                .enumerate()
                .map(|(i, setup_state)| {
                    ceremony.setups[i].chunks.len() == setup_state.chunks_state.len()
                })
                .all(|same_chunk_number| same_chunk_number);

        if !equal_setup_and_chunk_sizes {
            if !self.setups_contribution_state.is_empty() && !first_round {
                error!("A change of setups and or chunk sizes was detected!");
            }

            // Creates the setup and respective chunks state based on the ceremony's configuration.
            self.init(ceremony);
        }
    }

    fn update_setups_state(&mut self, ceremony: &Ceremony) -> Result<bool> {
        let participant_ids: HashSet<_> = ceremony
            .contributor_ids
            .iter()
            .map(|pk| pk.clone())
            .collect();

        let mut is_round_complete = true;
        for (i, setup_state) in self.setups_contribution_state.iter_mut().enumerate() {
            let new_chunks = &ceremony.setups[i].chunks;
            let mut setup_finished = true;

            // TODO make parallel iter.
            setup_state
                .chunks_state
                .iter_mut()
                .enumerate()
                .for_each(|(j, chunk_state)| {
                    chunk_state
                        .update(new_chunks[j].contributions.last())
                        .unwrap();

                    // TODO Update last contribution and if new entry then log started contributing.
                    // TODO Update paxs is stuck on the same last contribution for too long.
                    // TODO Update finished pax and log

                    if setup_finished {
                        let verified_participant_ids_in_chunk: HashSet<_> = new_chunks[j]
                            .contributions
                            .iter()
                            .filter(|c| c.verified)
                            .filter_map(|c| c.contributor_id)
                            .collect();
                        if participant_ids.len() > verified_participant_ids_in_chunk.len()
                            && !participant_ids
                                .iter()
                                .all(|p| verified_participant_ids_in_chunk.contains(p))
                        {
                            setup_finished = false;
                        }
                    }
                });
            setup_state.finished = setup_finished;

            is_round_complete &= setup_state.finished;
        }

        Ok(is_round_complete)
    }
}

#[derive(Debug, Options, Clone)]
pub struct MonitorOpts {
    help: bool,
    #[options(
        help = "the url of the coordinator API",
        default = "http://localhost:8080"
    )]
    pub coordinator_url: String,
    #[options(help = "polling interval in minutes", default = "3")]
    pub polling_interval: u64,
    #[options(help = "chunk lock timeout in minutes", default = "10")]
    pub chunk_timeout: i64,
    #[options(help = "ceremony timeout in minutes", default = "60")]
    pub ceremony_timeout: i64,
}

pub struct Monitor {
    // Settings
    pub server_url: Url,
    pub timeout: Duration,
    pub ceremony_timeout: Duration,

    // Last changed values in the ceremony
    pub ceremony_version: u64,
    pub ceremony_update: DateTime<Utc>,
    pub round: u64,

    /// The state of the round of contributions.
    pub round_state: RoundState,
}

impl Monitor {
    pub fn new(opts: &MonitorOpts) -> Result<Self> {
        Ok(Self {
            server_url: Url::parse(&opts.coordinator_url)?.join("ceremony")?,
            timeout: Duration::minutes(opts.chunk_timeout),
            ceremony_timeout: Duration::minutes(opts.ceremony_timeout),
            ceremony_version: 0,
            ceremony_update: chrono::Utc::now(),
            round: 0,
            round_state: RoundState::default(),
        })
    }

    async fn run(&mut self) -> Result<()> {
        let response = reqwest::get(self.server_url.as_str())
            .await?
            .error_for_status()?;
        let data = response.text().await?;
        let ceremony: Ceremony = serde_json::from_str::<Response<Ceremony>>(&data)?.result;

        let new_ceremony_version = self.check_and_update_ceremony_version(&ceremony)?;
        if new_ceremony_version {
            self.check_and_update_round_number(&ceremony);
            self.update_setups_chunks_state(&ceremony)?;
        }

        Ok(())
    }

    pub fn check_and_update_ceremony_version(&mut self, ceremony: &Ceremony) -> Result<bool> {
        let current_time = chrono::Utc::now();
        let elapsed = current_time - self.ceremony_update;
        let new_version = ceremony.version != self.ceremony_version;

        // If the we are running for the first time or the ceremony has changed setups or chunk sizes
        // the monitor must be (re)initialized.
        self.round_state
            .check_and_initialize_setups(ceremony, self.round == 0);

        if new_version {
            self.ceremony_update = current_time;
            self.ceremony_version = ceremony.version;
        } else {
            if self.ceremony_timeout <= elapsed {
                warn!(
                    "Ceremony progress is stuck at version {:?} for {:?} minutes",
                    ceremony.version,
                    elapsed.num_minutes()
                );
            }
        }

        Ok(new_version)
    }

    pub fn check_and_update_round_number(&mut self, ceremony: &Ceremony) {
        if self.round == ceremony.round {
            return;
        }

        // If we never notified that the round is complete before, we announce it now.
        if !self.round_state.is_round_complete() {
            info!("Round {}: All setups are complete!", self.round);
        }

        // Sets new round and resets the state of each setup and chunk.
        self.round_state.reset();
        self.round = ceremony.round;

        info!("Round {}: New started!", self.round);
    }

    pub fn update_setups_chunks_state(&mut self, ceremony: &Ceremony) -> Result<()> {
        let is_round_complete = self.round_state.update_setups_state(ceremony)?;
        if is_round_complete {
            info!("Round {}: All setups are complete!", self.round);
        }

        Ok(())
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt().json().init();

    let opts: MonitorOpts = MonitorOpts::parse_args_default_or_exit();

    let mut monitor = Monitor::new(&opts).expect("Should have been able to create a monitor.");
    let mut monitor_interval =
        tokio::time::interval(std::time::Duration::from_secs(60 * opts.polling_interval));
    loop {
        monitor_interval.tick().await;

        match monitor.run().await {
            Err(e) => error!("Got error from monitor: {}", e.to_string()),
            _ => {}
        }
    }
}
