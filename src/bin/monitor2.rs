use nimiq_keys::PublicKey;
// use rayon::iter::{IndexedParallelIterator, IntoParallelRefMutIterator, ParallelIterator};
use snark_setup_operator::{
    data_structs::{Ceremony, Chunk, Contribution, ContributionMetadata, Response, UniqueChunkId},
    error::VerifyTranscriptError,
};

use anyhow::{Ok, Result};
use chrono::{DateTime, Duration, Utc};
use gumdrop::Options;
use std::collections::{HashMap, HashSet};
use tracing::{error, info, warn};
use url::Url;

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
    fn unwrap_recorded_contribution_state(&self) -> (PublicKey, ContributionMetadata) {
        match self {
            ChunkState::RecordedState {
                last_contributor,
                metadata,
            } => {
                return (last_contributor.clone(), metadata.clone());
            }
            ChunkState::EmptyState() => {
                panic!("Empty chunk state");
            }
        }
    }
}

impl ChunkState {
    fn update(&mut self, new_chunk: &Chunk) -> Result<()> {
        let new_last_contribution = new_chunk.contributions.last();

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
                let new_chunk_state: ChunkState = new_last_contribution.try_into()?;
                let (new_contributor, new_metadata) =
                    new_chunk_state.unwrap_recorded_contribution_state();

                // If chunk is pending verification for too long we log it.
                if last_contributor == &new_contributor
                    && metadata.contributed_time.is_some()
                    && metadata.verified_time.is_none()
                    && metadata.contributed_time == new_metadata.contributed_time
                    && new_metadata.verified_time.is_none()
                {
                    warn!(
                        "Chunk is pending verification! ChunkID: {} Contributor: {}", // TODO dynamic threshold!
                        new_chunk.unique_chunk_id, new_contributor
                    );
                }

                // Update last contribution.
                *self = new_chunk_state;
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

#[derive(Debug)]
pub struct SetupContributionState {
    finished: bool,
    chunks_state: Vec<ChunkState>,
}

impl SetupContributionState {
    pub fn new(num_chunks: usize) -> Self {
        Self {
            finished: false,
            chunks_state: vec![ChunkState::EmptyState(); num_chunks],
        }
    }
}

#[derive(Debug, Clone)]
pub struct ParticipantState {
    contributed_chunks_counter: usize,
    last_contribution: (UniqueChunkId, DateTime<Utc>),
}

impl ParticipantState {
    pub fn new(unique_chunk_id: UniqueChunkId, contribution_time: DateTime<Utc>) -> Self {
        Self {
            contributed_chunks_counter: 1,
            last_contribution: (unique_chunk_id, contribution_time),
        }
    }

    pub fn reset_counter(&mut self) {
        self.contributed_chunks_counter = 0;
    }

    pub fn update_participant_contributions_state(
        &mut self,
        unique_chunk_id: &UniqueChunkId,
        contribution_time: DateTime<Utc>,
    ) -> &Self {
        if self.last_contribution.1 < contribution_time {
            self.last_contribution = (unique_chunk_id.clone(), contribution_time);
        }
        self.contributed_chunks_counter += 1;

        self
    }

    pub fn is_finished_contributing(&self, total_chunks: usize) -> bool {
        self.contributed_chunks_counter == total_chunks
    }
}

#[derive(Debug, Default)]
pub struct ParticipantsContributionState {
    /// The participants contribution state including the last contribution time
    /// and chunk as well as the total chunks contributed so far.
    current_state: HashMap<PublicKey, ParticipantState>,
    /// The participants contribution state of the last ceremony version.
    /// This is needed to understand if a participant is stuck on the same chunk for too long
    last_ceremony_version_state: HashMap<PublicKey, ParticipantState>,
}

impl ParticipantsContributionState {
    /// This copies the backs up the state to the `last_ceremony_iteration_state` and resets
    /// the chunks contribution counters on the current state.
    /// This function must be called before applying any chunk from a new ceremony version.
    pub fn new_ceremony_update(&mut self, participant_ids: &HashSet<PublicKey>) {
        self.last_ceremony_version_state = self.current_state.clone();
        for participant_id in participant_ids {
            if let Some(state) = self.current_state.get_mut(participant_id) {
                state.reset_counter();
            }
        }
    }

    /// Updates the current participants state with the new chunk contributions data.
    /// This assumes that the counters have been reset and the old state has been copied
    /// before updating with the first chunk.
    pub fn update(&mut self, new_chunk: &Chunk, total_chunks: usize) {
        // Update last contribution.
        // If it's the first contribution or the last one we log it.
        new_chunk
            .contributions
            .iter()
            .filter_map(|c| match (c.contributor_id, c.metadata.as_ref()) {
                (Some(contributor_id), Some(metadata)) => {
                    if let Some(contribution_time) = metadata.contributed_time {
                        return Some((contributor_id, contribution_time));
                    }
                    None
                }
                (_, _) => None,
            })
            .for_each(|(contributor, contribution_time)| {
                let new_participant_state = self
                    .current_state
                    .entry(contributor)
                    .or_insert_with(|| {
                        info!("New participant started contributing! {}", contributor);

                        ParticipantState::new(
                            new_chunk.unique_chunk_id.clone(),
                            contribution_time.clone(),
                        )
                    })
                    .update_participant_contributions_state(
                        &new_chunk.unique_chunk_id,
                        contribution_time,
                    );

                if new_participant_state.is_finished_contributing(total_chunks) {
                    info!("Participant finished contributing! {}", contributor);
                }
            });
    }

    /// Logs all the paxs that are on the same last contribution as in the previous iteration.
    /// This should only be called after applying all chunks.
    pub fn check_for_stuck_paxs(&self, participant_ids: &HashSet<PublicKey>, total_chunks: usize) {
        for participant_id in participant_ids.iter() {
            let old_state = self.last_ceremony_version_state.get(participant_id);
            let new_state = self.current_state.get(participant_id);
            match (old_state, new_state) {
                (Some(old_state), Some(new_state)) => {
                    if !new_state.is_finished_contributing(total_chunks)
                        && new_state.last_contribution == old_state.last_contribution
                    {
                        warn!("Participant is stuck! {}", participant_id); // TODO dynamic threshold.
                    }
                }
                (_, _) => {}
            }
        }
    }
}

#[derive(Debug, Default)]
pub struct RoundState {
    /// The total number of chunks of the ceremony.
    total_chunks: usize,

    /// The setup and chunks contribution state.
    pub setups_contribution_state: Vec<SetupContributionState>,

    /// Alls paxs that have started contributing and their last contribution data.
    pub paxs_contribution_state: ParticipantsContributionState,
}

impl RoundState {
    fn init(&mut self, ceremony: &Ceremony) {
        *self = Self::default();
        ceremony.setups.iter().for_each(|setup| {
            self.total_chunks += setup.chunks.len();
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

        self.paxs_contribution_state = ParticipantsContributionState::default();
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

    fn update_round_state(&mut self, ceremony: &Ceremony) -> Result<bool> {
        let participant_ids: HashSet<_> = ceremony
            .contributor_ids
            .iter()
            .map(|pk| pk.clone())
            .collect();

        // Prepares the participants state for a new ceremony version.
        self.paxs_contribution_state
            .new_ceremony_update(&participant_ids);

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
                    let new_chunk = &new_chunks[j];

                    chunk_state.update(new_chunk).unwrap();

                    // Update participants last and total amount of contribution.
                    self.paxs_contribution_state
                        .update(new_chunk, self.total_chunks);

                    if setup_finished {
                        let verified_participant_ids_in_chunk: HashSet<_> = new_chunk
                            .contributions
                            .iter()
                            .filter_map(
                                |c: &Contribution| if c.verified { c.contributor_id } else { None },
                            )
                            .collect();

                        if participant_ids
                            .difference(&verified_participant_ids_in_chunk)
                            .count()
                            > 0
                        {
                            setup_finished = false;
                        }
                    }
                });
            setup_state.finished = setup_finished;

            is_round_complete &= setup_state.finished;
        }

        // Log participants that are stuck on the same contribution.
        if !is_round_complete {
            self.paxs_contribution_state
                .check_for_stuck_paxs(&participant_ids, self.total_chunks);
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
        let is_round_complete = self.round_state.update_round_state(ceremony)?;
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
