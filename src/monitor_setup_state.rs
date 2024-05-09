use anyhow::{Ok, Result};
use chrono::{DateTime, Duration, Utc};
use nimiq_keys::PublicKey;

use crate::{
    data_structs::{Chunk, Contribution, ContributionMetadata, UniqueChunkId},
    error::VerifyTranscriptError,
    monitor_logger::{Logger, NotificationPriority},
};

impl Contribution {
    fn get_recorded_contribution_state(&self) -> Result<(PublicKey, ContributionMetadata)> {
        let last_contributor = self.contributor_id()?;

        Ok((
            last_contributor,
            self.metadata
                .clone()
                .ok_or(VerifyTranscriptError::ContributorDataIsNoneError)?,
        ))
    }

    fn get_state(&self) -> Result<Option<RecordedState>> {
        if let Some(last_contributor) = self.contributor_id {
            let metadata = self
                .metadata
                .clone()
                .ok_or(VerifyTranscriptError::ContributorDataIsNoneError)?;

            Ok(Some(RecordedState {
                last_contributor,
                metadata,
                verifying_timeout: false,
                contributing_timeout: false,
            }))
        } else {
            Ok(None)
        }
    }
}

#[derive(Debug, Clone)]
pub struct RecordedState {
    last_contributor: PublicKey,
    metadata: ContributionMetadata,
    // Records of whether the verification or last contribution had a timeout on the last run.
    // We use this to avoid spamming with equal alerts.
    verifying_timeout: bool,
    contributing_timeout: bool,
}

impl RecordedState {
    async fn update_existing_state_with_new_state(
        &mut self,
        logger: &Logger,
        new_chunk: &Chunk,
        new_last_contribution: &Contribution,
        ceremony_update: DateTime<Utc>,
        pending_verification_timeout: (Duration, bool),
        contribution_lock_timeout: Duration,
    ) -> Result<()> {
        // We take the last contribution data.
        let (mut new_contributor, mut new_contribution_metadata) =
            new_last_contribution.get_recorded_contribution_state()?;
        // If a new lock holder for the chunk then we take that information since it's the most recent one.
        // Note: We check that the last contribution is verified so that a verifier's lock does not get mistaken with a participant.
        if let Some(lock_holder) = new_chunk.lock_holder {
            if new_contribution_metadata.verified_time.is_some() {
                new_contributor = lock_holder;
                new_contribution_metadata = ContributionMetadata {
                    contributed_time: None,
                    contributed_lock_holder_time: new_chunk
                        .metadata
                        .as_ref()
                        .unwrap()
                        .lock_holder_time,
                    verified_time: None,
                    verified_lock_holder_time: None,
                };
            }
        };

        let old_verifying_timeout = self.verifying_timeout;
        let old_contributing_timeout = self.contributing_timeout;
        let mut verifying_elapsed_time = Duration::min_value();
        let mut contributing_elapsed_time = Duration::min_value();

        // If the state has the same last contribution has before.
        if self.last_contributor == new_contributor
            && self.metadata.contributed_time == new_contribution_metadata.contributed_time
        {
            // If there is a finished contribution, we want to check if the verification is pending for too long.
            if let Some(contributed_time) = self.metadata.contributed_time {
                if self.metadata.verified_time.is_none()
                    && new_contribution_metadata.verified_time.is_none()
                {
                    verifying_elapsed_time = ceremony_update - contributed_time;
                    // Log that we are pending verification for too long.
                    if verifying_elapsed_time >= pending_verification_timeout.0 {
                        self.verifying_timeout = true;
                    }
                } else if !new_contribution_metadata.verified_time.is_none() {
                    self.verifying_timeout = false;
                }
            } else {
                // Since the current contribution is not finished, we check if the lock is held for too long.
                if let Some(new_chunk_metadata) = new_chunk.metadata.as_ref() {
                    if let Some(lock_time) = new_chunk_metadata.lock_holder_time {
                        contributing_elapsed_time = ceremony_update - lock_time;
                        // Log that a lock is being held for too long.
                        if contributing_elapsed_time >= contribution_lock_timeout {
                            self.contributing_timeout = true;
                        }
                    } else {
                        self.contributing_timeout = false;
                    }
                }
            }
        } else {
            // Different contribution resets the timeouts.
            self.verifying_timeout = false;
            self.contributing_timeout = false;
        }

        // Only log if the verifiers are not overwhelmed. This avoids spam.
        if !pending_verification_timeout.1 {
            Self::log_update_verifying_timeout(
                old_verifying_timeout,
                self.verifying_timeout,
                logger,
                &new_chunk.unique_chunk_id,
                &self.last_contributor,
                &verifying_elapsed_time,
            )
            .await;
        }
        Self::log_update_contributing_timeout(
            old_contributing_timeout,
            self.contributing_timeout,
            logger,
            &new_chunk.unique_chunk_id,
            &self.last_contributor,
            &contributing_elapsed_time,
        )
        .await;
        self.last_contributor = new_contributor;
        self.metadata = new_contribution_metadata;

        Ok(())
    }

    async fn log_reset(&self, logger: &Logger, unique_chunk_id: &UniqueChunkId) {
        Self::log_update_contributing_timeout(
            self.contributing_timeout,
            false,
            logger,
            &unique_chunk_id,
            &self.last_contributor,
            &Duration::min_value(),
        )
        .await;
        Self::log_update_verifying_timeout(
            self.verifying_timeout,
            false,
            logger,
            &unique_chunk_id,
            &self.last_contributor,
            &Duration::min_value(),
        )
        .await;
    }

    async fn log_update_verifying_timeout(
        old_verifying_timeout: bool,
        new_verifying_timeout: bool,
        logger: &Logger,
        unique_chunk_id: &UniqueChunkId,
        old_contributor: &PublicKey,
        elapsed: &Duration,
    ) {
        match (&old_verifying_timeout, new_verifying_timeout) {
            (false, true) => {
                logger
                    .log_and_notify_slack(
                        format!( "Chunk is pending verification for {} hour(s)! ChunkID: {} Contributor: {}",
                            elapsed.num_hours(), unique_chunk_id, old_contributor),
                        NotificationPriority::Error,
                    )
                    .await;
            }
            (true, false) => {
                logger
                    .log_and_notify_slack(
                        format!(
                            "Chunk verification got solved! ChunkID: {} Contributor: {}",
                            unique_chunk_id, old_contributor,
                        ),
                        NotificationPriority::Resolved,
                    )
                    .await;
            }
            _ => {}
        }
    }

    async fn log_update_contributing_timeout(
        old_contributing_timeout: bool,
        new_contributing_timeout: bool,
        logger: &Logger,
        unique_chunk_id: &UniqueChunkId,
        old_contributor: &PublicKey,
        elapsed: &Duration,
    ) {
        match (&old_contributing_timeout, new_contributing_timeout) {
            (false, true) => {
                logger
                    .log_and_notify_slack(
                        format!(
                            "Chunk lock held for too long! ChunkID: {} Contributor: {} Time: {}min",
                            unique_chunk_id,
                            old_contributor,
                            elapsed.num_minutes()
                        ),
                        NotificationPriority::Error,
                    )
                    .await;
            }
            (true, false) => {
                logger
                    .log_and_notify_slack(
                        format!(
                            "Chunk lock timeout got solved! ChunkID: {} Contributor: {}",
                            unique_chunk_id, old_contributor,
                        ),
                        NotificationPriority::Resolved,
                    )
                    .await;
            }
            _ => {}
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct ChunkState {
    state: Option<RecordedState>,
}

impl ChunkState {
    pub fn is_verification_timeout(&self) -> bool {
        if let Some(chunk_state) = &self.state {
            return chunk_state.verifying_timeout;
        }

        false
    }

    pub async fn update(
        &mut self,
        new_chunk: &Chunk,
        logger: &Logger,
        ceremony_update: DateTime<Utc>,
        pending_verification_timeout: (Duration, bool),
        contribution_lock_timeout: Duration,
    ) -> Result<()> {
        let new_last_contribution = new_chunk.contributions.last();
        match (self.state.is_some(), new_last_contribution.is_some()) {
            // Nothing to update.
            (false, false) => {}
            // First contribution for the chunk.
            (false, true) => {
                // Simply replace the current value.
                self.state = new_last_contribution.unwrap().get_state()?;
            }
            // All contributions were deleted.
            (true, false) => {
                // Simply reset the current value.
                self.reset_state(logger, &new_chunk.unique_chunk_id).await;
            }
            // There's a current and a new state to compare and update.
            (true, true) => {
                if let Err(_) = self
                    .state
                    .as_mut()
                    .unwrap()
                    .update_existing_state_with_new_state(
                        logger,
                        new_chunk,
                        new_last_contribution.unwrap(),
                        ceremony_update,
                        pending_verification_timeout,
                        contribution_lock_timeout,
                    )
                    .await
                {
                    // This means there is no contributor so we simply reset the current value.
                    self.reset_state(logger, &new_chunk.unique_chunk_id).await;
                }
            }
        }

        Ok(())
    }

    async fn reset_state(&mut self, logger: &Logger, unique_chunk_id: &UniqueChunkId) {
        if let Some(ref state) = self.state {
            state.log_reset(logger, unique_chunk_id).await;
        }

        self.state = None;
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
            chunks_state: vec![ChunkState::default(); num_chunks],
        }
    }

    pub fn is_finished(&self) -> bool {
        self.finished
    }

    pub fn set_is_finished(&mut self, is_finished: bool) {
        self.finished = is_finished;
    }

    pub fn get_chunks_state_mut(&mut self) -> &mut Vec<ChunkState> {
        &mut self.chunks_state
    }

    pub fn get_chunks_state(&self) -> &Vec<ChunkState> {
        &self.chunks_state
    }
}
