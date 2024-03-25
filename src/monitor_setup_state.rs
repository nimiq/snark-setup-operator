use anyhow::{Ok, Result};
use chrono::{DateTime, Duration, Utc};
use nimiq_keys::PublicKey;

use crate::{
    data_structs::{Chunk, Contribution, ContributionMetadata},
    error::VerifyTranscriptError,
    monitor_logger::{Logger, NotificationPriority},
};

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
                panic!("Unwrapped empty chunk state!");
            }
        }
    }

    pub async fn update(
        &mut self,
        new_chunk: &Chunk,
        logger: &Logger,
        ceremony_update: DateTime<Utc>,
        pending_verification_timeout: Duration,
        contribution_timeout: Duration,
    ) -> Result<()> {
        let new_last_contribution = new_chunk.contributions.last();

        match (&self, new_last_contribution) {
            // First contribution for the chunk.
            (ChunkState::EmptyState(), Some(new_last_contribution)) => {
                // Simply replace the current value.
                *self = new_last_contribution.try_into()?;
            }
            // All chunk contributions were deleted.
            (ChunkState::RecordedState { .. }, None) => {
                // Simply reset the current value.
                *self = ChunkState::EmptyState();
            }
            // Both versions have contributions.
            (
                ChunkState::RecordedState {
                    last_contributor,
                    metadata,
                },
                Some(new_last_contribution),
            ) => {
                //  We must check if progress has been made before replacing value.
                let new_chunk_state: ChunkState = new_last_contribution.try_into()?;
                let (new_contributor, new_contribution_metadata) =
                    new_chunk_state.unwrap_recorded_contribution_state();

                // If the state has the same last contribution has before.
                if last_contributor == &new_contributor {
                    // If there is a finished contribution, we want to check if the verification is pending for too long.
                    if metadata.contributed_time == new_contribution_metadata.contributed_time {
                        if metadata.verified_time.is_none()
                            && new_contribution_metadata.verified_time.is_none()
                        {
                            if let Some(contributed_time) = metadata.contributed_time {
                                // Log that we are pending verification for too long.
                                if ceremony_update - contributed_time
                                    >= pending_verification_timeout
                                {
                                    logger
                                        .log_and_notify_slack(
                                            &format!(
                                                "Chunk is pending verification! ChunkID: {} Contributor: {}",
                                                new_chunk.unique_chunk_id, new_contributor
                                            ),
                                            NotificationPriority::Error,
                                        )
                                        .await;
                                }
                            }
                        }
                    } else {
                        // If the current contribution is not finished, then we must check if the lock is held for too long.
                        if let Some(new_chunk_metadata) = new_chunk.metadata.as_ref() {
                            if let Some(lock_time) = new_chunk_metadata.lock_holder_time {
                                // Log that a lock is being held for too long.
                                if ceremony_update - lock_time >= contribution_timeout {
                                    logger
                                    .log_and_notify_slack(
                                        &format!(
                                            "Chunk lock held for too long! ChunkID: {} Contributor: {} Time: {}",
                                            new_chunk.unique_chunk_id, new_contributor,lock_time
                                        ),
                                        NotificationPriority::Error,
                                    )
                                    .await;
                                }
                            }
                        }
                    }
                }

                // Replace the current value.
                *self = new_chunk_state;
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
