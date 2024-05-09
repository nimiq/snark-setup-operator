use chrono::{DateTime, Duration, Utc};
use nimiq_keys::PublicKey;
use std::collections::{HashMap, HashSet};

use crate::{
    data_structs::{Chunk, UniqueChunkId},
    monitor_logger::{Logger, NotificationPriority},
};

#[derive(Debug, Clone)]
pub struct ParticipantState {
    contributed_chunks_counter: usize,
    last_contribution: (UniqueChunkId, DateTime<Utc>),
    // Records if the participant was stuck on the last run.
    // We use this to avoid spamming with equal alerts.
    is_stuck: bool,
}

impl ParticipantState {
    fn new(unique_chunk_id: UniqueChunkId, contribution_time: DateTime<Utc>) -> Self {
        Self {
            contributed_chunks_counter: 1,
            last_contribution: (unique_chunk_id, contribution_time),
            is_stuck: false,
        }
    }

    fn reset_counter(&mut self) {
        self.contributed_chunks_counter = 0;
    }

    async fn update_participant_contributions_state(
        &mut self,
        unique_chunk_id: &UniqueChunkId,
        contribution_time: DateTime<Utc>,
        contributor_id: &PublicKey,
        logger: &Logger,
    ) {
        if self.last_contribution.1 < contribution_time {
            self.last_contribution = (unique_chunk_id.clone(), contribution_time);
            if self.is_stuck {
                logger
                    .log_and_notify_slack(
                        format!("Participant got unstuck! {}", contributor_id),
                        NotificationPriority::Resolved,
                    )
                    .await;
            }
            self.is_stuck = false;
        }
        self.contributed_chunks_counter += 1;
    }

    fn is_finished_contributing(&self, total_chunks: usize) -> bool {
        self.contributed_chunks_counter == total_chunks
    }
}

#[derive(Debug, Default)]
pub struct ParticipantsContributionState {
    /// The participants contribution state including the last contribution time
    /// and chunk as well as the total chunks contributed so far.
    current_participants_state: HashMap<PublicKey, ParticipantState>,
    /// The participants contribution state of the last ceremony version.
    /// This is needed to understand if a participant is stuck on the same chunk for too long
    last_ceremony_version_state: HashMap<PublicKey, ParticipantState>,
}

impl ParticipantsContributionState {
    /// The number of ongoing contributing participants.
    /// Returns total participants that started contributing and haven't finished yet.
    pub fn get_active_participants_count(&self, total_chunks: usize) -> usize {
        self.current_participants_state
            .iter()
            .filter(|(_, state)| !state.is_finished_contributing(total_chunks))
            .count()
    }

    /// The number of participants that have started contributing.
    /// Returns total participants that started contributing including the ones that concluded all chunks.
    pub fn get_total_contributing_participants(&self) -> usize {
        self.current_participants_state.keys().count()
    }

    /// This copies the backs up the state to the `last_ceremony_iteration_state` and resets
    /// the chunks contribution counters on the current state.
    /// This function must be called before applying any chunk from a new ceremony version.
    pub fn new_ceremony_update(&mut self, participant_ids: &HashSet<PublicKey>) {
        self.last_ceremony_version_state = self.current_participants_state.clone();
        for participant_id in participant_ids {
            if let Some(state) = self.current_participants_state.get_mut(participant_id) {
                state.reset_counter();
            }
        }
    }

    /// Updates the current participants state with the new chunk contributions data.
    /// This assumes that the counters have been reset and the old state has been copied
    /// before updating with the first chunk.
    pub async fn update(&mut self, logger: &Logger, new_chunk: &Chunk) {
        for (contributor_id, contribution_time) in new_chunk.contributions.iter().filter_map(|c| {
            match (c.contributor_id, c.metadata.as_ref()) {
                (Some(contributor_id), Some(metadata)) => {
                    if let Some(contribution_time) = metadata.contributed_time {
                        return Some((contributor_id, contribution_time));
                    }
                    None
                }
                (_, _) => None,
            }
        }) {
            if let Some(participant_state) =
                self.current_participants_state.get_mut(&contributor_id)
            {
                // Update last contribution.
                participant_state
                    .update_participant_contributions_state(
                        &new_chunk.unique_chunk_id,
                        contribution_time,
                        &contributor_id,
                        logger,
                    )
                    .await;
            } else {
                // When it's the first one we insert it and log it.
                self.current_participants_state.insert(
                    contributor_id,
                    ParticipantState::new(
                        new_chunk.unique_chunk_id.clone(),
                        contribution_time.clone(),
                    ),
                );
                logger
                    .log_and_notify_slack(
                        format!("New participant started contributing! {}", contributor_id),
                        NotificationPriority::Info,
                    )
                    .await;
            }
        }
    }

    /// Logs all the paxs that are on the same last contribution as in the previous iteration.
    /// This should only be called after applying all chunks.
    pub async fn check_for_stuck_paxs(
        &mut self,
        participant_ids: &HashSet<PublicKey>,
        total_chunks: usize,
        logger: &Logger,
        ceremony_update: DateTime<Utc>,
        same_contribution_timeout: Duration,
    ) {
        for participant_id in participant_ids.iter() {
            let old_state = self.last_ceremony_version_state.get(participant_id);
            let new_state = self.current_participants_state.get_mut(participant_id);
            match (old_state, new_state) {
                (Some(old_state), Some(new_state)) => {
                    // If the participant is not finished we check for timeouts.
                    if !new_state.is_finished_contributing(total_chunks) {
                        // Detect that the participant is on the same chunk for too long.
                        let elapse = ceremony_update - new_state.last_contribution.1;
                        if !old_state.is_stuck
                            && new_state.last_contribution == old_state.last_contribution
                            && elapse >= same_contribution_timeout
                        {
                            new_state.is_stuck = true;
                            logger
                                .log_and_notify_slack(
                                    format!(
                                        "Participant {} is stuck for {}min!",
                                        participant_id,
                                        elapse.num_minutes()
                                    ),
                                    NotificationPriority::Warning,
                                )
                                .await;
                        }
                    } else {
                        // If the participant is finished we log it only once.
                        if !old_state.is_finished_contributing(total_chunks) {
                            logger
                                .log_and_notify_slack(
                                    format!(
                                        "Participant finished contributing! {}",
                                        participant_id
                                    ),
                                    NotificationPriority::Resolved,
                                )
                                .await;
                        }
                    }
                }
                (None, Some(new_state)) => {
                    // When it's the first iteration we only need to log if the participant has finished.
                    if new_state.is_finished_contributing(total_chunks) {
                        logger
                            .log_and_notify_slack(
                                format!("Participant finished contributing! {}", participant_id),
                                NotificationPriority::Resolved,
                            )
                            .await;
                    }
                }
                (_, _) => {}
            }
        }
    }
}
