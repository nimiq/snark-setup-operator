use chrono::{DateTime, Duration, Utc};
use nimiq_keys::PublicKey;
use std::collections::{HashMap, HashSet};
use tracing::{info, warn};

use crate::data_structs::{Chunk, UniqueChunkId};

#[derive(Debug, Clone)]
pub struct ParticipantState {
    contributed_chunks_counter: usize,
    last_contribution: (UniqueChunkId, DateTime<Utc>),
}

impl ParticipantState {
    fn new(unique_chunk_id: UniqueChunkId, contribution_time: DateTime<Utc>) -> Self {
        Self {
            contributed_chunks_counter: 0,
            last_contribution: (unique_chunk_id, contribution_time),
        }
    }

    fn reset_counter(&mut self) {
        self.contributed_chunks_counter = 0;
    }

    fn update_participant_contributions_state(
        &mut self,
        unique_chunk_id: &UniqueChunkId,
        contribution_time: DateTime<Utc>,
    ) {
        if self.last_contribution.1 < contribution_time {
            self.last_contribution = (unique_chunk_id.clone(), contribution_time);
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
    pub fn update(&mut self, new_chunk: &Chunk) {
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
            .for_each(|(contributor_id, contribution_time)| {
                self.current_participants_state
                    .entry(contributor_id)
                    .or_insert_with(|| {
                        info!("New participant started contributing! {}", contributor_id);

                        ParticipantState::new(
                            new_chunk.unique_chunk_id.clone(),
                            contribution_time.clone(),
                        )
                    })
                    .update_participant_contributions_state(
                        &new_chunk.unique_chunk_id,
                        contribution_time,
                    );
            });
    }

    /// Logs all the paxs that are on the same last contribution as in the previous iteration.
    /// This should only be called after applying all chunks.
    pub fn check_for_stuck_paxs(
        &self,
        participant_ids: &HashSet<PublicKey>,
        total_chunks: usize,
        ceremony_update: DateTime<Utc>,
        last_contribution_timeout: Duration,
    ) {
        for participant_id in participant_ids.iter() {
            let old_state = self.last_ceremony_version_state.get(participant_id);
            let new_state = self.current_participants_state.get(participant_id);
            match (old_state, new_state) {
                (Some(old_state), Some(new_state)) => {
                    // Detect that the participant is on the same chunk for too long.
                    let elapse = ceremony_update - new_state.last_contribution.1;
                    if !new_state.is_finished_contributing(total_chunks) {
                        if new_state.last_contribution == old_state.last_contribution
                            && elapse >= last_contribution_timeout
                        {
                            warn!(
                                "Participant {} is stuck for {}min {}s!",
                                participant_id,
                                elapse.num_minutes(),
                                elapse.num_seconds()
                            );
                        }
                    } else {
                        // Log that the participant finished contributing only once.
                        if !old_state.is_finished_contributing(total_chunks) {
                            info!("Participant finished contributing! {}", participant_id);
                        }
                    }
                }
                (_, _) => {}
            }
        }
    }
}
