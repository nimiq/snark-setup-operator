use anyhow::{Ok, Result};
use chrono::{DateTime, Duration, Utc};
use gumdrop::Options;
use std::{
    collections::HashSet,
    fmt::{Debug, Display},
    ops::Deref,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};
use url::Url;

use snark_setup_operator::{
    data_structs::{Ceremony, Contribution, Response},
    error::MonitorError,
    monitor_logger::{Logger, NotificationPriority},
    monitor_paxs_state::ParticipantsContributionState,
    monitor_setup_state::SetupContributionState,
};

#[derive(Debug, Default)]
pub struct Round {
    pub round: u64,
}

impl Display for Round {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.round + 1)
    }
}
impl Deref for Round {
    type Target = u64;

    fn deref(&self) -> &Self::Target {
        &self.round
    }
}
impl From<u64> for Round {
    fn from(value: u64) -> Self {
        Self { round: value }
    }
}

#[derive(Debug, Default)]
pub struct RoundState {
    pub round: Round,

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
        self.round = ceremony.round.into();
    }

    /// Returns true if the current round is complete.
    /// It assumes that setups completion status has all the setups registered.
    fn is_round_complete(&self) -> bool {
        self.setups_contribution_state
            .iter()
            .all(|setup| setup.is_finished())
    }

    // Sanity check on the setups number and respective chunk number.
    // If the ceremony has a different setup, the current data must be overwritten.
    async fn sanity_check_setups_and_chunks_size(
        &mut self,
        logger: &Logger,
        ceremony: &Ceremony,
    ) -> Result<()> {
        let equal_setup_and_chunk_sizes = ceremony.setups.len()
            == self.setups_contribution_state.len()
            && self
                .setups_contribution_state
                .iter()
                .enumerate()
                .map(|(i, setup_state)| {
                    ceremony.setups[i].chunks.len() == setup_state.get_chunks_state().len()
                })
                .all(|same_chunk_number| same_chunk_number);

        if !equal_setup_and_chunk_sizes {
            if !*self.round == 0 {
                logger
                    .log_and_notify_slack(
                        &format!("A change of setups and or chunk sizes was detected!"),
                        NotificationPriority::Error,
                    )
                    .await;

                return Err(MonitorError::ParametersDifferentBetweenRounds(
                    self.setups_contribution_state.len(),
                    ceremony.setups.len(),
                )
                .into());
            }
        }

        Ok(())
    }

    async fn check_and_update_round_number(&mut self, logger: &Logger, ceremony: &Ceremony) {
        if *self.round == ceremony.round
            && self
                .sanity_check_setups_and_chunks_size(logger, ceremony)
                .await
                .is_ok()
        {
            return;
        }
        // If there's a new round or the ceremony has changed setups or chunk sizes
        // the round state must be (re)initialized.

        // If we never notified that the round is complete before, we announce it now.
        if !self.is_round_complete() {
            logger
                .log_and_notify_slack(
                    &format!("Round {}: All setups are complete!", self.round),
                    NotificationPriority::Info,
                )
                .await;
        }

        // Sets new round and resets the state of each setup and participant.
        self.init(ceremony);

        logger
            .log_and_notify_slack(
                &format!("Round {}: New started!", self.round),
                NotificationPriority::Info,
            )
            .await;
    }

    async fn update_round_state(
        &mut self,
        ceremony: &Ceremony,
        ceremony_update: DateTime<Utc>,
        logger: &Logger,
        pending_verification_timeout: Duration,
        last_contribution_timeout: Duration,
    ) -> Result<()> {
        self.check_and_update_round_number(logger, ceremony).await;

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
            let setup_finished = Arc::new(AtomicBool::new(true));

            for new_chunk in new_chunks.iter() {
                // Update participants last and total amount of contribution.
                self.paxs_contribution_state.update(logger, new_chunk).await;
            }

            for (j, chunk_state) in setup_state.get_chunks_state_mut().iter_mut().enumerate() {
                let new_chunk = &new_chunks[j];

                chunk_state
                    .update(
                        new_chunk,
                        logger,
                        ceremony_update,
                        pending_verification_timeout,
                    )
                    .await
                    .unwrap();

                if setup_finished.load(Ordering::Relaxed) {
                    let verified_participant_ids_in_chunk: HashSet<_> = new_chunk
                        .contributions
                        .iter()
                        .filter_map(
                            |c: &Contribution| {
                                if c.verified {
                                    c.contributor_id
                                } else {
                                    None
                                }
                            },
                        )
                        .collect();

                    if participant_ids
                        .difference(&verified_participant_ids_in_chunk)
                        .count()
                        > 0
                    {
                        setup_finished.store(false, Ordering::Relaxed);
                    }
                }
            }

            setup_state.set_is_finished(setup_finished.load(Ordering::Relaxed));
            is_round_complete &= setup_state.is_finished();
        }

        // Log round is complete or the participants stuck on the same chunk.
        if !is_round_complete {
            // Log participants that are stuck on the same contribution.
            self.paxs_contribution_state
                .check_for_stuck_paxs(
                    &participant_ids,
                    self.total_chunks,
                    logger,
                    ceremony_update,
                    last_contribution_timeout,
                )
                .await;
        } else {
            logger
                .log_and_notify_slack(
                    &format!("Round {}: All setups are complete!", self.round),
                    NotificationPriority::Info,
                )
                .await;
        }

        Ok(())
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
    #[options(help = "the webhook url for slack notifications")]
    pub slack_webhook_url: String,
    #[options(help = "polling interval in minutes", default = "1")]
    pub polling_interval: u64,
    #[options(help = "ceremony timeout in minutes", default = "30")]
    pub ceremony_timeout: i64,

    #[options(help = "chunk pending verification timeout in minutes", default = "5")]
    pub pending_verification_timeout: i64,
    #[options(
        help = "participant's stuck on the same chunk timeout in minutes",
        default = "10"
    )]
    pub last_contribution_timeout: i64,
    // #[options(help = "chunk lock timeout in minutes", default = "10")]
    // pub chunk_timeout: i64,
}

pub struct Monitor {
    // Settings
    pub server_url: Url,
    pub logger: Logger,
    pub ceremony_timeout: Duration,
    pub pending_verification_timeout: Duration,
    pub last_contribution_timeout: Duration,

    // Last changed values in the ceremony
    pub ceremony_version: u64,
    pub ceremony_update: DateTime<Utc>,

    /// The state of the round of contributions.
    pub round_state: RoundState,
}

impl Monitor {
    pub fn new(opts: &MonitorOpts) -> Result<Self> {
        Ok(Self {
            server_url: Url::parse(&opts.coordinator_url)?.join("ceremony")?,
            logger: Logger::new(opts.slack_webhook_url.clone()),
            ceremony_timeout: Duration::minutes(opts.ceremony_timeout),
            pending_verification_timeout: Duration::minutes(opts.pending_verification_timeout),
            last_contribution_timeout: Duration::minutes(opts.last_contribution_timeout),
            ceremony_version: 0,
            ceremony_update: chrono::Utc::now(),
            round_state: RoundState::default(),
        })
    }

    async fn run(&mut self) -> Result<()> {
        let response = reqwest::get(self.server_url.as_str())
            .await?
            .error_for_status()?;
        let data = response.text().await?;
        let ceremony: Ceremony = serde_json::from_str::<Response<Ceremony>>(&data)?.result;

        let new_ceremony_version = self.check_and_update_ceremony_version(&ceremony).await?;
        if new_ceremony_version {
            self.round_state
                .update_round_state(
                    &ceremony,
                    self.ceremony_update,
                    &self.logger,
                    self.pending_verification_timeout,
                    self.last_contribution_timeout,
                )
                .await?;
        }

        Ok(())
    }

    pub async fn check_and_update_ceremony_version(&mut self, ceremony: &Ceremony) -> Result<bool> {
        let current_time = chrono::Utc::now();
        let elapsed = current_time - self.ceremony_update;
        let new_version = ceremony.version != self.ceremony_version;

        if new_version {
            self.ceremony_update = current_time;
            self.ceremony_version = ceremony.version;
        } else {
            if self.ceremony_timeout <= elapsed && !self.round_state.is_round_complete() {
                let ongoing_contributions_count = self
                    .round_state
                    .paxs_contribution_state
                    .get_active_participants_count(self.round_state.total_chunks);
                let total_round_contributions = self
                    .round_state
                    .paxs_contribution_state
                    .get_total_contributing_participants();

                if ongoing_contributions_count > 0 {
                    // If there's contributors that haven't finished their contribution. Either all participants
                    // died off or this is a product of dark evil forces of darkness.
                    self.logger.log_and_notify_slack(
                        &format!("Ceremony progress is stuck at version {:?} for {:?} minutes. Currently active {} {}/{} participants",
                    ceremony.version,
                    elapsed.num_minutes(),
                    ongoing_contributions_count,
                    total_round_contributions,
                    ceremony.contributor_ids.iter().count()), NotificationPriority::Error).await;
                } else {
                    // The round is not complete but no participant is actively contributing.
                    // So participant that has started to contribute, has also finished.
                    // Thus it is not an indication of a serious problem with the ceremony.
                    self.logger
                        .log_and_notify_slack(
                            &format!(
                            "Nobody is participating for {:?} minutes. Participation count: {}/{}",
                            elapsed.num_minutes(),
                            total_round_contributions,
                            ceremony.contributor_ids.iter().count()
                        ),
                            NotificationPriority::Warning,
                        )
                        .await;
                }
            }
        }

        Ok(new_version)
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
            Err(e) => {
                monitor
                    .logger
                    .log_and_notify_slack(
                        &format!("Got error from monitor: {}", e.to_string()),
                        NotificationPriority::Error,
                    )
                    .await
            }
            _ => {}
        }
    }
}
