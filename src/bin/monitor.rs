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

    /// The percentage of chunks of pending verification.
    previous_pending_verification_percentage: f32,

    /// The setup and chunks contribution state.
    pub setups_contribution_state: Vec<SetupContributionState>,

    /// Alls paxs that have started contributing and their last contribution data.
    pub paxs_contribution_state: ParticipantsContributionState,
}

impl RoundState {
    pub fn get_num_setups(&self) -> usize {
        if self.setups_contribution_state.is_empty() {
            return 0;
        }

        self.setups_contribution_state.len() - 1
    }

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
                        format!("A change of setups and or chunk sizes was detected!"),
                        NotificationPriority::Error,
                    )
                    .await;
            }

            return Err(MonitorError::MonitorParametersDifferentBetweenRounds(
                self.setups_contribution_state.len(),
                ceremony.setups.len(),
            )
            .into());
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
            if !ceremony.contributor_ids.is_empty() {
                logger
                    .log_and_notify_slack(
                        format!("Round {}: All setups are complete!", self.round),
                        NotificationPriority::Info,
                    )
                    .await;
            }
        }

        // Sets new round and resets the state of each setup and participant.
        self.init(ceremony);

        if ceremony.round == 0 && ceremony.contributor_ids.is_empty() {
            logger
                .log_and_notify_slack(
                    format!("Setting up round. Setup {} done", self.get_num_setups()),
                    NotificationPriority::Info,
                )
                .await;
        } else {
            logger
                .log_and_notify_slack(
                    format!("Round {} started!", self.round),
                    NotificationPriority::Info,
                )
                .await;
        }
    }

    async fn check_for_verifiers_bottleneck(
        &mut self,
        logger: &Logger,
        verification_timeout_counter: u32,
    ) {
        let new_pending_verification_percentage =
            verification_timeout_counter as f32 / self.total_chunks as f32;

        match (
            self.previous_pending_verification_percentage > 0.0,
            new_pending_verification_percentage >= 0.25,
        ) {
            (_, true) => {
                // If it's the first detection we will always log. Otherwise we only log if the situation is aggravating.
                if new_pending_verification_percentage
                    >= self.previous_pending_verification_percentage + 0.25
                {
                    let ongoing_contributions_count = self
                        .paxs_contribution_state
                        .get_active_participants_count(self.total_chunks);

                    logger
                    .log_and_notify_slack(
                        format!(
                            "Verifiers bottleneck detected! There's {} ongoing contributions. {}% chunks pending verification ({}/{}).",
                            ongoing_contributions_count,
                            new_pending_verification_percentage*100.0,
                            verification_timeout_counter,self.total_chunks
                        ),
                        NotificationPriority::Warning,
                    )
                    .await;

                    self.previous_pending_verification_percentage =
                        new_pending_verification_percentage;
                }
            }
            (true, false) => {
                // The verifiers managed to catch up with the contributors.
                self.previous_pending_verification_percentage = 0.0;
                logger
                    .log_and_notify_slack(
                        format!(
                            "Verifiers bottleneck solved! {}% chunks pending verification ({}/{}).",
                            new_pending_verification_percentage * 100.0,
                            verification_timeout_counter,
                            self.total_chunks
                        ),
                        NotificationPriority::Resolved,
                    )
                    .await;
            }
            _ => {}
        }
    }

    async fn update_round_state(
        &mut self,
        ceremony: &Ceremony,
        ceremony_update: DateTime<Utc>,
        logger: &Logger,
        pending_verification_timeout: Duration,
        same_contribution_timeout: Duration,
        contribution_lock_timeout: Duration,
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
        let mut verification_timeout_count = 0;

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
                        (
                            pending_verification_timeout,
                            self.previous_pending_verification_percentage > 0.0,
                        ),
                        contribution_lock_timeout,
                    )
                    .await?;

                if chunk_state.is_verification_timeout() {
                    verification_timeout_count += 1;
                }

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
                    same_contribution_timeout,
                )
                .await;

            // Log that the verifiers are not keeping up with the contributions.
            self.check_for_verifiers_bottleneck(logger, verification_timeout_count)
                .await;
        } else {
            if !ceremony.contributor_ids.is_empty() {
                logger
                    .log_and_notify_slack(
                        format!("Round {}: All setups are complete!", self.round),
                        NotificationPriority::Info,
                    )
                    .await;
            }
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
    #[options(help = "polling interval in minutes", default = "5")]
    pub polling_interval: u64,
    #[options(help = "ceremony timeout in minutes", default = "120")]
    pub ceremony_timeout: i64,

    #[options(help = "chunk pending verification timeout in minutes", default = "90")]
    pub pending_verification_timeout: i64,
    #[options(
        help = "participant's stuck with the same finished contribution timeout in minutes",
        default = "60"
    )]
    pub same_contribution_timeout: i64,

    #[options(
        help = "participant's locked on a chunk timeout in minutes",
        default = "15"
    )]
    pub contribution_lock_timeout: i64,

    #[options(
        help = "whether to log the first run. This avoids the redeployment spam",
        default = "false"
    )]
    pub first_run_logging: bool,
}

pub struct Monitor {
    // Settings
    pub server_url: Url,
    pub logger: Logger,
    pub ceremony_timeout: Duration,
    pub pending_verification_timeout: Duration,
    pub same_contribution_timeout: Duration,
    pub contribution_lock_timeout: Duration,

    // Last changed values in the ceremony
    pub ceremony_version: u64,
    pub ceremony_update: DateTime<Utc>,
    /// The counter for timeouts due to no ongoing contributions.
    pub last_timeout_ceremony_time: Option<DateTime<Utc>>,
    pub no_ongoing_contributions_timeout_count: usize,

    /// The state of the round of contributions.
    pub round_state: RoundState,
}

impl Monitor {
    pub fn new(opts: &MonitorOpts) -> Result<Self> {
        Ok(Self {
            server_url: Url::parse(&opts.coordinator_url)?.join("ceremony")?,
            logger: Logger::new(opts.slack_webhook_url.clone(), opts.first_run_logging),
            ceremony_timeout: Duration::minutes(opts.ceremony_timeout),
            pending_verification_timeout: Duration::minutes(opts.pending_verification_timeout),
            same_contribution_timeout: Duration::minutes(opts.same_contribution_timeout),
            contribution_lock_timeout: Duration::minutes(opts.contribution_lock_timeout),
            last_timeout_ceremony_time: None,
            no_ongoing_contributions_timeout_count: 0,
            ceremony_version: 0,
            ceremony_update: DateTime::default(),
            round_state: RoundState::default(),
        })
    }

    async fn run(&mut self) -> Result<()> {
        let response = reqwest::get(self.server_url.as_str())
            .await?
            .error_for_status()?;
        let data = response.text().await?;
        let ceremony: Ceremony = serde_json::from_str::<Response<Ceremony>>(&data)?.result;

        let first_run = self.ceremony_update.eq(&DateTime::<Utc>::default());
        if first_run {
            self.logger
                .log_and_notify_slack(format!("Monitor was restarted"), NotificationPriority::Info)
                .await;
        }

        let new_ceremony_version = self.check_and_update_ceremony_version(&ceremony).await?;
        if new_ceremony_version {
            self.round_state
                .update_round_state(
                    &ceremony,
                    self.ceremony_update,
                    &self.logger,
                    self.pending_verification_timeout,
                    self.same_contribution_timeout,
                    self.contribution_lock_timeout,
                )
                .await?;
        }
        if first_run {
            self.logger.finish_first_run();
        }
        Ok(())
    }

    pub async fn check_and_update_ceremony_version(&mut self, ceremony: &Ceremony) -> Result<bool> {
        let current_time = chrono::Utc::now();
        let last_check_time = if let Some(last_timeout_time) = self.last_timeout_ceremony_time {
            last_timeout_time
        } else {
            self.ceremony_update
        };
        let elapsed = current_time - last_check_time;
        let new_version = ceremony.version != self.ceremony_version;

        if new_version {
            self.ceremony_update = current_time;
            self.ceremony_version = ceremony.version;
            self.last_timeout_ceremony_time = None;
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
                    // died off or this is a product of evil forces of darkness.
                    self.logger.log_and_notify_slack(
                        format!("Ceremony progress is stuck at version {:?} for {:?} minutes. Currently active {} {}/{} participants",
                    ceremony.version,
                    elapsed.num_minutes(),
                    ongoing_contributions_count,
                    total_round_contributions,
                    ceremony.contributor_ids.iter().count()), NotificationPriority::Error).await;
                } else {
                    // In case of no ongoing contributions and we want to log with decreasing frequency.
                    if total_round_contributions > 0
                        && self.ceremony_timeout
                            * (2 + self.no_ongoing_contributions_timeout_count as i32)
                            <= elapsed
                    {
                        // The round is not complete but no participant is actively contributing.
                        // So participant that has started to contribute, has also finished.
                        // Thus it is not an indication of a serious problem with the ceremony.
                        self.no_ongoing_contributions_timeout_count += 1;
                        self.logger
                            .log_and_notify_slack(
                                format!(
                            "Nobody is participating for {:?} hours. Participation count: {}/{}",
                            elapsed.num_hours(),
                            total_round_contributions,
                            ceremony.contributor_ids.iter().count()
                        ),
                                NotificationPriority::Warning,
                            )
                            .await;
                    }
                }
            }
            self.last_timeout_ceremony_time = Some(current_time);
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
                monitor.logger.finish_first_run();
                monitor
                    .logger
                    .log_and_notify_slack(
                        format!("Got error from monitor: {}", e.to_string()),
                        NotificationPriority::Error,
                    )
                    .await
            }
            _ => {}
        }
    }
}
