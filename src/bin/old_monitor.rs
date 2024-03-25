use nimiq_keys::PublicKey;
use snark_setup_operator::{
    data_structs::{Ceremony, Response, UniqueChunkId},
    error::MonitorError,
};

use anyhow::{Ok, Result};
use chrono::{DateTime, Duration, Utc};
use gumdrop::Options;
use std::collections::HashSet;
use tracing::{error, warn};
use url::Url;

#[derive(Debug, Options, Clone)]
pub struct MonitorOpts {
    help: bool,
    #[options(
        help = "the url of the coordinator API",
        default = "http://localhost:8080"
    )]
    pub coordinator_url: String,
    #[options(help = "polling interval in minutes", default = "1")]
    pub polling_interval: u64,
    #[options(help = "chunk lock timeout in minutes", default = "1")]
    pub chunk_timeout: i64,
    #[options(help = "ceremony timeout in minutes", default = "5")]
    pub ceremony_timeout: i64,
}

pub struct Monitor {
    // Settings
    pub server_url: Url,
    pub timeout: Duration,
    pub ceremony_timeout: Duration,

    // Last changed values in the ceremony
    pub last_ceremony_version: u64,
    pub last_ceremony_update: DateTime<Utc>,

    pub last_setups_all_done: Vec<bool>,

    pub last_timed_out_participant_ids: Vec<PublicKey>,

    pub last_chunks_complete: Vec<UniqueChunkId>,
    pub last_chunks_incomplete: Vec<UniqueChunkId>,
    pub participant_ids_incomplete: Vec<PublicKey>,
}

impl Monitor {
    pub fn new(opts: &MonitorOpts) -> Result<Self> {
        let monitor = Self {
            server_url: Url::parse(&opts.coordinator_url)?.join("ceremony")?,
            timeout: Duration::minutes(opts.chunk_timeout),
            ceremony_timeout: Duration::minutes(opts.ceremony_timeout),
            last_ceremony_version: 0,
            last_ceremony_update: chrono::Utc::now(),
            last_setups_all_done: vec![],
            last_timed_out_participant_ids: vec![],
            last_chunks_complete: vec![],
            last_chunks_incomplete: vec![],
            participant_ids_incomplete: vec![],
        };
        Ok(monitor)
    }

    async fn run(&mut self) -> Result<()> {
        let response = reqwest::get(self.server_url.as_str())
            .await?
            .error_for_status()?;
        let data = response.text().await?;
        let ceremony: Ceremony = serde_json::from_str::<Response<Ceremony>>(&data)?.result;

        self.check_all_done(&ceremony)?;
        self.check_progress(&ceremony)?;
        self.check_timeout(&ceremony)?;
        // self.show_finished_chunks(&ceremony)?;

        Ok(())
    }

    fn check_progress(&mut self, ceremony: &Ceremony) -> Result<()> {
        let current_time = chrono::Utc::now();
        let elapsed = current_time - self.last_ceremony_update;
        if ceremony.version == self.last_ceremony_version {
            if self.ceremony_timeout <= elapsed {
                warn!(
                    "Ceremony progress is stuck at version {:?} for {:?} minutes",
                    ceremony.version,
                    elapsed.num_minutes()
                );
            }
        } else {
            self.last_ceremony_update = current_time;
            self.last_ceremony_version = ceremony.version;
        }

        Ok(())
    }

    fn check_timeout(&mut self, ceremony: &Ceremony) -> Result<()> {
        let current_time = chrono::Utc::now();
        let mut timed_out_participant_ids = HashSet::new();

        for setup in ceremony.setups.iter() {
            for chunk in setup.chunks.iter() {
                let participant_id = match chunk.lock_holder.as_ref() {
                    Some(participant_id) => participant_id.clone(),
                    None => continue,
                };

                let lock_time = chunk
                    .metadata
                    .as_ref()
                    .ok_or(MonitorError::MetadataNoneError)?
                    .lock_holder_time
                    .ok_or(MonitorError::LockTimeIsNoneError)?;
                let elapsed = current_time - lock_time;
                if elapsed > self.timeout {
                    timed_out_participant_ids.insert(participant_id);
                }
            }
        }
        let timed_out_participant_ids: Vec<_> = timed_out_participant_ids
            .iter()
            .map(|pk| pk.clone())
            .collect();
        if !self
            .last_timed_out_participant_ids
            .eq(&timed_out_participant_ids)
        {
            if !timed_out_participant_ids.is_empty() {
                warn!("timed out participants: {:?}", timed_out_participant_ids);
            }
            self.last_timed_out_participant_ids = timed_out_participant_ids;
        }

        Ok(())
    }

    fn check_all_done(&mut self, ceremony: &Ceremony) -> Result<()> {
        if ceremony.version == self.last_ceremony_version {
            return Ok(());
        }

        let participant_ids: HashSet<_> = ceremony
            .contributor_ids
            .iter()
            .map(|pk| pk.clone())
            .collect();
        let mut last_setups_all_done = vec![];

        if self.last_setups_all_done.len() <= ceremony.setups.len() {
            let missing_setups = ceremony.setups.len() - self.last_setups_all_done.len();
            for _ in 0..missing_setups {
                self.last_setups_all_done.push(false);
            }
        }

        for setup in ceremony.setups.iter() {
            let done = setup.chunks.iter().all(|chunk| {
                let verified_participant_ids_in_chunk: HashSet<_> = chunk
                    .contributions
                    .iter()
                    .filter(|c| c.verified)
                    .map(|c| c.contributor_id.as_ref())
                    .filter_map(|e| e)
                    .collect();
                participant_ids
                    .iter()
                    .all(|p| verified_participant_ids_in_chunk.contains(p))
            });
            last_setups_all_done.push(done);
            let index = setup.setup_id.len() - 1;

            if self.last_setups_all_done[index] != last_setups_all_done[index] {
                self.last_setups_all_done[index] = last_setups_all_done[index];
                let all_done = last_setups_all_done.iter().all(|done| *done);

                if all_done {
                    warn!("setups are all done!");
                    if self.last_setups_all_done.iter().all(|done| *done) {
                        self.reset();
                        break;
                    }
                } else {
                    warn!(
                        "setup {:?} done: {}",
                        setup.setup_id, last_setups_all_done[index]
                    );
                }
            }
        }
        Ok(())
    }

    // fn show_finished_chunks(&mut self, ceremony: &Ceremony) -> Result<()> {
    //     let participant_ids: HashSet<_> = ceremony.contributor_ids.iter().clone().collect();

    //     let mut chunks_complete = vec![];
    //     let mut chunks_incomplete = vec![];
    //     let mut participant_ids_incomplete = HashSet::new();

    //     for setup in ceremony.setups.iter() {
    //         for chunk in setup.chunks.iter() {
    //             let verified_participant_ids_in_chunk: HashSet<_> = chunk
    //                 .contributions
    //                 .iter()
    //                 .filter(|c| c.verified)
    //                 .map(|c| c.contributor_id)
    //                 .filter_map(|e| e)
    //                 .collect();
    //             if participant_ids
    //                 .iter()
    //                 .all(|p| verified_participant_ids_in_chunk.contains(*p))
    //             {
    //                 chunks_complete.push(chunk.unique_chunk_id.clone())
    //             } else {
    //                 participant_ids
    //                     .iter()
    //                     .filter(|x| !verified_participant_ids_in_chunk.contains(*x))
    //                     .for_each(|p| {
    //                         participant_ids_incomplete.insert((*p).clone());
    //                     });
    //                 chunks_incomplete.push(chunk.unique_chunk_id.clone())
    //             }
    //         }
    //     }

    //     if !self.last_chunks_complete.eq(&chunks_complete) {
    //         if !chunks_complete.is_empty() {
    //             info!("complete chunks: {:?}", chunks_complete);
    //         }
    //         self.last_chunks_complete = chunks_complete;
    //     }
    //     if !self.last_chunks_incomplete.eq(&chunks_incomplete) {
    //         if !chunks_incomplete.is_empty() {
    //             info!("incomplete chunks: {:?}", chunks_incomplete);
    //         }
    //         self.last_chunks_incomplete = chunks_incomplete;
    //     }
    //     let participant_ids_incomplete_vec: Vec<PublicKey> = participant_ids_incomplete
    //         .iter()
    //         .map(|pk| pk.clone())
    //         .collect();
    //     if !self
    //         .participant_ids_incomplete
    //         .eq(&participant_ids_incomplete_vec)
    //     {
    //         if !participant_ids_incomplete_vec.is_empty() {
    //             info!(
    //                 "incomplete participants: {:?}",
    //                 participant_ids_incomplete_vec
    //             );
    //         }
    //         self.participant_ids_incomplete = participant_ids_incomplete_vec;
    //     }

    //     Ok(())
    // }

    fn reset(&mut self) {
        warn!("setups are all done!");
        self.last_setups_all_done = vec![];
        self.last_timed_out_participant_ids = vec![];
        self.last_chunks_complete = vec![];
        self.last_chunks_incomplete = vec![];
        self.participant_ids_incomplete = vec![];
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
