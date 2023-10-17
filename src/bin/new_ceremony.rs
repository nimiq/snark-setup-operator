use anyhow::{anyhow, Result};
use gumdrop::Options;
use nimiq_keys::{KeyPair, PrivateKey};
#[allow(unused_imports)]
use phase1_cli::*;
#[allow(unused_imports)]
use phase2_cli::*;
use reqwest::header::AUTHORIZATION;
use secrecy::ExposeSecret;
use snark_setup_operator::data_structs::{Ceremony, ParticipantId, Response};
use snark_setup_operator::utils::{get_authorization_value, read_keys};
use std::fs::File;
use std::io::{Read, Write};
use tracing::info;
use url::Url;

#[derive(Debug, Options, Clone)]
pub struct NewCeremonyOpts {
    help: bool,
    #[options(help = "phase to be run. Must be either phase1 or phase2")]
    pub phase: String,
    #[options(help = "the server url", required)]
    pub server_url: String,
    #[options(help = "participants")]
    pub participant: Vec<ParticipantId>,
    #[options(help = "verifiers")]
    pub verifier: Vec<ParticipantId>,
    #[options(help = "deployer", required)]
    pub deployer: ParticipantId,
    #[options(
        help = "the encrypted keys for the Nimiq setup",
        default = "nimiq.keys"
    )]
    pub keys_file: String,
    #[options(help = "max locks", default = "3")]
    pub max_locks: u64,
    #[options(help = "read passphrase from stdin. THIS IS UNSAFE as it doesn't use pinentry!")]
    pub unsafe_passphrase: bool,
    #[options(help = "use prepared ceremony")]
    pub prepared_ceremony: Option<String>,
}

fn build_ceremony(
    opts: &NewCeremonyOpts,
    existing_contributor_ids: &[ParticipantId],
    existing_verifier_ids: &[ParticipantId],
) -> Result<Ceremony> {
    let ceremony = Ceremony {
        round: 0,
        version: 0,
        max_locks: opts.max_locks,
        shutdown_signal: false,
        attestations: Some(vec![]),
        contributor_ids: [&opts.participant, existing_contributor_ids].concat(),
        verifier_ids: [&opts.verifier, existing_verifier_ids].concat(), // PITODO: remove duplicates
        phase: opts.phase.clone(),
        setups: vec![],
    };
    let filename = format!(
        "ceremony_{}",
        chrono::Utc::now()
            .timestamp_nanos_opt()
            .expect("Invalid time")
    );
    info!("Saving ceremony to {}", filename);
    let mut file = File::create(filename)?;
    file.write_all(serde_json::to_string_pretty(&ceremony)?.as_bytes())?;
    file.sync_all()?;

    Ok(ceremony)
}

async fn run(opts: &NewCeremonyOpts, key_pair: &[u8]) -> Result<()> {
    let server_url = Url::parse(opts.server_url.as_str())?.join("ceremony")?;
    let data = reqwest::get(server_url.as_str())
        .await?
        .error_for_status()?
        .text()
        .await?;
    let ceremony: Ceremony = serde_json::from_str::<Response<Ceremony>>(&data)?.result;
    let deployer = opts.deployer.clone();
    let key_pair = KeyPair::from(PrivateKey::from_bytes(key_pair)?);
    let public_key = key_pair.public.clone();
    if public_key != deployer {
        return Err(anyhow!("Deployer must match the private key"));
    }
    if ceremony.version != 0 || !ceremony.verifier_ids.contains(&public_key) {
        return Err(anyhow!("Can only initialize a ceremony with version 0 and the verifiers list must contain the public key matching the private key"));
    }

    if let Some(prepared_ceremony) = opts.prepared_ceremony.as_ref() {
        let mut ceremony_contents = String::new();
        File::open(&prepared_ceremony)?.read_to_string(&mut ceremony_contents)?;
        let ceremony: Ceremony = serde_json::from_str::<Ceremony>(&ceremony_contents)?;
        info!("Updating ceremony");
        let client = reqwest::Client::new();
        let authorization = get_authorization_value(&key_pair, "PUT", "ceremony")?;
        client
            .put(server_url.as_str())
            .header(AUTHORIZATION, authorization)
            .json(&ceremony)
            .send()
            .await?
            .error_for_status()?;
        info!("Done!");
        return Ok(());
    }

    let ceremony = build_ceremony(&opts, &ceremony.contributor_ids, &ceremony.verifier_ids)?;
    info!("Updating ceremony");
    let client = reqwest::Client::new();
    let authorization = get_authorization_value(&key_pair, "PUT", "ceremony")?;
    client
        .put(server_url.as_str())
        .header(AUTHORIZATION, authorization)
        .json(&ceremony)
        .send()
        .await?
        .error_for_status()?;
    info!("Done!");

    Ok(())
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt().json().init();
    let opts: NewCeremonyOpts = NewCeremonyOpts::parse_args_default_or_exit();
    let (_, key_pair, _) = read_keys(&opts.keys_file, opts.unsafe_passphrase, false)
        .expect("Should have loaded Nimiq setup keys");
    run(&opts, key_pair.expose_secret())
        .await
        .expect("Should have run the new ceremony generation");
}
