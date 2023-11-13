use anyhow::Result;
use ark_bls12_377::Bls12_377;
use ark_bw6_761::BW6_761;
use ark_ec::pairing::Pairing;
use ark_mnt4_753::MNT4_753;
use ark_mnt6_753::MNT6_753;
use ark_serialize::CanonicalSerialize;
use gumdrop::Options;
use phase2::parameters::MPCParameters;
use phase2_cli::COMPRESS_CONTRIBUTE_INPUT;
use setup_utils::{SubgroupCheckMode, DEFAULT_VERIFY_CHECK_OUTPUT_CORRECTNESS};
use snark_setup_operator::data_structs::Setup;
use snark_setup_operator::setup_filename;
use snark_setup_operator::transcript_data_structs::Transcript;
use snark_setup_operator::utils::{COMBINED_NEW_CHALLENGE_FILENAME, PROVING_KEY, VERIFYING_KEY};
use snark_setup_operator::{error::VerifyTranscriptError, utils::remove_file_if_exists};
use std::ops::Neg;
use std::{fs::File, io::Read};

#[derive(Debug, Options, Clone)]
pub struct GetKeysOpts {
    help: bool,
    #[options(help = "the path of the transcript json file", default = "transcript")]
    pub transcript_path: String,
}

pub struct GetKeys {
    pub transcript: Transcript,
}

impl GetKeys {
    pub fn new(opts: &GetKeysOpts) -> Result<Self> {
        let mut transcript = String::new();
        File::open(&opts.transcript_path)
            .expect("Should have opened transcript file.")
            .read_to_string(&mut transcript)
            .expect("Should have read transcript file.");
        let transcript: Transcript = serde_json::from_str::<Transcript>(&transcript)?;

        Ok(Self { transcript })
    }

    fn run(&self) -> Result<()> {
        let ceremony = self
            .transcript
            .rounds
            .iter()
            .last()
            .expect("Round not found in transcript");

        for setup in ceremony.setups.iter() {
            match setup.parameters.curve_kind.as_str() {
                "bw6" => self.get_keys::<BW6_761>(setup),
                "bls12_377" => self.get_keys::<Bls12_377>(setup),
                "mnt4_753" => self.get_keys::<MNT4_753>(setup),
                "mnt6_753" => self.get_keys::<MNT6_753>(setup),
                _ => Err(VerifyTranscriptError::UnsupportedCurveKindError(
                    setup.parameters.curve_kind.clone(),
                )
                .into()),
            }?;
        }

        Ok(())
    }

    fn get_keys<E: Pairing>(&self, setup: &Setup) -> Result<()>
    where
        E::G1Affine: Neg<Output = E::G1Affine>,
    {
        let response_filename = setup_filename!(COMBINED_NEW_CHALLENGE_FILENAME, setup.setup_id);

        let response_contents =
            std::fs::read(response_filename).expect("should have read response");

        let parameters_after = MPCParameters::<E>::read_fast(
            response_contents.as_slice(),
            COMPRESS_CONTRIBUTE_INPUT,
            DEFAULT_VERIFY_CHECK_OUTPUT_CORRECTNESS,
            true,
            SubgroupCheckMode::Auto,
        )
        .expect("should have read parameters");

        let proving_key_path = setup_filename!(PROVING_KEY, setup.setup_id).to_string();
        let verifying_key_path = setup_filename!(VERIFYING_KEY, setup.setup_id).to_string();
        remove_file_if_exists(&proving_key_path)?;
        remove_file_if_exists(&verifying_key_path)?;

        let mut f = std::fs::File::create(&proving_key_path)
            .expect(&format!("unable to open new {:?} file", proving_key_path));
        parameters_after
            .params
            .serialize_compressed(&mut f)
            .expect("unable to serialize proving key");
        f.sync_all()
            .expect(&format!("unable to flush {:?}", proving_key_path));

        let mut f = std::fs::File::create(&verifying_key_path)
            .expect(&format!("unable to open new {:?} file", verifying_key_path));
        parameters_after
            .params
            .vk
            .serialize_compressed(&mut f)
            .expect("unable to serialize verifying key");
        f.sync_all()
            .expect(&format!("unable to flush {:?}", verifying_key_path));

        Ok(())
    }
}

fn main() {
    tracing_subscriber::fmt().json().init();

    let opts: GetKeysOpts = GetKeysOpts::parse_args_default_or_exit();

    let transformer = GetKeys::new(&opts).expect("Should have been able to get keys");

    transformer.run().expect("Should have run successfully");
}
