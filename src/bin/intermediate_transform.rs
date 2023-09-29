use anyhow::Result;
use ark_bls12_377::Bls12_377;
use ark_bw6_761::BW6_761;
use ark_ec::pairing::Pairing;
use ark_mnt4_753::MNT4_753;
use ark_mnt6_753::MNT6_753;
use gumdrop::Options;
use snark_setup_operator::data_structs::Setup;
use snark_setup_operator::setup_filename;
use snark_setup_operator::transcript_data_structs::Transcript;
use snark_setup_operator::utils::{COMBINED_FILENAME, PHASE2_FILENAME};
use snark_setup_operator::{
    error::VerifyTranscriptError,
    utils::{create_full_parameters, remove_file_if_exists},
};
use std::ops::Neg;
use std::{fs::File, io::Read};

#[derive(Debug, Options, Clone)]
pub struct IntermediateTransformOpts {
    help: bool,
    #[options(help = "the path of the transcript json file", default = "transcript")]
    pub transcript_path: String,
}

pub struct IntermediateTransform {
    pub transcript: Transcript,
}

impl IntermediateTransform {
    pub fn new(opts: &IntermediateTransformOpts) -> Result<Self> {
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
                "bw6" => self.transform::<BW6_761>(setup),
                "bls12_377" => self.transform::<Bls12_377>(setup),
                "mnt4_753" => self.transform::<MNT4_753>(setup),
                "mnt6_753" => self.transform::<MNT6_753>(setup),
                _ => Err(VerifyTranscriptError::UnsupportedCurveKindError(
                    setup.parameters.curve_kind.clone(),
                )
                .into()),
            }?;
        }

        Ok(())
    }

    fn transform<E: Pairing>(&self, setup: &Setup) -> Result<()>
    where
        E::G1Affine: Neg<Output = E::G1Affine>,
    {
        let parameters = create_full_parameters::<E>(&setup.parameters)?;

        remove_file_if_exists(setup_filename!(PHASE2_FILENAME, setup.setup_id))?;
        phase1_cli::prepare_phase2(
            setup_filename!(PHASE2_FILENAME, setup.setup_id),
            setup_filename!(COMBINED_FILENAME, setup.setup_id),
            setup.parameters.power,
            &parameters,
        )?;

        Ok(())
    }
}

fn main() {
    tracing_subscriber::fmt().json().init();

    let opts: IntermediateTransformOpts = IntermediateTransformOpts::parse_args_default_or_exit();

    let transformer = IntermediateTransform::new(&opts)
        .expect("Should have been able to create a transcript verifier");

    transformer.run().expect("Should have run successfully");
}
