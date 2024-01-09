use anyhow::Result;
use ark_bls12_377::Bls12_377;
use ark_bw6_761::BW6_761;
use ark_ec::pairing::Pairing;
use ark_mnt4_753::MNT4_753;
use ark_mnt6_753::MNT6_753;
use ark_serialize::CanonicalDeserialize;
use gumdrop::Options;
use phase2::load_circuit::Matrices;
use snark_setup_operator::data_structs::Setup;
use snark_setup_operator::setup_filename;
use snark_setup_operator::transcript_data_structs::Transcript;
use snark_setup_operator::utils::{COMBINED_FILENAME, PHASE2_INIT_FILENAME};
use snark_setup_operator::{
    error::VerifyTranscriptError,
    utils::{create_full_parameters, remove_file_if_exists},
};
use std::ops::Neg;
use std::{fs::File, io::Read};

/// If a circuit filename is given, the phase2 powers are estimated from the circuit itself.
/// Otherwise, the powers must be given by the additional argument.
#[derive(Debug, Options, Clone)]
pub struct IntermediateTransformOpts {
    help: bool,
    #[options(help = "the path of the transcript json file", default = "transcript")]
    pub transcript_path: String,
    #[options(help = "setup id", required)]
    pub setup_id: usize,
    #[options(help = "powers in phase2")]
    pub phase2_powers: Option<usize>,
    #[options(help = "circuit filename")]
    pub circuit_filename: Option<String>,
}

pub struct IntermediateTransform {
    pub transcript: Transcript,
    pub setup_id: usize,
    pub phase2_powers: usize,
}

impl IntermediateTransform {
    pub fn new(opts: &IntermediateTransformOpts) -> Result<Self> {
        let mut transcript = String::new();
        File::open(&opts.transcript_path)
            .expect("Should have opened transcript file.")
            .read_to_string(&mut transcript)
            .expect("Should have read transcript file.");
        let transcript: Transcript = serde_json::from_str::<Transcript>(&transcript)?;

        let phase2_powers = if let Some(ref circuit_filename) = opts.circuit_filename {
            let ceremony = transcript
                .rounds
                .iter()
                .last()
                .expect("Round not found in transcript");

            let setup = &ceremony.setups[opts.setup_id];
            match setup.parameters.curve_kind.as_str() {
                "bw6" => Self::estimate_circuit_powers::<BW6_761>(circuit_filename),
                "bls12_377" => Self::estimate_circuit_powers::<Bls12_377>(circuit_filename),
                "mnt4_753" => Self::estimate_circuit_powers::<MNT4_753>(circuit_filename),
                "mnt6_753" => Self::estimate_circuit_powers::<MNT6_753>(circuit_filename),
                _ => {
                    return Err(VerifyTranscriptError::UnsupportedCurveKindError(
                        setup.parameters.curve_kind.clone(),
                    )
                    .into())
                }
            }
        } else {
            opts.phase2_powers
                .expect("Need to give either phase2_powers or circuit_filename")
        };

        Ok(Self {
            transcript,
            setup_id: opts.setup_id,
            phase2_powers,
        })
    }

    fn estimate_circuit_powers<P: Pairing>(circuit_filename: &str) -> usize {
        let mut file = File::open(circuit_filename).unwrap();
        let mut buffer = Vec::<u8>::new();
        file.read_to_end(&mut buffer).unwrap();
        let m = Matrices::<P>::deserialize_compressed(&*buffer).unwrap();

        std::cmp::max(
            m.num_constraints,
            m.num_witness_variables + m.num_instance_variables,
        )
        .next_power_of_two()
        .trailing_zeros() as usize
    }

    fn run(&self) -> Result<()> {
        let ceremony = self
            .transcript
            .rounds
            .iter()
            .last()
            .expect("Round not found in transcript");

        let setup = &ceremony.setups[self.setup_id];
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

        Ok(())
    }

    fn transform<E: Pairing>(&self, setup: &Setup) -> Result<()>
    where
        E::G1Affine: Neg<Output = E::G1Affine>,
    {
        let parameters = create_full_parameters::<E>(&setup.parameters)?;

        remove_file_if_exists(setup_filename!(PHASE2_INIT_FILENAME, setup.setup_id))?;
        phase1_cli::prepare_phase2(
            setup_filename!(PHASE2_INIT_FILENAME, setup.setup_id),
            setup_filename!(COMBINED_FILENAME, setup.setup_id),
            self.phase2_powers,
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
