use anyhow::Result;
use ark_bls12_377::Bls12_377;
use ark_bw6_761::BW6_761;
use ark_ec::pairing::Pairing;
use ark_mnt4_753::MNT4_753;
use ark_mnt6_753::MNT6_753;
use ark_serialize::CanonicalDeserialize;
use gumdrop::Options;
use phase2::load_circuit::Matrices;
use setup_utils::{domain_size, CheckForCorrectness};
use snark_setup_operator::data_structs::Setup;
use snark_setup_operator::setup_filename;
use snark_setup_operator::transcript_data_structs::Transcript;
use snark_setup_operator::utils::COMBINED_VERIFIED_POK_AND_CORRECTNESS_NEW_CHALLENGE_FILENAME;
use snark_setup_operator::{
    error::VerifyTranscriptError,
    utils::{create_full_parameters, remove_file_if_exists},
};
use std::collections::HashMap;
use std::ops::Neg;
use std::{
    fs::{copy, File},
    io::Read,
};
use tracing::info;

/// If a circuit filename is given, the phase2 powers are estimated from the circuit itself.
/// Otherwise, the powers must be given by the additional argument.
#[derive(Debug, Options, Clone)]
pub struct IntermediateTransformOpts {
    help: bool,
    #[options(help = "the path of the transcript json file", default = "transcript")]
    pub transcript_path: String,
    #[options(help = "setup id", required)]
    pub setup_id: usize,
    #[options(help = "circuit size in phase2")]
    pub phase2_size: Option<usize>,
    #[options(help = "circuit filenames")]
    pub circuit_filenames: Vec<String>,
    #[options(help = "disable correctness checks for testing")]
    pub disable_correctness_checks: bool,
}

pub struct IntermediateTransform {
    pub transcript: Transcript,
    pub setup_id: usize,
    pub phase2_sizes: Vec<usize>,
    pub output_filenames: Vec<String>,
    pub disable_correctness_checks: bool,
}

impl IntermediateTransform {
    pub fn new(opts: &IntermediateTransformOpts) -> Result<Self> {
        let mut transcript = String::new();
        File::open(&opts.transcript_path)
            .expect("Should have opened transcript file.")
            .read_to_string(&mut transcript)
            .expect("Should have read transcript file.");
        let transcript: Transcript = serde_json::from_str::<Transcript>(&transcript)?;

        let mut phase2_sizes = vec![];
        let mut output_filenames = vec![];
        if !opts.circuit_filenames.is_empty() {
            let ceremony = transcript
                .rounds
                .iter()
                .last()
                .expect("Round not found in transcript");

            let setup = &ceremony.setups[opts.setup_id];
            for circuit_filename in opts.circuit_filenames.iter() {
                info!("Estimating powers for {}", circuit_filename);
                let phase2_size = match setup.parameters.curve_kind.as_str() {
                    "bw6" => Self::estimate_phase2_size::<BW6_761>(&circuit_filename),
                    "bls12_377" => Self::estimate_phase2_size::<Bls12_377>(&circuit_filename),
                    "mnt4_753" => Self::estimate_phase2_size::<MNT4_753>(&circuit_filename),
                    "mnt6_753" => Self::estimate_phase2_size::<MNT6_753>(&circuit_filename),
                    _ => {
                        return Err(VerifyTranscriptError::UnsupportedCurveKindError(
                            setup.parameters.curve_kind.clone(),
                        )
                        .into())
                    }
                };
                info!("Circuit {} has {} powers", circuit_filename, phase2_size);
                phase2_sizes.push(phase2_size);
                output_filenames.push(format!("{}_phase2_init", circuit_filename));
            }
        } else {
            phase2_sizes.push(
                opts.phase2_size
                    .expect("Need to give either phase2_powers or circuit_filename"),
            );
            output_filenames.push(format!("setup{}_phase2_init", opts.setup_id));
        }

        Ok(Self {
            transcript,
            setup_id: opts.setup_id,
            phase2_sizes,
            output_filenames,
            disable_correctness_checks: opts.disable_correctness_checks,
        })
    }

    fn estimate_phase2_size<P: Pairing>(circuit_filename: &str) -> usize {
        let mut file = File::open(circuit_filename).unwrap();
        let mut buffer = Vec::<u8>::new();
        file.read_to_end(&mut buffer).unwrap();
        let m = Matrices::<P>::deserialize_compressed(&*buffer).unwrap();

        // num_constraints for the modified circuit includes the original num_instance_variables
        std::cmp::max(
            m.num_constraints,
            m.num_witness_variables + m.num_instance_variables,
        )
    }

    fn run(&self) -> Result<()> {
        let ceremony = self
            .transcript
            .rounds
            .iter()
            .last()
            .expect("Round not found in transcript");

        let setup = &ceremony.setups[self.setup_id];

        let mut transformed = HashMap::new();
        let mut first = true;
        for (&phase2_size, output_filename) in
            self.phase2_sizes.iter().zip(self.output_filenames.iter())
        {
            let domain = match setup.parameters.curve_kind.as_str() {
                "bw6" => domain_size::<BW6_761>(phase2_size),
                "bls12_377" => domain_size::<Bls12_377>(phase2_size),
                "mnt4_753" => domain_size::<MNT4_753>(phase2_size),
                "mnt6_753" => domain_size::<MNT6_753>(phase2_size),
                _ => {
                    return Err(VerifyTranscriptError::UnsupportedCurveKindError(
                        setup.parameters.curve_kind.clone(),
                    )
                    .into())
                }
            };
            info!(
                "Creating intermediate transform with domain size {} for {}",
                domain, output_filename
            );
            // If circuit with same domain size exists, copy transformation.
            if let Some(existing_filename) = transformed.get(&domain) {
                // Copy.
                info!("Copying existing output.");
                copy(existing_filename, output_filename).unwrap();
            } else {
                let disable_checks = self.disable_correctness_checks || !first;
                match setup.parameters.curve_kind.as_str() {
                    "bw6" => self.transform::<BW6_761>(
                        setup,
                        phase2_size,
                        output_filename,
                        disable_checks,
                    ),
                    "bls12_377" => self.transform::<Bls12_377>(
                        setup,
                        phase2_size,
                        output_filename,
                        disable_checks,
                    ),
                    "mnt4_753" => self.transform::<MNT4_753>(
                        setup,
                        phase2_size,
                        output_filename,
                        disable_checks,
                    ),
                    "mnt6_753" => self.transform::<MNT6_753>(
                        setup,
                        phase2_size,
                        output_filename,
                        disable_checks,
                    ),
                    _ => Err(VerifyTranscriptError::UnsupportedCurveKindError(
                        setup.parameters.curve_kind.clone(),
                    )
                    .into()),
                }?;
                // As long as the phase2_size yields the same domain size, we ran reuse the result.
                transformed.insert(domain, output_filename.to_string());
            }
            first = false;
        }

        Ok(())
    }

    fn transform<E: Pairing>(
        &self,
        setup: &Setup,
        phase2_size: usize,
        output_filename: &str,
        disable_correctness_checks: bool,
    ) -> Result<()>
    where
        E::G1Affine: Neg<Output = E::G1Affine>,
    {
        info!(
            "Setup {} has {} powers",
            setup.setup_id, setup.parameters.power
        );
        let parameters = create_full_parameters::<E>(&setup.parameters)?;

        remove_file_if_exists(output_filename)?;
        phase2_cli::prepare_phase2(
            output_filename,
            setup_filename!(
                COMBINED_VERIFIED_POK_AND_CORRECTNESS_NEW_CHALLENGE_FILENAME,
                setup.setup_id
            ),
            phase2_size,
            &parameters,
            if disable_correctness_checks {
                CheckForCorrectness::No
            } else {
                CheckForCorrectness::Full
            },
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
