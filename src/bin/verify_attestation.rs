use gumdrop::Options;
use nimiq_keys::{Address, PublicKey, Signature};
use snark_setup_operator::utils::extract_signature_from_attestation;
use std::io::Read;
use std::str::FromStr;

#[derive(Debug, Options, Clone)]
pub struct VerifyAttestationOpts {
    help: bool,
    #[options(
        help = "the path of the output keys file",
        default = "nimiq.attestation.txt"
    )]
    pub attestation_path: String,
    #[options(help = "the expected address", required)]
    pub expected_address: Address,
}

fn main() {
    let opts: VerifyAttestationOpts = VerifyAttestationOpts::parse_args_default_or_exit();
    let mut file =
        std::fs::File::open(&opts.attestation_path).expect("Should have opened attestation file");
    let mut contents = String::new();
    file.read_to_string(&mut contents)
        .expect("Should have read attestation");
    let (message, public_key_hex, signature) = extract_signature_from_attestation(&contents)
        .expect("Should have extracted signature from attestation");
    println!(
        "Verifying message \"{}\" with address \"{}\" and signature \"{}\"",
        message, public_key_hex, signature
    );
    let public_key = PublicKey::from_str(&public_key_hex).expect("Could not decode public key");
    let signature = Signature::from_str(&signature).expect("Should have parsed signature");
    if !public_key.verify(&signature, message.as_bytes()) {
        panic!("Could not verify signature.");
    }
    let address = Address::from(&public_key);
    if address != opts.expected_address {
        panic!(
            "Addresses were different. Expected {}, got {}",
            opts.expected_address, address
        );
    }
    println!("Attestation verified successfully!");
}
