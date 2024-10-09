//! An end-to-end example of using the SP1 SDK to generate a proof of a program that can be executed
//! or have a core proof generated.
//!
//! You can run this script using the following command:
//! ```shell
//! RUST_LOG=info cargo run --release -- --execute
//! ```
//! or
//! ```shell
//! RUST_LOG=info cargo run --release -- --prove
//! ```

use alloy_sol_types::SolType;
use clap::Parser;
use mdl_verification_lib::PublicValues;
use sp1_sdk::{ProverClient, SP1Stdin};

/// The ELF (executable and linkable format) file for the Succinct RISC-V zkVM.
pub const MDL_ELF: &[u8] = include_bytes!("../../../elf/riscv32im-succinct-zkvm-elf");

/// The arguments for the command.
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(long)]
    execute: bool,

    #[clap(long)]
    prove: bool,

    #[clap(long, default_value = "test")]
    cred: String,

    #[clap(long, default_value = "0x0000000000000000000000000000000000000000")]
    address: String,
}

fn main() {
    // Setup the logger.
    sp1_sdk::utils::setup_logger();

    // Parse the command line arguments.
    let args = Args::parse();

    if args.execute == args.prove {
        eprintln!("Error: You must specify either --execute or --prove");
        std::process::exit(1);
    }

    // Setup the prover client.
    let client = ProverClient::new();

    // Setup the inputs.
    let mut stdin = SP1Stdin::new();
    stdin.write(&args.cred);
    stdin.write(&args.address);

    println!("jwk: {}", args.cred);

    if args.execute {
        // Execute the program
        let (output, report) = client.execute(MDL_ELF, stdin).run().unwrap();
        println!("Program executed successfully.");

        let bytes = output.as_slice();
        println!("{}", format!("0x{}", hex::encode(bytes)));

        // Read the output.
        let vals = PublicValues::abi_decode(bytes, true).unwrap();
        let id = vals.id;
        let city = vals.city;
        let issued_at = vals.issuedAt;
        let owner = vals.owner;
        println!("id: {}", id);
        println!("city: {}", city);
        println!("issued at: {}", issued_at);
        println!("new owner: {}", owner);

        let (verified_id, verified_issued_at, verified_city) = mdl_verification_lib::verify_credential(&args.cred);
        assert_eq!(verified_id, id);
        assert_eq!(verified_city, city);
        assert_eq!(verified_issued_at, issued_at);
        println!("Values are correct!");

        // Record the number of cycles executed.
        println!("Number of cycles: {}", report.total_instruction_count());
    } else {
        // Setup the program for proving.
        let (pk, vk) = client.setup(MDL_ELF);

        // Generate the proof
        let proof = client
            .prove(&pk, stdin)
            .compressed()
            .run()
            .expect("failed to generate proof");

        println!("Successfully generated proof!");

        // Verify the proof.
        client.verify(&proof, &vk).expect("failed to verify proof");
        println!("Successfully verified proof!");
    }
}
