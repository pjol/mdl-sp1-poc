//! A simple program that takes a number `n` as input, and writes the `n-1`th and `n`th fibonacci
//! number as an output.

// These two lines are necessary for the program to properly compile.
//
// Under the hood, we wrap your main function with some extra code so that it behaves properly
// inside the zkVM.
#![no_main]
sp1_zkvm::entrypoint!(main);

use alloy_sol_types::{sol_data, SolType, SolValue};
use mdl_verification_lib::{verify_credential, PublicValues};
use alloy_primitives::{U256, Address};


pub fn main() {

    // Read input.
    let credential = sp1_zkvm::io::read::<String>();
    let address = sp1_zkvm::io::read::<String>();

    // Verify the credential signatures & get the expiration, unique ID, and city attestation.
    let (id, issued_at, city) = verify_credential(&credential);

    let a = Address::parse_checksummed(address, None).unwrap();

    let vals = PublicValues {
        owner: a,
        id,
        issuedAt: U256::from(issued_at),
        city
    };

    // Encode the public values of the program.
    let bytes = vals.abi_encode();

    // Commit to the public values of the program. The final proof will have a commitment to all the
    // bytes that were committed to.
    sp1_zkvm::io::commit_slice(&bytes);
}
