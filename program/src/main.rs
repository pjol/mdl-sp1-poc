//! A simple program that takes a number `n` as input, and writes the `n-1`th and `n`th fibonacci
//! number as an output.

// These two lines are necessary for the program to properly compile.
//
// Under the hood, we wrap your main function with some extra code so that it behaves properly
// inside the zkVM.
#![no_main]
sp1_zkvm::entrypoint!(main);

use alloy_sol_types::SolType;
use mdl_verification_lib::{verify_credential, PublicValuesStruct};


pub fn main() {

    // Read input.
    let credential = sp1_zkvm::io::read::<String>();

    // Verify the credential signature & get the expiration, unique ID, and zip code.
    let (mut ok, issued_at, city, id) = verify_credential(&credential);


    // Confirm that the credential's zip code is a valid San Francisco zip.
    if !(city.as_str() == "SAN FRANCISCO") || id == "" || issued_at == 0 {
        ok = false;
    }

    // Encode the public values of the program.
    let bytes = PublicValuesStruct::abi_encode(&PublicValuesStruct { issued_at, id, ok });

    // Commit to the public values of the program. The final proof will have a commitment to all the
    // bytes that were committed to.
    sp1_zkvm::io::commit_slice(&bytes);
}
