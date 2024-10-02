use alloy_sol_types::sol;
use serde::{Serialize, Deserialize};
use jwt_compact::{alg::{Es256, VerifyingKey}, prelude::*};
use elliptic_curve::JwkEcKey;
use elliptic_curve;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use p256::NistP256;
use std::str::FromStr;

sol! {
    /// The public values encoded as a struct that can be easily deserialized inside Solidity.
    struct PublicValuesStruct {
        int64 issued_at;
        string id;
        bool ok;
    }
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]

struct DriversLicense {
    #[serde(rename = "resident_city")]
    resident_city: String,

}

#[derive(Debug, PartialEq, Serialize, Deserialize)]

struct CredentialSubject {
    #[serde(rename = "driversLicense")]
    drivers_license: DriversLicense
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]

struct VerifiableCredential {
    #[serde(rename = "credentialSubject")]
    credential_subject: CredentialSubject,

    #[serde(rename = "id")]
    id: String,

}

#[derive(Debug, PartialEq, Serialize, Deserialize)]

struct VCClaims {
    #[serde(rename = "vc")]
    verifiable_credential: VerifiableCredential,

    #[serde(rename = "sub")]
    subject_id: String
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]

struct VerifiablePresentation {
    #[serde(rename = "verifiableCredential")]
    verifiable_credential: Vec<String>,
}


#[derive(Debug, PartialEq, Serialize, Deserialize)]

struct VPClaims {
    #[serde(rename = "iss")]
    issuer: String,

    #[serde(rename = "vp")]
    verifiable_presentation: VerifiablePresentation,
    // other fields...
}

pub const DMV_KEY: &[u8] = &[4, 222, 219, 144, 201, 169, 53, 107, 20, 75, 115, 0, 151, 179, 220, 173, 73, 32, 184, 147, 16, 184, 248, 246, 158, 102, 26, 80, 186, 192, 37, 35, 122, 163, 142, 147, 98, 43, 255, 134, 125, 55, 10, 217, 21, 14, 18, 14, 47, 114, 232, 183, 203, 85, 97, 96, 106, 52, 249, 153, 126, 47, 122, 61, 82];

/// Custom claims encoded in the token.

pub fn verify_credential(vp: &String) -> (bool, i64, String, String) {

    // Parse the VerifiablePresentation token from the vp string.
    let vp_token = UntrustedToken::new(vp).unwrap();

    // Extract the user's public key id from the token header.
    let key_id = vp_token.header().key_id.as_ref().unwrap();

    // Derive the bytes of the user's public key from the key id jwk and parse into a VerifyingKey struct.
    let wallet_key_bytes = get_public_key_from_id(key_id).unwrap();
    let wallet_key = VerifyingKey::from_slice(&wallet_key_bytes).unwrap();

    // Validate the signature of the VerifiablePresentation against the user's public key.
    let valid_vp: Token<VPClaims> = Es256.validator(&wallet_key).validate(&vp_token).unwrap();
    let vp_claims = valid_vp.claims();

    // Get the vc token string from the validated vp and parse into a vc token.
    let vc_string = vp_claims.custom.verifiable_presentation.verifiable_credential.first().unwrap();
    let vc_token = UntrustedToken::new(vc_string).unwrap();

    // Parse the bytes of the DMV signature into a VerifyingKey struct.
    let dmv_key = VerifyingKey::from_slice(DMV_KEY).unwrap();

    // Validate the signature of the VerifiableCredential against the DMV's known public key.
    let valid_vc: Token<VCClaims> = Es256.validator(&dmv_key).validate(&vc_token).unwrap();
    let vc_claims = valid_vc.claims();

    // Match the dmv attested public key value with the key id used to validate the VerifiablePresentation.
    let attested_id = vc_claims.custom.subject_id.clone();
    let formatted_key_id = key_id.split("#").next().unwrap();
    let matching = attested_id.as_str() == formatted_key_id;
    if !matching {
        panic!();
    }

    // All validation checks passed!
    let issued_at: i64 = vp_claims.issued_at.unwrap().timestamp();
    let city: String = vc_claims.custom.verifiable_credential.credential_subject.drivers_license.resident_city.clone();

    return (true, issued_at, city, attested_id);
}


// Helper function to parse public key bytes from a did:jwk token.
fn get_public_key_from_id(id: &str) -> Result<Box<[u8]>, String> {

    let split = id.split(":").nth(2);
    if split.is_none() {
        return Err(String::from("invalid id field"))
    }


    let split2 = split.unwrap().split("#").nth(0);
    if split2.is_none() {
        return Err(String::from("invalid id field"))
    }


    let parsed = STANDARD.decode(split2.unwrap());
    if !parsed.is_ok() {
        return Err(String::from("error parsing id"))
    }


    let key_string = String::from_utf8(parsed.unwrap().clone());
    if !key_string.is_ok() {
        return Err(String::from("error parsing id"))
    }

    let jwk = JwkEcKey::from_str(key_string.unwrap().as_str());
    if !jwk.is_ok() {
        return Err(String::from("error deriving JWK from key string"))
    }


    let key: Result<elliptic_curve::PublicKey<NistP256>, elliptic_curve::Error> = jwk.unwrap().to_public_key();
    if !key.is_ok() {
        return Err(String::from("error parsing public key from jwk"))
    }

    let jwk_bytes = key.unwrap().to_sec1_bytes();

    return Ok(jwk_bytes)

}