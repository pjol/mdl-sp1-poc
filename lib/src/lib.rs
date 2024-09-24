use alloy_sol_types::sol;
use serde::{Serialize, Deserialize};
use jwt_compact::{alg::{Es256, VerifyingKey}, prelude::*, ValidationError};

sol! {
    /// The public values encoded as a struct that can be easily deserialized inside Solidity.
    struct PublicValuesStruct {
        int64 expiration;
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
}

/// Custom claims encoded in the token.
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

/// Compute the n'th fibonacci number (wrapping around on overflows), using normal Rust code.
pub fn verify_credential(enc_vp_token: &String) -> (bool, i64, String, String) {
    let token = UntrustedToken::new(enc_vp_token.as_str()).unwrap();

    let c: Claims<VPClaims> = token.deserialize_claims_unchecked().unwrap();

    // println!("{:?}", c.custom.issuer);

    let vp = &c.custom.verifiable_presentation;
    let vc = vp.verifiable_credential.first().unwrap();

    let vc_token = UntrustedToken::new(vc).unwrap();


    let key_bytes: Vec<u8> = hex::decode(b"04dedb90c9a9356b144b730097b3dcad4920b89310b8f8f69e661a50bac025237a\
    a38e93622bff867d370ad9150e120e2f72e8b7cb5561606a34f9997e2f7a3d52").unwrap();
    let public_key = VerifyingKey::from_slice(key_bytes.as_slice()).unwrap();

    let valid_vc: Result<Token<VCClaims>, ValidationError> = Es256.validator(&public_key).validate(&vc_token);

    let ok = valid_vc.is_ok();
    let mut expiration: i64 = 0;
    let mut city: String = String::from("");
    let mut id: String = String::from("");
    if ok {
        let valid_vc_token = valid_vc.unwrap();
        let claims = valid_vc_token.claims();
        expiration = claims.expiration.unwrap().timestamp();
        city = claims.custom.verifiable_credential.credential_subject.drivers_license.resident_city.clone();
        id = claims.custom.verifiable_credential.id.clone();
    } else {
        let error = valid_vc.unwrap_err();
        println!("{:?}", error)
    }

    return (ok, expiration, city, id);
}
