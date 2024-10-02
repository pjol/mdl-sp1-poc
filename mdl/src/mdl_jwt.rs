use std::str::FromStr;

use serde::{Serialize, Deserialize};
use elliptic_curve::JwkEcKey;
use elliptic_curve;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use p256::NistP256;
use jwt_compact::{alg::Es256, Algorithm};
use jwt_compact::alg::VerifyingKey;
type PubKey = <Es256 as Algorithm>::VerifyingKey;


#[derive(Debug, PartialEq, Serialize, Deserialize)]

struct CredentialSubject {
    #[serde(rename = "type")]
    credential_type: String
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]

struct VerifiableCredential {
    #[serde(rename = "credentialSubject")]
    credential_subject: CredentialSubject
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

#[cfg(test)]
mod tests {
    use std::env;
    use jwt_compact::{alg::Es256, prelude::*, Algorithm, ValidationError};
    use jwt_compact::alg::VerifyingKey;
    use super::get_public_key_from_id;
    // use p256::elliptic_curve::PublicKey;
    use crate::mdl_jwt::{VCClaims, VPClaims};

    type PubKey = <Es256 as Algorithm>::VerifyingKey;

    #[test]
    fn test_mdl_jwt_sig_match() {
        let enc_vp_token = env::var("ENC_VP_TOKEN").unwrap();
        // println!("{}", enc_vp_token);

        let token = UntrustedToken::new(&enc_vp_token).unwrap();
        // println!("{}", token.algorithm());
        // println!("{}", token.header().key_id.clone().unwrap());


        let header = token.header();
        let header_key_id = header.key_id.as_ref().unwrap().as_str();
        let jwk = get_public_key_from_id(header_key_id).unwrap();


        let public_key = PubKey::from_slice(&jwk).unwrap();


        let valid: Result<Token<VPClaims>, ValidationError> = Es256.validator(&public_key).validate(&token);
        let ok = valid.is_ok();
        assert_eq!(ok, true);
    }

    #[test]

    fn test_cred_jwt_sig_match() {
        let enc_vp_token = env::var("ENC_VP_TOKEN").unwrap();
        let token = UntrustedToken::new(&enc_vp_token).unwrap();

        let c: Claims<VPClaims> = token.deserialize_claims_unchecked().unwrap();

        // println!("{:?}", c.custom.issuer);

        let vp = &c.custom.verifiable_presentation;
        let vc = vp.verifiable_credential.first().unwrap();

        let vc_token = UntrustedToken::new(vc).unwrap();

        let header = vc_token.header();
        let header_key_id = header.key_id.as_ref().unwrap().as_str();

        let key_bytes: Vec<u8> = hex::decode(b"04dedb90c9a9356b144b730097b3dcad4920b89310b8f8f69e661a50bac025237a\
        a38e93622bff867d370ad9150e120e2f72e8b7cb5561606a34f9997e2f7a3d52").unwrap();
        println!("{:?}", key_bytes.as_slice());
        let public_key = PubKey::from_slice(key_bytes.as_slice()).unwrap();

        let valid_vc: Result<Token<VCClaims>, ValidationError> = Es256.validator(&public_key).validate(&vc_token);

        let ok = valid_vc.is_ok();

        let valid_vc_token = valid_vc.unwrap();

        let t = &valid_vc_token.claims().custom.verifiable_credential.credential_subject.credential_type;

        println!("{}", t);
        assert_eq!(ok, true)



        // let claims = valid_token.claims();

        // println!("{:?}", vp.verifiable_credential.first());

        // println!("{}", body);
    }
}
