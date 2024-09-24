use serde::{Serialize, Deserialize};

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

#[cfg(test)]
mod tests {
    use std::env;
    use jwt_compact::{alg::Es256, prelude::*, Algorithm, ValidationError};
    use jwt_compact::alg::VerifyingKey;
    // use p256::elliptic_curve::PublicKey;
    use crate::mdl_jwt::{VCClaims, VPClaims};

    type PublicKey = <Es256 as Algorithm>::VerifyingKey;

    #[test]
    fn test_mdl_jwt() {
        let enc_vp_token = env::var("ENC_VP_TOKEN").unwrap();
        // println!("{}", enc_vp_token);

        let token = UntrustedToken::new(&enc_vp_token).unwrap();
        // println!("{}", token.algorithm());
        // println!("{}", token.header().key_id.clone().unwrap());

        let key_bytes = hex::decode(
            b"04b3fb2bc13cebe87240f88f8c3bee35f4bb96ab887a58482dadf11f1d4a5dac03\
             234b6323a979ffeb0a4e40efc98f973cd76d326581748f237ce8522d3395eebd",
        ).unwrap();
        let public_key = PublicKey::from_slice(key_bytes.as_slice()).unwrap();

        let valid: Result<Token<VPClaims>, ValidationError> = Es256.validator(&public_key).validate(&token);
        let ok = valid.is_ok();
        assert_eq!(ok, true);
    }

    #[test]

    fn test_cred_jwt() {
        let enc_vp_token = env::var("ENC_VP_TOKEN").unwrap();
        let token = UntrustedToken::new(&enc_vp_token).unwrap();

        let c: Claims<VPClaims> = token.deserialize_claims_unchecked().unwrap();

        // println!("{:?}", c.custom.issuer);

        let vp = &c.custom.verifiable_presentation;
        let vc = vp.verifiable_credential.first().unwrap();

        let vc_token = UntrustedToken::new(vc).unwrap();


        let key_bytes: Vec<u8> = hex::decode(b"04dedb90c9a9356b144b730097b3dcad4920b89310b8f8f69e661a50bac025237a\
        a38e93622bff867d370ad9150e120e2f72e8b7cb5561606a34f9997e2f7a3d52").unwrap();
        let public_key = PublicKey::from_slice(key_bytes.as_slice()).unwrap();

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