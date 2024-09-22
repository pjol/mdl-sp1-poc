use serde::{Serialize, Deserialize};

/// Custom claims encoded in the token.
#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct VPClaims {
    #[serde(rename = "iss")]
    issuer: String,
    // other fields...
}

#[cfg(test)]
mod tests {
    use std::env;
    use jwt_compact::{prelude::*, alg::{Es256}, Algorithm};
    use jwt_compact::alg::VerifyingKey;
    use crate::mdl_jwt::VPClaims;

    type PublicKey = <Es256 as Algorithm>::VerifyingKey;

    #[test]
    fn test_mdl_jwt() {
        let enc_vp_token = env::var("ENC_VP_TOKEN").unwrap();
        println!("{}", enc_vp_token);

        let token = UntrustedToken::new(&enc_vp_token).unwrap();
        println!("{}", token.algorithm());
        println!("{}", token.header().key_id.clone().unwrap());

        let key_bytes = hex::decode(
            b"04b3fb2bc13cebe87240f88f8c3bee35f4bb96ab887a58482dadf11f1d4a5dac03\
             234b6323a979ffeb0a4e40efc98f973cd76d326581748f237ce8522d3395eebd",
        ).unwrap();
        let public_key = PublicKey::from_slice(key_bytes.as_slice()).unwrap();

        let valid_token: Token<VPClaims> = Es256.validator(&public_key).validate(&token).unwrap();

    }
}