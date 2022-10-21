use serde::{Deserialize, Serialize};

mod tee;
#[cfg(feature = "tee-sev")]
pub use tee::sev::{SevChallenge, SevRequest};

#[derive(Serialize, Clone, Deserialize, Debug, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Tee {
    Sev,
    Sgx,
    Snp,
    Tdx,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Request {
    pub version: String,
    pub tee: Tee,
    #[serde(rename = "extra-params")]
    pub extra_params: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Challenge {
    pub nonce: String,
    #[serde(rename = "extra-params")]
    pub extra_params: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct TeePubKey {
    pub kty: String,
    pub alg: String,
    pub k: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Attestation {
    #[serde(rename = "tee-pubkey")]
    pub tee_pubkey: TeePubKey,
    #[serde(rename = "tee-evidence")]
    pub tee_evidence: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Response {
    pub protected: String,
    pub encrypted_key: String,
    pub iv: String,
    pub ciphertext: String,
    pub tag: String,
}

#[cfg(test)]
mod tests {
    use crate::*;

    #[test]
    fn parse_request() {
        let data = r#"
        {
            "version": "0.0.0",
            "tee": "sev",
            "extra-params": ""
        }"#;

        let request: Request = serde_json::from_str(data).unwrap();

        assert_eq!(request.version, "0.0.0");
        assert_eq!(request.tee, Tee::Sev);
        assert_eq!(request.extra_params, "");
    }

    #[test]
    fn parse_challenge() {
        let data = r#"
        {
            "nonce": "42",
            "extra-params": ""
        }"#;

        let challenge: Challenge = serde_json::from_str(data).unwrap();

        assert_eq!(challenge.nonce, "42");
        assert_eq!(challenge.extra_params, "");
    }

    #[test]
    fn parse_response() {
        let data = r#"
        {
            "protected": "fakejoseheader",
            "encrypted_key": "fakekey",
            "iv": "randomdata",
            "ciphertext": "fakeencoutput",
            "tag": "faketag"
        }"#;

        let response: Response = serde_json::from_str(data).unwrap();

        assert_eq!(response.protected, "fakejoseheader");
        assert_eq!(response.encrypted_key, "fakekey");
        assert_eq!(response.iv, "randomdata");
        assert_eq!(response.ciphertext, "fakeencoutput");
        assert_eq!(response.tag, "faketag");
    }

    #[test]
    fn parse_attesation() {
        let data = r#"
        {
            "tee-pubkey": {
                "kty": "fakekeytype",
                "alg": "fakealgorithm",
                "k": "fakepubkey"
            },
            "tee-evidence": "fakeevidence"
        }"#;

        let attestation: Attestation = serde_json::from_str(data).unwrap();

        assert_eq!(attestation.tee_pubkey.kty, "fakekeytype");
        assert_eq!(attestation.tee_pubkey.alg, "fakealgorithm");
        assert_eq!(attestation.tee_pubkey.k, "fakepubkey");
        assert_eq!(attestation.tee_evidence, "fakeevidence");
    }
}
