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
    pub workload_id: String,
    pub tee: Tee,
    pub extra_params: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Challenge {
    pub nonce: String,
    pub extra_params: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct TeePubKey {
    pub algorithm: String,
    #[serde(rename = "pubkey-length")]
    pub pubkey_length: String,
    pub pubkey: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Attestation {
    pub nonce: String,
    pub tee: Tee,
    #[serde(rename = "tee-pubkey")]
    pub tee_pubkey: TeePubKey,
    #[serde(rename = "tee-evidence")]
    pub tee_evidence: String,
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct CryptoAnnotation {
    pub algorithm: String,
    #[serde(rename = "initialization-vector")]
    pub initialization_vector: String,
    #[serde(rename = "enc-symkey")]
    pub enc_symkey: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Response {
    pub output: String,
    #[serde(rename = "crypto-annotation")]
    pub crypto_annotation: CryptoAnnotation,
}

#[cfg(test)]
mod tests {
    use crate::*;

    #[test]
    fn parse_request() {
        let data = r#"
        {
            "version": "0.0.0",
            "workload_id": "fakeid",
            "tee": "sev",
            "extra_params": ""
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
            "extra_params": ""
        }"#;

        let challenge: Challenge = serde_json::from_str(data).unwrap();

        assert_eq!(challenge.nonce, "42");
        assert_eq!(challenge.extra_params, "");
    }

    #[test]
    fn parse_response() {
        let data = r#"
        {
            "output": "fakeoutput",
            "crypto-annotation": {
                "algorithm": "fake-4096",
                "initialization-vector": "randomdata",
                "enc-symkey": "fakesymkey"
            }
        }"#;

        let response: Response = serde_json::from_str(data).unwrap();

        assert_eq!(response.output, "fakeoutput");
        assert_eq!(response.crypto_annotation.algorithm, "fake-4096");
        assert_eq!(
            response.crypto_annotation.initialization_vector,
            "randomdata"
        );
        assert_eq!(response.crypto_annotation.enc_symkey, "fakesymkey");
    }

    #[test]
    fn parse_attesation() {
        let data = r#"
        {
            "nonce": "42",
            "tee": "sev",
            "tee-pubkey": {
                "algorithm": "fake-4096",
                "pubkey-length": "4096",
                "pubkey": "fakepubkey"
            },
            "tee-evidence": "fakeevidence"
        }"#;

        let attestation: Attestation = serde_json::from_str(data).unwrap();

        assert_eq!(attestation.nonce, "42");
        assert_eq!(attestation.tee, Tee::Sev);
        assert_eq!(attestation.tee_pubkey.algorithm, "fake-4096");
        assert_eq!(attestation.tee_pubkey.pubkey_length, "4096");
        assert_eq!(attestation.tee_pubkey.pubkey, "fakepubkey");
        assert_eq!(attestation.tee_evidence, "fakeevidence");
    }
}
