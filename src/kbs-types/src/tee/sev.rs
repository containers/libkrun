use serde::{Deserialize, Serialize};
use sev::certs::Chain;
use sev::launch::sev::Start;
use sev::Build;

#[derive(Serialize, Deserialize)]
pub struct SevRequest {
    pub build: Build,
    pub chain: Chain,
    pub workload_id: String,
}

#[derive(Serialize, Deserialize)]
pub struct SevChallenge {
    pub id: String,
    pub start: Start,
}

#[cfg(test)]
mod tests {
    use std::fmt;
    use std::fs;
    use std::path::PathBuf;

    use codicon::Decoder;
    use procfs::CpuInfo;
    use sev::certs;
    use sev::certs::Verifiable;
    use sev::firmware::Firmware;
    use sev::launch::sev::Policy;
    use sev::session::Session;

    use crate::SevChallenge;
    use crate::{Challenge, Request, SevRequest, Tee};

    #[derive(Debug)]
    enum Error {
        DecodeAskArk,
        DecodeCek,
        DownloadCek,
        DownloadAskArk,
        FetchIdentifier,
        InvalidCpuData,
        ReadingCpuData(procfs::ProcError),
        ReadingCoreData,
        UnknownCpuModel,
    }

    enum CpuModel {
        Naples,
        Rome,
        Milan,
    }

    impl fmt::Display for CpuModel {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            match self {
                CpuModel::Naples => write!(f, "naples"),
                CpuModel::Rome => write!(f, "rome"),
                CpuModel::Milan => write!(f, "milan"),
            }
        }
    }

    fn find_cpu_model() -> Result<CpuModel, Error> {
        let cpuinfo = CpuInfo::new().map_err(Error::ReadingCpuData)?;
        let coreinfo = cpuinfo.get_info(0);

        if let Some(coreinfo) = coreinfo {
            match coreinfo.get("cpu family") {
                Some(family) => match *family {
                    "23" => match coreinfo.get("model") {
                        Some(model) => match *model {
                            "1" => Ok(CpuModel::Naples),
                            "49" => Ok(CpuModel::Rome),
                            _ => Err(Error::UnknownCpuModel),
                        },
                        None => Err(Error::InvalidCpuData),
                    },
                    "25" => match coreinfo.get("model") {
                        Some(model) => match *model {
                            "1" => Ok(CpuModel::Milan),
                            _ => Err(Error::UnknownCpuModel),
                        },
                        None => Err(Error::InvalidCpuData),
                    },
                    _ => Err(Error::UnknownCpuModel),
                },
                None => Err(Error::InvalidCpuData),
            }
        } else {
            Err(Error::ReadingCoreData)
        }
    }

    fn fetch_chain(fw: &mut Firmware) -> Result<certs::Chain, Error> {
        const CEK_SVC: &str = "https://kdsintf.amd.com/cek/id";
        const ASK_ARK_SVC: &str = "https://developer.amd.com/wp-content/resources/";

        let mut chain = fw
            .pdh_cert_export()
            .expect("unable to export SEV certificates");

        let id = fw.get_identifier().map_err(|_| Error::FetchIdentifier)?;
        let url = format!("{}/{}", CEK_SVC, id);

        let mut rsp = reqwest::get(&url).map_err(|_| Error::DownloadCek)?;
        assert!(rsp.status().is_success());

        chain.cek =
            (certs::sev::Certificate::decode(&mut rsp, ())).map_err(|_| Error::DecodeCek)?;

        let cpu_model = find_cpu_model()?;
        let url = format!("{}/ask_ark_{}.cert", ASK_ARK_SVC, cpu_model);
        let mut rsp = reqwest::get(&url).map_err(|_| Error::DownloadAskArk)?;

        Ok(certs::Chain {
            ca: certs::ca::Chain::decode(&mut rsp, ()).map_err(|_| Error::DecodeAskArk)?,
            sev: chain,
        })
    }

    // This test can only run on SEV-capable machines
    #[test]
    #[ignore]
    fn marshall_sev_request() {
        let mut fw = Firmware::open().unwrap();
        let chain = fetch_chain(&mut fw).unwrap();
        let build = fw.platform_status().unwrap().build;

        let sev_request = SevRequest {
            build,
            chain,
            workload_id: "fakeid".to_string(),
        };

        let sev_request_json = serde_json::to_string(&sev_request).unwrap();

        println!("SevRequest:\n{}", sev_request_json);

        let request = Request {
            version: "0.0.0".to_string(),
            tee: Tee::Sev,
            extra_params: sev_request_json,
        };

        let request_json = serde_json::to_string(&request).unwrap();

        println!("Request:\n{}", request_json);
    }

    #[test]
    fn parse_sev_request() {
        let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        d.push("testdata/sev_request.json");

        let data = fs::read_to_string(d).unwrap();

        let request: Request = serde_json::from_str(&data).unwrap();

        assert_eq!(request.version, "0.0.0");
        assert_eq!(request.tee, Tee::Sev);

        let sev_request: SevRequest = serde_json::from_str(&request.extra_params).unwrap();

        assert_eq!(sev_request.build.version.major, 1);
        assert_eq!(sev_request.build.version.minor, 49);
        assert_eq!(sev_request.build.build, 6);
        sev_request.chain.verify().unwrap();
    }

    #[test]
    fn marshall_sev_challenge() {
        let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        d.push("testdata/sev_request.json");

        let data = fs::read_to_string(d).unwrap();

        let request: Request = serde_json::from_str(&data).unwrap();
        let sev_request: SevRequest = serde_json::from_str(&request.extra_params).unwrap();

        let policy = Policy::default();
        let session = Session::try_from(policy).unwrap();
        let start = session.start(sev_request.chain).unwrap();

        let sev_challenge = SevChallenge {
            id: "fakeid".to_string(),
            start,
        };

        let sev_challenge_json = serde_json::to_string(&sev_challenge).unwrap();

        println!("SevChallenge:\n{}", sev_challenge_json);

        let challenge = Challenge {
            nonce: "42".to_string(),
            extra_params: sev_challenge_json,
        };

        let challenge_json = serde_json::to_string(&challenge).unwrap();

        println!("Challenge:\n{}", challenge_json);
    }

    #[test]
    fn parse_sev_challenge() {
        let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        d.push("testdata/sev_challenge.json");

        let data = fs::read_to_string(d).unwrap();

        let challenge: Challenge = serde_json::from_str(&data).unwrap();

        assert_eq!(challenge.nonce, "42");

        let sev_challenge: SevChallenge = serde_json::from_str(&challenge.extra_params).unwrap();

        assert_eq!(sev_challenge.id, "fakeid");
        assert_eq!(sev_challenge.start.policy.minfw.major, 0);
        assert_eq!(sev_challenge.start.policy.minfw.minor, 0);
    }
}
