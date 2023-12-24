use std::fmt;
use std::fs::File;
use std::io::Read;
use std::os::unix::io::{AsRawFd, RawFd};
use std::path::Path;
use std::sync::{Arc, Mutex};

use super::super::super::resources::TeeConfig;
use super::super::vstate::MeasuredRegion;

use codicon::{Decoder, Encoder};
use curl::easy::{Easy, List};
use kbs_types::{Attestation, Challenge, Request, SevChallenge, SevRequest, TeePubKey};
use kvm_bindings::{kvm_enc_region, kvm_sev_cmd};
use kvm_ioctls::VmFd;
use procfs::CpuInfo;
use serde::{Deserialize, Serialize};
use sev::certs;
use sev::firmware::host::Firmware;
use sev::launch::sev::*;
use sev::session::Session;
use vm_memory::{GuestAddress, GuestMemory, GuestMemoryMmap, GuestMemoryRegion};

#[derive(Debug)]
pub enum Error {
    AttestationRequest(curl::Error),
    DecodeAskArk,
    DecodeCek,
    DecodeChain,
    DownloadCek(curl::Error),
    DownloadAskArk(curl::Error),
    EncodeChain,
    FetchIdentifier,
    InvalidCpuData,
    OpenChainFile(std::io::Error),
    OpenFirmware(std::io::Error),
    OpenTmpFile,
    ParseAttestationSecret(serde_json::Error),
    ParseSevCertConfig(serde_json::Error),
    ParseSessionResponse(serde_json::Error),
    PlatformStatus,
    MemoryEncryptRegion,
    ReadingCpuData(procfs::ProcError),
    ReadingCoreData,
    SessionFromPolicy(std::io::Error),
    SessionRequest(curl::Error),
    SevInit(kvm_ioctls::Error),
    SevInjectSecret(kvm_ioctls::Error),
    SevLaunchFinish(kvm_ioctls::Error),
    SevLaunchMeasure(kvm_ioctls::Error),
    SevLaunchStart(kvm_ioctls::Error),
    SevLaunchUpdateData(kvm_ioctls::Error),
    SevLaunchUpdateVmsa(kvm_ioctls::Error),
    StartFromSession(std::io::Error),
    UnknownCpuModel,
}

struct CurlAgent {
    easy: Easy,
    session_id: Option<String>,
}

fn extract_session_id(header: &[u8]) -> Option<String> {
    let header = match std::str::from_utf8(header) {
        Ok(h) => h,
        Err(_) => return None,
    };

    if !header.contains("session_id") {
        return None;
    }

    let parts: Vec<&str> = header.split(';').collect();
    for p in parts {
        let elems: Vec<&str> = p.split('=').collect();
        if elems.len() == 2 && elems[0].contains("session_id") {
            return Some(elems[1].to_string());
        }
    }

    None
}

impl CurlAgent {
    fn new() -> Self {
        CurlAgent {
            easy: Easy::new(),
            session_id: None,
        }
    }

    fn get(&mut self, url: &str) -> Result<Vec<u8>, curl::Error> {
        let mut rsp = Vec::new();

        self.easy.post(false)?;
        self.easy.url(url)?;

        let mut transfer = self.easy.transfer();
        transfer.write_function(|data| {
            rsp.extend_from_slice(data);
            Ok(data.len())
        })?;
        transfer.perform()?;
        drop(transfer);

        Ok(rsp)
    }

    fn post(&mut self, url: &str, mut data: &[u8]) -> Result<Vec<u8>, curl::Error> {
        let mut rsp = Vec::new();

        let mut headers = List::new();
        headers.append("Accept: application/json")?;
        headers.append("Content-Type: application/json; charset=utf-8")?;
        if let Some(session_id) = &self.session_id {
            headers.append(&format!("Cookie: session_id={}", session_id))?;
        }

        self.easy.post(true)?;
        self.easy.post_field_size(data.len() as u64)?;
        self.easy.url(url)?;
        self.easy.http_headers(headers)?;

        let mut transfer = self.easy.transfer();
        transfer.read_function(|buf| Ok(data.read(buf).unwrap_or(0)))?;
        transfer.write_function(|data| {
            rsp.extend_from_slice(data);
            Ok(data.len())
        })?;
        transfer
            .header_function(|header| {
                if let Some(session_id) = extract_session_id(header) {
                    self.session_id = Some(session_id);
                }
                true
            })
            .unwrap();
        transfer.perform()?;
        drop(transfer);

        Ok(rsp)
    }
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

fn fetch_chain(fw: &mut Firmware, curl_agent: &mut CurlAgent) -> Result<certs::sev::Chain, Error> {
    const CEK_SVC: &str = "https://kdsintf.amd.com/cek/id";
    const ASK_ARK_SVC: &str = "https://developer.amd.com/wp-content/resources/";

    let mut chain = fw
        .pdh_cert_export()
        .expect("unable to export SEV certificates");

    let id = fw.get_identifier().map_err(|_| Error::FetchIdentifier)?;

    let rsp = curl_agent
        .get(&format!("{}/{}", CEK_SVC, id))
        .map_err(Error::DownloadCek)?;

    chain.cek = (certs::sev::sev::Certificate::decode(&mut rsp.as_slice(), ()))
        .map_err(|_| Error::DecodeCek)?;

    let cpu_model = find_cpu_model()?;

    let rsp = curl_agent
        .get(&format!("{}/ask_ark_{}.cert", ASK_ARK_SVC, cpu_model))
        .map_err(Error::DownloadCek)?;

    Ok(certs::sev::Chain {
        ca: certs::sev::ca::Chain::decode(&mut rsp.as_slice(), ())
            .map_err(|_| Error::DecodeAskArk)?,
        sev: chain,
    })
}

#[derive(Serialize, Deserialize)]
struct SevCertConfig {
    pub vendor_chain: String,
    pub attestation_server_pubkey: String,
}

fn get_and_store_chain(
    fw: &mut Firmware,
    tee_config: &TeeConfig,
    curl_agent: &mut CurlAgent,
) -> Result<certs::sev::Chain, Error> {
    let cert_config: SevCertConfig =
        serde_json::from_str(&tee_config.tee_data).map_err(Error::ParseSevCertConfig)?;

    if !cert_config.vendor_chain.is_empty() {
        let filepath = Path::new(&cert_config.vendor_chain);
        let mut file = File::open(filepath).map_err(Error::OpenChainFile)?;
        Ok(certs::sev::Chain::decode(&mut file, ()).map_err(|_| Error::DecodeChain)?)
    } else {
        let chain = fetch_chain(fw, curl_agent)?;
        let mut file = File::create("/tmp/libkrun-sev.chain").map_err(|_| Error::OpenTmpFile)?;
        chain
            .encode(&mut file, ())
            .map_err(|_| Error::EncodeChain)?;
        Ok(chain)
    }
}

/// Payload sent to the attestation server on session request.
#[derive(Serialize, Deserialize)]
struct SessionRequest {
    build: sev::Build,
    chain: sev::certs::sev::Chain,
}

/// Payload received from the attestation server on session request.
#[derive(Serialize, Deserialize)]
struct SessionResponse {
    id: String,
    start: Start,
}

pub struct AmdSev {
    tee_config: TeeConfig,
    fw: Firmware,
    start: Start,
    sev_es: bool,
    curl_agent: Arc<Mutex<CurlAgent>>,
}

impl AmdSev {
    pub fn new(tee_config: &TeeConfig) -> Result<Self, Error> {
        let mut fw = Firmware::open().map_err(Error::OpenFirmware)?;
        let mut curl_agent = CurlAgent::new();
        let chain = get_and_store_chain(&mut fw, tee_config, &mut curl_agent)?;
        let mut sev_es = false;

        let start = if !tee_config.attestation_url.is_empty() {
            let build = fw
                .platform_status()
                .map_err(|_| Error::PlatformStatus)?
                .build;

            let sev_request = SevRequest {
                build,
                chain,
                workload_id: tee_config.workload_id.clone(),
            };
            let request = Request {
                version: "0.0.0".to_string(),
                tee: tee_config.tee,
                extra_params: serde_json::json!(sev_request).to_string(),
            };

            let response = curl_agent
                .post(
                    format!("{}/kbs/v0/auth", tee_config.attestation_url).as_str(),
                    serde_json::json!(request).to_string().as_bytes(),
                )
                .map_err(Error::SessionRequest)?;

            let challenge: Challenge =
                serde_json::from_slice(&response).map_err(Error::ParseSessionResponse)?;
            let sev_challenge: SevChallenge = serde_json::from_str(&challenge.extra_params)
                .map_err(Error::ParseSessionResponse)?;

            if sev_challenge
                .start
                .policy
                .flags
                .contains(PolicyFlags::ENCRYPTED_STATE)
            {
                sev_es = true;
            }

            sev_challenge.start
        } else {
            let policy = Policy::default();
            let session = Session::try_from(policy).map_err(Error::SessionFromPolicy)?;
            session.start(chain).map_err(Error::StartFromSession)?
        };

        Ok(AmdSev {
            tee_config: tee_config.clone(),
            fw,
            start,
            sev_es,
            curl_agent: Arc::new(Mutex::new(curl_agent)),
        })
    }

    fn sev_launch_update_data(
        &self,
        vm_fd: &VmFd,
        data_uaddr: u64,
        data_size: usize,
    ) -> Result<(), kvm_ioctls::Error> {
        #[repr(C)]
        struct Data {
            addr: u64,
            size: u32,
        }

        let mut data = Data {
            addr: data_uaddr,
            size: data_size as u32,
        };

        let mut cmd = kvm_sev_cmd {
            id: 3, // SEV_LAUNCH_UPDATE_DATA
            data: &mut data as *mut _ as u64,
            error: 0,
            sev_fd: self.fw.as_raw_fd() as u32,
        };

        vm_fd.encrypt_op_sev(&mut cmd)
    }

    pub fn vm_prepare(
        &self,
        vm_fd: &VmFd,
        guest_mem: &GuestMemoryMmap,
    ) -> Result<Launcher<Started, RawFd, RawFd>, Error> {
        let vm_rfd = vm_fd.as_raw_fd();
        let fw_rfd = self.fw.as_raw_fd();

        let launcher = if self.sev_es {
            Launcher::new_es(vm_rfd, fw_rfd).unwrap()
        } else {
            Launcher::new(vm_rfd, fw_rfd).unwrap()
        };

        for region in guest_mem.iter() {
            // It's safe to unwrap because the guest address is valid.
            let host_addr = guest_mem.get_host_address(region.start_addr()).unwrap();
            let enc_region = kvm_enc_region {
                addr: host_addr as u64,
                size: region.len(),
            };
            vm_fd
                .register_enc_memory_region(&enc_region)
                .map_err(|_| Error::MemoryEncryptRegion)?;
        }

        let launcher = launcher.start(self.start).unwrap();

        Ok(launcher)
    }

    pub fn vm_attest(
        &self,
        vm_fd: &VmFd,
        guest_mem: &GuestMemoryMmap,
        measured_regions: Vec<MeasuredRegion>,
        mut launcher: Launcher<Started, RawFd, RawFd>,
    ) -> Result<(), Error> {
        for region in measured_regions {
            self.sev_launch_update_data(vm_fd, region.host_addr, region.size)
                .map_err(Error::SevLaunchUpdateData)?;
        }

        if self.sev_es {
            launcher.update_vmsa().unwrap()
        }

        let mut launcher = launcher.measure().unwrap();
        let measurement = launcher.measurement();

        if !self.tee_config.attestation_url.is_empty() {
            let tee_pubkey = TeePubKey {
                kty: "".to_string(),
                alg: "".to_string(),
                k_mod: "".to_string(),
                k_exp: "".to_string(),
            };

            let attestation = Attestation {
                tee_pubkey,
                tee_evidence: serde_json::json!(measurement).to_string(),
            };

            let mut curl_agent = self.curl_agent.lock().unwrap();
            curl_agent
                .post(
                    &format!("{}/kbs/v0/attest", self.tee_config.attestation_url,),
                    serde_json::json!(attestation).to_string().as_bytes(),
                )
                .map_err(Error::AttestationRequest)?;

            let secret_resp = curl_agent
                .get(&format!(
                    "{}/kbs/v0/key/{}",
                    self.tee_config.attestation_url, self.tee_config.workload_id,
                ))
                .map_err(Error::AttestationRequest)?;

            let secret: Secret =
                serde_json::from_slice(&secret_resp).map_err(Error::ParseAttestationSecret)?;

            let secret_host_addr = guest_mem
                .get_host_address(GuestAddress(arch::x86_64::layout::CMDLINE_START))
                .unwrap() as u64;

            launcher
                .inject(&secret, secret_host_addr.try_into().unwrap())
                .unwrap();
        }

        let _handle = launcher.finish();

        Ok(())
    }
}
