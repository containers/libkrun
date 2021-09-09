use std::convert::TryFrom;
use std::fs::File;
use std::mem::{size_of_val, MaybeUninit};
use std::os::unix::io::AsRawFd;

use super::vstate::MeasuredRegion;

use codicon::{Decoder, Encoder};
use kvm_bindings::kvm_enc_region;
use kvm_ioctls::{SevCommand, VmFd};
use sev::certs;
use sev::firmware::Firmware;
use sev::launch::{Measurement, Policy, Start};
use sev::session::Session;
use vm_memory::{GuestMemory, GuestMemoryMmap, GuestMemoryRegion};

#[derive(Debug)]
pub enum Error {
    DecodeAskArk,
    DecodeCek,
    DecodeChain,
    DownloadCek,
    DownloadAskArk,
    EncodeChain,
    FetchIdentifier,
    OpenFirmware(std::io::Error),
    OpenTmpFile,
    PlatformStatus,
    MemoryEncryptRegion,
    SessionFromPolicy(std::io::Error),
    SevInit(kvm_ioctls::Error),
    SevLaunchFinish(kvm_ioctls::Error),
    SevLaunchMeasure(kvm_ioctls::Error),
    SevLaunchStart(kvm_ioctls::Error),
    SevLaunchUpdateData(kvm_ioctls::Error),
    StartFromSession(std::io::Error),
}

fn fetch_chain(fw: &mut Firmware) -> Result<certs::Chain, Error> {
    const CEK_SVC: &str = "https://kdsintf.amd.com/cek/id";
    const NAPLES: &str = "https://developer.amd.com/wp-content/resources/ask_ark_naples.cert";
    const ROME: &str = "https://developer.amd.com/wp-content/resources/ask_ark_rome.cert";

    let mut chain = fw
        .pdh_cert_export()
        .expect("unable to export SEV certificates");

    let id = fw.get_identifier().map_err(|_| Error::FetchIdentifier)?;
    let url = format!("{}/{}", CEK_SVC, id);

    let mut rsp = reqwest::get(&url).map_err(|_| Error::DownloadCek)?;
    assert!(rsp.status().is_success());

    chain.cek = (certs::sev::Certificate::decode(&mut rsp, ())).map_err(|_| Error::DecodeCek)?;

    let mut rsp = reqwest::get(NAPLES).map_err(|_| Error::DownloadAskArk)?;

    Ok(certs::Chain {
        ca: certs::ca::Chain::decode(&mut rsp, ()).map_err(|_| Error::DecodeAskArk)?,
        sev: chain,
    })
}

fn get_and_store_chain(fw: &mut Firmware) -> Result<certs::Chain, Error> {
    if let Ok(mut file) = File::open("/tmp/libkrun-sev.chain") {
        Ok(certs::Chain::decode(&mut file, ()).map_err(|_| Error::DecodeChain)?)
    } else {
        let chain = fetch_chain(fw)?;
        let mut file = File::create("/tmp/libkrun-sev.chain").map_err(|_| Error::OpenTmpFile)?;
        chain
            .encode(&mut file, ())
            .map_err(|_| Error::EncodeChain)?;
        Ok(chain)
    }
}

pub struct AmdSev {
    fw: Firmware,
    start: Start,
}

impl AmdSev {
    pub fn new() -> Result<Self, Error> {
        let mut fw = Firmware::open().map_err(Error::OpenFirmware)?;

        let chain = get_and_store_chain(&mut fw)?;
        let policy = Policy::default();
        let session = Session::try_from(policy).map_err(Error::SessionFromPolicy)?;
        let start = session.start(chain).map_err(Error::StartFromSession)?;

        Ok(AmdSev { fw, start })
    }

    fn sev_init(&self, vm_fd: &VmFd) -> Result<(), kvm_ioctls::Error> {
        let mut cmd = SevCommand {
            error: 0,
            data: 0,
            fd: self.fw.as_raw_fd() as u32,
            code: 0, // SEV_INIT
        };

        vm_fd.memory_encrypt(&mut cmd)?;
        Ok(())
    }

    fn sev_launch_start(&self, vm_fd: &VmFd) -> Result<(), kvm_ioctls::Error> {
        #[repr(C)]
        struct Data {
            handle: u32,
            policy: sev::launch::Policy,
            dh_addr: u64,
            dh_size: u32,
            session_addr: u64,
            session_size: u32,
        }

        let mut data = Data {
            handle: 0,
            policy: self.start.policy,
            dh_addr: &self.start.cert as *const _ as u64,
            dh_size: size_of_val(&self.start.cert) as u32,
            session_addr: &self.start.session as *const _ as u64,
            session_size: size_of_val(&self.start.session) as u32,
        };

        let mut cmd = SevCommand {
            error: 0,
            data: &mut data as *mut _ as u64,
            fd: self.fw.as_raw_fd() as u32,
            code: 2, // SEV_LAUNCH_START
        };

        vm_fd.memory_encrypt(&mut cmd)?;
        Ok(())
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
            addr: data_uaddr as u64,
            size: data_size as u32,
        };

        let mut cmd = SevCommand {
            error: 0,
            data: &mut data as *mut _ as u64,
            fd: self.fw.as_raw_fd() as u32,
            code: 3, // SEV_LAUNCH_UPDATE_DATA
        };

        vm_fd.memory_encrypt(&mut cmd)?;
        Ok(())
    }

    fn sev_launch_measure(&self, vm_fd: &VmFd) -> Result<Measurement, kvm_ioctls::Error> {
        #[repr(C)]
        struct Data {
            addr: u64,
            size: u32,
        }

        let mut measurement: MaybeUninit<Measurement> = MaybeUninit::uninit();
        let mut data = Data {
            addr: &mut measurement as *mut _ as u64,
            size: size_of_val(&measurement) as u32,
        };

        let mut cmd = SevCommand {
            error: 0,
            data: &mut data as *mut _ as u64,
            fd: self.fw.as_raw_fd() as u32,
            code: 6, // SEV_LAUNCH_MEASURE
        };

        vm_fd.memory_encrypt(&mut cmd)?;

        Ok(unsafe { measurement.assume_init() })
    }

    fn sev_launch_finish(&self, vm_fd: &VmFd) -> Result<(), kvm_ioctls::Error> {
        let mut cmd = SevCommand {
            error: 0,
            data: 0,
            fd: self.fw.as_raw_fd() as u32,
            code: 7, // SEV_LAUNCH_FINISH
        };

        vm_fd.memory_encrypt(&mut cmd).unwrap();
        Ok(())
    }

    pub fn vm_prepare(&self, vm_fd: &VmFd, guest_mem: &GuestMemoryMmap) -> Result<(), Error> {
        self.sev_init(vm_fd).map_err(Error::SevInit)?;

        for region in guest_mem.iter() {
            // It's safe to unwrap because the guest address is valid.
            let host_addr = guest_mem.get_host_address(region.start_addr()).unwrap();
            let enc_region = kvm_enc_region {
                addr: host_addr as u64,
                size: region.len() as u64,
            };
            unsafe {
                vm_fd
                    .memory_encrypt_reg_region(&enc_region)
                    .map_err(|_| Error::MemoryEncryptRegion)?;
            }
        }

        self.sev_launch_start(vm_fd)
            .map_err(Error::SevLaunchStart)?;

        Ok(())
    }

    pub fn vm_attest(
        &self,
        vm_fd: &VmFd,
        measured_regions: Vec<MeasuredRegion>,
    ) -> Result<Measurement, Error> {
        for region in measured_regions {
            self.sev_launch_update_data(vm_fd, region.host_addr, region.size)
                .map_err(Error::SevLaunchUpdateData)?;
        }

        let measurement = self
            .sev_launch_measure(vm_fd)
            .map_err(Error::SevLaunchMeasure)?;

        self.sev_launch_finish(vm_fd)
            .map_err(Error::SevLaunchFinish)?;

        Ok(measurement)
    }
}
