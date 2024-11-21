use kvm_ioctls::VmFd;
use tdx::launch::{TdxCapabilities, TdxVm};
use tdx::tdvf::{self, TdvfSection, TdvfSectionType};
use vm_memory::{self, ByteValued, Bytes, GuestAddress, GuestMemory, GuestMemoryMmap};

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};

use arch_gen::x86::bootparam::e820entry;

const EFI_HOB_TYPE_HANDOFF: u64 = 0x0001;
const EFI_HOB_TYPE_RESOURCE_DESCRIPTOR: u64 = 0x0003;
const EFI_HOB_HANDOFF_TABLE_VERSION: u64 = 0x0009;
const EFI_HOB_TYPE_END_OF_HOB_LIST: u64 = 0xFFFF;
const EFI_RESOURCE_MEMORY_UNACCEPTED: u64 = 0x00000005;
const EFI_RESOURCE_ATTRIBUTE_TDVF_UNACCEPTED: u64 = 0x00000007;
const EFI_RESOURCE_SYSTEM_MEMORY: u64 = 0x00000000;
const EFI_RESOURCE_ATTRIBUTE_PRESENT: u64 = 0x00000001;
const EFI_RESOURCE_ATTRIBUTE_INITIALIZE: u64 = 0x00000002;
const EFI_RESOURCE_ATTRIBUTE_TESTED: u64 = 0x00000004;
const EFI_RESOURCE_ATTRIBUTE_TDVF_PRIVATE: u64 = EFI_RESOURCE_ATTRIBUTE_PRESENT
    | EFI_RESOURCE_ATTRIBUTE_INITIALIZE
    | EFI_RESOURCE_ATTRIBUTE_TESTED;
const EFI_HOB_OWNER_ZERO: EfiGuid = EfiGuid {
    data1: 0x00000000,
    data2: 0x0000,
    data3: 0x0000,
    data4: [0x00; 8],
};

type EfiResourceAttributeType = u32;
type EfiResourceType = u32;
type EfiBootMode = u32;
type EfiPhysicalAddress = u64;

#[repr(C)]
#[derive(Copy, Clone)]
struct EfiGuid {
    data1: u32,
    data2: u16,
    data3: u16,
    data4: [u8; 8],
}

#[repr(C)]
#[derive(Copy, Clone)]
struct EfiHobResourceDescriptor {
    header: EfiHobGenericHeader,
    owner: EfiGuid,
    resource_type: EfiResourceType,
    resource_attribute: EfiResourceAttributeType,
    physical_start: EfiPhysicalAddress,
    resource_length: u64,
}

#[repr(C)]
#[derive(Copy, Clone, Default)]
struct EfiHobGenericHeader {
    hob_type: u16,
    hob_length: u16,
    reserved: u32,
}

#[repr(C)]
#[derive(Copy, Clone, Default)]
struct EfiHobHandoffInfoTable {
    header: EfiHobGenericHeader,
    version: u32,
    boot_mode: EfiBootMode,
    efi_memory_top: EfiPhysicalAddress,
    efi_memory_bottom: EfiPhysicalAddress,
    efi_free_memory_top: EfiPhysicalAddress,
    efi_free_memory_bottom: EfiPhysicalAddress,
    efi_end_of_hob_list: EfiPhysicalAddress,
}

// SAFETY: data structure only contain a series of integers
unsafe impl ByteValued for EfiHobHandoffInfoTable {}
// SAFETY: data structure only contain a series of integers
unsafe impl ByteValued for EfiHobGenericHeader {}
// SAFETY: data structure only contain a series of integers
unsafe impl ByteValued for EfiHobResourceDescriptor {}

#[derive(Debug)]
pub enum Error {
    CreateTdxVmStruct,
    GetCapabilities,
    GuestMemoryWriteTdHob(vm_memory::GuestMemoryError),
    InitVm,
    MissingHobTdvfSection,
    OpenTdvfFirmwareFile(io::Error),
    ParseTdvfSections(tdvf::Error),
    InvalidRamRange,
    InvalidRamType,
    TooManyRamEntries,
    FinalizeVm,
}

pub struct IntelTdx {
    caps: TdxCapabilities,
    vm: TdxVm,
    tdvf_sections: Vec<TdvfSection>,
    tdvf_file: File,
}

impl IntelTdx {
    pub fn new(vm_fd: &VmFd) -> Result<Self, Error> {
        // FIXME(jakecorrenti): need to specify the max number of VCPUs here and not just assume 100. This should come from the VmResources that we set when doing krun_set_vm_config()
        let vm = TdxVm::new(vm_fd, 100).or_else(|_| return Err(Error::CreateTdxVmStruct))?;
        let caps = vm
            .get_capabilities(vm_fd)
            .or_else(|_| return Err(Error::GetCapabilities))?;

        let mut firmware = std::fs::File::open("/usr/share/edk2/ovmf/OVMF.inteltdx.fd")
            .map_err(Error::OpenTdvfFirmwareFile)?;
        let tdvf_sections =
            tdx::tdvf::parse_sections(&mut firmware).map_err(Error::ParseTdvfSections)?;

        Ok(IntelTdx {
            caps,
            vm,
            tdvf_sections,
            tdvf_file: firmware,
        })
    }

    pub fn vm_prepare(
        &self,
        fd: &kvm_ioctls::VmFd,
        cpuid: kvm_bindings::CpuId,
    ) -> Result<(), Error> {
        self.vm
            .init_vm(fd, cpuid)
            .or_else(|_| return Err(Error::InitVm))?;

        Ok(())
    }

    pub fn get_tdvf_hob_address(&self) -> Result<u64, Error> {
        for section in &self.tdvf_sections {
            if let TdvfSectionType::TdHob = section.section_type {
                return Ok(section.memory_address);
            }
        }
        Err(Error::MissingHobTdvfSection)
    }

    pub fn configure_td_memory(
        &self,
        fd: &kvm_ioctls::VmFd,
        guest_mem: &mut GuestMemoryMmap,
        ram_entries: &mut Vec<e820entry>,
        nr_ram_entries: &mut u64,
    ) -> Result<(), Error> {
        let mut tdx_firmware_entries: Vec<TdxFirmwareEntry> = self
            .tdvf_sections
            .iter()
            .map(|&s| TdxFirmwareEntry {
                data_offset: s.data_offset,
                data_len: s.raw_data_size,
                address: s.memory_address,
                size: s.memory_data_size,
                r#type: s.section_type,
                attributes: s.attributes,
                mem_ptr: guest_mem
                    .get_host_address(vm_memory::GuestAddress(s.memory_address))
                    .unwrap() as u64,
            })
            .collect();

        let mut tdx_ram_entries = tdx_init_ram_entries(&ram_entries[0..(*nr_ram_entries as usize)]);

        for entry in tdx_firmware_entries {
            match entry.r#type {
                TdvfSectionType::TempMem | TdvfSectionType::TdHob => {
                    let ret = tdx_accept_ram_range(&mut tdx_ram_entries, entry.address, entry.size);
                    if ret < 0 {
                        panic!("unable to accept ram range");
                    }
                }
                _ => (),
            }
        }

        tdx_ram_entries.sort_by(|a, b| a.address.cmp(&b.address));

        Ok(())
    }

    pub fn finalize_vm(&self, fd: &kvm_ioctls::VmFd) -> Result<(), Error> {
        self.vm
            .finalize(fd)
            .or_else(|_| return Err(Error::FinalizeVm))
    }
}

#[derive(Debug, Default)]
struct TdxFirmwareEntry {
    data_offset: u32,
    data_len: u32,
    address: u64,
    size: u64,
    r#type: TdvfSectionType,
    attributes: u32,
    mem_ptr: u64,
}

#[derive(Copy, Clone, Debug, Default)]
enum TdxRamType {
    #[default]
    TdxRamUnaccepted,
    TdxRamAdded,
}

#[derive(Copy, Clone, Debug, Default)]
struct TdxRamEntry {
    address: u64,
    length: u64,
    r#type: TdxRamType,
}

fn tdx_init_ram_entries(entries: &[e820entry]) -> Vec<TdxRamEntry> {
    entries
        .iter()
        .map(|e| TdxRamEntry {
            address: e.addr,
            length: e.size,
            r#type: TdxRamType::TdxRamUnaccepted,
        })
        .collect()
}

fn tdx_accept_ram_range(ram_entries: &mut Vec<TdxRamEntry>, address: u64, length: u64) -> i32 {
    let mut found_entry: Option<&mut TdxRamEntry> = None;

    for entry in ram_entries.iter_mut() {
        if address + length <= entry.address || entry.address + entry.length <= address {
            continue;
        }

        if entry.address > address || entry.address + entry.length < address + length {
            return -libc::EINVAL;
        }

        if let TdxRamType::TdxRamAdded = entry.r#type {
            return -libc::EINVAL;
        }

        found_entry = Some(entry);
    }

    let found_entry = found_entry.unwrap();

    let tmp_address = found_entry.address;
    let tmp_length = found_entry.length;

    found_entry.address = address;
    found_entry.length = length;
    found_entry.r#type = TdxRamType::TdxRamAdded;

    // determine the chunk of the ram range before the newly added range
    let head_length = address - tmp_address;
    if head_length > 0 {
        let head_start = tmp_address;
        ram_entries.push(TdxRamEntry {
            address: head_start,
            length: head_length,
            r#type: TdxRamType::TdxRamUnaccepted,
        });
    }

    // determine the chunk of the ram range after the newly added range
    let tail_start = address + length;
    // check if the start of the ram range after the newly added range begins before the old
    // range's end
    if tail_start < tmp_address + tmp_length {
        let tail_length = tmp_address + tmp_length - tail_start;
        ram_entries.push(TdxRamEntry {
            address: tail_start,
            length: tail_length,
            r#type: TdxRamType::TdxRamUnaccepted,
        });
    }

    0
}
