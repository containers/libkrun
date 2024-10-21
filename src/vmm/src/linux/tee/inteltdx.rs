use kvm_ioctls::VmFd;
use tdx::launch::{TdxCapabilities, TdxVm};
use tdx::tdvf::{self, TdvfSection, TdvfSectionType};
use vm_memory::{self, ByteValued, Bytes, GuestAddress, GuestMemory, GuestMemoryMmap};

use std::fs::File;
use std::io;

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
}

pub struct IntelTdx {
    caps: TdxCapabilities,
    vm: TdxVm,
    tdvf_sections: Vec<TdvfSection>,
    tdvf_file: File,
}

impl IntelTdx {
    pub fn new(vm_fd: &VmFd) -> Result<Self, Error> {
        // FIXME(jakecorrenti): need to specify the max number of VCPUs here and not just assume 100
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

    fn init_ram_entries(&self, ram_entries: &Vec<e820entry>) -> Vec<TdxRamEntry> {
        ram_entries
            .iter()
            .map(|entry| TdxRamEntry {
                addr: entry.addr,
                size: entry.size,
                r#type: TdxRamType::TDX_RAM_UNACCEPTED,
            })
            .collect()
    }
}

#[derive(Debug, Default, PartialEq)]
enum TdxRamType {
    #[default]
    TDX_RAM_UNACCEPTED,
    TDX_RAM_ADDED,
}

#[derive(Default)]
struct TdxRamEntry {
    addr: u64,
    size: u64,
    r#type: TdxRamType,
}

#[derive(Debug, Default)]
struct TdxFirmwareEntry {
    data_offset: u32,
    data_len: u32,
    address: u64,
    size: u64,
    r#type: TdvfSectionType,
    mem_ptr: u64,
}

#[repr(C)]
struct TdHob {
    hob_addr: u64,
    ptr: u64,
    size: u32,

    // working area
    current: u64,
    end: u64,
}

impl TdHob {
    fn new(hob_entry: &TdxFirmwareEntry) -> Self {
        Self {
            hob_addr: hob_entry.address,
            size: hob_entry.size as u32,
            ptr: hob_entry.mem_ptr,
            current: hob_entry.mem_ptr,
            end: hob_entry.mem_ptr + hob_entry.size,
        }
    }
}

fn align_down(n: u64, m: u64) -> u64 {
    n / m * m
}

fn align_up(n: u64, m: u64) -> u64 {
    align_down(n + m - 1, m)
}

// FIXME: can simplify this to (hob.current + 7) / 8 * 8
fn tdvf_align(hob: &TdHob, align: usize) -> u64 {
    align_up(hob.current, align as u64)
}

fn tdvf_get_area(hob: &mut TdHob, size: u64) -> u64 {
    if hob.current + size > hob.end {
        panic!("TD_HOB overrun, size 0x{:x}", size);
    }

    let ret = hob.current;
    hob.current += size;
    tdvf_align(&hob, 8);
    ret
}

fn tdvf_hob_add_memory_resources(
    hob: &mut TdHob,
    ram_entries: &Vec<TdxRamEntry>,
    nr_ram_entries: u64,
    guest_mem: &mut GuestMemoryMmap,
) -> Result<(), Error> {
    let mut region: EfiHobResourceDescriptor;
    let mut attr: EfiResourceAttributeType;
    let mut resource_type: EfiResourceType;

    for i in 0..nr_ram_entries {
        let entry = &ram_entries[i as usize];

        match entry.r#type {
            TdxRamType::TDX_RAM_UNACCEPTED => {
                resource_type = EFI_RESOURCE_MEMORY_UNACCEPTED as u32;
                attr = EFI_RESOURCE_ATTRIBUTE_TDVF_UNACCEPTED as u32;
            }
            TdxRamType::TDX_RAM_ADDED => {
                resource_type = EFI_RESOURCE_SYSTEM_MEMORY as u32;
                attr = EFI_RESOURCE_ATTRIBUTE_TDVF_PRIVATE as u32;
            }
            _ => {
                panic!("unknown TdxRamType: {:?}", entry.r#type);
            }
        }

        let region_area =
            tdvf_get_area(hob, std::mem::size_of::<EfiHobResourceDescriptor>() as u64);
        region = EfiHobResourceDescriptor {
            header: EfiHobGenericHeader {
                hob_type: EFI_HOB_TYPE_RESOURCE_DESCRIPTOR as u16,
                hob_length: std::mem::size_of::<EfiHobResourceDescriptor>() as u16,
                reserved: 0,
            },
            owner: EFI_HOB_OWNER_ZERO,
            resource_type,
            resource_attribute: attr,
            physical_start: entry.addr,
            resource_length: entry.size,
        };
        guest_mem
            .write_obj(region, GuestAddress(region_area))
            .map_err(Error::GuestMemoryWriteTdHob)?;
    }
    Ok(())
}

fn tdvf_current_guest_addr(hob: &TdHob) -> u64 {
    hob.hob_addr + (hob.current - hob.ptr)
}

fn tdvf_hob_create(
    hob_entry: &TdxFirmwareEntry,
    ram_entries: &Vec<TdxRamEntry>,
    nr_ram_entries: u64,
    guest_mem: &mut GuestMemoryMmap,
) -> Result<(), Error> {
    let mut hob = TdHob::new(&hob_entry);

    // here we wnt to set the address of hit to be the one that we get from this function...
    // how would I do that in rust because I don't think this will work...
    let hit_area = tdvf_get_area(
        &mut hob,
        std::mem::size_of::<EfiHobHandoffInfoTable>() as u64,
    );

    tdvf_hob_add_memory_resources(&mut hob, &ram_entries, nr_ram_entries, guest_mem)?;

    // here we wnt to set the address of hit to be the one that we get from this function...
    // how would I do that in rust because I don't think this will work...
    let last_hob_area = tdvf_get_area(&mut hob, std::mem::size_of::<EfiHobGenericHeader>() as u64);
    let mut last_hob = EfiHobGenericHeader {
        hob_type: EFI_HOB_TYPE_END_OF_HOB_LIST as u16,
        hob_length: std::mem::size_of::<EfiHobGenericHeader>() as u16,
        reserved: 0,
    };
    guest_mem
        .write_obj(last_hob, GuestAddress(last_hob_area))
        .map_err(Error::GuestMemoryWriteTdHob)?;

    // NOTE: this is done out of order when compared to QEMU... hoping that this works since we
    // kept track of the hit area. we need to do this so we can write the `efi_end_of_hob_list`
    // value
    let mut hit = EfiHobHandoffInfoTable {
        header: EfiHobGenericHeader {
            hob_type: EFI_HOB_TYPE_HANDOFF as u16,
            hob_length: std::mem::size_of::<EfiHobHandoffInfoTable>() as u16,
            reserved: 0,
        },
        version: EFI_HOB_HANDOFF_TABLE_VERSION as u32,
        efi_end_of_hob_list: tdvf_current_guest_addr(&hob),
        // NOTE: Efi{free}Memory{Bottom, Top} are ignored, leave 'em zeroed
        ..Default::default()
    };
    guest_mem
        .write_obj(hit, GuestAddress(hit_area))
        .map_err(Error::GuestMemoryWriteTdHob)
}
