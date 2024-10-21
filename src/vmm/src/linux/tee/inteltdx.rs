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

    pub fn configure_td_memory(
        &self,
        fd: &kvm_ioctls::VmFd,
        guest_mem: &mut GuestMemoryMmap,
        ram_entries: &mut Vec<e820entry>,
        nr_ram_entries: &mut u64,
    ) -> Result<(), Error> {
        let mut hob_section = &mut TdxFirmwareEntry::default();

        // FIXME: TdxFirmwareEntry is missing the `attributes` field
        let mut sections: Vec<TdxFirmwareEntry> = self
            .tdvf_sections
            .iter()
            .map(|s| TdxFirmwareEntry {
                data_offset: s.data_offset,
                data_len: s.raw_data_size,
                address: s.memory_address,
                size: s.memory_data_size,
                r#type: s.section_type,
                mem_ptr: 0,
            })
            .collect();

        let mut tdx_ram_entries = self.init_ram_entries(ram_entries);

        let mut firmware_file =
            std::fs::File::open("/usr/share/edk2/ovmf/OVMF.inteltdx.fd").unwrap();
        for section in &sections {
            match section.r#type {
                // put Bfv and Cfv sections into the memory regions on the guest
                TdvfSectionType::Bfv | TdvfSectionType::Cfv => {
                    firmware_file
                        .seek(SeekFrom::Start(section.data_offset as u64))
                        .unwrap();
                    guest_mem
                        .read_volatile_from(
                            GuestAddress(section.address),
                            &mut firmware_file,
                            section.data_len as usize,
                        )
                        .unwrap();
                }
                TdvfSectionType::TdHob => {
                    if let Err(e) = tdx_accept_ram_range(
                        section.address,
                        section.size,
                        nr_ram_entries,
                        &mut tdx_ram_entries,
                    ) {
                        return Err(e);
                    }
                }
                TdvfSectionType::TempMem => {
                    if let Err(e) = tdx_accept_ram_range(
                        section.address,
                        section.size,
                        nr_ram_entries,
                        &mut tdx_ram_entries,
                    ) {
                        return Err(e);
                    }
                }
                _ => (),
            }
        }

        tdx_ram_entries.sort_by_key(|entry| entry.addr);
        tdx_ram_entries.reverse();

        for section in &sections {
            match section.r#type {
                TdvfSectionType::TdHob => {
                    tdvf_hob_create(section, &tdx_ram_entries, *nr_ram_entries, guest_mem)?;
                }
                _ => (),
            }
        }

        for section in &sections {
            // TODO: we should be checking to see if the KVM_CAP_MEMORY_MAPPING capability is
            // enabled, but for now just assume its not
            self.vm
                .init_mem_region(
                    fd,
                    section.address,
                    section.size / 4096,
                    // FIXME: instead of checking the section type we should be checking the
                    // attributes to see if the feature is set to extend the measurement
                    if let tdx::tdvf::TdvfSectionType::Bfv = section.r#type {
                        1
                    } else {
                        0
                    },
                    guest_mem
                        .get_host_address(vm_memory::GuestAddress(section.address))
                        .unwrap() as u64,
                )
                .unwrap();

            // TODO: if the entry is of type TD_HOB or TEMP_MEM then we need to unmap the memory
            // and set the mem_ptr to NULL (or 0 in this case)
        }

        Ok(())
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

fn tdx_add_ram_entry(
    address: u64,
    length: u64,
    ram_type: TdxRamType,
    ram_entries: &mut Vec<TdxRamEntry>,
    nr_ram_entries: &mut u64,
) {
    let mut entry = &mut ram_entries[*nr_ram_entries as usize];
    entry.addr = address;
    entry.size = length;
    entry.r#type = ram_type;
    *nr_ram_entries += 1;
}

fn tdx_accept_ram_range(
    address: u64,
    length: u64,
    nr_ram_entries: &mut u64,
    ram_entries: &mut Vec<TdxRamEntry>,
) -> Result<(), Error> {
    let mut head_start: u64;
    let mut tail_start: u64;
    let mut head_length: u64;
    let mut tail_length: u64;
    let mut e: &mut TdxRamEntry = &mut TdxRamEntry::default();
    let mut i: usize = 0;

    for idx in 0..*nr_ram_entries {
        e = &mut ram_entries[idx as usize];

        if address + length <= e.addr || e.addr + e.size <= address {
            continue;
        }

        // The to-be-accepted ram range must be fully contained by one RAM entry
        if e.addr > address || e.addr + e.size < address + length {
            return Err(Error::InvalidRamRange);
        }

        if e.r#type == TdxRamType::TDX_RAM_ADDED {
            return Err(Error::InvalidRamType);
        }

        i = idx as usize;
        break;
    }

    if i as u64 == *nr_ram_entries {
        return Err(Error::TooManyRamEntries);
    }

    let mut tmp_address = e.addr;
    let mut tmp_length = e.size;

    e.addr = address;
    e.size = length;
    e.r#type = TdxRamType::TDX_RAM_ADDED;

    head_length = address - tmp_address;
    if head_length > 0 {
        head_start = tmp_address;
        tdx_add_ram_entry(
            head_start,
            head_length,
            TdxRamType::TDX_RAM_UNACCEPTED,
            ram_entries,
            nr_ram_entries,
        );
    }

    tail_start = address + length;
    if tail_start < tmp_address + tmp_length {
        tail_length = tmp_address + tmp_length - tail_start;
        tdx_add_ram_entry(
            tail_start,
            tail_length,
            TdxRamType::TDX_RAM_UNACCEPTED,
            ram_entries,
            nr_ram_entries,
        );
    }

    Ok(())
}
