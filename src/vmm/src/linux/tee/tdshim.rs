use std::fmt::{self, Display, Formatter};
use std::fs::File;
use std::io::{self, Read, Seek};
use std::mem;
use std::path::Path;

use tdx::tdvf::{self, TdvfSection, TdvfSectionType};
use vm_memory::{ByteValued, Bytes, GuestAddress, GuestMemoryMmap};

const HOB_TYPE_PHIT: u16 = 0x0001;
const HOB_TYPE_RESOURCE: u16 = 0x0003;
const HOB_TYPE_GUID_EXT: u16 = 0x0004;
const HOB_TYPE_END: u16 = 0xFFFF;
const EFI_RESOURCE_SYSTEM_MEMORY: u32 = 0x00000000;
// PRESENT | INITIALIZED | TESTED (bits 0–2). 0x307 would also set
// WRITE_PROTECTED | EXECUTION_PROTECTED, which is wrong for system RAM.
// td-shim ignores those bits today, but QEMU uses 0x7 and so do we.
const EFI_RESOURCE_ATTR_TESTED: u32 = 0x7;

// B96FA412-461F-4BE3-8C0D-AD805A497AC0
const PAYLOAD_INFO_GUID: [u8; 16] = [
    0x12, 0xa4, 0x6f, 0xb9, 0x1f, 0x46, 0xe3, 0x4b, 0x8c, 0x0d, 0xad, 0x80, 0x5a, 0x49, 0x7a, 0xc0,
];

#[derive(Debug)]
pub enum Error {
    OpenFirmware(io::Error),
    ReadFirmware(io::Error),
    ParseSections(tdx::tdvf::Error),
    InvalidSectionOffset,
    MissingBfv,
    MissingTdHob,
    HobRegionTooSmall,
    GuestMemory(vm_memory::GuestMemoryError),
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            Self::OpenFirmware(e) => write!(f, "Unable to open TDShim firmware: {e}"),
            Self::ReadFirmware(e) => write!(f, "Unable to read TDShim firmware: {e}"),
            Self::ParseSections(e) => write!(f, "Unable to parse TDShim sections: {e}"),
            Self::InvalidSectionOffset => write!(f, "Invalid TDShim section offset"),
            Self::MissingBfv => write!(f, "TDShim missing BFV section"),
            Self::MissingTdHob => write!(f, "TDShim missing TD HOB section"),
            Self::HobRegionTooSmall => write!(f, "TDShim TD HOB region too small"),
            Self::GuestMemory(e) => {
                write!(f, "Unable to write TDShim data to guest memory: {e}")
            }
        }
    }
}

type Result<T> = std::result::Result<T, Error>;

pub struct TdShim {
    pub sections: Vec<TdvfSection>,
    pub hob_address: u64,
    pub firmware_data: Vec<u8>,
}

#[derive(Copy, Clone, Default)]
#[repr(C, packed)]
struct HobHeader {
    hob_type: u16,
    hob_length: u16,
    reserved: u32,
}
unsafe impl ByteValued for HobHeader {}

impl HobHeader {
    fn new(hob_type: u16, hob_length: u16) -> Self {
        Self {
            hob_type,
            hob_length,
            reserved: 0,
        }
    }
}

#[derive(Copy, Clone)]
#[repr(C, packed)]
struct PhitHob {
    header: HobHeader,
    version: u32,
    boot_mode: u32,
    efi_memory_top: u64,
    efi_memory_bottom: u64,
    efi_free_memory_top: u64,
    efi_free_memory_bottom: u64,
    efi_end_of_hob_list: u64,
}
unsafe impl ByteValued for PhitHob {}

impl Default for PhitHob {
    fn default() -> Self {
        Self {
            header: HobHeader::new(HOB_TYPE_PHIT, mem::size_of::<PhitHob>() as u16),
            version: 0x0009,
            boot_mode: 0,
            efi_memory_top: 0,
            efi_memory_bottom: 0,
            efi_free_memory_top: 0,
            efi_free_memory_bottom: 0,
            efi_end_of_hob_list: 0,
        }
    }
}

#[derive(Copy, Clone)]
#[repr(C, packed)]
struct ResourceHob {
    header: HobHeader,
    owner: [u8; 16],
    resource_type: u32,
    resource_attributes: u32,
    physical_start: u64,
    resource_length: u64,
}
unsafe impl ByteValued for ResourceHob {}

impl Default for ResourceHob {
    fn default() -> Self {
        Self {
            header: HobHeader::new(HOB_TYPE_RESOURCE, mem::size_of::<ResourceHob>() as u16),
            owner: [0u8; 16],
            resource_type: EFI_RESOURCE_SYSTEM_MEMORY,
            resource_attributes: EFI_RESOURCE_ATTR_TESTED,
            physical_start: 0,
            resource_length: 0,
        }
    }
}

#[derive(Copy, Clone, Default)]
#[repr(C, packed)]
struct GuidExtHobHeader {
    header: HobHeader,
    name: [u8; 16],
}
unsafe impl ByteValued for GuidExtHobHeader {}

#[derive(Copy, Clone)]
#[repr(C, packed)]
struct PayloadInfoHob {
    guid_header: GuidExtHobHeader,
    image_type: u32,
    reserved: u32,
    entry_point: u64,
}
unsafe impl ByteValued for PayloadInfoHob {}

impl Default for PayloadInfoHob {
    fn default() -> Self {
        Self {
            guid_header: GuidExtHobHeader {
                header: HobHeader::new(HOB_TYPE_GUID_EXT, mem::size_of::<PayloadInfoHob>() as u16),
                name: PAYLOAD_INFO_GUID,
            },
            // libkrunfw packages the kernel as a raw ELF vmlinux (not bzImage).
            // Use RawVmLinux (2) so td-shim jumps directly to entry_point rather
            // than treating the image as a bzImage and miscalculating startup_64.
            image_type: 2,
            reserved: 0,
            entry_point: 0,
        }
    }
}

#[derive(Copy, Clone)]
#[repr(C, packed)]
struct EndHob {
    header: HobHeader,
}
unsafe impl ByteValued for EndHob {}

impl Default for EndHob {
    fn default() -> Self {
        Self {
            header: HobHeader::new(HOB_TYPE_END, mem::size_of::<EndHob>() as u16),
        }
    }
}

fn append<T: ByteValued>(buf: &mut Vec<u8>, val: &T) {
    buf.extend_from_slice(val.as_slice());
}

pub fn write_hob_chain(
    out: &mut [u8],
    hob_region_addr: u64,
    memory_regions: &[(u64, u64)],
    kernel_entry_addr: u64,
) -> Result<()> {
    let mut chain: Vec<u8> = Vec::new();

    let phit_offset = chain.len();
    append(&mut chain, &PhitHob::default());

    for &(start, length) in memory_regions {
        append(
            &mut chain,
            &ResourceHob {
                physical_start: start,
                resource_length: length,
                ..Default::default()
            },
        );
    }

    append(
        &mut chain,
        &PayloadInfoHob {
            entry_point: kernel_entry_addr,
            ..Default::default()
        },
    );

    append(&mut chain, &EndHob::default());

    // Patch PHIT: efi_end_of_hob_list points past the End HOB (exclusive end of the chain).
    // td-shim validates: hob_length == efi_end_of_hob_list - hob_ptr, where
    // hob_length = end_hob_offset + size_of::<Header>() = chain.len().
    let end_of_list_addr = hob_region_addr + chain.len() as u64;
    let eol_off = phit_offset + mem::offset_of!(PhitHob, efi_end_of_hob_list);
    chain[eol_off..eol_off + 8].copy_from_slice(&end_of_list_addr.to_le_bytes());

    if chain.len() > out.len() {
        return Err(Error::HobRegionTooSmall);
    }

    out[..chain.len()].copy_from_slice(&chain);
    Ok(())
}

fn is_bfv(s: &TdvfSection) -> bool {
    matches!(s.section_type, TdvfSectionType::Bfv)
}

fn is_td_hob(s: &TdvfSection) -> bool {
    matches!(s.section_type, TdvfSectionType::TdHob)
}

fn validate_sections(sections: &[TdvfSection]) -> Result<()> {
    if !sections.iter().any(is_bfv) {
        return Err(Error::MissingBfv);
    }
    if !sections.iter().any(is_td_hob) {
        return Err(Error::MissingTdHob);
    }
    Ok(())
}

impl TdShim {
    pub fn parse(path: &Path) -> Result<Self> {
        let mut file = File::open(path).map_err(Error::OpenFirmware)?;
        let sections = tdvf::parse_sections(&mut file).map_err(Error::ParseSections)?;
        validate_sections(&sections)?;

        let file_size = file
            .seek(io::SeekFrom::End(0))
            .map_err(Error::ReadFirmware)?;
        for section in &sections {
            if u64::from(section.data_offset) + u64::from(section.raw_data_size) > file_size {
                return Err(Error::InvalidSectionOffset);
            }
        }

        // safe to unwrap since validate_sections() will verify the TDHob is present
        let hob_address = sections
            .iter()
            .find(|s| is_td_hob(s))
            .unwrap()
            .memory_address;
        file.rewind().map_err(Error::ReadFirmware)?;
        let mut firmware_data = Vec::new();
        file.read_to_end(&mut firmware_data)
            .map_err(Error::ReadFirmware)?;
        Ok(Self {
            sections,
            hob_address,
            firmware_data,
        })
    }

    #[cfg(test)]
    fn firmware_range(&self) -> (u64, u64) {
        let min = self
            .sections
            .iter()
            .map(|s| s.memory_address)
            .min()
            .unwrap();
        let max = self
            .sections
            .iter()
            .map(|s| s.memory_address + s.memory_data_size)
            .max()
            .unwrap();
        (min, max)
    }

    /// Returns [min_addr, max_addr) covering only sections above the 32-bit MMIO gap.
    /// These sections need their own GuestMemoryMmap region; sections below the gap
    /// fall within the normal RAM mapping and need no separate hole.
    pub fn high_firmware_range(&self) -> Option<(u64, u64)> {
        let mmio_start = arch::x86_64::layout::MMIO_MEM_START;
        let min = self
            .sections
            .iter()
            .filter(|s| s.memory_address >= mmio_start)
            .map(|s| s.memory_address)
            .min()?;
        let max = self
            .sections
            .iter()
            .filter(|s| s.memory_address >= mmio_start)
            .map(|s| s.memory_address + s.memory_data_size)
            .max()?;
        Some((min, max))
    }

    /// Copies sections with raw data into guest memory. Zero-fill sections are
    /// already handled by the mmap backing.
    pub fn load_sections(&self, guest_mem: &GuestMemoryMmap) -> Result<()> {
        for section in &self.sections {
            if section.raw_data_size == 0 {
                continue;
            }
            // Bounds already validated by parse(), safe to slice directly.
            let start = section.data_offset as usize;
            let end = start + section.raw_data_size as usize;
            guest_mem
                .write(
                    &self.firmware_data[start..end],
                    GuestAddress(section.memory_address),
                )
                .map_err(Error::GuestMemory)?;
        }
        Ok(())
    }

    pub fn generate_hobs(
        &self,
        guest_mem: &GuestMemoryMmap,
        kernel_entry_addr: u64,
        ram_regions: &[(u64, u64)],
    ) -> Result<()> {
        let hob_section = self.sections.iter().find(|s| is_td_hob(s)).unwrap();
        let hob_size = hob_section.memory_data_size as usize;
        let mut buf = vec![0u8; hob_size];

        write_hob_chain(
            &mut buf,
            hob_section.memory_address,
            ram_regions,
            kernel_entry_addr,
        )?;

        guest_mem
            .write(&buf, GuestAddress(hob_section.memory_address))
            .map_err(Error::GuestMemory)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bfv_section() -> TdvfSection {
        TdvfSection {
            data_offset: 0,
            raw_data_size: 0x1000,
            memory_address: 0xffff_0000,
            memory_data_size: 0x1000,
            section_type: TdvfSectionType::Bfv,
            attributes: 1,
        }
    }

    fn hob_section() -> TdvfSection {
        TdvfSection {
            data_offset: 0,
            raw_data_size: 0,
            memory_address: 0x5000_0000,
            memory_data_size: 0x1000,
            section_type: TdvfSectionType::TdHob,
            attributes: 0,
        }
    }

    #[test]
    fn test_validate_missing_bfv() {
        let sections = vec![hob_section()];
        assert!(matches!(
            validate_sections(&sections),
            Err(Error::MissingBfv)
        ));
    }

    #[test]
    fn test_validate_missing_hob() {
        let sections = vec![bfv_section()];
        assert!(matches!(
            validate_sections(&sections),
            Err(Error::MissingTdHob)
        ));
    }

    #[test]
    fn test_validate_both_present() {
        let sections = vec![bfv_section(), hob_section()];
        assert!(validate_sections(&sections).is_ok());
    }

    #[test]
    fn test_hob_address_extracted() {
        let hob_addr = 0x5000_0000u64;
        let sections = vec![bfv_section(), hob_section()];
        validate_sections(&sections).unwrap();
        let found = sections.iter().find(|s| is_td_hob(s)).unwrap();
        assert_eq!(found.memory_address, hob_addr);
    }

    #[test]
    fn test_firmware_range() {
        let sections = vec![bfv_section(), hob_section()];
        // hob at 0x5000_0000 with size 0x1000 and bfv at 0xffff_0000 with size 0x1000
        let td = TdShim {
            hob_address: 0x5000_0000,
            sections,
            firmware_data: vec![],
        };
        let (min, max) = td.firmware_range();
        assert_eq!(min, 0x5000_0000);
        assert_eq!(max, 0xffff_0000 + 0x1000);
    }

    #[test]
    fn test_high_firmware_range_excludes_low_sections() {
        let sections = vec![bfv_section(), hob_section()];
        let td = TdShim {
            hob_address: 0x5000_0000,
            sections,
            firmware_data: vec![],
        };
        let (start, end) = td.high_firmware_range().expect("BFV is above MMIO gap");
        assert_eq!(start, 0xffff_0000);
        assert_eq!(end, 0xffff_0000 + 0x1000);
    }

    #[test]
    fn test_high_firmware_range_none_when_all_sections_low() {
        let sections = vec![
            TdvfSection {
                data_offset: 0,
                raw_data_size: 0,
                memory_address: 0x0080_0000,
                memory_data_size: 0x1000,
                section_type: TdvfSectionType::TempMem,
                attributes: 0,
            },
            hob_section(),
        ];
        let td = TdShim {
            hob_address: 0x5000_0000,
            sections,
            firmware_data: vec![],
        };
        assert!(td.high_firmware_range().is_none());
    }

    #[test]
    fn test_hob_chain_starts_with_phit() {
        let mut buf = vec![0u8; 4096];
        write_hob_chain(&mut buf, 0x5000_0000, &[(0, 0x4000_0000)], 0x0100_0000).unwrap();
        let hob_type = u16::from_le_bytes([buf[0], buf[1]]);
        assert_eq!(hob_type, 0x0001, "First HOB must be PHIT");
    }

    #[test]
    fn test_hob_chain_ends_with_end_hob() {
        let mut buf = vec![0u8; 4096];
        write_hob_chain(&mut buf, 0x5000_0000, &[(0, 0x4000_0000)], 0x100_0000).unwrap();
        let mut offset = 0usize;
        let mut found_end = false;
        while offset + 4 <= buf.len() {
            let hob_type = u16::from_le_bytes([buf[offset], buf[offset + 1]]);
            let hob_len = u16::from_le_bytes([buf[offset + 2], buf[offset + 3]]) as usize;
            if hob_type == 0xFFFF {
                found_end = true;
                break;
            }
            if hob_len == 0 {
                break;
            }
            offset += hob_len;
        }
        assert!(found_end, "HOB chain must terminate with 0xFFFF");
    }

    #[test]
    fn test_hob_chain_too_small_returns_error() {
        let mut buf = vec![0u8; 8];
        let result = write_hob_chain(&mut buf, 0x5000_0000, &[(0, 0x1000)], 0x100_0000);
        assert!(matches!(result, Err(Error::HobRegionTooSmall)));
    }

    #[test]
    fn test_phit_efi_end_of_hob_list_points_past_end_hob() {
        // td-shim validates: hob_length == efi_end_of_hob_list - hob_region_addr
        // where hob_length = end_hob_offset + 8 = chain.len()
        let hob_region_addr = 0x5000_0000u64;
        let mut buf = vec![0u8; 4096];
        write_hob_chain(&mut buf, hob_region_addr, &[(0, 0x4000_0000)], 0x100_0000).unwrap();

        // Read efi_end_of_hob_list from PHIT at offset 48 (after header+version+boot_mode+3×u64)
        let efi_end = u64::from_le_bytes(buf[48..56].try_into().unwrap());

        // Find the End HOB and compute hob_length = end_hob_offset + 8
        let mut offset = 0usize;
        let mut end_hob_offset = None;
        while offset + 4 <= buf.len() {
            let hob_type = u16::from_le_bytes([buf[offset], buf[offset + 1]]);
            let hob_len = u16::from_le_bytes([buf[offset + 2], buf[offset + 3]]) as usize;
            if hob_type == 0xFFFF {
                end_hob_offset = Some(offset);
                break;
            }
            if hob_len == 0 {
                break;
            }
            offset += hob_len;
        }
        let hob_length = end_hob_offset.unwrap() + 8;
        assert_eq!(
            efi_end,
            hob_region_addr + hob_length as u64,
            "efi_end_of_hob_list must equal hob_region_addr + chain.len()"
        );
    }
}
