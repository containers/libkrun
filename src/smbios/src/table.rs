use std::{mem, ptr, slice};
use vm_memory::ByteValued;

// SMBIOS 3.0 (64-bit) Entry Point anchor string
const SM3_ANCHOR: &[u8; 5usize] = b"_SM3_";

// Type of structure
const BIOS_INFORMATION: u8 = 0;
const SYSTEM_INFORMATION: u8 = 1;
const OEM_STRINGS: u8 = 11;
const END_OF_TABLE: u8 = 127;

// Structure’s handle, a unique 16-bit number in the range 0 to 0FEFFh.
// The handle numbers are not required to be contiguous. Handle values in the range
// 0FF00h to 0FFFFh are reserved.
const TYPE_0_HANDLE: u16 = 0x000; // BiosInfo
const TYPE_1_HANDLE: u16 = 0x100; // SystemInfo
const TYPE_11_HANDLE: u16 = 0xe00; // OemStrings
const TYPE_127_HANDLE: u16 = 0x7f00; // EndOfTable

// SMBIOS 3.0 (64-bit) Entry Point
#[repr(C, packed)]
#[derive(Default, Copy, Clone)]
pub struct Entrypoint30 {
    anchor: [u8; 5usize], // "_SM3_" specified as five ASCII characters (5F 53 4D 33 5F).
    checksum: u8,
    length: u8,
    major_version: u8,
    minor_version: u8,
    docrev: u8,
    revision: u8,
    reserved: u8,
    table_max_size: u32,
    table_addr: u64,
}
// SAFETY: `Entrypoint30` is packed and it doesn't contains any reference type
unsafe impl ByteValued for Entrypoint30 {}

impl Entrypoint30 {
    pub fn new(table_max_size: u32, table_addr: u64) -> Self {
        let mut ep = Entrypoint30 {
            anchor: *SM3_ANCHOR,
            length: mem::size_of::<Entrypoint30>() as u8,
            // SMBIOS rev 3.0
            major_version: 3,
            minor_version: 0,
            docrev: 0,
            revision: 1, // SMBIOS 3.0
            table_max_size,
            table_addr,
            ..Default::default()
        };
        ep.checksum = ep.compute_checksum();
        ep
    }

    fn compute_checksum(&self) -> u8 {
        // SAFETY: we are reading within a single allocated and properly
        // initialized `Entrypoint30` object
        let v_slice = unsafe {
            slice::from_raw_parts(
                ptr::from_ref::<Entrypoint30>(self).cast::<u8>(),
                mem::size_of::<Entrypoint30>(),
            )
        };

        let mut checksum: u8 = 0;
        for i in v_slice {
            checksum = checksum.wrapping_add(*i);
        }
        (!checksum).wrapping_add(1)
    }
}

// BIOS Information (Type 0)
// One and only one structure is present in the structure-table. BIOS Version and
// BIOS Release Date strings are non-null; the date field uses a 4-digit year (for
// example, 1999). All other fields reflect full BIOS support information
#[repr(C, packed)]
#[derive(Default, Copy, Clone)]
pub struct BiosInfo {
    r#type: u8,
    length: u8,
    handle: u16,
    vendor: u8,
    version: u8,
    start_addr_segment: u16,
    release_date: u8,
    rom_size: u8,
    characteristics: u64,
    characteristics_ext1: u8,
    characteristics_ext2: u8,
    system_bios_major_release: u8,
    system_bios_minor_release: u8,
    embedded_controller_major_release: u8,
    embedded_controller_minor_release: u8,
}
// SAFETY: `BiosInfo` is packed and it doesn't contains any reference type
unsafe impl ByteValued for BiosInfo {}
// BIOS Information (Type 0) Characteristics
const CHARACTERISTICS_NOT_SUPPORTED: u64 = 1 << 3; // BIOS Characteristics are not supported.

// BIOS Information (Type 0) Characteristics Extension Byte 2
const TARGETED_CONTENT_DISTRIBUTION: u8 = 1 << 2;
const UEFI: u8 = 1 << 3;
const IS_VIRTUAL_MACHINE: u8 = 1 << 4;

impl BiosInfo {
    pub fn new(vendor_str_idx: u8, version_str_idx: u8, release_date_str_idx: u8) -> Self {
        const DEFAULT_CHARACTERISTICS: u8 =
            TARGETED_CONTENT_DISTRIBUTION | UEFI | IS_VIRTUAL_MACHINE;

        BiosInfo {
            r#type: BIOS_INFORMATION,
            length: mem::size_of::<BiosInfo>() as u8,
            handle: TYPE_0_HANDLE,
            vendor: vendor_str_idx,
            version: version_str_idx,
            release_date: release_date_str_idx,
            characteristics: CHARACTERISTICS_NOT_SUPPORTED,
            characteristics_ext2: DEFAULT_CHARACTERISTICS,
            embedded_controller_major_release: 0xFF, // Spec: If the system does not have field upgradeable
            embedded_controller_minor_release: 0xFF, // embedded controller firmware, the value is 0FFh.
            ..Default::default()
        }
    }
}

// System Information (Type 1)
// Manufacturer and Product Name strings are non-null. UUID field identifies the
// system’s non-zero UUID value. Wake-up Type field identifies the wake-up
// source and cannot be Unknown. One and only one structure is present in the
// structure-table.
#[repr(C, packed)]
#[derive(Default, Copy, Clone)]
pub struct SystemInfo {
    r#type: u8,
    length: u8,
    handle: u16,
    manufacturer: u8,
    product_name: u8,
    version: u8,
    serial_number: u8,
    uuid: [u8; 16usize],
    wake_up_type: u8,
    sku_number: u8,
    family: u8,
}
// SAFETY: `SystemInfo` is packed and it doesn't contains any reference type
unsafe impl ByteValued for SystemInfo {}

// Wake-up Types
const POWER_SWITCH: u8 = 0x06;

impl SystemInfo {
    pub fn new(manufacturer_str_idx: u8, product_name_str_idx: u8) -> Self {
        SystemInfo {
            r#type: SYSTEM_INFORMATION,
            length: mem::size_of::<SystemInfo>() as u8,
            handle: TYPE_1_HANDLE,
            manufacturer: manufacturer_str_idx,
            product_name: product_name_str_idx,
            wake_up_type: POWER_SWITCH,
            ..Default::default()
        }
    }
}

// OEM Strings (Type 11)
// Contains free-form strings defined by the OEM. For instance, part numbers
// for system reference documents, contact information for the manufacturer, and so on.
#[repr(C, packed)]
#[derive(Default, Copy, Clone)]
pub struct OemStrings {
    r#type: u8,
    length: u8,
    handle: u16,
    count: u8,
}
// SAFETY: `OemStrings` is packed and it doesn't contains any reference type
unsafe impl ByteValued for OemStrings {}

impl OemStrings {
    pub fn new(count: u8) -> Self {
        OemStrings {
            r#type: OEM_STRINGS,
            length: mem::size_of::<OemStrings>() as u8,
            handle: TYPE_11_HANDLE,
            count,
        }
    }
}

// End-of-table (Type 127)
#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct EndOfTable {
    r#type: u8,
    length: u8,
    handle: u16,
}
// SAFETY: `EndOfTable` is packed and it doesn't contains any reference type
unsafe impl ByteValued for EndOfTable {}

impl EndOfTable {
    pub fn new() -> Self {
        EndOfTable {
            r#type: END_OF_TABLE,
            length: mem::size_of::<EndOfTable>() as u8,
            handle: TYPE_127_HANDLE,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entry_point_checksum() {
        let ep = Entrypoint30::new(0, 0);
        assert_eq!(ep.checksum, 83);
        // The checksum value, when added to all other bytes in the `Entrypoint30`
        // must results in the value 00h (using 8-bit addition calculations)
        assert_eq!(ep.compute_checksum(), 0);
    }
}
