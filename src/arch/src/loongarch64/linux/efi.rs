use crate::ArchMemoryInfo;
use log::debug;
use std::mem::size_of;
use vm_memory::{Address, ByteValued, Bytes, GuestAddress, GuestMemoryError, GuestMemoryMmap};

const EFI_SYSTEM_TABLE_SIGNATURE: u64 = 0x5453_5953_2049_4249;
const EFI_2_10_SYSTEM_TABLE_REVISION: u32 = (2 << 16) | 10;

const EFI_CONFIG_TABLE_OFFSET: u64 = 0x100;
const EFI_VENDOR_OFFSET: u64 = 0x200;
const DEVICE_TREE_GUID: EfiGuid = EfiGuid {
    data1: 0xb1b621d5,
    data2: 0xf19c,
    data3: 0x41a5,
    data4: [0x83, 0x0b, 0xd9, 0x15, 0x2c, 0x69, 0xaa, 0xe0],
};

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct EfiGuid {
    data1: u32,
    data2: u16,
    data3: u16,
    data4: [u8; 8],
}
unsafe impl ByteValued for EfiGuid {}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct EfiTableHeader {
    signature: u64,
    revision: u32,
    headersize: u32,
    crc32: u32,
    reserved: u32,
}
unsafe impl ByteValued for EfiTableHeader {}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct EfiConfigTable64 {
    guid: EfiGuid,
    table: u64,
}
unsafe impl ByteValued for EfiConfigTable64 {}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct EfiSystemTable64 {
    hdr: EfiTableHeader,
    fw_vendor: u64,
    fw_revision: u32,
    __pad1: u32,
    con_in_handle: u64,
    con_in: u64,
    con_out_handle: u64,
    con_out: u64,
    stderr_handle: u64,
    stderr: u64,
    runtime: u64,
    boottime: u64,
    nr_tables: u32,
    __pad2: u32,
    tables: u64,
}
unsafe impl ByteValued for EfiSystemTable64 {}

#[derive(Debug)]
pub enum Error {
    Write(GuestMemoryError),
}

type Result<T> = std::result::Result<T, Error>;

pub fn setup_fdt_system_table(mem: &GuestMemoryMmap, info: &ArchMemoryInfo) -> Result<()> {
    let systab_addr = GuestAddress(info.efi_system_table_addr);
    let config_addr = systab_addr.unchecked_add(EFI_CONFIG_TABLE_OFFSET);
    let vendor_addr = systab_addr.unchecked_add(EFI_VENDOR_OFFSET);

    let config = EfiConfigTable64 {
        guid: DEVICE_TREE_GUID,
        table: info.fdt_addr,
    };
    mem.write_obj(config, config_addr).map_err(Error::Write)?;

    let systab = EfiSystemTable64 {
        hdr: EfiTableHeader {
            signature: EFI_SYSTEM_TABLE_SIGNATURE,
            revision: EFI_2_10_SYSTEM_TABLE_REVISION,
            headersize: size_of::<EfiSystemTable64>() as u32,
            crc32: 0,
            reserved: 0,
        },
        fw_vendor: vendor_addr.raw_value(),
        fw_revision: 0,
        __pad1: 0,
        con_in_handle: 0,
        con_in: 0,
        con_out_handle: 0,
        con_out: 0,
        stderr_handle: 0,
        stderr: 0,
        runtime: 0,
        boottime: 0,
        nr_tables: 1,
        __pad2: 0,
        tables: config_addr.raw_value(),
    };
    mem.write_obj(systab, systab_addr).map_err(Error::Write)?;
    debug!(
        "loongarch efi handoff: systab=0x{:x}, config=0x{:x}, vendor=0x{:x}, fdt=0x{:x}",
        systab_addr.raw_value(),
        config_addr.raw_value(),
        vendor_addr.raw_value(),
        info.fdt_addr,
    );
    let vendor: [u16; 8] = [
        b'l' as u16,
        b'i' as u16,
        b'b' as u16,
        b'k' as u16,
        b'r' as u16,
        b'u' as u16,
        b'n' as u16,
        0,
    ];
    for (i, ch) in vendor.iter().enumerate() {
        mem.write_obj(*ch, vendor_addr.unchecked_add((i * 2) as u64))
            .map_err(Error::Write)?;
    }

    Ok(())
}
