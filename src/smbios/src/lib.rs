use crate::table::{BiosInfo, EndOfTable, Entrypoint30, OemStrings, SystemInfo};
use std::fmt::Display;
use std::{fmt, mem, result};
use vm_memory::{Address, ByteValued, Bytes, GuestAddress, GuestMemoryMmap};

mod table;

#[derive(Debug)]
pub enum Error {
    /// The size of the SMBIOS table is too big.
    SmBiosOverflow,
    /// Not enough guest memory to store the SMBIOS table.
    NotEnoughMemory,
    /// Failure to write SMBIOS entrypoint structure
    WriteSmbiosEp,
    /// Failure to write additional data to memory
    WriteData,
    /// There was too many OEM Strings
    OEMStringsOverflow,
}

impl std::error::Error for Error {}

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::Error::{
            NotEnoughMemory, OEMStringsOverflow, SmBiosOverflow, WriteData, WriteSmbiosEp,
        };

        let description = match self {
            SmBiosOverflow => "The size of the SMBIOS table is too big".to_string(),
            NotEnoughMemory => "Not enough guest memory to store the SMBIOS table".to_string(),
            WriteSmbiosEp => "Failure to write SMBIOS entrypoint structure".to_string(),
            WriteData => "Failure to write additional data to memory".to_string(),
            OEMStringsOverflow => "There was too many OEM Strings".to_string(),
        };

        write!(f, "SMBIOS error: {description}")
    }
}

pub type Result<T> = result::Result<T, Error>;

pub fn setup_smbios(
    mem: &GuestMemoryMmap,
    start_addr: u64,
    oem_strings: &Option<Vec<String>>,
) -> Result<u64> {
    let start_addr = GuestAddress(start_addr);
    let table_starting_addr = start_addr
        .checked_add(mem::size_of::<Entrypoint30>() as u64)
        .ok_or(Error::NotEnoughMemory)?;
    let mut next_write_addr = table_starting_addr;

    // Required structures and data

    // BIOS Information (Type 0)
    next_write_addr = write_type_0_table(mem, next_write_addr)?;

    // System Information (Type 1)
    next_write_addr = write_type_1_table(mem, next_write_addr)?;

    // OEM Strings (Type 11)
    next_write_addr = write_type_11_table(mem, next_write_addr, oem_strings)?;

    next_write_addr = write_end_of_table(mem, next_write_addr)?;

    write_entry_point(mem, start_addr, next_write_addr)
}

fn write_entry_point(
    mem: &GuestMemoryMmap,
    start_addr: GuestAddress,
    current: GuestAddress,
) -> Result<u64> {
    let ep_size = mem::size_of::<Entrypoint30>() as u64;
    let table_addr = start_addr
        .checked_add(ep_size)
        .ok_or(Error::NotEnoughMemory)?;
    let table_max_size = u32::try_from(current.unchecked_offset_from(table_addr))
        .map_err(|_| Error::SmBiosOverflow)?;

    let ep = Entrypoint30::new(table_max_size, table_addr.0);

    mem.write_obj(ep, start_addr)
        .map_err(|_| Error::WriteSmbiosEp)?;

    // Let's return the SMBIOS's total numbers of bytes
    Ok(ep_size + u64::from(table_max_size))
}

fn write_type_0_table(mem: &GuestMemoryMmap, mut current: GuestAddress) -> Result<GuestAddress> {
    // One and only one structure is present in the structure-table. BIOS Version and
    // BIOS Release Date strings are non-null; the date field uses a 4-digit year (for
    // example, 1999). All other fields reflect full BIOS support information
    let biosinfo = BiosInfo::new(1, 2, 3);

    current = write_obj(mem, biosinfo, current)?;
    current = write_string(mem, "libkrun", current)?; // vendor string
    current = write_string(mem, "0", current)?; // version string
    current = write_string(mem, "01/05/2024", current)?; // release date string

    // the set of strings is terminated with an additional null (00h) byte
    current = write_obj(mem, 0u8, current)?;
    Ok(current)
}

fn write_type_1_table(mem: &GuestMemoryMmap, mut current: GuestAddress) -> Result<GuestAddress> {
    // Manufacturer and Product Name strings are non-null. One and only one structure
    // is present in the structure-table.
    let sysinfo = SystemInfo::new(1, 2);

    current = write_obj(mem, sysinfo, current)?;
    current = write_string(mem, "Libkrun", current)?;
    current = write_string(mem, "libkrun Virtual Machine", current)?;

    // the set of strings is terminated with an additional null (00h) byte
    current = write_obj(mem, 0u8, current)?;
    Ok(current)
}

fn write_type_11_table(
    mem: &GuestMemoryMmap,
    mut current: GuestAddress,
    oem_strings: &Option<Vec<String>>,
) -> Result<GuestAddress> {
    let Some(oem_strings) = oem_strings else {
        return Ok(current);
    };

    let number_of_strings = oem_strings
        .len()
        .try_into()
        .map_err(|_| Error::OEMStringsOverflow)?;
    let oemstrs = OemStrings::new(number_of_strings);

    current = write_obj(mem, oemstrs, current)?;

    for s in oem_strings {
        current = write_string(mem, s.as_str(), current)?;
    }

    current = write_obj(mem, 0u8, current)?;
    Ok(current)
}

fn write_end_of_table(mem: &GuestMemoryMmap, mut current: GuestAddress) -> Result<GuestAddress> {
    let smbios_end = EndOfTable::new();

    current = write_obj(mem, smbios_end, current)?;

    // 0x0000 is the structure terminator without strings
    current = write_obj(mem, 0u8, current)?;
    current = write_obj(mem, 0u8, current)?;
    Ok(current)
}

// Write text strings
// Text strings associated with a given SMBIOS structure are appended directly after the formatted
// portion of the structure. Each string is terminated with a null (00h) byte and the set of strings
// is terminated with an additional null (00h) BYTE. When the formatted portion of an SMBIOS
// structure references a string, it does so by specifying a non-zero string number within the
// structure’s string-set. For example, if a string field contains 02h, it references the second
// string following the formatted portion of the SMBIOS structure. If a string field references no
// string, a null (0) is placed in that string field. If the formatted portion of the structure
// contains string-reference fields and all the string fields are set to 0 (no string references),
// the formatted section of the structure is followed by two null (00h) bytes.
fn write_string(mem: &GuestMemoryMmap, val: &str, curptr: GuestAddress) -> Result<GuestAddress> {
    let mut curptr = curptr;
    for c in val.as_bytes() {
        curptr = write_obj(mem, *c, curptr)?;
    }
    curptr = write_obj(mem, 0u8, curptr)?;
    Ok(curptr)
}

fn write_obj<T: ByteValued>(
    mem: &GuestMemoryMmap,
    val: T,
    curptr: GuestAddress,
) -> Result<GuestAddress> {
    mem.write_obj(val, curptr).map_err(|_| Error::WriteData)?;
    let next = curptr
        .checked_add(mem::size_of::<T>() as u64)
        .ok_or(Error::NotEnoughMemory)?;
    Ok(next)
}
