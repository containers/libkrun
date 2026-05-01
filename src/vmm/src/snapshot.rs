//! AGX vCPU/VM-state snapshot artifact format.
//!
//! Wire layout (little-endian):
//!
//! ```text
//!   header:
//!     [0..8]   magic = b"AGXSNAP1"
//!     [8..12]  format_version (u32)
//!     [12]     arch    (u8) — 0 = x86_64
//!     [13]     vcpu_count (u8)
//!     [14..16] reserved
//!
//!   per vCPU (vcpu_count of these):
//!     repr(C) memcpy of:
//!       kvm_regs, kvm_sregs, kvm_xsave, kvm_xcrs, kvm_lapic_state,
//!       kvm_mp_state, kvm_vcpu_events, kvm_debug_regs
//!     u32 msr_count
//!     msr_count * sizeof(kvm_msr_entry) bytes
//!     u32 cpuid_count
//!     cpuid_count * sizeof(kvm_cpuid_entry2) bytes
//!
//!   VmState:
//!     repr(C) memcpy of:
//!       kvm_pit_state2, kvm_clock_data, kvm_irqchip (PIC master),
//!       kvm_irqchip (PIC slave), kvm_irqchip (IOAPIC)
//! ```
//!
//! `repr(C)` direct memcpy is a deliberate choice — KVM struct
//! layouts are stable across kernel versions on a given arch
//! because they're part of the KVM_GET/SET_* ABI. Saves us from
//! writing field-by-field serialization for ~10 dense structs.
//!
//! x86_64 only (the only arch the AGX snapshot path supports
//! today).

#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use crate::vstate::{VcpuState, VmState};
use kvm_bindings::{
    kvm_clock_data, kvm_cpuid_entry2, kvm_debugregs, kvm_irqchip, kvm_lapic_state,
    kvm_mp_state, kvm_msr_entry, kvm_pit_state2, kvm_regs, kvm_sregs, kvm_vcpu_events,
    kvm_xcrs, kvm_xsave, CpuId, Msrs,
};
use std::io;
use std::mem::size_of;

pub const AGX_SNAP_MAGIC: &[u8; 8] = b"AGXSNAP1";
pub const AGX_SNAP_FORMAT_VERSION: u32 = 1;
pub const AGX_SNAP_ARCH_X86_64: u8 = 0;

#[derive(Debug)]
pub enum SnapshotError {
    Io(io::Error),
    BadMagic,
    UnsupportedFormatVersion(u32),
    UnsupportedArch(u8),
    TruncatedHeader,
    TruncatedBody { wanted: usize, got: usize },
    InvalidMsrCount(u32),
    InvalidCpuidCount(u32),
}

impl std::fmt::Display for SnapshotError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SnapshotError::Io(e) => write!(f, "io: {e}"),
            SnapshotError::BadMagic => write!(f, "bad snapshot magic"),
            SnapshotError::UnsupportedFormatVersion(v) => {
                write!(f, "unsupported snapshot format version {v}")
            }
            SnapshotError::UnsupportedArch(a) => write!(f, "unsupported snapshot arch {a}"),
            SnapshotError::TruncatedHeader => write!(f, "truncated snapshot header"),
            SnapshotError::TruncatedBody { wanted, got } => {
                write!(f, "truncated snapshot body: wanted {wanted}, got {got}")
            }
            SnapshotError::InvalidMsrCount(n) => write!(f, "invalid MSR count {n}"),
            SnapshotError::InvalidCpuidCount(n) => write!(f, "invalid CPUID count {n}"),
        }
    }
}

impl From<io::Error> for SnapshotError {
    fn from(e: io::Error) -> Self {
        SnapshotError::Io(e)
    }
}

/// Direct memcpy of `t` into `out`. Caller asserts `T` is
/// `repr(C)` and contains no internal padding-leak hazards
/// (KVM structs satisfy both).
fn copy_struct_into<T>(out: &mut Vec<u8>, t: &T) {
    let bytes = unsafe {
        std::slice::from_raw_parts(t as *const T as *const u8, size_of::<T>())
    };
    out.extend_from_slice(bytes);
}

/// Inverse of [`copy_struct_into`]. Returns `T` zero-initialized
/// then byte-overwritten from `bytes[off..off + size_of::<T>()]`.
/// `T` MUST be POD (no Drop, no references); KVM `repr(C)`
/// structs satisfy this. Bumps `off` past the consumed bytes.
///
/// Only requires `Default` (not `Copy`) because some KVM
/// structs — notably `kvm_xsave` and `kvm_lapic_state`, both
/// containing 4 KiB byte arrays — implement `Default` but not
/// `Copy`. The byte-level overwrite is correct for any POD
/// regardless of its `Copy` impl.
fn read_struct<T: Default>(bytes: &[u8], off: &mut usize) -> Result<T, SnapshotError> {
    let need = size_of::<T>();
    if bytes.len() < *off + need {
        return Err(SnapshotError::TruncatedBody {
            wanted: *off + need,
            got: bytes.len(),
        });
    }
    let mut t = T::default();
    unsafe {
        std::ptr::copy_nonoverlapping(
            bytes.as_ptr().add(*off),
            &mut t as *mut T as *mut u8,
            need,
        );
    }
    *off += need;
    Ok(t)
}

fn read_u32_le(bytes: &[u8], off: &mut usize) -> Result<u32, SnapshotError> {
    if bytes.len() < *off + 4 {
        return Err(SnapshotError::TruncatedBody {
            wanted: *off + 4,
            got: bytes.len(),
        });
    }
    let v = u32::from_le_bytes(bytes[*off..*off + 4].try_into().unwrap());
    *off += 4;
    Ok(v)
}

/// Serialize `(vcpu_states, vm_state)` into the on-disk format.
pub fn serialize(vcpu_states: &[VcpuState], vm_state: &VmState) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(8 + 4 + 4 + 1024);
    out.extend_from_slice(AGX_SNAP_MAGIC);
    out.extend_from_slice(&AGX_SNAP_FORMAT_VERSION.to_le_bytes());
    out.push(AGX_SNAP_ARCH_X86_64);
    out.push(vcpu_states.len() as u8);
    out.extend_from_slice(&[0u8, 0u8]); // reserved

    for vs in vcpu_states {
        copy_struct_into(&mut out, &vs.regs);
        copy_struct_into(&mut out, &vs.sregs);
        copy_struct_into(&mut out, &vs.xsave);
        copy_struct_into(&mut out, &vs.xcrs);
        copy_struct_into(&mut out, &vs.lapic);
        copy_struct_into(&mut out, &vs.mp_state);
        copy_struct_into(&mut out, &vs.vcpu_events);
        copy_struct_into(&mut out, &vs.debug_regs);

        let msr_entries = vs.msrs.as_slice();
        out.extend_from_slice(&(msr_entries.len() as u32).to_le_bytes());
        out.extend_from_slice(unsafe {
            std::slice::from_raw_parts(
                msr_entries.as_ptr() as *const u8,
                msr_entries.len() * size_of::<kvm_msr_entry>(),
            )
        });

        let cpuid_entries = vs.cpuid.as_slice();
        out.extend_from_slice(&(cpuid_entries.len() as u32).to_le_bytes());
        out.extend_from_slice(unsafe {
            std::slice::from_raw_parts(
                cpuid_entries.as_ptr() as *const u8,
                cpuid_entries.len() * size_of::<kvm_cpuid_entry2>(),
            )
        });
    }

    copy_struct_into(&mut out, &vm_state.pitstate);
    copy_struct_into(&mut out, &vm_state.clock);
    copy_struct_into(&mut out, &vm_state.pic_master);
    copy_struct_into(&mut out, &vm_state.pic_slave);
    copy_struct_into(&mut out, &vm_state.ioapic);

    out
}

/// Inverse of [`serialize`]. Reads the artifact byte buffer and
/// reconstructs the per-vCPU `VcpuState` list and the global
/// `VmState`.
pub fn deserialize(bytes: &[u8]) -> Result<(Vec<VcpuState>, VmState), SnapshotError> {
    if bytes.len() < 16 {
        return Err(SnapshotError::TruncatedHeader);
    }
    if &bytes[0..8] != AGX_SNAP_MAGIC {
        return Err(SnapshotError::BadMagic);
    }
    let format = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
    if format != AGX_SNAP_FORMAT_VERSION {
        return Err(SnapshotError::UnsupportedFormatVersion(format));
    }
    let arch = bytes[12];
    if arch != AGX_SNAP_ARCH_X86_64 {
        return Err(SnapshotError::UnsupportedArch(arch));
    }
    let vcpu_count = bytes[13] as usize;
    let mut off = 16usize;

    let mut vcpu_states: Vec<VcpuState> = Vec::with_capacity(vcpu_count);
    for _ in 0..vcpu_count {
        let regs: kvm_regs = read_struct(bytes, &mut off)?;
        let sregs: kvm_sregs = read_struct(bytes, &mut off)?;
        let xsave: kvm_xsave = read_struct(bytes, &mut off)?;
        let xcrs: kvm_xcrs = read_struct(bytes, &mut off)?;
        let lapic: kvm_lapic_state = read_struct(bytes, &mut off)?;
        let mp_state: kvm_mp_state = read_struct(bytes, &mut off)?;
        let vcpu_events: kvm_vcpu_events = read_struct(bytes, &mut off)?;
        let debug_regs: kvm_debugregs = read_struct(bytes, &mut off)?;

        let msr_count = read_u32_le(bytes, &mut off)? as usize;
        if msr_count > 4096 {
            return Err(SnapshotError::InvalidMsrCount(msr_count as u32));
        }
        let msr_bytes = msr_count * size_of::<kvm_msr_entry>();
        if bytes.len() < off + msr_bytes {
            return Err(SnapshotError::TruncatedBody {
                wanted: off + msr_bytes,
                got: bytes.len(),
            });
        }
        let mut msrs = Msrs::new(msr_count.max(1)).map_err(|_| {
            SnapshotError::InvalidMsrCount(msr_count as u32)
        })?;
        // Msrs::new pads to 1 if zero; if msr_count==0, leave the slice empty.
        if msr_count > 0 {
            unsafe {
                let dst = msrs.as_mut_slice().as_mut_ptr() as *mut u8;
                std::ptr::copy_nonoverlapping(bytes.as_ptr().add(off), dst, msr_bytes);
            }
        }
        off += msr_bytes;

        let cpuid_count = read_u32_le(bytes, &mut off)? as usize;
        if cpuid_count > 256 {
            return Err(SnapshotError::InvalidCpuidCount(cpuid_count as u32));
        }
        let cpuid_bytes = cpuid_count * size_of::<kvm_cpuid_entry2>();
        if bytes.len() < off + cpuid_bytes {
            return Err(SnapshotError::TruncatedBody {
                wanted: off + cpuid_bytes,
                got: bytes.len(),
            });
        }
        let mut cpuid = CpuId::new(cpuid_count.max(1)).map_err(|_| {
            SnapshotError::InvalidCpuidCount(cpuid_count as u32)
        })?;
        if cpuid_count > 0 {
            unsafe {
                let dst = cpuid.as_mut_slice().as_mut_ptr() as *mut u8;
                std::ptr::copy_nonoverlapping(bytes.as_ptr().add(off), dst, cpuid_bytes);
            }
        }
        off += cpuid_bytes;

        vcpu_states.push(VcpuState {
            cpuid,
            msrs,
            debug_regs,
            lapic,
            mp_state,
            regs,
            sregs,
            vcpu_events,
            xcrs,
            xsave,
        });
    }

    let pitstate: kvm_pit_state2 = read_struct(bytes, &mut off)?;
    let clock: kvm_clock_data = read_struct(bytes, &mut off)?;
    let pic_master: kvm_irqchip = read_struct(bytes, &mut off)?;
    let pic_slave: kvm_irqchip = read_struct(bytes, &mut off)?;
    let ioapic: kvm_irqchip = read_struct(bytes, &mut off)?;

    Ok((
        vcpu_states,
        VmState {
            pitstate,
            clock,
            pic_master,
            pic_slave,
            ioapic,
        },
    ))
}

/// Convenience: read an artifact file and deserialize it.
pub fn read_artifact(
    path: &std::path::Path,
) -> Result<(Vec<VcpuState>, VmState), SnapshotError> {
    let bytes = std::fs::read(path)?;
    deserialize(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bad_magic_rejected() {
        let bytes = vec![0u8; 32];
        assert!(matches!(deserialize(&bytes), Err(SnapshotError::BadMagic)));
    }

    #[test]
    fn truncated_header_rejected() {
        let bytes = vec![0u8; 8];
        assert!(matches!(
            deserialize(&bytes),
            Err(SnapshotError::TruncatedHeader)
        ));
    }

    #[test]
    fn unsupported_format_rejected() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(AGX_SNAP_MAGIC);
        bytes.extend_from_slice(&999u32.to_le_bytes());
        bytes.extend_from_slice(&[0, 0, 0, 0]);
        assert!(matches!(
            deserialize(&bytes),
            Err(SnapshotError::UnsupportedFormatVersion(999))
        ));
    }
}
