use log::debug;
use std::sync::atomic::{AtomicU64, Ordering};
/// LoongArch IOCSR Mailbox and Control Registers
///
/// This module provides emulation for LoongArch IOCSR (I/O Control and Status Register)
/// mailbox system used for inter-processor communication.
use std::sync::Arc;

/// Maximum Number of LoongArch vCpus supported
const MAX_LOONGARCH_VCPUS: usize = 16;

/// IOCSR Mailbox addresses (each 8 bytes apart)
pub const LOONGARCH_IOCSR_MBUF0: u64 = 0x1020;
pub const LOONGARCH_IOCSR_MBUF1: u64 = 0x1028;
pub const LOONGARCH_IOCSR_MBUF2: u64 = 0x1030;
pub const LOONGARCH_IOCSR_MBUF3: u64 = 0x1038;

/// IOCSR Mailbox send command register
pub const LOONGARCH_IOCSR_MBUF_SEND: u64 = 0x1048;

/// IOCSR Any-Send register (for arbitrary CSR access between CPUs)
pub const LOONGARCH_IOCSR_ANY_SEND: u64 = 0x1158;

/// IOCSR Miscellaneous function register
pub const LOONGARCH_IOCSR_MISC_FUNC: u64 = 0x0420;

/// IOCSR feature flags (read-only)
pub const LOONGARCH_IOCSR_FEATURES: u64 = 0x0008;

/// IOCSR identification strings
pub const LOONGARCH_IOCSR_VENDOR: u64 = 0x0010;
pub const LOONGARCH_IOCSR_MODEL: u64 = 0x0020;

/// Bit field definitions for MBUF_SEND register
pub const IOCSR_MBUF_SEND_BLOCKING: u64 = 1 << 31;
pub const IOCSR_MBUF_SEND_BOX_SHIFT: u32 = 2;
pub const IOCSR_MBUF_SEND_BOX_LO: fn(u32) -> u32 = |box_num| box_num << 1;
pub const IOCSR_MBUF_SEND_BOX_HI: fn(u32) -> u32 = |box_num| (box_num << 1) + 1;
pub const IOCSR_MBUF_SEND_CPU_SHIFT: u32 = 16;
pub const IOCSR_MBUF_SEND_BUF_SHIFT: u32 = 32;
pub const IOCSR_MBUF_SEND_H32_MASK: u64 = 0xFFFFFFFF00000000;

/// Feature flags for LoongArch
pub const IOCSRF_EXTIOI: u32 = 1 << 3;
pub const IOCSRF_CSRIPI: u32 = 1 << 4;
pub const IOCSRF_VM: u32 = 1 << 11;

/// Shared IOCSR state for all vCPUs
#[derive(Debug)]
pub struct LoongArchIocsrState {
    misc_func: AtomicU64,
    mailboxes: Vec<[AtomicU64; 4]>,
}

impl LoongArchIocsrState {
    /// Create a new IOCSR state with the specified number of vCPUs
    pub fn new(vcpu_count: usize) -> Self {
        let count = vcpu_count.min(MAX_LOONGARCH_VCPUS);
        Self {
            misc_func: AtomicU64::new(0),
            mailboxes: (0..count)
                .map(|_| {
                    [
                        AtomicU64::new(0),
                        AtomicU64::new(0),
                        AtomicU64::new(0),
                        AtomicU64::new(0),
                    ]
                })
                .collect(),
        }
    }

    /// Read miscellaneous function register
    pub fn read_misc_func(&self) -> u64 {
        self.misc_func.load(Ordering::SeqCst)
    }

    /// Write miscellaneous function register
    pub fn write_misc_func(&self, value: u64) {
        self.misc_func.store(value, Ordering::SeqCst);
    }

    /// Read a mailbox slot for the specified CPU
    pub fn read_mailbox(&self, cpu_id: usize, mailbox_id: usize) -> u64 {
        if cpu_id < self.mailboxes.len() && mailbox_id < 4 {
            self.mailboxes[cpu_id][mailbox_id].load(Ordering::SeqCst)
        } else {
            0
        }
    }

    /// Write a mailbox slot for the specified CPU
    pub fn write_mailbox(&self, cpu_id: usize, mailbox_id: usize, value: u64) {
        if cpu_id < self.mailboxes.len() && mailbox_id < 4 {
            self.mailboxes[cpu_id][mailbox_id].store(value, Ordering::SeqCst);
        }
    }

    /// Process a mailbox send command
    ///
    /// This function parses the MBUF_SEND register value and updates the target CPU's mailbox.
    /// Currently used only for SMP support, which is disabled in single-vCPU mode.
    ///
    /// # Arguments
    /// * `value` - The 64-bit value written to MBUF_SEND register
    ///
    /// The value format:
    /// - Bits 32-63: 32-bit data to be sent
    /// - Bits 16-31: Target CPU ID (14 bits)
    /// - Bit 3: HI/LO flag (0=low 32 bits, 1=high 32 bits)
    /// - Bits 2-3: Mailbox number encoding
    /// - Bit 2: Base mailbox number (0-3)
    pub fn process_mbuf_send(&self, value: u64) -> Result<(), String> {
        // Extract fields from the value
        let target_cpu = ((value >> IOCSR_MBUF_SEND_CPU_SHIFT) & 0x3FFF) as usize;
        // Linux encodes mailbox selector as:
        //   (IOCSR_MBUF_SEND_BOX_{LO,HI}(box) << IOCSR_MBUF_SEND_BOX_SHIFT)
        // where BOX_LO(box)=(box<<1), BOX_HI(box)=((box<<1)+1).
        // So the packed field is 3 bits: [box_num(2b), hi_low(1b)].
        let box_sel = ((value >> IOCSR_MBUF_SEND_BOX_SHIFT) & 0x7) as u32;
        let box_hi = (box_sel & 0x1) != 0;
        let box_num = (box_sel >> 1) as usize;
        let data32 = ((value >> IOCSR_MBUF_SEND_BUF_SHIFT) & 0xFFFFFFFF) as u32;
        // Validate target CPU
        if target_cpu >= self.mailboxes.len() {
            return Err(format!(
                "Invalid target CPU: {} (max: {})",
                target_cpu,
                self.mailboxes.len() - 1
            ));
        }
        // Validate mailbox number
        if box_num >= 4 {
            return Err(format!("Invalid mailbox number: {} (max: 3)", box_num));
        }
        // Update the target mailbox
        if box_hi {
            // Write high 32 bits
            let current = self.read_mailbox(target_cpu, box_num);
            let new_val = (current & 0xFFFFFFFF) | ((data32 as u64) << 32);
            self.write_mailbox(target_cpu, box_num, new_val);
        } else {
            // Write low 32 bits
            let current = self.read_mailbox(target_cpu, box_num);
            let new_val = (current & 0xFFFFFFFF00000000) | (data32 as u64);
            self.write_mailbox(target_cpu, box_num, new_val);
        }
        Ok(())
    }

    /// Get the number of configured vCPUs
    pub fn vcpu_count(&self) -> usize {
        self.mailboxes.len()
    }
}

/// IOCSR read operation result
#[derive(Debug)]
pub enum IocsrReadResult {
    /// Successfully read a value
    Value(u64),
    /// Unhandled register address
    Unhandled,
}
/// IOCSR write operation result
#[derive(Debug)]
pub enum IocsrWriteResult {
    /// Successfully processed write
    Handled,
    /// Unhandled register address
    Unhandled,
}

/// Process an IOCSR read operation
pub fn process_iocsr_read(
    addr: u64,
    data: &mut [u8],
    iocsr_state: &Arc<LoongArchIocsrState>,
    cpu_id: u8,
) -> IocsrReadResult {
    match (addr, data.len()) {
        (LOONGARCH_IOCSR_FEATURES, 4) => {
            // Feature flags: EXTIOI, CSRIPI, VM support
            let features = IOCSRF_EXTIOI | IOCSRF_CSRIPI | IOCSRF_VM;
            data.copy_from_slice(&features.to_le_bytes());
            IocsrReadResult::Value(features as u64)
        }
        (LOONGARCH_IOCSR_VENDOR, 8) => {
            // Vendor string: "Loongson"
            data.copy_from_slice(b"Loongson");
            IocsrReadResult::Value(0)
        }
        (LOONGARCH_IOCSR_MODEL, 8) => {
            // Model string: "KVMGuest"
            data.copy_from_slice(b"KVMGuest");
            IocsrReadResult::Value(0)
        }
        (LOONGARCH_IOCSR_MISC_FUNC, 8) => {
            // Miscellaneous function register
            let value = iocsr_state.read_misc_func();
            data.copy_from_slice(&value.to_le_bytes());
            IocsrReadResult::Value(value)
        }
        (LOONGARCH_IOCSR_MBUF0..=LOONGARCH_IOCSR_MBUF3, 8) => {
            // Mailbox read operations
            let mailbox_idx = ((addr - LOONGARCH_IOCSR_MBUF0) / 8) as usize;
            let value = iocsr_state.read_mailbox(cpu_id as usize, mailbox_idx);
            data.copy_from_slice(&value.to_le_bytes());
            IocsrReadResult::Value(value)
        }
        _ => IocsrReadResult::Unhandled,
    }
}

/// Process an IOCSR write operation
pub fn process_iocsr_write(
    addr: u64,
    data: &[u8],
    iocsr_state: &Arc<LoongArchIocsrState>,
    cpu_id: u8,
) -> IocsrWriteResult {
    match (addr, data.len()) {
        (LOONGARCH_IOCSR_MISC_FUNC, 8) => {
            // Miscellaneous function register
            let value = u64::from_le_bytes(data.try_into().unwrap());
            iocsr_state.write_misc_func(value);
            IocsrWriteResult::Handled
        }
        (LOONGARCH_IOCSR_MBUF0..=LOONGARCH_IOCSR_MBUF3, 8) => {
            // Mailbox write operations
            let mailbox_idx = ((addr - LOONGARCH_IOCSR_MBUF0) / 8) as usize;
            let value = u64::from_le_bytes(data.try_into().unwrap());
            iocsr_state.write_mailbox(cpu_id as usize, mailbox_idx, value);
            IocsrWriteResult::Handled
        }
        (LOONGARCH_IOCSR_MBUF_SEND, 8) => {
            // Mailbox send command
            let value = u64::from_le_bytes(data.try_into().unwrap());
            match iocsr_state.process_mbuf_send(value) {
                Ok(()) => IocsrWriteResult::Handled,
                Err(_) => IocsrWriteResult::Unhandled, // Keep it simple for now
            }
        }
        (LOONGARCH_IOCSR_ANY_SEND, 8) => {
            // ANY_SEND: Send data to arbitrary CSR of another CPU
            // Format: [data:32][cpu:10][mask:4][addr:16] + BLOCKING bit
            // For now, just acknowledge the write (no actual cross-CPU CSR emulation needed)
            let value = u64::from_le_bytes(data.try_into().unwrap());
            let blocking = (value & 0x8000_0000_0000_0000) != 0;
            let target_addr = (value & 0xFFFF) as u32;
            let target_cpu = ((value >> 16) & 0x3FF) as u32;
            let data_val = (value >> 32) as u32;

            debug!(
                "IOCSR ANY_SEND: to CPU {}, addr=0x{:x}, data=0x{:x}, blocking={}",
                target_cpu, target_addr, data_val, blocking
            );
            IocsrWriteResult::Handled
        }
        _ => IocsrWriteResult::Unhandled,
    }
}
