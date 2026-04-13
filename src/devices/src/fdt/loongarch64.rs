use std::collections::HashMap;
use std::fmt::Debug;
use std::{io, result};

use crate::legacy::IrqChip;
use crate::DeviceType;

use arch::{ArchMemoryInfo, InitrdConfig};
use vm_fdt::{Error as FdtError, FdtWriter};
use vm_memory::{Address, Bytes, GuestAddress, GuestMemoryError, GuestMemoryMmap};

const CPU_INTC_PHANDLE: u32 = 1;
const EIOINTC_PHANDLE: u32 = 2;
const PCH_PIC_PHANDLE: u32 = 3;

const ADDRESS_CELLS: u32 = 0x2;
const SIZE_CELLS: u32 = 0x2;

const IRQ_TYPE_LEVEL_HI: u32 = 4;

/// Trait for devices to be added to the Flattened Device Tree.
pub trait DeviceInfoForFDT {
    /// Returns the address where this device will be loaded.
    fn addr(&self) -> u64;
    /// Returns the associated interrupt for this device.
    fn irq(&self) -> u32;
    /// Returns the amount of memory that needs to be reserved for this device.
    fn length(&self) -> u64;
}

/// Errors thrown while configuring the Flattened Device Tree for aarch64.
#[derive(Debug)]
pub enum Error {
    /// Creating FDT failed.
    CreateFDT(FdtError),
    /// Failure in calling syscall for terminating this FDT.
    FinishFDTReserveMap(io::Error),
    /// Failure in writing FDT in memory.
    WriteFDTToMemory(GuestMemoryError),
}
type Result<T> = result::Result<T, Error>;

impl From<FdtError> for Error {
    fn from(item: FdtError) -> Self {
        Error::CreateFDT(item)
    }
}

/// Creates the flattened device tree for this loongarch64 VM.
pub fn create_fdt<T: DeviceInfoForFDT + Clone + Debug>(
    guest_mem: &GuestMemoryMmap,
    arch_memory_info: &ArchMemoryInfo,
    num_vcpu: u32,
    cmdline: &str,
    device_info: &HashMap<(DeviceType, String), T>,
    intc: &IrqChip,
    initrd: &Option<InitrdConfig>,
) -> Result<Vec<u8>> {
    // Allocate stuff necessary for the holding the blob.
    let mut fdt = FdtWriter::new()?;

    // For an explanation why these nodes were introduced in the blob take a look at
    // https://github.com/torvalds/linux/blob/master/Documentation/devicetree/booting-without-of.txt#L845
    // Look for "Required nodes and properties".

    // Header or the root node as per above mentioned documentation.
    let root_node = fdt.begin_node("root")?;
    fdt.property_string("compatible", "linux,dummy-virt")?;
    // For info on #address-cells and size-cells resort to Table 3.1 Root Node
    // Properties
    fdt.property_u32("#address-cells", ADDRESS_CELLS)?;
    fdt.property_u32("#size-cells", SIZE_CELLS)?;
    create_cpu_nodes(&mut fdt, num_vcpu)?;
    create_memory_node(&mut fdt, guest_mem, arch_memory_info)?;
    create_chosen_node(&mut fdt, cmdline, initrd, device_info)?;
    create_cpuintc_node(&mut fdt)?;
    create_eiointc_node(&mut fdt)?;
    create_pic_node(&mut fdt, intc)?;
    create_devices_node(&mut fdt, device_info)?;
    //create_console_node(&mut fdt )?;

    // End Header node.
    fdt.end_node(root_node)?;

    // Allocate another buffer so we can format and then write fdt to guest.
    let fdt_final = fdt.finish()?;

    // Write FDT to memory.
    let fdt_address = GuestAddress(arch_memory_info.fdt_addr);
    guest_mem
        .write_slice(fdt_final.as_slice(), fdt_address)
        .map_err(Error::WriteFDTToMemory)?;
    debug!(
        "loongarch fdt written: addr=0x{:x}, size=0x{:x}",
        arch_memory_info.fdt_addr,
        fdt_final.len(),
    );
    Ok(fdt_final)
}

// Following are the auxiliary function for creating the different nodes that we append to our FDT.
fn create_cpu_nodes(fdt: &mut FdtWriter, num_cpus: u32) -> Result<()> {
    let cpus = fdt.begin_node("cpus")?;
    fdt.property_u32("#address-cells", 0x01)?;
    fdt.property_u32("#size-cells", 0x0)?;

    for cpu_index in 0..num_cpus {
        let cpu = fdt.begin_node(&format!("cpu@{cpu_index:x}"))?;
        fdt.property_string("device_type", "cpu")?;
        fdt.property_string("compatible", "loongson,la664")?;
        fdt.property_u32("reg", cpu_index)?;
        fdt.end_node(cpu)?;
    }
    fdt.end_node(cpus)?;
    Ok(())
}
fn create_memory_node(
    fdt: &mut FdtWriter,
    _guest_mem: &GuestMemoryMmap,
    arch_memory_info: &ArchMemoryInfo,
) -> Result<()> {
    let mem_size = arch_memory_info.ram_last_addr - arch::loongarch64::layout::DRAM_MEM_START;
    // See https://github.com/torvalds/linux/blob/master/Documentation/devicetree/booting-without-of.txt#L960
    // for an explanation of this.
    let mem_reg_prop = [arch::loongarch64::layout::DRAM_MEM_START, mem_size];

    let mem_node = fdt.begin_node("memory")?;
    fdt.property_string("device_type", "memory")?;
    fdt.property_array_u64("reg", &mem_reg_prop)?;
    fdt.end_node(mem_node)?;
    Ok(())
}

fn create_chosen_node<T: DeviceInfoForFDT + Clone + Debug>(
    fdt: &mut FdtWriter,
    cmdline: &str,
    initrd: &Option<InitrdConfig>,
    dev_info: &HashMap<(DeviceType, String), T>,
) -> Result<()> {
    let chosen_node = fdt.begin_node("chosen")?;
    fdt.property_string("bootargs", cmdline)?;

    // Only set stdout-path if we have a Serial device (not when using Virtio Console).
    // When using Virtio Console (hvc0), kernel uses the console= cmdline parameter instead.
    // When using Serial (ttyS0), we point FDT to the serial device node.
    let has_serial = dev_info.keys().any(|(device_type, _)| device_type == &DeviceType::Serial);
    let has_virtio_console = dev_info.keys()
        .any(|(device_type, _)| matches!(device_type, DeviceType::Virtio(3))); // VIRTIO_ID_CONSOLE = 3

    if has_serial && !has_virtio_console {
        // Only set stdout-path if Serial is the only console device
        for ((device_type, _device_id), info) in dev_info {
            if device_type == &DeviceType::Serial {
                fdt.property_string("stdout-path", &format!("/serial@{:x}", info.addr()))?;
                break;
            }
        }
    }
    let stdout_path = if has_serial && !has_virtio_console {
        dev_info.iter().find_map(|((device_type, _device_id), info)| {
            if device_type == &DeviceType::Serial {
                Some(format!("/serial@{:x}", info.addr()))
            } else {
                None
            }
        })
    } else {
        None
    };

    debug!(
        "loongarch chosen: has_serial={}, has_virtio_console={}, stdout_path={:?}",
        has_serial,
        has_virtio_console,
        stdout_path,
    );

    if let Some(path) = &stdout_path {
        fdt.property_string("stdout-path", path)?;
    }
    // If Virtio Console exists, don't set stdout-path; kernel uses console= cmdline parameter

    if let Some(initrd_config) = initrd {
        fdt.property_u64("linux,initrd-start", initrd_config.address.raw_value())?;
        fdt.property_u64(
            "linux,initrd-end",
            initrd_config.address.raw_value() + initrd_config.size as u64,
        )?;
    }

    fdt.end_node(chosen_node)?;

    Ok(())
}

fn create_cpuintc_node(fdt: &mut FdtWriter) -> Result<()> {
    let cpuintc_node = fdt.begin_node("interrupt-controller")?;
    fdt.property_string("compatible", "loongson,cpu-interrupt-controller")?;
    fdt.property_u32("#interrupt-cells", 1)?;
    fdt.property_null("interrupt-controller")?;
    fdt.property_u32("phandle", CPU_INTC_PHANDLE)?;
    fdt.end_node(cpuintc_node)?;
    Ok(())
}
fn create_eiointc_node(fdt: &mut FdtWriter) -> Result<()> {
    // Keep the external IRQ fabric in the DT for compatibility, even though
    // the current serial/virtio path wires devices directly to cpuintc.
    let reg = [0x1fe0_1600_u64, 0xea00_u64];

    let node = fdt.begin_node("interrupt-controller@1fe01600")?;
    fdt.property_string("compatible", "loongson,ls2k2000-eiointc")?;
    fdt.property_array_u64("reg", &reg)?;
    fdt.property_null("interrupt-controller")?;
    fdt.property_u32("#interrupt-cells", 1)?;
    fdt.property_u32("phandle", EIOINTC_PHANDLE)?;
    fdt.property_u32("interrupt-parent", CPU_INTC_PHANDLE)?;
    fdt.property_array_u32("interrupts", &[3])?;
    fdt.end_node(node)?;
    Ok(())
}
fn create_pic_node(fdt: &mut FdtWriter, intc: &IrqChip) -> Result<()> {
    let intc = intc.lock().unwrap();
    let reg = [intc.get_mmio_addr(), intc.get_mmio_size()];

    let node = fdt.begin_node(&format!("interrupt-controller@{:x}", intc.get_mmio_addr()))?;
    fdt.property_string("compatible", "loongson,pch-pic-1.0")?;
    fdt.property_array_u64("reg", &reg)?;
    fdt.property_null("interrupt-controller")?;
    fdt.property_u32("#interrupt-cells", 2)?;
    fdt.property_u32("phandle", PCH_PIC_PHANDLE)?;
    fdt.property_u32("loongson,pic-base-vec", 0)?;
    fdt.property_u32("interrupt-parent", EIOINTC_PHANDLE)?;
    fdt.end_node(node)?;
    Ok(())
}
fn create_serial_node<T: DeviceInfoForFDT + Clone + Debug>(
    fdt: &mut FdtWriter,
    dev_info: &T,
) -> Result<()> {
    let reg = [dev_info.addr(), dev_info.length()];

    let node = fdt.begin_node(&format!("serial@{:x}", dev_info.addr()))?;
    fdt.property_string("compatible", "ns16550a")?;
    fdt.property_array_u64("reg", &reg)?;
    fdt.property_u32("clock-frequency", 3686400)?;
    //let irq = [dev_info.irq(), IRQ_TYPE_LEVEL_HI];
    //fdt.property_u32("interrupt-parent", PCH_PIC_PHANDLE)?;
    //fdt.property_array_u32("interrupts", &irq)?;
    // LoongArch currently injects serial/virtio interrupts through cpuintc
    // with KVM_INTERRUPT instead of the retained PCH-PIC/EIOINTC path.
    let irq = [dev_info.irq()];
    fdt.property_u32("interrupt-parent", CPU_INTC_PHANDLE)?;
    fdt.property_array_u32("interrupts", &irq)?;
    fdt.end_node(node)?;
    // debug!(
    //     "loongarch serial node: addr=0x{:x}, len=0x{:x}, irq={}, clock-frequency={}",
    //     dev_info.addr(),
    //     dev_info.length(),
    //     dev_info.irq(),
    //     3686400u32,
    // );
    Ok(())
}
fn create_virtio_node<T: DeviceInfoForFDT + Clone + Debug>(
    fdt: &mut FdtWriter,
    dev_info: &T,
) -> Result<()> {
    let reg = [dev_info.addr(), dev_info.length()];

    // debug!(
    //     "loongarch virtio node: addr=0x{:x}, irq={}",
    //     dev_info.addr(),
    //     dev_info.irq(),
    // );
    let node = fdt.begin_node(&format!("virtio_mmio@{:x}", dev_info.addr()))?;
    fdt.property_string("compatible", "virtio,mmio")?;
    fdt.property_array_u64("reg", &reg)?;
    let irq = [dev_info.irq()];
    fdt.property_u32("interrupt-parent", CPU_INTC_PHANDLE)?;
    fdt.property_array_u32("interrupts", &irq)?;
    fdt.end_node(node)?;
    Ok(())
}
fn create_devices_node<T: DeviceInfoForFDT + Clone + Debug>(
    fdt: &mut FdtWriter,
    dev_info: &HashMap<(DeviceType, String), T>,
) -> Result<()> {
    let mut ordered_virtio_devices: Vec<&T> = Vec::new();

    for ((device_type, _device_id), info) in dev_info {
        match device_type {
            DeviceType::Serial => create_serial_node(fdt, info)?,
            DeviceType::Virtio(_) => ordered_virtio_devices.push(info),
        }
    }

    ordered_virtio_devices.sort_by_key(|info| info.addr());
    for info in ordered_virtio_devices {
        create_virtio_node(fdt, info)?;
    }

    Ok(())
}
