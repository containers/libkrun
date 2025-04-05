use kvm_bindings::{
    kvm_enable_cap, kvm_irq_routing, kvm_irq_routing_entry, kvm_irq_routing_entry__bindgen_ty_1,
    kvm_irq_routing_msi, KVM_CAP_SPLIT_IRQCHIP, KVM_IRQ_ROUTING_MSI,
};
use kvm_ioctls::{Error, VmFd};

use utils::eventfd::EventFd;

const APIC_DEFAULT_ADDRESS: u32 = 0xfee0_0000;
const IOAPIC_NUM_PINS: usize = 24;

const IOAPIC_LVT_DELIV_MODE_SHIFT: u64 = 8;
const IOAPIC_LVT_DEST_MODE_SHIFT: u64 = 11;
const IOAPIC_LVT_REMOTE_IRR_SHIFT: u64 = 14;
const IOAPIC_LVT_TRIGGER_MODE_SHIFT: u64 = 15;
const IOAPIC_LVT_MASKED_SHIFT: u64 = 16;
const IOAPIC_LVT_DEST_IDX_SHIFT: u64 = 48;

const MSI_DATA_VECTOR_SHIFT: u64 = 0;
const MSI_ADDR_DEST_MODE_SHIFT: u64 = 2;
const MSI_ADDR_DEST_IDX_SHIFT: u64 = 4;
const MSI_DATA_DELIVERY_MODE_SHIFT: u64 = 8;
const MSI_DATA_TRIGGER_SHIFT: u64 = 15;

const IOAPIC_LVT_REMOTE_IRR: u64 = 1 << IOAPIC_LVT_REMOTE_IRR_SHIFT;
const IOAPIC_LVT_TRIGGER_MODE: u64 = 1 << IOAPIC_LVT_TRIGGER_MODE_SHIFT;

const IOAPIC_DM_MASK: u64 = 0x7;
const IOAPIC_VECTOR_MASK: u64 = 0xff;

const IOAPIC_DM_EXTINT: u64 = 0x7;

/// 63:56 Destination Field (RW)
/// 55:17 Reserved
/// 16 Interrupt Mask (RW)
/// 15 Trigger Mode (RW)
/// 14 Remote IRR (RO)
/// 13 Interrupt Input Pin Polarity (INTPOL) (RW)
/// 12 Delivery Status (DELIVS) (RO)
/// 11 Destination Mode (DESTMOD) (RW)
/// 10:8 Delivery Mode (DELMOD) (RW)
/// 7:0 Interrupt Vector (INTVEC) (RW)
type RedirectionTableEntry = u64;

const IOAPIC_TRIGGER_EDGE: u64 = 0;

#[derive(Debug)]
pub enum IrqWorkerMessage {}

#[derive(Debug, Default)]
pub struct IoApicEntryInfo {
    masked: u8,
    trig_mode: u8,
    _dest_idx: u16,
    _dest_mode: u8,
    _delivery_mode: u8,
    _vector: u8,

    addr: u32,
    data: u32,
}

#[derive(Default)]
struct MsiMessage {
    address: u64,
    data: u64,
}

#[derive(Debug)]
pub struct IoApic {
    id: u8,
    ioregsel: u8,
    irr: u32,
    ioredtbl: [u64; IOAPIC_NUM_PINS],
    version: u8,
    irq_eoi: [i32; IOAPIC_NUM_PINS],
    irq_routes: Vec<kvm_irq_routing_entry>,
    irq_sender: crossbeam_channel::Sender<(IrqWorkerMessage, EventFd)>,
    event_fd: EventFd,
}

impl IoApic {
    pub fn new(
        vm: &VmFd,
        _irq_sender: crossbeam_channel::Sender<(IrqWorkerMessage, EventFd)>,
    ) -> Result<Self, Error> {
        let mut cap = kvm_enable_cap {
            cap: KVM_CAP_SPLIT_IRQCHIP,
            ..Default::default()
        };
        cap.args[0] = 24;
        vm.enable_cap(&cap)?;

        let mut ioapic = Self {
            id: 0,
            ioregsel: 0,
            irr: 0,
            ioredtbl: [1 << IOAPIC_LVT_MASKED_SHIFT; IOAPIC_NUM_PINS],
            version: 0x20,
            irq_eoi: [0; IOAPIC_NUM_PINS],
            irq_routes: Vec::with_capacity(IOAPIC_NUM_PINS),
            irq_sender: _irq_sender,
            event_fd: EventFd::new(libc::EFD_SEMAPHORE).unwrap(),
        };

        (0..IOAPIC_NUM_PINS).for_each(|i| ioapic.add_msi_route(i));

        let mut irq_routing = utils::sized_vec::vec_with_array_field::<
            kvm_irq_routing,
            kvm_irq_routing_entry,
        >(ioapic.irq_routes.len());
        irq_routing[0].nr = ioapic.irq_routes.len() as u32;
        irq_routing[0].flags = 0;

        unsafe {
            let entries_slice: &mut [kvm_irq_routing_entry] =
                irq_routing[0].entries.as_mut_slice(ioapic.irq_routes.len());
            entries_slice.copy_from_slice(ioapic.irq_routes.as_slice());
        }

        vm.set_gsi_routing(&irq_routing[0])?;

        Ok(ioapic)
    }

    fn add_msi_route(&mut self, virq: usize) {
        let msg = MsiMessage::default();
        let kroute = kvm_irq_routing_entry {
            gsi: virq as u32,
            type_: KVM_IRQ_ROUTING_MSI,
            flags: 0,
            u: kvm_irq_routing_entry__bindgen_ty_1 {
                msi: kvm_irq_routing_msi {
                    address_lo: msg.address as u32,
                    address_hi: (msg.address >> 32) as u32,
                    data: msg.data as u32,
                    ..Default::default()
                },
            },
            ..Default::default()
        };

        // 4095 is the max irq number for kvm (MAX_IRQ_ROUTES - 1)
        if self.irq_routes.len() < 4095 {
            self.irq_routes.push(kroute);
        } else {
            error!("ioapic: not enough space for irq");
        }
    }

    fn fix_edge_remote_irr(&mut self, index: usize) {
        if self.ioredtbl[index] & IOAPIC_LVT_TRIGGER_MODE == IOAPIC_TRIGGER_EDGE {
            self.ioredtbl[index] &= !IOAPIC_LVT_REMOTE_IRR;
        }
    }

    fn send_irq_worker_message(&self, msg: IrqWorkerMessage) {
        self.irq_sender
            .send((msg, self.event_fd.try_clone().unwrap()))
            .unwrap();

        self.event_fd.read().unwrap();
    }

    fn parse_entry(&self, entry: &RedirectionTableEntry) -> IoApicEntryInfo {
        let vector = (entry & IOAPIC_VECTOR_MASK) as u8;
        let dest_idx = ((entry >> IOAPIC_LVT_DEST_IDX_SHIFT) & 0xffff) as u16;
        let delivery_mode = ((entry >> IOAPIC_LVT_DELIV_MODE_SHIFT) & IOAPIC_DM_MASK) as u8;
        let trig_mode = ((entry >> IOAPIC_LVT_TRIGGER_MODE_SHIFT) & 1) as u8;
        let dest_mode = ((entry >> IOAPIC_LVT_DEST_MODE_SHIFT) & 1) as u8;

        if delivery_mode as u64 == IOAPIC_DM_EXTINT {
            panic!("ioapic: libkrun does not have PIC support");
        }

        IoApicEntryInfo {
            masked: ((entry >> IOAPIC_LVT_MASKED_SHIFT) & 1) as u8,
            trig_mode,
            _dest_idx: dest_idx,
            _dest_mode: dest_mode,
            _delivery_mode: delivery_mode,
            _vector: vector,

            addr: ((APIC_DEFAULT_ADDRESS as u64)
                | ((dest_idx as u64) << MSI_ADDR_DEST_IDX_SHIFT)
                | ((dest_mode as u64) << MSI_ADDR_DEST_MODE_SHIFT)) as u32,
            data: (((vector as u64) << MSI_DATA_VECTOR_SHIFT)
                | ((trig_mode as u64) << MSI_DATA_TRIGGER_SHIFT)
                | ((delivery_mode as u64) << MSI_DATA_DELIVERY_MODE_SHIFT))
                as u32,
        }
    }
}
