#[derive(Debug)]
pub struct MemoryProperties {
    pub gpa: u64,
    pub size: u64,
    pub private: bool,
}

#[derive(Debug)]
pub enum WorkerMessage {
    #[cfg(target_arch = "x86_64")]
    GsiRoute(
        crossbeam_channel::Sender<bool>,
        Vec<kvm_bindings::kvm_irq_routing_entry>,
    ),
    #[cfg(target_arch = "x86_64")]
    IrqLine(crossbeam_channel::Sender<bool>, u32, bool),
    #[cfg(target_os = "macos")]
    GpuAddMapping(crossbeam_channel::Sender<bool>, u64, u64, u64),
    #[cfg(target_os = "macos")]
    GpuRemoveMapping(crossbeam_channel::Sender<bool>, u64, u64),
    ConvertMemory(crossbeam_channel::Sender<bool>, MemoryProperties),
}
