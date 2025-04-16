#[derive(Debug)]
pub enum WorkerMessage {
    #[cfg(target_arch = "x86_64")]
    GsiRoute(Vec<kvm_bindings::kvm_irq_routing_entry>),
    #[cfg(target_arch = "x86_64")]
    IrqLine(u32, bool),
}
