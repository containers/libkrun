use std::io;
use std::sync::{Arc, Mutex};

use utils::eventfd::EventFd;
use utils::worker_message::WorkerMessage;

use crossbeam_channel::Receiver;

pub fn start_worker_thread(
    vmm: Arc<Mutex<super::Vmm>>,
    #[cfg(target_os = "macos")] receiver: Receiver<WorkerMessage>,
    #[cfg(not(target_os = "macos"))] receiver: Receiver<(WorkerMessage, EventFd)>,
) -> io::Result<()> {
    std::thread::Builder::new()
        .name("vmm worker".into())
        .spawn(move || loop {
            match receiver.recv() {
                Err(e) => error!("error receiving message from vmm worker thread: {:?}", e),
                #[cfg(target_os = "macos")]
                Ok(message) => vmm.lock().unwrap().match_worker_message(message),
                #[cfg(target_os = "linux")]
                Ok((message, evt_fd)) => vmm.lock().unwrap().match_worker_message(message, evt_fd),
            }
        })?;
    Ok(())
}

impl super::Vmm {
    fn match_worker_message(
        &self,
        msg: WorkerMessage,
        #[cfg(target_os = "linux")] evt_fd: EventFd,
    ) {
        match msg {
            #[cfg(target_os = "macos")]
            WorkerMessage::GpuAddMapping(s, h, g, l) => self.add_mapping(s, h, g, l),
            #[cfg(target_os = "macos")]
            WorkerMessage::GpuRemoveMapping(s, g, l) => self.remove_mapping(s, g, l),
            #[cfg(target_arch = "x86_64")]
            WorkerMessage::GsiRoute(entries) => {
                let mut irq_routing = utils::sized_vec::vec_with_array_field::<
                    kvm_bindings::kvm_irq_routing,
                    kvm_bindings::kvm_irq_routing_entry,
                >(entries.len());
                irq_routing[0].nr = entries.len() as u32;
                irq_routing[0].flags = 0;

                unsafe {
                    let entries_slice: &mut [kvm_bindings::kvm_irq_routing_entry] =
                        irq_routing[0].entries.as_mut_slice(entries.len());
                    entries_slice.copy_from_slice(&entries);
                }

                self.vm.fd().set_gsi_routing(&irq_routing[0]).unwrap();

                evt_fd.write(1).unwrap();
            }
            #[cfg(target_arch = "x86_64")]
            WorkerMessage::IrqLine(irq, active) => {
                self.vm.fd().set_irq_line(irq, active).unwrap();
                evt_fd.write(1).unwrap();
            }
        }
    }
}
