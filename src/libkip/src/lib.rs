#[macro_use]
extern crate logger;

use std::convert::TryInto;
use std::env;
use std::ffi::CStr;
use std::os::raw::c_char;
use std::process;

use logger::{LevelFilter, LOGGER};
use polly::event_manager::EventManager;
use vmm::resources::VmResources;
use vmm::vmm_config::boot_source::{BootSourceConfig, DEFAULT_KERNEL_CMDLINE};
use vmm::vmm_config::fs::FsDeviceConfig;
use vmm::vmm_config::machine_config::VmConfig;
use vmm::vmm_config::vsock::VsockDeviceConfig;

const DEFAULT_KERNEL: &str = "/tmp/vmlinux.kip";
const DEFAULT_INIT: &str = "/tmp/init.kip";

#[repr(C)]
pub struct KipConfig {
    log_level: u8,
    num_vcpus: u8,
    ram_mib: u32,
    kernel: *const c_char,
    init: *const c_char,
    root_dir: *const c_char,
    exec_path: *const c_char,
    args: *const c_char,
    env_line: *const c_char,
}

#[no_mangle]
pub extern "C" fn kip_exec(config: &KipConfig) -> i32 {
    let log_level = match config.log_level {
        0 => LevelFilter::Off,
        1 => LevelFilter::Error,
        2 => LevelFilter::Warn,
        3 => LevelFilter::Info,
        4 => LevelFilter::Debug,
        _ => LevelFilter::Trace,
    };

    LOGGER
        .set_max_level(log_level)
        .configure(Some(format!("libkip-{}", process::id())))
        .expect("Failed to register logger");

    let kernel = if config.kernel.is_null() {
        DEFAULT_KERNEL
    } else {
        unsafe { CStr::from_ptr(config.kernel).to_str().unwrap() }
    };
    let init = if config.init.is_null() {
        DEFAULT_INIT
    } else {
        unsafe { CStr::from_ptr(config.init).to_str().unwrap() }
    };
    let root_dir = unsafe { CStr::from_ptr(config.root_dir).to_str().unwrap() };
    let exec_path = unsafe { CStr::from_ptr(config.exec_path).to_str().unwrap() };
    let args = if config.args.is_null() {
        ""
    } else {
        unsafe { CStr::from_ptr(config.args).to_str().unwrap() }
    };
    let env_line = if config.env_line.is_null() {
        env::vars()
            .map(|(key, value)| format!(" {}={}", key, value))
            .collect()
    } else {
        unsafe {
            CStr::from_ptr(config.env_line)
                .to_str()
                .unwrap()
                .to_string()
        }
    };

    debug!(
        "Should create a vm with {} cpus, {} ram, {} as kernel and {} as root dir",
        config.num_vcpus, config.ram_mib, kernel, root_dir
    );

    let mut vm_resources = VmResources::default();
    let vm_config = VmConfig {
        vcpu_count: Some(config.num_vcpus),
        mem_size_mib: Some(config.ram_mib.try_into().unwrap()),
        ht_enabled: Some(false),
        cpu_template: None,
    };
    vm_resources.set_vm_config(&vm_config).unwrap();

    let mut boot_source = BootSourceConfig::default();
    boot_source.kernel_image_path = kernel.to_string();
    boot_source.boot_args = Some(format!(
        "{} init={} KIP_INIT={} {} {}",
        DEFAULT_KERNEL_CMDLINE, init, exec_path, env_line, args,
    ));
    vm_resources.set_boot_source(boot_source).unwrap();

    let fs_device_config = FsDeviceConfig {
        fs_id: "/dev/root".to_string(),
        shared_dir: root_dir.to_string(),
    };
    vm_resources.set_fs_device(fs_device_config).unwrap();

    let vsock_device_config = VsockDeviceConfig {
        vsock_id: "vsock0".to_string(),
        guest_cid: 3,
        uds_path: "/tmp/vsock0".to_string(),
    };
    vm_resources.set_vsock_device(vsock_device_config).unwrap();

    let mut event_manager = EventManager::new().expect("Unable to create EventManager");

    let _vmm =
        vmm::builder::build_microvm(&vm_resources, &mut event_manager).unwrap_or_else(|err| {
            println!(
                "Building VMM configured from cmdline json failed: {:?}",
                err
            );
            process::exit(i32::from(vmm::FC_EXIT_CODE_BAD_CONFIGURATION));
        });

    loop {
        event_manager.run().unwrap();
    }
}
