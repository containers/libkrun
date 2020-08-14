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

const INIT_PATH: &str = "/init.krun";

#[repr(C)]
pub struct KipConfig {
    config_size: usize,
    log_level: u8,
    num_vcpus: u8,
    ram_mib: u32,
    root_dir: *const c_char,
    exec_path: *const c_char,
    args: *const c_char,
    env_line: *const c_char,
}

#[no_mangle]
pub extern "C" fn krun_exec(config: &KipConfig) -> i32 {
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
        .configure(Some(format!("libkrun-{}", process::id())))
        .expect("Failed to register logger");

    if config.config_size != std::mem::size_of::<KipConfig>() {
        println!(
            "Invalid configuration, the specified struct size is invalid"
        );
        process::exit(i32::from(vmm::FC_EXIT_CODE_BAD_CONFIGURATION));
    }

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
        "Should create a vm with {} cpus, {} ram and {} as root dir",
        config.num_vcpus, config.ram_mib, root_dir
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
    boot_source.kernel_cmdline_prolog = Some(format!(
        "{} init={} KRUN_INIT={} {}",
        DEFAULT_KERNEL_CMDLINE, INIT_PATH, exec_path, env_line,
    ));
    boot_source.kernel_cmdline_epilog = Some(format!(" -- {}", args));
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
