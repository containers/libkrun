#[macro_use]
extern crate logger;

use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::convert::TryInto;
use std::env;
use std::ffi::CStr;
use std::process;
use std::slice;
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::Mutex;

use libc::{c_char, size_t};
use logger::{LevelFilter, LOGGER};
use once_cell::sync::Lazy;
use polly::event_manager::EventManager;
use vmm::resources::VmResources;
use vmm::vmm_config::boot_source::{BootSourceConfig, DEFAULT_KERNEL_CMDLINE};
use vmm::vmm_config::fs::FsDeviceConfig;
use vmm::vmm_config::kernel_bundle::KernelBundle;
use vmm::vmm_config::machine_config::VmConfig;
use vmm::vmm_config::vsock::VsockDeviceConfig;

// Minimum krunfw version we require.
const KRUNFW_MIN_VERSION: u32 = 1;
// Value returned on success. We use libc's errors otherwise.
const KRUN_SUCCESS: i32 = 0;
// Maximum number of arguments/environment variables we allow
const MAX_ARGS: usize = 4096;

// Path to the init binary to be executed inside the VM.
const INIT_PATH: &str = "/init.krun";

static VMR_MAP: Lazy<Mutex<HashMap<u32, VmResources>>> = Lazy::new(|| Mutex::new(HashMap::new()));
static VMR_IDS: AtomicI32 = AtomicI32::new(0);

#[link(name = "krunfw")]
extern "C" {
    fn krunfw_get_kernel(load_addr: *mut u64, size: *mut size_t) -> *mut c_char;
    fn krunfw_get_version() -> u32;
}

#[no_mangle]
pub extern "C" fn krun_set_log_level(level: u32) -> i32 {
    let log_level = match level {
        0 => LevelFilter::Off,
        1 => LevelFilter::Error,
        2 => LevelFilter::Warn,
        3 => LevelFilter::Info,
        4 => LevelFilter::Debug,
        _ => LevelFilter::Trace,
    };

    if LOGGER
        .set_max_level(log_level)
        .configure(Some(format!("libkrun-{}", process::id())))
        .is_err()
    {
        return -libc::EINVAL;
    }

    KRUN_SUCCESS
}

#[no_mangle]
pub extern "C" fn krun_create_ctx() -> i32 {
    let krunfw_version = unsafe { krunfw_get_version() };
    if krunfw_version < KRUNFW_MIN_VERSION {
        warn!("Unsupported libkrunfw version: {}", krunfw_version);
        return -libc::EINVAL;
    }

    let mut kernel_guest_addr: u64 = 0;
    let mut kernel_size: usize = 0;
    let kernel_host_addr = unsafe {
        krunfw_get_kernel(
            &mut kernel_guest_addr as *mut u64,
            &mut kernel_size as *mut usize,
        )
    };

    let mut vm_resources = VmResources::default();

    let kernel_bundle = KernelBundle {
        host_addr: kernel_host_addr as u64,
        guest_addr: kernel_guest_addr,
        size: kernel_size,
    };
    vm_resources.set_kernel_bundle(kernel_bundle).unwrap();

    let vsock_device_config = VsockDeviceConfig {
        vsock_id: "vsock0".to_string(),
        guest_cid: 3,
        uds_path: "/tmp/vsock0".to_string(),
    };
    vm_resources.set_vsock_device(vsock_device_config).unwrap();

    let ctx_id = VMR_IDS.fetch_add(1, Ordering::SeqCst);
    if ctx_id == i32::MAX || VMR_MAP.lock().unwrap().contains_key(&(ctx_id as u32)) {
        // libkrun is not intended to be used as a daemon for managing VMs.
        panic!("Context ID namespace exhausted");
    }
    VMR_MAP.lock().unwrap().insert(ctx_id as u32, vm_resources);

    ctx_id
}

#[no_mangle]
pub extern "C" fn krun_free_ctx(ctx_id: u32) -> i32 {
    match VMR_MAP.lock().unwrap().remove(&ctx_id) {
        Some(_) => KRUN_SUCCESS,
        None => -libc::ENOENT,
    }
}

#[no_mangle]
pub extern "C" fn krun_set_vm_config(ctx_id: u32, num_vcpus: u8, ram_mib: u32) -> i32 {
    let mem_size_mib: usize = match ram_mib.try_into() {
        Ok(size) => size,
        Err(e) => {
            warn!("Error parsing the amount of RAM: {:?}", e);
            return -libc::EINVAL;
        }
    };

    let vm_config = VmConfig {
        vcpu_count: Some(num_vcpus),
        mem_size_mib: Some(mem_size_mib),
        ht_enabled: Some(false),
        cpu_template: None,
    };

    match VMR_MAP.lock().unwrap().entry(ctx_id) {
        Entry::Occupied(mut vmr) => {
            if vmr.get_mut().set_vm_config(&vm_config).is_err() {
                return -libc::EINVAL;
            }
        }
        Entry::Vacant(_) => return -libc::ENOENT,
    }

    KRUN_SUCCESS
}

#[allow(clippy::missing_safety_doc)]
#[no_mangle]
pub unsafe extern "C" fn krun_set_root(ctx_id: u32, c_root_path: *const c_char) -> i32 {
    let root_path = match CStr::from_ptr(c_root_path).to_str() {
        Ok(root) => root,
        Err(_) => return -libc::EINVAL,
    };

    let fs_device_config = FsDeviceConfig {
        fs_id: "/dev/root".to_string(),
        shared_dir: root_path.to_string(),
    };

    match VMR_MAP.lock().unwrap().entry(ctx_id) {
        Entry::Occupied(mut vmr) => {
            if vmr.get_mut().set_fs_device(fs_device_config).is_err() {
                return -libc::EINVAL;
            }
        }
        Entry::Vacant(_) => return -libc::ENOENT,
    }

    KRUN_SUCCESS
}

unsafe fn collapse_str_array(array: &[*const c_char]) -> Result<String, std::str::Utf8Error> {
    let mut strvec = Vec::new();

    for item in array.iter().take(MAX_ARGS) {
        if item.is_null() {
            break;
        } else {
            let s = CStr::from_ptr(*item).to_str()?;
            strvec.push(format!("\"{}\"", s));
        }
    }

    Ok(strvec.join(" "))
}

#[allow(clippy::missing_safety_doc)]
#[no_mangle]
pub unsafe extern "C" fn krun_set_exec(
    ctx_id: u32,
    c_exec_path: *const c_char,
    c_argv: *const *const c_char,
    c_envp: *const *const c_char,
) -> i32 {
    let exec_path = match CStr::from_ptr(c_exec_path).to_str() {
        Ok(path) => path,
        Err(e) => {
            debug!("Error parsing exec_path: {:?}", e);
            return -libc::EINVAL;
        }
    };

    let args = if !c_argv.is_null() {
        let argv_array: &[*const c_char] = slice::from_raw_parts(c_argv, MAX_ARGS);
        match collapse_str_array(argv_array) {
            Ok(s) => s,
            Err(e) => {
                debug!("Error parsing args: {:?}", e);
                return -libc::EINVAL;
            }
        }
    } else {
        "".to_string()
    };

    let env = if !c_envp.is_null() {
        let envp_array: &[*const c_char] = slice::from_raw_parts(c_envp, MAX_ARGS);
        match collapse_str_array(envp_array) {
            Ok(s) => s,
            Err(e) => {
                debug!("Error parsing args: {:?}", e);
                return -libc::EINVAL;
            }
        }
    } else {
        env::vars()
            .map(|(key, value)| format!(" {}={}", key, value))
            .collect()
    };

    let mut boot_source = BootSourceConfig::default();
    boot_source.kernel_cmdline_prolog = Some(format!(
        "{} init={} KRUN_INIT={} {}",
        DEFAULT_KERNEL_CMDLINE, INIT_PATH, exec_path, env,
    ));
    boot_source.kernel_cmdline_epilog = Some(format!(" -- {}", args));

    match VMR_MAP.lock().unwrap().entry(ctx_id) {
        Entry::Occupied(mut vmr) => {
            if vmr.get_mut().set_boot_source(boot_source).is_err() {
                return -libc::EINVAL;
            }
        }
        Entry::Vacant(_) => return -libc::ENOENT,
    }

    KRUN_SUCCESS
}

#[no_mangle]
pub extern "C" fn krun_start_enter(ctx_id: u32) -> i32 {
    let mut event_manager = match EventManager::new() {
        Ok(em) => em,
        Err(e) => {
            warn!("Unable to create EventManager: {:?}", e);
            return -libc::EINVAL;
        }
    };

    let vmr = match VMR_MAP.lock().unwrap().remove(&ctx_id) {
        Some(vmr) => vmr,
        None => return -libc::ENOENT,
    };

    let _vmm = match vmm::builder::build_microvm(&vmr, &mut event_manager) {
        Ok(vmm) => vmm,
        Err(e) => {
            warn!("Building the microVM failed: {:?}", e);
            return -libc::EINVAL;
        }
    };

    loop {
        match event_manager.run() {
            Ok(_) => {}
            Err(e) => {
                warn!("Error in EventManager loop: {:?}", e);
                return -libc::EINVAL;
            }
        }
    }
}
