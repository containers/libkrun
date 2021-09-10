#[macro_use]
extern crate logger;

use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::convert::TryInto;
use std::env;
use std::ffi::CStr;
#[cfg(target_os = "linux")]
use std::ffi::CString;
#[cfg(not(feature = "amd-sev"))]
use std::path::Path;
use std::process;
use std::slice;
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::Mutex;

#[cfg(feature = "amd-sev")]
use devices::virtio::CacheType;
use libc::{c_char, size_t};
use logger::{LevelFilter, LOGGER};
use once_cell::sync::Lazy;
use polly::event_manager::EventManager;
use vmm::resources::VmResources;
#[cfg(feature = "amd-sev")]
use vmm::vmm_config::block::BlockDeviceConfig;
use vmm::vmm_config::boot_source::{BootSourceConfig, DEFAULT_KERNEL_CMDLINE};
#[cfg(not(feature = "amd-sev"))]
use vmm::vmm_config::fs::FsDeviceConfig;
use vmm::vmm_config::kernel_bundle::KernelBundle;
#[cfg(feature = "amd-sev")]
use vmm::vmm_config::kernel_bundle::QbootBundle;
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
// Default binary to be executed inside the VM.
const DEFAULT_EXEC_PATH: &str = "/bin/sh";
// Default working directory for the binary to be executed inside the VM.
const DEFAULT_WORKDIR: &str = "/";

#[derive(Default)]
struct ContextConfig {
    vmr: VmResources,
    workdir: Option<String>,
    exec_path: Option<String>,
    env: Option<String>,
    args: Option<String>,
    rlimits: Option<String>,
    #[cfg(not(feature = "amd-sev"))]
    fs_cfg: Option<FsDeviceConfig>,
    #[cfg(feature = "amd-sev")]
    block_cfg: Option<BlockDeviceConfig>,
    port_map: Option<HashMap<u16, u16>>,
}

impl ContextConfig {
    fn set_workdir(&mut self, workdir: String) {
        self.workdir = Some(workdir);
    }

    fn get_workdir(&self) -> String {
        match &self.workdir {
            Some(workdir) => workdir.clone(),
            None => DEFAULT_WORKDIR.to_string(),
        }
    }

    fn set_exec_path(&mut self, exec_path: String) {
        self.exec_path = Some(exec_path);
    }

    fn get_exec_path(&self) -> String {
        match &self.exec_path {
            Some(exec_path) => exec_path.clone(),
            None => DEFAULT_EXEC_PATH.to_string(),
        }
    }

    fn set_env(&mut self, env: String) {
        self.env = Some(env);
    }

    fn get_env(&self) -> String {
        match &self.env {
            Some(env) => env.clone(),
            None => "".to_string(),
        }
    }

    fn set_args(&mut self, args: String) {
        self.args = Some(args);
    }

    fn get_args(&self) -> String {
        match &self.args {
            Some(args) => args.clone(),
            None => "".to_string(),
        }
    }

    fn set_rlimits(&mut self, rlimits: String) {
        self.rlimits = Some(rlimits);
    }

    fn get_rlimits(&self) -> String {
        match &self.rlimits {
            Some(rlimits) => format!("KRUN_RLIMITS={}", rlimits),
            None => "".to_string(),
        }
    }

    #[cfg(not(feature = "amd-sev"))]
    fn set_fs_cfg(&mut self, fs_cfg: FsDeviceConfig) {
        self.fs_cfg = Some(fs_cfg);
    }

    #[cfg(not(feature = "amd-sev"))]
    fn get_fs_cfg(&self) -> Option<FsDeviceConfig> {
        self.fs_cfg.clone()
    }

    #[cfg(feature = "amd-sev")]
    fn set_block_cfg(&mut self, block_cfg: BlockDeviceConfig) {
        self.block_cfg = Some(block_cfg);
    }

    #[cfg(feature = "amd-sev")]
    fn get_block_cfg(&self) -> Option<BlockDeviceConfig> {
        self.block_cfg.clone()
    }

    fn set_port_map(&mut self, port_map: HashMap<u16, u16>) {
        self.port_map = Some(port_map);
    }

    fn get_port_map(&self) -> Option<HashMap<u16, u16>> {
        self.port_map.clone()
    }
}

static CTX_MAP: Lazy<Mutex<HashMap<u32, ContextConfig>>> = Lazy::new(|| Mutex::new(HashMap::new()));
static CTX_IDS: AtomicI32 = AtomicI32::new(0);

#[link(name = "krunfw")]
extern "C" {
    #[cfg(feature = "amd-sev")]
    fn krunfw_get_qboot(size: *mut size_t) -> *mut c_char;
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

    let mut ctx_cfg = ContextConfig::default();

    let kernel_bundle = KernelBundle {
        host_addr: kernel_host_addr as u64,
        guest_addr: kernel_guest_addr,
        size: kernel_size,
    };
    ctx_cfg.vmr.set_kernel_bundle(kernel_bundle).unwrap();

    #[cfg(feature = "amd-sev")]
    {
        let mut qboot_size: usize = 0;
        let qboot_host_addr = unsafe { krunfw_get_qboot(&mut qboot_size as *mut usize) };
        let qboot_bundle = QbootBundle {
            host_addr: qboot_host_addr as u64,
            size: qboot_size,
        };
        ctx_cfg.vmr.set_qboot_bundle(qboot_bundle).unwrap();
    }

    let ctx_id = CTX_IDS.fetch_add(1, Ordering::SeqCst);
    if ctx_id == i32::MAX || CTX_MAP.lock().unwrap().contains_key(&(ctx_id as u32)) {
        // libkrun is not intended to be used as a daemon for managing VMs.
        panic!("Context ID namespace exhausted");
    }
    CTX_MAP.lock().unwrap().insert(ctx_id as u32, ctx_cfg);

    ctx_id
}

#[no_mangle]
pub extern "C" fn krun_free_ctx(ctx_id: u32) -> i32 {
    match CTX_MAP.lock().unwrap().remove(&ctx_id) {
        Some(_) => KRUN_SUCCESS,
        None => -libc::ENOENT,
    }
}

#[no_mangle]
pub extern "C" fn krun_set_vm_config(ctx_id: u32, num_vcpus: u32, ram_mib: u32) -> i32 {
    let mem_size_mib: usize = match ram_mib.try_into() {
        Ok(size) => size,
        Err(e) => {
            warn!("Error parsing the amount of RAM: {:?}", e);
            return -libc::EINVAL;
        }
    };

    let vm_config = VmConfig {
        vcpu_count: Some(num_vcpus as u8),
        mem_size_mib: Some(mem_size_mib),
        ht_enabled: Some(false),
        cpu_template: None,
    };

    match CTX_MAP.lock().unwrap().entry(ctx_id) {
        Entry::Occupied(mut ctx_cfg) => {
            if ctx_cfg.get_mut().vmr.set_vm_config(&vm_config).is_err() {
                return -libc::EINVAL;
            }
        }
        Entry::Vacant(_) => return -libc::ENOENT,
    }

    KRUN_SUCCESS
}

#[allow(clippy::missing_safety_doc)]
#[no_mangle]
#[cfg(not(feature = "amd-sev"))]
pub unsafe extern "C" fn krun_set_root(ctx_id: u32, c_root_path: *const c_char) -> i32 {
    let root_path = match CStr::from_ptr(c_root_path).to_str() {
        Ok(root) => root,
        Err(_) => return -libc::EINVAL,
    };

    let fs_id = "/dev/root".to_string();
    let shared_dir = root_path.to_string();

    match CTX_MAP.lock().unwrap().entry(ctx_id) {
        Entry::Occupied(mut ctx_cfg) => {
            let cfg = ctx_cfg.get_mut();
            let fs_device_config = match cfg.get_fs_cfg() {
                Some(fs_cfg) => FsDeviceConfig {
                    fs_id,
                    shared_dir,
                    mapped_volumes: fs_cfg.mapped_volumes,
                },
                None => FsDeviceConfig {
                    fs_id,
                    shared_dir,
                    mapped_volumes: None,
                },
            };
            cfg.set_fs_cfg(fs_device_config);
        }
        Entry::Vacant(_) => return -libc::ENOENT,
    }

    KRUN_SUCCESS
}

#[allow(clippy::missing_safety_doc)]
#[no_mangle]
#[cfg(not(feature = "amd-sev"))]
pub unsafe extern "C" fn krun_set_mapped_volumes(
    ctx_id: u32,
    c_mapped_volumes: *const *const c_char,
) -> i32 {
    let mut mapped_volumes = Vec::new();
    let mapped_volumes_array: &[*const c_char] = slice::from_raw_parts(c_mapped_volumes, MAX_ARGS);
    for item in mapped_volumes_array.iter().take(MAX_ARGS) {
        if item.is_null() {
            break;
        } else {
            let s = match CStr::from_ptr(*item).to_str() {
                Ok(s) => s,
                Err(_) => return -libc::EINVAL,
            };
            let vol_tuple: Vec<&str> = s.split(":").collect();
            if vol_tuple.len() != 2 {
                return -libc::EINVAL;
            }
            let host_vol = Path::new(vol_tuple[0]);
            let guest_vol = Path::new(vol_tuple[1]);

            if !host_vol.is_absolute()
                || !host_vol.exists()
                || !guest_vol.is_absolute()
                || guest_vol.components().count() != 2
            {
                return -libc::EINVAL;
            }

            mapped_volumes.push((host_vol.to_path_buf(), guest_vol.to_path_buf()));
        }
    }

    match CTX_MAP.lock().unwrap().entry(ctx_id) {
        Entry::Occupied(mut ctx_cfg) => {
            let cfg = ctx_cfg.get_mut();
            let fs_device_config = match cfg.get_fs_cfg() {
                Some(fs_cfg) => FsDeviceConfig {
                    fs_id: fs_cfg.fs_id.clone(),
                    shared_dir: fs_cfg.shared_dir.clone(),
                    mapped_volumes: Some(mapped_volumes),
                },
                None => FsDeviceConfig {
                    fs_id: String::new(),
                    shared_dir: String::new(),
                    mapped_volumes: Some(mapped_volumes),
                },
            };
            cfg.set_fs_cfg(fs_device_config);
        }
        Entry::Vacant(_) => return -libc::ENOENT,
    }

    KRUN_SUCCESS
}

#[allow(clippy::missing_safety_doc)]
#[no_mangle]
#[cfg(feature = "amd-sev")]
pub unsafe extern "C" fn krun_set_root_disk(ctx_id: u32, c_disk_path: *const c_char) -> i32 {
    let disk_path = match CStr::from_ptr(c_disk_path).to_str() {
        Ok(disk) => disk,
        Err(_) => return -libc::EINVAL,
    };

    //let fs_id = "/dev/root".to_string();
    //let shared_dir = root_path.to_string();

    match CTX_MAP.lock().unwrap().entry(ctx_id) {
        Entry::Occupied(mut ctx_cfg) => {
            let cfg = ctx_cfg.get_mut();
            let block_device_config = BlockDeviceConfig {
                block_id: "root".to_string(),
                cache_type: CacheType::Writeback,
                disk_image_path: disk_path.to_string(),
                is_disk_read_only: false,
                is_disk_root: true,
            };
            cfg.set_block_cfg(block_device_config);
        }
        Entry::Vacant(_) => return -libc::ENOENT,
    }

    KRUN_SUCCESS
}

#[allow(clippy::missing_safety_doc)]
#[no_mangle]
pub unsafe extern "C" fn krun_set_port_map(ctx_id: u32, c_port_map: *const *const c_char) -> i32 {
    let mut port_map = HashMap::new();
    let port_map_array: &[*const c_char] = slice::from_raw_parts(c_port_map, MAX_ARGS);
    for item in port_map_array.iter().take(MAX_ARGS) {
        if item.is_null() {
            break;
        } else {
            let s = match CStr::from_ptr(*item).to_str() {
                Ok(s) => s,
                Err(_) => return -libc::EINVAL,
            };
            let port_tuple: Vec<&str> = s.split(":").collect();
            if port_tuple.len() != 2 {
                return -libc::EINVAL;
            }
            let host_port: u16 = match port_tuple[0].parse() {
                Ok(p) => p,
                Err(_) => return -libc::EINVAL,
            };
            let guest_port: u16 = match port_tuple[1].parse() {
                Ok(p) => p,
                Err(_) => return -libc::EINVAL,
            };

            if port_map.contains_key(&guest_port) {
                return -libc::EINVAL;
            }
            for hp in port_map.values() {
                if *hp == host_port {
                    return -libc::EINVAL;
                }
            }
            port_map.insert(guest_port, host_port);
        }
    }

    match CTX_MAP.lock().unwrap().entry(ctx_id) {
        Entry::Occupied(mut ctx_cfg) => {
            let cfg = ctx_cfg.get_mut();
            cfg.set_port_map(port_map);
        }
        Entry::Vacant(_) => return -libc::ENOENT,
    }

    KRUN_SUCCESS
}

#[allow(clippy::missing_safety_doc)]
#[no_mangle]
pub unsafe extern "C" fn krun_set_rlimits(ctx_id: u32, c_rlimits: *const *const c_char) -> i32 {
    let rlimits = if c_rlimits.is_null() {
        return -libc::EINVAL;
    } else {
        let mut strvec = Vec::new();

        let array: &[*const c_char] = slice::from_raw_parts(c_rlimits, MAX_ARGS);
        for item in array.iter().take(MAX_ARGS) {
            if item.is_null() {
                break;
            } else {
                let s = match CStr::from_ptr(*item).to_str() {
                    Ok(s) => s,
                    Err(_) => return -libc::EINVAL,
                };
                strvec.push(s);
            }
        }

        format!("\"{}\"", strvec.join(","))
    };

    match CTX_MAP.lock().unwrap().entry(ctx_id) {
        Entry::Occupied(mut ctx_cfg) => {
            ctx_cfg.get_mut().set_rlimits(rlimits.to_string());
        }
        Entry::Vacant(_) => return -libc::ENOENT,
    }

    KRUN_SUCCESS
}

#[allow(clippy::missing_safety_doc)]
#[no_mangle]
pub unsafe extern "C" fn krun_set_workdir(ctx_id: u32, c_workdir_path: *const c_char) -> i32 {
    let workdir_path = match CStr::from_ptr(c_workdir_path).to_str() {
        Ok(workdir) => workdir,
        Err(_) => return -libc::EINVAL,
    };

    match CTX_MAP.lock().unwrap().entry(ctx_id) {
        Entry::Occupied(mut ctx_cfg) => {
            ctx_cfg.get_mut().set_workdir(workdir_path.to_string());
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
            .map(|(key, value)| format!(" {}=\"{}\"", key, value))
            .collect()
    };

    match CTX_MAP.lock().unwrap().entry(ctx_id) {
        Entry::Occupied(mut ctx_cfg) => {
            let cfg = ctx_cfg.get_mut();
            cfg.set_exec_path(exec_path.to_string());
            cfg.set_env(env);
            cfg.set_args(args);
        }
        Entry::Vacant(_) => return -libc::ENOENT,
    }

    KRUN_SUCCESS
}

#[no_mangle]
pub extern "C" fn krun_start_enter(ctx_id: u32) -> i32 {
    #[cfg(target_os = "linux")]
    {
        let prname = match env::var("HOSTNAME") {
            Ok(val) => CString::new(format!("VM:{}", val)).unwrap(),
            Err(_) => CString::new("libkrun VM").unwrap(),
        };
        unsafe { libc::prctl(libc::PR_SET_NAME, prname.as_ptr()) };
    }

    let mut event_manager = match EventManager::new() {
        Ok(em) => em,
        Err(e) => {
            warn!("Unable to create EventManager: {:?}", e);
            return -libc::EINVAL;
        }
    };

    let mut ctx_cfg = match CTX_MAP.lock().unwrap().remove(&ctx_id) {
        Some(ctx_cfg) => ctx_cfg,
        None => return -libc::ENOENT,
    };

    #[cfg(not(feature = "amd-sev"))]
    if let Some(fs_cfg) = ctx_cfg.get_fs_cfg() {
        if ctx_cfg.vmr.set_fs_device(fs_cfg).is_err() {
            return -libc::EINVAL;
        }
    }

    #[cfg(feature = "amd-sev")]
    if let Some(block_cfg) = ctx_cfg.get_block_cfg() {
        if ctx_cfg.vmr.set_block_device(block_cfg).is_err() {
            return -libc::EINVAL;
        }
    }

    let mut boot_source = BootSourceConfig::default();
    boot_source.kernel_cmdline_prolog = Some(format!(
        "{} init={} KRUN_INIT={} KRUN_WORKDIR={} {} {}",
        DEFAULT_KERNEL_CMDLINE,
        INIT_PATH,
        ctx_cfg.get_exec_path(),
        ctx_cfg.get_workdir(),
        ctx_cfg.get_rlimits(),
        ctx_cfg.get_env(),
    ));
    boot_source.kernel_cmdline_epilog = Some(format!(" -- {}", ctx_cfg.get_args()));

    if ctx_cfg.vmr.set_boot_source(boot_source).is_err() {
        return -libc::EINVAL;
    }

    let vsock_device_config = VsockDeviceConfig {
        vsock_id: "vsock0".to_string(),
        guest_cid: 3,
        host_port_map: ctx_cfg.get_port_map(),
    };
    ctx_cfg.vmr.set_vsock_device(vsock_device_config).unwrap();

    let _vmm = match vmm::builder::build_microvm(&ctx_cfg.vmr, &mut event_manager) {
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
