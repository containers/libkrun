#[macro_use]
extern crate log;

use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::convert::TryInto;
use std::env;
use std::ffi::CStr;
#[cfg(target_os = "linux")]
use std::ffi::CString;
#[cfg(all(target_arch = "x86_64", not(feature = "tee")))]
use std::fs::File;
#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;
use std::os::fd::RawFd;
use std::path::PathBuf;
use std::slice;
use std::sync::atomic::{AtomicI32, Ordering};
#[cfg(not(feature = "efi"))]
use std::sync::LazyLock;
use std::sync::Mutex;

use crossbeam_channel::unbounded;
#[cfg(feature = "blk")]
use devices::virtio::block::ImageType;
#[cfg(feature = "net")]
use devices::virtio::net::device::VirtioNetBackend;
#[cfg(feature = "blk")]
use devices::virtio::CacheType;
use env_logger::Env;
#[cfg(not(feature = "efi"))]
use libc::size_t;
use libc::{c_char, c_int};
use once_cell::sync::Lazy;
use polly::event_manager::EventManager;
use utils::eventfd::EventFd;
use vmm::resources::VmResources;
#[cfg(feature = "blk")]
use vmm::vmm_config::block::BlockDeviceConfig;
use vmm::vmm_config::boot_source::{BootSourceConfig, DEFAULT_KERNEL_CMDLINE};
#[cfg(not(feature = "tee"))]
use vmm::vmm_config::external_kernel::{ExternalKernel, KernelFormat};
#[cfg(not(feature = "tee"))]
use vmm::vmm_config::fs::FsDeviceConfig;
#[cfg(not(feature = "efi"))]
use vmm::vmm_config::kernel_bundle::KernelBundle;
#[cfg(feature = "tee")]
use vmm::vmm_config::kernel_bundle::{InitrdBundle, QbootBundle};
use vmm::vmm_config::machine_config::VmConfig;
#[cfg(feature = "net")]
use vmm::vmm_config::net::NetworkInterfaceConfig;
use vmm::vmm_config::vsock::VsockDeviceConfig;

// Value returned on success. We use libc's errors otherwise.
const KRUN_SUCCESS: i32 = 0;
// Maximum number of arguments/environment variables we allow
const MAX_ARGS: usize = 4096;

// krunfw library name for each context
#[cfg(all(target_os = "linux", not(feature = "amd-sev")))]
const KRUNFW_NAME: &str = "libkrunfw.so.4";
#[cfg(all(target_os = "linux", feature = "amd-sev"))]
const KRUNFW_NAME: &str = "libkrunfw-sev.so.4";
#[cfg(all(target_os = "macos", not(feature = "efi")))]
const KRUNFW_NAME: &str = "libkrunfw.4.dylib";

// Path to the init binary to be executed inside the VM.
const INIT_PATH: &str = "/init.krun";

#[cfg(not(feature = "efi"))]
static KRUNFW: LazyLock<Option<libloading::Library>> =
    LazyLock::new(|| unsafe { libloading::Library::new(KRUNFW_NAME).ok() });

#[cfg(not(feature = "efi"))]
pub struct KrunfwBindings {
    get_kernel: libloading::Symbol<
        'static,
        unsafe extern "C" fn(*mut u64, *mut u64, *mut size_t) -> *mut c_char,
    >,
    #[cfg(feature = "tee")]
    get_initrd: libloading::Symbol<'static, unsafe extern "C" fn(*mut size_t) -> *mut c_char>,
    #[cfg(feature = "tee")]
    get_qboot: libloading::Symbol<'static, unsafe extern "C" fn(*mut size_t) -> *mut c_char>,
}

#[cfg(not(feature = "efi"))]
impl KrunfwBindings {
    fn load_bindings() -> Result<KrunfwBindings, libloading::Error> {
        let krunfw = match KRUNFW.as_ref() {
            Some(krunfw) => krunfw,
            None => return Err(libloading::Error::DlOpenUnknown),
        };
        Ok(unsafe {
            KrunfwBindings {
                get_kernel: krunfw.get(b"krunfw_get_kernel")?,
                #[cfg(feature = "tee")]
                get_initrd: krunfw.get(b"krunfw_get_initrd")?,
                #[cfg(feature = "tee")]
                get_qboot: krunfw.get(b"krunfw_get_qboot")?,
            }
        })
    }

    pub fn new() -> Option<Self> {
        Self::load_bindings().ok()
    }
}

#[derive(Default)]
struct TsiConfig {
    port_map: Option<HashMap<u16, u16>>,
}

enum NetworkConfig {
    Tsi(TsiConfig),
    VirtioNetPasst(RawFd),
    VirtioNetGvproxy(PathBuf),
}

impl Default for NetworkConfig {
    /// Default network mode is TSI, for backwards compatibility
    fn default() -> Self {
        NetworkConfig::Tsi(Default::default())
    }
}

#[derive(Default)]
struct ContextConfig {
    #[cfg(not(feature = "efi"))]
    krunfw: Option<KrunfwBindings>,
    vmr: VmResources,
    workdir: Option<String>,
    exec_path: Option<String>,
    env: Option<String>,
    args: Option<String>,
    rlimits: Option<String>,
    net_cfg: NetworkConfig,
    mac: Option<[u8; 6]>,
    #[cfg(feature = "blk")]
    block_cfgs: Vec<BlockDeviceConfig>,
    #[cfg(feature = "blk")]
    root_block_cfg: Option<BlockDeviceConfig>,
    #[cfg(feature = "blk")]
    data_block_cfg: Option<BlockDeviceConfig>,
    #[cfg(feature = "tee")]
    tee_config_file: Option<PathBuf>,
    unix_ipc_port_map: Option<HashMap<u32, (PathBuf, bool)>>,
    shutdown_efd: Option<EventFd>,
    gpu_virgl_flags: Option<u32>,
    gpu_shm_size: Option<usize>,
    enable_snd: bool,
    console_output: Option<PathBuf>,
    vmm_uid: Option<libc::uid_t>,
    vmm_gid: Option<libc::gid_t>,
}

impl ContextConfig {
    fn set_workdir(&mut self, workdir: String) {
        self.workdir = Some(workdir);
    }

    fn get_workdir(&self) -> String {
        match &self.workdir {
            Some(workdir) => format!("KRUN_WORKDIR={workdir}"),
            None => "".to_string(),
        }
    }

    fn set_exec_path(&mut self, exec_path: String) {
        self.exec_path = Some(exec_path);
    }

    fn get_exec_path(&self) -> String {
        match &self.exec_path {
            Some(exec_path) => format!("KRUN_INIT={exec_path}"),
            None => "".to_string(),
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
            Some(rlimits) => format!("KRUN_RLIMITS={rlimits}"),
            None => "".to_string(),
        }
    }

    #[cfg(feature = "blk")]
    fn add_block_cfg(&mut self, block_cfg: BlockDeviceConfig) {
        self.block_cfgs.push(block_cfg);
    }

    #[cfg(feature = "blk")]
    fn set_root_block_cfg(&mut self, block_cfg: BlockDeviceConfig) {
        self.root_block_cfg = Some(block_cfg);
    }

    #[cfg(feature = "blk")]
    fn set_data_block_cfg(&mut self, block_cfg: BlockDeviceConfig) {
        self.data_block_cfg = Some(block_cfg);
    }

    #[cfg(feature = "blk")]
    fn get_block_cfg(&self) -> Vec<BlockDeviceConfig> {
        // For backwards compat, when cfgs is empty (the new API is not used), this needs to be
        // root and then data, in that order. Also for backwards compat, root/data are setters and
        // need to discard redundant calls. So we have simple setters above and fix up here.
        //
        // When the new API is used, this is simpler.
        if self.block_cfgs.is_empty() {
            [&self.root_block_cfg, &self.data_block_cfg]
                .into_iter()
                .filter_map(|cfg| cfg.clone())
                .collect()
        } else {
            self.block_cfgs.clone()
        }
    }

    fn set_net_cfg(&mut self, net_cfg: NetworkConfig) {
        self.net_cfg = net_cfg;
    }

    fn set_net_mac(&mut self, mac: [u8; 6]) {
        self.mac = Some(mac);
    }

    fn set_port_map(&mut self, new_port_map: HashMap<u16, u16>) -> Result<(), ()> {
        match &mut self.net_cfg {
            NetworkConfig::Tsi(tsi_config) => {
                tsi_config.port_map.replace(new_port_map);
                Ok(())
            }
            NetworkConfig::VirtioNetPasst(_) => Err(()),
            NetworkConfig::VirtioNetGvproxy(_) => Err(()),
        }
    }

    #[cfg(feature = "tee")]
    fn set_tee_config_file(&mut self, filepath: PathBuf) {
        self.tee_config_file = Some(filepath);
    }

    #[cfg(feature = "tee")]
    fn get_tee_config_file(&self) -> Option<PathBuf> {
        self.tee_config_file.clone()
    }

    fn add_vsock_port(&mut self, port: u32, filepath: PathBuf, listen: bool) {
        if let Some(ref mut map) = &mut self.unix_ipc_port_map {
            map.insert(port, (filepath, listen));
        } else {
            let mut map: HashMap<u32, (PathBuf, bool)> = HashMap::new();
            map.insert(port, (filepath, listen));
            self.unix_ipc_port_map = Some(map);
        }
    }

    fn set_gpu_virgl_flags(&mut self, virgl_flags: u32) {
        self.gpu_virgl_flags = Some(virgl_flags);
    }

    fn set_gpu_shm_size(&mut self, shm_size: usize) {
        self.gpu_shm_size = Some(shm_size);
    }

    fn set_vmm_uid(&mut self, vmm_uid: libc::uid_t) {
        self.vmm_uid = Some(vmm_uid);
    }

    fn set_vmm_gid(&mut self, vmm_gid: libc::gid_t) {
        self.vmm_gid = Some(vmm_gid);
    }
}

static CTX_MAP: Lazy<Mutex<HashMap<u32, ContextConfig>>> = Lazy::new(|| Mutex::new(HashMap::new()));
static CTX_IDS: AtomicI32 = AtomicI32::new(0);

#[no_mangle]
pub extern "C" fn krun_set_log_level(level: u32) -> i32 {
    let log_level = match level {
        0 => "off",
        1 => "error",
        2 => "warn",
        3 => "info",
        4 => "debug",
        _ => "trace",
    };
    env_logger::Builder::from_env(Env::default().default_filter_or(log_level)).init();
    KRUN_SUCCESS
}

#[no_mangle]
pub extern "C" fn krun_create_ctx() -> i32 {
    let ctx_cfg = {
        let shutdown_efd = if cfg!(feature = "efi") {
            Some(EventFd::new(utils::eventfd::EFD_NONBLOCK).unwrap())
        } else {
            None
        };

        ContextConfig {
            #[cfg(not(feature = "efi"))]
            krunfw: KrunfwBindings::new(),
            shutdown_efd,
            ..Default::default()
        }
    };

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
pub extern "C" fn krun_set_vm_config(ctx_id: u32, num_vcpus: u8, ram_mib: u32) -> i32 {
    let mem_size_mib: usize = match ram_mib.try_into() {
        Ok(size) => size,
        Err(e) => {
            warn!("Error parsing the amount of RAM: {e:?}");
            return -libc::EINVAL;
        }
    };

    let vm_config = VmConfig {
        vcpu_count: Some(num_vcpus),
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
#[cfg(not(feature = "tee"))]
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
            cfg.vmr.add_fs_device(FsDeviceConfig {
                fs_id,
                shared_dir,
                // Default to a conservative 512 MB window.
                shm_size: Some(1 << 29),
            });
        }
        Entry::Vacant(_) => return -libc::ENOENT,
    }

    KRUN_SUCCESS
}

#[allow(clippy::missing_safety_doc)]
#[no_mangle]
#[cfg(not(feature = "tee"))]
pub unsafe extern "C" fn krun_add_virtiofs(
    ctx_id: u32,
    c_tag: *const c_char,
    c_path: *const c_char,
) -> i32 {
    let tag = match CStr::from_ptr(c_tag).to_str() {
        Ok(tag) => tag,
        Err(_) => return -libc::EINVAL,
    };
    let path = match CStr::from_ptr(c_path).to_str() {
        Ok(path) => path,
        Err(_) => return -libc::EINVAL,
    };

    match CTX_MAP.lock().unwrap().entry(ctx_id) {
        Entry::Occupied(mut ctx_cfg) => {
            let cfg = ctx_cfg.get_mut();
            cfg.vmr.add_fs_device(FsDeviceConfig {
                fs_id: tag.to_string(),
                shared_dir: path.to_string(),
                shm_size: None,
            });
        }
        Entry::Vacant(_) => return -libc::ENOENT,
    }

    KRUN_SUCCESS
}

#[allow(clippy::missing_safety_doc)]
#[no_mangle]
#[cfg(not(feature = "tee"))]
pub unsafe extern "C" fn krun_add_virtiofs2(
    ctx_id: u32,
    c_tag: *const c_char,
    c_path: *const c_char,
    shm_size: u64,
) -> i32 {
    let tag = match CStr::from_ptr(c_tag).to_str() {
        Ok(tag) => tag,
        Err(_) => return -libc::EINVAL,
    };
    let path = match CStr::from_ptr(c_path).to_str() {
        Ok(path) => path,
        Err(_) => return -libc::EINVAL,
    };

    match CTX_MAP.lock().unwrap().entry(ctx_id) {
        Entry::Occupied(mut ctx_cfg) => {
            let cfg = ctx_cfg.get_mut();
            cfg.vmr.add_fs_device(FsDeviceConfig {
                fs_id: tag.to_string(),
                shared_dir: path.to_string(),
                shm_size: Some(shm_size.try_into().unwrap()),
            });
        }
        Entry::Vacant(_) => return -libc::ENOENT,
    }

    KRUN_SUCCESS
}

#[allow(clippy::missing_safety_doc)]
#[no_mangle]
#[cfg(not(feature = "tee"))]
pub unsafe extern "C" fn krun_set_mapped_volumes(
    _ctx_id: u32,
    _c_mapped_volumes: *const *const c_char,
) -> i32 {
    -libc::EINVAL
}

#[allow(clippy::missing_safety_doc)]
#[no_mangle]
#[cfg(feature = "blk")]
pub unsafe extern "C" fn krun_add_disk(
    ctx_id: u32,
    c_block_id: *const c_char,
    c_disk_path: *const c_char,
    read_only: bool,
) -> i32 {
    let disk_path = match CStr::from_ptr(c_disk_path).to_str() {
        Ok(disk) => disk,
        Err(_) => return -libc::EINVAL,
    };

    let block_id = match CStr::from_ptr(c_block_id).to_str() {
        Ok(block_id) => block_id,
        Err(_) => return -libc::EINVAL,
    };

    match CTX_MAP.lock().unwrap().entry(ctx_id) {
        Entry::Occupied(mut ctx_cfg) => {
            let cfg = ctx_cfg.get_mut();
            let block_device_config = BlockDeviceConfig {
                block_id: block_id.to_string(),
                cache_type: CacheType::auto(disk_path),
                disk_image_path: disk_path.to_string(),
                disk_image_format: ImageType::Raw,
                is_disk_read_only: read_only,
            };
            cfg.add_block_cfg(block_device_config);
        }
        Entry::Vacant(_) => return -libc::ENOENT,
    }

    KRUN_SUCCESS
}

#[allow(clippy::missing_safety_doc)]
#[no_mangle]
#[cfg(feature = "blk")]
pub unsafe extern "C" fn krun_add_disk2(
    ctx_id: u32,
    c_block_id: *const c_char,
    c_disk_path: *const c_char,
    disk_format: u32,
    read_only: bool,
) -> i32 {
    let disk_path = match CStr::from_ptr(c_disk_path).to_str() {
        Ok(disk) => disk,
        Err(_) => return -libc::EINVAL,
    };

    let block_id = match CStr::from_ptr(c_block_id).to_str() {
        Ok(block_id) => block_id,
        Err(_) => return -libc::EINVAL,
    };

    let format = match disk_format {
        0 => ImageType::Raw,
        1 => ImageType::Qcow2,
        _ => {
            // Do not continue if the user cannot specify a valid disk format
            return -libc::EINVAL;
        }
    };

    match CTX_MAP.lock().unwrap().entry(ctx_id) {
        Entry::Occupied(mut ctx_cfg) => {
            let cfg = ctx_cfg.get_mut();
            let block_device_config = BlockDeviceConfig {
                block_id: block_id.to_string(),
                cache_type: CacheType::auto(disk_path),
                disk_image_path: disk_path.to_string(),
                disk_image_format: format,
                is_disk_read_only: read_only,
            };
            cfg.add_block_cfg(block_device_config);
        }
        Entry::Vacant(_) => return -libc::ENOENT,
    }

    KRUN_SUCCESS
}

#[allow(clippy::missing_safety_doc)]
#[no_mangle]
#[cfg(feature = "blk")]
pub unsafe extern "C" fn krun_set_root_disk(ctx_id: u32, c_disk_path: *const c_char) -> i32 {
    let disk_path = match CStr::from_ptr(c_disk_path).to_str() {
        Ok(disk) => disk,
        Err(_) => return -libc::EINVAL,
    };

    match CTX_MAP.lock().unwrap().entry(ctx_id) {
        Entry::Occupied(mut ctx_cfg) => {
            let cfg = ctx_cfg.get_mut();
            let block_device_config = BlockDeviceConfig {
                block_id: "root".to_string(),
                cache_type: CacheType::auto(disk_path),
                disk_image_path: disk_path.to_string(),
                disk_image_format: ImageType::Raw,
                is_disk_read_only: false,
            };
            cfg.set_root_block_cfg(block_device_config);
        }
        Entry::Vacant(_) => return -libc::ENOENT,
    }

    KRUN_SUCCESS
}

#[allow(clippy::missing_safety_doc)]
#[no_mangle]
#[cfg(feature = "blk")]
pub unsafe extern "C" fn krun_set_data_disk(ctx_id: u32, c_disk_path: *const c_char) -> i32 {
    let disk_path = match CStr::from_ptr(c_disk_path).to_str() {
        Ok(disk) => disk,
        Err(_) => return -libc::EINVAL,
    };

    match CTX_MAP.lock().unwrap().entry(ctx_id) {
        Entry::Occupied(mut ctx_cfg) => {
            let cfg = ctx_cfg.get_mut();
            let block_device_config = BlockDeviceConfig {
                block_id: "data".to_string(),
                cache_type: CacheType::auto(disk_path),
                disk_image_path: disk_path.to_string(),
                disk_image_format: ImageType::Raw,
                is_disk_read_only: false,
            };
            cfg.set_data_block_cfg(block_device_config);
        }
        Entry::Vacant(_) => return -libc::ENOENT,
    }

    KRUN_SUCCESS
}

#[allow(clippy::missing_safety_doc)]
#[no_mangle]
pub unsafe extern "C" fn krun_set_passt_fd(ctx_id: u32, fd: c_int) -> i32 {
    if fd < 0 {
        return -libc::EINVAL;
    }

    if cfg!(not(feature = "net")) {
        return -libc::ENOTSUP;
    }

    match CTX_MAP.lock().unwrap().entry(ctx_id) {
        Entry::Occupied(mut ctx_cfg) => {
            let cfg = ctx_cfg.get_mut();
            cfg.set_net_cfg(NetworkConfig::VirtioNetPasst(fd));
        }
        Entry::Vacant(_) => return -libc::ENOENT,
    }
    KRUN_SUCCESS
}

#[allow(clippy::missing_safety_doc)]
#[no_mangle]
pub unsafe extern "C" fn krun_set_gvproxy_path(ctx_id: u32, c_path: *const c_char) -> i32 {
    let path_str = match CStr::from_ptr(c_path).to_str() {
        Ok(path) => path,
        Err(e) => {
            debug!("Error parsing gvproxy_path: {:?}", e);
            return -libc::EINVAL;
        }
    };

    let path = PathBuf::from(path_str);

    match CTX_MAP.lock().unwrap().entry(ctx_id) {
        Entry::Occupied(mut ctx_cfg) => {
            let cfg = ctx_cfg.get_mut();
            cfg.set_net_cfg(NetworkConfig::VirtioNetGvproxy(path));
        }
        Entry::Vacant(_) => return -libc::ENOENT,
    }
    KRUN_SUCCESS
}

#[allow(clippy::missing_safety_doc)]
#[no_mangle]
pub unsafe extern "C" fn krun_set_net_mac(ctx_id: u32, c_mac: *const u8) -> i32 {
    if cfg!(not(feature = "net")) {
        return -libc::ENOTSUP;
    }

    let mac: [u8; 6] = match slice::from_raw_parts(c_mac, 6).try_into() {
        Ok(m) => m,
        Err(_) => return -libc::EINVAL,
    };

    match CTX_MAP.lock().unwrap().entry(ctx_id) {
        Entry::Occupied(mut ctx_cfg) => {
            let cfg = ctx_cfg.get_mut();
            cfg.set_net_mac(mac);
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
            let port_tuple: Vec<&str> = s.split(':').collect();
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
            if cfg.set_port_map(port_map).is_err() {
                return -libc::ENOTSUP;
            }
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
            ctx_cfg.get_mut().set_rlimits(rlimits);
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
            strvec.push(format!("\"{s}\""));
        }
    }

    Ok(strvec.join(" "))
}

#[allow(clippy::format_collect)]
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
            .map(|(key, value)| format!(" {key}=\"{value}\""))
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

#[allow(clippy::format_collect)]
#[allow(clippy::missing_safety_doc)]
#[no_mangle]
pub unsafe extern "C" fn krun_set_env(ctx_id: u32, c_envp: *const *const c_char) -> i32 {
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
            .map(|(key, value)| format!(" {key}=\"{value}\""))
            .collect()
    };

    match CTX_MAP.lock().unwrap().entry(ctx_id) {
        Entry::Occupied(mut ctx_cfg) => {
            let cfg = ctx_cfg.get_mut();
            cfg.set_env(env);
        }
        Entry::Vacant(_) => return -libc::ENOENT,
    }

    KRUN_SUCCESS
}

#[allow(clippy::missing_safety_doc)]
#[no_mangle]
#[cfg(feature = "tee")]
pub unsafe extern "C" fn krun_set_tee_config_file(ctx_id: u32, c_filepath: *const c_char) -> i32 {
    let filepath = match CStr::from_ptr(c_filepath).to_str() {
        Ok(f) => f,
        Err(_) => return -libc::EINVAL,
    };

    match CTX_MAP.lock().unwrap().entry(ctx_id) {
        Entry::Occupied(mut ctx_cfg) => {
            let cfg = ctx_cfg.get_mut();
            cfg.set_tee_config_file(PathBuf::from(filepath.to_string()));
        }
        Entry::Vacant(_) => return -libc::ENOENT,
    }

    KRUN_SUCCESS
}

#[allow(clippy::missing_safety_doc)]
#[no_mangle]
pub unsafe extern "C" fn krun_add_vsock_port(
    ctx_id: u32,
    port: u32,
    c_filepath: *const c_char,
) -> i32 {
    krun_add_vsock_port2(ctx_id, port, c_filepath, false)
}

#[allow(clippy::missing_safety_doc)]
#[no_mangle]
pub unsafe extern "C" fn krun_add_vsock_port2(
    ctx_id: u32,
    port: u32,
    c_filepath: *const c_char,
    listen: bool,
) -> i32 {
    let filepath = match CStr::from_ptr(c_filepath).to_str() {
        Ok(f) => PathBuf::from(f.to_string()),
        Err(_) => return -libc::EINVAL,
    };

    if listen {
        match filepath.try_exists() {
            Ok(true) => return -libc::EEXIST,
            Err(_) => return -libc::EINVAL,
            _ => {}
        }
    }

    match CTX_MAP.lock().unwrap().entry(ctx_id) {
        Entry::Occupied(mut ctx_cfg) => {
            let cfg = ctx_cfg.get_mut();
            cfg.add_vsock_port(port, filepath, listen);
        }
        Entry::Vacant(_) => return -libc::ENOENT,
    }

    KRUN_SUCCESS
}

#[allow(clippy::missing_safety_doc)]
#[no_mangle]
pub unsafe extern "C" fn krun_set_gpu_options(ctx_id: u32, virgl_flags: u32) -> i32 {
    match CTX_MAP.lock().unwrap().entry(ctx_id) {
        Entry::Occupied(mut ctx_cfg) => {
            let cfg = ctx_cfg.get_mut();
            cfg.set_gpu_virgl_flags(virgl_flags);
        }
        Entry::Vacant(_) => return -libc::ENOENT,
    }

    KRUN_SUCCESS
}

#[allow(clippy::missing_safety_doc)]
#[no_mangle]
pub unsafe extern "C" fn krun_set_gpu_options2(
    ctx_id: u32,
    virgl_flags: u32,
    shm_size: u64,
) -> i32 {
    match CTX_MAP.lock().unwrap().entry(ctx_id) {
        Entry::Occupied(mut ctx_cfg) => {
            let cfg = ctx_cfg.get_mut();
            cfg.set_gpu_virgl_flags(virgl_flags);
            cfg.set_gpu_shm_size(shm_size.try_into().unwrap());
        }
        Entry::Vacant(_) => return -libc::ENOENT,
    }

    KRUN_SUCCESS
}

#[allow(clippy::missing_safety_doc)]
#[no_mangle]
pub unsafe extern "C" fn krun_set_snd_device(ctx_id: u32, enable: bool) -> i32 {
    match CTX_MAP.lock().unwrap().entry(ctx_id) {
        Entry::Occupied(mut ctx_cfg) => {
            let cfg = ctx_cfg.get_mut();
            cfg.enable_snd = enable;
        }
        Entry::Vacant(_) => return -libc::ENOENT,
    }

    KRUN_SUCCESS
}

#[allow(unused_assignments)]
#[no_mangle]
pub extern "C" fn krun_get_shutdown_eventfd(ctx_id: u32) -> i32 {
    match CTX_MAP.lock().unwrap().entry(ctx_id) {
        Entry::Occupied(mut ctx_cfg) => {
            let cfg = ctx_cfg.get_mut();
            if let Some(efd) = cfg.shutdown_efd.as_ref() {
                #[cfg(target_os = "macos")]
                return efd.get_write_fd();
                #[cfg(target_os = "linux")]
                return efd.as_raw_fd();
            } else {
                -libc::EINVAL
            }
        }
        Entry::Vacant(_) => -libc::ENOENT,
    }
}

#[allow(clippy::missing_safety_doc)]
#[no_mangle]
pub unsafe extern "C" fn krun_set_console_output(ctx_id: u32, c_filepath: *const c_char) -> i32 {
    let filepath = match CStr::from_ptr(c_filepath).to_str() {
        Ok(f) => f,
        Err(_) => return -libc::EINVAL,
    };

    match CTX_MAP.lock().unwrap().entry(ctx_id) {
        Entry::Occupied(mut ctx_cfg) => {
            let cfg = ctx_cfg.get_mut();
            if cfg.console_output.is_some() {
                -libc::EINVAL
            } else {
                cfg.console_output = Some(PathBuf::from(filepath.to_string()));
                KRUN_SUCCESS
            }
        }
        Entry::Vacant(_) => -libc::ENOENT,
    }
}

#[allow(clippy::missing_safety_doc)]
#[no_mangle]
pub unsafe extern "C" fn krun_set_nested_virt(ctx_id: u32, enabled: bool) -> i32 {
    if enabled && !cfg!(target_os = "macos") {
        return -libc::EINVAL;
    }

    match CTX_MAP.lock().unwrap().entry(ctx_id) {
        Entry::Occupied(mut ctx_cfg) => {
            let cfg = ctx_cfg.get_mut();
            cfg.vmr.nested_enabled = enabled;
            KRUN_SUCCESS
        }
        Entry::Vacant(_) => -libc::ENOENT,
    }
}

#[allow(clippy::missing_safety_doc)]
#[no_mangle]
pub unsafe extern "C" fn krun_check_nested_virt() -> i32 {
    #[cfg(target_os = "macos")]
    match hvf::check_nested_virt() {
        Ok(supp) => supp as i32,
        Err(_) => -libc::EINVAL,
    }

    #[cfg(not(target_os = "macos"))]
    -libc::EOPNOTSUPP
}

#[allow(clippy::missing_safety_doc)]
#[no_mangle]
pub extern "C" fn krun_split_irqchip(ctx_id: u32, enable: bool) -> i32 {
    if enable && !cfg!(target_arch = "x86_64") {
        return -libc::EINVAL;
    }
    match CTX_MAP.lock().unwrap().entry(ctx_id) {
        Entry::Occupied(mut ctx_cfg) => {
            let cfg = ctx_cfg.get_mut();
            cfg.vmr.split_irqchip = enable;
            KRUN_SUCCESS
        }
        Entry::Vacant(_) => -libc::ENOENT,
    }
}

#[allow(clippy::missing_safety_doc)]
#[no_mangle]
pub unsafe extern "C" fn krun_set_smbios_oem_strings(
    ctx_id: u32,
    oem_strings: *const *const c_char,
) -> i32 {
    if oem_strings.is_null() {
        return -libc::EINVAL;
    }

    let cstr_ptr_slice = slice::from_raw_parts(oem_strings, MAX_ARGS);

    let mut oem_strings = Vec::new();

    for cstr_ptr in cstr_ptr_slice.iter().take_while(|p| !p.is_null()) {
        let Ok(s) = CStr::from_ptr(*cstr_ptr).to_str() else {
            return -libc::EINVAL;
        };
        oem_strings.push(s.to_string());
    }

    match CTX_MAP.lock().unwrap().entry(ctx_id) {
        Entry::Occupied(mut ctx_cfg) => {
            ctx_cfg.get_mut().vmr.smbios_oem_strings =
                (!oem_strings.is_empty()).then_some(oem_strings)
        }
        Entry::Vacant(_) => return -libc::ENOENT,
    }

    KRUN_SUCCESS
}

#[cfg(feature = "net")]
fn create_virtio_net(ctx_cfg: &mut ContextConfig, backend: VirtioNetBackend) {
    let mac = ctx_cfg.mac.unwrap_or([0x5a, 0x94, 0xef, 0xe4, 0x0c, 0xee]);

    let network_interface_config = NetworkInterfaceConfig {
        iface_id: "eth0".to_string(),
        backend,
        mac,
    };
    ctx_cfg
        .vmr
        .add_network_interface(network_interface_config)
        .expect("Failed to create network interface");
}

#[cfg(all(target_arch = "x86_64", not(feature = "tee")))]
fn map_kernel(ctx_id: u32, kernel_path: &PathBuf) -> i32 {
    let file = match File::options().read(true).write(false).open(kernel_path) {
        Ok(file) => file,
        Err(err) => {
            error!("Error opening external kernel: {err}");
            return -libc::EINVAL;
        }
    };

    let kernel_size = file.metadata().unwrap().len();

    let kernel_host_addr = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            kernel_size as usize,
            libc::PROT_READ,
            libc::MAP_SHARED,
            file.as_raw_fd(),
            0_i64,
        )
    };
    if std::ptr::eq(kernel_host_addr, libc::MAP_FAILED) {
        error!("Can't load kernel into process map");
        return -libc::EINVAL;
    }

    let kernel_bundle = KernelBundle {
        host_addr: kernel_host_addr as u64,
        guest_addr: 0x8000_0000,
        entry_addr: 0x8000_0000,
        size: kernel_size as usize,
    };

    match CTX_MAP.lock().unwrap().entry(ctx_id) {
        Entry::Occupied(mut ctx_cfg) => ctx_cfg
            .get_mut()
            .vmr
            .set_kernel_bundle(kernel_bundle)
            .unwrap(),
        Entry::Vacant(_) => return -libc::ENOENT,
    }

    KRUN_SUCCESS
}

#[cfg(feature = "tee")]
#[allow(clippy::format_collect)]
#[allow(clippy::missing_safety_doc)]
#[no_mangle]
pub unsafe extern "C" fn krun_set_kernel(_ctx_id: u32, _c_kernel_path: *const c_char) -> i32 {
    -libc::EOPNOTSUPP
}

#[cfg(not(feature = "tee"))]
#[allow(clippy::format_collect)]
#[allow(clippy::missing_safety_doc)]
#[no_mangle]
pub unsafe extern "C" fn krun_set_kernel(
    ctx_id: u32,
    c_kernel_path: *const c_char,
    kernel_format: u32,
    c_initramfs_path: *const c_char,
    c_cmdline: *const c_char,
) -> i32 {
    let path = match CStr::from_ptr(c_kernel_path).to_str() {
        Ok(path) => PathBuf::from(path),
        Err(e) => {
            error!("Error parsing kernel_path: {:?}", e);
            return -libc::EINVAL;
        }
    };

    let format = match kernel_format {
        // For raw kernels in x86_64, we map the kernel into the
        // process and treat it as a bundled kernel.
        #[cfg(all(target_arch = "x86_64", not(feature = "tee")))]
        0 => return map_kernel(ctx_id, &path),
        #[cfg(target_arch = "aarch64")]
        0 => KernelFormat::Raw,
        1 => KernelFormat::Elf,
        2 => KernelFormat::PeGz,
        3 => KernelFormat::ImageBz2,
        4 => KernelFormat::ImageGz,
        5 => KernelFormat::ImageZstd,
        _ => {
            return -libc::EINVAL;
        }
    };

    let (initramfs_path, initramfs_size) = if !c_initramfs_path.is_null() {
        match CStr::from_ptr(c_initramfs_path).to_str() {
            Ok(path) => {
                let path = PathBuf::from(path);
                let size = match std::fs::metadata(&path) {
                    Ok(metadata) => metadata.len(),
                    Err(e) => {
                        error!("Can't read initramfs metadata: {:?}", e);
                        return -libc::EINVAL;
                    }
                };
                (Some(path), size)
            }
            Err(e) => {
                error!("Error parsing initramfs path: {:?}", e);
                return -libc::EINVAL;
            }
        }
    } else {
        (None, 0)
    };

    let cmdline = if !c_cmdline.is_null() {
        match CStr::from_ptr(c_cmdline).to_str() {
            Ok(cmdline) => Some(cmdline.to_string()),
            Err(e) => {
                error!("Error parsing kernel cmdline: {:?}", e);
                return -libc::EINVAL;
            }
        }
    } else {
        None
    };

    let external_kernel = ExternalKernel {
        path,
        format,
        initramfs_path,
        initramfs_size,
        cmdline,
    };

    match CTX_MAP.lock().unwrap().entry(ctx_id) {
        Entry::Occupied(mut ctx_cfg) => ctx_cfg.get_mut().vmr.set_external_kernel(external_kernel),
        Entry::Vacant(_) => return -libc::ENOENT,
    }

    KRUN_SUCCESS
}

#[cfg(not(feature = "efi"))]
unsafe fn load_krunfw_payload(
    krunfw: &KrunfwBindings,
    vmr: &mut VmResources,
) -> Result<(), libloading::Error> {
    let mut kernel_guest_addr: u64 = 0;
    let mut kernel_entry_addr: u64 = 0;
    let mut kernel_size: usize = 0;
    let kernel_host_addr = unsafe {
        (krunfw.get_kernel)(
            &mut kernel_guest_addr as *mut u64,
            &mut kernel_entry_addr as *mut u64,
            &mut kernel_size as *mut usize,
        )
    };
    let kernel_bundle = KernelBundle {
        host_addr: kernel_host_addr as u64,
        guest_addr: kernel_guest_addr,
        entry_addr: kernel_entry_addr,
        size: kernel_size,
    };
    vmr.set_kernel_bundle(kernel_bundle).unwrap();

    #[cfg(feature = "tee")]
    {
        let mut qboot_size: usize = 0;
        let qboot_host_addr = unsafe { (krunfw.get_qboot)(&mut qboot_size as *mut usize) };
        let qboot_bundle = QbootBundle {
            host_addr: qboot_host_addr as u64,
            size: qboot_size,
        };
        vmr.set_qboot_bundle(qboot_bundle).unwrap();

        let mut initrd_size: usize = 0;
        let initrd_host_addr = unsafe { (krunfw.get_initrd)(&mut initrd_size as *mut usize) };
        let initrd_bundle = InitrdBundle {
            host_addr: initrd_host_addr as u64,
            size: initrd_size,
        };
        vmr.set_initrd_bundle(initrd_bundle).unwrap();
    }

    Ok(())
}

#[no_mangle]
pub extern "C" fn krun_setuid(ctx_id: u32, uid: libc::uid_t) -> i32 {
    match CTX_MAP.lock().unwrap().entry(ctx_id) {
        Entry::Occupied(mut ctx_cfg) => {
            let cfg = ctx_cfg.get_mut();
            cfg.set_vmm_uid(uid);
        }
        Entry::Vacant(_) => return -libc::ENOENT,
    }

    KRUN_SUCCESS
}

#[no_mangle]
pub extern "C" fn krun_setgid(ctx_id: u32, gid: libc::gid_t) -> i32 {
    match CTX_MAP.lock().unwrap().entry(ctx_id) {
        Entry::Occupied(mut ctx_cfg) => {
            let cfg = ctx_cfg.get_mut();
            cfg.set_vmm_gid(gid);
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
            Ok(val) => CString::new(format!("VM:{val}")).unwrap(),
            Err(_) => CString::new("libkrun VM").unwrap(),
        };
        unsafe { libc::prctl(libc::PR_SET_NAME, prname.as_ptr()) };
    }

    let mut event_manager = match EventManager::new() {
        Ok(em) => em,
        Err(e) => {
            error!("Unable to create EventManager: {:?}", e);
            return -libc::EINVAL;
        }
    };

    let mut ctx_cfg = match CTX_MAP.lock().unwrap().remove(&ctx_id) {
        Some(ctx_cfg) => ctx_cfg,
        None => return -libc::ENOENT,
    };

    #[cfg(not(feature = "efi"))]
    if ctx_cfg.vmr.external_kernel.is_none() && ctx_cfg.vmr.kernel_bundle.is_none() {
        if let Some(ref krunfw) = ctx_cfg.krunfw {
            if let Err(err) = unsafe { load_krunfw_payload(krunfw, &mut ctx_cfg.vmr) } {
                eprintln!("Can't load libkrunfw symbols: {err}");
                return -libc::ENOENT;
            }
        } else {
            eprintln!("Couldn't find or load {}", KRUNFW_NAME);
            return -libc::ENOENT;
        }
    }

    #[cfg(feature = "blk")]
    for block_cfg in ctx_cfg.get_block_cfg() {
        if ctx_cfg.vmr.add_block_device(block_cfg).is_err() {
            error!("Error configuring virtio-blk for block");
            return -libc::EINVAL;
        }
    }

    /*
     * Before krun_start_enter() is called in an encrypted context, the TEE
     * config must have been set via krun_set_tee_config_file(). If the TEE
     * config is not set by this point, print the relevant error message and
     * fail.
     */
    #[cfg(feature = "tee")]
    if let Some(tee_config) = ctx_cfg.get_tee_config_file() {
        if let Err(e) = ctx_cfg.vmr.set_tee_config(tee_config) {
            error!("Error setting up TEE config: {:?}", e);
            return -libc::EINVAL;
        }
    } else {
        error!("Missing TEE config file");
        return -libc::EINVAL;
    }

    let boot_source = BootSourceConfig {
        kernel_cmdline_prolog: Some(format!(
            "{} init={} {} {} {} {}",
            DEFAULT_KERNEL_CMDLINE,
            INIT_PATH,
            ctx_cfg.get_exec_path(),
            ctx_cfg.get_workdir(),
            ctx_cfg.get_rlimits(),
            ctx_cfg.get_env(),
        )),
        kernel_cmdline_epilog: Some(format!(" -- {}", ctx_cfg.get_args())),
    };

    if ctx_cfg.vmr.set_boot_source(boot_source).is_err() {
        return -libc::EINVAL;
    }

    let mut vsock_set = false;
    let mut vsock_config = VsockDeviceConfig {
        vsock_id: "vsock0".to_string(),
        guest_cid: 3,
        host_port_map: None,
        unix_ipc_port_map: None,
    };

    if let Some(ref map) = ctx_cfg.unix_ipc_port_map {
        vsock_config.unix_ipc_port_map = Some(map.clone());
        vsock_set = true;
    }

    match ctx_cfg.net_cfg {
        NetworkConfig::Tsi(tsi_cfg) => {
            vsock_config.host_port_map = tsi_cfg.port_map;
            vsock_set = true;
        }
        NetworkConfig::VirtioNetPasst(_fd) => {
            #[cfg(feature = "net")]
            {
                let backend = VirtioNetBackend::Passt(_fd);
                create_virtio_net(&mut ctx_cfg, backend);
            }
        }
        NetworkConfig::VirtioNetGvproxy(ref _path) => {
            #[cfg(feature = "net")]
            {
                let backend = VirtioNetBackend::Gvproxy(_path.clone());
                create_virtio_net(&mut ctx_cfg, backend);
            }
        }
    }

    if vsock_set {
        ctx_cfg.vmr.set_vsock_device(vsock_config).unwrap();
    }

    if let Some(virgl_flags) = ctx_cfg.gpu_virgl_flags {
        ctx_cfg.vmr.set_gpu_virgl_flags(virgl_flags);
    }
    if let Some(shm_size) = ctx_cfg.gpu_shm_size {
        ctx_cfg.vmr.set_gpu_shm_size(shm_size);
    }

    #[cfg(feature = "snd")]
    ctx_cfg.vmr.set_snd_device(ctx_cfg.enable_snd);

    if let Some(console_output) = ctx_cfg.console_output {
        ctx_cfg.vmr.set_console_output(console_output);
    }

    if let Some(gid) = ctx_cfg.vmm_gid {
        if unsafe { libc::setgid(gid) } != 0 {
            error!("Failed to set gid {}", gid);
            return -std::io::Error::last_os_error().raw_os_error().unwrap();
        }
    }

    if let Some(uid) = ctx_cfg.vmm_uid {
        if unsafe { libc::setuid(uid) } != 0 {
            error!("Failed to set uid {}", uid);
            return -std::io::Error::last_os_error().raw_os_error().unwrap();
        }
    }

    let (sender, _receiver) = unbounded();

    let _vmm = match vmm::builder::build_microvm(
        &ctx_cfg.vmr,
        &mut event_manager,
        ctx_cfg.shutdown_efd,
        sender,
    ) {
        Ok(vmm) => vmm,
        Err(e) => {
            error!("Building the microVM failed: {:?}", e);
            return -libc::EINVAL;
        }
    };

    #[cfg(target_os = "macos")]
    if ctx_cfg.gpu_virgl_flags.is_some() {
        vmm::worker::start_worker_thread(_vmm.clone(), _receiver).unwrap();
    }

    #[cfg(target_arch = "x86_64")]
    if ctx_cfg.vmr.split_irqchip {
        vmm::worker::start_worker_thread(_vmm.clone(), _receiver.clone()).unwrap();
    }

    #[cfg(feature = "amd-sev")]
    vmm::worker::start_worker_thread(_vmm.clone(), _receiver.clone()).unwrap();

    loop {
        match event_manager.run() {
            Ok(_) => {}
            Err(e) => {
                error!("Error in EventManager loop: {:?}", e);
                return -libc::EINVAL;
            }
        }
    }
}
