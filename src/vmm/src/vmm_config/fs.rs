use devices::virtio::fs::virtual_inode::VirtualEntry;

pub struct FsDeviceConfig {
    pub fs_id: String,
    /// Host directory to pass through. None means a virtual-only filesystem
    /// (NullFs + InodeOverlay, no host directory).
    pub shared_dir: Option<String>,
    pub shm_size: Option<usize>,
    pub read_only: bool,
    pub virtual_entries: Vec<VirtualEntry>,
}
