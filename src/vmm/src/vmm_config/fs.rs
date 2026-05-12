use devices::virtio::fs::virtual_entry::VirtualDirEntry;

#[derive(Clone, Debug)]
pub struct FsDeviceConfig {
    pub fs_id: String,
    pub shared_dir: String,
    pub shm_size: Option<usize>,
    pub allow_root_dir_delete: bool,
    pub read_only: bool,
    pub virtual_entries: Vec<VirtualDirEntry>,
}
