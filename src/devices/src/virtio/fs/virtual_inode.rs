// Virtual inode types for the virtiofs overlay.
//
// A `VirtualFile` represents a read-only file backed by static data that is
// injected into the guest filesystem without any corresponding host file.

use std::ffi::CString;
use std::mem;

use crate::virtio::bindings;

/// A read-only virtual file backed by a static byte slice.
pub struct VirtualFile {
    pub data: &'static [u8],
    pub mode: u32,
    /// If true, the file can only be looked up once.
    pub one_shot: bool,
}

impl VirtualFile {
    /// Synthesize a stat result for this virtual file.
    pub fn stat(&self, inode: u64) -> bindings::stat64 {
        let mut st: bindings::stat64 = unsafe { mem::zeroed() };
        st.st_ino = inode;
        st.st_size = self.data.len() as i64;
        st.st_mode = self.mode as _;
        st.st_nlink = 1;
        st.st_blksize = 4096;
        st.st_blocks = ((self.data.len() as i64) + 511) / 512;
        st
    }
}

/// An entry to register as a virtual inode in the root directory.
pub struct VirtualEntry {
    pub name: CString,
    pub file: VirtualFile,
}
