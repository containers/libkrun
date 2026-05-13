// Virtual inode types for the virtiofs overlay.
//
// A `VirtualInode` represents a synthetic inode injected into the guest
// filesystem without any corresponding host file or directory.

use std::ffi::CString;
use std::mem;

use crate::virtio::bindings;

/// A synthetic inode that exists only in memory.
pub enum VirtualInode {
    /// A read-only file backed by a static byte slice.
    File {
        data: &'static [u8],
        /// If true, the file can only be looked up once.
        one_shot: bool,
    },
    /// A directory containing other virtual entries.
    Dir { children: Vec<VirtualEntry> },
}

impl VirtualInode {
    pub fn is_dir(&self) -> bool {
        matches!(self, Self::Dir { .. })
    }

    pub fn is_one_shot(&self) -> bool {
        matches!(self, Self::File { one_shot: true, .. })
    }

    pub fn data(&self) -> &'static [u8] {
        match self {
            Self::File { data, .. } => data,
            Self::Dir { .. } => &[],
        }
    }

    /// Synthesize a stat result for this virtual inode.
    pub fn stat(&self, inode: u64, mode: u32) -> bindings::stat64 {
        let mut st: bindings::stat64 = unsafe { mem::zeroed() };
        st.st_ino = inode;
        st.st_mode = mode as _;
        st.st_blksize = 4096;
        match self {
            Self::File { data, .. } => {
                st.st_size = data.len() as i64;
                st.st_nlink = 1;
                st.st_blocks = ((data.len() as i64) + 511) / 512;
            }
            Self::Dir { .. } => {
                st.st_nlink = 2;
            }
        }
        st
    }
}

/// An entry to register as a virtual inode.
pub struct VirtualEntry {
    pub name: CString,
    pub mode: u32,
    pub inode: VirtualInode,
}
