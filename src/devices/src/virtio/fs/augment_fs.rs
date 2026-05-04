// Virtual inode overlay for virtiofs.
//
// `AugmentFs<T>` wraps an inner `FileSystem` implementation and intercepts
// FUSE operations for virtual inodes — synthetic read-only files that exist
// only in memory. All other operations are delegated to the inner filesystem.
//
// Virtual inodes are injected into the root directory (parent = ROOT_ID) and
// are currently only accessible via lookup (they do not appear in readdir).
//
// One-shot files can only be looked up once — the name is removed from the
// directory on first lookup so subsequent lookups return ENOENT.

#[cfg(target_os = "macos")]
use crossbeam_channel::Sender;
use std::collections::HashMap;
use std::ffi::CStr;
use std::ffi::CString;
use std::io;
use std::sync::atomic::AtomicI32;
use std::sync::Arc;
use std::sync::RwLock;
use std::time::Duration;

#[cfg(target_os = "macos")]
use utils::worker_message::WorkerMessage;

use super::filesystem::{
    Context, DirEntry, Entry, Extensions, FileSystem, FsOptions, GetxattrReply, ListxattrReply,
    OpenOptions, SetattrValid, ZeroCopyReader, ZeroCopyWriter,
};
use super::fuse;
use super::inode_alloc::InodeAllocator;
use super::virtual_inode::{VirtualEntry, VirtualFile};
use crate::virtio::bindings;

type Inode = u64;
type Handle = u64;

/// Sentinel handle returned for virtual file opens. The inner filesystem's
/// handle allocator starts at 1 so this never collides.
const VIRTUAL_HANDLE: Handle = 0;

/// Virtual entries never change; use a large cache timeout.
const VIRTUAL_TIMEOUT: Duration = Duration::from_secs(86400);

// Use Linux errno values, not host values. The guest always runs Linux
// and the FUSE server passes error codes through without translation.
const LINUX_ENOENT: i32 = 2;
const LINUX_EACCES: i32 = 13;
const LINUX_EEXIST: i32 = 17;
const LINUX_EXDEV: i32 = 18;
const LINUX_EINVAL: i32 = 22;
const LINUX_EPERM: i32 = 1;
const LINUX_ENOSYS: i32 = 38;
const LINUX_ENODATA: i32 = 61;
const LINUX_ENXIO: i32 = 6;

fn eperm() -> io::Error {
    io::Error::from_raw_os_error(LINUX_EPERM)
}

/// Overlay that injects virtual inodes into an inner `FileSystem`.
pub struct AugmentFs<T> {
    inner: T,
    /// Maps (name in root dir) → virtual inode number. One-shot entries
    /// are removed on first lookup so the file can only be opened once.
    name_to_inode: RwLock<HashMap<CString, Inode>>,
    /// Maps virtual inode number → file data. One-shot entries are removed
    /// from this map on release.
    inodes: RwLock<HashMap<Inode, VirtualFile>>,
}

impl<T: FileSystem<Inode = Inode, Handle = Handle>> AugmentFs<T> {
    /// Create a new overlay.
    ///
    /// `entries` are registered as virtual inodes in the root directory.
    /// Inode numbers are obtained from `inode_alloc`, the same allocator
    /// used by the inner filesystem.
    pub fn new(inner: T, inode_alloc: &InodeAllocator, entries: Vec<VirtualEntry>) -> Self {
        let mut name_to_inode = HashMap::with_capacity(entries.len());
        let mut inodes = HashMap::with_capacity(entries.len());

        for entry in entries {
            let inode = inode_alloc.next();
            name_to_inode.insert(entry.name, inode);
            inodes.insert(inode, entry.file);
        }

        Self {
            inner,
            name_to_inode: RwLock::new(name_to_inode),
            inodes: RwLock::new(inodes),
        }
    }

    fn is_virtual(&self, inode: Inode) -> bool {
        self.inodes.read().unwrap().contains_key(&inode)
    }
}

impl<T: FileSystem<Inode = Inode, Handle = Handle>> FileSystem for AugmentFs<T> {
    type Inode = Inode;
    type Handle = Handle;

    fn init(&self, capable: FsOptions) -> io::Result<FsOptions> {
        self.inner.init(capable)
    }

    fn destroy(&self) {
        self.inner.destroy()
    }

    fn lookup(&self, ctx: Context, parent: Inode, name: &CStr) -> io::Result<Entry> {
        if parent == fuse::ROOT_ID {
            let inode = self.name_to_inode.read().unwrap().get(name).copied();
            if let Some(inode) = inode {
                let inodes = self.inodes.read().unwrap();
                if let Some(file) = inodes.get(&inode) {
                    let one_shot = file.one_shot;
                    let st = file.stat(inode);
                    let entry_timeout = if one_shot {
                        Duration::ZERO
                    } else {
                        VIRTUAL_TIMEOUT
                    };

                    // One-shot: remove name so subsequent lookups fall
                    // through to the inner filesystem (or return ENOENT).
                    if one_shot {
                        // Drop the read lock first, before locking for write
                        drop(inodes);
                        self.name_to_inode.write().unwrap().remove(name);
                    }

                    return Ok(Entry {
                        inode,
                        generation: 0,
                        attr: st,
                        attr_flags: 0,
                        attr_timeout: VIRTUAL_TIMEOUT,
                        entry_timeout,
                    });
                }
            }
        }
        self.inner.lookup(ctx, parent, name)
    }

    fn forget(&self, ctx: Context, inode: Inode, count: u64) {
        if !self.is_virtual(inode) {
            self.inner.forget(ctx, inode, count)
        }
    }

    fn batch_forget(&self, ctx: Context, requests: Vec<(Inode, u64)>) {
        let real: Vec<_> = requests
            .into_iter()
            .filter(|(ino, _)| !self.is_virtual(*ino))
            .collect();
        if !real.is_empty() {
            self.inner.batch_forget(ctx, real);
        }
    }

    fn getattr(
        &self,
        ctx: Context,
        inode: Inode,
        handle: Option<Handle>,
    ) -> io::Result<(bindings::stat64, Duration)> {
        {
            let inodes = self.inodes.read().unwrap();
            if let Some(file) = inodes.get(&inode) {
                let st = file.stat(inode);
                return Ok((st, VIRTUAL_TIMEOUT));
            }
        }
        self.inner.getattr(ctx, inode, handle)
    }

    fn setattr(
        &self,
        ctx: Context,
        inode: Inode,
        attr: bindings::stat64,
        handle: Option<Handle>,
        valid: SetattrValid,
    ) -> io::Result<(bindings::stat64, Duration)> {
        if self.is_virtual(inode) {
            return Err(eperm());
        }
        self.inner.setattr(ctx, inode, attr, handle, valid)
    }

    fn readlink(&self, ctx: Context, inode: Inode) -> io::Result<Vec<u8>> {
        if self.is_virtual(inode) {
            return Err(io::Error::from_raw_os_error(LINUX_EINVAL));
        }
        self.inner.readlink(ctx, inode)
    }

    fn symlink(
        &self,
        ctx: Context,
        linkname: &CStr,
        parent: Inode,
        name: &CStr,
        extensions: Extensions,
    ) -> io::Result<Entry> {
        self.inner.symlink(ctx, linkname, parent, name, extensions)
    }

    fn mknod(
        &self,
        ctx: Context,
        inode: Inode,
        name: &CStr,
        mode: u32,
        rdev: u32,
        umask: u32,
        extensions: Extensions,
    ) -> io::Result<Entry> {
        self.inner
            .mknod(ctx, inode, name, mode, rdev, umask, extensions)
    }

    fn mkdir(
        &self,
        ctx: Context,
        parent: Inode,
        name: &CStr,
        mode: u32,
        umask: u32,
        extensions: Extensions,
    ) -> io::Result<Entry> {
                    .map_err(|_| io::Error::from_raw_os_error(LINUX_EINVAL))?;
                if off >= data.len() {                    return Ok(0);
                }
                let remaining = file.data.len() - off;
                let len = remaining.min(size as usize);
                return w.write(&file.data[off..(off + len)]);
            }
        }
        self.inner
            .read(ctx, inode, handle, w, size, offset, lock_owner, flags)
    }

    fn write<R: io::Read + ZeroCopyReader>(
        &self,
        ctx: Context,
        inode: Inode,
        handle: Handle,
        r: R,
        size: u32,
        offset: u64,
        lock_owner: Option<u64>,
        delayed_write: bool,
        kill_priv: bool,
        flags: u32,
    ) -> io::Result<usize> {
        if self.is_virtual(inode) {
            return Err(eperm());
        }
        self.inner.write(
            ctx,
            inode,
            handle,
            r,
            size,
            offset,
            lock_owner,
            delayed_write,
            kill_priv,
            flags,
        )
    }

    fn flush(&self, ctx: Context, inode: Inode, handle: Handle, lock_owner: u64) -> io::Result<()> {
        if self.is_virtual(inode) {
            return Ok(());
        }
        self.inner.flush(ctx, inode, handle, lock_owner)
    }

    fn fsync(&self, ctx: Context, inode: Inode, datasync: bool, handle: Handle) -> io::Result<()> {
        if self.is_virtual(inode) {
            return Ok(());
        }
        self.inner.fsync(ctx, inode, datasync, handle)
    }

    fn fallocate(
        &self,
        ctx: Context,
        inode: Inode,
        handle: Handle,
        mode: u32,
        offset: u64,
        length: u64,
    ) -> io::Result<()> {
        if self.is_virtual(inode) {
            return Err(eperm());
        }
        self.inner
            .fallocate(ctx, inode, handle, mode, offset, length)
    }

    fn release(
        &self,
        ctx: Context,
        inode: Inode,
        flags: u32,
        handle: Handle,
        flush: bool,
        flock_release: bool,
        lock_owner: Option<u64>,
    ) -> io::Result<()> {
        {
            let mut inodes = self.inodes.write().unwrap();
            if let Some(file) = inodes.get(&inode) {
                if file.one_shot {
                    inodes.remove(&inode);
                }
                return Ok(());
            }
        }
        self.inner
            .release(ctx, inode, flags, handle, flush, flock_release, lock_owner)
    }

    fn statfs(&self, ctx: Context, inode: Inode) -> io::Result<bindings::statvfs64> {
        self.inner.statfs(ctx, inode)
    }

    fn getxattr(
        &self,
        ctx: Context,
        inode: Inode,
        name: &CStr,
        size: u32,
    ) -> io::Result<GetxattrReply> {
        if self.is_virtual(inode) {
            return Err(io::Error::from_raw_os_error(LINUX_ENODATA));
        }
        self.inner.getxattr(ctx, inode, name, size)
    }

    fn listxattr(&self, ctx: Context, inode: Inode, size: u32) -> io::Result<ListxattrReply> {
        if self.is_virtual(inode) {
            if size == 0 {
                return Ok(ListxattrReply::Count(0));
            }
            return Ok(ListxattrReply::Names(Vec::new()));
        }
        self.inner.listxattr(ctx, inode, size)
    }

    fn setxattr(
        &self,
        ctx: Context,
        inode: Inode,
        name: &CStr,
        value: &[u8],
        flags: u32,
    ) -> io::Result<()> {
        if self.is_virtual(inode) {
            return Err(eperm());
        }
        self.inner.setxattr(ctx, inode, name, value, flags)
    }

    fn removexattr(&self, ctx: Context, inode: Inode, name: &CStr) -> io::Result<()> {
        if self.is_virtual(inode) {
            return Err(eperm());
        }
        self.inner.removexattr(ctx, inode, name)
    }

    fn opendir(
        &self,
        ctx: Context,
        inode: Inode,
        flags: u32,
    ) -> io::Result<(Option<Handle>, OpenOptions)> {
        self.inner.opendir(ctx, inode, flags)
    }

    fn readdir<F>(
        &self,
        ctx: Context,
        inode: Inode,
        handle: Handle,
        size: u32,
        offset: u64,
        add_entry: F,
    ) -> io::Result<()>
    where
        F: FnMut(DirEntry) -> io::Result<usize>,
    {
        self.inner
            .readdir(ctx, inode, handle, size, offset, add_entry)
    }

    fn readdirplus<F>(
        &self,
        ctx: Context,
        inode: Inode,
        handle: Handle,
        size: u32,
        offset: u64,
        add_entry: F,
    ) -> io::Result<()>
    where
        F: FnMut(DirEntry, Entry) -> io::Result<usize>,
    {
        self.inner
            .readdirplus(ctx, inode, handle, size, offset, add_entry)
    }

    fn fsyncdir(
        &self,
        ctx: Context,
        inode: Inode,
        datasync: bool,
        handle: Handle,
    ) -> io::Result<()> {
        self.inner.fsyncdir(ctx, inode, datasync, handle)
    }

    fn releasedir(&self, ctx: Context, inode: Inode, flags: u32, handle: Handle) -> io::Result<()> {
        self.inner.releasedir(ctx, inode, flags, handle)
    }

    fn access(&self, ctx: Context, inode: Inode, mask: u32) -> io::Result<()> {
        if self.is_virtual(inode) {
            if mask & (libc::W_OK as u32) != 0 {
                return Err(io::Error::from_raw_os_error(LINUX_EACCES));
            }
            return Ok(());
        }
        self.inner.access(ctx, inode, mask)
    }

    fn lseek(
        &self,
        ctx: Context,
        inode: Inode,
        _handle: Handle,
        offset: u64,
        whence: u32,
    ) -> io::Result<u64> {
        {
            let inodes = self.inodes.read().unwrap();
            if let Some(file) = inodes.get(&inode) {
                let size = file.data.len() as u64;
                // FUSE lseek is only called for SEEK_DATA/SEEK_HOLE.
                return match whence as i32 {
                    libc::SEEK_DATA => {
                        if offset < size {
                            Ok(offset)
                        } else {
                            Err(io::Error::from_raw_os_error(LINUX_ENXIO))
                        }
                    }
                    libc::SEEK_HOLE => {
                        if offset < size {
                            Ok(size)
                        } else {
                            Err(io::Error::from_raw_os_error(LINUX_ENXIO))
                        }
                    }
                    _ => Err(io::Error::from_raw_os_error(LINUX_EINVAL)),
                };
            }
        }
        self.inner.lseek(ctx, inode, _handle, offset, whence)
    }

    fn copyfilerange(
        &self,
        ctx: Context,
        inode_in: Inode,
        handle_in: Handle,
        offset_in: u64,
        inode_out: Inode,
        handle_out: Handle,
        offset_out: u64,
        len: u64,
        flags: u64,
    ) -> io::Result<usize> {
        // Virtual inodes don't have real file descriptors, so copy_file_range
        // cannot work. Return EXDEV to tell the kernel to fall back to
        // read+write.
        if self.is_virtual(inode_in) || self.is_virtual(inode_out) {
            return Err(io::Error::from_raw_os_error(LINUX_EXDEV));
        }
        self.inner.copyfilerange(
            ctx, inode_in, handle_in, offset_in, inode_out, handle_out, offset_out, len, flags,
        )
    }

    fn setupmapping(
        &self,
        ctx: Context,
        inode: Inode,
        handle: Handle,
        foffset: u64,
        len: u64,
        flags: u64,
        moffset: u64,
        host_shm_base: u64,
        shm_size: u64,
        #[cfg(target_os = "macos")] map_sender: &Option<Sender<WorkerMessage>>,
    ) -> io::Result<()> {
        {
            let inodes = self.inodes.read().unwrap();
            if let Some(file) = inodes.get(&inode) {
                #[cfg(target_os = "linux")]
                {
                    if (moffset + len) > shm_size {
                        return Err(io::Error::from_raw_os_error(LINUX_EINVAL));
                    }

                    let addr = host_shm_base + moffset;
                    let ret = unsafe {
                        libc::mmap(
                            addr as *mut libc::c_void,
                            len as usize,
                            libc::PROT_READ | libc::PROT_WRITE,
                            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED,
                            -1,
                            0,
                        )
                    };
                    if std::ptr::eq(ret, libc::MAP_FAILED) {
                        return Err(io::Error::last_os_error());
                    }

                    let foff = foffset as usize;
                    if foff < file.data.len() {
                        let available = file.data.len() - foff;
                        let to_copy = (len as usize).min(available);
                        unsafe {
                            libc::memcpy(
                                addr as *mut libc::c_void,
                                file.data.as_ptr().add(foff) as *const _,
                                to_copy,
                            )
                        };
                    }

                    return Ok(());
                }

                // TODO: implement DAX for virtual files on macOS using
                // the ShmRegionManager once it exists (see dax-window-layering task).
                #[cfg(target_os = "macos")]
                {
                    let _ = data;
                    return Err(io::Error::from_raw_os_error(LINUX_ENOSYS));                }
            }
        }
        self.inner.setupmapping(
            ctx,
            inode,
            handle,
            foffset,
            len,
            flags,
            moffset,
            host_shm_base,
            shm_size,
            #[cfg(target_os = "macos")]
            map_sender,
        )
    }

    fn removemapping(
        &self,
        ctx: Context,
        requests: Vec<fuse::RemovemappingOne>,
        host_shm_base: u64,
        shm_size: u64,
        #[cfg(target_os = "macos")] map_sender: &Option<Sender<WorkerMessage>>,
    ) -> io::Result<()> {
        self.inner.removemapping(
            ctx,
            requests,
            host_shm_base,
            shm_size,
            #[cfg(target_os = "macos")]
            map_sender,
        )
    }

    fn ioctl(
        &self,
        ctx: Context,
        inode: Inode,
        handle: Handle,
        flags: u32,
        cmd: u32,
        arg: u64,
        in_size: u32,
        out_size: u32,
        exit_code: &Arc<AtomicI32>,
    ) -> io::Result<Vec<u8>> {
        // Always delegate: the exit-code and root-dir-removal ioctls are
        // dispatched by command number, not by inode.
        self.inner.ioctl(
            ctx, inode, handle, flags, cmd, arg, in_size, out_size, exit_code,
        )
    }
}
