// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::collections::btree_map;
use std::collections::{BTreeMap, HashMap};
use std::ffi::{CStr, CString};
use std::fs::File;
use std::io;
use std::mem::{self, MaybeUninit};
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use lru::LruCache;
use vm_memory::ByteValued;

use super::super::super::linux_errno::{linux_error, LINUX_ERANGE};
use super::super::bindings;
use super::super::filesystem::{
    Context, DirEntry, Entry, FileSystem, FsOptions, GetxattrReply, ListxattrReply, OpenOptions,
    SetattrValid, ZeroCopyReader, ZeroCopyWriter,
};
use super::super::fuse;
use super::super::multikey::MultikeyBTreeMap;

const INIT_CSTR: &[u8] = b"init.krun\0";
const XATTR_KEY: &[u8] = b"user.containers.override_stat\0";

const UID_MAX: u32 = u32::MAX - 1;

static INIT_BINARY: &[u8] = include_bytes!("../../../../../../init/init");

type Inode = u64;
type Handle = u64;

#[derive(Clone, Copy, PartialOrd, Ord, PartialEq, Eq)]
struct InodeAltKey {
    ino: bindings::ino64_t,
    dev: libc::dev_t,
}

struct InodeData {
    inode: Inode,
    linkdata: CString,
    refcount: AtomicU64,
}

struct DirStream {
    stream: u64,
    offset: i64,
}

struct HandleData {
    inode: Inode,
    file: RwLock<File>,
    dirstream: Mutex<DirStream>,
}

#[repr(C, packed)]
#[derive(Clone, Copy, Debug, Default)]
struct LinuxDirent64 {
    d_ino: bindings::ino64_t,
    d_off: bindings::off64_t,
    d_reclen: libc::c_ushort,
    d_ty: libc::c_uchar,
}
unsafe impl ByteValued for LinuxDirent64 {}

fn ebadf() -> io::Error {
    io::Error::from_raw_os_error(libc::EBADF)
}

fn get_filepath(fd: RawFd) -> io::Result<String> {
    let mut filepath: Vec<u8> = vec![0; libc::PATH_MAX as usize];
    let res = unsafe {
        libc::fcntl(
            fd,
            libc::F_GETPATH,
            filepath.as_mut_ptr() as *mut libc::c_void,
        )
    };
    if res < 0 {
        return Err(linux_error(io::Error::last_os_error()));
    }

    let fpsize = filepath.iter().position(|&x| x == 0);
    filepath.resize(fpsize.unwrap(), 0);

    Ok(std::str::from_utf8(&filepath).unwrap().to_string())
}

fn get_path(path_cache: &mut BTreeMap<Inode, Vec<String>>, inode: Inode) -> io::Result<String> {
    match path_cache.get_mut(&inode) {
        None => Err(linux_error(io::Error::from_raw_os_error(libc::EBADF))),
        Some(path_list) => {
            let mut st = MaybeUninit::<bindings::stat64>::zeroed();
            if path_list.is_empty() {
                return Err(linux_error(io::Error::from_raw_os_error(libc::ENOENT)));
            }
            loop {
                let cpath = CString::new(path_list[0].clone()).unwrap();
                let res = unsafe { libc::lstat(cpath.as_ptr(), st.as_mut_ptr()) };
                if res >= 0 {
                    return Ok(path_list[0].clone());
                } else if path_list.len() > 1 {
                    path_list.remove(0);
                } else {
                    return Err(linux_error(io::Error::from_raw_os_error(libc::ENOENT)));
                }
            }
        }
    }
}

fn open_path(
    file_cache: &mut LruCache<Inode, Arc<File>>,
    inode: Inode,
    filepath: &str,
) -> io::Result<Arc<File>> {
    let c_filepath = CString::new(filepath).unwrap();
    let fd = unsafe { libc::open(c_filepath.as_ptr(), libc::O_SYMLINK | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(linux_error(io::Error::last_os_error()));
    }
    let file = Arc::new(unsafe { File::from_raw_fd(fd) });
    file_cache.put(inode, file.clone());
    Ok(file)
}

fn add_path(path_cache: &mut BTreeMap<Inode, Vec<String>>, inode: Inode, filepath: String) {
    debug!("add_path: inode={} filepath={}", inode, filepath);

    let path_list = path_cache.entry(inode).or_insert_with(Vec::new);
    if !path_list.contains(&filepath) {
        path_list.push(filepath);
    }
}

fn remove_path(path_cache: &mut BTreeMap<Inode, Vec<String>>, inode: Inode, filepath: String) {
    debug!("remove_path: inode={} filepath={}", inode, filepath);

    if let Some(path_list) = path_cache.get_mut(&inode) {
        if let Some(pos) = path_list.iter().position(|p| *p == filepath) {
            path_list.remove(pos);
        }
    }
}

fn path_cache_rename_dir(
    path_cache: &mut BTreeMap<Inode, Vec<String>>,
    olddir: Inode,
    oldname: &str,
    newdir: Inode,
    newname: &str,
) {
    let oldpath = format!("{}/{}", get_path(path_cache, olddir).unwrap(), oldname);
    let oldparts: Vec<&str> = oldpath.split('/').collect();
    let newpath = format!("{}/{}", get_path(path_cache, newdir).unwrap(), newname);

    for (_, path_list) in path_cache.iter_mut() {
        let mut path_replacements = Vec::new();
        for (index, path) in path_list.iter().enumerate() {
            if path.starts_with(&oldpath) {
                let parts: Vec<&str> = path.split('/').collect();
                if parts.len() > oldparts.len() {
                    let mut fixedpath = String::new();
                    fixedpath.push_str(&newpath);
                    fixedpath.push_str("/");
                    fixedpath.push_str(&parts[oldparts.len()..].join("/"));
                    path_replacements.push((index, fixedpath));
                }
            }
        }
        for (n, r) in path_replacements {
            path_list[n] = r;
        }
    }
}

#[derive(Clone)]
enum StatFile {
    Path(String),
    Fd(RawFd),
}

fn item_to_value(item: &[u8], radix: u32) -> Option<u32> {
    match std::str::from_utf8(item) {
        Ok(val) => match u32::from_str_radix(val, radix) {
            Ok(i) => Some(i),
            Err(e) => {
                debug!("invalid value: {} err={}", radix, e);
                None
            }
        },
        Err(_) => None,
    }
}

fn get_xattr_stat(file: StatFile) -> Option<(u32, u32, u32)> {
    let mut buf: Vec<u8> = vec![0; 32];
    let res = match file {
        StatFile::Path(path) => {
            let cpath = CString::new(path).unwrap();
            unsafe {
                libc::getxattr(
                    cpath.as_ptr(),
                    XATTR_KEY.as_ptr() as *const i8,
                    buf.as_mut_ptr() as *mut libc::c_void,
                    32,
                    0,
                    0,
                )
            }
        }
        StatFile::Fd(fd) => unsafe {
            libc::fgetxattr(
                fd,
                XATTR_KEY.as_ptr() as *const i8,
                buf.as_mut_ptr() as *mut libc::c_void,
                64,
                0,
                0,
            )
        },
    };
    if res < 0 {
        debug!("fget_xattr error: {}", res);
        return None;
    }

    buf.resize(res as usize, 0);

    let mut items = buf.split(|c| *c == b':');

    let uid = match items.next() {
        Some(item) => match item_to_value(item, 10) {
            Some(item) => item,
            None => return None,
        },
        None => return None,
    };
    let gid = match items.next() {
        Some(item) => match item_to_value(item, 10) {
            Some(item) => item,
            None => return None,
        },
        None => return None,
    };
    let mode = match items.next() {
        Some(item) => match item_to_value(item, 8) {
            Some(item) => item,
            None => return None,
        },
        None => return None,
    };

    Some((uid, gid, mode))
}

fn is_valid_owner(owner: Option<(u32, u32)>) -> bool {
    if let Some(owner) = owner {
        if owner.0 < UID_MAX && owner.1 < UID_MAX {
            return true;
        }
    }

    false
}

// We won't need this once expressions like "if let ... &&" are allowed.
#[allow(clippy::unnecessary_unwrap)]
fn set_xattr_stat(file: StatFile, owner: Option<(u32, u32)>, mode: Option<u32>) -> i32 {
    let (new_owner, new_mode) = if is_valid_owner(owner) && mode.is_some() {
        (owner.unwrap(), mode.unwrap())
    } else {
        let (orig_owner, orig_mode) =
            if let Some((xuid, xgid, xmode)) = get_xattr_stat(file.clone()) {
                ((xuid, xgid), xmode)
            } else {
                ((0, 0), 0o0777)
            };

        let new_owner = match owner {
            Some(o) => {
                let uid = if o.0 < UID_MAX { o.0 } else { orig_owner.0 };
                let gid = if o.1 < UID_MAX { o.1 } else { orig_owner.1 };
                (uid, gid)
            }
            None => orig_owner,
        };

        (new_owner, mode.unwrap_or(orig_mode))
    };

    let buf = format!("{}:{}:0{:o}", new_owner.0, new_owner.1, new_mode);

    match file {
        StatFile::Path(path) => {
            let cpath = CString::new(path).unwrap();
            let options = if (new_mode as u16 & libc::S_IFMT) == libc::S_IFLNK {
                libc::XATTR_NOFOLLOW
            } else {
                0
            };
            unsafe {
                libc::setxattr(
                    cpath.as_ptr(),
                    XATTR_KEY.as_ptr() as *const i8,
                    buf.as_ptr() as *mut libc::c_void,
                    buf.len() as libc::size_t,
                    0,
                    options,
                )
            }
        }
        StatFile::Fd(fd) => unsafe {
            libc::fsetxattr(
                fd,
                XATTR_KEY.as_ptr() as *const i8,
                buf.as_ptr() as *mut libc::c_void,
                buf.len() as libc::size_t,
                0,
                0,
            )
        },
    }
}

fn fstat(f: &File) -> io::Result<bindings::stat64> {
    let mut st = MaybeUninit::<bindings::stat64>::zeroed();

    // Safe because the kernel will only write data in `st` and we check the return
    // value.
    let res = unsafe { libc::fstat(f.as_raw_fd(), st.as_mut_ptr()) };
    if res >= 0 {
        // Safe because the kernel guarantees that the struct is now fully initialized.
        let mut st = unsafe { st.assume_init() };

        if let Some((uid, gid, mode)) = get_xattr_stat(StatFile::Fd(f.as_raw_fd())) {
            st.st_uid = uid;
            st.st_gid = gid;
            if mode as u16 & libc::S_IFMT == 0 {
                st.st_mode = (st.st_mode & libc::S_IFMT) | mode as u16;
            } else {
                st.st_mode = mode as u16;
            }
        }

        Ok(st)
    } else {
        Err(linux_error(io::Error::last_os_error()))
    }
}

/// The caching policy that the file system should report to the FUSE client. By default the FUSE
/// protocol uses close-to-open consistency. This means that any cached contents of the file are
/// invalidated the next time that file is opened.
#[derive(Debug, Clone)]
pub enum CachePolicy {
    /// The client should never cache file data and all I/O should be directly forwarded to the
    /// server. This policy must be selected when file contents may change without the knowledge of
    /// the FUSE client (i.e., the file system does not have exclusive access to the directory).
    Never,

    /// The client is free to choose when and how to cache file data. This is the default policy and
    /// uses close-to-open consistency as described in the enum documentation.
    Auto,

    /// The client should always cache file data. This means that the FUSE client will not
    /// invalidate any cached data that was returned by the file system the last time the file was
    /// opened. This policy should only be selected when the file system has exclusive access to the
    /// directory.
    Always,
}

impl FromStr for CachePolicy {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "never" | "Never" | "NEVER" => Ok(CachePolicy::Never),
            "auto" | "Auto" | "AUTO" => Ok(CachePolicy::Auto),
            "always" | "Always" | "ALWAYS" => Ok(CachePolicy::Always),
            _ => Err("invalid cache policy"),
        }
    }
}

impl Default for CachePolicy {
    fn default() -> Self {
        CachePolicy::Auto
    }
}

/// Options that configure the behavior of the file system.
#[derive(Debug, Clone)]
pub struct Config {
    /// How long the FUSE client should consider directory entries to be valid. If the contents of a
    /// directory can only be modified by the FUSE client (i.e., the file system has exclusive
    /// access), then this should be a large value.
    ///
    /// The default value for this option is 5 seconds.
    pub entry_timeout: Duration,

    /// How long the FUSE client should consider file and directory attributes to be valid. If the
    /// attributes of a file or directory can only be modified by the FUSE client (i.e., the file
    /// system has exclusive access), then this should be set to a large value.
    ///
    /// The default value for this option is 5 seconds.
    pub attr_timeout: Duration,

    /// The caching policy the file system should use. See the documentation of `CachePolicy` for
    /// more details.
    pub cache_policy: CachePolicy,

    /// Whether the file system should enabled writeback caching. This can improve performance as it
    /// allows the FUSE client to cache and coalesce multiple writes before sending them to the file
    /// system. However, enabling this option can increase the risk of data corruption if the file
    /// contents can change without the knowledge of the FUSE client (i.e., the server does **NOT**
    /// have exclusive access). Additionally, the file system should have read access to all files
    /// in the directory it is serving as the FUSE client may send read requests even for files
    /// opened with `O_WRONLY`.
    ///
    /// Therefore callers should only enable this option when they can guarantee that: 1) the file
    /// system has exclusive access to the directory and 2) the file system has read permissions for
    /// all files in that directory.
    ///
    /// The default value for this option is `false`.
    pub writeback: bool,

    /// The path of the root directory.
    ///
    /// The default is `/`.
    pub root_dir: String,

    /// Whether the file system should support Extended Attributes (xattr). Enabling this feature may
    /// have a significant impact on performance, especially on write parallelism. This is the result
    /// of FUSE attempting to remove the special file privileges after each write request.
    ///
    /// The default value for this options is `false`.
    pub xattr: bool,

    /// Optional file descriptor for /proc/self/fd. Callers can obtain a file descriptor and pass it
    /// here, so there's no need to open it in PassthroughFs::new(). This is specially useful for
    /// sandboxing.
    ///
    /// The default is `None`.
    pub proc_sfd_rawfd: Option<RawFd>,

    /// Optional list of tuples of (host_path, guest_path) elements, representing paths from the host
    /// to be exposed in the guest.
    ///
    /// The default in `None`.
    pub mapped_volumes: Option<Vec<(PathBuf, PathBuf)>>,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            entry_timeout: Duration::from_secs(5),
            attr_timeout: Duration::from_secs(5),
            cache_policy: Default::default(),
            writeback: false,
            root_dir: String::from("/"),
            xattr: false,
            proc_sfd_rawfd: None,
            mapped_volumes: None,
        }
    }
}

/// A file system that simply "passes through" all requests it receives to the underlying file
/// system. To keep the implementation simple it servers the contents of its root directory. Users
/// that wish to serve only a specific directory should set up the environment so that that
/// directory ends up as the root of the file system process. One way to accomplish this is via a
/// combination of mount namespaces and the pivot_root system call.
pub struct PassthroughFs {
    inodes: RwLock<MultikeyBTreeMap<Inode, InodeAltKey, Arc<InodeData>>>,
    next_inode: AtomicU64,
    init_inode: u64,
    path_cache: Mutex<BTreeMap<Inode, Vec<String>>>,
    file_cache: Mutex<LruCache<Inode, Arc<File>>>,
    pinned_files: Mutex<BTreeMap<Inode, Arc<File>>>,

    handles: RwLock<BTreeMap<Handle, Arc<HandleData>>>,
    next_handle: AtomicU64,
    init_handle: u64,

    host_volumes: RwLock<HashMap<String, Inode>>,

    // Whether writeback caching is enabled for this directory. This will only be true when
    // `cfg.writeback` is true and `init` was called with `FsOptions::WRITEBACK_CACHE`.
    writeback: AtomicBool,

    cfg: Config,
}

impl PassthroughFs {
    pub fn new(cfg: Config) -> io::Result<PassthroughFs> {
        Ok(PassthroughFs {
            inodes: RwLock::new(MultikeyBTreeMap::new()),
            next_inode: AtomicU64::new(fuse::ROOT_ID + 2),
            init_inode: fuse::ROOT_ID + 1,
            path_cache: Mutex::new(BTreeMap::new()),
            file_cache: Mutex::new(LruCache::new(256)),
            pinned_files: Mutex::new(BTreeMap::new()),

            handles: RwLock::new(BTreeMap::new()),
            next_handle: AtomicU64::new(1),
            init_handle: 0,

            host_volumes: RwLock::new(HashMap::new()),
            writeback: AtomicBool::new(false),
            cfg,
        })
    }

    fn cached_or_pinned(
        &self,
        inode: &Inode,
        file_cache: &mut LruCache<Inode, Arc<File>>,
    ) -> Option<Arc<File>> {
        if let Some(file) = file_cache.get(inode) {
            Some(file.clone())
        } else {
            self.pinned_files
                .lock()
                .unwrap()
                .get(&inode)
                .map(Arc::clone)
        }
    }

    fn get_file(&self, inode: Inode) -> io::Result<Arc<File>> {
        let mut file_cache = self.file_cache.lock().unwrap();
        if let Some(file) = self.cached_or_pinned(&inode, &mut file_cache) {
            Ok(file.clone())
        } else {
            open_path(
                &mut file_cache,
                inode,
                &get_path(&mut self.path_cache.lock().unwrap(), inode)?,
            )
        }
    }

    fn open_inode(&self, inode: Inode, mut flags: i32) -> io::Result<File> {
        // When writeback caching is enabled, the kernel may send read requests even if the
        // userspace program opened the file write-only. So we need to ensure that we have opened
        // the file for reading as well as writing.
        let writeback = self.writeback.load(Ordering::Relaxed);
        if writeback && flags & libc::O_ACCMODE == libc::O_WRONLY {
            flags &= !libc::O_ACCMODE;
            flags |= libc::O_RDWR;
        }

        // When writeback caching is enabled the kernel is responsible for handling `O_APPEND`.
        // However, this breaks atomicity as the file may have changed on disk, invalidating the
        // cached copy of the data in the kernel and the offset that the kernel thinks is the end of
        // the file. Just allow this for now as it is the user's responsibility to enable writeback
        // caching only for directories that are not shared. It also means that we need to clear the
        // `O_APPEND` flag.
        if writeback && flags & libc::O_APPEND != 0 {
            flags &= !libc::O_APPEND;
        }

        let filepath = match get_path(&mut self.path_cache.lock().unwrap(), inode) {
            Ok(fp) => CString::new(fp).unwrap(),
            Err(_) => CString::new(get_filepath(self.get_file(inode)?.as_raw_fd())?).unwrap(),
        };
        let fd = unsafe {
            libc::open(
                filepath.as_ptr(),
                (flags | libc::O_CLOEXEC) & (!libc::O_NOFOLLOW) & (!libc::O_EXLOCK),
            )
        };
        if fd < 0 {
            return Err(linux_error(io::Error::last_os_error()));
        }

        // Safe because we just opened this fd.
        Ok(unsafe { File::from_raw_fd(fd) })
    }

    fn lookup_host_volume(&self, name: &CStr) -> io::Result<Entry> {
        if let Some(inode) = self
            .host_volumes
            .read()
            .unwrap()
            .get(&name.to_str().unwrap().to_string())
        {
            if let Some(data) = self.inodes.read().unwrap().get(inode) {
                let file = self.get_file(data.inode)?;
                let st = fstat(&file)?;
                data.refcount.fetch_add(1, Ordering::Acquire);
                return Ok(Entry {
                    inode: data.inode,
                    generation: 0,
                    attr: st,
                    attr_timeout: self.cfg.attr_timeout,
                    entry_timeout: self.cfg.entry_timeout,
                });
            }
        }

        Err(linux_error(io::Error::from_raw_os_error(libc::ENOENT)))
    }

    fn do_lookup(&self, parent: Inode, name: &CStr) -> io::Result<Entry> {
        if parent == fuse::ROOT_ID {
            if let Ok(entry) = self.lookup_host_volume(name) {
                return Ok(entry);
            }
        }

        let file = self.get_file(parent)?;

        // Safe because this doesn't modify any memory and we check the return value.
        let fd = unsafe {
            libc::openat(
                file.as_raw_fd(),
                name.as_ptr(),
                libc::O_SYMLINK | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(linux_error(io::Error::last_os_error()));
        }

        // Safe because we just opened this fd.
        let f = unsafe { File::from_raw_fd(fd) };

        let st = fstat(&f)?;

        let linkdata = if (st.st_mode & libc::S_IFMT) == libc::S_IFLNK {
            let mut buf = vec![0; libc::PATH_MAX as usize];

            let res = unsafe {
                libc::readlinkat(
                    file.as_raw_fd(),
                    name.as_ptr(),
                    buf.as_mut_ptr() as *mut libc::c_char,
                    buf.len(),
                )
            };
            if res < 0 {
                return Err(linux_error(io::Error::last_os_error()));
            }

            buf.resize(res as usize, 0);

            CString::new(buf).unwrap()
        } else {
            CString::new("").unwrap()
        };

        let altkey = InodeAltKey {
            ino: st.st_ino,
            dev: st.st_dev,
        };
        let data = self.inodes.read().unwrap().get_alt(&altkey).map(Arc::clone);

        let inode = if let Some(data) = data {
            // Matches with the release store in `forget`.
            data.refcount.fetch_add(1, Ordering::Acquire);
            data.inode
        } else {
            // There is a possible race here where 2 threads end up adding the same file
            // into the inode list.  However, since each of those will get a unique Inode
            // value and unique file descriptors this shouldn't be that much of a problem.
            let inode = self.next_inode.fetch_add(1, Ordering::Relaxed);
            self.inodes.write().unwrap().insert(
                inode,
                InodeAltKey {
                    ino: st.st_ino,
                    dev: st.st_dev,
                },
                Arc::new(InodeData {
                    inode,
                    linkdata,
                    refcount: AtomicU64::new(1),
                }),
            );

            self.file_cache.lock().unwrap().put(inode, Arc::new(f));
            inode
        };

        debug!(
            "do_lookup result: path={:?} inode={}",
            get_filepath(fd)?,
            inode
        );

        add_path(
            &mut self.path_cache.lock().unwrap(),
            inode,
            get_filepath(fd)?,
        );

        Ok(Entry {
            inode,
            generation: 0,
            attr: st,
            attr_timeout: self.cfg.attr_timeout,
            entry_timeout: self.cfg.entry_timeout,
        })
    }

    fn do_readdir<F>(
        &self,
        inode: Inode,
        handle: Handle,
        size: u32,
        offset: u64,
        mut add_entry: F,
    ) -> io::Result<()>
    where
        F: FnMut(DirEntry) -> io::Result<usize>,
    {
        if size == 0 {
            return Ok(());
        }

        let data = self
            .handles
            .read()
            .unwrap()
            .get(&handle)
            .filter(|hd| hd.inode == inode)
            .map(Arc::clone)
            .ok_or_else(ebadf)?;

        let mut ds = data.dirstream.lock().unwrap();

        let dir_stream = if ds.stream == 0 {
            let dir = unsafe { libc::fdopendir(data.file.write().unwrap().as_raw_fd()) };
            if dir.is_null() {
                return Err(linux_error(io::Error::last_os_error()));
            }
            ds.stream = dir as u64;
            dir
        } else {
            ds.stream as *mut libc::DIR
        };

        if (offset as i64) != ds.offset {
            unsafe { libc::seekdir(dir_stream, offset as i64) };
        }

        loop {
            ds.offset = unsafe { libc::telldir(dir_stream) };

            let dentry = unsafe { libc::readdir(dir_stream) };
            if dentry.is_null() {
                break;
            }

            let mut name: Vec<u8> = Vec::new();

            unsafe {
                for c in &(*dentry).d_name {
                    if *c == 0 {
                        break;
                    }
                    name.push(*c as u8);
                }
            }

            if name == b"." || name == b".." {
                continue;
            }

            let res = unsafe {
                add_entry(DirEntry {
                    ino: (*dentry).d_ino,
                    offset: (ds.offset + 1) as u64,
                    type_: u32::from((*dentry).d_type),
                    name: &name,
                })
            };

            match res {
                Ok(size) => {
                    if size == 0 {
                        unsafe { libc::seekdir(dir_stream, ds.offset) };
                        break;
                    }
                }
                Err(e) => {
                    warn!(
                        "virtio-fs: error adding entry {}: {:?}",
                        std::str::from_utf8(&name).unwrap(),
                        e
                    );
                    break;
                }
            }
        }

        Ok(())
    }

    fn do_open(&self, inode: Inode, flags: u32) -> io::Result<(Option<Handle>, OpenOptions)> {
        let flags = self.parse_open_flags(flags as i32);

        let file = RwLock::new(self.open_inode(inode, flags as i32)?);

        let handle = self.next_handle.fetch_add(1, Ordering::Relaxed);
        let data = HandleData {
            inode,
            file,
            dirstream: Mutex::new(DirStream {
                stream: 0,
                offset: 0,
            }),
        };

        self.handles.write().unwrap().insert(handle, Arc::new(data));

        let mut opts = OpenOptions::empty();
        match self.cfg.cache_policy {
            // We only set the direct I/O option on files.
            CachePolicy::Never => opts.set(OpenOptions::DIRECT_IO, flags & libc::O_DIRECTORY == 0),
            CachePolicy::Always => {
                if flags & libc::O_DIRECTORY == 0 {
                    opts |= OpenOptions::KEEP_CACHE;
                } else {
                    opts |= OpenOptions::CACHE_DIR;
                }
            }
            _ => {}
        };

        Ok((Some(handle), opts))
    }

    fn do_release(&self, inode: Inode, handle: Handle) -> io::Result<()> {
        let mut handles = self.handles.write().unwrap();

        if let btree_map::Entry::Occupied(e) = handles.entry(handle) {
            if e.get().inode == inode {
                // We don't need to close the file here because that will happen automatically when
                // the last `Arc` is dropped.
                e.remove();
                return Ok(());
            }
        }

        Err(ebadf())
    }

    fn do_getattr(&self, inode: Inode) -> io::Result<(bindings::stat64, Duration)> {
        let file = self.get_file(inode)?;
        let st = fstat(&file)?;

        Ok((st, self.cfg.attr_timeout))
    }

    fn do_unlink(
        &self,
        _ctx: Context,
        parent: Inode,
        name: &CStr,
        flags: libc::c_int,
    ) -> io::Result<()> {
        let file = self.get_file(parent)?;
        let entry = match self.do_lookup(parent, name) {
            Ok(entry) => {
                let mut inodes = self.inodes.write().unwrap();
                let mut file_cache = self.file_cache.lock().unwrap();
                let mut path_cache = self.path_cache.lock().unwrap();
                let mut pinned_files = self.pinned_files.lock().unwrap();

                forget_one(
                    &mut inodes,
                    &mut file_cache,
                    &mut path_cache,
                    &mut pinned_files,
                    entry.inode,
                    1,
                    true,
                );

                Some(entry)
            }
            Err(_) => None,
        };

        // Safe because this doesn't modify any memory and we check the return value.
        let res = unsafe { libc::unlinkat(file.as_raw_fd(), name.as_ptr(), flags) };
        if res == 0 {
            if let Some(entry) = entry {
                let mut path_cache = self.path_cache.lock().unwrap();
                let filepath = format!(
                    "{}/{}",
                    get_path(&mut path_cache, parent)?,
                    name.to_str().unwrap(),
                );

                remove_path(&mut path_cache, entry.inode, filepath);
                drop(path_cache);
            }
            Ok(())
        } else {
            Err(linux_error(io::Error::last_os_error()))
        }
    }

    fn parse_open_flags(&self, flags: i32) -> i32 {
        let mut mflags: i32 = flags & 0b11;

        if (flags & bindings::LINUX_O_NONBLOCK) != 0 {
            mflags |= libc::O_NONBLOCK;
        }
        if (flags & bindings::LINUX_O_APPEND) != 0 {
            mflags |= libc::O_APPEND;
        }
        if (flags & bindings::LINUX_O_CREAT) != 0 {
            mflags |= libc::O_CREAT;
        }
        if (flags & bindings::LINUX_O_TRUNC) != 0 {
            mflags |= libc::O_TRUNC;
        }
        if (flags & bindings::LINUX_O_EXCL) != 0 {
            mflags |= libc::O_EXCL;
        }
        if (flags & bindings::LINUX_O_NOFOLLOW) != 0 {
            mflags |= libc::O_NOFOLLOW;
        }
        if (flags & bindings::LINUX_O_CLOEXEC) != 0 {
            mflags |= libc::O_CLOEXEC;
        }

        mflags
    }
}

fn forget_one(
    inodes: &mut MultikeyBTreeMap<Inode, InodeAltKey, Arc<InodeData>>,
    file_cache: &mut LruCache<Inode, Arc<File>>,
    path_cache: &mut BTreeMap<Inode, Vec<String>>,
    pinned_files: &mut BTreeMap<Inode, Arc<File>>,
    inode: Inode,
    count: u64,
    unlinked: bool,
) {
    if let Some(data) = inodes.get(&inode) {
        // Acquiring the write lock on the inode map prevents new lookups from incrementing the
        // refcount but there is the possibility that a previous lookup already acquired a
        // reference to the inode data and is in the process of updating the refcount so we need
        // to loop here until we can decrement successfully.
        loop {
            let refcount = data.refcount.load(Ordering::Relaxed);

            // Saturating sub because it doesn't make sense for a refcount to go below zero and
            // we don't want misbehaving clients to cause integer overflow.
            let new_count = refcount.saturating_sub(count);

            // Synchronizes with the acquire load in `do_lookup`.
            if data
                .refcount
                .compare_exchange(refcount, new_count, Ordering::Release, Ordering::Relaxed)
                .unwrap()
                == refcount
            {
                if new_count == 0 {
                    // We just removed the last refcount for this inode. There's no need for an
                    // acquire fence here because we hold a write lock on the inode map and any
                    // thread that is waiting to do a forget on the same inode will have to wait
                    // until we release the lock. So there's is no other release store for us to
                    // synchronize with before deleting the entry.
                    inodes.remove(&inode);
                    file_cache.pop(&inode);
                    path_cache.remove(&inode);
                    pinned_files.remove(&inode);
                } else if unlinked && !pinned_files.contains_key(&inode) {
                    if let Some(file) = file_cache.get(&inode) {
                        pinned_files.insert(inode, file.clone());
                    } else {
                        get_path(path_cache, inode)
                            .ok()
                            .map(|filepath| open_path(file_cache, inode, &filepath).ok())
                            .flatten()
                            .map(|file| pinned_files.insert(inode, file));
                    }
                }
                break;
            }
        }
    }
}

impl FileSystem for PassthroughFs {
    type Inode = Inode;
    type Handle = Handle;

    fn init(&self, capable: FsOptions) -> io::Result<FsOptions> {
        let root = CString::new(self.cfg.root_dir.as_str()).expect("CString::new failed");

        // Safe because this doesn't modify any memory and we check the return value.
        let fd = unsafe {
            libc::openat(
                libc::AT_FDCWD,
                root.as_ptr(),
                libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(linux_error(io::Error::last_os_error()));
        }

        // Safe because we just opened this fd above.
        let f = unsafe { File::from_raw_fd(fd) };

        let st = fstat(&f)?;

        // Safe because this doesn't modify any memory and there is no need to check the return
        // value because this system call always succeeds. We need to clear the umask here because
        // we want the client to be able to set all the bits in the mode.
        unsafe { libc::umask(0o000) };

        let mut inodes = self.inodes.write().unwrap();

        // Not sure why the root inode gets a refcount of 2 but that's what libfuse does.
        inodes.insert(
            fuse::ROOT_ID,
            InodeAltKey {
                ino: st.st_ino,
                dev: st.st_dev,
            },
            Arc::new(InodeData {
                inode: fuse::ROOT_ID,
                linkdata: CString::new("").unwrap(),
                refcount: AtomicU64::new(2),
            }),
        );

        let mut path_cache = self.path_cache.lock().unwrap();
        add_path(&mut path_cache, fuse::ROOT_ID, self.cfg.root_dir.clone());

        if let Some(mapped_volumes) = &self.cfg.mapped_volumes {
            for (host_vol, guest_vol) in mapped_volumes.iter() {
                assert!(host_vol.is_absolute());
                assert!(guest_vol.is_absolute());
                assert_eq!(guest_vol.components().count(), 2);

                let guest_vol_str = guest_vol
                    .file_name()
                    .unwrap()
                    .to_str()
                    .expect("Couldn't parse guest volume as String");
                let host_vol_str = host_vol
                    .to_str()
                    .expect("Couldn't parse host volume as String");
                let path = CString::new(host_vol_str).expect("Couldn't parse volume as CString");
                // Safe because this doesn't modify any memory and we check the return value.
                let fd = unsafe { libc::open(path.as_ptr(), libc::O_NOFOLLOW | libc::O_CLOEXEC) };
                if fd < 0 {
                    error!(
                        "Error setting up mapped volume: {:?}:{:?}: {:?}",
                        host_vol,
                        guest_vol,
                        io::Error::last_os_error(),
                    );
                    continue;
                }

                let st = fstat(&f)?;
                let inode = self.next_inode.fetch_add(1, Ordering::Relaxed);

                inodes.insert(
                    inode,
                    InodeAltKey {
                        ino: st.st_ino,
                        dev: st.st_dev,
                    },
                    Arc::new(InodeData {
                        inode,
                        linkdata: CString::new("").unwrap(),
                        refcount: AtomicU64::new(1),
                    }),
                );
                add_path(&mut path_cache, inode, host_vol_str.to_string());
                self.host_volumes
                    .write()
                    .unwrap()
                    .insert(guest_vol_str.to_string(), inode);
            }
        }

        let mut opts = FsOptions::empty();
        if self.cfg.writeback && capable.contains(FsOptions::WRITEBACK_CACHE) {
            opts |= FsOptions::WRITEBACK_CACHE;
            self.writeback.store(true, Ordering::Relaxed);
        }
        Ok(opts)
    }

    fn destroy(&self) {
        self.handles.write().unwrap().clear();
        self.inodes.write().unwrap().clear();
    }

    fn statfs(&self, _ctx: Context, inode: Inode) -> io::Result<bindings::statvfs64> {
        let mut out = MaybeUninit::<bindings::statvfs64>::zeroed();

        let file = self.get_file(inode)?;
        // Safe because this will only modify `out` and we check the return value.
        let res = unsafe { bindings::fstatvfs64(file.as_raw_fd(), out.as_mut_ptr()) };
        if res == 0 {
            // Safe because the kernel guarantees that `out` has been initialized.
            Ok(unsafe { out.assume_init() })
        } else {
            Err(linux_error(io::Error::last_os_error()))
        }
    }

    fn lookup(&self, _ctx: Context, parent: Inode, name: &CStr) -> io::Result<Entry> {
        debug!("lookup: {:?}", name);
        let init_name = unsafe { CStr::from_bytes_with_nul_unchecked(INIT_CSTR) };

        if self.init_inode != 0 && name == init_name {
            let mut st: bindings::stat64 = unsafe { mem::zeroed() };
            st.st_size = INIT_BINARY.len() as i64;
            st.st_ino = self.init_inode;
            st.st_mode = 0o100_755;

            Ok(Entry {
                inode: self.init_inode,
                generation: 0,
                attr: st,
                attr_timeout: self.cfg.attr_timeout,
                entry_timeout: self.cfg.entry_timeout,
            })
        } else {
            self.do_lookup(parent, name)
        }
    }

    fn forget(&self, _ctx: Context, inode: Inode, count: u64) {
        let mut inodes = self.inodes.write().unwrap();
        let mut file_cache = self.file_cache.lock().unwrap();
        let mut path_cache = self.path_cache.lock().unwrap();
        let mut pinned_files = self.pinned_files.lock().unwrap();

        forget_one(
            &mut inodes,
            &mut file_cache,
            &mut path_cache,
            &mut pinned_files,
            inode,
            count,
            false,
        )
    }

    fn batch_forget(&self, _ctx: Context, requests: Vec<(Inode, u64)>) {
        let mut inodes = self.inodes.write().unwrap();
        let mut file_cache = self.file_cache.lock().unwrap();
        let mut path_cache = self.path_cache.lock().unwrap();
        let mut pinned_files = self.pinned_files.lock().unwrap();

        for (inode, count) in requests {
            forget_one(
                &mut inodes,
                &mut file_cache,
                &mut path_cache,
                &mut pinned_files,
                inode,
                count,
                false,
            )
        }
    }

    fn opendir(
        &self,
        _ctx: Context,
        inode: Inode,
        flags: u32,
    ) -> io::Result<(Option<Handle>, OpenOptions)> {
        self.do_open(inode, flags | libc::O_DIRECTORY as u32)
    }

    fn releasedir(
        &self,
        _ctx: Context,
        inode: Inode,
        _flags: u32,
        handle: Handle,
    ) -> io::Result<()> {
        let data = self
            .handles
            .read()
            .unwrap()
            .get(&handle)
            .filter(|hd| hd.inode == inode)
            .map(Arc::clone)
            .ok_or_else(ebadf)?;

        let ds = data.dirstream.lock().unwrap();
        if ds.stream != 0 {
            unsafe { libc::closedir(ds.stream as *mut libc::DIR) };
        }

        self.do_release(inode, handle)
    }

    fn mkdir(
        &self,
        ctx: Context,
        parent: Inode,
        name: &CStr,
        mode: u32,
        umask: u32,
    ) -> io::Result<Entry> {
        let file = self.get_file(parent)?;
        // Safe because this doesn't modify any memory and we check the return value.
        let res = unsafe { libc::mkdirat(file.as_raw_fd(), name.as_ptr(), 0o700) };
        if res == 0 {
            let filepath = format!(
                "{}/{}",
                get_path(&mut self.path_cache.lock().unwrap(), parent)?,
                name.to_str().unwrap(),
            );
            set_xattr_stat(
                StatFile::Path(filepath),
                Some((ctx.uid, ctx.gid)),
                Some(mode & !umask),
            );
            self.do_lookup(parent, name)
        } else {
            Err(linux_error(io::Error::last_os_error()))
        }
    }

    fn rmdir(&self, ctx: Context, parent: Inode, name: &CStr) -> io::Result<()> {
        self.do_unlink(ctx, parent, name, libc::AT_REMOVEDIR)
    }

    fn readdir<F>(
        &self,
        _ctx: Context,
        inode: Inode,
        handle: Handle,
        size: u32,
        offset: u64,
        add_entry: F,
    ) -> io::Result<()>
    where
        F: FnMut(DirEntry) -> io::Result<usize>,
    {
        self.do_readdir(inode, handle, size, offset, add_entry)
    }

    fn readdirplus<F>(
        &self,
        _ctx: Context,
        inode: Inode,
        handle: Handle,
        size: u32,
        offset: u64,
        mut add_entry: F,
    ) -> io::Result<()>
    where
        F: FnMut(DirEntry, Entry) -> io::Result<usize>,
    {
        self.do_readdir(inode, handle, size, offset, |dir_entry| {
            // Safe because the kernel guarantees that the buffer is nul-terminated. Additionally,
            // the kernel will pad the name with '\0' bytes up to 8-byte alignment and there's no
            // way for us to know exactly how many padding bytes there are. This would cause
            // `CStr::from_bytes_with_nul` to return an error because it would think there are
            // interior '\0' bytes. We trust the kernel to provide us with properly formatted data
            // so we'll just skip the checks here.
            let name = unsafe { CStr::from_bytes_with_nul_unchecked(dir_entry.name) };
            let entry = self.do_lookup(inode, name)?;

            add_entry(dir_entry, entry)
        })
    }

    fn open(
        &self,
        _ctx: Context,
        inode: Inode,
        flags: u32,
    ) -> io::Result<(Option<Handle>, OpenOptions)> {
        if inode == self.init_inode {
            Ok((Some(self.init_handle), OpenOptions::empty()))
        } else {
            self.do_open(inode, flags)
        }
    }

    fn release(
        &self,
        _ctx: Context,
        inode: Inode,
        _flags: u32,
        handle: Handle,
        _flush: bool,
        _flock_release: bool,
        _lock_owner: Option<u64>,
    ) -> io::Result<()> {
        self.do_release(inode, handle)
    }

    fn create(
        &self,
        ctx: Context,
        parent: Inode,
        name: &CStr,
        mode: u32,
        flags: u32,
        umask: u32,
    ) -> io::Result<(Entry, Option<Handle>, OpenOptions)> {
        let file = self.get_file(parent)?;
        let flags = self.parse_open_flags(flags as i32);
        let hostmode = if (flags & libc::O_DIRECTORY) != 0 {
            0o700
        } else {
            0o600
        };

        // Safe because this doesn't modify any memory and we check the return value. We don't
        // really check `flags` because if the kernel can't handle poorly specified flags then we
        // have much bigger problems.
        let fd = unsafe {
            libc::openat(
                file.as_raw_fd(),
                name.as_ptr(),
                flags | libc::O_CREAT | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                hostmode,
            )
        };
        if fd < 0 {
            return Err(linux_error(io::Error::last_os_error()));
        }

        set_xattr_stat(
            StatFile::Fd(fd),
            Some((ctx.uid, ctx.gid)),
            Some(libc::S_IFREG as u32 | (mode & !(umask & 0o777))),
        );

        // Safe because we just opened this fd.
        let file = RwLock::new(unsafe { File::from_raw_fd(fd) });

        let entry = self.do_lookup(parent, name)?;

        let handle = self.next_handle.fetch_add(1, Ordering::Relaxed);
        let data = HandleData {
            inode: entry.inode,
            file,
            dirstream: Mutex::new(DirStream {
                stream: 0,
                offset: 0,
            }),
        };

        self.handles.write().unwrap().insert(handle, Arc::new(data));

        let mut opts = OpenOptions::empty();
        match self.cfg.cache_policy {
            CachePolicy::Never => opts |= OpenOptions::DIRECT_IO,
            CachePolicy::Always => opts |= OpenOptions::KEEP_CACHE,
            _ => {}
        };

        Ok((entry, Some(handle), opts))
    }

    fn unlink(&self, ctx: Context, parent: Inode, name: &CStr) -> io::Result<()> {
        self.do_unlink(ctx, parent, name, 0)
    }

    fn read<W: io::Write + ZeroCopyWriter>(
        &self,
        _ctx: Context,
        inode: Inode,
        handle: Handle,
        mut w: W,
        size: u32,
        offset: u64,
        _lock_owner: Option<u64>,
        _flags: u32,
    ) -> io::Result<usize> {
        debug!("read: {:?}", inode);
        if inode == self.init_inode {
            return w.write(&INIT_BINARY[offset as usize..(offset + (size as u64)) as usize]);
        }

        let data = self
            .handles
            .read()
            .unwrap()
            .get(&handle)
            .filter(|hd| hd.inode == inode)
            .map(Arc::clone)
            .ok_or_else(ebadf)?;

        // This is safe because write_from uses preadv64, so the underlying file descriptor
        // offset is not affected by this operation.
        let mut f = data.file.read().unwrap();
        w.write_from(&f, size as usize, offset)
    }

    fn write<R: io::Read + ZeroCopyReader>(
        &self,
        _ctx: Context,
        inode: Inode,
        handle: Handle,
        mut r: R,
        size: u32,
        offset: u64,
        _lock_owner: Option<u64>,
        _delayed_write: bool,
        _kill_priv: bool,
        _flags: u32,
    ) -> io::Result<usize> {
        let data = self
            .handles
            .read()
            .unwrap()
            .get(&handle)
            .filter(|hd| hd.inode == inode)
            .map(Arc::clone)
            .ok_or_else(ebadf)?;

        // This is safe because read_to uses pwritev64, so the underlying file descriptor
        // offset is not affected by this operation.
        let mut f = data.file.read().unwrap();
        r.read_to(&f, size as usize, offset)
    }

    fn getattr(
        &self,
        _ctx: Context,
        inode: Inode,
        _handle: Option<Handle>,
    ) -> io::Result<(bindings::stat64, Duration)> {
        self.do_getattr(inode)
    }

    fn setattr(
        &self,
        _ctx: Context,
        inode: Inode,
        attr: bindings::stat64,
        handle: Option<Handle>,
        valid: SetattrValid,
    ) -> io::Result<(bindings::stat64, Duration)> {
        let file = self.get_file(inode)?;

        enum Data {
            Handle(Arc<HandleData>, RawFd),
            FilePath,
        }

        // If we have a handle then use it otherwise get a new fd from the inode.
        let data = if let Some(handle) = handle {
            let hd = self
                .handles
                .read()
                .unwrap()
                .get(&handle)
                .filter(|hd| hd.inode == inode)
                .map(Arc::clone)
                .ok_or_else(ebadf)?;

            let fd = hd.file.write().unwrap().as_raw_fd();
            Data::Handle(hd, fd)
        } else {
            Data::FilePath
        };

        if valid.contains(SetattrValid::MODE) {
            let res = match data {
                Data::Handle(_, fd) => {
                    set_xattr_stat(StatFile::Fd(fd), None, Some(attr.st_mode as u32))
                }
                Data::FilePath => {
                    let filepath = get_path(&mut self.path_cache.lock().unwrap(), inode)?;
                    set_xattr_stat(StatFile::Path(filepath), None, Some(attr.st_mode as u32))
                }
            };
            if res < 0 {
                return Err(linux_error(io::Error::last_os_error()));
            }
        }

        if valid.intersects(SetattrValid::UID | SetattrValid::GID) {
            let uid = if valid.contains(SetattrValid::UID) {
                attr.st_uid
            } else {
                // Cannot use -1 here because these are unsigned values.
                ::std::u32::MAX
            };
            let gid = if valid.contains(SetattrValid::GID) {
                attr.st_gid
            } else {
                // Cannot use -1 here because these are unsigned values.
                ::std::u32::MAX
            };

            // Safe because this doesn't modify any memory and we check the return value.
            let res = set_xattr_stat(StatFile::Fd(file.as_raw_fd()), Some((uid, gid)), None);
            if res < 0 {
                return Err(linux_error(io::Error::last_os_error()));
            }
        }

        if valid.contains(SetattrValid::SIZE) {
            // Safe because this doesn't modify any memory and we check the return value.
            let res = match data {
                Data::Handle(_, fd) => unsafe { libc::ftruncate(fd, attr.st_size) },
                _ => {
                    // There is no `ftruncateat` so we need to get a new fd and truncate it.
                    let f = self.open_inode(inode, libc::O_NONBLOCK | libc::O_RDWR)?;
                    unsafe { libc::ftruncate(f.as_raw_fd(), attr.st_size) }
                }
            };
            if res < 0 {
                return Err(linux_error(io::Error::last_os_error()));
            }
        }

        if valid.intersects(SetattrValid::ATIME | SetattrValid::MTIME) {
            let mut tvs = [
                libc::timespec {
                    tv_sec: 0,
                    tv_nsec: libc::UTIME_OMIT,
                },
                libc::timespec {
                    tv_sec: 0,
                    tv_nsec: libc::UTIME_OMIT,
                },
            ];

            if valid.contains(SetattrValid::ATIME_NOW) {
                tvs[0].tv_nsec = libc::UTIME_NOW;
            } else if valid.contains(SetattrValid::ATIME) {
                tvs[0].tv_sec = attr.st_atime;
                tvs[0].tv_nsec = attr.st_atime_nsec;
            }

            if valid.contains(SetattrValid::MTIME_NOW) {
                tvs[1].tv_nsec = libc::UTIME_NOW;
            } else if valid.contains(SetattrValid::MTIME) {
                tvs[1].tv_sec = attr.st_mtime;
                tvs[1].tv_nsec = attr.st_mtime_nsec;
            }

            // Safe because this doesn't modify any memory and we check the return value.
            let res = match data {
                Data::Handle(_, fd) => unsafe { libc::futimens(fd, tvs.as_ptr()) },
                Data::FilePath => unsafe {
                    libc::futimens(self.get_file(inode)?.as_raw_fd(), tvs.as_ptr())
                },
            };
            if res < 0 {
                return Err(io::Error::last_os_error());
            }
        }

        self.do_getattr(inode)
    }

    fn rename(
        &self,
        ctx: Context,
        olddir: Inode,
        oldname: &CStr,
        newdir: Inode,
        newname: &CStr,
        flags: u32,
    ) -> io::Result<()> {
        let mut mflags: u32 = 0;
        if ((flags as i32) & bindings::LINUX_RENAME_NOREPLACE) != 0 {
            mflags |= libc::RENAME_EXCL;
        }
        if ((flags as i32) & bindings::LINUX_RENAME_EXCHANGE) != 0 {
            mflags |= libc::RENAME_SWAP;
        }

        if ((flags as i32) & bindings::LINUX_RENAME_WHITEOUT) != 0
            && ((flags as i32) & bindings::LINUX_RENAME_EXCHANGE) != 0
        {
            return Err(linux_error(io::Error::from_raw_os_error(libc::EINVAL)));
        }

        let olddir_file = self.get_file(olddir)?;
        let newdir_file = self.get_file(newdir)?;

        let res = unsafe {
            libc::renameatx_np(
                olddir_file.as_raw_fd(),
                oldname.as_ptr(),
                newdir_file.as_raw_fd(),
                newname.as_ptr(),
                mflags,
            )
        };
        if res == 0 {
            if ((flags as i32) & bindings::LINUX_RENAME_WHITEOUT) != 0 {
                let fd = unsafe {
                    libc::openat(
                        olddir_file.as_raw_fd(),
                        oldname.as_ptr(),
                        libc::O_CREAT | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                        0o600,
                    )
                };
                if fd > 0 {
                    set_xattr_stat(StatFile::Fd(fd), None, Some((libc::S_IFCHR | 0o600) as u32));
                    unsafe { libc::close(fd) };
                }
            }

            let entry = self.do_lookup(newdir, newname)?;
            let mut path_cache = self.path_cache.lock().unwrap();
            let filepath = format!(
                "{}/{}",
                get_path(&mut path_cache, olddir)?,
                oldname.to_str().unwrap()
            );
            remove_path(&mut path_cache, entry.inode, filepath);
            if (entry.attr.st_mode & libc::S_IFMT) == libc::S_IFDIR {
                // The renaming a directory may invalidate a number of entries in
                // our path cache. This is costly, but we have no other option.
                path_cache_rename_dir(
                    &mut path_cache,
                    olddir,
                    oldname.to_str().unwrap(),
                    newdir,
                    newname.to_str().unwrap(),
                );
            }
            drop(path_cache);

            self.forget(ctx, entry.inode, 1);

            Ok(())
        } else {
            Err(linux_error(io::Error::last_os_error()))
        }
    }

    fn mknod(
        &self,
        ctx: Context,
        parent: Inode,
        name: &CStr,
        mode: u32,
        _rdev: u32,
        umask: u32,
    ) -> io::Result<Entry> {
        let file = self.get_file(parent)?;

        let fd = unsafe {
            libc::openat(
                file.as_raw_fd(),
                name.as_ptr(),
                libc::O_CREAT | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                0o600,
            )
        };
        if fd < 0 {
            Err(linux_error(io::Error::last_os_error()))
        } else {
            set_xattr_stat(
                StatFile::Fd(fd),
                Some((ctx.uid, ctx.gid)),
                Some(mode & !umask),
            );
            unsafe { libc::close(fd) };
            self.do_lookup(parent, name)
        }
    }

    fn link(
        &self,
        _ctx: Context,
        inode: Inode,
        newparent: Inode,
        newname: &CStr,
    ) -> io::Result<Entry> {
        let mut path_cache = self.path_cache.lock().unwrap();
        let newfullpath = CString::new(format!(
            "{}/{}",
            get_path(&mut path_cache, newparent)?,
            newname.to_str().unwrap(),
        ))
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        let filepath = CString::new(get_path(&mut path_cache, inode)?).unwrap();
        drop(path_cache);

        // Safe because this doesn't modify any memory and we check the return value.
        let res = unsafe { libc::link(filepath.as_ptr(), newfullpath.as_ptr()) };
        if res == 0 {
            self.do_lookup(newparent, newname)
        } else {
            Err(linux_error(io::Error::last_os_error()))
        }
    }

    fn symlink(
        &self,
        ctx: Context,
        linkname: &CStr,
        parent: Inode,
        name: &CStr,
    ) -> io::Result<Entry> {
        let file = self.get_file(parent)?;
        // Safe because this doesn't modify any memory and we check the return value.
        let res = unsafe { libc::symlinkat(linkname.as_ptr(), file.as_raw_fd(), name.as_ptr()) };
        if res == 0 {
            let mut entry = self.do_lookup(parent, name)?;
            let mode = libc::S_IFLNK | 0o777;
            set_xattr_stat(
                StatFile::Path(get_path(&mut self.path_cache.lock().unwrap(), entry.inode)?),
                Some((ctx.uid, ctx.gid)),
                Some(mode as u32),
            );
            entry.attr.st_uid = ctx.uid;
            entry.attr.st_gid = ctx.gid;
            entry.attr.st_mode = mode;
            Ok(entry)
        } else {
            Err(linux_error(io::Error::last_os_error()))
        }
    }

    fn readlink(&self, _ctx: Context, inode: Inode) -> io::Result<Vec<u8>> {
        let data = self
            .inodes
            .read()
            .unwrap()
            .get(&inode)
            .map(Arc::clone)
            .ok_or_else(ebadf)?;

        Ok(data.linkdata.as_bytes().to_vec())
    }

    fn flush(
        &self,
        _ctx: Context,
        inode: Inode,
        handle: Handle,
        _lock_owner: u64,
    ) -> io::Result<()> {
        let data = self
            .handles
            .read()
            .unwrap()
            .get(&handle)
            .filter(|hd| hd.inode == inode)
            .map(Arc::clone)
            .ok_or_else(ebadf)?;

        // Since this method is called whenever an fd is closed in the client, we can emulate that
        // behavior by doing the same thing (dup-ing the fd and then immediately closing it). Safe
        // because this doesn't modify any memory and we check the return values.
        unsafe {
            let newfd = libc::dup(data.file.write().unwrap().as_raw_fd());
            if newfd < 0 {
                return Err(linux_error(io::Error::last_os_error()));
            }

            if libc::close(newfd) < 0 {
                Err(linux_error(io::Error::last_os_error()))
            } else {
                Ok(())
            }
        }
    }

    fn fsync(
        &self,
        _ctx: Context,
        inode: Inode,
        _datasync: bool,
        handle: Handle,
    ) -> io::Result<()> {
        let data = self
            .handles
            .read()
            .unwrap()
            .get(&handle)
            .filter(|hd| hd.inode == inode)
            .map(Arc::clone)
            .ok_or_else(ebadf)?;

        let fd = data.file.write().unwrap().as_raw_fd();

        // Safe because this doesn't modify any memory and we check the return value.
        let res = unsafe { libc::fsync(fd) };

        if res == 0 {
            Ok(())
        } else {
            Err(linux_error(io::Error::last_os_error()))
        }
    }

    fn fsyncdir(
        &self,
        ctx: Context,
        inode: Inode,
        datasync: bool,
        handle: Handle,
    ) -> io::Result<()> {
        self.fsync(ctx, inode, datasync, handle)
    }

    fn access(&self, ctx: Context, inode: Inode, mask: u32) -> io::Result<()> {
        let file = self.get_file(inode)?;
        let st = fstat(&file)?;

        let mode = mask as i32 & (libc::R_OK | libc::W_OK | libc::X_OK);

        if mode == libc::F_OK {
            // The file exists since we were able to call `stat(2)` on it.
            return Ok(());
        }

        if (mode & libc::R_OK) != 0
            && ctx.uid != 0
            && (st.st_uid != ctx.uid || st.st_mode & 0o400 == 0)
            && (st.st_gid != ctx.gid || st.st_mode & 0o040 == 0)
            && st.st_mode & 0o004 == 0
        {
            return Err(linux_error(io::Error::from_raw_os_error(libc::EACCES)));
        }

        if (mode & libc::W_OK) != 0
            && ctx.uid != 0
            && (st.st_uid != ctx.uid || st.st_mode & 0o200 == 0)
            && (st.st_gid != ctx.gid || st.st_mode & 0o020 == 0)
            && st.st_mode & 0o002 == 0
        {
            return Err(linux_error(io::Error::from_raw_os_error(libc::EACCES)));
        }

        // root can only execute something if it is executable by one of the owner, the group, or
        // everyone.
        if (mode & libc::X_OK) != 0
            && (ctx.uid != 0 || st.st_mode & 0o111 == 0)
            && (st.st_uid != ctx.uid || st.st_mode & 0o100 == 0)
            && (st.st_gid != ctx.gid || st.st_mode & 0o010 == 0)
            && st.st_mode & 0o001 == 0
        {
            return Err(linux_error(io::Error::from_raw_os_error(libc::EACCES)));
        }

        Ok(())
    }

    fn setxattr(
        &self,
        _ctx: Context,
        inode: Inode,
        name: &CStr,
        value: &[u8],
        flags: u32,
    ) -> io::Result<()> {
        debug!(
            "setxattr: inode={} name={:?} value={:?}",
            inode, name, value
        );

        if !self.cfg.xattr {
            return Err(linux_error(io::Error::from_raw_os_error(libc::ENOSYS)));
        }

        if name.to_bytes() == XATTR_KEY {
            return Err(linux_error(io::Error::from_raw_os_error(libc::EACCES)));
        }

        let mut mflags: i32 = 0;
        if (flags as i32) & bindings::LINUX_XATTR_CREATE != 0 {
            mflags |= libc::XATTR_CREATE;
        }
        if (flags as i32) & bindings::LINUX_XATTR_REPLACE != 0 {
            mflags |= libc::XATTR_REPLACE;
        }

        let file = self.get_file(inode)?;

        // Safe because this doesn't modify any memory and we check the return value.
        let res = unsafe {
            libc::fsetxattr(
                file.as_raw_fd(),
                name.as_ptr(),
                value.as_ptr() as *const libc::c_void,
                value.len(),
                0,
                mflags as libc::c_int,
            )
        };
        if res == 0 {
            Ok(())
        } else {
            Err(linux_error(io::Error::last_os_error()))
        }
    }

    fn getxattr(
        &self,
        _ctx: Context,
        inode: Inode,
        name: &CStr,
        size: u32,
    ) -> io::Result<GetxattrReply> {
        debug!("getxattr: inode={} name={:?}", inode, name);

        if !self.cfg.xattr {
            return Err(linux_error(io::Error::from_raw_os_error(libc::ENOSYS)));
        }

        if inode == self.init_inode {
            return Err(linux_error(io::Error::from_raw_os_error(libc::ENODATA)));
        }

        if name.to_bytes() == XATTR_KEY {
            return Err(linux_error(io::Error::from_raw_os_error(libc::EACCES)));
        }

        let mut buf = vec![0; size as usize];

        let file = self.get_file(inode)?;

        // Safe because this will only modify the contents of `buf`.
        let res = unsafe {
            libc::fgetxattr(
                file.as_raw_fd(),
                name.as_ptr(),
                buf.as_mut_ptr() as *mut libc::c_void,
                size as libc::size_t,
                0,
                0,
            )
        };
        if res < 0 {
            return Err(linux_error(io::Error::last_os_error()));
        }

        if size == 0 {
            Ok(GetxattrReply::Count(res as u32))
        } else {
            buf.resize(res as usize, 0);
            Ok(GetxattrReply::Value(buf))
        }
    }

    fn listxattr(&self, _ctx: Context, inode: Inode, size: u32) -> io::Result<ListxattrReply> {
        if !self.cfg.xattr {
            return Err(linux_error(io::Error::from_raw_os_error(libc::ENOSYS)));
        }

        let mut buf = vec![0; 512_usize];

        let file = self.get_file(inode)?;

        // Safe because this will only modify the contents of `buf`.
        let res = unsafe {
            libc::flistxattr(
                file.as_raw_fd(),
                buf.as_mut_ptr() as *mut libc::c_char,
                512,
                0,
            )
        };
        if res < 0 {
            return Err(linux_error(io::Error::last_os_error()));
        }

        buf.truncate(res as usize);

        if size == 0 {
            let mut clean_size = res as usize;

            for attr in buf.split(|c| *c == 0) {
                if attr.starts_with(&XATTR_KEY[..XATTR_KEY.len() - 1]) {
                    clean_size -= XATTR_KEY.len();
                }
            }

            Ok(ListxattrReply::Count(clean_size as u32))
        } else {
            let mut clean_buf = Vec::new();

            for attr in buf.split(|c| *c == 0) {
                if attr.is_empty() || attr.starts_with(&XATTR_KEY[..XATTR_KEY.len() - 1]) {
                    continue;
                }

                clean_buf.extend_from_slice(attr);
                clean_buf.push(0);
            }

            clean_buf.shrink_to_fit();

            if clean_buf.len() > size as usize {
                Err(io::Error::from_raw_os_error(LINUX_ERANGE))
            } else {
                Ok(ListxattrReply::Names(clean_buf))
            }
        }
    }

    fn removexattr(&self, _ctx: Context, inode: Inode, name: &CStr) -> io::Result<()> {
        if !self.cfg.xattr {
            return Err(linux_error(io::Error::from_raw_os_error(libc::ENOSYS)));
        }

        if name.to_bytes() == XATTR_KEY {
            return Err(linux_error(io::Error::from_raw_os_error(
                bindings::LINUX_EACCES,
            )));
        }

        let file = self.get_file(inode)?;

        // Safe because this doesn't modify any memory and we check the return value.
        let res = unsafe { libc::fremovexattr(file.as_raw_fd(), name.as_ptr(), 0) };

        if res == 0 {
            Ok(())
        } else {
            Err(linux_error(io::Error::last_os_error()))
        }
    }

    fn fallocate(
        &self,
        _ctx: Context,
        inode: Inode,
        handle: Handle,
        _mode: u32,
        offset: u64,
        length: u64,
    ) -> io::Result<()> {
        let data = self
            .handles
            .read()
            .unwrap()
            .get(&handle)
            .filter(|hd| hd.inode == inode)
            .map(Arc::clone)
            .ok_or_else(ebadf)?;

        let fd = data.file.write().unwrap().as_raw_fd();

        let mut fs = libc::fstore_t {
            fst_flags: libc::F_ALLOCATECONTIG,
            fst_posmode: libc::F_PEOFPOSMODE,
            fst_offset: 0,
            fst_length: (offset + length) as i64,
            fst_bytesalloc: 0,
        };

        let res = unsafe { libc::fcntl(fd, libc::F_PREALLOCATE, &mut fs as *mut _) };
        if res < 0 {
            fs.fst_flags = libc::F_ALLOCATEALL;
            let res = unsafe { libc::fcntl(fd, libc::F_PREALLOCATE, &mut fs as &mut _) };
            if res < 0 {
                return Err(linux_error(io::Error::last_os_error()));
            }
        }

        let res = unsafe { libc::ftruncate(fd, (offset + length) as i64) };

        if res == 0 {
            Ok(())
        } else {
            Err(linux_error(io::Error::last_os_error()))
        }
    }

    fn lseek(
        &self,
        _ctx: Context,
        inode: Inode,
        handle: Handle,
        offset: u64,
        whence: u32,
    ) -> io::Result<u64> {
        let data = self
            .handles
            .read()
            .unwrap()
            .get(&handle)
            .filter(|hd| hd.inode == inode)
            .map(Arc::clone)
            .ok_or_else(ebadf)?;

        // SEEK_DATA and SEEK_HOLE have slightly different semantics
        // in Linux vs. macOS, which means we can't support them.
        let mwhence = if whence == 3 {
            // SEEK_DATA
            return Ok(offset);
        } else if whence == 4 {
            // SEEK_HOLE
            libc::SEEK_END
        } else {
            whence as i32
        };

        let fd = data.file.write().unwrap().as_raw_fd();

        // Safe because this doesn't modify any memory and we check the return value.
        let res = unsafe { libc::lseek(fd, offset as bindings::off64_t, mwhence as libc::c_int) };
        if res < 0 {
            Err(linux_error(io::Error::last_os_error()))
        } else {
            Ok(res as u64)
        }
    }
}
