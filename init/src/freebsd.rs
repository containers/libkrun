use std::ffi::CString;

extern "C" {
    fn revoke(path: *const libc::c_char) -> libc::c_int;
}

const KENV_MVALLEN: usize = 128;
const ISO_DEV: &str = "/dev/iso9660/KRUN_CONFIG";
const ISO_MOUNT: &str = "/mnt";
pub const ISO_CONFIG_PATH: &str = "/mnt/krun_config.json";

const KENV_VARS: &[&str] = &[
    "HOSTNAME",
    "KRUN_CONFIG",
    "KRUN_HOME",
    "KRUN_INIT",
    "KRUN_INIT_PID1",
    "KRUN_RLIMITS",
    "KRUN_TERM",
    "KRUN_WORKDIR",
];

fn kenv_get(name: &str) -> Option<String> {
    let c_name = CString::new(name).ok()?;
    let mut buf = vec![0u8; KENV_MVALLEN + 1];
    let ret = unsafe {
        libc::kenv(
            libc::KENV_GET,
            c_name.as_ptr(),
            buf.as_mut_ptr() as *mut libc::c_char,
            (KENV_MVALLEN + 1) as i32,
        )
    };
    if ret < 0 {
        return None;
    }
    let s = unsafe { std::ffi::CStr::from_ptr(buf.as_ptr() as *const libc::c_char) };
    Some(s.to_string_lossy().into_owned())
}

/// Populate the process environment from the FreeBSD kernel environment.
///
/// On FreeBSD, init runs before the process environment is set up, so
/// variables like KRUN_INIT must be read from kenv(2) rather than getenv(3).
pub fn populate_env_from_kenv() {
    for &var in KENV_VARS {
        if let Some(val) = kenv_get(var) {
            unsafe { std::env::set_var(var, val) };
        }
    }
}

/// Open /dev/console and make it the controlling terminal.
///
/// Replicates login_tty(3) inline to avoid a libutil dependency:
/// revoke any existing opens, open the device, create a new session,
/// set the controlling terminal via TIOCSCTTY, then dup2 into stdio.
/// Falls back to /dev/null + /init.log if the console cannot be opened.
pub fn open_console() {
    let console = b"/dev/console\0";
    unsafe { revoke(console.as_ptr() as *const libc::c_char) };

    let fd = unsafe {
        libc::open(
            console.as_ptr() as *const libc::c_char,
            libc::O_RDWR | libc::O_NONBLOCK,
        )
    };

    if fd < 0 {
        fallback_console();
        return;
    }

    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    unsafe { libc::fcntl(fd, libc::F_SETFL, flags & !libc::O_NONBLOCK) };

    unsafe {
        libc::setsid();
        libc::ioctl(fd, libc::TIOCSCTTY, 0);
        libc::dup2(fd, libc::STDIN_FILENO);
        libc::dup2(fd, libc::STDOUT_FILENO);
        libc::dup2(fd, libc::STDERR_FILENO);
        if fd > libc::STDERR_FILENO {
            libc::close(fd);
        }
    }
}

fn fallback_console() {
    let null = b"/dev/null\0";
    let log = b"/init.log\0";

    let null_fd = unsafe { libc::open(null.as_ptr().cast(), libc::O_RDWR) };
    if null_fd >= 0 && null_fd != libc::STDIN_FILENO {
        unsafe {
            libc::dup2(null_fd, libc::STDIN_FILENO);
            libc::close(null_fd);
        }
    }

    let log_fd = unsafe {
        libc::open(
            log.as_ptr().cast(),
            libc::O_WRONLY | libc::O_APPEND | libc::O_CREAT,
            0o644u32,
        )
    };
    let out_fd = if log_fd >= 0 {
        log_fd
    } else {
        libc::STDIN_FILENO
    };
    unsafe {
        libc::dup2(out_fd, libc::STDOUT_FILENO);
        libc::dup2(libc::STDOUT_FILENO, libc::STDERR_FILENO);
        if log_fd >= 0 && log_fd != libc::STDOUT_FILENO {
            libc::close(log_fd);
        }
    }
}

/// Mount the KRUN_CONFIG ISO image at /mnt via nmount(2).
/// Returns true on success.
pub fn mount_config_iso() -> bool {
    let _ = std::fs::create_dir_all(ISO_MOUNT);

    let fstype_key = b"fstype\0";
    let fstype_val = b"cd9660\0";
    let fspath_key = b"fspath\0";
    let fspath_cstr = CString::new(ISO_MOUNT).unwrap();
    let from_key = b"from\0";
    let from_cstr = CString::new(ISO_DEV).unwrap();

    let mut iov = [
        libc::iovec {
            iov_base: fstype_key.as_ptr() as *mut _,
            iov_len: fstype_key.len(),
        },
        libc::iovec {
            iov_base: fstype_val.as_ptr() as *mut _,
            iov_len: fstype_val.len(),
        },
        libc::iovec {
            iov_base: fspath_key.as_ptr() as *mut _,
            iov_len: fspath_key.len(),
        },
        libc::iovec {
            iov_base: fspath_cstr.as_ptr() as *mut _,
            iov_len: fspath_cstr.as_bytes_with_nul().len(),
        },
        libc::iovec {
            iov_base: from_key.as_ptr() as *mut _,
            iov_len: from_key.len(),
        },
        libc::iovec {
            iov_base: from_cstr.as_ptr() as *mut _,
            iov_len: from_cstr.as_bytes_with_nul().len(),
        },
    ];

    unsafe { libc::nmount(iov.as_mut_ptr(), iov.len() as u32, libc::MNT_RDONLY) == 0 }
}

pub fn unmount_config_iso() {
    let mount_cstr = CString::new(ISO_MOUNT).unwrap();
    unsafe { libc::unmount(mount_cstr.as_ptr(), 0) };
}
