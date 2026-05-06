#[cfg(target_os = "linux")]
use nix::fcntl::{self, OFlag};
#[cfg(target_os = "linux")]
use nix::sys::reboot::{self, RebootMode};
#[cfg(target_os = "linux")]
use nix::sys::stat::Mode;
use nix::sys::wait::{self, WaitStatus};
use nix::unistd::{self, ForkResult};
use std::env;
use std::ffi::CString;
#[cfg(target_os = "linux")]
use std::fs;
#[cfg(target_os = "linux")]
use std::path::Path;
use std::process;

#[cfg(target_os = "linux")]
use nix::sys::statfs::{self, FsType};
#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;

#[cfg(target_os = "linux")]
const KRUN_EXIT_CODE_IOCTL: libc::c_ulong = 0x7602;
#[cfg(target_os = "linux")]
// 0x6573_5546 fits in i32, so the cast to FsType's inner c_long is safe on
// both 32-bit (c_long = i32) and 64-bit (c_long = i64) targets.
const VIRTIOFS_MAGIC: libc::c_long = 0x6573_5546;

#[cfg(target_os = "linux")]
pub fn setup_redirects() {
    let Ok(ports_dir) = fs::read_dir("/sys/class/virtio-ports") else {
        return;
    };
    for entry in ports_dir.flatten() {
        let name_path = entry.path().join("name");
        let Ok(port_name) = fs::read_to_string(&name_path) else {
            continue;
        };
        let (fd, flags) = match port_name.trim_end_matches('\n') {
            "krun-stdin" => (libc::STDIN_FILENO, libc::O_RDONLY),
            "krun-stdout" => (libc::STDOUT_FILENO, libc::O_WRONLY),
            "krun-stderr" => (libc::STDERR_FILENO, libc::O_WRONLY),
            _ => continue,
        };
        let dev = CString::new(format!("/dev/{}", entry.file_name().to_string_lossy())).unwrap();
        let new_fd = unsafe { libc::open(dev.as_ptr(), flags) };
        if new_fd >= 0 && new_fd != fd {
            // new_fd != fd: dup it onto the target and close the spare.
            unsafe {
                libc::dup2(new_fd, fd);
                libc::close(new_fd);
            }
        }
        // new_fd == fd: device opened directly onto the target fd (happens when
        // the target was already closed); it is already in the right place.
        // new_fd < 0: open failed; leave the existing fd untouched.
    }
}

#[cfg(target_os = "linux")]
pub fn set_exit_code(code: i32) {
    let Ok(fs) = statfs::statfs(Path::new("/")) else {
        return;
    };
    if fs.filesystem_type() != FsType(VIRTIOFS_MAGIC as _) {
        return;
    }
    if let Ok(fd) = fcntl::open(Path::new("/"), OFlag::O_RDONLY, Mode::empty()) {
        unsafe { libc::ioctl(fd.as_raw_fd(), KRUN_EXIT_CODE_IOCTL as _, code) };
    }
}

#[cfg(not(target_os = "linux"))]
pub fn set_exit_code(_code: i32) {}

pub fn run_workload(argv: &[String]) -> ! {
    if env::var("KRUN_INIT_PID1") == Ok("1".to_owned()) {
        exec_workload(argv);
    }

    match unsafe { unistd::fork() } {
        Err(_) => {
            set_exit_code(125);
            process::exit(125);
        }
        Ok(ForkResult::Child) => exec_workload(argv),
        Ok(ForkResult::Parent { child }) => {
            let code = loop {
                match wait::waitpid(None, None) {
                    Ok(WaitStatus::Exited(pid, c)) if pid == child => break c,
                    Ok(WaitStatus::Signaled(pid, sig, _)) if pid == child => {
                        break sig as i32 + 128;
                    }
                    _ => continue,
                }
            };
            set_exit_code(code);
            unistd::sync();
            #[cfg(target_os = "linux")]
            let _ = reboot::reboot(RebootMode::RB_AUTOBOOT);
            process::exit(code)
        }
    }
}

fn exec_workload(argv: &[String]) -> ! {
    #[cfg(target_os = "linux")]
    setup_redirects();
    #[cfg(target_os = "freebsd")]
    crate::freebsd::open_console();

    let c_argv: Vec<CString> = argv
        .iter()
        .map(|s| CString::new(s.as_str()).unwrap())
        .collect();

    let Err(e) = unistd::execvp(&c_argv[0], &c_argv);
    let code = if e == nix::errno::Errno::ENOENT {
        127
    } else {
        126
    };
    eprintln!("Couldn't execute '{}': {e}", argv[0]);
    process::exit(code);
}
