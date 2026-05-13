use std::mem;

const TSYNC_PORT: u32 = 123;
const NANOS_IN_SECOND: u64 = 1_000_000_000;
const DELTA_SYNC: u64 = 100_000_000; // 100ms — don't bother adjusting for smaller drifts

pub fn run() {
    let sock = unsafe { libc::socket(libc::AF_VSOCK, libc::SOCK_DGRAM, 0) };
    if sock < 0 {
        return;
    }

    let mut addr: libc::sockaddr_vm = unsafe { mem::zeroed() };
    addr.svm_family = libc::AF_VSOCK as _;
    addr.svm_port = TSYNC_PORT;
    addr.svm_cid = libc::VMADDR_CID_ANY;

    if unsafe {
        libc::bind(
            sock,
            &addr as *const _ as *const libc::sockaddr,
            mem::size_of_val(&addr) as _,
        )
    } < 0
    {
        unsafe { libc::close(sock) };
        return;
    }

    std::thread::Builder::new()
        .name("timesync".into())
        .spawn(move || loop {
            let mut buf = [0u8; 8];
            let n = unsafe { libc::recv(sock, buf.as_mut_ptr() as *mut _, buf.len(), 0) };
            if n < 0 {
                break;
            }
            if n != 8 {
                continue;
            }

            let host_ns = u64::from_le_bytes(buf);

            let mut guest_ts: libc::timespec = unsafe { mem::zeroed() };
            unsafe { libc::clock_gettime(libc::CLOCK_REALTIME, &mut guest_ts) };
            let guest_ns = guest_ts.tv_sec as u64 * NANOS_IN_SECOND + guest_ts.tv_nsec as u64;

            if host_ns.abs_diff(guest_ns) > DELTA_SYNC {
                let host_ts = libc::timespec {
                    tv_sec: (host_ns / NANOS_IN_SECOND) as libc::time_t,
                    tv_nsec: (host_ns % NANOS_IN_SECOND) as libc::c_long,
                };
                unsafe { libc::clock_settime(libc::CLOCK_REALTIME, &host_ts) };
            }
        })
        .unwrap();
}
