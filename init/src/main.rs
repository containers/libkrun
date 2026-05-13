mod config;
#[cfg(target_os = "linux")]
mod dhcp;
mod env;
mod exec;
#[cfg(target_os = "freebsd")]
mod freebsd;
#[cfg(target_os = "linux")]
mod fs;
#[cfg(feature = "timesync")]
mod timesync;

fn main() -> anyhow::Result<()> {
    #[cfg(target_os = "freebsd")]
    freebsd::open_console();

    #[cfg(target_os = "freebsd")]
    freebsd::populate_env_from_kenv();

    #[cfg(any(feature = "amd-sev", feature = "tdx"))]
    fs::mount_tee_block_device()?;

    #[cfg(target_os = "linux")]
    {
        fs::mount_filesystems()?;
        fs::mount_block_root_device()?;
        fs::mount_shared_root()?;
    }

    unsafe {
        libc::setsid();
        libc::ioctl(0, libc::TIOCSCTTY as _, 1i32);
    }

    #[cfg(target_os = "freebsd")]
    unsafe {
        libc::setlogin(b"root\0".as_ptr().cast())
    };

    env::setup_network(
        #[cfg(target_os = "linux")]
        "eth0",
    );

    #[cfg(target_os = "freebsd")]
    let iso_mounted = std::env::var("KRUN_CONFIG").is_err() && freebsd::mount_config_iso();

    #[cfg(target_os = "linux")]
    let cfg = config::load(fs::is_mount_point);
    #[cfg(not(target_os = "linux"))]
    let cfg = config::load();

    #[cfg(target_os = "freebsd")]
    if iso_mounted {
        freebsd::unmount_config_iso();
    }

    #[cfg(target_os = "linux")]
    if let Some(ref path) = cfg.tmpfs {
        fs::mount_tmpfs(path)?;
    }

    env::apply_env();
    env::apply_hostname();
    env::apply_rlimits();

    if let Some(ref workdir) = std::env::var("KRUN_WORKDIR").ok().or(cfg.workdir) {
        let _ = nix::unistd::chdir(workdir.as_str());
    }

    // The kernel places everything after `--` in the cmdline as this
    // process's argv[1..].  The C init built exec_argv by replacing argv[0]
    // with KRUN_INIT (or /bin/sh) and keeping argv[1..] in every branch.
    let proc_args: Vec<String> = std::env::args().collect();

    let argv: Vec<String> = if let Ok(init) = std::env::var("KRUN_INIT") {
        // KRUN_INIT holds the binary; kernel cmdline args are the arguments.
        let mut v = vec![init];
        v.extend_from_slice(&proc_args[1..]);
        v
    } else if let Some(v) = cfg.argv {
        v
    } else if proc_args.len() > 1 {
        // No KRUN_INIT and no config: treat proc_args[1..] as the command.
        proc_args.into_iter().skip(1).collect()
    } else {
        vec!["/bin/sh".to_string()]
    };

    #[cfg(feature = "timesync")]
    timesync::run();

    exec::run_workload(&argv);
}
