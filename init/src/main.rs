mod config;
#[cfg(target_os = "linux")]
mod dhcp;
mod env;
mod exec;
#[cfg(target_os = "linux")]
mod fs;

fn main() -> anyhow::Result<()> {
    #[cfg(any(feature = "amd-sev", feature = "tdx"))]
    fs::mount_tee_block_device()?;

    #[cfg(target_os = "linux")]
    {
        fs::mount_filesystems()?;
        fs::mount_block_root_device()?;
        fs::mount_shared_root()?;
    }

    let _ = nix::unistd::setsid();
    unsafe { libc::ioctl(0, libc::TIOCSCTTY as _, 1i32) };

    env::setup_network(
        #[cfg(target_os = "linux")]
        "eth0",
    );

    #[cfg(target_os = "linux")]
    let cfg = config::load(fs::is_mount_point);
    #[cfg(not(target_os = "linux"))]
    let cfg = config::load();

    #[cfg(target_os = "linux")]
    if let Some(ref path) = cfg.tmpfs {
        fs::mount_tmpfs(path)?;
    }

    env::apply_env();
    env::apply_hostname();
    env::apply_rlimits();

    if let Some(workdir) = std::env::var("KRUN_WORKDIR").ok().or(cfg.workdir)
        && let Err(e) = nix::unistd::chdir(workdir.as_str())
    {
        eprintln!("chdir to {workdir} failed: {e}");
        std::process::exit(125);
    }

    // The kernel places everything after `--` in the cmdline as this
    // process's argv[1..].  The C init built exec_argv by replacing argv[0]
    // with KRUN_INIT (or /bin/sh) and keeping argv[1..] in every branch.
    let proc_args: Vec<String> = std::env::args().collect();

    let argv: Vec<String> = if let Ok(init) = std::env::var("KRUN_INIT") {
        // KRUN_INIT holds the binary; kernel cmdline args are the arguments.
        let mut v = vec![init];
        v.extend_from_slice(proc_args.get(1..).unwrap_or_default());
        v
    } else if let Some(v) = cfg.argv {
        v
    } else if proc_args.len() > 1 {
        // No KRUN_INIT and no config: treat proc_args[1..] as the command.
        proc_args.into_iter().skip(1).collect()
    } else {
        vec!["/bin/sh".to_string()]
    };

    exec::run_workload(&argv);
}
