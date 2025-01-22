use macros::{guest, host};

pub struct TestVmConfig {
    pub(crate) num_cpus: u8,
    pub(crate) ram_mib: u32,
}

#[host]
mod host {
    use super::*;

    use crate::common::setup_fs_and_enter;
    use crate::{krun_call, krun_call_u32};
    use crate::{Test, TestSetup};
    use krun_sys::*;

    impl Test for TestVmConfig {
        fn start_vm(self: Box<Self>, test_setup: TestSetup) -> anyhow::Result<()> {
            unsafe {
                let ctx = krun_call_u32!(krun_create_ctx())?;
                krun_call!(krun_set_vm_config(ctx, self.num_cpus, self.ram_mib))?;
                setup_fs_and_enter(ctx, test_setup)?;
            }
            Ok(())
        }
    }
}

#[guest]
mod guest {
    use super::*;
    use crate::Test;
    use std::fs;
    use std::fs::File;
    use std::io::{BufRead, BufReader};
    use std::str::FromStr;

    fn detect_num_cpus() -> u32 {
        let cpus = fs::read_to_string("/sys/devices/system/cpu/online").unwrap();
        let mut parts = cpus.split("-");
        let low = u32::from_str(parts.next().unwrap().trim()).unwrap();
        if let Some(high) = parts.next() {
            let high = u32::from_str(high.trim()).unwrap();
            high - low + 1
        } else {
            low + 1
        }
    }

    fn detect_ram_size_mib() -> u32 {
        let file = BufReader::new(File::open("/proc/meminfo").unwrap());

        for line in file.lines() {
            let line = line.expect("Could not read line");
            if line.starts_with("MemTotal:") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    let size_kb: u32 = parts[1].trim().parse().unwrap();
                    let size_mib = size_kb / 1024;
                    return size_mib;
                }
            }
        }
        panic!("MemTotal field not found");
    }

    impl Test for TestVmConfig {
        fn in_guest(self: Box<Self>) {
            assert_eq!(detect_num_cpus(), self.num_cpus as u32);

            let ram_avalible = detect_ram_size_mib();
            // Check if ram within 5percent of specifed
            assert!(self.ram_mib >= (ram_avalible as f64 * 0.95) as u32);
            assert!(self.ram_mib <= (ram_avalible as f64 * 1.05) as u32);
            println!("OK");
        }
    }
}
