use macros::{guest, host};

pub struct TestVirtioRtc;

/// Printed by the guest if its kernel has no virtio-rtc driver.
const SKIP_OUTPUT: &str = "SKIP\n";

#[host]
mod host {
    use super::*;

    use crate::common::setup_and_run;
    use crate::{ShouldRun, Test, TestOutcome, TestSetup};

    impl Test for TestVirtioRtc {
        fn should_run(&self) -> ShouldRun {
            #[cfg(feature = "dynamic-linking")]
            if crate::common::require_vm_symbols().is_err() {
                return ShouldRun::No("core VM symbols not available");
            }
            ShouldRun::Yes
        }

        fn start_vm(self: Box<Self>, test_setup: TestSetup) -> anyhow::Result<()> {
            // The virtio-rtc device is attached to every VM.
            setup_and_run(1, 256, test_setup)
        }

        fn check(self: Box<Self>, stdout: Vec<u8>, _test_setup: TestSetup) -> TestOutcome {
            let output = String::from_utf8(stdout).unwrap();
            match output.as_str() {
                "OK\n" => TestOutcome::Pass,
                SKIP_OUTPUT => TestOutcome::Skip("guest kernel has no virtio-rtc driver"),
                _ => TestOutcome::Fail(format!("expected exactly {:?}, got {:?}", "OK\n", output)),
            }
        }
    }
}

#[guest]
mod guest {
    use super::*;
    use crate::Test;
    use std::fs;
    use std::path::Path;

    /// `VIRTIO_ID_CLOCK`.
    const VIRTIO_ID_CLOCK: u32 = 17;

    /// The PTP clock names that the guest driver gives to the clocks of the
    /// device: "Virtio PTP type <clock type>/variant <smearing>".
    const PTP_CLOCK_NAMES: [(&str, &str); 3] = [
        ("Virtio PTP type 3/variant 0", "UTC"),
        ("Virtio PTP type 1/variant 0", "TAI"),
        ("Virtio PTP type 2/variant 0", "monotonic"),
    ];

    fn read_trimmed(path: &Path) -> String {
        fs::read_to_string(path)
            .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()))
            .trim()
            .to_string()
    }

    /// The directory of the virtio device with `VIRTIO_ID_CLOCK`.
    fn find_clock_device() -> Option<std::path::PathBuf> {
        for entry in fs::read_dir("/sys/bus/virtio/devices").expect("virtio sysfs is missing") {
            let device = entry.expect("failed to read virtio device entry").path();
            let id = read_trimmed(&device.join("device"));
            let id = u32::from_str_radix(id.trim_start_matches("0x"), 16).unwrap();
            if id == VIRTIO_ID_CLOCK {
                return Some(device);
            }
        }
        None
    }

    fn ptp_clock_names() -> Vec<String> {
        let Ok(entries) = fs::read_dir("/sys/class/ptp") else {
            return Vec::new();
        };
        entries
            .map(|entry| read_trimmed(&entry.unwrap().path().join("clock_name")))
            .collect()
    }

    /// Clocks are found by name: the numbering of the PTP devices depends on
    /// which other PTP drivers the kernel has (e.g. the KVM clock).
    fn check_ptp_clocks() {
        let names = ptp_clock_names();
        for (name, clock) in PTP_CLOCK_NAMES {
            assert!(
                names.iter().any(|n| n == name),
                "the {clock} PTP clock {name:?} is missing, found {names:?}"
            );
        }
    }

    /// The RTC of the device is found through the virtio device that is its
    /// parent in sysfs: the number of the RTC depends on the other RTCs.
    fn check_rtc(device: &Path) {
        let device = fs::canonicalize(device).unwrap();
        let rtc = fs::read_dir("/sys/class/rtc")
            .expect("RTC sysfs is missing")
            .map(|entry| fs::canonicalize(entry.unwrap().path()).unwrap())
            .find(|rtc| rtc.starts_with(&device))
            .unwrap_or_else(|| panic!("no RTC below {}", device.display()));

        // The RTC reads the clock of the host.
        let since_epoch: u64 = read_trimmed(&rtc.join("since_epoch")).parse().unwrap();
        assert!(since_epoch > 1_700_000_000, "RTC time: {since_epoch}");
    }

    impl Test for TestVirtioRtc {
        fn in_guest(self: Box<Self>) {
            let device = find_clock_device().expect("no virtio-rtc device (virtio id 17)");
            if !device.join("driver").exists() {
                // Not a failure of the device: the kernel cannot use it.
                print!("{SKIP_OUTPUT}");
                return;
            }

            let features = read_trimmed(&device.join("features"));
            // One character per negotiated feature bit, bit 0 first. The
            // number of bits depends on the kernel.
            assert!(features.len() >= 64, "features: {features:?}");
            // Bit 0: alarm. Bit 28: indirect descriptors, which the device
            // does not offer.
            assert_eq!(&features[0..1], "1", "no alarm feature: {features}");
            assert_eq!(&features[28..29], "0", "indirect descriptors: {features}");

            check_ptp_clocks();
            check_rtc(&device);
            println!("OK");
        }
    }
}
