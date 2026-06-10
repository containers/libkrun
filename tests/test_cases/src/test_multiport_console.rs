use macros::{guest, host};

pub struct TestMultiportConsole;

#[host]
mod host {
    use super::*;

    use crate::common::setup_rootfs;
    use crate::{Test, TestSetup};
    use anyhow::Context;
    use krun::{
        BalloonDevice, ConsoleDevice, FsDevice, InitConfig, Krunfw, MmioDeviceManager, RngDevice,
        VmmBuilder,
    };
    use std::io::{BufRead, BufReader, Write};
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixStream;
    use std::{mem, thread};

    fn spawn_ping_pong_responder(stream: UnixStream) {
        thread::spawn(move || {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut writer = stream;
            let mut line = String::new();
            while reader.read_line(&mut line).is_ok() && !line.is_empty() {
                let response = line.replace("PING", "PONG");
                writer.write_all(response.as_bytes()).unwrap();
                writer.flush().unwrap();
                line.clear();
            }
        });
    }

    fn add_ping_pong_port(
        console_builder: &mut krun::ConsoleBuilder<'_>,
        name: &str,
    ) -> anyhow::Result<()> {
        let (guest, host) = UnixStream::pair()?;
        console_builder
            .add_io_port(name, Some(guest.as_raw_fd()), Some(guest.as_raw_fd()))
            .context("add port")?;
        mem::forget(guest);
        spawn_ping_pong_responder(host);
        Ok(())
    }

    impl Test for TestMultiportConsole {
        fn start_vm(self: Box<Self>, test_setup: TestSetup) -> anyhow::Result<()> {
            let root_dir = setup_rootfs(&test_setup)?;

            let mut rootfs =
                FsDevice::new("/dev/root", root_dir.to_str().context("non-UTF8 path")?)
                    .context("create rootfs")?;
            let config = InitConfig::builder()
                .args(&["/guest-agent", &test_setup.test_case])
                .workdir("/")
                .build();
            rootfs.inject(&config.guest_files());

            // Single console device with:
            //   - init stdio redirect ports
            //   - three named ping-pong ports
            let mut console_builder = ConsoleDevice::builder();
            console_builder.add_console_port("", krun::port_io::output_to_log(log::Level::Info));
            console_builder
                .add_io_port("krun-stdin", Some(libc::STDIN_FILENO), None)
                .context("add stdin port")?;
            console_builder
                .add_io_port("krun-stdout", None, Some(libc::STDOUT_FILENO))
                .context("add stdout port")?;
            console_builder
                .add_io_port("krun-stderr", None, Some(libc::STDERR_FILENO))
                .context("add stderr port")?;
            add_ping_pong_port(&mut console_builder, "test-port-alpha")?;
            add_ping_pong_port(&mut console_builder, "test-port-beta")?;
            add_ping_pong_port(&mut console_builder, "test-port-gamma")?;
            let console = console_builder.build().context("build console")?;

            let payload = Krunfw::load();

            let mut devices = MmioDeviceManager::new();
            devices.add(rootfs);
            devices.add(console);
            devices.add(BalloonDevice::new().context("balloon")?);
            devices.add(RngDevice::new().context("rng")?);

            let mut vmm = VmmBuilder::new()
                .vcpus(1)
                .context("vcpus")?
                .ram_mib(1024)
                .context("ram")?
                .payload(payload)
                .devices(devices)
                .build()
                .context("build vmm")?;
            vmm.run();
            Ok(())
        }
    }
}

#[guest]
mod guest {
    use super::*;
    use crate::Test;
    use std::fs;
    use std::io::{BufRead, BufReader, Write};

    fn test_port(port_map: &std::collections::HashMap<String, String>, name: &str, message: &str) {
        let device_path = format!("/dev/{}", port_map.get(name).unwrap());
        let mut port = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&device_path)
            .unwrap();

        port.write_all(message.as_bytes()).unwrap();
        port.flush().unwrap();

        let mut reader = BufReader::new(port);
        let mut response = String::new();
        reader.read_line(&mut response).unwrap();

        let expected = message.replace("PING", "PONG").to_string();
        assert_eq!(response, expected, "{}: wrong response", name);
    }

    impl Test for TestMultiportConsole {
        fn in_guest(self: Box<Self>) {
            let ports_dir = "/sys/class/virtio-ports";

            let mut port_map = std::collections::HashMap::new();

            for entry in fs::read_dir(ports_dir).unwrap() {
                let entry = entry.unwrap();
                let port_name_path = entry.path().join("name");

                if port_name_path.exists() {
                    let port_name = fs::read_to_string(&port_name_path)
                        .unwrap()
                        .trim()
                        .to_string();

                    if !port_name.is_empty() {
                        let device_name = entry.file_name().to_string_lossy().to_string();
                        port_map.insert(port_name, device_name);
                    }
                }
            }

            assert!(
                port_map.contains_key("krun-stdout"),
                "krun-stdout not found"
            );
            assert!(
                port_map.contains_key("test-port-alpha"),
                "test-port-alpha not found"
            );
            assert!(
                port_map.contains_key("test-port-beta"),
                "test-port-beta not found"
            );
            assert!(
                port_map.contains_key("test-port-gamma"),
                "test-port-gamma not found"
            );

            // 7 ports: default console + stdin, stdout, stderr + 3 ping-pong
            // (default console has empty name, won't be in port_map)
            assert_eq!(port_map.len(), 6);

            test_port(&port_map, "test-port-alpha", "PING-ALPHA\n");
            test_port(&port_map, "test-port-beta", "PING-BETA\n");
            test_port(&port_map, "test-port-gamma", "PING-GAMMA\n");

            println!("OK");
        }
    }
}
