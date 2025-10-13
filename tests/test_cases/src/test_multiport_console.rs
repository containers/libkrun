use macros::{guest, host};

pub struct TestMultiportConsole;

#[host]
mod host {
    use super::*;

    use crate::common::setup_fs_and_enter;
    use crate::{krun_call, krun_call_u32};
    use crate::{Test, TestSetup};
    use krun_sys::*;
    use std::ffi::CString;
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

    fn test_port(ctx: u32, console_id: u32, name: &str) -> anyhow::Result<()> {
        let (guest, host) = UnixStream::pair()?;
        let name_cstring = CString::new(name)?;
        unsafe {
            krun_call!(krun_add_console_port_inout(
                ctx,
                console_id,
                name_cstring.as_ptr(),
                guest.as_raw_fd(),
                guest.as_raw_fd()
            ))?;
        }
        mem::forget(guest);
        spawn_ping_pong_responder(host);
        Ok(())
    }

    impl Test for TestMultiportConsole {
        fn start_vm(self: Box<Self>, test_setup: TestSetup) -> anyhow::Result<()> {
            unsafe {
                krun_call!(krun_set_log_level(KRUN_LOG_LEVEL_WARN))?;
                let ctx = krun_call_u32!(krun_create_ctx())?;

                krun_call!(krun_disable_implicit_console(ctx))?;

                // Add a default console (as with other tests this uses stdout for writing "OK")
                krun_call!(krun_add_virtio_console_default(
                    ctx,
                    -1,
                    std::io::stdout().as_raw_fd(),
                    -1,
                ))?;

                let console_id = krun_call_u32!(krun_add_virtio_console_multiport(ctx))?;

                test_port(ctx, console_id, "test-port-alpha")?;
                test_port(ctx, console_id, "test-port-beta")?;
                test_port(ctx, console_id, "test-port-gamma")?;

                krun_call!(krun_set_vm_config(ctx, 1, 1024))?;
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

            // We shouldn't have any more than configured here
            assert_eq!(port_map.len(), 4);

            test_port(&port_map, "test-port-alpha", "PING-ALPHA\n");
            test_port(&port_map, "test-port-beta", "PING-BETA\n");
            test_port(&port_map, "test-port-gamma", "PING-GAMMA\n");

            println!("OK");
        }
    }
}
