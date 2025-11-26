use crate::IpVersion;
use macros::{guest, host};
use std::thread::JoinHandle;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    Tcp {
        ip: IpVersion,
        port: u16,
    },
    Udp {
        ip: IpVersion,
        port: u16,
    },
    UnixStream {
        path: &'static str,
    },
    UnixDgram {
        server_path: &'static str,
        client_path: &'static str,
    },
}

impl Transport {
    fn spawn_server(&self, root: impl AsRef<std::path::Path>) -> JoinHandle<()> {
        use crate::{datagram_tester, stream_tester};
        let root = root.as_ref();
        match self {
            Transport::Tcp { ip, port } => stream_tester::spawn_server_tcp(*ip, *port),
            Transport::Udp { ip, port } => datagram_tester::spawn_server_udp(*ip, *port),
            Transport::UnixStream { path } => {
                stream_tester::spawn_server_unix(root.join(&path[1..]))
            }
            Transport::UnixDgram { server_path, .. } => {
                datagram_tester::spawn_server_unix(root.join(&server_path[1..]))
            }
        }
    }

    fn spawn_client(&self, root: impl AsRef<std::path::Path>) -> JoinHandle<()> {
        use crate::{datagram_tester, stream_tester};
        let root = root.as_ref();
        match self {
            Transport::Tcp { ip, port } => stream_tester::spawn_client_tcp(*ip, *port),
            Transport::Udp { ip, port } => datagram_tester::spawn_client_udp(*ip, *port),
            Transport::UnixStream { path } => {
                stream_tester::spawn_client_unix(root.join(&path[1..]))
            }
            Transport::UnixDgram {
                server_path,
                client_path,
            } => datagram_tester::spawn_client_unix(
                root.join(&server_path[1..]),
                root.join(&client_path[1..]),
            ),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum At {
    Host,
    Guest,
}

pub struct TestTsi {
    transport: Transport,
    server_at: At,
    client_at: At,
}

impl TestTsi {
    pub fn new(transport: Transport, server_at: At, client_at: At) -> Self {
        Self {
            transport,
            server_at,
            client_at,
        }
    }
}

#[host]
mod host {
    use super::*;
    use crate::common::setup_fs_and_enter;
    use crate::{krun_call, krun_call_u32};
    use crate::{Test, TestSetup};
    use krun_sys::*;
    use std::ffi::CString;
    use std::ptr::null;

    impl Test for TestTsi {
        fn start_vm(self: Box<Self>, test_setup: TestSetup) -> anyhow::Result<()> {
            let root = test_setup.tmp_dir.join("root");

            if self.server_at == At::Host {
                self.transport.spawn_server(&root);
            }
            if self.client_at == At::Host {
                self.transport.spawn_client(&root);
            }

            unsafe {
                krun_call!(krun_set_log_level(KRUN_LOG_LEVEL_TRACE))?;
                let ctx = krun_call_u32!(krun_create_ctx())?;

                // TCP with server in guest and client on host needs port mapping
                if let Transport::Tcp { port, .. } = self.transport {
                    if self.server_at == At::Guest && self.client_at == At::Host {
                        let port_mapping = format!("{port}:{port}");
                        let port_mapping = CString::new(port_mapping).unwrap();
                        let port_map = [port_mapping.as_ptr(), null()];
                        krun_call!(krun_set_port_map(ctx, port_map.as_ptr()))?;
                    }
                }

                krun_call!(krun_set_vm_config(ctx, 1, 512))?;
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

    impl Test for TestTsi {
        fn in_guest(self: Box<Self>) {
            let server_handle =
                (self.server_at == At::Guest).then(|| self.transport.spawn_server("/"));
            let client_handle =
                (self.client_at == At::Guest).then(|| self.transport.spawn_client("/"));

            // Wait for whichever side runs in guest to complete
            if let Some(handle) = client_handle {
                handle.join().unwrap();
            } else if let Some(handle) = server_handle {
                handle.join().unwrap();
            }

            println!("OK");
        }
    }
}
