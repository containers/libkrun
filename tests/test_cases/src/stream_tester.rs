use std::io::{ErrorKind, Read, Write};
use std::net::{
    IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, TcpListener, TcpStream,
};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use crate::IpVersion;

trait StreamSocket: Read + Write + Send + Sized + 'static {
    fn set_nonblocking(&self, nonblocking: bool) -> std::io::Result<()>;

    fn expect_msg(&mut self, expected: &[u8]) {
        let mut buf = vec![0; expected.len()];
        self.read_exact(&mut buf[..]).unwrap();
        assert_eq!(&buf[..], expected);
    }

    fn expect_wouldblock(&mut self) {
        self.set_nonblocking(true).unwrap();
        let err = self.read(&mut [0u8; 1]).unwrap_err();
        self.set_nonblocking(false).unwrap();
        assert_eq!(err.kind(), ErrorKind::WouldBlock);
    }

    fn run_server(mut self) {
        self.expect_msg(b"ping!");
        self.expect_wouldblock();
        self.write_all(b"pong!").unwrap();
        self.flush().unwrap();
        self.expect_msg(b"bye!");
        std::mem::forget(self);
    }

    fn run_client(mut self) {
        self.write_all(b"ping!").unwrap();
        self.flush().unwrap();
        self.expect_msg(b"pong!");
        self.expect_wouldblock();
        self.write_all(b"bye!").unwrap();
        self.flush().unwrap();
    }
}

impl StreamSocket for TcpStream {
    fn set_nonblocking(&self, nonblocking: bool) -> std::io::Result<()> {
        TcpStream::set_nonblocking(self, nonblocking)
    }
}

impl StreamSocket for UnixStream {
    fn set_nonblocking(&self, nonblocking: bool) -> std::io::Result<()> {
        UnixStream::set_nonblocking(self, nonblocking)
    }
}

fn tcp_bind(ip_version: IpVersion, port: u16) -> TcpListener {
    match ip_version {
        IpVersion::V4 => TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port)),
        IpVersion::V6 => TcpListener::bind(SocketAddrV6::new(Ipv6Addr::LOCALHOST, port, 0, 0)),
    }
    .expect("Failed to bind server socket")
}

fn connect_with_retry<T>(mut connect: impl FnMut() -> std::io::Result<T>) -> T {
    for attempt in 1..=5 {
        match connect() {
            Ok(stream) => return stream,
            Err(err) if attempt == 5 => panic!("Couldn't connect after 5 attempts: {err}"),
            Err(_) => thread::sleep(Duration::from_secs(1)),
        }
    }
    unreachable!()
}

pub fn spawn_server_tcp(ip_version: IpVersion, port: u16) -> JoinHandle<()> {
    let listener = tcp_bind(ip_version, port);
    thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        stream.run_server();
    })
}

pub fn spawn_client_tcp(ip_version: IpVersion, port: u16) -> JoinHandle<()> {
    thread::spawn(move || {
        let addr = match ip_version {
            IpVersion::V4 => SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
            IpVersion::V6 => SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), port),
        };
        connect_with_retry(|| TcpStream::connect(addr)).run_client();
    })
}

pub fn spawn_server_unix(path: impl AsRef<Path> + Send + 'static) -> JoinHandle<()> {
    let path = path.as_ref().to_path_buf();
    let _ = std::fs::remove_file(&path);
    let listener = UnixListener::bind(&path).expect("Failed to bind server socket");
    thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        stream.run_server();
    })
}

pub fn spawn_client_unix(path: impl AsRef<Path> + Send + 'static) -> JoinHandle<()> {
    let path = path.as_ref().to_path_buf();
    thread::spawn(move || {
        connect_with_retry(|| UnixStream::connect(&path)).run_client();
    })
}
