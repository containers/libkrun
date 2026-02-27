use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::os::unix::io::AsRawFd;
use std::os::unix::net::UnixDatagram;
use std::path::Path;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use nix::sys::socket::{recvfrom, sendto, MsgFlags, UnixAddr};

use crate::IpVersion;

trait DatagramSocket: Send + Sized + 'static {
    type Addr: Clone + Send;
    fn send_to(&self, buf: &[u8], addr: Self::Addr) -> std::io::Result<usize>;
    fn recv_from(&self, buf: &mut [u8]) -> std::io::Result<(usize, Self::Addr)>;

    fn run_server(self) {
        let mut buf = [0u8; 64];

        let (len, client_addr) = self.recv_from(&mut buf).expect("recv_from failed");
        assert_eq!(len, 5);
        assert_eq!(&buf[..len], b"ping!");

        assert_eq!(self.send_to(b"pong!", client_addr.clone()).unwrap(), 5);

        let (len, _) = self.recv_from(&mut buf).expect("recv_from failed");
        assert_eq!(len, 4);
        assert_eq!(&buf[..len], b"bye!");
    }

    fn run_client(self, server_addr: Self::Addr) {
        let mut buf = [0u8; 64];

        assert_eq!(self.send_to(b"ping!", server_addr.clone()).unwrap(), 5);

        let (len, _) = self.recv_from(&mut buf).expect("recv_from failed");
        assert_eq!(len, 5);
        assert_eq!(&buf[..len], b"pong!");

        assert_eq!(self.send_to(b"bye!", server_addr).unwrap(), 4);
    }
}

impl DatagramSocket for UdpSocket {
    type Addr = SocketAddr;
    fn send_to(&self, buf: &[u8], addr: SocketAddr) -> std::io::Result<usize> {
        UdpSocket::send_to(self, buf, addr)
    }
    fn recv_from(&self, buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
        UdpSocket::recv_from(self, buf)
    }
}

impl DatagramSocket for UnixDatagram {
    type Addr = UnixAddr;
    fn send_to(&self, buf: &[u8], addr: UnixAddr) -> std::io::Result<usize> {
        sendto(self.as_raw_fd(), buf, &addr, MsgFlags::empty())
            .map_err(|e| std::io::Error::from_raw_os_error(e as i32))
    }
    fn recv_from(&self, buf: &mut [u8]) -> std::io::Result<(usize, UnixAddr)> {
        let (size, addr_opt) = recvfrom::<UnixAddr>(self.as_raw_fd(), buf)
            .map_err(|e| std::io::Error::from_raw_os_error(e as i32))?;
        let addr = addr_opt.ok_or_else(|| std::io::Error::other("No source address"))?;
        Ok((size, addr))
    }
}

fn udp_bind(ip_version: IpVersion, port: u16) -> UdpSocket {
    let addr = match ip_version {
        IpVersion::V4 => SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
        IpVersion::V6 => SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), port),
    };
    let socket = UdpSocket::bind(addr).expect("Failed to bind socket");
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    socket
}

fn unix_bind(path: &Path) -> UnixDatagram {
    let _ = std::fs::remove_file(path);
    let socket = UnixDatagram::bind(path).expect("Failed to bind socket");
    socket
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    socket
}

pub fn spawn_server_udp(ip_version: IpVersion, port: u16) -> JoinHandle<()> {
    let socket = udp_bind(ip_version, port);
    thread::spawn(move || socket.run_server())
}

pub fn spawn_client_udp(ip_version: IpVersion, port: u16) -> JoinHandle<()> {
    thread::spawn(move || {
        let socket = udp_bind(ip_version, 0);
        let server_addr = match ip_version {
            IpVersion::V4 => SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
            IpVersion::V6 => SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), port),
        };
        socket.run_client(server_addr);
    })
}

pub fn spawn_server_unix(path: impl AsRef<Path> + Send + 'static) -> JoinHandle<()> {
    let socket = unix_bind(path.as_ref());
    thread::spawn(move || socket.run_server())
}

pub fn spawn_client_unix(
    server_path: impl AsRef<Path> + Send + 'static,
    client_path: impl AsRef<Path> + Send + 'static,
) -> JoinHandle<()> {
    let server_path = server_path.as_ref().to_path_buf();
    let client_path = client_path.as_ref().to_path_buf();
    thread::spawn(move || {
        let socket = unix_bind(&client_path);
        socket.run_client(UnixAddr::new(&server_path).expect("Invalid server path"));
    })
}
