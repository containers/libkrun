use std::io::{ErrorKind, Read, Write};
use std::mem;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

fn expect_msg(stream: &mut TcpStream, expected: &[u8]) {
    let mut buf = vec![0; expected.len()];
    stream.read_exact(&mut buf[..]).unwrap();
    assert_eq!(&buf[..], expected);
}

fn expect_wouldblock(stream: &mut TcpStream) {
    stream.set_nonblocking(true).unwrap();
    let err = stream.read(&mut [0u8; 1]).unwrap_err();
    stream.set_nonblocking(false).unwrap();
    assert_eq!(err.kind(), ErrorKind::WouldBlock);
}

fn set_timeouts(stream: &mut TcpStream) {
    stream
        .set_read_timeout(Some(Duration::from_millis(500)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_millis(500)))
        .unwrap();
}

fn connect(port: u16) -> TcpStream {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port);
    let mut tries = 0;
    loop {
        match TcpStream::connect(addr) {
            Ok(stream) => return stream,
            Err(err) => {
                if tries == 5 {
                    panic!("Couldn't connect to server after 5 attempts: {err}");
                }
                tries += 1;
                thread::sleep(Duration::from_secs(1));
            }
        }
    }
}

#[derive(Debug, Copy, Clone)]
pub struct TcpTester {
    port: u16,
}

impl TcpTester {
    pub const fn new(port: u16) -> Self {
        Self { port }
    }

    pub fn create_server_socket(&self) -> TcpListener {
        TcpListener::bind(SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), self.port)).unwrap()
    }

    pub fn run_server(&self, listener: TcpListener) {
        let (mut stream, _addr) = listener.accept().unwrap();
        set_timeouts(&mut stream);
        stream.write_all(b"ping!").unwrap();
        expect_msg(&mut stream, b"pong!");
        expect_wouldblock(&mut stream);
        stream.write_all(b"bye!").unwrap();
        // We leak the file descriptor for now, since there is no easy way to close it on libkrun exit
        mem::forget(listener);
    }

    pub fn run_client(&self) {
        let mut stream = connect(self.port);
        set_timeouts(&mut stream);
        expect_msg(&mut stream, b"ping!");
        expect_wouldblock(&mut stream);
        stream.write_all(b"pong!").unwrap();
        expect_msg(&mut stream, b"bye!");
    }
}
