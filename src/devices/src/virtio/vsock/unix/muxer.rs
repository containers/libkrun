// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//

use libc::unlink;
/// `VsockMuxer` is the device-facing component of the Unix domain sockets vsock backend. I.e.
/// by implementing the `VsockBackend` trait, it abstracts away the gory details of translating
/// between AF_VSOCK and AF_UNIX, and presents a clean interface to the rest of the vsock
/// device model.
///
/// The vsock muxer has two main roles:
/// 1. Vsock connection multiplexer:
///    It's the muxer's job to create, manage, and terminate `VsockConnection` objects. The
///    muxer also routes packets to their owning connections. It does so via a connection
///    `HashMap`, keyed by what is basically a (host_port, guest_port) tuple.
///    Vsock packet traffic needs to be inspected, in order to detect connection request
///    packets (leading to the creation of a new connection), and connection reset packets
///    (leading to the termination of an existing connection). All other packets, though, must
///    belong to an existing connection and, as such, the muxer simply forwards them.
/// 2. Event dispatcher
///    There are three event categories that the vsock backend is interested it:
///    1. A new host-initiated connection is ready to be accepted from the listening host Unix
///       socket;
///    2. Data is available for reading from a newly-accepted host-initiated connection (i.e.
///       the host is ready to issue a vsock connection request, informing us of the
///       destination port to which it wants to connect);
///    3. Some event was triggered for a connected Unix socket, that belongs to a
///       `VsockConnection`.
///    The muxer gets notified about all of these events, because, as a `VsockEpollListener`
///    implementor, it gets to register a nested epoll FD into the main VMM epolling loop. All
///    other pollable FDs are then registered under this nested epoll FD.
///    To route all these events to their handlers, the muxer uses another `HashMap` object,
///    mapping `RawFd`s to `EpollListener`s.
use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use std::net::Shutdown;
use std::net::{TcpListener, TcpStream};
use std::os::raw::c_char;
use std::os::unix::io::{AsRawFd, RawFd};
use std::os::unix::net::{UnixListener, UnixStream};

use utils::epoll::{ControlOperation, Epoll, EpollEvent, EventSet};

use super::super::csm::{CommonStream, ConnState, Error as CsmError};
use super::super::defs::uapi;
use super::super::packet::VsockPacket;
use super::super::{
    Result as VsockResult, VsockBackend, VsockChannel, VsockEpollListener, VsockError,
};
use super::defs;
use super::muxer_killq::MuxerKillQ;
use super::muxer_rxq::MuxerRxQ;
use super::MuxerConnection;
use super::{Error, Result};

impl CommonStream for UnixStream {
    fn get_write_buf(&self) -> Option<Vec<u8>> {
        None
    }

    fn cs_shutdown(&self, how: Shutdown) -> std::result::Result<(), CsmError> {
        self.shutdown(how).map_err(CsmError::StreamWrite)
    }
}
impl CommonStream for TcpStream {
    fn get_write_buf(&self) -> Option<Vec<u8>> {
        None
    }

    fn cs_shutdown(&self, how: Shutdown) -> std::result::Result<(), CsmError> {
        self.shutdown(how).map_err(CsmError::StreamWrite)
    }
}

/// A unique identifier of a `MuxerConnection` object. Connections are stored in a hash map,
/// keyed by a `ConnMapKey` object.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ConnMapKey {
    local_port: u32,
    peer_port: u32,
}

/// A muxer RX queue item.
#[derive(Debug)]
pub enum MuxerRx {
    /// The packet must be fetched from the connection identified by `ConnMapKey`.
    ConnRx(ConnMapKey),
    /// The muxer must produce an RST packet.
    RstPkt { local_port: u32, peer_port: u32 },
}

/// An epoll listener, registered under the muxer's nested epoll FD.
enum EpollListener {
    /// The listener is a `MuxerConnection`, identified by `key`, and interested in the events
    /// in `evset`. Since `MuxerConnection` implements `VsockEpollListener`, notifications will
    /// be forwarded to the listener via `VsockEpollListener::notify()`.
    Connection {
        key: ConnMapKey,
        evset: EventSet,
    },

    WrapUnix {
        port: u32,
        listener: UnixListener,
    },

    WrapTcp {
        port: u32,
        listener: TcpListener,
    },
}

/// The vsock connection multiplexer.
pub struct VsockMuxer {
    /// Guest CID.
    cid: u64,
    /// A hash map used to store the active UNIX connections.
    conn_map: HashMap<ConnMapKey, MuxerConnection>,
    /// A hash map used to store epoll event listeners / handlers.
    listener_map: HashMap<RawFd, EpollListener>,
    /// A hash map used to store wrapped listeners.
    wrap_map: HashMap<u32, RawFd>,
    /// An optional hash map with host to guest port mappings.
    host_port_map: Option<HashMap<u16, u16>>,
    /// The RX queue. Items in this queue are consumed by `VsockMuxer::recv_pkt()`, and
    /// produced
    /// - by `VsockMuxer::send_pkt()` (e.g. RST in response to a connection request packet);
    ///   and
    /// - in response to EPOLLIN events (e.g. data available to be read from an AF_UNIX
    ///   socket).
    rxq: MuxerRxQ,
    /// A queue used for terminating connections that are taking too long to shut down.
    killq: MuxerKillQ,
    /// The nested epoll event set, used to register epoll listeners.
    epoll: Epoll,
    /// A hash set used to keep track of used host-side (local) ports, in order to assign local
    /// ports to host-initiated connections.
    local_port_set: HashSet<u32>,
    /// The last used host-side port.
    local_port_last: u32,
}

impl VsockChannel for VsockMuxer {
    /// Deliver a vsock packet to the guest vsock driver.
    ///
    /// Retuns:
    /// - `Ok(())`: `pkt` has been successfully filled in; or
    /// - `Err(VsockError::NoData)`: there was no available data with which to fill in the
    ///   packet.
    fn recv_pkt(&mut self, pkt: &mut VsockPacket) -> VsockResult<()> {
        // We'll look for instructions on how to build the RX packet in the RX queue. If the
        // queue is empty, that doesn't necessarily mean we don't have any pending RX, since
        // the queue might be out-of-sync. If that's the case, we'll attempt to sync it first,
        // and then try to pop something out again.
        if self.rxq.is_empty() && !self.rxq.is_synced() {
            self.rxq = MuxerRxQ::from_conn_map(&self.conn_map);
        }

        while let Some(rx) = self.rxq.pop() {
            let res = match rx {
                // We need to build an RST packet, going from `local_port` to `peer_port`.
                MuxerRx::RstPkt {
                    local_port,
                    peer_port,
                } => {
                    pkt.set_op(uapi::VSOCK_OP_RST)
                        .set_src_cid(uapi::VSOCK_HOST_CID)
                        .set_dst_cid(self.cid)
                        .set_src_port(local_port)
                        .set_dst_port(peer_port)
                        .set_len(0)
                        .set_type(uapi::VSOCK_TYPE_STREAM)
                        .set_flags(0)
                        .set_buf_alloc(0)
                        .set_fwd_cnt(0);
                    return Ok(());
                }

                // We'll defer building the packet to this connection, since it has something
                // to say.
                MuxerRx::ConnRx(key) => {
                    let mut conn_res = Err(VsockError::NoData);
                    self.apply_conn_mutation(key, |conn| {
                        conn_res = conn.recv_pkt(pkt);
                    });
                    conn_res
                }
            };

            if res.is_ok() {
                // Inspect traffic, looking for RST packets, since that means we have to
                // terminate and remove this connection from the active connection pool.
                //
                if pkt.op() == uapi::VSOCK_OP_RST {
                    self.remove_connection(ConnMapKey {
                        local_port: pkt.src_port(),
                        peer_port: pkt.dst_port(),
                    });
                }

                debug!("vsock muxer: RX pkt: {:?}", pkt.hdr());
                return Ok(());
            }
        }

        Err(VsockError::NoData)
    }

    /// Deliver a guest-generated packet to its destination in the vsock backend.
    ///
    /// This absorbs unexpected packets, handles RSTs (by dropping connections), and forwards
    /// all the rest to their owning `MuxerConnection`.
    ///
    /// Returns:
    /// always `Ok(())` - the packet has been consumed, and its virtio TX buffers can be
    /// returned to the guest vsock driver.
    fn send_pkt(&mut self, pkt: &VsockPacket) -> VsockResult<()> {
        let conn_key = ConnMapKey {
            local_port: pkt.dst_port(),
            peer_port: pkt.src_port(),
        };

        debug!(
            "vsock: muxer.send[rxq.len={}]: {:?}",
            self.rxq.len(),
            pkt.hdr()
        );

        // We don't know how to handle packets addressed to other CIDs. We only handle the host
        // part of the guest - host communication here.
        if pkt.dst_cid() != uapi::VSOCK_HOST_CID {
            info!(
                "vsock: dropping guest packet for unknown CID: {:?}",
                pkt.hdr()
            );
            return Ok(());
        }

        if !self.conn_map.contains_key(&conn_key) {
            // This packet can't be routed to any active connection (based on its src and dst
            // ports).  The only orphan / unroutable packets we know how to handle are
            // connection requests.
            match pkt.op() {
                uapi::VSOCK_OP_REQUEST_EX => {
                    // A connection request with extended parameters
                    self.handle_peer_request_ex_pkt(pkt)
                        .unwrap_or_else(|_| self.enq_rst(pkt.dst_port(), pkt.src_port()))
                }
                uapi::VSOCK_OP_WRAP_LISTEN => {
                    // A listen request for wrapped socket with extended parameters
                    self.handle_peer_wrap_listen(pkt)
                        .unwrap_or_else(|_| self.enq_rst(pkt.dst_port(), pkt.src_port()))
                }
                uapi::VSOCK_OP_WRAP_CLOSE => {
                    // A close request for wrapped socket
                    self.handle_peer_wrap_close(pkt);
                }
                _ => {
                    // Send back an RST, to let the drive know we weren't expecting this packet.
                    self.enq_rst(pkt.dst_port(), pkt.src_port());
                }
            }
            return Ok(());
        }

        // Right, we know where to send this packet, then (to `conn_key`).
        // However, if this is an RST, we have to forcefully terminate the connection, so
        // there's no point in forwarding it the packet.
        if pkt.op() == uapi::VSOCK_OP_RST {
            self.remove_connection(conn_key);
            return Ok(());
        }

        // Alright, everything looks in order - forward this packet to its owning connection.
        let mut res: VsockResult<()> = Ok(());
        self.apply_conn_mutation(conn_key, |conn| {
            res = conn.send_pkt(pkt);
        });

        res
    }

    /// Check if the muxer has any pending RX data, with which to fill a guest-provided RX
    /// buffer.
    fn has_pending_rx(&self) -> bool {
        !self.rxq.is_empty() || !self.rxq.is_synced()
    }
}

impl AsRawFd for VsockMuxer {
    /// Get the FD to be registered for polling upstream (in the main VMM epoll loop, in this
    /// case).
    ///
    /// This will be the muxer's nested epoll FD.
    fn as_raw_fd(&self) -> RawFd {
        self.epoll.as_raw_fd()
    }
}

impl VsockEpollListener for VsockMuxer {
    /// Get the epoll events to be polled upstream.
    ///
    /// Since the polled FD is a nested epoll FD, we're only interested in EPOLLIN events (i.e.
    /// some event occured on one of the FDs registered under our epoll FD).
    fn get_polled_evset(&self) -> EventSet {
        EventSet::IN
    }

    /// Notify the muxer about a pending event having occured under its nested epoll FD.
    fn notify(&mut self, _: EventSet) {
        debug!("vsock: muxer received kick");

        let mut epoll_events = vec![EpollEvent::new(EventSet::empty(), 0); 32];
        match self
            .epoll
            .wait(epoll_events.len(), 0, epoll_events.as_mut_slice())
        {
            Ok(ev_cnt) => {
                for ev in &epoll_events[0..ev_cnt] {
                    self.handle_event(
                        ev.fd(),
                        // It's ok to unwrap here, since the `epoll_events[i].events` is filled
                        // in by `epoll::wait()`, and therefore contains only valid epoll
                        // flags.
                        EventSet::from_bits(ev.events).unwrap(),
                    );
                }
            }
            Err(e) => {
                warn!("vsock: failed to consume muxer epoll event: {}", e);
            }
        }
    }
}

impl VsockBackend for VsockMuxer {}

impl VsockMuxer {
    /// Muxer constructor.
    pub fn new(cid: u64, host_port_map: Option<HashMap<u16, u16>>) -> Result<Self> {
        #[allow(unused_mut)]
        let mut epoll = Epoll::new().map_err(Error::EpollFdCreate)?;
        #[cfg(target_os = "macos")]
        epoll.disable_clears();

        let muxer = Self {
            cid,
            epoll,
            rxq: MuxerRxQ::new(),
            conn_map: HashMap::with_capacity(defs::MAX_CONNECTIONS),
            listener_map: HashMap::with_capacity(defs::MAX_CONNECTIONS + 1),
            wrap_map: HashMap::with_capacity(defs::MAX_CONNECTIONS),
            host_port_map,
            killq: MuxerKillQ::new(),
            local_port_last: (1u32 << 30) - 1,
            local_port_set: HashSet::with_capacity(defs::MAX_CONNECTIONS),
        };

        Ok(muxer)
    }

    /// Handle/dispatch an epoll event to its listener.
    fn handle_event(&mut self, fd: RawFd, evset: EventSet) {
        debug!(
            "vsock: muxer processing event: fd={}, evset={:?}",
            fd, evset
        );

        match self.listener_map.get_mut(&fd) {
            // This event needs to be forwarded to a `MuxerConnection` that is listening for
            // it.
            Some(EpollListener::Connection { key, evset }) => {
                let key_copy = *key;
                let evset_copy = *evset;
                // The handling of this event will most probably mutate the state of the
                // receiving conection. We'll need to check for new pending RX, event set
                // mutation, and all that, so we're wrapping the event delivery inside those
                // checks.
                self.apply_conn_mutation(key_copy, |conn| {
                    conn.notify(evset_copy);
                });
            }

            Some(EpollListener::WrapTcp { port, listener }) => {
                let peer_port = *port;

                debug!("WrapTcp: peer_port {}", peer_port);

                listener
                    .accept()
                    .map_err(Error::UnixAccept)
                    .and_then(|(stream, _)| {
                        stream
                            .set_nonblocking(true)
                            .map(|_| stream)
                            .map_err(Error::WrapUnixAccept)
                    })
                    .and_then(|stream| {
                        stream
                            .set_nodelay(true)
                            .map(|_| stream)
                            .map_err(Error::WrapUnixAccept)
                    })
                    .and_then(|stream| {
                        let local_port = self.allocate_local_port();
                        self.add_connection(
                            ConnMapKey {
                                local_port,
                                peer_port,
                            },
                            MuxerConnection::new_local_wrap_init(
                                Box::new(stream) as Box<dyn CommonStream>,
                                uapi::VSOCK_HOST_CID,
                                self.cid,
                                local_port,
                                peer_port,
                            ),
                        )
                    })
                    .unwrap_or_else(|err| {
                        warn!("vsock: unable to accept wrapped TCP connection: {:?}", err);
                    });
            }

            Some(EpollListener::WrapUnix { port, listener }) => {
                let peer_port = *port;

                listener
                    .accept()
                    .map_err(Error::UnixAccept)
                    .and_then(|(stream, _)| {
                        stream
                            .set_nonblocking(true)
                            .map(|_| stream)
                            .map_err(Error::WrapUnixAccept)
                    })
                    .and_then(|stream| {
                        let local_port = self.allocate_local_port();
                        self.add_connection(
                            ConnMapKey {
                                local_port,
                                peer_port,
                            },
                            MuxerConnection::new_local_wrap_init(
                                Box::new(stream) as Box<dyn CommonStream>,
                                uapi::VSOCK_HOST_CID,
                                self.cid,
                                local_port,
                                peer_port,
                            ),
                        )
                    })
                    .unwrap_or_else(|err| {
                        warn!("vsock: unable to accept wrapped unix connection: {:?}", err);
                    });
            }
            _ => {
                info!("vsock: unexpected event: fd={:?}, evset={:?}", fd, evset);
            }
        }
    }

    /// Add a new connection to the active connection pool.
    fn add_connection(&mut self, key: ConnMapKey, conn: MuxerConnection) -> Result<()> {
        // We might need to make room for this new connection, so let's sweep the kill queue
        // first.  It's fine to do this here because:
        // - unless the kill queue is out of sync, this is a pretty inexpensive operation; and
        // - we are under no pressure to respect any accurate timing for connection
        //   termination.
        self.sweep_killq();

        if self.conn_map.len() >= defs::MAX_CONNECTIONS {
            info!(
                "vsock: muxer connection limit reached ({})",
                defs::MAX_CONNECTIONS
            );
            return Err(Error::TooManyConnections);
        }

        self.add_listener(
            conn.as_raw_fd(),
            EpollListener::Connection {
                key,
                evset: conn.get_polled_evset(),
            },
        )
        .map(|_| {
            if conn.has_pending_rx() {
                // We can safely ignore any error in adding a connection RX indication. Worst
                // case scenario, the RX queue will get desynchronized, but we'll handle that
                // the next time we need to yield an RX packet.
                self.rxq.push(MuxerRx::ConnRx(key));
            }
            self.conn_map.insert(key, conn);
        })
    }

    /// Remove a connection from the active connection poll.
    fn remove_connection(&mut self, key: ConnMapKey) {
        if let Some(conn) = self.conn_map.remove(&key) {
            self.remove_listener(conn.as_raw_fd());
        }
        self.free_local_port(key.local_port);
    }

    /// Schedule a connection for immediate termination.
    /// I.e. as soon as we can also let our peer know we're dropping the connection, by sending
    /// it an RST packet.
    fn kill_connection(&mut self, key: ConnMapKey) {
        let mut had_rx = false;
        self.conn_map.entry(key).and_modify(|conn| {
            had_rx = conn.has_pending_rx();
            conn.kill();
        });
        // This connection will now have an RST packet to yield, so we need to add it to the RX
        // queue.  However, there's no point in doing that if it was already in the queue.
        if !had_rx {
            // We can safely ignore any error in adding a connection RX indication. Worst case
            // scenario, the RX queue will get desynchronized, but we'll handle that the next
            // time we need to yield an RX packet.
            self.rxq.push(MuxerRx::ConnRx(key));
        }
    }

    /// Register a new epoll listener under the muxer's nested epoll FD.
    fn add_listener(&mut self, fd: RawFd, listener: EpollListener) -> Result<()> {
        let evset = match listener {
            EpollListener::Connection { evset, .. } => evset,
            EpollListener::WrapUnix { .. } => EventSet::IN,
            EpollListener::WrapTcp { .. } => EventSet::IN,
        };

        self.epoll
            .ctl(
                ControlOperation::Add,
                fd,
                &EpollEvent::new(evset, fd as u64),
            )
            .map(|_| {
                self.listener_map.insert(fd, listener);
            })
            .map_err(Error::EpollAdd)?;

        Ok(())
    }

    /// Remove (and return) a previously registered epoll listener.
    fn remove_listener(&mut self, fd: RawFd) -> Option<EpollListener> {
        let maybe_listener = self.listener_map.remove(&fd);

        if maybe_listener.is_some() {
            self.epoll
                .ctl(ControlOperation::Delete, fd, &EpollEvent::default())
                .unwrap_or_else(|err| {
                    warn!(
                        "vosck muxer: error removing epoll listener for fd {:?}: {:?}",
                        fd, err
                    );
                });
        }

        maybe_listener
    }

    /// Allocate a host-side port to be assigned to a new host-initiated connection.
    fn allocate_local_port(&mut self) -> u32 {
        // TODO: this doesn't seem very space-efficient.
        // Mybe rewrite this to limit port range and use a bitmap?
        //

        loop {
            self.local_port_last = (self.local_port_last + 1) & !(1 << 31) | (1 << 30);
            if self.local_port_set.insert(self.local_port_last) {
                break;
            }
        }
        self.local_port_last
    }

    /// Mark a previously used host-side port as free.
    fn free_local_port(&mut self, port: u32) {
        self.local_port_set.remove(&port);
    }

    fn handle_peer_request_ex_pkt(&mut self, pkt: &VsockPacket) -> Result<()> {
        match pkt.sa_family() {
            Some(uapi::AF_INET) => {
                let port = pkt.inet_port().ok_or(Error::AddressInvalidPort)?;
                let ipv4_addr = Ipv4Addr::from(pkt.inet_addr().ok_or(Error::AddressInvalidIpv4)?);

                debug!("vsock ports src={} dst={}", pkt.src_port(), pkt.dst_port());
                debug!("should connect to {}:{}", ipv4_addr, port);

                TcpStream::connect(format!("{}:{}", ipv4_addr, port))
                    .and_then(|stream| stream.set_nonblocking(true).map(|_| stream))
                    .map_err(Error::TcpConnect)
                    .and_then(|stream| {
                        self.add_connection(
                            ConnMapKey {
                                local_port: pkt.dst_port(),
                                peer_port: pkt.src_port(),
                            },
                            MuxerConnection::new_peer_wrap_init(
                                Box::new(stream) as Box<dyn CommonStream>,
                                uapi::VSOCK_HOST_CID,
                                self.cid,
                                pkt.dst_port(),
                                pkt.src_port(),
                                pkt.buf_alloc(),
                            ),
                        )
                    })
            }
            Some(uapi::AF_UNIX) => {
                let path = pkt.unix_path().ok_or(Error::AddressInvalidPath)?;

                debug!("should connect to unix socket at: {:?}", path);
                UnixStream::connect(path)
                    .and_then(|stream| stream.set_nonblocking(true).map(|_| stream))
                    .map_err(Error::UnixConnect)
                    .and_then(|stream| {
                        self.add_connection(
                            ConnMapKey {
                                local_port: pkt.dst_port(),
                                peer_port: pkt.src_port(),
                            },
                            MuxerConnection::new_peer_init(
                                Box::new(stream) as Box<dyn CommonStream>,
                                uapi::VSOCK_HOST_CID,
                                self.cid,
                                pkt.dst_port(),
                                pkt.src_port(),
                                pkt.buf_alloc(),
                            ),
                        )
                    })
            }
            Some(_) => {
                debug!("unknown sa_family");
                Err(Error::AddressInvalidFamily)
            }
            None => {
                debug!("invalid buffer");
                Err(Error::AddressInvalidBuffer)
            }
        }
    }

    fn handle_peer_wrap_listen(&mut self, pkt: &VsockPacket) -> Result<()> {
        match pkt.sa_family() {
            Some(uapi::AF_INET) => {
                let guest_port = pkt.inet_port().ok_or(Error::AddressInvalidPort)?;
                let ipv4_addr = Ipv4Addr::from(pkt.inet_addr().ok_or(Error::AddressInvalidIpv4)?);

                let port = if let Some(port_map) = &self.host_port_map {
                    match port_map.get(&guest_port) {
                        Some(host_port) => *host_port,
                        None => return Err(Error::WrapTcpPortMap),
                    }
                } else {
                    guest_port
                };

                debug!("vsock ports src={} dst={}", pkt.src_port(), pkt.dst_port());
                debug!("should listen at {}:{}", ipv4_addr, port);

                TcpListener::bind(format!("{}:{}", ipv4_addr, port))
                    .and_then(|sock| sock.set_nonblocking(true).map(|_| sock))
                    .map_err(Error::WrapTcpBind)
                    .and_then(|sock| {
                        let fd = sock.as_raw_fd();
                        self.add_listener(
                            fd,
                            EpollListener::WrapTcp {
                                port: pkt.src_port(),
                                listener: sock,
                            },
                        )?;
                        self.wrap_map.insert(pkt.src_port(), fd);
                        Ok(())
                    })
            }
            Some(uapi::AF_UNIX) => {
                let path = pkt.unix_path().ok_or(Error::AddressInvalidPath)?;

                debug!("should listen to unix socket at: {:?}", path);

                // HACK: FS is shared between VMM and guest, so if we don't
                // unlink() the path , the bind() will receive "AddrInUse"
                // error.
                let _ = unsafe { unlink(path.as_ptr() as *const c_char) };

                UnixListener::bind(&path)
                    .and_then(|sock| sock.set_nonblocking(true).map(|_| sock))
                    .map_err(Error::WrapUnixBind)
                    .and_then(|sock| {
                        let fd = sock.as_raw_fd();
                        self.add_listener(
                            fd,
                            EpollListener::WrapUnix {
                                port: pkt.src_port(),
                                listener: sock,
                            },
                        )?;
                        self.wrap_map.insert(pkt.src_port(), fd);
                        Ok(())
                    })
            }
            Some(_) => {
                debug!("unknown sa_family");
                Err(Error::AddressInvalidFamily)
            }
            None => {
                debug!("invalid buffer");
                Err(Error::AddressInvalidBuffer)
            }
        }
    }

    fn handle_peer_wrap_close(&mut self, pkt: &VsockPacket) {
        if let Some(fd) = self.wrap_map.remove(&pkt.src_port()) {
            self.remove_listener(fd);
        }
    }

    /// Perform an action that might mutate a connection's state.
    ///
    /// This is used as shorthand for repetitive tasks that need to be performed after a
    /// connection object mutates. E.g.
    /// - update the connection's epoll listener;
    /// - schedule the connection to be queried for RX data;
    /// - kill the connection if an unrecoverable error occurs.
    fn apply_conn_mutation<F>(&mut self, key: ConnMapKey, mut_fn: F)
    where
        F: FnOnce(&mut MuxerConnection),
    {
        if let Some(conn) = self.conn_map.get_mut(&key) {
            let had_rx = conn.has_pending_rx();
            let was_expiring = conn.will_expire();
            let prev_state = conn.state();

            mut_fn(conn);

            // If this is a host-initiated connection that has just become established, we'll have
            // to send an ack message to the host end.
            if prev_state == ConnState::LocalInit && conn.state() == ConnState::Established {
                conn.send_bytes(format!("OK {}\n", key.local_port).as_bytes())
                    .unwrap_or_else(|err| {
                        conn.kill();
                        warn!("vsock: unable to ack host connection: {:?}", err);
                    });
            }

            // If the connection wasn't previously scheduled for RX, add it to our RX queue.
            if !had_rx && conn.has_pending_rx() {
                self.rxq.push(MuxerRx::ConnRx(key));
            }

            // If the connection wasn't previously scheduled for termination, add it to the
            // kill queue.
            if !was_expiring && conn.will_expire() {
                // It's safe to unwrap here, since `conn.will_expire()` already guaranteed that
                // an `conn.expiry` is available.
                self.killq.push(key, conn.expiry().unwrap());
            }

            let fd = conn.as_raw_fd();
            let new_evset = conn.get_polled_evset();
            if new_evset.is_empty() {
                // If the connection no longer needs epoll notifications, remove its listener
                // from our list.
                self.remove_listener(fd);
                return;
            }
            if let Some(EpollListener::Connection { evset, .. }) = self.listener_map.get_mut(&fd) {
                if *evset != new_evset {
                    // If the set of events that the connection is interested in has changed,
                    // we need to update its epoll listener.
                    debug!(
                        "vsock: updating listener for (lp={}, pp={}): old={:?}, new={:?}",
                        key.local_port, key.peer_port, *evset, new_evset
                    );

                    *evset = new_evset;
                    self.epoll
                        .ctl(
                            ControlOperation::Modify,
                            fd,
                            &EpollEvent::new(new_evset, fd as u64),
                        )
                        .unwrap_or_else(|err| {
                            // This really shouldn't happen, like, ever. However, "famous last
                            // words" and all that, so let's just kill it with fire, and walk away.
                            self.kill_connection(key);
                            error!(
                                "vsock: error updating epoll listener for (lp={}, pp={}): {:?}",
                                key.local_port, key.peer_port, err
                            );
                        });
                }
            } else {
                // The connection had previously asked to be removed from the listener map (by
                // returning an empty event set via `get_polled_fd()`), but now wants back in.
                self.add_listener(
                    fd,
                    EpollListener::Connection {
                        key,
                        evset: new_evset,
                    },
                )
                .unwrap_or_else(|err| {
                    self.kill_connection(key);
                    error!(
                        "vsock: error updating epoll listener for (lp={}, pp={}): {:?}",
                        key.local_port, key.peer_port, err
                    );
                });
            }
        }
    }

    /// Check if any connections have timed out, and if so, schedule them for immediate
    /// termination.
    fn sweep_killq(&mut self) {
        while let Some(key) = self.killq.pop() {
            // Connections don't get removed from the kill queue when their kill timer is
            // disarmed, since that would be a costly operation. This means we must check if
            // the connection has indeed expired, prior to killing it.
            let mut kill = false;
            self.conn_map
                .entry(key)
                .and_modify(|conn| kill = conn.has_expired());
            if kill {
                self.kill_connection(key);
            }
        }

        if self.killq.is_empty() && !self.killq.is_synced() {
            self.killq = MuxerKillQ::from_conn_map(&self.conn_map);
            // If we've just re-created the kill queue, we can sweep it again; maybe there's
            // more to kill.
            self.sweep_killq();
        }
    }

    /// Enqueue an RST packet into `self.rxq`.
    ///
    /// Enqueue errors aren't propagated up the call chain, since there is nothing we can do to
    /// handle them. We do, however, log a warning, since not being able to enqueue an RST
    /// packet means we have to drop it, which is not normal operation.
    fn enq_rst(&mut self, local_port: u32, peer_port: u32) {
        let pushed = self.rxq.push(MuxerRx::RstPkt {
            local_port,
            peer_port,
        });
        if !pushed {
            warn!(
                "vsock: muxer.rxq full; dropping RST packet for lp={}, pp={}",
                local_port, peer_port
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::super::tests::TestContext as VsockTestContext;
    use super::*;

    use crate::virtio::vsock::device::RXQ_INDEX;

    const PEER_CID: u64 = 3;
    const PEER_BUF_ALLOC: u32 = 64 * 1024;

    struct MuxerTestContext {
        _vsock_test_ctx: VsockTestContext,
        pkt: VsockPacket,
        muxer: VsockMuxer,
    }

    impl MuxerTestContext {
        fn new() -> Self {
            let vsock_test_ctx = VsockTestContext::new();
            let mut handler_ctx = vsock_test_ctx.create_event_handler_context();
            let pkt = VsockPacket::from_rx_virtq_head(
                &handler_ctx.device.queues[RXQ_INDEX]
                    .pop(&vsock_test_ctx.mem)
                    .unwrap(),
            )
            .unwrap();

            let muxer = VsockMuxer::new(PEER_CID, None).unwrap();
            Self {
                _vsock_test_ctx: vsock_test_ctx,
                pkt,
                muxer,
            }
        }

        fn init_pkt(&mut self, local_port: u32, peer_port: u32, op: u16) -> &mut VsockPacket {
            for b in self.pkt.hdr_mut() {
                *b = 0;
            }
            self.pkt
                .set_type(uapi::VSOCK_TYPE_STREAM)
                .set_src_cid(PEER_CID)
                .set_dst_cid(uapi::VSOCK_HOST_CID)
                .set_src_port(peer_port)
                .set_dst_port(local_port)
                .set_op(op)
                .set_buf_alloc(PEER_BUF_ALLOC)
        }

        fn send(&mut self) {
            self.muxer.send_pkt(&self.pkt).unwrap();
        }

        fn recv(&mut self) {
            self.muxer.recv_pkt(&mut self.pkt).unwrap();
        }
    }

    #[test]
    fn test_muxer_epoll_listener() {
        let ctx = MuxerTestContext::new();
        assert_eq!(ctx.muxer.as_raw_fd(), ctx.muxer.epoll.as_raw_fd());
        assert_eq!(ctx.muxer.get_polled_evset(), EventSet::IN);
    }

    #[test]
    fn test_bad_peer_pkt() {
        const LOCAL_PORT: u32 = 1026;
        const PEER_PORT: u32 = 1025;
        const SOCK_DGRAM: u16 = 2;

        let mut ctx = MuxerTestContext::new();
        ctx.init_pkt(LOCAL_PORT, PEER_PORT, uapi::VSOCK_OP_REQUEST)
            .set_type(SOCK_DGRAM);
        ctx.send();

        // The guest sent a SOCK_DGRAM packet. Per the vsock spec, we need to reply with an RST
        // packet, since vsock only supports stream sockets.
        assert!(ctx.muxer.has_pending_rx());
        ctx.recv();
        assert_eq!(ctx.pkt.op(), uapi::VSOCK_OP_RST);
        assert_eq!(ctx.pkt.src_cid(), uapi::VSOCK_HOST_CID);
        assert_eq!(ctx.pkt.dst_cid(), PEER_CID);
        assert_eq!(ctx.pkt.src_port(), LOCAL_PORT);
        assert_eq!(ctx.pkt.dst_port(), PEER_PORT);

        // Any orphan (i.e. without a connection), non-RST packet, should be replied to with an
        // RST.
        let bad_ops = [
            uapi::VSOCK_OP_RESPONSE,
            uapi::VSOCK_OP_CREDIT_REQUEST,
            uapi::VSOCK_OP_CREDIT_UPDATE,
            uapi::VSOCK_OP_SHUTDOWN,
            uapi::VSOCK_OP_RW,
        ];
        for op in bad_ops.iter() {
            ctx.init_pkt(LOCAL_PORT, PEER_PORT, *op);
            ctx.send();
            assert!(ctx.muxer.has_pending_rx());
            ctx.recv();
            assert_eq!(ctx.pkt.op(), uapi::VSOCK_OP_RST);
            assert_eq!(ctx.pkt.src_port(), LOCAL_PORT);
            assert_eq!(ctx.pkt.dst_port(), PEER_PORT);
        }

        // Any packet addressed to anything other than VSOCK_VHOST_CID should get dropped.
        assert!(!ctx.muxer.has_pending_rx());
        ctx.init_pkt(LOCAL_PORT, PEER_PORT, uapi::VSOCK_OP_REQUEST)
            .set_dst_cid(uapi::VSOCK_HOST_CID + 1);
        ctx.send();
        assert!(!ctx.muxer.has_pending_rx());
    }
}
