use nix::sys::socket::{recv, send, setsockopt, sockopt, MsgFlags};
use std::num::NonZeroUsize;
use std::os::fd::{AsRawFd, RawFd};
use vm_memory::VolatileMemory;

/// Each frame from passt is prepended by a 4 byte "header".
/// It is interpreted as a big-endian u32 integer and is the length of the following ethernet frame.
const PASST_HEADER_LEN: usize = 4;

#[derive(Debug)]
pub enum ReadError {
    /// Nothing was written
    NothingRead,
    /// Another internal error occurred
    Internal(nix::Error),
}

#[derive(Debug)]
pub enum WriteError {
    /// Nothing was written, you can drop the frame or try to resend it later
    NothingWritten,
    /// Part of the buffer was written, the write has to be finished using try_finish_write
    PartialWrite,
    /// Passt doesnt seem to be running (received EPIPE)
    ProcessNotRunning,
    /// Another internal error occurred
    Internal(nix::Error),
}

pub struct Passt {
    fd: RawFd,
    // 0 when a frame length has not been read
    expecting_frame_length: u32,
    last_partial_write_length: Option<NonZeroUsize>,
}

impl Passt {
    /// Connect to a running passt instance, given a socket file descriptor
    pub fn new(passt_fd: RawFd) -> Self {
        if let Err(e) = setsockopt(passt_fd, sockopt::SndBuf, &(16 * 1024 * 1024)) {
            log::warn!("Failed to increase SO_SNDBUF (performance may be decreased): {e}");
        }

        Self {
            fd: passt_fd,
            expecting_frame_length: 0,
            last_partial_write_length: None,
        }
    }

    /// Try to read a frame from passt. If no bytes are available reports PasstError::WouldBlock
    pub fn read_frame(&mut self, buf: &mut [u8]) -> Result<usize, ReadError> {
        if self.expecting_frame_length == 0 {
            self.expecting_frame_length = {
                let mut frame_length_buf = [0u8; PASST_HEADER_LEN];
                self.read_loop(&mut frame_length_buf, false)?;
                u32::from_be_bytes(frame_length_buf)
            };
        }

        let frame_length = self.expecting_frame_length as usize;
        self.read_loop(&mut buf[..frame_length], false)?;
        self.expecting_frame_length = 0;
        log::trace!("Read eth frame from passt: {} bytes", frame_length);
        Ok(frame_length)
    }

    /// Try to write a frame to passt.
    /// (Will mutate and override parts of buf, with a passt header!)
    ///
    /// * `hdr_len` - specifies the size of any existing headers encapsulating the ethernet frame,
    ///               (such as vnet header), that can be overwritten.
    ///               must be >= PASST_HEADER_LEN
    /// * `buf` - the buffer to write to passt, `buf[..hdr_len]` may be overwritten
    ///
    /// If this function returns WriteError::PartialWrite, you have to finish the write using
    /// try_finish_write.
    pub fn write_frame(&mut self, hdr_len: usize, buf: &mut [u8]) -> Result<(), WriteError> {
        if self.last_partial_write_length.is_some() {
            panic!("Cannot write a frame to passt, while a partial write is not resolved.");
        }
        assert!(
            hdr_len >= PASST_HEADER_LEN,
            "Not enough space to write passt header"
        );
        assert!(buf.len() > hdr_len);
        let frame_length = buf.len() - hdr_len;

        buf[hdr_len - PASST_HEADER_LEN..hdr_len]
            .copy_from_slice(&(frame_length as u32).to_be_bytes());

        self.write_loop(&buf[hdr_len - PASST_HEADER_LEN..])?;
        Ok(())
    }

    pub fn has_unfinished_write(&self) -> bool {
        self.last_partial_write_length.is_some()
    }

    /// Try to finish a partial write
    ///
    /// If no partial write is required will do nothing and return Ok(())
    ///
    /// * `hdr_len` - must be the same value as passed to write_frame, that caused the partial write
    /// * `buf` - must be same buffer that was given to write_frame, that caused the partial write
    pub fn try_finish_write(&mut self, hdr_len: usize, buf: &[u8]) -> Result<(), WriteError> {
        if let Some(written_bytes) = self.last_partial_write_length {
            log::trace!("Requested to finish partial write");
            self.write_loop(&buf[hdr_len - PASST_HEADER_LEN + written_bytes.get()..])?;
            log::debug!(
                "Finished partial write ({}bytes written before)",
                written_bytes.get()
            )
        }

        Ok(())
    }

    pub fn raw_socket_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }

    /// Try to read until filling the whole slice.
    /// May return WouldBlock only if the first read fails
    fn read_loop(&self, buf: &mut [u8], block_until_has_data: bool) -> Result<(), ReadError> {
        let mut bytes_read = 0;

        if !block_until_has_data {
            match recv(
                self.fd,
                buf,
                MsgFlags::MSG_DONTWAIT | MsgFlags::MSG_NOSIGNAL,
            ) {
                Ok(size) => bytes_read += size,
                #[allow(unreachable_patterns)]
                Err(nix::Error::EAGAIN | nix::Error::EWOULDBLOCK) => {
                    return Err(ReadError::NothingRead)
                }
                Err(e) => return Err(ReadError::Internal(e)),
            }
        }

        while bytes_read < buf.len() {
            match recv(
                self.fd,
                &mut buf[bytes_read..],
                MsgFlags::MSG_WAITALL | MsgFlags::MSG_NOSIGNAL,
            ) {
                #[allow(unreachable_patterns)]
                Err(nix::Error::EAGAIN | nix::Error::EWOULDBLOCK) => {
                    log::warn!("read_loop: unexpected EAGAIN/EWOULDBLOCK on blocking socket");
                    continue;
                }
                Err(e) => return Err(ReadError::Internal(e)),
                Ok(size) => {
                    bytes_read += size;
                    //log::trace!("passt recv {}/{}", bytes_read, buf.len());
                }
            }
        }

        Ok(())
    }

    fn write_loop(&mut self, buf: &[u8]) -> Result<(), WriteError> {
        let mut bytes_send = 0;

        while bytes_send < buf.len() {
            match send(
                self.fd,
                buf,
                MsgFlags::MSG_DONTWAIT | MsgFlags::MSG_NOSIGNAL,
            ) {
                Ok(size) => bytes_send += size,
                #[allow(unreachable_patterns)]
                Err(nix::Error::EAGAIN | nix::Error::EWOULDBLOCK) => {
                    if bytes_send == 0 {
                        return Err(WriteError::NothingWritten);
                    } else {
                        log::trace!(
                            "Wrote {} bytes, but socket blocked, will need try_finish_write() to finish",
                            bytes_send
                        );
                        self.last_partial_write_length = Some(bytes_send.try_into().unwrap());
                        return Err(WriteError::PartialWrite);
                    }
                }
                Err(nix::Error::EPIPE) => return Err(WriteError::ProcessNotRunning),
                Err(e) => return Err(WriteError::Internal(e)),
            }
        }
        self.last_partial_write_length = None;
        Ok(())
    }
}
