// Copyright 2021 Sergio Lopez. All rights reserved.
//
// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

//! Structure and wrapper functions emulating eventfd using a pipe.

use std::os::unix::io::{AsRawFd, RawFd};
use std::{io, mem, result};

use libc::{c_void, dup, fcntl, pipe, read, write, F_GETFL, F_SETFL, O_NONBLOCK};

pub const EFD_NONBLOCK: i32 = 1;

fn set_nonblock(fd: RawFd) -> result::Result<(), io::Error> {
    let flags = unsafe { fcntl(fd, F_GETFL) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }

    let ret = unsafe { fcntl(fd, F_SETFL, flags | O_NONBLOCK) };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(())
}

#[derive(Debug)]
pub struct EventFd {
    read_fd: RawFd,
    write_fd: RawFd,
}

impl EventFd {
    pub fn new(flag: i32) -> result::Result<EventFd, io::Error> {
        let mut fds: [RawFd; 2] = [0, 0];
        let ret = unsafe { pipe(&mut fds[0]) };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }

        if flag == EFD_NONBLOCK {
            set_nonblock(fds[0])?;
            set_nonblock(fds[1])?;
        }

        Ok(EventFd {
            read_fd: fds[0],
            write_fd: fds[1],
        })
    }

    pub fn write(&self, v: u64) -> result::Result<(), io::Error> {
        let ret = unsafe {
            write(
                self.write_fd,
                &v as *const u64 as *const c_void,
                mem::size_of::<u64>(),
            )
        };
        if ret <= 0 {
            let error = io::Error::last_os_error();
            match error.kind() {
                // We may get EAGAIN if the eventfd is overstimulated, but we can safely
                // ignore it as we can be sure the subscriber will get notified.
                io::ErrorKind::WouldBlock => Ok(()),
                _ => Err(error),
            }
        } else {
            Ok(())
        }
    }

    pub fn read(&self) -> result::Result<u64, io::Error> {
        let mut buf: u64 = 0;
        let ret = unsafe {
            read(
                self.read_fd,
                &mut buf as *mut u64 as *mut c_void,
                mem::size_of::<u64>(),
            )
        };
        if ret < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(buf)
        }
    }

    pub fn try_clone(&self) -> result::Result<EventFd, io::Error> {
        let read_fd = unsafe { dup(self.read_fd) };
        if read_fd < 0 {
            return Err(io::Error::last_os_error());
        }

        let write_fd = unsafe { dup(self.write_fd) };
        if write_fd < 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(EventFd { read_fd, write_fd })
    }

    pub fn get_write_fd(&self) -> RawFd {
        self.write_fd
    }
}

impl AsRawFd for EventFd {
    fn as_raw_fd(&self) -> RawFd {
        self.read_fd
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new() {
        EventFd::new(EFD_NONBLOCK).unwrap();
        EventFd::new(0).unwrap();
    }

    #[test]
    fn test_read_write() {
        let evt = EventFd::new(EFD_NONBLOCK).unwrap();
        evt.write(55).unwrap();
        assert_eq!(evt.read().unwrap(), 55);
    }

    #[test]
    fn test_write_overflow() {
        let evt = EventFd::new(EFD_NONBLOCK).unwrap();
        evt.write(std::u64::MAX - 1).unwrap();
        let r = evt.write(1);
        match r {
            Err(ref inner) if inner.kind() == io::ErrorKind::WouldBlock => (),
            _ => panic!("Unexpected"),
        }
    }
    #[test]
    fn test_read_nothing() {
        let evt = EventFd::new(EFD_NONBLOCK).unwrap();
        let r = evt.read();
        match r {
            Err(ref inner) if inner.kind() == io::ErrorKind::WouldBlock => (),
            _ => panic!("Unexpected"),
        }
    }
    #[test]
    fn test_clone() {
        let evt = EventFd::new(EFD_NONBLOCK).unwrap();
        let evt_clone = evt.try_clone().unwrap();
        evt.write(923).unwrap();
        assert_eq!(evt_clone.read().unwrap(), 923);
    }
}
