// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::mem;
use std::os::unix::io::AsFd;
use std::os::unix::io::AsRawFd;
use std::os::unix::io::FromRawFd;
use std::os::unix::io::OwnedFd;

use libc::c_int;
use nix::errno::Errno;
use nix::sys::epoll::EpollCreateFlags;
use nix::sys::epoll::EpollFlags;
use nix::sys::epoll::EpollOp;
use nix::Result;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(transparent)]
pub struct EpollEvent {
    event: libc::epoll_event,
}

impl EpollEvent {
    pub fn new(events: EpollFlags, data: u64) -> Self {
        EpollEvent {
            event: libc::epoll_event {
                events: events.bits() as u32,
                u64: data,
            },
        }
    }

    pub fn empty() -> Self {
        unsafe { mem::zeroed::<EpollEvent>() }
    }

    pub fn events(&self) -> EpollFlags {
        EpollFlags::from_bits(self.event.events as c_int).unwrap()
    }

    pub fn data(&self) -> u64 {
        self.event.u64
    }
}

// This is a function is unreleased nix 0.27 -- when it is released, we can delete this.
#[derive(Debug)]
pub struct Epoll(pub OwnedFd);
impl Epoll {
    /// Creates a new epoll instance and returns a file descriptor referring to that instance.
    ///
    /// [`epoll_create1`](https://man7.org/linux/man-pages/man2/epoll_create1.2.html).
    pub fn new(flags: EpollCreateFlags) -> Result<Self> {
        let res = unsafe { libc::epoll_create1(flags.bits()) };
        let fd = Errno::result(res)?;
        let owned_fd = unsafe { OwnedFd::from_raw_fd(fd) };
        Ok(Self(owned_fd))
    }
    /// Add an entry to the interest list of the epoll file descriptor for
    /// specified in events.
    ///
    /// [`epoll_ctl`](https://man7.org/linux/man-pages/man2/epoll_ctl.2.html) with `EPOLL_CTL_ADD`.
    pub fn add<Fd: AsFd>(&self, fd: Fd, mut event: EpollEvent) -> Result<()> {
        self.epoll_ctl(EpollOp::EpollCtlAdd, fd, &mut event)
    }
    /// Remove (deregister) the target file descriptor `fd` from the interest list.
    ///
    /// [`epoll_ctl`](https://man7.org/linux/man-pages/man2/epoll_ctl.2.html) with `EPOLL_CTL_DEL` .
    pub fn delete<Fd: AsFd>(&self, fd: Fd) -> Result<()> {
        self.epoll_ctl(EpollOp::EpollCtlDel, fd, None)
    }
    /// Change the settings associated with `fd` in the interest list to the new settings specified
    /// in `event`.
    ///
    /// [`epoll_ctl`](https://man7.org/linux/man-pages/man2/epoll_ctl.2.html) with `EPOLL_CTL_MOD`.
    #[allow(dead_code)]
    pub fn modify<Fd: AsFd>(&self, fd: Fd, event: &mut EpollEvent) -> Result<()> {
        self.epoll_ctl(EpollOp::EpollCtlMod, fd, event)
    }
    /// Waits for I/O events, blocking the calling thread if no events are currently available.
    /// (This can be thought of as fetching items from the ready list of the epoll instance.)
    ///
    /// [`epoll_wait`](https://man7.org/linux/man-pages/man2/epoll_wait.2.html)
    pub fn wait(&self, events: &mut [EpollEvent], timeout: isize) -> Result<usize> {
        let res = unsafe {
            libc::epoll_wait(
                self.0.as_raw_fd(),
                events.as_mut_ptr() as *mut libc::epoll_event,
                events.len() as c_int,
                timeout as c_int,
            )
        };

        Errno::result(res).map(|r| r as usize)
    }
    /// This system call is used to add, modify, or remove entries in the interest list of the epoll
    /// instance referred to by `self`. It requests that the operation `op` be performed for the
    /// target file descriptor, `fd`.
    ///
    /// When possible prefer [`Epoll::add`], [`Epoll::delete`] and [`Epoll::modify`].
    ///
    /// [`epoll_ctl`](https://man7.org/linux/man-pages/man2/epoll_ctl.2.html)
    fn epoll_ctl<'a, Fd: AsFd, T>(&self, op: EpollOp, fd: Fd, event: T) -> Result<()>
    where
        T: Into<Option<&'a mut EpollEvent>>,
    {
        let event: Option<&mut EpollEvent> = event.into();
        let ptr = event
            .map(|x| &mut x.event as *mut libc::epoll_event)
            .unwrap_or(std::ptr::null_mut());
        unsafe {
            Errno::result(libc::epoll_ctl(
                self.0.as_raw_fd(),
                op as c_int,
                fd.as_fd().as_raw_fd(),
                ptr,
            ))
            .map(drop)
        }
    }
}
