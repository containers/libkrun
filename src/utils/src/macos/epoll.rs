// Copyright 2021 Sergio Lopez. All rights reserved.
//
// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::io;
use std::os::unix::io::{AsRawFd, RawFd};
use std::ptr;
use std::time::Duration;

use bitflags::bitflags;
use log::debug;

#[repr(i32)]
pub enum ControlOperation {
    Add,
    Modify,
    Delete,
}

bitflags! {
    pub struct EventSet: u32 {
        const IN = 0b00000001;
        const OUT = 0b00000010;
        const HANG_UP = 0b00000100;
        const READ_HANG_UP = 0b00001000;
        const EDGE_TRIGGERED = 0b00010000;
    }
}

#[repr(transparent)]
#[derive(Clone, Copy)]
pub struct Kevent(libc::kevent);

impl std::fmt::Debug for Kevent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{{ ident: {}, data: {} }}", self.ident(), self.data())
    }
}

impl Default for Kevent {
    fn default() -> Self {
        Kevent(libc::kevent {
            ident: 0,
            filter: 0,
            flags: 0,
            fflags: 0,
            data: 0,
            udata: ptr::null_mut(),
        })
    }
}

impl Kevent {
    pub fn new(ident: usize, filter: i16, flags: u16, udata: u64) -> Self {
        Kevent(libc::kevent {
            ident,
            filter,
            flags,
            fflags: 0,
            data: 0,
            udata: udata as *mut libc::c_void,
        })
    }

    pub fn ident(&self) -> usize {
        self.0.ident
    }

    pub fn data(&self) -> isize {
        self.0.data
    }

    pub fn udata(&self) -> u64 {
        self.0.udata as u64
    }
}

#[derive(Clone, Copy, Default)]
pub struct EpollEvent {
    pub events: u32,
    u64: u64,
}

impl std::fmt::Debug for EpollEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{{ events: {}, data: {} }}", self.events(), self.data())
    }
}

impl EpollEvent {
    pub fn new(events: EventSet, data: u64) -> Self {
        debug!("EpollEvent new: {}", data);
        EpollEvent {
            events: events.bits(),
            u64: data,
        }
    }

    pub fn events(&self) -> u32 {
        self.events
    }

    pub fn event_set(&self) -> EventSet {
        // This unwrap is safe because `epoll_events` can only be user created or
        // initialized by the kernel. We trust the kernel to only send us valid
        // events. The user can only initialize `epoll_events` using valid events.
        EventSet::from_bits(self.events()).unwrap()
    }

    pub fn data(&self) -> u64 {
        debug!("EpollEvent data: {}", self.u64);
        self.u64
    }

    pub fn fd(&self) -> RawFd {
        self.u64 as i32
    }
}

#[derive(Clone, Debug)]
pub struct Epoll {
    queue: RawFd,
}

impl Epoll {
    pub fn new() -> io::Result<Self> {
        let queue = unsafe { libc::kqueue() };
        if queue == -1 {
            Err(io::Error::last_os_error())
        } else {
            Ok(Epoll { queue })
        }
    }

    pub fn ctl(
        &self,
        operation: ControlOperation,
        fd: RawFd,
        event: &EpollEvent,
    ) -> io::Result<()> {
        let eset = EventSet::from_bits(event.events).unwrap();

        match operation {
            ControlOperation::Add | ControlOperation::Modify => {
                let mut kevs: Vec<Kevent> = Vec::new();
                let clear = if eset.contains(EventSet::EDGE_TRIGGERED) {
                    libc::EV_CLEAR
                } else {
                    0
                };
                if eset.contains(EventSet::IN) {
                    debug!("add fd in: {}", fd);
                    kevs.push(Kevent::new(
                        fd as usize,
                        libc::EVFILT_READ,
                        libc::EV_ADD | clear,
                        event.u64,
                    ));
                }
                if eset.contains(EventSet::OUT) {
                    debug!("add fd out: {}", fd);
                    kevs.push(Kevent::new(
                        fd as usize,
                        libc::EVFILT_WRITE,
                        libc::EV_ADD | clear,
                        event.u64,
                    ));
                }
                let ret = unsafe {
                    libc::kevent(
                        self.queue,
                        kevs.as_ptr() as *const libc::kevent,
                        kevs.len() as i32,
                        ptr::null_mut(),
                        0,
                        ptr::null(),
                    )
                };
                assert_eq!(ret, 0);
            }
            ControlOperation::Delete => {
                let mut kevs: Vec<Kevent> = Vec::new();
                if eset.bits() == 0 {
                    debug!("remove fd in and out: {}", fd);
                    kevs.push(Kevent::new(
                        fd as usize,
                        libc::EVFILT_READ,
                        libc::EV_DELETE,
                        event.u64,
                    ));
                    kevs.push(Kevent::new(
                        fd as usize,
                        libc::EVFILT_WRITE,
                        libc::EV_DELETE,
                        event.u64,
                    ));
                } else {
                    if eset.contains(EventSet::IN) {
                        debug!("remove fd in: {}", fd);
                        kevs.push(Kevent::new(
                            fd as usize,
                            libc::EVFILT_READ,
                            libc::EV_DELETE,
                            event.u64,
                        ));
                    }
                    if eset.contains(EventSet::OUT) {
                        debug!("remove fd out: {}", fd);
                        kevs.push(Kevent::new(
                            fd as usize,
                            libc::EVFILT_WRITE,
                            libc::EV_DELETE,
                            event.u64,
                        ));
                    }
                }
                let _ = unsafe {
                    libc::kevent(
                        self.queue,
                        kevs.as_ptr() as *const libc::kevent,
                        kevs.len() as i32,
                        ptr::null_mut(),
                        0,
                        ptr::null(),
                    )
                };
            }
        }
        Ok(())
    }

    pub fn wait(
        &self,
        max_events: usize,
        timeout: i32,
        events: &mut [EpollEvent],
    ) -> io::Result<usize> {
        let _tout = if timeout >= 0 {
            Some(Duration::from_millis(timeout as u64))
        } else {
            None
        };

        let ts = libc::timespec {
            tv_sec: 3,
            tv_nsec: 0,
        };

        let mut kevs = vec![Kevent::default(); events.len()];
        debug!("kevs len: {}", kevs.len());
        let ret = unsafe {
            libc::kevent(
                self.queue,
                ptr::null(),
                0,
                kevs.as_mut_ptr() as *mut libc::kevent,
                max_events as i32,
                &ts as *const libc::timespec,
            )
        };

        debug!("ret: {}", ret);

        for i in 0..ret {
            debug!("kev: {:?}", kevs[i as usize]);
            if kevs[i as usize].0.filter == libc::EVFILT_READ {
                events[i as usize].events = EventSet::IN.bits();
            } else if kevs[i as usize].0.filter == libc::EVFILT_WRITE {
                events[i as usize].events = EventSet::OUT.bits();
            }
            if kevs[i as usize].0.flags & libc::EV_EOF != 0 {
                events[i as usize].events |= if kevs[i as usize].0.flags & libc::EV_CLEAR != 0 {
                    EventSet::READ_HANG_UP.bits()
                } else {
                    EventSet::HANG_UP.bits()
                };
            }
            events[i as usize].u64 = kevs[i as usize].udata();
        }

        match ret {
            -1 => Err(io::Error::last_os_error()),
            0 => Ok(0),
            nev => Ok(nev as usize),
        }
    }
}

impl AsRawFd for Epoll {
    fn as_raw_fd(&self) -> RawFd {
        self.queue
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::eventfd::{EventFd, EFD_NONBLOCK};

    #[test]
    fn test_event_ops() {
        let mut event = EpollEvent::default();
        assert_eq!(event.events(), 0);
        assert_eq!(event.data(), 0);

        event = EpollEvent::new(EventSet::IN, 2);
        assert_eq!(event.events(), 1);
        assert_eq!(event.event_set(), EventSet::IN);

        assert_eq!(event.data(), 2);
        assert_eq!(event.fd(), 2);
    }

    #[test]
    fn test_events_debug() {
        let events = EpollEvent::new(EventSet::IN, 42);
        assert_eq!(format!("{:?}", events), "{ events: 1, data: 42 }")
    }

    #[test]
    fn test_epoll() {
        const DEFAULT__TIMEOUT: i32 = 250;
        const EVENT_BUFFER_SIZE: usize = 128;

        let epoll = Epoll::new().unwrap();
        assert_eq!(epoll.queue, epoll.as_raw_fd());

        // Let's test different scenarios for `epoll_ctl()` and `epoll_wait()` functionality.

        let event_fd_1 = EventFd::new(EFD_NONBLOCK).unwrap();
        // For EPOLLOUT to be available it is enough only to be possible to write a value of
        // at least 1 to the eventfd counter without blocking.
        // If we write a value greater than 0 to this counter, the fd will be available for
        // EPOLLIN events too.
        event_fd_1.write(1).unwrap();

        let event_1 = EpollEvent::new(EventSet::IN, event_fd_1.as_raw_fd() as u64);

        // For EPOLL_CTL_ADD behavior we will try to add some fds with different event masks into
        // the interest list of epoll instance.
        assert!(epoll
            .ctl(
                ControlOperation::Add,
                event_fd_1.as_raw_fd() as i32,
                event_1
            )
            .is_ok());

        let event_fd_2 = EventFd::new(EFD_NONBLOCK).unwrap();
        event_fd_2.write(1).unwrap();
        assert!(epoll
            .ctl(
                ControlOperation::Add,
                event_fd_2.as_raw_fd() as i32,
                // For this fd, we want an Event instance that has `data` field set to other
                // value than the value of the fd and `events` without EPOLLIN type set.
                EpollEvent::new(EventSet::IN, 10)
            )
            .is_ok());

        // Let's check `epoll_wait()` behavior for our epoll instance.
        let mut ready_events = vec![EpollEvent::default(); EVENT_BUFFER_SIZE];
        let mut ev_count = epoll.wait(DEFAULT__TIMEOUT, &mut ready_events[..]).unwrap();

        // We expect to have 3 fds in the ready list of epoll instance.
        assert_eq!(ev_count, 2);

        // Let's check also the Event values that are now returned in the ready list.
        assert_eq!(ready_events[0].data(), event_fd_1.as_raw_fd() as u64);
        assert_eq!(ready_events[1].data(), 10 as u64);

        // EPOLLIN and EPOLLOUT should be available for this fd.
        assert_eq!(ready_events[0].events(), EventSet::IN.bits());
        // Only EPOLLOUT is expected because we didn't want to monitor EPOLLIN on this fd.
        assert_eq!(ready_events[1].events(), EventSet::IN.bits());

        // Let's also delete a fd from the interest list.
        assert!(epoll
            .ctl(
                ControlOperation::Delete,
                event_fd_2.as_raw_fd() as i32,
                EpollEvent::default()
            )
            .is_ok());

        // We expect to have only one fd remained in the ready list (event_fd_3).
        ev_count = epoll.wait(DEFAULT__TIMEOUT, &mut ready_events[..]).unwrap();

        assert_eq!(ev_count, 1);
        assert_eq!(ready_events[0].data(), event_fd_1.as_raw_fd() as u64);
        assert_eq!(ready_events[0].events(), EventSet::IN.bits());
    }
}
