use crate::eventfd::{EventFd, EFD_NONBLOCK};
use std::collections::VecDeque;
use std::io;
use std::io::ErrorKind;
use std::os::fd::{AsRawFd, RawFd};
use std::sync::{Arc, Mutex};

/// A multiple producer single consumer channel that can be listened to by a file descriptor
pub fn pollable_channel<T: Send>(
) -> io::Result<(PollableChannelSender<T>, PollableChannelReciever<T>)> {
    let eventfd = EventFd::new(EFD_NONBLOCK)?;

    let inner = Arc::new(Inner {
        eventfd,
        queue: Mutex::new(VecDeque::new()),
    });
    let tx = PollableChannelSender {
        inner: inner.clone(),
    };
    let rx = PollableChannelReciever { inner };
    Ok((tx, rx))
}

struct Inner<T: Send> {
    eventfd: EventFd,
    queue: Mutex<VecDeque<T>>,
}

#[derive(Clone)]
pub struct PollableChannelSender<T: Send> {
    inner: Arc<Inner<T>>,
}

impl<T: Send> PollableChannelSender<T> {
    pub fn send(&self, msg: T) -> io::Result<()> {
        let mut data_lock = self.inner.queue.lock().expect("Poisoned mutex");
        data_lock.push_back(msg);
        self.inner.eventfd.write(1)?;
        Ok(())
    }
}

pub struct PollableChannelReciever<T: Send> {
    inner: Arc<Inner<T>>,
}

impl<T: Send> PollableChannelReciever<T> {
    pub fn try_recv(&self) -> io::Result<Option<T>> {
        let mut data_lock = self.inner.queue.lock().expect("Poisoned mutex");
        match self.inner.eventfd.read() {
            Ok(_) => (),
            Err(e) if e.kind() == ErrorKind::WouldBlock => (),
            Err(e) => return Err(e),
        }

        Ok(data_lock.pop_back())
    }
}

impl<T: Send> AsRawFd for PollableChannelReciever<T> {
    fn as_raw_fd(&self) -> RawFd {
        self.inner.eventfd.as_raw_fd()
    }
}
