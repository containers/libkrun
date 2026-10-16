use std::fs::File;
use std::io::{self, ErrorKind, IsTerminal};
use std::mem::MaybeUninit;
use std::os::windows::io::{AsRawHandle, BorrowedHandle, OwnedHandle, RawHandle};
use utils::eventfd::EventFd;
use utils::windows::AsRawFd;
use vm_memory::VolatileSlice;
use vm_memory::bitmap::Bitmap;
use windows_sys::Win32::{
    Foundation::{CloseHandle, ERROR_IO_PENDING, FALSE, GetLastError, WAIT_OBJECT_0},
    Storage::FileSystem::{ReadFile, WriteFile},
    System::{
        Console::{CONSOLE_SCREEN_BUFFER_INFO, GetConsoleScreenBufferInfo},
        IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED},
        Threading::{CreateEventW, INFINITE, WaitForMultipleObjects, WaitForSingleObject},
    },
};

use super::{PortInput, PortInputEmpty, PortOutput, PortTerminalProperties};

pub fn input_to_handle_dup(
    handle: *mut core::ffi::c_void,
) -> io::Result<Box<dyn PortInput + Send>> {
    Ok(Box::new(PortInputHandle(dup_handle(handle)?)))
}

pub fn term_handle(
    handle: *mut core::ffi::c_void,
) -> io::Result<Box<dyn PortTerminalProperties + Send + Sync>> {
    let handle = dup_handle(handle)?;
    assert!(
        handle.is_terminal(),
        "Expected handle to be a tty, to query the window size!"
    );
    Ok(Box::new(PortTerminalPropertiesHandle(handle)))
}

pub fn input_empty() -> Result<Box<dyn PortInput + Send>, io::Error> {
    Ok(Box::new(PortInputEmpty {}))
}

pub fn output_file(file: File) -> Result<Box<dyn PortOutput + Send>, io::Error> {
    output_to_handle_dup(file.as_raw_handle())
}

pub fn output_to_handle_dup(
    handle: *mut core::ffi::c_void,
) -> Result<Box<dyn PortOutput + Send>, io::Error> {
    let owned_handle = dup_handle(handle)?;
    Ok(Box::new(PortOutputHandle(owned_handle)))
}

struct PortInputHandle(OwnedHandle);

impl AsRawHandle for PortInputHandle {
    fn as_raw_handle(&self) -> RawHandle {
        self.0.as_raw_handle()
    }
}

impl PortInput for PortInputHandle {
    fn read_volatile(&mut self, buf: &mut VolatileSlice) -> io::Result<usize> {
        let len = u32::try_from(buf.len()).map_err(|_| {
            io::Error::new(ErrorKind::InvalidInput, "buffer length exceeds u32::MAX")
        })?;
        let mut bytes_read: u32 = 0;
        let ret = unsafe {
            ReadFile(
                self.as_raw_handle(),
                buf.ptr_guard_mut().as_ptr(),
                len,
                &mut bytes_read,
                std::ptr::null_mut(),
            )
        };
        if ret == 0 {
            let err = io::Error::last_os_error();
            if err.kind() == ErrorKind::BrokenPipe {
                return Ok(0);
            }
            if err.kind() != ErrorKind::WouldBlock {
                // We don't know if a partial read might have happened, so mark everything as dirty
                buf.bitmap().mark_dirty(0, buf.len());
            }
            Err(err)
        } else {
            let n = bytes_read as usize;
            buf.bitmap().mark_dirty(0, n);
            Ok(n)
        }
    }

    fn wait_until_readable(&self, cancel_fds: &[&EventFd]) {
        let mut handles = vec![self.as_raw_handle()];
        handles.extend(cancel_fds.iter().map(|s| s.as_raw_fd()));
        wait_for_handles(&handles);
    }
}

impl PortInput for PortInputEmpty {
    fn read_volatile(&mut self, _buf: &mut VolatileSlice) -> Result<usize, io::Error> {
        Ok(0)
    }

    fn wait_until_readable(&self, cancel_fds: &[&EventFd]) {
        let handles: Vec<_> = cancel_fds.iter().map(|s| s.as_raw_fd()).collect();
        wait_for_handles(&handles);
    }
}

struct PortOutputHandle(OwnedHandle);

impl AsRawHandle for PortOutputHandle {
    fn as_raw_handle(&self) -> RawHandle {
        self.0.as_raw_handle()
    }
}

impl PortOutput for PortOutputHandle {
    fn write_volatile(
        &mut self,
        buf: &VolatileSlice,
        pausefd: Option<&EventFd>,
    ) -> io::Result<usize> {
        let len = u32::try_from(buf.len()).map_err(|_| {
            io::Error::new(ErrorKind::InvalidInput, "buffer length exceeds u32::MAX")
        })?;

        // Issue the write as overlapped I/O so that, if the peer never
        // drains it (e.g. a full pipe) and the port is being paused (not a
        // real VM shutdown), we can cancel the pending write instead of
        // blocking this thread indefinitely. `pausefd` must only be set by
        // callers performing a pause, never by real VM shutdown -- shutdown
        // must keep blocking here until the sink actually accepts the data.
        let overlapped_event = unsafe {
            CreateEventW(
                std::ptr::null(),
                1, /* manual reset */
                0,
                std::ptr::null(),
            )
        };
        if overlapped_event.is_null() {
            return Err(io::Error::last_os_error());
        }
        let _guard = HandleGuard(overlapped_event);

        let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };
        overlapped.hEvent = overlapped_event;

        let mut bytes_written: u32 = 0;
        let ret = unsafe {
            WriteFile(
                self.as_raw_handle(),
                buf.ptr_guard().as_ptr(),
                len,
                &mut bytes_written,
                &mut overlapped,
            )
        };

        if ret != 0 {
            // Completed synchronously.
            return Ok(bytes_written as usize);
        }

        let err = unsafe { GetLastError() };
        if err != ERROR_IO_PENDING {
            return Err(io::Error::from_raw_os_error(err as i32));
        }

        let mut handles = vec![overlapped_event];
        if let Some(pausefd) = pausefd {
            handles.push(pausefd.as_raw_fd());
        }
        let wait_ret = unsafe {
            WaitForMultipleObjects(handles.len() as u32, handles.as_ptr(), FALSE, INFINITE)
        };

        if wait_ret != WAIT_OBJECT_0 {
            // The stop signal (or some other handle) fired first: cancel
            // the still-pending write instead of waiting for it to
            // complete on its own.
            unsafe {
                CancelIoEx(self.as_raw_handle(), &overlapped);
            }
        }

        // Whether the write completed or was just canceled above,
        // GetOverlappedResult (with bWait=TRUE) blocks only long enough to
        // observe its final outcome, which is bounded now that
        // cancellation has been requested.
        let overlapped_ret = unsafe {
            GetOverlappedResult(
                self.as_raw_handle(),
                &overlapped,
                &mut bytes_written,
                1, /* wait for completion/cancellation to settle */
            )
        };
        if overlapped_ret == 0 {
            let err = io::Error::last_os_error();
            if bytes_written > 0 {
                // A partial write happened before cancellation; report it
                // instead of discarding it, same as a short write would be
                // reported on Unix.
                return Ok(bytes_written as usize);
            }
            return Err(err);
        }
        Ok(bytes_written as usize)
    }

    fn wait_until_writable(&self, _pausefd: Option<&EventFd>) {
        // All waiting happens inside `write_volatile`'s overlapped I/O
        // handling above (it never returns `io::ErrorKind::WouldBlock`),
        // so `process_tx` never invokes this function on Windows.
    }
}

/// Closes the wrapped Windows HANDLE on drop.
struct HandleGuard(*mut core::ffi::c_void);

impl Drop for HandleGuard {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.0);
        }
    }
}

struct PortTerminalPropertiesHandle(OwnedHandle);

impl PortTerminalProperties for PortTerminalPropertiesHandle {
    fn get_win_size(&self) -> (u16, u16) {
        let mut info = MaybeUninit::<CONSOLE_SCREEN_BUFFER_INFO>::uninit();
        let ret = unsafe { GetConsoleScreenBufferInfo(self.0.as_raw_handle(), info.as_mut_ptr()) };
        if ret == 0 {
            log::error!(
                "GetConsoleScreenBufferInfo failed: {}",
                io::Error::last_os_error()
            );
            return (0, 0);
        }
        let info = unsafe { info.assume_init() };

        let cols = (info.srWindow.Right - info.srWindow.Left + 1) as u16;
        let rows = (info.srWindow.Bottom - info.srWindow.Top + 1) as u16;
        (cols, rows)
    }
}

fn dup_handle(raw: *mut core::ffi::c_void) -> Result<OwnedHandle, io::Error> {
    let borrowed = unsafe { BorrowedHandle::borrow_raw(raw) };
    borrowed.try_clone_to_owned()
}

/// Block until at least one of the given Windows HANDLEs becomes signaled.
fn wait_for_handles(handles: &[*mut core::ffi::c_void]) {
    match handles.len() {
        0 => std::thread::sleep(std::time::Duration::MAX),
        1 => unsafe {
            WaitForSingleObject(handles[0], INFINITE);
        },
        n => unsafe {
            WaitForMultipleObjects(n as u32, handles.as_ptr(), FALSE, INFINITE);
        },
    }
}
