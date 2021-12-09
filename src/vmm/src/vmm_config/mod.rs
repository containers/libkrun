// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fs::{File, OpenOptions};
use std::io;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use libc::O_NONBLOCK;

/// Wrapper for configuring the Block devices attached to the microVM.
#[cfg(feature = "amd-sev")]
pub mod block;
/// Wrapper for configuring the microVM boot source.
pub mod boot_source;
/// Wrapper for configuring the Fs devices attached to the microVM.
#[cfg(not(feature = "amd-sev"))]
pub mod fs;
/// Wrapper over the microVM general information attached to the microVM.
pub mod instance_info;
/// Wrapper for configuring the kernel bundle to be loaded in the microVM.
pub mod kernel_bundle;
/// Wrapper for configuring the logger.
pub mod logger;
/// Wrapper for configuring the memory and CPU of the microVM.
pub mod machine_config;
/// Wrapper for configuring the vsock devices attached to the microVM.
pub mod vsock;

type Result<T> = std::result::Result<T, std::io::Error>;

/// Create and opens a File for writing to it.
/// In case we open a FIFO, in order to not block the instance if nobody is consuming the message
/// that is flushed to the two pipes, we are opening it with `O_NONBLOCK` flag.
/// In this case, writing to a pipe will start failing when reaching 64K of unconsumed content.
fn open_file_nonblock(path: &Path) -> Result<File> {
    OpenOptions::new()
        .custom_flags(O_NONBLOCK)
        .read(true)
        .write(true)
        .open(&path)
}

type FcLineWriter = io::LineWriter<File>;

#[cfg(test)]
mod tests {
    use std::io::Write;

    use utils::tempfile::TempFile;

    use super::*;

    #[test]
    fn test_fifo_line_writer() {
        let log_file_temp =
            TempFile::new().expect("Failed to create temporary output logging file.");
        let good_file = log_file_temp.as_path().to_path_buf();
        let maybe_fifo = open_file_nonblock(&good_file);
        assert!(maybe_fifo.is_ok());
        let mut fw = FcLineWriter::new(maybe_fifo.unwrap());

        let msg = String::from("some message");
        assert!(fw.write(msg.as_bytes()).is_ok());
        assert!(fw.flush().is_ok());
    }
}
