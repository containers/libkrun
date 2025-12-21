// SPDX-License-Identifier: Apache-2.0

use std::io;

#[derive(Debug)]
pub enum Error {
    InvalidInterface,
    UnixClone(io::Error),
    UnixRead(io::Error),
    UnixWrite(io::Error),
    VsockAccept(io::Error),
    VsockBind(io::Error),
    VsockClone(io::Error),
    VsockRead(io::Error),
    VsockWrite(io::Error),
}
