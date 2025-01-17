//! Synchronous wrapper around qcow2 functions.

use super::*;

impl<S: Storage + 'static, F: WrappedFormat<S> + 'static> Qcow2<S, F> {
    /// Synchronous wrapper around [`Qcow2::open_image()`].
    ///
    /// Runs the async function in an ephemeral tokio runtime.
    pub fn open_image_sync(metadata: S, writable: bool) -> io::Result<Self> {
        tokio::runtime::Builder::new_current_thread()
            .build()?
            .block_on(Self::open_image(metadata, writable))
    }

    /// Synchronous wrapper around [`Qcow2::open_path()`].
    ///
    /// Runs the async function in an ephemeral tokio runtime.
    pub fn open_path_sync<P: AsRef<Path>>(path: P, writable: bool) -> io::Result<Self> {
        tokio::runtime::Builder::new_current_thread()
            .build()?
            .block_on(Self::open_path(path, writable))
    }

    /// Synchronous wrapper around [`Qcow2::open_implicit_dependencies()`].
    ///
    /// Runs the async function in an ephemeral tokio runtime.
    pub fn open_implicit_dependencies_sync(&mut self) -> io::Result<()> {
        tokio::runtime::Builder::new_current_thread()
            .build()?
            .block_on(self.open_implicit_dependencies())
    }
}
