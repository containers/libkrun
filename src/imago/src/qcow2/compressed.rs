//! Support for compressed clusters.

use super::*;
use crate::io_buffers::IoBuffer;
use miniz_oxide::inflate::core::{decompress as inflate, DecompressorOxide};
use miniz_oxide::inflate::TINFLStatus;

impl<S: Storage + 'static, F: WrappedFormat<S> + 'static> Qcow2<S, F> {
    /// Read one compressed cluster.
    ///
    /// Read the compressed data at `compressed_offset` of length `compressed_length` (which must
    /// be the values from the L2 compressed cluster descriptor) into a bounce buffer, then
    /// decompress it into `buf` (which must have a length of exactly one cluster).
    pub(super) async fn read_compressed_cluster(
        &self,
        buf: &mut [u8],
        compressed_offset: HostOffset,
        compressed_length: u64,
    ) -> io::Result<()> {
        debug_assert!(buf.len() == self.header.cluster_size());

        let storage = self.storage();

        // Must fit (really shouldn’t be compressed if this exceeds the cluster size anyway)
        let compressed_length = compressed_length.try_into().map_err(io::Error::other)?;
        let mut compressed_buf = IoBuffer::new(compressed_length, storage.mem_align())?;
        storage
            .read(&mut compressed_buf, compressed_offset.0)
            .await?;

        let mut dec_ox = DecompressorOxide::new();
        let (status, _read, written) =
            inflate(&mut dec_ox, compressed_buf.as_ref().into_slice(), buf, 0, 0);

        // Because `compressed_length` will generally exceed the actual length, `HasMoreOutput` is
        // expected and can be ignored
        if status != TINFLStatus::Done && status != TINFLStatus::HasMoreOutput {
            return Err(io::Error::other(format!(
                "Failed to decompress cluster (host offset {}+{}): {:?}",
                compressed_offset, compressed_length, status
            )));
        }
        if written < buf.len() {
            return Err(io::Error::other(format!(
                "Failed to decompress cluster (host offset {}+{}): Decompressed {} bytes, expected {}",
                compressed_offset,
                compressed_length,
                written,
                buf.len(),
            )));
        }

        Ok(())
    }
}
