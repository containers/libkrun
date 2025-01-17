//! Special I/O functions.
//!
//! Most of I/O should be implemented in the generic
//! [`imago::format::access`](crate::format::access) module, but some I/O needs to be done directly
//! by image drivers (like handling compression).

use super::*;
use crate::io_buffers::IoBuffer;

impl<S: Storage, F: WrappedFormat<S>> Qcow2<S, F> {
    /// Read the special range at `offset`.
    ///
    /// Currently, the only special range we have are compressed clusters.
    pub(super) async fn do_readv_special(
        &self,
        mut bufv: IoVectorMut<'_>,
        mut offset: GuestOffset,
    ) -> io::Result<()> {
        let mut saved_l2_table: Option<Arc<L2Table>> = None;
        let cb = self.header.cluster_bits();

        // Do everything cluster by cluster.
        while !bufv.is_empty() {
            let l2_table = if let Some(saved) = saved_l2_table.as_ref() {
                saved
            } else {
                let new_l2 = self
                    .get_l2(offset, false)
                    .await?
                    .ok_or(io::ErrorKind::Other)?;
                saved_l2_table.get_or_insert(new_l2)
            };

            let chunk_length = offset.remaining_in_cluster(cb);
            let (chunk, remainder) = bufv.split_at(chunk_length);
            bufv = remainder;

            let mut bounce_buffer_and_chunk = None;
            let need_bounce_buffer = chunk.buffer_count() != 1
                || offset.in_cluster_offset(cb) != 0
                || chunk.len() != self.header.cluster_size() as u64;

            let slice = if need_bounce_buffer {
                let bounce_buffer = IoBuffer::new(self.header.cluster_size(), 1)?;
                bounce_buffer_and_chunk = Some((bounce_buffer, chunk));
                bounce_buffer_and_chunk.as_mut().unwrap().0.as_mut()
            } else {
                chunk.into_inner().pop().unwrap().into()
            };

            let guest_cluster = offset.cluster(cb);
            match l2_table.get_mapping(guest_cluster)? {
                L2Mapping::Compressed {
                    host_offset,
                    length,
                } => {
                    self.read_compressed_cluster(slice.into_slice(), host_offset, length)
                        .await?;
                }

                _ => return Err(io::ErrorKind::Other.into()),
            }

            if let Some((bounce_buffer, mut chunk)) = bounce_buffer_and_chunk {
                let ofs = offset.in_cluster_offset(cb);
                let end = ofs + chunk.len() as usize;
                chunk.copy_from_slice(bounce_buffer.as_ref_range(ofs..end).into_slice());
            }

            let next_cluster = if let Some(next) = guest_cluster.next_in_l2(cb) {
                next
            } else {
                saved_l2_table.take();
                guest_cluster.first_in_next_l2(cb)
            };
            offset = next_cluster.offset(cb);
        }

        Ok(())
    }
}
