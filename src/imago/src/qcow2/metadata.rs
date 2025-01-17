//! Functionality for working with qcow2 metadata.

use super::types::*;
use crate::io_buffers::IoBuffer;
use crate::macros::numerical_enum;
use crate::misc_helpers::invalid_data;
use crate::{Storage, StorageExt};
use bincode::Options;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::mem::size_of;
use std::num::TryFromIntError;
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU32, AtomicU64, AtomicU8, Ordering};
use std::{cmp, io};
use tokio::sync::{Mutex, MutexGuard};
use tracing::error;

/// Qcow header magic ("QFI\xfb").
const MAGIC: u32 = 0x51_46_49_fb;

/// Maximum file length.
const MAX_FILE_LENGTH: u64 = 0x0100_0000_0000_0000u64;

/// Maximum permissible host offset.
pub(super) const MAX_OFFSET: HostOffset = HostOffset(MAX_FILE_LENGTH - 512);

/// Minimum cluster size.
///
/// Defined by the specification.
pub(super) const MIN_CLUSTER_SIZE: usize = 512;

/// Maximum cluster size.
///
/// This is QEMU’s limit, so we can apply it, too.
pub(super) const MAX_CLUSTER_SIZE: usize = 2 * 1024 * 1024;

/// Minimum number of bits per refcount entry.
pub(super) const MIN_REFCOUNT_WIDTH: usize = 1;

/// Maximum number of bits per refcount entry.
pub(super) const MAX_REFCOUNT_WIDTH: usize = 64;

/// Qcow2 v2 header.
#[derive(Deserialize, Serialize)]
struct V2Header {
    /// Qcow magic string ("QFI\xfb").
    magic: u32,

    /// Version number (valid values are 2 and 3).
    version: u32,

    /// Offset into the image file at which the backing file name is stored (NB: The string is not
    /// null terminated).  0 if the image doesn’t have a backing file.
    ///
    /// Note: backing files are incompatible with raw external data files (auto-clear feature bit
    /// 1).
    backing_file_offset: u64,

    /// Length of the backing file name in bytes.  Must not be longer than 1023 bytes.  Undefined
    /// if the image doesn’t have a backing file.
    backing_file_size: u32,

    /// Number of bits that are used for addressing an offset within a cluster (`1 << cluster_bits`
    /// is the cluster size).  Must not be less than 9 (i.e. 512 byte clusters).
    ///
    /// Note: qemu as of today has an implementation limit of 2 MB as the maximum cluster size and
    /// won’t be able to open images with larger cluster sizes.
    ///
    /// Note: if the image has Extended L2 Entries then `cluster_bits` must be at least 14 (i.e.
    /// 16384 byte clusters).
    cluster_bits: u32,

    /// Virtual disk size in bytes.
    ///
    /// Note: qemu has an implementation limit of 32 MB as the maximum L1 table size.  With a 2 MB
    /// cluster size, it is unable to populate a virtual cluster beyond 2 EB (61 bits); with a 512
    /// byte cluster size, it is unable to populate a virtual size larger than 128 GB (37 bits).
    /// Meanwhile, L1/L2 table layouts limit an image to no more than 64 PB (56 bits) of populated
    /// clusters, and an image may hit other limits first (such as a file system’s maximum size).
    size: u64,

    /// Encryption method:
    ///
    /// 0. no encryption
    /// 1. AES encryption
    /// 2. LUKS encryption
    crypt_method: u32,

    /// Number of entries in the active L1 table.
    l1_size: AtomicU32,

    /// Offset into the image file at which the active L1 table starts.  Must be aligned to a
    /// cluster boundary.
    l1_table_offset: AtomicU64,

    /// Offset into the image file at which the refcount table starts.  Must be aligned to a
    /// cluster boundary.
    refcount_table_offset: AtomicU64,

    /// Number of clusters that the refcount table occupies.
    refcount_table_clusters: AtomicU32,

    /// Number of snapshots contained in the image.
    nb_snapshots: u32,

    /// Offset into the image file at which the snapshot table starts.  Must be aligned to a
    /// cluster boundary.
    snapshots_offset: u64,
}

impl V2Header {
    /// Raw v2 header length.
    const RAW_SIZE: usize = 72;
}

/// Qcow2 v3 header.
#[derive(Deserialize, Serialize)]
struct V3HeaderBase {
    /// Bitmask of incompatible features.  An implementation must fail to open an image if an
    /// unknown bit is set.
    ///
    /// 0. Dirty bit.  If this bit is set then refcounts may be inconsistent, make sure to scan
    ///    L1/L2 tables to repair refcounts before accessing the image.
    /// 1. Corrupt bit.  If this bit is set then any data structure may be corrupt and the image
    ///    must not be written to (unless for regaining consistency).
    /// 2. External data file bit.  If this bit is set, an external data file is used.  Guest
    ///    clusters are then stored in the external data file.  For such images, clusters in the
    ///    external data file are not refcounted.  The offset field in the Standard Cluster
    ///    Descriptor must match the guest offset and neither compressed clusters nor internal
    ///    snapshots are supported.  An External Data File Name header extension may be present if
    ///    this bit is set.
    /// 3. Compression type bit.  If this bit is set, a non-default compression is used for
    ///    compressed clusters.  The compression_type field must be present and not zero.
    /// 4. Extended L2 Entries.  If this bit is set then L2 table entries use an extended format
    ///    that allows subcluster-based allocation.  See the Extended L2 Entries section for more
    ///    details.
    ///
    /// Bits 5-63 are reserved (set to 0).
    incompatible_features: u64,

    /// Bitmask of compatible features.  An implementation can safely ignore any unknown bits that
    /// are set.
    ///
    /// 0. Lazy refcounts bit.  If this bit is set then lazy refcount updates can be used.  This
    ///    means marking the image file dirty and postponing refcount metadata updates.
    ///
    /// Bits 1-63 are reserved (set to 0).
    compatible_features: u64,

    /// Bitmask of auto-clear features.  An implementation may only write to an image with unknown
    /// auto-clear features if it clears the respective bits from this field first.
    ///
    /// 0. Bitmaps extension bit.  This bit indicates consistency for the bitmaps extension data.
    ///    It is an error if this bit is set without the bitmaps extension present.  If the bitmaps
    ///    extension is present but this bit is unset, the bitmaps extension data must be
    ///    considered inconsistent.
    /// 1. Raw external data bit.  If this bit is set, the external data file can be read as a
    ///    consistent standalone raw image without looking at the qcow2 metadata.  Setting this bit
    ///    has a performance impact for some operations on the image (e.g. writing zeros requires
    ///    writing to the data file instead of only setting the zero flag in the L2 table entry)
    ///    and conflicts with backing files.  This bit may only be set if the External Data File
    ///    bit (incompatible feature bit 1) is also set.
    ///
    /// Bits 2-63 are reserved (set to 0).
    autoclear_features: u64,

    /// Describes the width of a reference count block entry (width in bits: `refcount_bits = 1 <<
    /// refcount_order`).  For version 2 images, the order is always assumed to be 4 (i.e.
    /// `refcount_bits = 16`).  This value may not exceed 6 (i.e. `refcount_bits = 64`).
    refcount_order: u32,

    /// Length of the header structure in bytes.  For version 2 images, the length is always
    /// assumed to be 72 bytes.  For version 3 it’s at least 104 bytes and must be a multiple of 8.
    header_length: u32,
}

impl V3HeaderBase {
    /// Raw v3 header length beyond the v2 header.
    const RAW_SIZE: usize = 104 - V2Header::RAW_SIZE;
}

impl Default for V3HeaderBase {
    fn default() -> Self {
        V3HeaderBase {
            incompatible_features: 0,
            compatible_features: 0,
            autoclear_features: 0,
            refcount_order: 4,
            header_length: (V2Header::RAW_SIZE + V3HeaderBase::RAW_SIZE) as u32,
        }
    }
}

numerical_enum! {
    /// Incompatible feature bits.
    pub(super) enum IncompatibleFeatures as u64 {
        Dirty = 1 << 0,
        Corrupt = 1 << 1,
        ExternalDataFile = 1 << 2,
        CompressionType = 1 << 3,
        ExtendedL2Entries = 1 << 4,
    }
}

numerical_enum! {
    /// Extension type IDs.
    pub(super) enum HeaderExtensionType as u32 {
        /// End of extension list.
        End = 0,

        /// Backing file format string.
        BackingFileFormat = 0xe2792aca,

        /// Map of feature bits to human-readable names.
        FeatureNameTable = 0x6803f857,

        /// External data file filename string.
        ExternalDataFileName = 0x44415441,
    }
}

/// Header for a header extension.
#[derive(Default, Deserialize, Serialize)]
struct HeaderExtensionHeader {
    /// Type code of the header extension.
    extension_type: u32,

    /// Data length.
    length: u32,
}

impl HeaderExtensionHeader {
    /// Raw struct length.
    const RAW_SIZE: usize = 8;
}

numerical_enum! {
    /// Feature type ID for the feature name table.
    #[derive(Hash)]
    pub(super) enum FeatureType as u8 {
        Incompatible = 0,
        Compatible = 1,
        Autoclear = 2,
    }
}

/// Header extensions (high-level representation).
#[derive(Debug, Clone, Eq, PartialEq)]
pub(super) enum HeaderExtension {
    /// Backing file format string.
    BackingFileFormat(String),

    /// Map of feature bits to human-readable names.
    FeatureNameTable(HashMap<(FeatureType, u8), String>),

    /// External data file filename string.
    ExternalDataFileName(String),

    /// Unknown extension.
    Unknown {
        /// Type.
        extension_type: u32,
        /// Data (as read).
        data: Vec<u8>,
    },
}

/// Integrated header representation.
pub(super) struct Header {
    /// v2 part of the header.
    v2: V2Header,

    /// Base v3 part of the header.
    v3: V3HeaderBase,

    /// Unrecognized header fields.
    unknown_header_fields: Vec<u8>,

    /// Backing filename string.
    backing_filename: Option<String>,

    /// Extensions.
    extensions: Vec<HeaderExtension>,

    /// Whether an external data file is required.
    external_data_file: bool,
}

impl Header {
    /// Load the qcow2 header from disk.
    ///
    /// If `writable` is false, do not perform any modifications (e.g. clearing auto-clear bits).
    pub async fn load<S: Storage>(image: &S, writable: bool) -> io::Result<Self> {
        let bincode = bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .with_big_endian();

        let mut header_buf = vec![0u8; V2Header::RAW_SIZE];
        image.read(header_buf.as_mut_slice(), 0).await?;

        let header: V2Header = bincode.deserialize(&header_buf).map_err(invalid_data)?;
        if header.magic != MAGIC {
            return Err(invalid_data("Not a qcow2 file"));
        }

        let v3header_base = if header.version == 2 {
            V3HeaderBase::default()
        } else if header.version == 3 {
            let mut header_buf = vec![0u8; V3HeaderBase::RAW_SIZE];
            image
                .read(header_buf.as_mut_slice(), V2Header::RAW_SIZE as u64)
                .await?;
            bincode.deserialize(&header_buf).map_err(invalid_data)?
        } else {
            return Err(invalid_data(format!(
                "qcow2 v{} is not supported",
                header.version
            )));
        };

        let cluster_size = 1usize.checked_shl(header.cluster_bits).ok_or_else(|| {
            invalid_data(format!("Invalid cluster size: 2^{}", header.cluster_bits))
        })?;
        if !(MIN_CLUSTER_SIZE..=MAX_CLUSTER_SIZE).contains(&cluster_size) {
            return Err(invalid_data(format!(
                "Invalid cluster size: {}; must be between {} and {}",
                cluster_size, MIN_CLUSTER_SIZE, MAX_CLUSTER_SIZE,
            )));
        }

        let min_header_size = V2Header::RAW_SIZE + V3HeaderBase::RAW_SIZE;
        if (v3header_base.header_length as usize) < min_header_size {
            return Err(invalid_data(format!(
                "qcow2 header too short: {} < {}",
                v3header_base.header_length, min_header_size,
            )));
        } else if (v3header_base.header_length as usize) > cluster_size {
            return Err(invalid_data(format!(
                "qcow2 header too big: {} > {}",
                v3header_base.header_length, cluster_size,
            )));
        }

        let unknown_header_fields = if header.version == 2 {
            Vec::new()
        } else {
            let mut unknown_header_fields =
                vec![0u8; v3header_base.header_length as usize - min_header_size];
            image
                .read(&mut unknown_header_fields, min_header_size as u64)
                .await?;
            unknown_header_fields
        };

        let l1_offset = HostOffset(header.l1_table_offset.load(Ordering::Relaxed));
        l1_offset
            .checked_cluster(header.cluster_bits)
            .ok_or_else(|| invalid_data(format!("Unaligned L1 table: {l1_offset}")))?;

        let rt_offset = HostOffset(header.refcount_table_offset.load(Ordering::Relaxed));
        rt_offset
            .checked_cluster(header.cluster_bits)
            .ok_or_else(|| invalid_data(format!("Unaligned refcount table: {rt_offset}")))?;

        let rc_width = 1usize
            .checked_shl(v3header_base.refcount_order)
            .ok_or_else(|| {
                invalid_data(format!(
                    "Invalid refcount width: 2^{}",
                    v3header_base.refcount_order
                ))
            })?;
        if !(MIN_REFCOUNT_WIDTH..=MAX_REFCOUNT_WIDTH).contains(&rc_width) {
            return Err(invalid_data(format!(
                "Invalid refcount width: {}; must be between {} and {}",
                rc_width, MIN_REFCOUNT_WIDTH, MAX_REFCOUNT_WIDTH,
            )));
        }

        let backing_filename = if header.backing_file_offset != 0 {
            let (offset, length) = (header.backing_file_offset, header.backing_file_size);
            if length > 1023 {
                return Err(invalid_data(format!(
                    "Backing file name is too long ({length}, must not exceed 1023)"
                )));
            }

            let end = offset.checked_add(length as u64).ok_or(invalid_data(
                "Backing file name offset is invalid (too high)",
            ))?;
            if end >= cluster_size as u64 {
                return Err(invalid_data(
                    "Backing file name offset is invalid (beyond first cluster)",
                ));
            }

            let mut backing_buf = vec![0; length as usize];
            image.read(&mut backing_buf, offset).await?;

            Some(
                String::from_utf8(backing_buf)
                    .map_err(|err| invalid_data(format!("Backing file name is invalid: {err}")))?,
            )
        } else {
            None
        };

        let extensions = if header.version == 2 {
            Vec::new()
        } else {
            let mut ext_offset: u64 = v3header_base.header_length as u64;
            let mut extensions = Vec::<HeaderExtension>::new();
            loop {
                if ext_offset + HeaderExtensionHeader::RAW_SIZE as u64 > cluster_size as u64 {
                    return Err(invalid_data("Header extensions exceed the first cluster"));
                }

                let mut ext_hdr_buf = vec![0; HeaderExtensionHeader::RAW_SIZE];
                image.read(&mut ext_hdr_buf, ext_offset).await?;

                ext_offset += HeaderExtensionHeader::RAW_SIZE as u64;

                let ext_hdr: HeaderExtensionHeader =
                    bincode.deserialize(&ext_hdr_buf).map_err(invalid_data)?;
                let ext_end = ext_offset
                    .checked_add(ext_hdr.length as u64)
                    .ok_or_else(|| invalid_data("Header size overflow"))?;
                if ext_end > cluster_size as u64 {
                    return Err(invalid_data("Header extensions exceed the first cluster"));
                }

                let mut ext_data = vec![0; ext_hdr.length as usize];
                image.read(&mut ext_data, ext_offset).await?;

                ext_offset += (ext_hdr.length as u64).next_multiple_of(8);

                let Some(extension) =
                    HeaderExtension::deserialize(ext_hdr.extension_type, ext_data)?
                else {
                    break;
                };

                extensions.push(extension);
            }
            extensions
        };

        // Check for header extension conflicts
        let backing_fmt = extensions
            .iter()
            .find(|ext| matches!(ext, HeaderExtension::BackingFileFormat(_)));
        if let Some(backing_fmt) = backing_fmt {
            let conflicting = extensions.iter().find(|ext| {
                matches!(ext, HeaderExtension::BackingFileFormat(_)) && ext != &backing_fmt
            });
            if let Some(conflicting) = conflicting {
                return Err(io::Error::other(format!(
                    "Found conflicting backing file formats: {:?} != {:?}",
                    backing_fmt, conflicting
                )));
            }
        }
        let ext_data_file = extensions
            .iter()
            .find(|ext| matches!(ext, HeaderExtension::ExternalDataFileName(_)));
        if let Some(ext_data_file) = ext_data_file {
            let conflicting = extensions.iter().find(|ext| {
                matches!(ext, HeaderExtension::ExternalDataFileName(_)) && ext != &ext_data_file
            });
            if let Some(conflicting) = conflicting {
                return Err(io::Error::other(format!(
                    "Found conflicting external data file names: {:?} != {:?}",
                    ext_data_file, conflicting
                )));
            }
        }

        let mut incompatible_features = v3header_base.incompatible_features;
        let autoclear_features = v3header_base.autoclear_features;

        let external_data_file =
            incompatible_features & IncompatibleFeatures::ExternalDataFile as u64 != 0;
        incompatible_features &= !(IncompatibleFeatures::ExternalDataFile as u64);

        let mut header = Header {
            v2: header,
            v3: v3header_base,
            unknown_header_fields,
            backing_filename,
            extensions,
            external_data_file,
        };

        // No need to clear autoclear features for read-only images
        if autoclear_features != 0 && writable {
            header.v3.autoclear_features = 0;
            header.write(image).await?;
        }

        if incompatible_features != 0 {
            let feats = (0..64)
                .filter(|bit| header.v3.incompatible_features & (1u64 << bit) != 0)
                .map(|bit| {
                    if let Some(name) = header.feature_name(FeatureType::Incompatible, bit) {
                        format!("{bit} ({name})")
                    } else {
                        format!("{bit}")
                    }
                })
                .collect::<Vec<String>>();

            return Err(invalid_data(format!(
                "Unrecognized incompatible feature(s) {}",
                feats.join(", ")
            )));
        }

        Ok(header)
    }

    /// Write the qcow2 header to disk.
    pub async fn write<S: Storage>(&mut self, image: &S) -> io::Result<()> {
        let bincode = bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .with_big_endian();

        let header_len = if self.v2.version > 2 {
            let len = bincode.serialized_size(&self.v2).unwrap() as usize
                + bincode.serialized_size(&self.v3).unwrap() as usize
                + self.unknown_header_fields.len();
            let len = len.next_multiple_of(8);
            self.v3.header_length = len as u32;
            len
        } else {
            V2Header::RAW_SIZE
        };

        let mut header_exts = self.serialize_extensions()?;

        if let Some(backing) = self.backing_filename.as_ref() {
            let offset = header_len + header_exts.len();
            let size = backing.len(); // length in bytes
            let end = offset.checked_add(size).ok_or_else(|| {
                io::Error::other("Header plus header extensions plus backing filename is too long")
            })?;
            if end > self.cluster_size() {
                return Err(io::Error::other(
                    "Header plus header extensions plus backing filename is too long",
                ))?;
            }
            self.v2.backing_file_offset = offset as u64;
            self.v2.backing_file_size = size as u32;
        } else {
            self.v2.backing_file_offset = 0;
            self.v2.backing_file_size = 0;
        }

        let mut full_buf = bincode.serialize(&self.v2).map_err(invalid_data)?;
        if self.v2.version > 2 {
            full_buf.append(&mut bincode.serialize(&self.v3).map_err(invalid_data)?);
            full_buf.extend_from_slice(&self.unknown_header_fields);
            full_buf.resize(full_buf.len().next_multiple_of(8), 0);
        }

        full_buf.append(&mut header_exts);

        if let Some(backing) = self.backing_filename.as_ref() {
            full_buf.extend_from_slice(backing.as_bytes());
        }

        if full_buf.len() > self.cluster_size() {
            return Err(io::Error::other(format!(
                "Header is too big to write ({}, larger than a cluster ({}))",
                full_buf.len(),
                self.cluster_size(),
            )));
        }

        image.write(&full_buf, 0).await
    }

    /// Guest disk size.
    pub fn size(&self) -> u64 {
        self.v2.size
    }

    /// log2 of the cluster size.
    pub fn cluster_bits(&self) -> u32 {
        self.v2.cluster_bits
    }

    /// Cluster size in bytes.
    pub fn cluster_size(&self) -> usize {
        1 << self.cluster_bits()
    }

    /// Number of entries per L2 table.
    pub fn l2_entries(&self) -> usize {
        // 3 == log2(size_of::<u64>())
        1 << (self.cluster_bits() - 3)
    }

    /// log2 of the number of entries per refcount block.
    pub fn rb_bits(&self) -> u32 {
        // log2(cluster_size >> (refcount_order - 3))
        self.cluster_bits() - (self.refcount_order() - 3)
    }

    /// Number of entries per refcount block.
    pub fn rb_entries(&self) -> usize {
        1 << self.rb_bits()
    }

    /// log2 of the refcount bits.
    pub fn refcount_order(&self) -> u32 {
        self.v3.refcount_order
    }

    /// Offset of the L1 table.
    pub fn l1_table_offset(&self) -> HostOffset {
        HostOffset(self.v2.l1_table_offset.load(Ordering::Relaxed))
    }

    /// Number of entries in the L1 table.
    pub fn l1_table_entries(&self) -> usize {
        self.v2.l1_size.load(Ordering::Relaxed) as usize
    }

    /// Enter a new L1 table in the image header.
    pub fn set_l1_table(&self, l1_table: &L1Table) -> io::Result<()> {
        let offset = l1_table.get_offset().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "New L1 table has no assigned offset",
            )
        })?;

        let entries = l1_table.entries();
        let entries = entries
            .try_into()
            .map_err(|err| invalid_data(format!("Too many L1 entries ({entries}): {err}")))?;

        self.v2.l1_table_offset.store(offset.0, Ordering::Relaxed);

        self.v2.l1_size.store(entries, Ordering::Relaxed);

        Ok(())
    }

    /// Offset of the refcount table.
    pub fn reftable_offset(&self) -> HostOffset {
        HostOffset(self.v2.refcount_table_offset.load(Ordering::Relaxed))
    }

    /// Number of clusters occupied by the refcount table.
    pub fn reftable_clusters(&self) -> ClusterCount {
        ClusterCount(self.v2.refcount_table_clusters.load(Ordering::Relaxed) as u64)
    }

    /// Number of entries in the refcount table.
    pub fn reftable_entries(&self) -> usize {
        // 3 == log2(size_of::<u64>())
        (self.reftable_clusters().byte_size(self.cluster_bits()) >> 3) as usize
    }

    /// Enter a new refcount table in the image header.
    pub fn set_reftable(&self, reftable: &RefTable) -> io::Result<()> {
        let offset = reftable.get_offset().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "New refcount table has no assigned offset",
            )
        })?;

        let clusters = reftable.cluster_count();
        let clusters = clusters.0.try_into().map_err(|err| {
            invalid_data(format!("Too many reftable clusters ({clusters}): {err}"))
        })?;

        self.v2
            .refcount_table_clusters
            .store(clusters, Ordering::Relaxed);

        self.v2
            .refcount_table_offset
            .store(offset.0, Ordering::Relaxed);

        Ok(())
    }

    /// Backing filename from the image header (if any).
    pub fn backing_filename(&self) -> Option<&String> {
        self.backing_filename.as_ref()
    }

    /// Backing format string from the image header (if any).
    pub fn backing_format(&self) -> Option<&String> {
        self.extensions.iter().find_map(|e| match e {
            HeaderExtension::BackingFileFormat(fmt) => Some(fmt),
            _ => None,
        })
    }

    /// Whether this image requires an external data file.
    pub fn external_data_file(&self) -> bool {
        self.external_data_file
    }

    /// External data file filename from the image header (if any).
    pub fn external_data_filename(&self) -> Option<&String> {
        self.extensions.iter().find_map(|e| match e {
            HeaderExtension::ExternalDataFileName(filename) => Some(filename),
            _ => None,
        })
    }

    /// Translate a feature bit to a human-readable name.
    ///
    /// Uses the feature name table from the image header, if present.
    pub fn feature_name(&self, feat_type: FeatureType, bit: u32) -> Option<&String> {
        for e in &self.extensions {
            if let HeaderExtension::FeatureNameTable(names) = e {
                if let Some(name) = names.get(&(feat_type, bit as u8)) {
                    return Some(name);
                }
            }
        }

        None
    }

    /// Serialize all header extensions.
    fn serialize_extensions(&self) -> io::Result<Vec<u8>> {
        let bincode = bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .with_big_endian();

        let mut result = Vec::new();
        for e in &self.extensions {
            let mut data = e.serialize_data()?;
            let ext_hdr = HeaderExtensionHeader {
                extension_type: e.extension_type(),
                length: data.len().try_into().map_err(|err| {
                    invalid_data(format!(
                        "Header extension too long ({}): {}",
                        data.len(),
                        err
                    ))
                })?,
            };
            result.append(&mut bincode.serialize(&ext_hdr).map_err(invalid_data)?);
            result.append(&mut data);
            result.resize(result.len().next_multiple_of(8), 0);
        }

        let end_ext = HeaderExtensionHeader {
            extension_type: HeaderExtensionType::End as u32,
            length: 0,
        };
        result.append(&mut bincode.serialize(&end_ext).map_err(invalid_data)?);
        result.resize(result.len().next_multiple_of(8), 0);

        Ok(result)
    }

    /// Helper for functions that just need to change little bits in the v2 header part.
    async fn write_v2_header<S: Storage>(&self, image: &S) -> io::Result<()> {
        let bincode = bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .with_big_endian();

        let v2_header = bincode.serialize(&self.v2).map_err(invalid_data)?;
        image.write(&v2_header, 0).await
    }

    /// Write the refcount table pointer (offset and size) to disk.
    pub async fn write_reftable_pointer<S: Storage>(&self, image: &S) -> io::Result<()> {
        // TODO: Just write the reftable offset and size
        self.write_v2_header(image).await
    }

    /// Write the L1 table pointer (offset and size) to disk.
    pub async fn write_l1_table_pointer<S: Storage>(&self, image: &S) -> io::Result<()> {
        // TODO: Just write the L1 table offset and size
        self.write_v2_header(image).await
    }
}

impl HeaderExtension {
    /// Parse an extension from its type and data.  Unrecognized types are stored as `Unknown`
    /// extensions, encountering the end of extensions returns `Ok(None)`.
    fn deserialize(ext_type: u32, data: Vec<u8>) -> io::Result<Option<Self>> {
        let ext = if let Ok(ext_type) = HeaderExtensionType::try_from(ext_type) {
            match ext_type {
                HeaderExtensionType::End => return Ok(None),
                HeaderExtensionType::BackingFileFormat => {
                    let fmt = String::from_utf8(data).map_err(|err| {
                        invalid_data(format!("Invalid backing file format: {err}"))
                    })?;
                    HeaderExtension::BackingFileFormat(fmt)
                }
                HeaderExtensionType::FeatureNameTable => {
                    let mut feats = HashMap::new();
                    for feat in data.chunks(48) {
                        let feat_type: FeatureType = match feat[0].try_into() {
                            Ok(ft) => ft,
                            Err(_) => continue, // skip unrecognized entries
                        };
                        // Cannot use CStr to parse this, as it may not be NUL-terminated.
                        // Use this to remove everything from the first NUL byte.
                        let feat_name_bytes = feat[2..].split(|c| *c == 0).next().unwrap();
                        // Then just use it as a UTF-8 string.
                        let feat_name = String::from_utf8_lossy(feat_name_bytes);
                        feats.insert((feat_type, feat[1]), feat_name.to_string());
                    }
                    HeaderExtension::FeatureNameTable(feats)
                }
                HeaderExtensionType::ExternalDataFileName => {
                    let filename = String::from_utf8(data).map_err(|err| {
                        invalid_data(format!("Invalid external data file name: {err}"))
                    })?;
                    HeaderExtension::ExternalDataFileName(filename)
                }
            }
        } else {
            HeaderExtension::Unknown {
                extension_type: ext_type,
                data,
            }
        };

        Ok(Some(ext))
    }

    /// Return the extension type ID.
    fn extension_type(&self) -> u32 {
        match self {
            HeaderExtension::BackingFileFormat(_) => HeaderExtensionType::BackingFileFormat as u32,
            HeaderExtension::FeatureNameTable(_) => HeaderExtensionType::FeatureNameTable as u32,
            HeaderExtension::ExternalDataFileName(_) => {
                HeaderExtensionType::ExternalDataFileName as u32
            }
            HeaderExtension::Unknown {
                extension_type,
                data: _,
            } => *extension_type,
        }
    }

    /// Serialize this extension’s data (exclusing its header).
    fn serialize_data(&self) -> io::Result<Vec<u8>> {
        match self {
            HeaderExtension::BackingFileFormat(fmt) => Ok(fmt.as_bytes().into()),
            HeaderExtension::FeatureNameTable(map) => {
                let mut result = Vec::new();
                for (bit, name) in map {
                    result.push(bit.0 as u8);
                    result.push(bit.1);

                    let mut padded_name = vec![0; 46];
                    let name_bytes = name.as_bytes();
                    // Might truncate in the middle of a multibyte character, but getting that
                    // right is complicated and probably not worth it
                    let truncated_len = cmp::min(name_bytes.len(), 46);
                    padded_name[..truncated_len].copy_from_slice(&name_bytes[..truncated_len]);
                    result.extend_from_slice(&padded_name);
                }
                Ok(result)
            }
            HeaderExtension::ExternalDataFileName(filename) => Ok(filename.as_bytes().into()),
            HeaderExtension::Unknown {
                extension_type: _,
                data,
            } => Ok(data.clone()),
        }
    }
}

/// L1 table entry.
///
/// - Bit 0 - 8: Reserved (set to 0)
/// - Bit 9 – 55: Bits 9-55 of the offset into the image file at which the L2 table starts.  Must
///   be aligned to a cluster boundary.  If the offset is 0, the L2 table and all clusters
///   described by this L2 table are unallocated.
/// - Bit 56 - 62: Reserved (set to 0)
/// - Bit 63: 0 for an L2 table that is unused or requires COW, 1 if its refcount is exactly one.
///   This information is only accurate in the active L1 table.
#[derive(Copy, Clone, Default, Debug)]
pub(super) struct L1Entry(u64);

impl L1Entry {
    /// Offset of the L2 table, if any.
    pub fn l2_offset(&self) -> Option<HostOffset> {
        let ofs = self.0 & 0x00ff_ffff_ffff_fe00u64;
        if ofs == 0 {
            None
        } else {
            Some(HostOffset(ofs))
        }
    }

    /// Whether the L2 table’s cluster is “copied”.
    ///
    /// `true` means is refcount is one, `false` means modifying it will require COW.
    pub fn is_copied(&self) -> bool {
        self.0 & (1u64 << 63) != 0
    }

    /// Return all reserved bits.
    pub fn reserved_bits(&self) -> u64 {
        self.0 & 0x7f00_0000_0000_01feu64
    }
}

impl TableEntry for L1Entry {
    fn try_from_plain(value: u64, header: &Header) -> io::Result<Self> {
        let entry = L1Entry(value);

        if entry.reserved_bits() != 0 {
            return Err(invalid_data(format!(
                "Invalid L1 entry 0x{:x}, reserved bits set (0x{:x})",
                value,
                entry.reserved_bits(),
            )));
        }

        if let Some(l2_ofs) = entry.l2_offset() {
            if l2_ofs.in_cluster_offset(header.cluster_bits()) != 0 {
                return Err(invalid_data(format!(
                    "Invalid L1 entry 0x{:x}, offset ({}) is not aligned to cluster size (0x{:x})",
                    value,
                    l2_ofs,
                    header.cluster_size(),
                )));
            }
        }

        Ok(entry)
    }

    fn to_plain(&self) -> u64 {
        self.0
    }
}

/// L1 table.
#[derive(Debug)]
pub(super) struct L1Table {
    /// First cluster in the image file.
    cluster: Option<HostCluster>,

    /// Table data.
    data: Box<[L1Entry]>,

    /// log2 of the cluster size.
    cluster_bits: u32,

    /// Whether this table has been modified since it was last written.
    modified: AtomicBool,
}

impl L1Table {
    /// Create a clone that covers at least `at_least_index`.
    pub fn clone_and_grow(&self, at_least_index: usize, header: &Header) -> io::Result<Self> {
        let new_entry_count = cmp::max(at_least_index + 1, self.data.len());
        let new_entry_count =
            new_entry_count.next_multiple_of(header.cluster_size() / size_of::<L1Entry>());

        if new_entry_count > <Self as Table>::MAX_ENTRIES {
            return Err(io::Error::other(
                "Cannot grow the image to this size; L1 table would become too big",
            ));
        }

        let mut new_data = vec![L1Entry::default(); new_entry_count];
        new_data[..self.data.len()].copy_from_slice(&self.data);

        Ok(Self {
            cluster: None,
            data: new_data.into_boxed_slice(),
            cluster_bits: header.cluster_bits(),
            modified: true.into(),
        })
    }

    /// Check whether `index` is in bounds.
    pub fn in_bounds(&self, index: usize) -> bool {
        index < self.data.len()
    }

    /// Enter the given L2 table into this L1 table.
    pub fn enter_l2_table(&mut self, index: usize, l2: &L2Table) -> io::Result<()> {
        let l2_offset = l2.get_offset().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "L2 table has no assigned offset",
            )
        })?;

        let l1entry = L1Entry((1 << 63) | l2_offset.0);
        debug_assert!(l1entry.reserved_bits() == 0);
        self.data[index] = l1entry;
        self.modified.store(true, Ordering::Relaxed);

        Ok(())
    }
}

impl Table for L1Table {
    type InternalEntry = L1Entry;
    type Entry = L1Entry;
    const NAME: &'static str = "L1 table";

    /// Maximum number of L1 table entries.
    ///
    /// Limit taken from QEMU; if QEMU rejects this, we can, too.
    const MAX_ENTRIES: usize = 4 * 1024 * 1024;

    fn from_data(data: Box<[L1Entry]>, header: &Header) -> Self {
        Self {
            cluster: None,
            data,
            cluster_bits: header.cluster_bits(),
            modified: true.into(),
        }
    }

    fn entries(&self) -> usize {
        self.data.len()
    }

    fn get_ref(&self, index: usize) -> Option<&L1Entry> {
        self.data.get(index)
    }

    fn get(&self, index: usize) -> L1Entry {
        self.data.get(index).copied().unwrap_or(L1Entry(0))
    }

    fn get_cluster(&self) -> Option<HostCluster> {
        self.cluster
    }

    fn get_offset(&self) -> Option<HostOffset> {
        self.cluster.map(|index| index.offset(self.cluster_bits))
    }

    fn set_cluster(&mut self, cluster: HostCluster) {
        self.cluster = Some(cluster);
        self.modified.store(true, Ordering::Relaxed);
    }

    fn unset_cluster(&mut self) {
        self.cluster = None;
    }

    fn is_modified(&self) -> bool {
        self.modified.load(Ordering::Relaxed)
    }

    fn clear_modified(&self) {
        self.modified.store(false, Ordering::Relaxed);
    }

    fn set_modified(&self) {
        self.modified.store(true, Ordering::Relaxed);
    }

    fn cluster_bits(&self) -> u32 {
        self.cluster_bits
    }
}

/// L2 table entry.
///
/// - Bit 0 - 61: Cluster descriptor
/// - Bit 62: 0 for standard clusters, 1 for compressed clusters
/// - Bit 63: 0 for clusters that are unused, compressed or require COW.  1 for standard clusters
///   whose refcount is exactly one.  This information is only accurate in L2 tables that are
///   reachable from the active L1 table.  With external data files, all guest clusters have an
///   implicit refcount of 1 (because of the fixed host = guest mapping for guest cluster offsets),
///   so this bit should be 1 for all allocated clusters.
///
/// Standard Cluster Descriptor:
/// - Bit 0: If set to 1, the cluster reads as all zeros. The host cluster offset can be used to
///   describe a preallocation, but it won’t be used for reading data from this cluster, nor is
///   data read from the backing file if the cluster is unallocated.  With version 2 or with
///   extended L2 entries (see the next section), this is always 0.
/// - Bit 1 – 8: Reserved (set to 0)
/// - Bit 9 – 55: Bits 9-55 of host cluster offset. Must be aligned to a cluster boundary. If the
///   offset is 0 and bit 63 is clear, the cluster is unallocated. The offset may only be 0 with
///   bit 63 set (indicating a host cluster offset of 0) when an external data file is used.
/// - Bit 56 - 61: Reserved (set to 0)
///
/// Compressed Cluster Descriptor (`x = 62 - (cluster_bits - 8)`):
/// - Bit 0 - x-1: Host cluster offset.  This is usually _not_ aligned to a cluster or sector
///   boundary!  If cluster_bits is small enough that this field includes bits beyond 55, those
///   upper bits must be set to 0.
/// - Bit x - 61: Number of additional 512-byte sectors used for the compressed data, beyond the
///   sector containing the offset in the previous field. Some of these sectors may reside in the
///   next contiguous host cluster.  Note that the compressed data does not necessarily occupy all
///   of the bytes in the final sector; rather, decompression stops when it has produced a cluster
///   of data.  Another compressed cluster may map to the tail of the final sector used by this
///   compressed cluster.
#[derive(Copy, Clone, Default, Debug)]
pub(super) struct L2Entry(u64);

/// Internal actual type of L2 entries.
///
/// Using atomic allows flushing L2 tables from the cache while they are write-locked.
#[derive(Default, Debug)]
pub(super) struct AtomicL2Entry(AtomicU64);

/// High-level representation of an L2 entry.
#[derive(Debug, Clone)]
pub(super) enum L2Mapping {
    /// Data is in the data file.
    DataFile {
        /// Cluster in the data file.
        host_cluster: HostCluster,

        /// Whether the cluster has a refcount of exactly 1.
        copied: bool,
    },

    /// Data is in the backing file.
    Backing {
        /// Guest cluster index.
        backing_offset: u64,
    },

    /// Data is zero.
    Zero {
        /// Preallocated cluster in the data file, if any.
        host_cluster: Option<HostCluster>,

        /// Whether the preallocated cluster has a refcount of exactly 1.
        copied: bool,
    },

    /// Data is compressed.
    Compressed {
        /// Offset in the data file.
        host_offset: HostOffset,

        /// Upper limit on the number of bytes that comprise the compressed data.
        length: u64,
    },
}

impl L2Entry {
    /// Offset of the data cluster, if any.
    ///
    /// Assumes the L2 entry references a data cluster, not a compressed cluster.
    ///
    /// `external_data_file` must be true when using an external data file; in this case, offset 0
    /// is a valid offset, and can only be distinguished from “unallocated” by whether the COPIED
    /// flag is set or not (which it always is when using an external data file).
    pub fn cluster_offset(&self, external_data_file: bool) -> Option<HostOffset> {
        let ofs = self.0 & 0x00ff_ffff_ffff_fe00u64;
        if ofs != 0 || (external_data_file && self.is_copied()) {
            Some(HostOffset(ofs))
        } else {
            None
        }
    }

    /// Whether the cluster is compressed.
    pub fn is_compressed(&self) -> bool {
        self.0 & (1u64 << 62) != 0
    }

    /// Whether the cluster is “copied”.
    ///
    /// `true` means is refcount is one, `false` means modifying it will require COW.
    pub fn is_copied(&self) -> bool {
        self.0 & (1u64 << 63) != 0
    }

    /// Clear “copied” flag.
    #[must_use]
    pub fn without_copied(self) -> Self {
        L2Entry(self.0 & !(1u64 << 63))
    }

    /// Whether the cluster is a zero cluster.
    ///
    /// Assumes the L2 entry references a data cluster, not a compressed cluster.
    pub fn is_zero(&self) -> bool {
        self.0 & (1u64 << 0) != 0
    }

    /// Return all reserved bits.
    pub fn reserved_bits(&self) -> u64 {
        if self.is_compressed() {
            self.0 & 0x8000_0000_0000_0000u64
        } else {
            self.0 & 0x3f00_0000_0000_01feu64
        }
    }

    /// Return the full compressed cluster descriptor.
    pub fn compressed_descriptor(&self) -> u64 {
        self.0 & 0x3fff_ffff_ffff_ffffu64
    }

    /// If this entry is compressed, return the start host offset and upper limit on the compressed
    /// number of bytes.
    pub fn compressed_range(&self, cluster_bits: u32) -> Option<(HostOffset, u64)> {
        if self.is_compressed() {
            let desc = self.compressed_descriptor();
            let compressed_offset_bits = 62 - (cluster_bits - 8);
            let offset = desc & ((1 << compressed_offset_bits) - 1) & 0x00ff_ffff_ffff_ffffu64;
            let sectors = desc >> compressed_offset_bits;
            // The first sector is not considered in `sectors`, so we add it and subtract the
            // number of bytes there that do not belong to this compressed cluster
            let length = (sectors + 1) * 512 - (offset & 511);

            Some((HostOffset(offset), length))
        } else {
            None
        }
    }

    /// If this entry is allocated, return the first host cluster and the number of clusters it
    /// references.
    ///
    /// `external_data_file` must be true when using an external data file.
    fn allocation(
        &self,
        cluster_bits: u32,
        external_data_file: bool,
    ) -> Option<(HostCluster, ClusterCount)> {
        if let Some((offset, length)) = self.compressed_range(cluster_bits) {
            // Compressed clusters can cross host cluster boundaries, and thus occupy two clusters
            let first_cluster = offset.cluster(cluster_bits);
            let cluster_count = ClusterCount::from_byte_size(
                offset + length - first_cluster.offset(cluster_bits),
                cluster_bits,
            );
            Some((first_cluster, cluster_count))
        } else {
            self.cluster_offset(external_data_file)
                .map(|ofs| (ofs.cluster(cluster_bits), ClusterCount(1)))
        }
    }

    /// Return the high-level `L2Mapping` representation.
    ///
    /// `guest_cluster` is the guest cluster being accessed, `cluster_bits` is log2 of the cluster
    /// size.  `external_data_file` must be true when using an external data file.
    fn into_mapping(
        self,
        guest_cluster: GuestCluster,
        cluster_bits: u32,
        external_data_file: bool,
    ) -> io::Result<L2Mapping> {
        let mapping = if let Some((offset, length)) = self.compressed_range(cluster_bits) {
            L2Mapping::Compressed {
                host_offset: offset,
                length,
            }
        } else if self.is_zero() {
            let host_cluster = self
                .cluster_offset(external_data_file)
                .map(|ofs| {
                    ofs.checked_cluster(cluster_bits).ok_or_else(|| {
                        let offset = guest_cluster.offset(cluster_bits);
                        io::Error::other(format!(
                            "Unaligned pre-allocated zero cluster at {offset}; L2 entry: {self:?}"
                        ))
                    })
                })
                .transpose()?;

            L2Mapping::Zero {
                host_cluster,
                copied: host_cluster.is_some() && self.is_copied(),
            }
        } else if let Some(host_offset) = self.cluster_offset(external_data_file) {
            let host_cluster = host_offset.checked_cluster(cluster_bits).ok_or_else(|| {
                let offset = guest_cluster.offset(cluster_bits);
                io::Error::other(format!(
                    "Unaligned data cluster at {offset}; L2 entry: {self:?}"
                ))
            })?;

            L2Mapping::DataFile {
                host_cluster,
                copied: self.is_copied(),
            }
        } else {
            L2Mapping::Backing {
                backing_offset: guest_cluster.offset(cluster_bits).0,
            }
        };

        Ok(mapping)
    }

    /// Create an L2 entry from its high-level `L2Mapping` representation.
    fn from_mapping(value: L2Mapping, cluster_bits: u32) -> Self {
        let num_val: u64 = match value {
            L2Mapping::DataFile {
                host_cluster,
                copied,
            } => {
                debug_assert!(host_cluster.offset(cluster_bits) <= MAX_OFFSET);
                if copied {
                    (1 << 63) | host_cluster.offset(cluster_bits).0
                } else {
                    host_cluster.offset(cluster_bits).0
                }
            }

            L2Mapping::Backing { backing_offset: _ } => 0,

            L2Mapping::Zero {
                host_cluster,
                copied,
            } => {
                let host_offset = host_cluster.map(|hc| hc.offset(cluster_bits));
                debug_assert!(host_offset.unwrap_or(HostOffset(0)) <= MAX_OFFSET);
                if copied {
                    (1 << 63) | host_offset.unwrap().0 | 0x1
                } else {
                    host_offset.unwrap_or(HostOffset(0)).0 | 0x1
                }
            }

            L2Mapping::Compressed {
                host_offset,
                length,
            } => {
                let compressed_offset_bits = 62 - (cluster_bits - 8);
                assert!(length < 1 << cluster_bits);
                assert!(host_offset.0 < 1 << compressed_offset_bits);

                // The first sector is not considered, so we subtract the number of bytes in it
                // that belong to this compressed cluster from `length`:
                // ceil((length - (512 - (host_offset & 511))) / 512)
                // = (length + 511 - 512 + (host_offset & 511)) / 512
                let sectors = (length - 1 + (host_offset.0 & 511)) / 512;

                (1 << 62) | (sectors << compressed_offset_bits) | host_offset.0
            }
        };

        let entry = L2Entry(num_val);
        debug_assert!(entry.reserved_bits() == 0);
        entry
    }
}

impl AtomicL2Entry {
    /// Get the contained value.
    fn get(&self) -> L2Entry {
        L2Entry(self.0.load(Ordering::Relaxed))
    }

    /// Exchange the contained value.
    ///
    /// # Safety
    /// Caller must ensure that:
    /// (1) No reader sees invalid intermediate states.
    /// (2) Updates are done atomically (do not depend on prior state of the L2 table), or there is
    ///     only one writer at a time.
    unsafe fn swap(&self, l2e: L2Entry) -> L2Entry {
        L2Entry(self.0.swap(l2e.0, Ordering::Relaxed))
    }
}

impl TableEntry for AtomicL2Entry {
    fn try_from_plain(value: u64, header: &Header) -> io::Result<Self> {
        let entry = L2Entry(value);

        if entry.reserved_bits() != 0 {
            return Err(invalid_data(format!(
                "Invalid L2 entry 0x{:x}, reserved bits set (0x{:x})",
                value,
                entry.reserved_bits(),
            )));
        }

        if let Some(offset) = entry.cluster_offset(header.external_data_file()) {
            if !entry.is_compressed() && offset.in_cluster_offset(header.cluster_bits()) != 0 {
                return Err(invalid_data(format!(
                    "Invalid L2 entry 0x{:x}, offset ({}) is not aligned to cluster size (0x{:x})",
                    value,
                    offset,
                    header.cluster_size(),
                )));
            }
        }

        Ok(AtomicL2Entry(AtomicU64::new(entry.0)))
    }

    fn to_plain(&self) -> u64 {
        self.get().0
    }
}

impl L2Mapping {
    /// Check whether two mappings are consecutive.
    ///
    /// Given the `preceding` mapping, check whether `self` is consecutive to it, i.e. is the same
    /// kind of mapping, and the offsets are consecutive.
    pub fn is_consecutive(&self, preceding: &L2Mapping, cluster_bits: u32) -> bool {
        match preceding {
            L2Mapping::DataFile {
                host_cluster: prior_cluster,
                copied,
            } => {
                if let L2Mapping::DataFile {
                    host_cluster: next_cluster,
                    copied: next_copied,
                } = self
                {
                    *next_cluster == *prior_cluster + ClusterCount(1) && *next_copied == *copied
                } else {
                    false
                }
            }

            L2Mapping::Backing {
                backing_offset: prior_backing_offset,
            } => {
                let Some(expected_next) = prior_backing_offset.checked_add(1 << cluster_bits)
                else {
                    return false;
                };

                if let L2Mapping::Backing {
                    backing_offset: next_offset,
                } = self
                {
                    *next_offset == expected_next
                } else {
                    false
                }
            }

            L2Mapping::Zero {
                host_cluster: _,
                copied: _,
            } => {
                // Cluster and copied do not matter; every read is continuous regardless (always
                // zero), and every write is, too (always allocate)
                matches!(
                    self,
                    L2Mapping::Zero {
                        host_cluster: _,
                        copied: _,
                    }
                )
            }

            L2Mapping::Compressed {
                host_offset: _,
                length: _,
            } => {
                // Not really true, but in practice it is.  Reads need to go through a special
                // function anyway, and every write will need COW anyway.
                matches!(
                    self,
                    L2Mapping::Compressed {
                        host_offset: _,
                        length: _,
                    }
                )
            }
        }
    }
}

/// L2 table.
#[derive(Debug)]
pub(super) struct L2Table {
    /// Cluster of the L2 table.
    cluster: Option<HostCluster>,

    /// Table data.
    data: Box<[AtomicL2Entry]>,

    /// log2 of the cluster size.
    cluster_bits: u32,

    /// Whether this image uses an external data file.
    external_data_file: bool,

    /// Whether this table has been modified since it was last written.
    modified: AtomicBool,

    /// Lock for creating `L2TableWriteGuard`.
    writer_lock: Mutex<()>,
}

/// Write guard for an L2 table.
#[derive(Debug)]
pub(super) struct L2TableWriteGuard<'a> {
    /// Referenced L2 table.
    table: &'a L2Table,

    /// Held guard mutex on that L2 table.
    _lock: MutexGuard<'a, ()>,
}

impl L2Table {
    /// Create a new zeroed L2 table.
    pub fn new_cleared(header: &Header) -> Self {
        let mut data = Vec::with_capacity(header.l2_entries());
        data.resize_with(header.l2_entries(), Default::default);

        L2Table {
            cluster: None,
            data: data.into_boxed_slice(),
            cluster_bits: header.cluster_bits(),
            external_data_file: header.external_data_file(),
            modified: true.into(),
            writer_lock: Default::default(),
        }
    }

    /// Look up a cluster mapping.
    pub fn get_mapping(&self, lookup_cluster: GuestCluster) -> io::Result<L2Mapping> {
        self.get(lookup_cluster.l2_index(self.cluster_bits))
            .into_mapping(lookup_cluster, self.cluster_bits, self.external_data_file)
    }

    /// Allow modifying this L2 table.
    ///
    /// Note that readers are allowed to exist while modifications are happening.
    pub async fn lock_write(&self) -> L2TableWriteGuard<'_> {
        L2TableWriteGuard {
            table: self,
            _lock: self.writer_lock.lock().await,
        }
    }
}

impl L2TableWriteGuard<'_> {
    /// Look up a cluster mapping.
    pub fn get_mapping(&self, lookup_cluster: GuestCluster) -> io::Result<L2Mapping> {
        self.table.get_mapping(lookup_cluster)
    }

    /// Enter the given raw data cluster mapping into the L2 table.
    ///
    /// If the previous entry pointed to an allocated cluster, return the old allocation so its
    /// refcount can be decreased (offset of the first cluster and number of clusters -- compressed
    /// clusters can span across host cluster boundaries).
    ///
    /// If the allocation is reused, `None` is returned, so this function only returns `Some(_)` if
    /// some cluster is indeed leaked.
    #[must_use]
    pub fn map_cluster(
        &mut self,
        index: usize,
        host_cluster: HostCluster,
    ) -> Option<(HostCluster, ClusterCount)> {
        let new = L2Entry::from_mapping(
            L2Mapping::DataFile {
                host_cluster,
                copied: true,
            },
            self.table.cluster_bits,
        );
        // Safe: We set a full valid mapping, and there is only one writer (thanks to
        // `L2TableWriteGuard`).
        let l2e = unsafe { self.table.data[index].swap(new) };
        self.table.modified.store(true, Ordering::Relaxed);

        let allocation = l2e.allocation(self.table.cluster_bits, self.table.external_data_file);
        if let Some((a_cluster, a_count)) = allocation {
            if a_cluster == host_cluster && a_count == ClusterCount(1) {
                None
            } else {
                allocation
            }
        } else {
            None
        }
    }
}

impl Table for L2Table {
    type InternalEntry = AtomicL2Entry;
    type Entry = L2Entry;
    const NAME: &'static str = "L2 table";
    const MAX_ENTRIES: usize = MAX_CLUSTER_SIZE / 8;

    fn from_data(data: Box<[AtomicL2Entry]>, header: &Header) -> Self {
        assert!(data.len() == header.l2_entries());

        Self {
            cluster: None,
            data,
            cluster_bits: header.cluster_bits(),
            external_data_file: header.external_data_file(),
            modified: true.into(),
            writer_lock: Default::default(),
        }
    }

    fn entries(&self) -> usize {
        self.data.len()
    }

    fn get_ref(&self, index: usize) -> Option<&AtomicL2Entry> {
        self.data.get(index)
    }

    fn get(&self, index: usize) -> L2Entry {
        self.data
            .get(index)
            .map(|l2e| l2e.get())
            .unwrap_or(L2Entry(0))
    }

    fn get_cluster(&self) -> Option<HostCluster> {
        self.cluster
    }

    fn get_offset(&self) -> Option<HostOffset> {
        self.cluster.map(|index| index.offset(self.cluster_bits))
    }

    fn set_cluster(&mut self, cluster: HostCluster) {
        self.cluster = Some(cluster);
        self.modified.store(true, Ordering::Relaxed);
    }

    fn unset_cluster(&mut self) {
        self.cluster = None;
    }

    fn is_modified(&self) -> bool {
        self.modified.load(Ordering::Relaxed)
    }

    fn clear_modified(&self) {
        self.modified.store(false, Ordering::Relaxed);
    }

    fn set_modified(&self) {
        self.modified.store(true, Ordering::Relaxed);
    }

    fn cluster_bits(&self) -> u32 {
        self.cluster_bits
    }
}

impl Clone for L2Table {
    fn clone(&self) -> Self {
        let mut data = Vec::with_capacity(self.data.len());
        for entry in &self.data {
            // None of these can be `copied`
            let entry = entry.get().without_copied();
            data.push(AtomicL2Entry(AtomicU64::new(entry.0)));
        }

        let modified = AtomicBool::new(self.is_modified());

        L2Table {
            cluster: None,
            data: data.into_boxed_slice(),
            cluster_bits: self.cluster_bits,
            external_data_file: self.external_data_file,
            modified,
            writer_lock: Default::default(),
        }
    }
}

impl Drop for L2Table {
    fn drop(&mut self) {
        if self.is_modified() {
            error!("L2 table dropped while modified; was the image closed before being flushed?");
        }
    }
}

/// Refcount table entry.
#[derive(Copy, Clone, Default, Debug)]
pub(super) struct RefTableEntry(u64);

impl RefTableEntry {
    /// Offset of the referenced refblock, if any.
    pub fn refblock_offset(&self) -> Option<HostOffset> {
        let ofs = self.0 & 0xffff_ffff_ffff_fe00u64;
        if ofs == 0 {
            None
        } else {
            Some(HostOffset(ofs))
        }
    }

    /// Return all reserved bits.
    pub fn reserved_bits(&self) -> u64 {
        self.0 & 0x0000_0000_0000_01ffu64
    }
}

impl TableEntry for RefTableEntry {
    fn try_from_plain(value: u64, header: &Header) -> io::Result<Self> {
        let entry = RefTableEntry(value);

        if entry.reserved_bits() != 0 {
            return Err(invalid_data(format!(
                "Invalid reftable entry 0x{:x}, reserved bits set (0x{:x})",
                value,
                entry.reserved_bits(),
            )));
        }

        if let Some(rb_ofs) = entry.refblock_offset() {
            if rb_ofs.in_cluster_offset(header.cluster_bits()) != 0 {
                return Err(invalid_data(
                    format!(
                        "Invalid reftable entry 0x{:x}, offset ({}) is not aligned to cluster size (0x{:x})",
                        value,
                        rb_ofs,
                        header.cluster_size(),
                    ),
                ));
            }
        }

        Ok(entry)
    }

    fn to_plain(&self) -> u64 {
        self.0
    }
}

/// Refcount table.
#[derive(Debug)]
pub(super) struct RefTable {
    /// First cluster in the image file.
    cluster: Option<HostCluster>,

    /// Table data.
    data: Box<[RefTableEntry]>,

    /// log2 of the cluster size.
    cluster_bits: u32,

    /// Whether this table has been modified since it was last written.
    modified: AtomicBool,
}

impl RefTable {
    /// Create a clone that covers at least `at_least_index`.
    ///
    /// Also ensure that beyond `at_least_index`, there are enough entries to self-describe the new
    /// refcount table (so that it can actually be allocated).
    pub fn clone_and_grow(&self, header: &Header, at_least_index: usize) -> io::Result<Self> {
        let cluster_size = header.cluster_size();
        let rb_entries = header.rb_entries();

        // There surely is an optimal O(1) solution, but probably would look less clear, and this
        // is not a hot path.
        let mut extra_rbs = 1;
        let new_entry_count = loop {
            let entry_count = cmp::max(at_least_index + 1 + extra_rbs, self.data.len());
            let entry_count = entry_count.next_multiple_of(cluster_size / size_of::<u64>());
            let size = entry_count * size_of::<u64>();
            // Full number of clusters needed to both the new reftable *and* the `extra_rbs`
            let refcount_clusters = size / cluster_size + extra_rbs;
            let rbs_needed = refcount_clusters.div_ceil(rb_entries);
            if extra_rbs == rbs_needed {
                break entry_count;
            }
            extra_rbs = rbs_needed;
        };

        if new_entry_count > <Self as Table>::MAX_ENTRIES {
            return Err(io::Error::other(
                "Cannot grow the image to this size; refcount table would become too big",
            ));
        }

        let mut new_data = vec![RefTableEntry::default(); new_entry_count];
        new_data[..self.data.len()].copy_from_slice(&self.data);

        Ok(Self {
            cluster: None,
            data: new_data.into_boxed_slice(),
            cluster_bits: header.cluster_bits(),
            modified: true.into(),
        })
    }

    /// Check whether `index` is in bounds.
    pub fn in_bounds(&self, index: usize) -> bool {
        index < self.data.len()
    }

    /// Enter the given refcount block into this refcount table.
    pub fn enter_refblock(&mut self, index: usize, rb: &RefBlock) -> io::Result<()> {
        let rb_offset = rb.get_offset().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "Refcount block as no assigned offset",
            )
        })?;

        let rt_entry = RefTableEntry(rb_offset.0);
        debug_assert!(rt_entry.reserved_bits() == 0);
        self.data[index] = rt_entry;
        self.modified.store(true, Ordering::Relaxed);

        Ok(())
    }
}

impl Table for RefTable {
    type InternalEntry = RefTableEntry;
    type Entry = RefTableEntry;
    const NAME: &'static str = "Refcount table";

    /// Maximum number of refcount table entries.
    ///
    /// Not in QEMU, but makes sense to limit to the same as the L1 table.  Note that refcount
    /// blocks usually cover more clusters than an L2 table, so this generally allows larger image
    /// files than would be necessary for the maximum guest disk size determined by the maximum
    /// number of L1 entries.
    const MAX_ENTRIES: usize = <L1Table as Table>::MAX_ENTRIES;

    fn from_data(data: Box<[RefTableEntry]>, header: &Header) -> Self {
        Self {
            cluster: None,
            data,
            cluster_bits: header.cluster_bits(),
            modified: true.into(),
        }
    }

    fn entries(&self) -> usize {
        self.data.len()
    }

    fn get_ref(&self, index: usize) -> Option<&RefTableEntry> {
        self.data.get(index)
    }

    fn get(&self, index: usize) -> RefTableEntry {
        self.data.get(index).copied().unwrap_or(RefTableEntry(0))
    }

    fn get_cluster(&self) -> Option<HostCluster> {
        self.cluster
    }

    fn get_offset(&self) -> Option<HostOffset> {
        self.cluster.map(|index| index.offset(self.cluster_bits))
    }

    fn set_cluster(&mut self, cluster: HostCluster) {
        self.cluster = Some(cluster);
        self.modified.store(true, Ordering::Relaxed);
    }

    fn unset_cluster(&mut self) {
        self.cluster = None;
    }

    fn is_modified(&self) -> bool {
        self.modified.load(Ordering::Relaxed)
    }

    fn clear_modified(&self) {
        self.modified.store(false, Ordering::Relaxed);
    }

    fn set_modified(&self) {
        self.modified.store(true, Ordering::Relaxed);
    }

    fn cluster_bits(&self) -> u32 {
        self.cluster_bits
    }
}

/// Refcount block.
pub(super) struct RefBlock {
    /// Cluster in the image file.
    cluster: Option<HostCluster>,

    /// Raw table data (big endian).
    raw_data: IoBuffer,

    /// log2 of the refcount bits.
    refcount_order: u32,

    /// log2 of the cluster size.
    cluster_bits: u32,

    /// Whether this block has been modified since it was last written.
    modified: AtomicBool,

    /// Lock for creating `RefBlockWriteGuard`.
    writer_lock: Mutex<()>,
}

/// Write guard for a refblock.
pub(super) struct RefBlockWriteGuard<'a> {
    /// Referenced refblock.
    rb: &'a RefBlock,

    /// Held guard mutex on that refblock.
    _lock: MutexGuard<'a, ()>,
}

impl RefBlock {
    /// Create a new zeroed refcount block.
    pub fn new_cleared<S: Storage>(for_image: &S, header: &Header) -> io::Result<Self> {
        let mut raw_data = IoBuffer::new(header.cluster_size(), for_image.mem_align())?;
        raw_data.as_mut().into_slice().fill(0);

        Ok(RefBlock {
            cluster: None,
            raw_data,
            refcount_order: header.refcount_order(),
            cluster_bits: header.cluster_bits(),
            modified: true.into(),
            writer_lock: Default::default(),
        })
    }

    /// Load a refcount block from disk.
    pub async fn load<S: Storage>(
        image: &S,
        header: &Header,
        cluster: HostCluster,
    ) -> io::Result<Self> {
        let cluster_bits = header.cluster_bits();
        let cluster_size = 1 << cluster_bits;
        let refcount_order = header.refcount_order();
        let offset = cluster.offset(cluster_bits);

        check_table(
            "Refcount block",
            offset.0,
            cluster_size,
            1,
            MAX_CLUSTER_SIZE,
            cluster_size,
        )?;

        let mut raw_data =
            IoBuffer::new(cluster_size, cmp::max(image.mem_align(), size_of::<u64>()))?;
        image.read(&mut raw_data, offset.0).await?;

        Ok(RefBlock {
            cluster: Some(cluster),
            raw_data,
            refcount_order,
            cluster_bits,
            modified: false.into(),
            writer_lock: Default::default(),
        })
    }

    /// Write a refcount block to disk.
    pub async fn write<S: Storage>(&self, image: &S) -> io::Result<()> {
        let offset = self
            .get_offset()
            .ok_or_else(|| io::Error::other("Cannot write qcow2 refcount block, no offset set"))?;

        self.clear_modified();
        if let Err(err) = image.write(self.raw_data.as_ref(), offset.0).await {
            self.set_modified();
            return Err(err);
        }

        Ok(())
    }

    /// Get the block’s cluster in the image file.
    pub fn get_cluster(&self) -> Option<HostCluster> {
        self.cluster
    }

    /// Get the block’s offset in the image file.
    pub fn get_offset(&self) -> Option<HostOffset> {
        self.cluster.map(|index| index.offset(self.cluster_bits))
    }

    /// Change the block’s cluster in the image file (for writing).
    pub fn set_cluster(&mut self, cluster: HostCluster) {
        self.cluster = Some(cluster);
        self.set_modified();
    }

    /// Calculate sub-byte refcount access parameters.
    ///
    /// For a given refcount index, return its:
    /// - byte index,
    /// - access mask,
    /// - in-byte shift.
    fn sub_byte_refcount_access(&self, index: usize) -> (usize, u8, usize) {
        let order = self.refcount_order;
        debug_assert!(order < 3);

        // Note that `order` is in bits, i.e. `1 << order` is the number of bits.  `index` is in
        // units of refcounts, so `index << order` is the bit index, and `index << (order - 3)` is
        // then the byte index, which is equal to `index >> (3 - order)`.
        let byte_index = index >> (3 - order);
        // `1 << order` is the bits per refcount (bprc), so `(1 << bprc) - 1` is the mask for one
        // refcount (its maximum value).
        let mask = (1 << (1 << order)) - 1;
        // `index` is in units of refcounts, so `index << order` is the bit index.  `% 8`, we get
        // the base index inside of a byte.
        let shift = (index << order) % 8;

        (byte_index, mask, shift)
    }

    /// Get the given cluster’s refcount.
    pub fn get(&self, index: usize) -> u64 {
        match self.refcount_order {
            // refcount_bits == 1, 2, 4
            0..=2 => {
                let (index, mask, shift) = self.sub_byte_refcount_access(index);
                let raw_data_slice = unsafe { self.raw_data.as_ref().into_typed_slice::<u8>() };
                let atomic =
                    unsafe { AtomicU8::from_ptr(&raw_data_slice[index] as *const u8 as *mut u8) };
                ((atomic.load(Ordering::Relaxed) >> shift) & mask) as u64
            }

            // refcount_bits == 8
            3 => {
                let raw_data_slice = unsafe { self.raw_data.as_ref().into_typed_slice::<u8>() };
                let atomic =
                    unsafe { AtomicU8::from_ptr(&raw_data_slice[index] as *const u8 as *mut u8) };
                atomic.load(Ordering::Relaxed) as u64
            }

            // refcount_bits == 16
            4 => {
                let raw_data_slice = unsafe { self.raw_data.as_ref().into_typed_slice::<u16>() };
                let atomic = unsafe {
                    AtomicU16::from_ptr(&raw_data_slice[index] as *const u16 as *mut u16)
                };
                u16::from_be(atomic.load(Ordering::Relaxed)) as u64
            }

            // refcount_bits == 32
            5 => {
                let raw_data_slice = unsafe { self.raw_data.as_ref().into_typed_slice::<u32>() };
                let atomic = unsafe {
                    AtomicU32::from_ptr(&raw_data_slice[index] as *const u32 as *mut u32)
                };
                u32::from_be(atomic.load(Ordering::Relaxed)) as u64
            }

            // refcount_bits == 64
            6 => {
                let raw_data_slice = unsafe { self.raw_data.as_ref().into_typed_slice::<u64>() };
                let atomic = unsafe {
                    AtomicU64::from_ptr(&raw_data_slice[index] as *const u64 as *mut u64)
                };
                u64::from_be(atomic.load(Ordering::Relaxed))
            }

            _ => unreachable!(),
        }
    }

    /// Allow modifying this refcount block.
    ///
    /// Note that readers are allowed to exist while modifications are happening.
    pub async fn lock_write(&self) -> RefBlockWriteGuard<'_> {
        RefBlockWriteGuard {
            rb: self,
            _lock: self.writer_lock.lock().await,
        }
    }

    /// Check whether this block has been modified since it was last written.
    pub fn is_modified(&self) -> bool {
        self.modified.load(Ordering::Relaxed)
    }

    /// Clear the modified flag.
    pub fn clear_modified(&self) {
        self.modified.store(false, Ordering::Relaxed);
    }

    /// Set the modified flag.
    pub fn set_modified(&self) {
        self.modified.store(true, Ordering::Relaxed);
    }

    /// Check whether the given cluster’s refcount is 0.
    pub fn is_zero(&self, index: usize) -> bool {
        self.get(index) == 0
    }
}

impl RefBlockWriteGuard<'_> {
    /// # Safety
    /// Caller must ensure there are no concurrent writers.
    unsafe fn fetch_update_bitset(
        bitset: &AtomicU8,
        change: i64,
        base_mask: u8,
        shift: usize,
    ) -> io::Result<u64> {
        let mask = base_mask << shift;

        // load + store is OK without concurrent writers
        let full = bitset.load(Ordering::Relaxed);
        let old = (full & mask) >> shift;
        let new = if change > 0 {
            let change = change.try_into().map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("Requested refcount change of {change} is too big for the image’s refcount width"),
                )
            })?;
            old.checked_add(change)
        } else {
            let change = (-change).try_into().map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("Requested refcount change of {change} is too big for the image’s refcount width"),
                )
            })?;
            old.checked_sub(change)
        };
        let new = new.ok_or_else(|| {
            invalid_data(format!(
                "Changing refcount from {old} by {change} would overflow"
            ))
        })?;
        if new > base_mask {
            return Err(invalid_data(format!(
                "Changing refcount from {old} to {new} (by {change}) would overflow"
            )));
        }

        let full = (full & !mask) | (new << shift);
        bitset.store(full, Ordering::Relaxed);
        Ok(old as u64)
    }

    /// # Safety
    /// Caller must ensure there are no concurrent writers.
    unsafe fn fetch_update_full<
        T,
        L: FnOnce(&T) -> u64,
        S: FnOnce(&T, u64) -> Result<(), TryFromIntError>,
    >(
        atomic: &T,
        change: i64,
        load: L,
        store: S,
    ) -> io::Result<u64> {
        // load + store is OK without concurrent writers
        let old = load(atomic);

        let new = if change > 0 {
            old.checked_add(change as u64)
        } else {
            old.checked_sub(-change as u64)
        };
        let new = new.ok_or_else(|| {
            invalid_data(format!(
                "Changing refcount from {old} by {change} would overflow"
            ))
        })?;

        store(atomic, new).map_err(|_| {
            invalid_data(format!(
                "Changing refcount from {old} to {new} (by {change}) would overflow"
            ))
        })?;

        Ok(old)
    }

    /// Modify the given cluster’s refcount.
    fn modify(&mut self, index: usize, change: i64) -> io::Result<u64> {
        let result = match self.rb.refcount_order {
            // refcount_bits == 1, 2, 4
            0..=2 => {
                let (index, mask, shift) = self.rb.sub_byte_refcount_access(index);
                let raw_data_slice = unsafe { self.rb.raw_data.as_ref().into_typed_slice::<u8>() };
                let atomic =
                    unsafe { AtomicU8::from_ptr(&raw_data_slice[index] as *const u8 as *mut u8) };
                // Safe: `RefBlockWriteGuard` ensures there are no concurrent writers.
                unsafe { Self::fetch_update_bitset(atomic, change, mask, shift) }
            }

            // refcount_bits == 8
            3 => {
                let raw_data_slice = unsafe { self.rb.raw_data.as_ref().into_typed_slice::<u8>() };
                let atomic =
                    unsafe { AtomicU8::from_ptr(&raw_data_slice[index] as *const u8 as *mut u8) };
                // Safe: `RefBlockWriteGuard` ensures there are no concurrent writers.
                unsafe {
                    Self::fetch_update_full(
                        atomic,
                        change,
                        |a| a.load(Ordering::Relaxed) as u64,
                        |a, v| {
                            a.store(v.try_into()?, Ordering::Relaxed);
                            Ok(())
                        },
                    )
                }
            }

            // refcount_bits == 16
            4 => {
                let raw_data_slice = unsafe { self.rb.raw_data.as_ref().into_typed_slice::<u16>() };
                let atomic = unsafe {
                    AtomicU16::from_ptr(&raw_data_slice[index] as *const u16 as *mut u16)
                };
                unsafe {
                    Self::fetch_update_full(
                        atomic,
                        change,
                        |a| u16::from_be(a.load(Ordering::Relaxed)) as u64,
                        |a, v| {
                            a.store(u16::try_from(v)?.to_be(), Ordering::Relaxed);
                            Ok(())
                        },
                    )
                }
            }

            // refcount_bits == 32
            5 => {
                let raw_data_slice = unsafe { self.rb.raw_data.as_ref().into_typed_slice::<u32>() };
                let atomic = unsafe {
                    AtomicU32::from_ptr(&raw_data_slice[index] as *const u32 as *mut u32)
                };
                unsafe {
                    Self::fetch_update_full(
                        atomic,
                        change,
                        |a| u32::from_be(a.load(Ordering::Relaxed)) as u64,
                        |a, v| {
                            a.store(u32::try_from(v)?.to_be(), Ordering::Relaxed);
                            Ok(())
                        },
                    )
                }
            }

            // refcount_bits == 64
            6 => {
                let raw_data_slice = unsafe { self.rb.raw_data.as_ref().into_typed_slice::<u64>() };
                let atomic = unsafe {
                    AtomicU64::from_ptr(&raw_data_slice[index] as *const u64 as *mut u64)
                };
                unsafe {
                    Self::fetch_update_full(
                        atomic,
                        change,
                        |a| u64::from_be(a.load(Ordering::Relaxed)),
                        |a, v| {
                            a.store(v.to_be(), Ordering::Relaxed);
                            Ok(())
                        },
                    )
                }
            }

            _ => unreachable!(),
        };

        let result = result?;
        self.rb.modified.store(true, Ordering::Relaxed);
        Ok(result)
    }

    /// Increment the given cluster’s refcount.
    ///
    /// Returns the old value.
    pub fn increment(&mut self, index: usize) -> io::Result<u64> {
        self.modify(index, 1)
    }

    /// Decrement the given cluster’s refcount.
    ///
    /// Returns the old value.
    pub fn decrement(&mut self, index: usize) -> io::Result<u64> {
        self.modify(index, -1)
    }

    /// Check whether the given cluster’s refcount is 0.
    pub fn is_zero(&self, index: usize) -> bool {
        self.rb.is_zero(index)
    }
}

impl Drop for RefBlock {
    fn drop(&mut self) {
        if self.is_modified() {
            error!(
                "Refcount block dropped while modified; was the image closed before being flushed?"
            );
        }
    }
}

/// Generic trait for qcow2 table entries (L1, L2, refcount table).
pub trait TableEntry
where
    Self: Sized,
{
    /// Load the given raw value, checking it for validity.
    fn try_from_plain(value: u64, header: &Header) -> io::Result<Self>;

    /// Return the contained raw value.
    fn to_plain(&self) -> u64;
}

/// Generic trait for qcow2 metadata tables (L1, L2, refcount table).
pub trait Table: Sized {
    /// Internal type for each table entry.
    type InternalEntry: TableEntry;
    /// Externally visible type for each table entry.
    type Entry: Copy;
    /// User-readable struct name.
    const NAME: &'static str;
    /// Maximum allowable number of entries.
    const MAX_ENTRIES: usize;

    /// Create a new table with the given contents
    fn from_data(data: Box<[Self::InternalEntry]>, header: &Header) -> Self;

    /// Number of entries.
    fn entries(&self) -> usize;
    /// Get the given entry (as reference).
    fn get_ref(&self, index: usize) -> Option<&Self::InternalEntry>;
    /// Get the given entry (copied).
    fn get(&self, index: usize) -> Self::Entry;
    /// Get this table’s (first) cluster in the image file.
    fn get_cluster(&self) -> Option<HostCluster>;
    /// Get this table’s offset in the image file.
    fn get_offset(&self) -> Option<HostOffset>;
    /// Set this table’s (first) cluster in the image file (for writing).
    fn set_cluster(&mut self, cluster: HostCluster);
    /// Remove the table’s association with any cluster in the image file.
    fn unset_cluster(&mut self);

    /// Return log2 of the cluster size.
    ///
    /// All tables store this anyway.
    fn cluster_bits(&self) -> u32;

    /// Check whether this table has been modified since it was last written.
    fn is_modified(&self) -> bool;
    /// Clear the modified flag.
    fn clear_modified(&self);
    /// Set the modified flag.
    fn set_modified(&self);

    /// Table size in bytes.
    fn byte_size(&self) -> usize {
        self.entries() * size_of::<u64>()
    }

    /// Number of clusters used by this table.
    fn cluster_count(&self) -> ClusterCount {
        ClusterCount::from_byte_size(self.byte_size() as u64, self.cluster_bits())
    }

    /// Load a table from the image file.
    async fn load<S: Storage>(
        image: &S,
        header: &Header,
        cluster: HostCluster,
        entries: usize,
    ) -> io::Result<Self> {
        let offset = cluster.offset(header.cluster_bits());

        check_table(
            Self::NAME,
            offset.0,
            entries,
            size_of::<u64>(),
            Self::MAX_ENTRIES,
            header.cluster_size(),
        )?;

        let byte_size = entries * size_of::<u64>();
        let mut buffer = IoBuffer::new(byte_size, cmp::max(image.mem_align(), size_of::<u64>()))?;

        image.read(&mut buffer, offset.0).await?;

        // Safe because `u64` is a plain type, and the alignment fits
        let raw_table = unsafe { buffer.as_ref().into_typed_slice::<u64>() };

        let mut table = Vec::<Self::InternalEntry>::with_capacity(entries);
        for be_value in raw_table {
            table.push(Self::InternalEntry::try_from_plain(
                u64::from_be(*be_value),
                header,
            )?)
        }

        let mut table = Self::from_data(table.into_boxed_slice(), header);
        table.set_cluster(cluster);
        table.clear_modified();
        Ok(table)
    }

    /// Write a table to the image file.
    ///
    /// Callers must ensure the table is copied, i.e. its refcount is 1.
    async fn write<S: Storage>(&self, image: &S) -> io::Result<()> {
        let offset = self
            .get_offset()
            .ok_or_else(|| io::Error::other("Cannot write qcow2 metadata table, no offset set"))?;

        check_table(
            Self::NAME,
            offset.0,
            self.entries(),
            size_of::<u64>(),
            Self::MAX_ENTRIES,
            1 << self.cluster_bits(),
        )?;

        let byte_size = self.byte_size();
        let mut buffer = IoBuffer::new(byte_size, cmp::max(image.mem_align(), size_of::<u64>()))?;

        self.clear_modified();

        // Safe because we have just allocated this, and it fits the alignment
        let raw_table = unsafe { buffer.as_mut().into_typed_slice::<u64>() };
        for (i, be_value) in raw_table.iter_mut().enumerate() {
            // 0 always works, that’s by design.
            *be_value = self.get_ref(i).map(|e| e.to_plain()).unwrap_or(0).to_be();
        }

        if let Err(err) = image.write(&buffer, offset.0).await {
            self.set_modified();
            return Err(err);
        }

        Ok(())
    }

    /// Write at least the given single (modified) entry to the image file.
    ///
    /// Potentially writes more of the table, if alignment requirements ask for that.
    async fn write_entry<S: Storage>(&self, image: &S, index: usize) -> io::Result<()> {
        // This alignment calculation code implicitly assumes that the cluster size is aligned to
        // the storage’s request/memory alignment, but that is often fair.  If that is not the
        // case, there is not much we can do anyway.
        let byte_size = self.byte_size();
        let power_of_two_up_to_byte_size = if byte_size.is_power_of_two() {
            byte_size
        } else {
            ((byte_size + 1) / 2).next_power_of_two()
        };
        let alignment = cmp::min(
            power_of_two_up_to_byte_size,
            cmp::max(
                cmp::max(image.mem_align(), image.req_align()),
                size_of::<u64>(),
            ),
        );
        let alignment_in_entries = alignment / size_of::<u64>();

        let offset = self
            .get_offset()
            .ok_or_else(|| io::Error::other("Cannot write qcow2 metadata table, no offset set"))?;

        check_table(
            Self::NAME,
            offset.0,
            self.entries(),
            size_of::<u64>(),
            Self::MAX_ENTRIES,
            1 << self.cluster_bits(),
        )?;

        let mut buffer = IoBuffer::new(alignment, cmp::max(image.mem_align(), size_of::<u64>()))?;

        // Safe because we have just allocated this, and it fits the alignment
        let raw_entries = unsafe { buffer.as_mut().into_typed_slice::<u64>() };
        let first_index = (index / alignment_in_entries) * alignment_in_entries;
        #[allow(clippy::needless_range_loop)]
        for i in 0..alignment_in_entries {
            // 0 always works, that’s by design.
            raw_entries[i] = self
                .get_ref(first_index + i)
                .map(|e| e.to_plain())
                .unwrap_or(0)
                .to_be();
        }

        image
            .write(&buffer, offset.0 + (first_index * size_of::<u64>()) as u64)
            .await
    }
}

/// Check whether the given table offset/size is valid.
///
/// Also works for refcount blocks (with cheating, because their entry size can be less than a
/// byte), which is why it is outside of [`Table`].
fn check_table(
    name: &str,
    offset: u64,
    entries: usize,
    entry_size: usize,
    max_entries: usize,
    cluster_size: usize,
) -> io::Result<()> {
    if entries > max_entries {
        return Err(invalid_data(format!(
            "{name} too big: {entries} > {max_entries}",
        )));
    }

    if offset % (cluster_size as u64) != 0 {
        return Err(invalid_data(format!("{name}: Unaligned offset: {offset}")));
    }

    let byte_size = entries
        .checked_mul(entry_size)
        .ok_or_else(|| invalid_data(format!("{name} size overflow: {entries} * {entry_size}")))?;
    let end_offset = offset
        .checked_add(byte_size as u64)
        .ok_or_else(|| invalid_data(format!("{name} offset overflow: {offset} + {byte_size}")))?;
    if end_offset > MAX_FILE_LENGTH {
        return Err(invalid_data(format!(
            "{name}: Invalid end offset: {end_offset} > {MAX_FILE_LENGTH}"
        )));
    }

    Ok(())
}
