//! Helper types.
//!
//! Contains types like `GuestOffset` or `HostCluster`.  This strong typing ensures there is no
//! confusion between what is what.

use super::*;
use std::fmt::{self, Display, Formatter};
use std::ops::{Add, AddAssign, Sub, SubAssign};

/// Guest offset.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(super) struct GuestOffset(pub u64);

/// Guest cluster index.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(super) struct GuestCluster(pub u64);

/// Host cluster offset.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(super) struct HostOffset(pub u64);

/// Host cluster index.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(super) struct HostCluster(pub u64);

/// Cluster count.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(super) struct ClusterCount(pub u64);

impl GuestOffset {
    /// Return the offset from the start of the containing guest clusters.
    pub fn in_cluster_offset(self, cluster_bits: u32) -> usize {
        (self.0 % (1 << cluster_bits)) as usize
    }

    /// Return the containing cluster’s index in its L2 table.
    pub fn l2_index(self, cluster_bits: u32) -> usize {
        self.cluster(cluster_bits).l2_index(cluster_bits)
    }

    /// Return the containing cluster’s L2 table’s index in the L1 table.
    pub fn l1_index(self, cluster_bits: u32) -> usize {
        self.cluster(cluster_bits).l1_index(cluster_bits)
    }

    /// Return the containing cluster’s index.
    pub fn cluster(self, cluster_bits: u32) -> GuestCluster {
        GuestCluster(self.0 >> cluster_bits)
    }

    /// How many bytes remain in this cluster after this offset.
    pub fn remaining_in_cluster(self, cluster_bits: u32) -> u64 {
        ((1 << cluster_bits) - self.in_cluster_offset(cluster_bits)) as u64
    }

    /// How many bytes remain in this L2 table after this offset.
    pub fn remaining_in_l2_table(self, cluster_bits: u32) -> u64 {
        // See `Header::l2_entries()`
        let l2_entries = 1 << (cluster_bits - 3);
        let after_this = ((l2_entries - (self.l2_index(cluster_bits) + 1)) as u64) << cluster_bits;
        self.remaining_in_cluster(cluster_bits) + after_this
    }
}

impl GuestCluster {
    /// Return this cluster’s offset.
    pub fn offset(self, cluster_bits: u32) -> GuestOffset {
        GuestOffset(self.0 << cluster_bits)
    }

    /// Return this cluster’s index in its L2 table.
    pub fn l2_index(self, cluster_bits: u32) -> usize {
        // See `Header::l2_entries()`
        let l2_entries = 1 << (cluster_bits - 3);
        (self.0 % l2_entries) as usize
    }

    /// Return this cluster’s L2 table’s index in the L1 table.
    pub fn l1_index(self, cluster_bits: u32) -> usize {
        let l2_entries_shift = cluster_bits - 3;
        (self.0 >> l2_entries_shift) as usize
    }

    /// Return the cluster at the given L1 and L2 table indices.
    pub fn from_l1_l2_indices(l1_index: usize, l2_index: usize, cluster_bits: u32) -> Self {
        let l2_entries_shift = cluster_bits - 3;
        GuestCluster(((l1_index as u64) << l2_entries_shift) + l2_index as u64)
    }

    /// Return the next cluster in this L2 table, if any.
    ///
    /// Return `None` if this is the last cluster in this L2 table.
    pub fn next_in_l2(self, cluster_bits: u32) -> Option<GuestCluster> {
        // See `Header::l2_entries()`
        let l2_entries = 1 << (cluster_bits - 3);
        let l1_index = self.l1_index(cluster_bits);
        let l2_index = self.l2_index(cluster_bits);
        let l2_index = l2_index.checked_add(1)?;
        if l2_index >= l2_entries {
            None
        } else {
            Some(GuestCluster::from_l1_l2_indices(
                l1_index,
                l2_index,
                cluster_bits,
            ))
        }
    }

    /// Return the first cluster in the next L2 table.
    pub fn first_in_next_l2(self, cluster_bits: u32) -> GuestCluster {
        let l2_entries = 1 << (cluster_bits - 3);
        GuestCluster((self.0 + 1).next_multiple_of(l2_entries))
    }
}

impl HostOffset {
    /// Return the offset from the start of the containing host cluster.
    pub fn in_cluster_offset(self, cluster_bits: u32) -> usize {
        (self.0 % (1 << cluster_bits)) as usize
    }

    /// Return the containing cluster’s index.
    pub fn cluster(self, cluster_bits: u32) -> HostCluster {
        HostCluster(self.0 >> cluster_bits)
    }

    /// If this offset points to the start of a cluster, get its index.
    ///
    /// If this offset points inside of a cluster, return `None`.  As oposed to just `cluster()`,
    /// this will not discard information: `self.checked_cluster(cb).unwrap().offset() == self`,
    /// because there is no in-cluster offset that could be lost.
    pub fn checked_cluster(self, cluster_bits: u32) -> Option<HostCluster> {
        (self.in_cluster_offset(cluster_bits) == 0).then_some(self.cluster(cluster_bits))
    }
}

impl HostCluster {
    /// Return this cluster’s offset.
    pub fn offset(self, cluster_bits: u32) -> HostOffset {
        HostOffset(self.0 << cluster_bits)
    }

    /// Get this cluster’s index in its refcount block.
    pub fn rb_index(self, rb_bits: u32) -> usize {
        let rb_entries = 1 << rb_bits;
        (self.0 % rb_entries) as usize
    }

    /// Get this cluster’s refcount block’s index in the refcount table.
    pub fn rt_index(self, rb_bits: u32) -> usize {
        (self.0 >> rb_bits) as usize
    }

    /// Get both the reftable and refblock indices for this cluster.
    pub fn rt_rb_indices(self, rb_bits: u32) -> (usize, usize) {
        (self.rt_index(rb_bits), self.rb_index(rb_bits))
    }

    /// Construct a cluster index from its reftable and refblock indices.
    pub fn from_ref_indices(rt_index: usize, rb_index: usize, rb_bits: u32) -> Self {
        HostCluster(((rt_index as u64) << rb_bits) + rb_index as u64)
    }

    /// Returns the host offset corresponding to `guest_offset`.
    ///
    /// Assuming `guest_offset.cluster()` is mapped to `self`, return the exact host offset
    /// matching `guest_offset`.
    ///
    /// Same as `self.offset(cb) + guest_offset.in_cluster_offset`.
    pub fn relative_offset(self, guest_offset: GuestOffset, cluster_bits: u32) -> HostOffset {
        self.offset(cluster_bits) + guest_offset.in_cluster_offset(cluster_bits) as u64
    }
}

impl ClusterCount {
    /// Get how many clusters are required to cover `byte_size`.
    ///
    /// This rounds up.
    pub fn from_byte_size(byte_size: u64, cluster_bits: u32) -> Self {
        ClusterCount(byte_size.div_ceil(1 << cluster_bits))
    }

    /// Return the full byte size of this many clusters.
    pub fn byte_size(self, cluster_bits: u32) -> u64 {
        self.0 << cluster_bits
    }
}

impl Add<ClusterCount> for HostCluster {
    type Output = Self;

    fn add(self, rhs: ClusterCount) -> Self {
        HostCluster(self.0 + rhs.0)
    }
}

impl AddAssign<ClusterCount> for HostCluster {
    fn add_assign(&mut self, rhs: ClusterCount) {
        self.0 += rhs.0;
    }
}

impl Sub<ClusterCount> for HostCluster {
    type Output = Self;

    fn sub(self, rhs: ClusterCount) -> Self {
        HostCluster(self.0 - rhs.0)
    }
}

impl SubAssign<ClusterCount> for HostCluster {
    fn sub_assign(&mut self, rhs: ClusterCount) {
        self.0 -= rhs.0;
    }
}

impl Sub<HostCluster> for HostCluster {
    type Output = ClusterCount;

    fn sub(self, rhs: Self) -> ClusterCount {
        ClusterCount(self.0 - rhs.0)
    }
}

impl Add<ClusterCount> for ClusterCount {
    type Output = Self;

    fn add(self, rhs: ClusterCount) -> Self {
        ClusterCount(self.0 + rhs.0)
    }
}

impl AddAssign<ClusterCount> for ClusterCount {
    fn add_assign(&mut self, rhs: ClusterCount) {
        self.0 += rhs.0;
    }
}

impl Sub<ClusterCount> for ClusterCount {
    type Output = Self;

    fn sub(self, rhs: ClusterCount) -> Self {
        ClusterCount(self.0 - rhs.0)
    }
}

impl SubAssign<ClusterCount> for ClusterCount {
    fn sub_assign(&mut self, rhs: ClusterCount) {
        self.0 -= rhs.0;
    }
}

impl Add<u64> for HostOffset {
    type Output = Self;

    fn add(self, rhs: u64) -> Self {
        HostOffset(self.0 + rhs)
    }
}

impl Sub<u64> for HostOffset {
    type Output = Self;

    fn sub(self, rhs: u64) -> Self {
        HostOffset(self.0 - rhs)
    }
}

impl Sub<HostOffset> for HostOffset {
    type Output = u64;

    fn sub(self, rhs: Self) -> u64 {
        self.0 - rhs.0
    }
}

impl Display for GuestOffset {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "0x{:x}", self.0)
    }
}

impl Display for HostOffset {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "0x{:x}", self.0)
    }
}

impl Display for ClusterCount {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}
