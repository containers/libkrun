// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

mod descriptor;
mod memory_mapping;
mod shm;
pub mod sys;

pub use descriptor::AsRawDescriptor;
pub use descriptor::AsRawDescriptors;
pub use descriptor::FromRawDescriptor;
pub use descriptor::IntoRawDescriptor;
pub use descriptor::SafeDescriptor;
pub use shm::SharedMemory;

pub use memory_mapping::MemoryMapping;

pub use sys::platform::descriptor::RawDescriptor;
pub use sys::platform::shm::round_up_to_page_size;

pub unsafe trait MappedRegion: Send + Sync {
    /// Returns a pointer to the beginning of the memory region. Should only be
    /// used for passing this region to ioctls for setting guest memory.
    fn as_ptr(&self) -> *mut u8;

    /// Returns the size of the memory region in bytes.
    fn size(&self) -> usize;
}
