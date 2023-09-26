// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

pub mod descriptor;
pub mod memory_mapping;
pub mod shm;

pub use shm::round_up_to_page_size;
pub use shm::SharedMemory;

pub use memory_mapping::MemoryMapping;
