// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.
use crate::virtio::net::Result;
use std::os::fd::RawFd;

pub struct Net {
    id: String,
}

impl Net {
    /// Create a new virtio network device using passt
    pub fn new(id: String, _passt_fd: RawFd) -> Result<Self> {
        Ok(Net { id })
    }

    /// Provides the ID of this net device.
    pub fn id(&self) -> &str {
        &self.id
    }
}
