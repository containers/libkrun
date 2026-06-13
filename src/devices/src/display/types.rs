// Copyright 2026, Red Hat Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Common display types for EDID generation.

#[derive(Debug, Clone, Copy)]
pub struct EdidParams {
    pub refresh_rate: u32,
    pub physical_size: PhysicalSize,
}

impl Default for EdidParams {
    fn default() -> Self {
        EdidParams {
            refresh_rate: 60,
            physical_size: PhysicalSize::Dpi(300),
        }
    }
}

#[derive(Debug, Copy, Clone)]
pub enum PhysicalSize {
    Dpi(u32),
    DimensionsMillimeters(u16, u16),
}
