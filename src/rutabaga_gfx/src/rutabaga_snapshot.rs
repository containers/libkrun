// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::collections::BTreeMap;
use std::io::Read;
use std::io::Write;
use zerocopy::AsBytes;
use zerocopy::FromBytes;

pub struct RutabagaSnapshot {
    pub resources: BTreeMap<u32, RutabagaResourceSnapshot>,
}

pub struct RutabagaResourceSnapshot {
    pub resource_id: u32,
    pub width: u32,
    pub height: u32,
}

impl RutabagaSnapshot {
    // To avoid adding a build dependency, we use a custom serialization format. It is an internal
    // detail, doesn't need to support host migration (e.g. we don't need to care about endianess
    // or integer sizes), and isn't expected to be stable across releases.
    pub fn serialize_to(&self, w: &mut impl Write) -> std::io::Result<()> {
        fn write(w: &mut impl Write, v: impl AsBytes) -> std::io::Result<()> {
            w.write_all(v.as_bytes())
        }

        write(w, self.resources.len())?;
        for (id, resource) in self.resources.iter() {
            assert_eq!(*id, resource.resource_id);
            write(w, resource.resource_id)?;
            write(w, resource.width)?;
            write(w, resource.height)?;
        }

        Ok(())
    }

    pub fn deserialize_from(r: &mut impl Read) -> std::io::Result<Self> {
        fn read<T: AsBytes + FromBytes + Default>(r: &mut impl Read) -> std::io::Result<T> {
            let mut v: T = Default::default();
            r.read_exact(v.as_bytes_mut())?;
            Ok(v)
        }

        let num_resources: usize = read::<usize>(r)?;
        let mut resources = BTreeMap::new();
        for _ in 0..num_resources {
            let resource_id = read(r)?;
            let width = read(r)?;
            let height = read(r)?;
            resources.insert(
                resource_id,
                RutabagaResourceSnapshot {
                    resource_id,
                    width,
                    height,
                },
            );
        }

        // Verify we have consumed the all the input by checking for EOF.
        let mut buf = [0u8];
        if r.read(&mut buf)? != 0 {
            return Err(std::io::ErrorKind::InvalidData.into());
        }

        Ok(RutabagaSnapshot { resources })
    }
}
