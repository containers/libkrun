// Copyright 2021 The ChromiumOS Authors
// Copyright 2023 Red Hat, Inc.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::env;

fn main() -> Result<(), pkg_config::Error> {
    // Skip installing dependencies when generating documents.
    if env::var("CARGO_DOC").is_ok() {
        return Ok(());
    }

    pkg_config::Config::new().probe("epoxy")?;
    pkg_config::Config::new().probe("libdrm")?;
    pkg_config::Config::new().probe("virglrenderer")?;

    Ok(())
}
