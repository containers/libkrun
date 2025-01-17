# Imago

Provides access to VM image formats.

Simple example (requires the `sync-wrappers` feature):
```rust
use imago::file::File;
use imago::qcow2::Qcow2;
use imago::SyncFormatAccess;
use std::fs::OpenOptions;

// Produce read-only qcow2 instance using purely `File` for storage
let mut qcow2 = Qcow2::<File>::open_path_sync("image.qcow2", false)?;
qcow2.open_implicit_dependencies_sync()?;

let qcow2 = SyncFormatAccess::new(qcow2)?;

let mut buf = vec![0u8; 512];
qcow2.read(&mut buf, 0)?;
```

Another example, using the native async interface instead of sync wrapper functions, explicitly
overriding the implicit references contained in qcow2 files, and showcasing using different
types of storage (specifically normal files and null storage):
```rust
use imago::file::File;
use imago::null::Null;
use imago::qcow2::Qcow2;
use imago::raw::Raw;
use imago::{DynStorage, FormatAccess, Storage, StorageOpenOptions};
use std::sync::Arc;

let qcow2_file_opts = StorageOpenOptions::new()
    .write(true)
    .filename(String::from("image.qcow2"));
let qcow2_file = File::open(qcow2_file_opts).await?;

// Produce qcow2 instance with arbitrary (and potentially mixed) storage instances
let mut qcow2 =
    Qcow2::<Box<dyn DynStorage>, Arc<FormatAccess<_>>>::open_image(Box::new(qcow2_file), true)
        .await?;

let backing_storage: Box<dyn DynStorage> = Box::new(Null::new(0));
let backing = Raw::open_image(backing_storage, false).await?;
let backing = Arc::new(FormatAccess::new(backing));
qcow2.set_backing(Some(Arc::clone(&backing)));

// Open potentially remaining dependencies (like an external data file)
qcow2.open_implicit_dependencies().await?;

let qcow2 = FormatAccess::new(qcow2);

let mut buf = vec![0u8; 512];
qcow2.read(&mut buf, 0).await?;

qcow2.flush().await?;
```

# Flushing

Given that `AsyncDrop` is not stable yet (and probably will not be stable for a long time),
callers must ensure that images are properly flushed before dropping them, i.e. call
`.flush().await` on any image that is not read-only.

(The synchronous wrapper `SyncFormatAccess` does perform a synchronous flush in its `Drop`
implementation.)

# Features

- `sync-wrappers`: Provide synchronous wrappers for the native `async` interface.  Note that
  these build a `tokio` runtime in which they run the `async` functions, so using the `async`
  interface is definitely preferred.

- `vm-memory`: Provide conversion functions `IoVector::from_volatile_slice` and
  `IoVectorMut::from_volatile_slice` to convert the vm-memory crate’s `[VolatileSlice]` arrays into
  imago’s native I/O vectors.
