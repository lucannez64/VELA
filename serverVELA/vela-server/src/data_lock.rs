use std::{fs::File, path::Path};

use anyhow::{Context, Result};
use fs2::FileExt;

pub struct DataDirLock {
    _file: File,
}

impl DataDirLock {
    pub fn try_acquire(data_dir: &Path) -> Result<Self> {
        std::fs::create_dir_all(data_dir)
            .with_context(|| format!("failed to create data dir {}", data_dir.display()))?;
        let lock_path = data_dir.join(".vela-data.lock");
        let file = File::options()
            .create(true)
            .read(true)
            .write(true)
            .open(&lock_path)
            .with_context(|| format!("failed to open lock file {}", lock_path.display()))?;
        file.try_lock_exclusive().with_context(|| {
            format!(
                "failed to lock {}; stop vela-server before migration",
                lock_path.display()
            )
        })?;
        Ok(Self { _file: file })
    }
}
