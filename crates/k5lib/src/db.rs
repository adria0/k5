// The database of attestation records.
//
// Records are text entries addressed by name (`<k5>-<type>...md`, the name
// carries the attested k5, see `attestations`). [`Db`] is how the rest of the
// library reads and stores them, so it does not depend on where they live.
// [`FsDb`] is the default implementation: a directory, [`DIR`], with one file
// per record.
//
// The trait only stores and fetches records. Which entries are attestations,
// and whether they are valid, is decided by `attestations`.

use std::{
    io::Write,
    path::{Path, PathBuf},
};

use anyhow::anyhow;
use async_trait::async_trait;

use crate::Error;

/// Directory of the default database.
pub const DIR: &str = "db/attestations";
/// Directory of the default inbox: received signcrypted messages, stored as
/// received (still encrypted), in a [`Db`] of their own.
pub const INBOX_DIR: &str = "db/inbox";
/// Directory of the default sent messages: a copy of each message sent,
/// signcrypted to the local key, in a [`Db`] of their own.
pub const SENT_DIR: &str = "db/sent";

/// Storage of attestation records by name.
#[async_trait]
pub trait Db: Send + Sync {
    /// Names of all the entries, in no particular order.
    async fn names(&self) -> Result<Vec<String>, Error>;

    /// The record of the entry `name`, or `None` if there is none.
    async fn get(&self, name: &str) -> Result<Option<String>, Error>;

    /// Stores `record` as the entry `name`, replacing any existing one.
    async fn put(&self, name: &str, record: &str) -> Result<(), Error>;

    /// Where the entry `name` is stored, for messages (a path, a URL...).
    fn location(&self, name: &str) -> String {
        name.to_string()
    }
}

/// A database kept as a directory, with one file per record, named as the
/// entry. The directory is created on the first write.
pub struct FsDb {
    dir: PathBuf,
}

impl FsDb {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    /// Path of the entry `name`, which must not escape the directory.
    fn path(&self, name: &str) -> Result<PathBuf, Error> {
        if name.is_empty() || name.starts_with('.') || name.contains(['/', '\\']) {
            return Err(anyhow!("invalid entry name `{name}`"));
        }

        Ok(self.dir.join(name))
    }
}

impl Default for FsDb {
    /// The database in [`DIR`].
    fn default() -> Self {
        Self::new(DIR)
    }
}

#[async_trait]
impl Db for FsDb {
    async fn names(&self) -> Result<Vec<String>, Error> {
        let mut entries = match tokio::fs::read_dir(&self.dir).await {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e.into()),
        };

        let mut names = Vec::new();
        while let Some(entry) = entries.next_entry().await? {
            let name = entry.file_name().to_string_lossy().into_owned();
            // Hidden entries cannot be addressed (see `path`), and include the
            // temporary files of writes in progress.
            if !name.starts_with('.') {
                names.push(name);
            }
        }

        Ok(names)
    }

    async fn get(&self, name: &str) -> Result<Option<String>, Error> {
        let path = self.path(name)?;
        match tokio::fs::read_to_string(path).await {
            Ok(record) => Ok(Some(record)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    async fn put(&self, name: &str, record: &str) -> Result<(), Error> {
        let path = self.path(name)?;
        tokio::fs::create_dir_all(&self.dir).await?;
        let record = record.to_string();
        tokio::task::spawn_blocking(move || write_atomic(&path, record.as_bytes(), false, false))
            .await
            .map_err(|e| anyhow!("writing {name}: {e}"))??;

        Ok(())
    }

    fn location(&self, name: &str) -> String {
        format!("{}/{name}", self.dir.display())
    }
}

/// Writes `content` to `path` atomically: to a hidden temporary file in the
/// same directory, synced to disk, then moved over `path`. A crash leaves
/// either the old file or the new one, never a truncated one, and readers
/// never see a partial write. With `private`, the file is readable only by
/// its owner. With `create_new`, fails if `path` exists: the name is claimed
/// first (an empty file, created only if there is none), then replaced. A
/// crash in between leaves that empty file, never a partial one. No hard link
/// is used, as Android does not let apps create them.
pub(crate) fn write_atomic(
    path: &Path,
    content: &[u8],
    private: bool,
    create_new: bool,
) -> std::io::Result<()> {
    let dir = match path.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => dir,
        _ => Path::new("."),
    };
    let file_name = path.file_name().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("{} is not a file", path.display()),
        )
    })?;
    let tmp = dir.join(format!(
        ".{}.{:016x}.tmp",
        file_name.to_string_lossy(),
        rand::random::<u64>()
    ));

    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    if private {
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    }
    #[cfg(not(unix))]
    let _ = private;

    if create_new {
        options.open(path)?;
    }
    let result = (|| {
        let mut file = options.open(&tmp)?;
        file.write_all(content)?;
        file.sync_all()?;
        std::fs::rename(&tmp, path)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
        if create_new {
            // The empty file this call claimed.
            let _ = std::fs::remove_file(path);
        }
    }
    result?;

    // Make the new directory entry durable too.
    #[cfg(unix)]
    std::fs::File::open(dir)?.sync_all()?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_fs_db() {
        let dir = std::env::temp_dir().join(format!("k5-db-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let db = FsDb::new(&dir);

        // Missing directory: an empty database.
        assert!(db.names().await.unwrap().is_empty());
        assert_eq!(db.get("a.md").await.unwrap(), None);

        db.put("a.md", "one").await.unwrap();
        db.put("b.md", "two").await.unwrap();
        db.put("a.md", "three").await.unwrap();
        let mut names = db.names().await.unwrap();
        names.sort();
        assert_eq!(names, ["a.md", "b.md"]);
        assert_eq!(db.get("a.md").await.unwrap().as_deref(), Some("three"));
        assert_eq!(db.location("a.md"), format!("{}/a.md", dir.display()));

        // Writes leave no temporary files behind.
        let mut entries: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        entries.sort();
        assert_eq!(entries, ["a.md", "b.md"]);

        // Names never escape the directory.
        for name in ["", ".hidden.md", "../a.md", "x/a.md", "x\\a.md"] {
            assert!(db.put(name, "x").await.is_err(), "{name}");
            assert!(db.get(name).await.is_err(), "{name}");
        }

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_write_atomic() {
        let dir = std::env::temp_dir().join(format!("k5-write-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("f");

        write_atomic(&path, b"one", true, true).unwrap();
        // `create_new` never replaces an existing file.
        let err = write_atomic(&path, b"two", true, true).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists);
        assert_eq!(std::fs::read(&path).unwrap(), b"one");

        write_atomic(&path, b"three", true, false).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"three");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        // Only the file itself is left.
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1);

        std::fs::remove_dir_all(&dir).unwrap();
    }
}
