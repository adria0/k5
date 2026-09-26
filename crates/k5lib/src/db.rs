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

use std::path::PathBuf;

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
            return Err(format!("invalid entry name `{name}`").into());
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
            names.push(entry.file_name().to_string_lossy().into_owned());
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
        tokio::fs::write(path, record).await?;

        Ok(())
    }

    fn location(&self, name: &str) -> String {
        format!("{}/{name}", self.dir.display())
    }
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

        // Names never escape the directory.
        for name in ["", ".hidden.md", "../a.md", "x/a.md", "x\\a.md"] {
            assert!(db.put(name, "x").await.is_err(), "{name}");
            assert!(db.get(name).await.is_err(), "{name}");
        }

        std::fs::remove_dir_all(&dir).unwrap();
    }
}
