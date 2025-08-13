use digest::Digest;
use md5::Md5;
use rocksdb::{ColumnFamily, ColumnFamilyDescriptor, Options};
use sha2::Sha256;
use std::borrow::Cow;
use std::path::Path;

pub mod hash;

const MD5_CF_NAME: &str = "md5";
const SHA256_CF_NAME: &str = "sha256";

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("RocksDB error")]
    Db(#[from] rocksdb::Error),
    #[error("RocksDB store error")]
    Store(#[from] rocksdb_store::error::Error),
    #[error("UTF-8 error")]
    InvalidUtf8(#[from] std::string::FromUtf8Error),
    #[error("Invalid key")]
    InvalidKey(Vec<u8>),
    #[error("Invalid value")]
    InvalidValue(Vec<u8>),
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub enum Hashes {
    #[default]
    Both,
    Md5Only,
    Sha256Only,
}

impl Hashes {
    pub fn supports_md5(&self) -> bool {
        matches!(self, Self::Both | Self::Md5Only)
    }

    pub fn supports_sha256(&self) -> bool {
        matches!(self, Self::Both | Self::Sha256Only)
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct Config {
    pub hashes: Hashes,
    pub case_sensitive: bool,
}

impl Config {
    pub fn new(hashes: Hashes, case_sensitive: bool) -> Self {
        Self {
            hashes,
            case_sensitive,
        }
    }
}

pub struct Database<const W: bool> {
    underlying: rocksdb_store::Database<W, Config, ()>,
}

impl Database<true> {
    pub fn create<P: AsRef<Path>>(path: P, config: Config) -> Result<Self, Error> {
        Ok(Self {
            underlying: rocksdb_store::Database::create(
                path,
                Self::cfs(),
                Options::default(),
                true,
                config,
                (),
            )?,
        })
    }

    pub fn add_all<'a, I: Iterator<Item = &'a str>>(&self, values: I) -> Result<(), Error> {
        // Safe since we know statically that the database is writable.
        let tx = self.underlying.db.transaction().unwrap();

        match self.underlying.config.hashes {
            Hashes::Both => {
                let mut md5_hasher = Md5::new();
                let mut sha256_hasher = Sha256::new();

                let mut md5_hash = [0u8; 16];
                let mut sha256_hash = [0u8; 32];

                let md5_cf = self.md5_cf();
                let sha256_cf = self.sha256_cf();

                for value in values {
                    let value = self.preprocess_value(value);
                    let bytes = value.as_bytes();

                    md5_hasher.update(bytes);
                    sha256_hasher.update(bytes);

                    md5_hasher.finalize_into_reset((&mut md5_hash).into());
                    sha256_hasher.finalize_into_reset((&mut sha256_hash).into());

                    tx.put(md5_cf, md5_hash, bytes)?;
                    tx.put(sha256_cf, sha256_hash, bytes)?;
                }
            }
            Hashes::Md5Only => {
                let mut md5_hasher = Md5::new();

                let mut md5_hash = [0u8; 16];

                let md5_cf = self.md5_cf();

                for value in values {
                    let value = self.preprocess_value(value);
                    let bytes = value.as_bytes();

                    md5_hasher.update(bytes);

                    md5_hasher.finalize_into_reset((&mut md5_hash).into());

                    tx.put(md5_cf, md5_hash, bytes)?;
                }
            }
            Hashes::Sha256Only => {
                let mut sha256_hasher = Sha256::new();

                let mut sha256_hash = [0u8; 32];

                let sha256_cf = self.sha256_cf();

                for value in values {
                    let value = self.preprocess_value(value);
                    let bytes = value.as_bytes();

                    sha256_hasher.update(bytes);

                    sha256_hasher.finalize_into_reset((&mut sha256_hash).into());

                    tx.put(sha256_cf, sha256_hash, bytes)?;
                }
            }
        }

        tx.commit()?;

        Ok(())
    }

    pub fn flush<P: AsRef<Path>>(path: P) -> Result<(), rocksdb::Error> {
        let mut cfs = Self::cfs();
        cfs.push(ColumnFamilyDescriptor::new("_config", Options::default()));
        cfs.push(ColumnFamilyDescriptor::new("_books", Options::default()));

        let db = rocksdb::DB::open_cf_descriptors(&Options::default(), path, cfs)?;

        db.flush_wal(true)
    }
}

impl<const W: bool> Database<W> {
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, Error> {
        Ok(Self {
            underlying: rocksdb_store::Database::open(path, Self::cfs(), Options::default())?,
        })
    }

    /// Iterate over all values in the database.
    ///
    /// Assumes that both hash tables have the same value if both are present, and does not perform any validation.
    pub fn values(&self) -> impl Iterator<Item = Result<String, Error>> {
        let cf = match self.underlying.config.hashes {
            Hashes::Both | Hashes::Md5Only => self.md5_cf(),
            Hashes::Sha256Only => self.sha256_cf(),
        };

        self.underlying
            .db
            .iterator(cf, rocksdb::IteratorMode::Start)
            .map(|result| {
                let (_, value) = result?;

                Ok(String::from_utf8(value.to_vec())?)
            })
    }

    pub fn md5_values(&self) -> impl Iterator<Item = Result<(String, [u8; 16]), Error>> {
        let cf = self.md5_cf();

        self.underlying
            .db
            .iterator(cf, rocksdb::IteratorMode::Start)
            .map(|result| {
                let (key, value) = result?;

                let hash: [u8; 16] = key
                    .as_ref()
                    .try_into()
                    .map_err(|_| Error::InvalidKey(key.to_vec()))?;

                Ok((String::from_utf8(value.to_vec())?, hash))
            })
    }

    pub fn sha256_values(&self) -> impl Iterator<Item = Result<(String, [u8; 32]), Error>> {
        let cf = self.sha256_cf();

        self.underlying
            .db
            .iterator(cf, rocksdb::IteratorMode::Start)
            .map(|result| {
                let (key, value) = result?;

                let hash: [u8; 32] = key
                    .as_ref()
                    .try_into()
                    .map_err(|_| Error::InvalidKey(key.to_vec()))?;

                Ok((String::from_utf8(value.to_vec())?, hash))
            })
    }

    pub fn lookup(&self, hash: hash::Hash) -> Result<Option<String>, Error> {
        match hash {
            hash::Hash::Md5(bytes) => self.lookup_md5(bytes),
            hash::Hash::Sha256(bytes) => self.lookup_sha256(bytes),
        }
    }

    pub fn lookup_all<I: Iterator<Item = hash::Hash>>(
        &self,
        hashes: I,
    ) -> Result<Vec<Option<String>>, Error> {
        let md5_cf = self.md5_cf();
        let sha256_cf = self.sha256_cf();

        hashes
            .map(|hash| match hash {
                hash::Hash::Md5(bytes) => self.lookup_md5_with_cf(bytes, md5_cf),
                hash::Hash::Sha256(bytes) => self.lookup_sha256_with_cf(bytes, sha256_cf),
            })
            .collect()
    }

    pub fn lookup_md5(&self, hash: [u8; 16]) -> Result<Option<String>, Error> {
        self.lookup_md5_with_cf(hash, self.md5_cf())
    }

    pub fn lookup_sha256(&self, hash: [u8; 32]) -> Result<Option<String>, Error> {
        self.lookup_sha256_with_cf(hash, self.sha256_cf())
    }

    pub fn lookup_all_md5<I: Iterator<Item = [u8; 16]>>(
        &self,
        hashes: I,
    ) -> Result<Vec<Option<String>>, Error> {
        let cf = self.md5_cf();

        hashes
            .map(|hash| self.lookup_md5_with_cf(hash, cf))
            .collect()
    }

    pub fn lookup_all_sha256<I: Iterator<Item = [u8; 32]>>(
        &self,
        hashes: I,
    ) -> Result<Vec<Option<String>>, Error> {
        let cf = self.sha256_cf();

        hashes
            .map(|hash| self.lookup_sha256_with_cf(hash, cf))
            .collect()
    }

    fn lookup_with_cf(
        &self,
        hash: &[u8],
        cf: &rocksdb::ColumnFamily,
    ) -> Result<Option<String>, Error> {
        self.underlying
            .db
            .get(cf, hash)
            .map_err(Error::from)
            .and_then(|bytes| {
                bytes.map_or_else(
                    || Ok(None),
                    |bytes| {
                        String::from_utf8(bytes.to_vec())
                            .map_err(Error::from)
                            .map(Some)
                    },
                )
            })
    }

    fn lookup_md5_with_cf(
        &self,
        hash: [u8; 16],
        cf: &rocksdb::ColumnFamily,
    ) -> Result<Option<String>, Error> {
        if self.underlying.config.hashes.supports_md5() {
            self.lookup_with_cf(&hash, cf)
        } else {
            Ok(None)
        }
    }

    fn lookup_sha256_with_cf(
        &self,
        hash: [u8; 32],
        cf: &rocksdb::ColumnFamily,
    ) -> Result<Option<String>, Error> {
        if self.underlying.config.hashes.supports_sha256() {
            self.lookup_with_cf(&hash, cf)
        } else {
            Ok(None)
        }
    }

    fn md5_cf(&self) -> &ColumnFamily {
        // If this fails that is a programming error.
        self.underlying.db.handle(MD5_CF_NAME).unwrap()
    }

    fn sha256_cf(&self) -> &ColumnFamily {
        // If this fails that is a programming error.
        self.underlying.db.handle(SHA256_CF_NAME).unwrap()
    }

    fn cfs() -> Vec<ColumnFamilyDescriptor> {
        let mut cf_options = Options::default();

        cf_options.set_compression_type(rocksdb::DBCompressionType::Zstd);

        vec![
            ColumnFamilyDescriptor::new(MD5_CF_NAME, cf_options.clone()),
            ColumnFamilyDescriptor::new(SHA256_CF_NAME, cf_options),
        ]
    }

    fn preprocess_value<'a>(&self, value: &'a str) -> Cow<'a, str> {
        if self.underlying.config.case_sensitive || value.chars().all(|c| c.is_ascii_lowercase()) {
            value.into()
        } else {
            Cow::from(value.to_ascii_lowercase())
        }
    }
}

#[cfg(test)]
mod tests {
    use digest::Digest;
    use md5::Md5;
    use sha2::Sha256;
    use std::collections::HashSet;

    impl quickcheck::Arbitrary for super::Hashes {
        fn arbitrary(g: &mut quickcheck::Gen) -> Self {
            *g.choose(&[Self::Both, Self::Md5Only, Self::Sha256Only])
                .unwrap()
        }
    }

    impl quickcheck::Arbitrary for super::Config {
        fn arbitrary(g: &mut quickcheck::Gen) -> Self {
            Self {
                hashes: super::Hashes::arbitrary(g),
                case_sensitive: bool::arbitrary(g),
            }
        }
    }

    #[quickcheck_macros::quickcheck]
    fn add_all_lookup(
        config: super::Config,
        values: HashSet<String>,
        excluded: HashSet<String>,
    ) -> bool {
        let mut excluded = excluded.difference(&values).collect::<HashSet<_>>();

        if !config.case_sensitive {
            let lowercase_values = values
                .iter()
                .map(|value| value.to_ascii_lowercase())
                .collect::<HashSet<_>>();

            excluded = excluded
                .iter()
                .filter(|value| !lowercase_values.contains(&value.to_ascii_lowercase()))
                .cloned()
                .collect();
        }

        let test_db_dir = tempfile::tempdir().unwrap();

        let database = super::Database::create(test_db_dir, config).unwrap();

        database
            .add_all(values.iter().map(|value| value.as_str()))
            .unwrap();

        assert_eq!(
            database.md5_values().count(),
            if config.hashes.supports_md5() {
                values.len()
            } else {
                0
            }
        );
        assert_eq!(
            database.sha256_values().count(),
            if config.hashes.supports_sha256() {
                values.len()
            } else {
                0
            }
        );

        for value in &values {
            let value = if config.case_sensitive {
                value
            } else {
                &value.to_ascii_lowercase()
            };

            let md5_result = database
                .lookup_md5(Md5::digest(value.as_bytes()).into())
                .unwrap();

            assert_eq!(
                md5_result.as_deref(),
                if config.hashes.supports_md5() {
                    Some(value.as_str())
                } else {
                    None
                }
            );

            let sha256_result = database
                .lookup_sha256(Sha256::digest(value.as_bytes()).into())
                .unwrap();

            assert_eq!(
                sha256_result.as_deref(),
                if config.hashes.supports_sha256() {
                    Some(value.as_str())
                } else {
                    None
                }
            );
        }

        for value in excluded {
            let value = if config.case_sensitive {
                value
            } else {
                &value.to_ascii_lowercase()
            };

            let md5_result = database
                .lookup_md5(Md5::digest(value.as_bytes()).into())
                .unwrap();

            assert_eq!(md5_result, None);

            let sha256_result = database
                .lookup_sha256(Sha256::digest(value.as_bytes()).into())
                .unwrap();

            assert_eq!(sha256_result, None);
        }

        true
    }
}
