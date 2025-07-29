use hex::FromHex;
use std::fmt::Display;
use std::str::FromStr;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Invalid length")]
    InvalidLength(String),
    #[error("Invalid character")]
    InvalidCharacter(String),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Hash {
    Md5([u8; 16]),
    Sha256([u8; 32]),
}

impl Hash {
    pub fn bytes(&self) -> &[u8] {
        match self {
            Self::Md5(bytes) => bytes,
            Self::Sha256(bytes) => bytes,
        }
    }
}

impl FromStr for Hash {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.len() {
            32 => <[u8; 16]>::from_hex(s)
                .map_err(|_| Error::InvalidCharacter(s.to_string()))
                .map(Self::Md5),
            64 => <[u8; 32]>::from_hex(s)
                .map_err(|_| Error::InvalidCharacter(s.to_string()))
                .map(Self::Sha256),
            _ => Err(Error::InvalidLength(s.to_string())),
        }
    }
}

impl Display for Hash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.bytes()))
    }
}
