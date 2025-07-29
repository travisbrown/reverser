use cli_helpers::prelude::*;
use itertools::Itertools;
use std::{io::BufRead, path::PathBuf};

fn main() -> Result<(), Error> {
    let opts: Opts = Opts::parse();
    opts.verbose.init_logging()?;

    match opts.command {
        Command::Create {
            db,
            case_sensitive,
            skip_md5,
            skip_sha256,
        } => {
            let hashes = match (skip_md5, skip_sha256) {
                (true, true) => {
                    panic!("Invalid configutation");
                }
                (true, false) => reverser_db::Hashes::Sha256Only,
                (false, true) => reverser_db::Hashes::Md5Only,
                (false, false) => reverser_db::Hashes::Both,
            };

            let config = reverser_db::Config::new(hashes, case_sensitive);

            reverser_db::Database::create(db, config)?;
        }
        Command::Add { db, chunk_size } => {
            let database = reverser_db::Database::open(db)?;

            for chunk in &std::io::stdin().lock().lines().chunks(chunk_size) {
                let values = chunk
                    .map(|line| line.map(|line| line.trim().to_string()))
                    .collect::<Result<Vec<_>, _>>()?;

                database.add_all(values.iter().map(|value| value.as_str()))?;
            }
        }
        Command::Flush { db } => {
            reverser_db::Database::flush(db).unwrap();
        }
        Command::Lookup { db, hash } => {
            let database = reverser_db::Database::<false>::open(db)?;

            if let Some(value) = database.lookup(hash.parse()?)? {
                println!("{value}");
            }
        }
        Command::LookupAll { db, chunk_size } => {
            let database = reverser_db::Database::<false>::open(db)?;

            for chunk in &std::io::stdin().lock().lines().chunks(chunk_size) {
                let hashes = chunk
                    .map(|line| {
                        line.map_err(Error::from).and_then(|line| {
                            line.trim()
                                .parse::<reverser_db::hash::Hash>()
                                .map_err(Error::from)
                        })
                    })
                    .collect::<Result<Vec<_>, _>>()?;

                let results = database.lookup_all(hashes.iter().copied())?;

                if hashes.len() == results.len() {
                    for (hash, result) in hashes.into_iter().zip(results.into_iter()) {
                        println!("{},{}", hash, result.unwrap_or_default());
                    }
                } else {
                    return Err(Error::InvalidLookupResult(hashes.len(), results.len()));
                }
            }
        }
    }

    Ok(())
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("I/O error")]
    Io(#[from] std::io::Error),
    #[error("CLI argument reading error")]
    Args(#[from] cli_helpers::Error),
    #[error("Database error")]
    Database(#[from] reverser_db::Error),
    #[error("Invalid lookup result length")]
    InvalidLookupResult(usize, usize),
    #[error("Invalid hash")]
    Hash(#[from] reverser_db::hash::Error),
}

#[derive(Debug, Parser)]
#[clap(name = "reverser", version, author)]
struct Opts {
    #[clap(flatten)]
    verbose: Verbosity,
    #[clap(subcommand)]
    command: Command,
}

#[derive(Debug, Parser)]
enum Command {
    Create {
        #[clap(long)]
        db: PathBuf,
        #[clap(long)]
        case_sensitive: bool,
        #[clap(long)]
        skip_md5: bool,
        #[clap(long)]
        skip_sha256: bool,
    },
    Add {
        #[clap(long)]
        db: PathBuf,
        #[clap(long, default_value = "10000")]
        chunk_size: usize,
    },
    Flush {
        #[clap(long)]
        db: PathBuf,
    },
    Lookup {
        #[clap(long)]
        db: PathBuf,
        #[clap(long)]
        hash: String,
    },
    LookupAll {
        #[clap(long)]
        db: PathBuf,
        #[clap(long, default_value = "1000")]
        chunk_size: usize,
    },
}
