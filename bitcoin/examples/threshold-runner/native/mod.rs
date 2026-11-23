mod protocol;

use bitcoin::CompressedPublicKey;
use chronos_vault::{SigningPackage, parse_master_key};
use clap::{Parser, Subcommand};
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::{self, ErrorKind, Write};
use std::path::{Path, PathBuf};
use tempfile::NamedTempFile;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
const PARTIES: [u64; 3] = [1, 2, 3];

#[derive(Parser)]
#[command(about = "Run local threshold ECDSA parties for a Bitcoin Testnet4 demo")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create a new 2-of-3 wallet and print its compressed public key.
    Keygen { wallet: PathBuf },
    /// Create one pair of presign records per reviewed input and print the batch directory.
    Presign { wallet: PathBuf, payment: PathBuf },
    #[command(hide = true)]
    Worker { party_dir: PathBuf, id: u64 },
}

#[derive(Serialize, Deserialize)]
struct Job {
    parties: Vec<u64>,
    operation: Operation,
}

#[derive(Serialize, Deserialize)]
enum Operation {
    Keygen {
        aux_sid: u64,
        share_sid: u64,
    },
    Presign {
        sessions: Vec<u64>,
        public_key: CompressedPublicKey,
        output: PathBuf,
    },
}

pub(super) fn run() -> Result<()> {
    match Cli::parse().command {
        Command::Keygen { wallet } => println!("{}", keygen(&wallet)?),
        Command::Presign { wallet, payment } => {
            println!("{}", presign(&wallet, &payment)?.display());
        }
        Command::Worker { party_dir, id } => protocol::worker(&party_dir, id)?,
    }
    Ok(())
}

fn private_dir(path: &Path) -> io::Result<()> {
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path)
}

// The final name becomes visible only after the entire file has been written.
fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = NamedTempFile::new_in(path.parent().ok_or("missing parent directory")?)?;
    file.write_all(bytes)?;
    file.as_file().sync_all()?;
    file.persist_noclobber(path)?;
    Ok(())
}

fn party_dir(wallet: &Path, id: u64) -> PathBuf {
    wallet.join(format!("party-{id}"))
}

// Reserve every session ID, including sessions of abandoned batches.
fn new_session(wallet: &Path) -> Result<u64> {
    loop {
        let sid = OsRng.next_u64();
        match File::create_new(wallet.join("sessions").join(sid.to_string())) {
            Ok(_) => return Ok(sid),
            Err(err) if err.kind() == ErrorKind::AlreadyExists => continue,
            Err(err) => return Err(err.into()),
        }
    }
}

fn keygen(wallet: &Path) -> Result<CompressedPublicKey> {
    private_dir(wallet)
        .map_err(|e| format!("cannot create new wallet {}: {e}", wallet.display()))?;
    write_new(&wallet.join(".gitignore"), b"*\n")?;
    private_dir(&wallet.join("sessions"))?;
    private_dir(&wallet.join("batches"))?;
    for id in PARTIES {
        private_dir(&party_dir(wallet, id))?;
    }

    let job = Job {
        parties: PARTIES.to_vec(),
        operation: Operation::Keygen {
            aux_sid: new_session(wallet)?,
            share_sid: new_session(wallet)?,
        },
    };
    protocol::relay(wallet, &job)?;
    let public_key = |id| -> Result<_> {
        Ok(parse_master_key(&fs::read_to_string(
            party_dir(wallet, id).join("public-key.json"),
        )?)?)
    };
    let key = public_key(PARTIES[0])?;
    for id in &PARTIES[1..] {
        if public_key(*id)? != key {
            return Err("participants derived different public keys".into());
        }
    }
    // A wallet is ready for funding only once all three workers succeeded.
    write_new(&wallet.join("public-key.json"), &serde_json::to_vec(&key)?)?;
    Ok(key)
}

fn presign(wallet: &Path, payment: &Path) -> Result<PathBuf> {
    let package: SigningPackage = serde_json::from_reader(File::open(payment)?)?;
    let review = package.review()?;
    let wallet_key = parse_master_key(&fs::read_to_string(wallet.join("public-key.json"))?)?;
    if package.public_key != wallet_key || !package.signers.iter().all(|id| PARTIES.contains(id)) {
        return Err("payment public key or signer IDs do not match this wallet".into());
    }

    let sessions: Vec<_> = review
        .input_sighashes
        .iter()
        .map(|_| new_session(wallet))
        .collect::<Result<_>>()?;
    let batch_id = sessions.first().ok_or("payment has no inputs")?;
    let batches = wallet.join("batches");
    let destination = batches.join(batch_id.to_string());
    let staging = tempfile::tempdir_in(&batches)?;
    let job = Job {
        parties: package.signers.to_vec(),
        operation: Operation::Presign {
            sessions,
            public_key: wallet_key,
            output: staging.path().to_owned(),
        },
    };
    protocol::relay(wallet, &job)?;
    // Publish both participant files together; a retry always reserves fresh sessions.
    fs::rename(staging.path(), &destination)?;
    Ok(destination)
}
