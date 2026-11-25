#[cfg(not(target_arch = "wasm32"))]
mod cli {
    use std::error::Error;
    use std::fs::{self, File, OpenOptions};
    use std::io;
    use std::path::{Path, PathBuf};
    use std::process::{Command as Process, Stdio};

    use bitcoin::{
        Address, Txid,
        hashes::{Hash, sha256},
    };
    use chronos_vault::mempool::MempoolClient;
    use chronos_vault::parse_master_key;
    use chronos_vault::{
        NETWORK, PartyResponse, SendAmount, SignRequest, SignerIdentity, SigningPackage,
        VaultError, combine, sign_share,
    };
    use clap::{Parser, Subcommand};
    use serde::{Serialize, de::DeserializeOwned};
    use zeroize::Zeroizing;

    #[derive(Parser)]
    #[command(about = "Chronos Vault threshold Bitcoin Testnet4 wallet")]
    struct Cli {
        #[command(subcommand)]
        command: Command,
    }

    #[derive(Subcommand)]
    enum Command {
        /// Show the deposit address of the threshold master public key (SEC1 compressed hex).
        Address { public_key: String },
        /// Export the local public identity for the selected signing pair.
        Identity {
            public_key: String,
            party_id: u64,
            peer_id: u64,
        },
        /// Show available UTXOs and the recommended fee rate.
        Utxos { address: String },
        /// Fetch UTXOs and write the public unsigned signing package to stdout.
        Prepare {
            #[arg(long)]
            public_key: String,
            #[arg(long)]
            party_a: u64,
            #[arg(long)]
            party_b: u64,
            #[arg(long)]
            recipient: String,
            #[arg(long, conflicts_with = "sweep", required_unless_present = "sweep")]
            amount_sat: Option<u64>,
            #[arg(long)]
            sweep: bool,
            #[arg(long)]
            fee_rate_sat_vb: Option<u64>,
        },
        /// Validate the payment, amounts, fee and list of input sighashes.
        Review { package: PathBuf },
        /// Read the package on stdin. Use this party's own identity and one-use presign records.
        SignShare {
            wallet_dir: PathBuf,
            records_file: PathBuf,
            /// Use the peer identity saved by threshold-runner keygen.
            #[arg(long)]
            peer_id: Option<u64>,
        },
        /// Verify both replies and output the signed transaction, without sending.
        Combine {
            package: PathBuf,
            reply_a: PathBuf,
            reply_b: PathBuf,
        },
        /// Verify both replies and broadcast to Testnet4.
        Broadcast {
            package: PathBuf,
            reply_a: PathBuf,
            reply_b: PathBuf,
        },
        /// Pass the package to two signer executables over stdin, verify their replies and broadcast.
        Send {
            package: PathBuf,
            signer_a: PathBuf,
            signer_b: PathBuf,
            /// Return the verified signed transaction without broadcasting it.
            #[arg(long)]
            dry_run: bool,
        },
        /// Show mempool confirmation status.
        Status { txid: Txid },
    }

    fn read<T: DeserializeOwned>(path: &Path) -> Result<T, Box<dyn Error>> {
        Ok(serde_json::from_reader(File::open(path)?)?)
    }

    fn print_json(value: &impl Serialize) -> Result<(), Box<dyn Error>> {
        serde_json::to_writer_pretty(io::stdout().lock(), value)?;
        println!();
        Ok(())
    }

    pub(super) use chronos_vault::nonce::reserve;

    fn ask_signer(
        program: &Path,
        package: &SigningPackage,
    ) -> Result<PartyResponse, Box<dyn Error>> {
        let mut child = Process::new(program)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()?;
        let mut input = child.stdin.take().ok_or("signer stdin unavailable")?;
        let written = serde_json::to_writer(&mut input, package);
        drop(input);
        let output = child.wait_with_output()?;
        written?;
        if !output.status.success() {
            return Err(format!("signer {} failed ({})", program.display(), output.status).into());
        }
        Ok(serde_json::from_slice(&output.stdout)?)
    }

    fn cached_reply(
        dir: &Path,
        id: u64,
        program: &Path,
        package: &SigningPackage,
    ) -> Result<PartyResponse, Box<dyn Error>> {
        let path = dir.join(format!("party-{id}.json"));
        match File::open(&path) {
            Ok(file) => return Ok(serde_json::from_reader(file)?),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        let reply = ask_signer(program, package)?;
        if reply.party_id != id {
            return Err(VaultError::WrongParty.into());
        }
        let mut temp = tempfile::NamedTempFile::new_in(dir)?;
        serde_json::to_writer(&mut temp, &reply)?;
        temp.as_file().sync_all()?;
        temp.persist(&path)?;
        #[cfg(unix)]
        File::open(dir)?.sync_all()?;
        Ok(reply)
    }

    pub fn run() -> Result<(), Box<dyn Error>> {
        match Cli::parse().command {
            Command::Address { public_key } => {
                println!(
                    "{}",
                    Address::p2wpkh(&parse_master_key(&public_key)?, NETWORK)
                );
            }
            Command::Identity {
                public_key,
                party_id,
                peer_id,
            } => {
                if party_id == peer_id {
                    return Err(VaultError::WrongParty.into());
                }
                print_json(&SignerIdentity {
                    party_id,
                    peer_id,
                    public_key: parse_master_key(&public_key)?,
                })?;
            }
            Command::Utxos { address } => {
                let client = MempoolClient::new()?;
                print_json(
                    &serde_json::json!({"utxos": client.utxos(&address)?, "recommended_fees": client.recommended_fees()?}),
                )?;
            }
            Command::Prepare {
                public_key,
                party_a,
                party_b,
                recipient,
                amount_sat,
                sweep: _,
                fee_rate_sat_vb,
            } => {
                let public_key = parse_master_key(&public_key)?;
                let sender_address = Address::p2wpkh(&public_key, NETWORK).to_string();
                let client = MempoolClient::new()?;
                let utxos = client.utxos(&sender_address)?;
                let rate = match fee_rate_sat_vb {
                    Some(rate) => rate,
                    None => client.recommended_fees()?.half_hour_sat_vb()?,
                };
                let amount =
                    amount_sat.map_or(SendAmount::Sweep, |sats| SendAmount::Exact { sats });
                let mut request = SignRequest {
                    funding_transactions: Default::default(),
                    sender_address,
                    recipient_address: recipient,
                    amount,
                    fee_rate_sat_vb: rate,
                    utxos,
                };
                client.fetch_funding(&public_key, &mut request)?;
                print_json(&SigningPackage::new(
                    public_key,
                    [party_a, party_b],
                    request,
                )?)?;
            }
            Command::Review { package } => {
                print_json(&read::<SigningPackage>(&package)?.review()?)?
            }
            Command::SignShare {
                wallet_dir,
                records_file,
                peer_id,
            } => {
                let identity_name = peer_id.map_or_else(
                    || "identity.json".to_owned(),
                    |id| format!("peer-{id}.json"),
                );
                let identity: SignerIdentity = read(&wallet_dir.join(identity_name))?;
                let package: SigningPackage = serde_json::from_reader(io::stdin().lock())?;
                package.review()?;
                identity.check_quorum(&package)?;
                let claimed =
                    tempfile::tempdir_in(records_file.parent().unwrap_or_else(|| Path::new(".")))?;
                let batch = claimed.path().join("records.json");
                fs::rename(records_file, &batch)?;
                let input = Zeroizing::new(fs::read(&batch)?);
                let records = serde_json::from_slice(&input)?;
                let reply = sign_share(&identity, &package, records, |ids| {
                    reserve(&wallet_dir, ids).map_err(|_| VaultError::NonceStorage)
                })?;
                claimed.close()?;
                print_json(&reply)?;
            }
            Command::Combine {
                package,
                reply_a,
                reply_b,
            } => {
                print_json(&combine(
                    &read(&package)?,
                    &read(&reply_a)?,
                    &read(&reply_b)?,
                )?)?;
            }
            Command::Broadcast {
                package,
                reply_a,
                reply_b,
            } => {
                let signed = combine(&read(&package)?, &read(&reply_a)?, &read(&reply_b)?)?;
                print_json(&MempoolClient::new()?.broadcast(&signed.raw_tx_hex)?)?;
            }
            Command::Send {
                package,
                signer_a,
                signer_b,
                dry_run,
            } => {
                let parent = package.parent().unwrap_or_else(|| Path::new("."));
                let package: SigningPackage = read(&package)?;
                let fingerprint = sha256::Hash::hash(&serde_json::to_vec(&package)?);
                let exchange = parent.join(format!("exchange-{fingerprint}"));

                package.review()?;
                fs::create_dir_all(&exchange)?;
                let lock = OpenOptions::new()
                    .create(true)
                    .truncate(false)
                    .read(true)
                    .write(true)
                    .open(exchange.join("lock"))?;
                lock.lock()?;
                let a = cached_reply(&exchange, package.signers[0], &signer_a, &package)?;
                let b = cached_reply(&exchange, package.signers[1], &signer_b, &package)?;
                let signed = combine(&package, &a, &b)?;
                if dry_run {
                    return print_json(&signed);
                }

                print_json(&MempoolClient::new()?.broadcast(&signed.raw_tx_hex)?)?;
            }
            Command::Status { txid } => {
                print_json(&MempoolClient::new()?.transaction_status(txid)?)?
            }
        }
        Ok(())
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn main() {
    if let Err(error) = cli::run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

#[cfg(target_arch = "wasm32")]
fn main() {}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    #[test]
    fn signing_processes_cannot_both_claim_the_same_nonce() {
        use std::{fs, sync::Barrier, thread};
        let base = std::env::temp_dir().join(format!("chronos-claims-{}", std::process::id()));
        fs::create_dir(&base).unwrap();
        let barrier = Barrier::new(2);
        let claims = thread::scope(|scope| {
            let try_claim = || {
                barrier.wait();
                super::cli::reserve(&base, &[[7; 32]]).is_ok()
            };
            let a = scope.spawn(try_claim);
            let b = scope.spawn(try_claim);
            [a.join().unwrap(), b.join().unwrap()]
        });
        assert_ne!(claims[0], claims[1]);
        assert!(super::cli::reserve(&base, &[[7; 32]]).is_err());
        fs::remove_dir_all(base).unwrap();
    }
}
