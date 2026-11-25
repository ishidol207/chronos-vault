use std::fs::{self, File, OpenOptions};
use std::io;
use std::path::Path;

// A durable, append-only ledger. Independent processes race on create_new.
// A crash or partial batch may burn unused nonces, but never releases them twice.
pub fn reserve(wallet: &Path, nonces: &[[u8; 32]]) -> io::Result<()> {
    let dir = wallet.join("spent-nonces");
    fs::create_dir_all(&dir)?;
    for nonce in nonces {
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(dir.join(hex::encode(nonce)))?
            .sync_all()?;
    }
    #[cfg(unix)]
    {
        File::open(&dir)?.sync_all()?;
        File::open(wallet)?.sync_all()?;
    }
    Ok(())
}
