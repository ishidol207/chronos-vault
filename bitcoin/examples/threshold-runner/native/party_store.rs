use super::{Result, write_new};
use bitcoin::CompressedPublicKey;
use rand::{RngCore, rngs::OsRng};
use ring::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use std::env;
use std::fs::{self, DirBuilder, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

pub(super) const FORMAT_FILE: &str = "party-store.version";
pub(super) const MAGIC: &[u8; 8] = b"CVPART\0\x01";
const KEY_BYTES: usize = 32;
const NONCE_BYTES: usize = 12;
type Secrets = (Zeroizing<String>, Zeroizing<String>);

fn private_dirs(path: &Path) -> io::Result<()> {
    let mut builder = DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path)
}

// Custom directories can be separate mounted devices. Scope objects to a wallet and a party.
fn paths(dir: &Path, id: u64, public_key: &CompressedPublicKey) -> Result<(PathBuf, PathBuf)> {
    let stem = format!("{public_key}-party-{id}");
    let bundle = match env::var_os(format!("CHRONOS_PARTY_{id}_STORE_DIR")) {
        Some(root) => PathBuf::from(root).join(format!("{stem}.cvparty")),
        None => dir.join("secrets.cvparty"),
    };
    let key_dir = env::var_os(format!("CHRONOS_PARTY_{id}_KEY_DIR"))
        .map(PathBuf::from)
        .or_else(|| {
            let base = env::var_os("XDG_DATA_HOME")
                .or_else(|| env::var_os("LOCALAPPDATA"))
                .map(PathBuf::from)
                .or_else(|| env::var_os("HOME").map(|home| PathBuf::from(home).join(".local/share")))?;
            Some(base.join("chronos-vault/keys"))
        })
        .ok_or("set a private CHRONOS_PARTY_<id>_KEY_DIR for this party")?;
    Ok((bundle, key_dir.join(format!("{stem}.key"))))
}

fn cipher(raw: &[u8]) -> Result<LessSafeKey> {
    let unbound = UnboundKey::new(&AES_256_GCM, raw).map_err(|_| "invalid AES-256 key length")?;
    Ok(LessSafeKey::new(unbound))
}

fn aad(id: u64, public_key: &CompressedPublicKey) -> Vec<u8> {
    let mut data = MAGIC.to_vec();
    data.extend_from_slice(&id.to_be_bytes());
    data.extend_from_slice(&public_key.0.serialize());
    data
}

fn encrypt(
    raw: &[u8],
    id: u64,
    pk: &CompressedPublicKey,
    aux: &str,
    share: &str,
) -> Result<Vec<u8>> {
    let mut nonce = [0; NONCE_BYTES];
    OsRng.try_fill_bytes(&mut nonce)?;
    let mut body = Zeroizing::new(serde_json::to_vec(&(aux, share))?);
    cipher(raw)?
        .seal_in_place_append_tag(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(aad(id, pk)),
            &mut *body,
        )
        .map_err(|_| "could not encrypt party secrets")?;
    let mut out = MAGIC.to_vec();
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&body);
    Ok(out)
}

fn decrypt(raw: &[u8], id: u64, pk: &CompressedPublicKey, encoded: Vec<u8>) -> Result<Secrets> {
    let mut data = Zeroizing::new(encoded);
    if !data.starts_with(MAGIC) || data.len() < MAGIC.len() + NONCE_BYTES + AES_256_GCM.tag_len() {
        return Err("invalid encrypted party file".into());
    }
    let (header, body) = data.split_at_mut(MAGIC.len() + NONCE_BYTES);
    let nonce = Nonce::try_assume_unique_for_key(&header[MAGIC.len()..])
        .map_err(|_| "invalid nonce")?;
    let clear = cipher(raw)?
        .open_in_place(nonce, Aad::from(aad(id, pk)), body)
        .map_err(|_| "party file authentication failed (key, wallet, party or file mismatch)")?;
    let (aux, share): (String, String) = serde_json::from_slice(clear)?;
    Ok((Zeroizing::new(aux), Zeroizing::new(share)))
}

pub(super) fn seal(
    dir: &Path,
    id: u64,
    pk: &CompressedPublicKey,
    aux: &str,
    share: &str,
) -> Result<()> {
    let (bundle, key_file) = paths(dir, id, pk)?;
    let bundle_dir = bundle.parent().ok_or("no encrypted store directory")?;
    let key_dir = key_file.parent().ok_or("no key directory")?;
    private_dirs(bundle_dir)?;
    private_dirs(key_dir)?;
    let key_root = key_dir.canonicalize()?;
    let wallet_root = dir.parent().ok_or("no wallet directory")?.canonicalize()?;
    if key_root.starts_with(wallet_root) || key_root.starts_with(bundle_dir.canonicalize()?) {
        return Err("choose a key directory outside the wallet and encrypted store".into());
    }
    let mut key = Zeroizing::new([0u8; KEY_BYTES]);
    OsRng.try_fill_bytes(&mut key[..])?;
    let encrypted = encrypt(&key[..], id, pk, aux, share)?;
    // If interrupted, a stray wrapping key is harmless. Never replace a previous key or envelope.
    write_new(&key_file, &key[..])?;
    write_new(&bundle, &encrypted)
}

pub(super) fn open(dir: &Path, id: u64, pk: &CompressedPublicKey) -> Result<Secrets> {
    let marker = dir
        .parent()
        .ok_or("no wallet directory")?
        .join(FORMAT_FILE);
    match fs::read(marker) {
        Ok(version) if version.as_slice() == MAGIC => {}
        Ok(_) => return Err("unrecognized wallet storage version".into()),
        // Wallets created before encrypted storage have this pair of files and no marker.
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            return Ok((
                Zeroizing::new(fs::read_to_string(dir.join("aux.json"))?),
                Zeroizing::new(fs::read_to_string(dir.join("share.json"))?),
            ));
        }
        Err(err) => return Err(err.into()),
    }
    let (bundle, key_file) = paths(dir, id, pk)?;
    let mut raw = Zeroizing::new(Vec::new());
    File::open(&key_file)
        .map_err(|err| io::Error::new(err.kind(), format!("{}: {err}", key_file.display())))?
        .take((KEY_BYTES + 1) as u64)
        .read_to_end(&mut raw)?;
    decrypt(&raw, id, pk, fs::read(bundle)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn public_key(prefix: &str) -> CompressedPublicKey {
        format!("{prefix}79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
            .parse()
            .unwrap()
    }

    #[test]
    fn envelope_authenticates_wallet_party_and_secret_material() {
        let pk = public_key("02");
        let key = [7; KEY_BYTES];
        let envelope = encrypt(&key, 2, &pk, "server aux", "server share").unwrap();
        let (aux, share) = decrypt(&key, 2, &pk, envelope.clone()).unwrap();
        assert_eq!(aux.as_str(), "server aux");
        assert_eq!(share.as_str(), "server share");
        assert!(decrypt(&[8; KEY_BYTES], 2, &pk, envelope.clone()).is_err());
        assert!(decrypt(&key, 2, &public_key("03"), envelope.clone()).is_err());
        assert!(decrypt(&key, 3, &pk, envelope.clone()).is_err());
        for i in [0, MAGIC.len(), envelope.len() - 1] {
            let mut tampered = envelope.clone();
            tampered[i] ^= 1;
            assert!(decrypt(&key, 2, &pk, tampered).is_err());
        }
        assert!(decrypt(&key, 2, &pk, envelope[..10].to_vec()).is_err());
    }

    // External AES-GCM fixture: key 00..1f, nonce 00..0b, compressed generator, party 3.
    #[test]
    fn opens_v1_interoperability_vector() {
        let key: [u8; KEY_BYTES] = std::array::from_fn(|i| i as u8);
        let envelope = hex::decode(concat!(
            "4356504152540001000102030405060708090a0b",
            "1c20b76ebdc7ee39fe29f6f9d4cb25cccec17e63b61e021d808366f2e9bd80",
        )).unwrap();
        let (aux, share) = decrypt(&key, 3, &public_key("02"), envelope).unwrap();
        assert_eq!((aux.as_str(), share.as_str()), ("aux", "share"));
    }

    #[test]
    fn legacy_wallet_reads_both_files_and_new_wallet_rejects_plaintext_fallback() {
        let wallet = tempfile::tempdir().unwrap();
        let dir = wallet.path().join("party-2");
        fs::create_dir(&dir).unwrap();
        fs::write(dir.join("aux.json"), "aux").unwrap();
        fs::write(dir.join("share.json"), "share").unwrap();
        let pk = public_key("02");
        let (aux, share) = open(&dir, 2, &pk).unwrap();
        assert_eq!((aux.as_str(), share.as_str()), ("aux", "share"));
        fs::write(wallet.path().join(FORMAT_FILE), MAGIC).unwrap();
        assert!(open(&dir, 2, &pk).is_err());
    }
}
