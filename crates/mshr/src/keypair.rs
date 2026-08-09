//! Per-machine Ed25519 keypair: load-or-create at a stable path so every
//! yah-family process running on the same machine sees the same `NodeId`.
//!
//! Storage layout (under `directories::ProjectDirs::from("dev","yah","yah").data_local_dir()`):
//!
//! | File | Mode | Contents |
//! |---|---|---|
//! | `identity.ed25519` | 0600 | 32-byte raw secret (binary) |
//! | `identity.pub`     | 0644 | hex-encoded `NodeId`, newline-terminated (human inspection) |
//!
//! First-run creates `identity.ed25519` atomically with `O_EXCL`; concurrent
//! processes racing to create the same file all converge on the same key
//! (whichever wins the create gets read by the others on retry).
//!
//! Rotation is a consumer-layer concern (see Q1 in xlb-net.md) — this
//! module is intentionally minimal: load existing or create fresh.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use directories::ProjectDirs;
use iroh::SecretKey;
use zeroize::Zeroizing;

use crate::{Error, NodeId, Result};

const SECRET_FILENAME: &str = "identity.ed25519";
const PUBLIC_FILENAME: &str = "identity.pub";

/// Per-machine keypair. Holds the secret in memory; the public `NodeId` is
/// derivable via [`Keypair::node_id`].
#[derive(Clone, Debug)]
pub struct Keypair {
    secret: SecretKey,
}

impl Keypair {
    /// Load the per-machine keypair from the platform data-local directory,
    /// creating it on first run.
    pub fn load_or_create() -> Result<Self> {
        let dir = identity_dir()?;
        Self::load_or_create_at(&dir)
    }

    /// Load-or-create at an explicit directory. Useful for tests and for
    /// callers that override the platform default (e.g. an admin running
    /// multiple yah instances on one host).
    pub fn load_or_create_at(dir: &Path) -> Result<Self> {
        fs::create_dir_all(dir)?;
        let secret_path = dir.join(SECRET_FILENAME);

        if let Some(secret) = read_secret(&secret_path)? {
            return Ok(Self { secret });
        }

        // First run: generate a candidate and try to claim the on-disk secret
        // via an O_EXCL create on the *final* path. If a concurrent process
        // beat us to it, `write_secret_converge` reads its key back and we
        // adopt it, so racing first-run processes converge on one key instead
        // of clobbering each other's identity.
        let secret = write_secret_converge(&secret_path, SecretKey::generate())?;
        write_public(&dir.join(PUBLIC_FILENAME), &secret)?;
        Ok(Self { secret })
    }

    /// Construct from an explicit `SecretKey` (tests, in-memory endpoints).
    pub fn from_secret(secret: SecretKey) -> Self {
        Self { secret }
    }

    /// Generate a fresh in-memory keypair (no disk I/O).
    pub fn generate() -> Self {
        Self {
            secret: SecretKey::generate(),
        }
    }

    /// Borrow the underlying iroh `SecretKey`.
    pub fn secret(&self) -> &SecretKey {
        &self.secret
    }

    /// Derive the public `NodeId` (Ed25519 pubkey).
    pub fn node_id(&self) -> NodeId {
        self.secret.public()
    }
}

/// Resolve the per-machine identity directory under the platform's
/// data-local dir (e.g. `~/Library/Application Support/yah` on macOS,
/// `~/.local/share/yah` on Linux).
pub fn identity_dir() -> Result<PathBuf> {
    let proj = ProjectDirs::from("dev", "yah", "yah").ok_or(Error::NoDataDir)?;
    Ok(proj.data_local_dir().to_path_buf())
}

fn read_secret(path: &Path) -> Result<Option<SecretKey>> {
    let bytes = match fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    let arr: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| Error::Keypair(format!("expected 32 bytes, got {}", bytes.len())))?;
    Ok(Some(SecretKey::from_bytes(&arr)))
}

/// Claim the on-disk secret at `path`, converging with concurrent creators.
///
/// The candidate's raw bytes are wiped from memory on drop (`Zeroizing`). We
/// attempt to create `path` exclusively (O_EXCL, via a fully-written temp
/// hard-linked into place); if we win, the passed `candidate` is returned. If
/// another process created it first (`AlreadyExists`), we read the winning key
/// back and adopt it so every racing first-run process ends up with the same
/// key on disk and in memory.
fn write_secret_converge(path: &Path, candidate: SecretKey) -> Result<SecretKey> {
    let bytes = Zeroizing::new(candidate.to_bytes());
    if write_new_atomic(path, &bytes[..], 0o600)? {
        Ok(candidate)
    } else {
        read_secret(path)?
            .ok_or_else(|| Error::Keypair("secret vanished during concurrent create".into()))
    }
}

fn write_public(path: &Path, secret: &SecretKey) -> Result<()> {
    let pubkey = secret.public();
    let line = format!("{}\n", hex::encode(pubkey.as_bytes()));
    // The public file is derived data (identical for a given secret), so a
    // last-writer-wins rename is fine here.
    write_atomic(path, line.as_bytes(), 0o644)?;
    Ok(())
}

/// A unique sibling temp path: `<name>.<pid>.<nonce>.<seq>.tmp`.
///
/// The pid disambiguates processes, a process-local random `nonce` defeats
/// reuse of a stale/leftover temp from a crashed peer that happened to share a
/// pid, and the per-call `seq` counter keeps concurrent writes within this
/// process distinct (so the secret and public writes never share a temp).
fn unique_tmp_path(final_path: &Path) -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::OnceLock;

    // One CSPRNG draw per process, reusing the key generator the crate already
    // depends on (rather than Date/SystemTime, which is guessable/repeatable).
    static NONCE: OnceLock<u64> = OnceLock::new();
    let nonce = *NONCE.get_or_init(|| {
        let seed = Zeroizing::new(SecretKey::generate().to_bytes());
        u64::from_le_bytes(seed[..8].try_into().expect("32 >= 8 bytes"))
    });

    static SEQ: AtomicU64 = AtomicU64::new(0);
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);

    let stem = final_path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "identity".to_string());
    let tmp_name = format!(
        "{stem}.{pid}.{nonce:016x}.{seq}.tmp",
        pid = std::process::id()
    );
    match final_path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.join(tmp_name),
        _ => PathBuf::from(tmp_name),
    }
}

/// Write `contents` to a freshly created, uniquely named temp sibling of
/// `path` with the given `mode`, `sync_all` it, and return the temp path.
///
/// The temp is opened with `create_new(true)` (O_EXCL), which defeats symlink
/// attacks and refuses to reuse a leftover temp; the mode is also set
/// explicitly after creation so a restrictive/permissive umask can't leak
/// through. Retries a handful of times if a same-named temp somehow exists.
fn write_temp(path: &Path, contents: &[u8], mode: u32) -> io::Result<PathBuf> {
    use std::io::Write;
    #[cfg(not(unix))]
    let _ = mode;

    let mut last_err: Option<io::Error> = None;
    for _ in 0..8 {
        let tmp = unique_tmp_path(path);
        let mut opts = fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(mode);
        }
        match opts.open(&tmp) {
            Ok(mut f) => {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    f.set_permissions(fs::Permissions::from_mode(mode))?;
                }
                f.write_all(contents)?;
                f.sync_all()?;
                return Ok(tmp);
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                last_err = Some(e);
                continue;
            }
            Err(e) => return Err(e),
        }
    }
    Err(last_err.unwrap_or_else(|| {
        io::Error::new(
            io::ErrorKind::AlreadyExists,
            "could not create unique temp file",
        )
    }))
}

/// Atomically replace `path` with `contents` (temp + rename + parent fsync).
fn write_atomic(path: &Path, contents: &[u8], mode: u32) -> io::Result<()> {
    let tmp = write_temp(path, contents, mode)?;
    if let Err(e) = fs::rename(&tmp, path) {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }
    sync_parent_dir(path)?;
    Ok(())
}

/// Atomically create `path` with `contents` *only if it does not yet exist*.
///
/// Returns `Ok(true)` if we created it, `Ok(false)` if another writer got
/// there first (so the caller can read the existing value back and converge).
/// Content is written to a fully-`sync_all`'d temp and then hard-linked into
/// place — `link(2)` fails with `AlreadyExists` if the target exists, giving
/// O_EXCL semantics on the final path while keeping the write torn-free.
fn write_new_atomic(path: &Path, contents: &[u8], mode: u32) -> io::Result<bool> {
    let tmp = write_temp(path, contents, mode)?;
    let created = match fs::hard_link(&tmp, path) {
        Ok(()) => true,
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => false,
        Err(e) => {
            let _ = fs::remove_file(&tmp);
            return Err(e);
        }
    };
    let _ = fs::remove_file(&tmp);
    if created {
        sync_parent_dir(path)?;
    }
    Ok(created)
}

/// fsync the directory containing `path` so the rename/link is durable. This
/// is only meaningful on unix; skipped elsewhere (a directory can't be opened
/// as a file handle on Windows without special flags).
fn sync_parent_dir(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        let parent = path.parent().unwrap_or_else(|| Path::new(""));
        let parent = if parent.as_os_str().is_empty() {
            Path::new(".")
        } else {
            parent
        };
        fs::File::open(parent)?.sync_all()?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn load_or_create_round_trips() {
        let dir = tempdir().unwrap();
        let kp1 = Keypair::load_or_create_at(dir.path()).unwrap();
        let id1 = kp1.node_id();

        // Second call returns the same identity.
        let kp2 = Keypair::load_or_create_at(dir.path()).unwrap();
        assert_eq!(kp1.node_id(), kp2.node_id());

        // Files exist.
        assert!(dir.path().join(SECRET_FILENAME).exists());
        let pub_text = fs::read_to_string(dir.path().join(PUBLIC_FILENAME)).unwrap();
        assert_eq!(pub_text.trim(), hex::encode(id1.as_bytes()));
    }

    #[cfg(unix)]
    #[test]
    fn secret_file_is_mode_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        let _ = Keypair::load_or_create_at(dir.path()).unwrap();
        let meta = fs::metadata(dir.path().join(SECRET_FILENAME)).unwrap();
        let mode = meta.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "secret file mode should be 0600, got {mode:o}");
    }

    #[test]
    fn corrupt_secret_file_errors_loudly() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join(SECRET_FILENAME), b"too short").unwrap();
        let err = Keypair::load_or_create_at(dir.path()).unwrap_err();
        assert!(matches!(err, Error::Keypair(_)), "got {err:?}");
    }

    #[cfg(unix)]
    #[test]
    fn public_file_is_mode_0644() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        let _ = Keypair::load_or_create_at(dir.path()).unwrap();
        let meta = fs::metadata(dir.path().join(PUBLIC_FILENAME)).unwrap();
        let mode = meta.permissions().mode() & 0o777;
        assert_eq!(mode, 0o644, "public file mode should be 0644, got {mode:o}");
    }

    #[test]
    fn no_temp_files_left_behind() {
        let dir = tempdir().unwrap();
        let _ = Keypair::load_or_create_at(dir.path()).unwrap();
        // Both the hard-linked secret write and the rename'd public write must
        // clean up their unique temps; only the two identity files remain.
        let leftovers: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.contains(".tmp"))
            .collect();
        assert!(leftovers.is_empty(), "leftover temp files: {leftovers:?}");
    }
}
