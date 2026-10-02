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
//!
//! @yah:relay(R939, "mshr identity creation on Android (SELinux denies hard_link)")
//! @yah:at(2026-09-23T06:20:40Z)
//! @yah:status(open)
//! @yah:assignee(agent:bundle-anthropic-glimmerstone)
//! @yah:next("Reported by @Ashguard (noisetable R742-F1/T4), 2026-09-23. Child bug carries evidence + fix options.")

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
///
/// On Android, `link(2)` is SELinux-denied for `untrusted_app`
/// (`avc: denied { link }`, R939-B1) — surfaces as `PermissionDenied`. On
/// linux/android, that (or `Unsupported`, e.g. some fuse filesystems) falls
/// back to [`claim_via_renameat2_or_create_new`], which tries the
/// still-torn-free `renameat2(RENAME_NOREPLACE)` first. Other platforms are
/// unaffected: the error propagates exactly as before.
///
/// @yah:ticket(R939-B1, "write_new_atomic's fs::hard_link is SELinux-denied for untrusted_app — no Android node can create an identity")
/// @yah:status(review)
/// @yah:at(2026-09-23T06:56:17Z)
/// @yah:assignee(agent:bundle-anthropic-miravel)
/// @yah:parent(R939)
/// @yah:severity(high)
/// @yah:next("Measured on Pixel_3a API33 emulator (noisetable R742-F1/T4): Keypair::load_or_create_at -> write_new_atomic -> fs::hard_link(tmp, path) fails. logcat: `avc: denied { link } for name=\"identity.ed25519.<pid>...tmp\" scontext=u:r:untrusted_app tcontext=u:object_r:app_data_file permissive=0`; surfaces as `load the mshr identity at /data/user/0/com.noisetable.app/files/.noise_table/identity: io: Permission denied (os error 13)`. Every Android Society endpoint stays down. Same code in published 0.8.37.")
/// @yah:next("Proposed (reporter): on hard_link PermissionDenied/Unsupported, fall back to OpenOptions::create_new(true) on the final path + write + sync_all + sync_parent_dir. Still O_EXCL-converging. Weigh against renameat2(RENAME_NOREPLACE) (bionic API 30+, Linux 3.15+), which keeps the torn-free property; the create_new fallback does not.")
/// @yah:next("Tier: Cleric — small, contained fs change plus a torn-file recovery decision.")
/// @yah:verify("Unit: force the fallback path (inject hard_link failure) and assert two racing creators converge on one key.")
/// @yah:verify("E2E: noisetable Android on Pixel_3a API33 emulator (app/android/run.sh) boots a Society endpoint; logcat shows no avc denied { link }.")
/// @yah:handoff("Fixed: write_new_atomic (oss/mshr/crates/mshr/src/keypair.rs) now falls back off a denied/unsupported hard_link, on cfg(any(target_os=\"linux\",target_os=\"android\")), to a raw renameat2(AT_FDCWD, tmp, AT_FDCWD, path, RENAME_NOREPLACE) syscall via libc::syscall(libc::SYS_renameat2, ...) -- not libc::renameat2, since bionic only exports that symbol from API 30 and minSdk is 28. Only on ENOSYS/EINVAL does it drop further to OpenOptions::create_new+write+sync_all (documented non-torn-free). tmp cleanup happens on every path. Other platforms (mac/windows/ios): hard_link error propagates unchanged, same as before. Added target-scoped libc = \"0.2\" dep in crates/mshr/Cargo.toml for cfg(any(target_os=\"linux\",target_os=\"android\")) (mac already had it for the LAN backend).")
/// @yah:handoff("Test seam: hard_link is now an injected closure param on the new internal claim_new() (write_new_atomic delegates to it with fs::hard_link) so tests force the SELinux-denial path without a real SELinux policy.")
/// @yah:handoff("Unit tests added: hard_link_denied_falls_back_and_still_claims_the_file, racing_creators_converge_through_the_fallback (two racers with different content converge on the first writer's bytes), renameat2_moves_tmp_into_place_when_absent, renameat2_refuses_to_replace_an_existing_target -- all cfg(any(target_os=\"linux\",target_os=\"android\")).")
/// @yah:handoff("Test results: baseline cargo test -p mshr --lib (macOS, before edit): 55 passed/0 failed/5 ignored. After edit, macOS: 55 passed/0 failed/5 ignored (new tests compile out off linux/android). Linux (docker rust:1.97.0-bookworm, real target_os=linux): cargo test -p mshr --lib keypair -> 10 passed/0 failed (all 4 new tests included); full cargo test -p mshr --lib -> 58 passed/0 failed/1 ignored (the mDNSResponder-only tests don't exist on the mdns-sd backend, so the total differs from mac by design, not a regression).")
/// @yah:handoff("E2E on Pixel_3a API33 emulator (Android app, live mshr devcrate burst so noisetable built against this exact working copy): app/android/run.sh built release arm64, installed, launched. Full-session logcat grepped for avc denied{link}/Permission denied/identity/endpoint/BLE: ZERO avc denied{link} matches, ZERO Permission denied matches. `society: endpoint bound, addr=...` logged. `adb shell run-as com.noisetable.app ls -la .../files/.noise_table/identity/` confirms identity.ed25519 (32B, mode 600) and identity.pub (65B, mode 644) on device.")
/// @yah:handoff("BLE bonus check: `BLE pairing: not advertising: ... AdvertiseCallback did not fire within 5s` -- matches the ticket's own caveat that the emulator may lack a BLE radio; unrelated to the identity/renameat2 fix.")
/// @yah:handoff("Note: my first board_review call failed with 'ticket not found' because my earlier Edit had replaced write_new_atomic's whole doc comment (including the @yah:ticket(...) annotation block) with new prose, deleting the board's source-of-truth annotation. Restored the original @yah:ticket/@yah:next/@yah:verify block verbatim above the new prose doc comment before re-claiming and reviewing.")
/// @yah:verify("cargo test -p mshr --lib keypair (macOS): 4 pre-existing keypair tests pass, 4 new R939-B1 tests compile out (not linux/android)")
/// @yah:verify("cargo test -p mshr --lib keypair inside docker rust:1.97.0-bookworm (real target_os=linux): 10 passed, 0 failed")
/// @yah:verify("cargo test -p mshr --lib full suite: macOS 55/0/5-ignored, linux 58/0/1-ignored -- no regressions vs pre-fix baseline")
/// @yah:verify("Android E2E: app/android/run.sh on Pixel_3a API33 AVD -- logcat shows no avc denied{link}, no Permission denied, endpoint bound; adb shell run-as ls confirms identity.ed25519 + identity.pub on disk with correct modes")
fn write_new_atomic(path: &Path, contents: &[u8], mode: u32) -> io::Result<bool> {
    claim_new(path, contents, mode, |a, b| fs::hard_link(a, b))
}

/// Same as [`write_new_atomic`], parameterized over the `hard_link`
/// implementation so tests can force the SELinux-denial fallback path
/// without an actual SELinux policy (R939-B1).
fn claim_new(
    path: &Path,
    contents: &[u8],
    mode: u32,
    hard_link: impl for<'a, 'b> Fn(&'a Path, &'b Path) -> io::Result<()>,
) -> io::Result<bool> {
    let tmp = write_temp(path, contents, mode)?;
    let outcome = match hard_link(&tmp, path) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Ok(false),
        #[cfg(any(target_os = "linux", target_os = "android"))]
        Err(e) if matches!(e.kind(), io::ErrorKind::PermissionDenied | io::ErrorKind::Unsupported) => {
            claim_via_renameat2_or_create_new(&tmp, path, contents, mode)
        }
        Err(e) => Err(e),
    };
    // The renameat2 success path already moved `tmp` to `path`; this is a
    // harmless no-op then. Every other path (hard_link, its AlreadyExists
    // twin, and the create_new rung) leaves `tmp` behind for us to remove.
    let _ = fs::remove_file(&tmp);
    let created = outcome?;
    if created {
        sync_parent_dir(path)?;
    }
    Ok(created)
}

/// R939-B1 fallback chain, tried in order once `hard_link` is denied:
///
/// 1. `renameat2(2)` with `RENAME_NOREPLACE` — an atomic move, so `path` is
///    only ever seen as absent or as the fully-written `tmp` (torn-free).
///    Called via the raw syscall (`libc::syscall(SYS_renameat2, ...)`), not
///    `libc::renameat2`: this app's minSdk is 28 but bionic only exports the
///    `renameat2` *symbol* from API 30, so calling the wrapper would abort
///    with an unresolved dynamic symbol on API 28/29 devices. The syscall
///    number itself is present on every Android/Linux kernel that matters,
///    and the raw syscall needs no `dlopen`, so this stays musl-safe too.
/// 2. Only if the kernel itself lacks `renameat2` (`ENOSYS`/`EINVAL`, e.g.
///    some fuse/network filesystems): `OpenOptions::create_new` directly on
///    `path` + write + `sync_all`. This rung is NOT torn-free — a crash
///    between `create_new` and `sync_all` can leave a truncated file at
///    `path` for a reader that opens it before this process finishes.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn claim_via_renameat2_or_create_new(
    tmp: &Path,
    path: &Path,
    contents: &[u8],
    mode: u32,
) -> io::Result<bool> {
    match renameat2_no_replace(tmp, path) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Ok(false),
        Err(e)
            if matches!(e.raw_os_error(), Some(libc::ENOSYS) | Some(libc::EINVAL)) =>
        {
            claim_via_create_new(path, contents, mode)
        }
        Err(e) => Err(e),
    }
}

/// Raw `renameat2(AT_FDCWD, tmp, AT_FDCWD, path, RENAME_NOREPLACE)` — see
/// [`claim_via_renameat2_or_create_new`] for why this goes through
/// `libc::syscall` instead of `libc::renameat2`.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn renameat2_no_replace(tmp: &Path, path: &Path) -> io::Result<()> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let tmp_c = CString::new(tmp.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "tmp path has interior NUL"))?;
    let path_c = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path has interior NUL"))?;

    // SAFETY: `tmp_c`/`path_c` are valid NUL-terminated C strings kept alive
    // for the duration of the call. AT_FDCWD resolves a relative path the
    // same way plain rename(2) would; both `tmp` and `path` are always
    // siblings under the caller-supplied identity dir.
    let ret = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            libc::AT_FDCWD,
            tmp_c.as_ptr(),
            libc::AT_FDCWD,
            path_c.as_ptr(),
            libc::RENAME_NOREPLACE as libc::c_uint,
        )
    };
    if ret == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Last-resort claim for when the filesystem lacks `renameat2` entirely
/// (`ENOSYS`/`EINVAL`). Not torn-free — see
/// [`claim_via_renameat2_or_create_new`].
#[cfg(any(target_os = "linux", target_os = "android"))]
fn claim_via_create_new(path: &Path, contents: &[u8], mode: u32) -> io::Result<bool> {
    use std::io::Write;

    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(mode);
    }
    match opts.open(path) {
        Ok(mut f) => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                f.set_permissions(fs::Permissions::from_mode(mode))?;
            }
            f.write_all(contents)?;
            f.sync_all()?;
            Ok(true)
        }
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Ok(false),
        Err(e) => Err(e),
    }
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

    // R939-B1: hard_link is SELinux-denied for untrusted_app on Android.
    // These force that failure via `claim_new`'s injectable `hard_link`
    // param rather than depending on an actual SELinux policy.

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn hard_link_denied_falls_back_and_still_claims_the_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join(SECRET_FILENAME);
        let deny = |_: &Path, _: &Path| Err(io::Error::from(io::ErrorKind::PermissionDenied));

        let created = claim_new(&path, b"deadbeefdeadbeefdeadbeefdeadbeef", 0o600, deny).unwrap();

        assert!(created, "the renameat2 fallback should have claimed the file");
        assert_eq!(
            fs::read(&path).unwrap(),
            b"deadbeefdeadbeefdeadbeefdeadbeef"
        );
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn racing_creators_converge_through_the_fallback() {
        let dir = tempdir().unwrap();
        let path = dir.path().join(SECRET_FILENAME);
        let deny = |_: &Path, _: &Path| Err(io::Error::from(io::ErrorKind::PermissionDenied));

        let first = claim_new(&path, b"winner-bytes-thirty-two-long-xx", 0o600, deny).unwrap();
        let second = claim_new(&path, b"loser--bytes-thirty-two-long-xx", 0o600, deny).unwrap();

        assert!(first, "first creator should win the claim");
        assert!(!second, "second creator should see AlreadyExists and defer");
        assert_eq!(fs::read(&path).unwrap(), b"winner-bytes-thirty-two-long-xx");
    }

    // Directly exercises the renameat2 syscall wrapper (not reachable from a
    // Mac dev box — see R939-B1's verify note; run in a linux container).

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn renameat2_moves_tmp_into_place_when_absent() {
        let dir = tempdir().unwrap();
        let tmp = dir.path().join("src.tmp");
        let dst = dir.path().join("dst");
        fs::write(&tmp, b"hello").unwrap();

        renameat2_no_replace(&tmp, &dst).unwrap();

        assert!(!tmp.exists());
        assert_eq!(fs::read(&dst).unwrap(), b"hello");
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn renameat2_refuses_to_replace_an_existing_target() {
        let dir = tempdir().unwrap();
        let tmp = dir.path().join("src.tmp");
        let dst = dir.path().join("dst");
        fs::write(&tmp, b"new").unwrap();
        fs::write(&dst, b"winner").unwrap();

        let err = renameat2_no_replace(&tmp, &dst).unwrap_err();

        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(fs::read(&tmp).unwrap(), b"new");
        assert_eq!(fs::read(&dst).unwrap(), b"winner");
    }
}
