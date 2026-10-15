//! The daemon's iroh secret key file.
//!
//! Exactly 32 bytes, the raw Ed25519 secret key, in a regular file of mode
//! `0600`. The daemon writes it atomically before the first `start`; the helper
//! only ever reads it. Every check is made on the opened file descriptor, so the
//! file that is checked is the file that is read.

use std::fs::File;
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use iroh::SecretKey;
use zeroize::Zeroize;

use crate::protocol::ErrorCode;

/// The key file's exact size.
pub const KEY_BYTES: usize = 32;

/// The key file's required mode.
pub const KEY_MODE: u32 = 0o600;

/// Why the key could not be loaded. Maps onto the contract's error codes.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum KeyError {
    /// The file could not be opened or read: `key_unreadable`.
    #[error("{0}")]
    Unreadable(String),
    /// The file is not a 32-byte, mode-0600 regular file: `key_invalid`.
    #[error("{0}")]
    Invalid(String),
}

impl KeyError {
    /// The contract's error code for this failure.
    pub fn code(&self) -> ErrorCode {
        match self {
            KeyError::Unreadable(_) => ErrorCode::KeyUnreadable,
            KeyError::Invalid(_) => ErrorCode::KeyInvalid,
        }
    }
}

/// Load the secret key at `path`. A symlink is refused, never followed: the
/// key is a regular file in the daemon's private directory.
pub fn load(path: &Path) -> Result<SecretKey, KeyError> {
    let link = std::fs::symlink_metadata(path)
        .map_err(|e| KeyError::Unreadable(format!("key file cannot be inspected: {e}")))?;
    if link.file_type().is_symlink() {
        return Err(KeyError::Invalid("key file is not a regular file".into()));
    }
    let mut file = File::open(path)
        .map_err(|e| KeyError::Unreadable(format!("key file cannot be opened: {e}")))?;
    let meta = file
        .metadata()
        .map_err(|e| KeyError::Unreadable(format!("key file cannot be inspected: {e}")))?;
    if !meta.is_file() {
        return Err(KeyError::Invalid("key file is not a regular file".into()));
    }
    let mode = meta.permissions().mode() & 0o7777;
    if mode != KEY_MODE {
        return Err(KeyError::Invalid(format!(
            "key file mode is {mode:04o}, not {KEY_MODE:04o}"
        )));
    }
    if meta.len() != KEY_BYTES as u64 {
        return Err(KeyError::Invalid(format!(
            "key file is {} bytes, not {KEY_BYTES}",
            meta.len()
        )));
    }
    let mut bytes = [0u8; KEY_BYTES];
    let read = read_exactly(&mut file, &mut bytes);
    let key = read.map(|()| SecretKey::from_bytes(&bytes));
    bytes.zeroize();
    key
}

/// Fill `bytes` and confirm the file ends right after them, so a file that
/// changed size after it was inspected is refused rather than truncated.
fn read_exactly(file: &mut File, bytes: &mut [u8; KEY_BYTES]) -> Result<(), KeyError> {
    file.read_exact(bytes)
        .map_err(|e| KeyError::Unreadable(format!("key file cannot be read: {e}")))?;
    let mut probe = [0u8; 1];
    let extra = file
        .read(&mut probe)
        .map_err(|e| KeyError::Unreadable(format!("key file cannot be read: {e}")))?;
    if extra != 0 {
        return Err(KeyError::Invalid(format!(
            "key file is longer than {KEY_BYTES} bytes"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn write_key(dir: &Path, bytes: &[u8], mode: u32) -> std::path::PathBuf {
        let path = dir.join("iroh_key");
        fs::write(&path, bytes).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
        path
    }

    fn fixture_bytes() -> [u8; 32] {
        std::array::from_fn(|i| (i + 1) as u8)
    }

    #[test]
    fn the_fixture_key_loads_and_yields_the_fixture_endpoint_id() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_key(dir.path(), &fixture_bytes(), 0o600);
        let key = load(&path).unwrap();
        assert_eq!(
            key.public().to_string(),
            "79b5562e8fe654f94078b112e8a98ba7901f853ae695bed7e0e3910bad049664"
        );
    }

    // The daemon refuses a key that is not a regular file; a symlink to one
    // is refused here too, not followed.
    #[test]
    fn a_symlink_to_a_valid_key_is_invalid() {
        let dir = tempfile::tempdir().unwrap();
        let real = write_key(dir.path(), &fixture_bytes(), 0o600);
        let link = dir.path().join("linked_key");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let err = load(&link).unwrap_err();
        assert_eq!(err.code(), ErrorCode::KeyInvalid);
        assert_eq!(err.to_string(), "key file is not a regular file");
    }

    #[test]
    fn a_missing_file_is_unreadable() {
        let dir = tempfile::tempdir().unwrap();
        let err = load(&dir.path().join("absent")).unwrap_err();
        assert_eq!(err.code(), ErrorCode::KeyUnreadable);
    }

    #[test]
    fn a_wrong_mode_is_invalid_with_the_contract_message() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_key(dir.path(), &fixture_bytes(), 0o644);
        let err = load(&path).unwrap_err();
        assert_eq!(err.code(), ErrorCode::KeyInvalid);
        assert_eq!(err.to_string(), "key file mode is 0644, not 0600");
        let path = write_key(dir.path(), &fixture_bytes(), 0o400);
        assert_eq!(load(&path).unwrap_err().code(), ErrorCode::KeyInvalid);
    }

    #[test]
    fn any_size_but_32_is_invalid() {
        let dir = tempfile::tempdir().unwrap();
        for len in [0usize, 31, 33, 64] {
            let path = write_key(dir.path(), &vec![7u8; len], 0o600);
            let err = load(&path).unwrap_err();
            assert_eq!(err.code(), ErrorCode::KeyInvalid, "len {len}");
            assert_eq!(err.to_string(), format!("key file is {len} bytes, not 32"));
        }
    }

    #[test]
    fn a_directory_is_invalid() {
        let dir = tempfile::tempdir().unwrap();
        let sub = dir.path().join("iroh_key");
        fs::create_dir(&sub).unwrap();
        fs::set_permissions(&sub, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(load(&sub).unwrap_err().code(), ErrorCode::KeyInvalid);
    }
}
