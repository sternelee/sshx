//! Local state that outlives a single client run.
//!
//! The server names each session with a random string it generates itself, so a
//! restarted client gets a new name and cannot ask for the old one. Anything
//! that has to survive a restart therefore needs a key of our own, kept here.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

/// File holding this machine's workspace identifier.
const WORKSPACE_FILE: &str = "herdr-workspace";

/// Length of a generated workspace identifier.
const WORKSPACE_ID_LEN: usize = 12;

/// Returns the directory holding sshx's local state.
///
/// `SSHX_STATE_DIR` overrides it outright; otherwise the platform's state
/// directory is used.
pub fn state_dir() -> Result<PathBuf> {
    if let Ok(dir) = std::env::var("SSHX_STATE_DIR") {
        if !dir.is_empty() {
            return Ok(PathBuf::from(dir));
        }
    }

    if let Ok(state) = std::env::var("XDG_STATE_HOME") {
        if !state.is_empty() {
            return Ok(Path::new(&state).join("sshx"));
        }
    }

    #[cfg(unix)]
    if let Ok(home) = std::env::var("HOME") {
        if !home.is_empty() {
            return Ok(Path::new(&home).join(".local/state/sshx"));
        }
    }

    #[cfg(windows)]
    if let Ok(local) = std::env::var("LOCALAPPDATA") {
        if !local.is_empty() {
            return Ok(Path::new(&local).join("sshx"));
        }
    }

    anyhow::bail!("cannot locate a state directory; set SSHX_STATE_DIR")
}

/// Returns this machine's workspace identifier, creating it on first use.
///
/// The identifier is stable across runs, which is what lets a restarted client
/// find the herdr terminals its predecessor left running.
pub fn workspace_id() -> Result<String> {
    let path = state_dir()?.join(WORKSPACE_FILE);
    if let Some(id) = read_workspace_id(&path) {
        return Ok(id);
    }

    let id = generate_workspace_id();
    write_workspace_id(&path, &id)
        .with_context(|| format!("persisting workspace id to {}", path.display()))?;
    Ok(id)
}

/// Read a workspace identifier from `path`, if it holds a usable one.
fn read_workspace_id(path: &Path) -> Option<String> {
    let contents = fs::read_to_string(path).ok()?;
    let id = contents.trim();
    is_valid_id(id).then(|| id.to_string())
}

/// Write a workspace identifier, creating the state directory if needed.
fn write_workspace_id(path: &Path, id: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        create_private_dir(parent)?;
    }

    // Write beside the target with a unique temporary name and rename, so
    // concurrent startups cannot overwrite each other's temporary file.
    let suffix = generate_workspace_id();
    let temp = path.with_extension(format!("tmp.{suffix}"));
    fs::write(&temp, format!("{id}\n")).with_context(|| format!("writing {}", temp.display()))?;
    fs::rename(&temp, path).with_context(|| format!("renaming into {}", path.display()))?;
    Ok(())
}

/// Create a directory readable only by this account.
fn create_private_dir(path: &Path) -> Result<()> {
    if path.is_dir() {
        return Ok(());
    }
    fs::create_dir_all(path).with_context(|| format!("creating {}", path.display()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .with_context(|| format!("restricting {}", path.display()))?;
    }
    Ok(())
}

/// Whether `id` is a usable workspace identifier.
///
/// Only lowercase letters and digits, so it is safe as a herdr label value and
/// as part of a terminal name.
fn is_valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
}

/// Generate a fresh workspace identifier.
///
/// Built from a lowercase alphabet directly rather than lowercasing a mixed-case
/// string, which would shrink the effective alphabet and bias the result.
fn generate_workspace_id() -> String {
    use rand::Rng;

    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let mut rng = rand::thread_rng();
    (0..WORKSPACE_ID_LEN)
        .map(|_| ALPHABET[rng.gen_range(0..ALPHABET.len())] as char)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_ids_are_valid() {
        for _ in 0..16 {
            let id = generate_workspace_id();
            assert_eq!(id.len(), WORKSPACE_ID_LEN);
            assert!(is_valid_id(&id), "generated id {id:?} is not valid");
        }
    }

    #[test]
    fn rejects_ids_that_are_not_plain_lowercase_alphanumeric() {
        assert!(is_valid_id("abc123"));
        assert!(!is_valid_id(""));
        assert!(!is_valid_id("ABC123"));
        assert!(!is_valid_id("abc-123"));
        assert!(!is_valid_id("abc 123"));
        assert!(!is_valid_id(&"a".repeat(65)));
    }

    #[test]
    fn roundtrips_through_the_state_file() {
        let dir = std::env::temp_dir().join(format!("sshx-state-{}", generate_workspace_id()));
        let path = dir.join(WORKSPACE_FILE);

        assert_eq!(read_workspace_id(&path), None, "missing file reads as none");

        write_workspace_id(&path, "abc123").unwrap();
        assert_eq!(read_workspace_id(&path).as_deref(), Some("abc123"));

        // A second read returns the same value, which is what makes it stable.
        assert_eq!(read_workspace_id(&path).as_deref(), Some("abc123"));

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn ignores_a_corrupt_state_file() {
        let dir = std::env::temp_dir().join(format!("sshx-state-{}", generate_workspace_id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join(WORKSPACE_FILE);

        fs::write(&path, "NOT VALID !!!").unwrap();
        assert_eq!(read_workspace_id(&path), None);

        fs::remove_dir_all(&dir).ok();
    }
}
