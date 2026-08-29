//! Global-override fallback: directly read/write `/etc/resolv.conf` when no
//! smarter DNS manager (systemd-resolved, NetworkManager, resolvconf) is
//! usable.
//!
//! This is the last resort in the Linux backend chain, and the only one
//! that cannot do conditional forwarding - a plain `resolv.conf` has no
//! concept of "route this domain elsewhere, leave everything else as-is",
//! only a flat, global nameserver list. [`set`](StaticResolvConf::set)
//! therefore refuses a non-empty `routing_domains` outright rather than
//! silently applying a global override for what was asked as a scoped one.
//!
//! ## Crash safety
//!
//! The original file content is backed up to `<path>.dns-host-config.bak`
//! before being overwritten, and every write this backend makes starts
//! with a marker comment carrying `owner`. `reset()` - and a fresh `set()`
//! that finds a marker/backup pair already left over from an earlier,
//! uncleanly-terminated run with the same `owner` - only ever restores
//! from the backup if the current file still carries that marker, so a
//! legitimate later change by something else is never silently clobbered.
//! [`new`](StaticResolvConf::new) itself detects that leftover state (a
//! matching marker plus an existing backup file) so that even a `reset()`
//! called with no prior `set()` in *this* process instance still cleans up
//! after a previous one that crashed.
//!
//! ## Known limitation
//!
//! Unlike the file-based backend in `talpid-dns` this is modeled on, there
//! is currently no background watch-and-reassert loop: if something else
//! rewrites the file after `set()`, this backend does not notice or fight
//! back. The D-Bus-scoped backends (systemd-resolved, NetworkManager)
//! don't need this, since their state lives in the DNS manager itself, not
//! in a file anything else can freely rewrite.

use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use crate::{DnsRoute, DnsRouteConfig};

const MARKER_PREFIX: &str = "# managed-by=dns-host-config;owner=";

#[derive(Debug)]
pub enum Error {
    /// `routing_domains` was non-empty - see the module docs for why a
    /// flat `resolv.conf` can't honor that.
    RoutingDomainsUnsupported,
    Io(io::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::RoutingDomainsUnsupported => write!(
                f,
                "a plain /etc/resolv.conf cannot do conditional forwarding; \
                 routing_domains must be empty for this backend"
            ),
            Error::Io(e) => write!(f, "static resolv.conf backend: {e}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::Io(e)
    }
}

pub struct StaticResolvConf {
    owner: String,
    path: PathBuf,
    backup_path: PathBuf,
    /// Whether *this* instance (or, per [`new`](Self::new), a previous one
    /// that never cleanly reset) currently has an override in place.
    active: bool,
}

impl StaticResolvConf {
    /// `owner` tags every write so a later `reset()` (even from a
    /// different process instance, after a crash) can tell "did *we* last
    /// write this file" apart from "something else changed it since".
    /// Pick something stable and specific to your application, e.g. its
    /// name.
    pub fn new(owner: impl Into<String>) -> Self {
        Self::with_path(owner, "/etc/resolv.conf")
    }

    fn with_path(owner: impl Into<String>, path: impl Into<PathBuf>) -> Self {
        let owner = owner.into();
        let path = path.into();
        let backup_path = backup_path_for(&path);
        let active = current_owner(&path) == Some(owner.clone()) && backup_path.exists();
        Self {
            owner,
            path,
            backup_path,
            active,
        }
    }
}

#[async_trait::async_trait]
impl DnsRoute for StaticResolvConf {
    type Error = Error;

    async fn set(&mut self, _interface: &str, config: &DnsRouteConfig) -> Result<(), Error> {
        if !config.routing_domains.is_empty() {
            return Err(Error::RoutingDomainsUnsupported);
        }

        let reusing_backup =
            current_owner(&self.path) == Some(self.owner.clone()) && self.backup_path.exists();
        if !reusing_backup {
            // First takeover: preserve whatever was there before (or the
            // absence of a file at all) so reset() can restore it exactly.
            match fs::read(&self.path) {
                Ok(existing) => fs::write(&self.backup_path, existing)?,
                Err(e) if e.kind() == io::ErrorKind::NotFound => {
                    fs::write(&self.backup_path, b"")?;
                }
                Err(e) => return Err(e.into()),
            }
        }

        fs::write(&self.path, render(&self.owner, config))?;
        self.active = true;
        Ok(())
    }

    async fn reset(&mut self) -> Result<(), Error> {
        if !self.active {
            return Ok(());
        }
        self.active = false;

        if current_owner(&self.path) != Some(self.owner.clone()) {
            // Something else has taken over /etc/resolv.conf since we set
            // it; leave it alone and just drop our now-stale backup rather
            // than clobber a legitimate later change.
            let _ = fs::remove_file(&self.backup_path);
            return Ok(());
        }

        if self.backup_path.exists() {
            let backup = fs::read(&self.backup_path)?;
            if backup.is_empty() {
                // We recorded "no file existed before us".
                if let Err(e) = fs::remove_file(&self.path) {
                    if e.kind() != io::ErrorKind::NotFound {
                        return Err(e.into());
                    }
                }
            } else {
                fs::write(&self.path, backup)?;
            }
            fs::remove_file(&self.backup_path)?;
        }
        Ok(())
    }
}

fn backup_path_for(path: &Path) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(".dns-host-config.bak");
    PathBuf::from(s)
}

fn marker_line(owner: &str) -> String {
    format!("{MARKER_PREFIX}{owner}\n")
}

/// The `owner` recorded in `path`'s first line, if any - `None` if the
/// file doesn't exist, can't be read, or wasn't written by this backend.
fn current_owner(path: &Path) -> Option<String> {
    let content = fs::read_to_string(path).ok()?;
    let first_line = content.lines().next()?;
    first_line.strip_prefix(MARKER_PREFIX).map(str::to_owned)
}

fn render(owner: &str, config: &DnsRouteConfig) -> String {
    let mut out = marker_line(owner);
    for server in &config.servers {
        out.push_str(&format!("nameserver {server}\n"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn config(server: &str) -> DnsRouteConfig {
        DnsRouteConfig::new(vec![server.parse::<IpAddr>().unwrap()], vec![]).unwrap()
    }

    fn backend(dir: &tempfile::TempDir) -> StaticResolvConf {
        StaticResolvConf::with_path("test-owner", dir.path().join("resolv.conf"))
    }

    #[tokio::test]
    async fn set_refuses_routing_domains() {
        let dir = tempfile::tempdir().unwrap();
        let mut b = backend(&dir);
        let cfg = DnsRouteConfig::new(
            vec![IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))],
            vec!["myvpn.example".into()],
        )
        .unwrap();
        assert!(matches!(
            b.set("eth0", &cfg).await,
            Err(Error::RoutingDomainsUnsupported)
        ));
    }

    #[tokio::test]
    async fn set_writes_marker_and_nameserver_then_reset_restores_original() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("resolv.conf");
        fs::write(&path, "nameserver 9.9.9.9\n").unwrap();

        let mut b = StaticResolvConf::with_path("test-owner", &path);
        b.set("eth0", &config("1.2.3.4")).await.unwrap();

        let written = fs::read_to_string(&path).unwrap();
        assert!(written.starts_with(MARKER_PREFIX));
        assert!(written.contains("nameserver 1.2.3.4\n"));

        b.reset().await.unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "nameserver 9.9.9.9\n");
        assert!(!backup_path_for(&path).exists());
    }

    #[tokio::test]
    async fn reset_with_no_prior_file_removes_it() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("resolv.conf");
        // No file exists yet.

        let mut b = StaticResolvConf::with_path("test-owner", &path);
        b.set("eth0", &config("1.2.3.4")).await.unwrap();
        assert!(path.exists());

        b.reset().await.unwrap();
        assert!(!path.exists());
        assert!(!backup_path_for(&path).exists());
    }

    #[tokio::test]
    async fn reset_without_a_prior_set_is_a_no_op() {
        let dir = tempfile::tempdir().unwrap();
        let mut b = backend(&dir);
        b.reset().await.unwrap();
        assert!(!dir.path().join("resolv.conf").exists());
    }

    #[tokio::test]
    async fn reset_leaves_a_foreign_takeover_alone() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("resolv.conf");
        fs::write(&path, "nameserver 9.9.9.9\n").unwrap();

        let mut b = StaticResolvConf::with_path("test-owner", &path);
        b.set("eth0", &config("1.2.3.4")).await.unwrap();

        // Something else (a package manager, a human) rewrites the file
        // after we set it, without going through us.
        fs::write(&path, "nameserver 8.8.8.8\n").unwrap();

        b.reset().await.unwrap();
        // Left exactly as the foreign write made it.
        assert_eq!(fs::read_to_string(&path).unwrap(), "nameserver 8.8.8.8\n");
        // The now-stale backup doesn't linger around either.
        assert!(!backup_path_for(&path).exists());
    }

    #[tokio::test]
    async fn a_fresh_instance_recovers_state_left_by_a_crashed_one() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("resolv.conf");
        let original = "nameserver 9.9.9.9\n";

        // Simulate a first process instance that called set() and then
        // crashed before it could reset().
        {
            let mut b = StaticResolvConf::with_path("test-owner", &path);
            fs::write(&path, original).unwrap();
            b.set("eth0", &config("1.2.3.4")).await.unwrap();
        }
        assert!(backup_path_for(&path).exists());

        // A brand new instance, same owner, no set() call of its own.
        let mut recovered = StaticResolvConf::with_path("test-owner", &path);
        recovered.reset().await.unwrap();

        assert_eq!(fs::read_to_string(&path).unwrap(), original);
        assert!(!backup_path_for(&path).exists());
    }

    #[tokio::test]
    async fn a_fresh_instance_with_a_different_owner_does_not_touch_leftover_state() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("resolv.conf");

        {
            let mut b = StaticResolvConf::with_path("owner-a", &path);
            fs::write(&path, "nameserver 9.9.9.9\n").unwrap();
            b.set("eth0", &config("1.2.3.4")).await.unwrap();
        }

        let mut other = StaticResolvConf::with_path("owner-b", &path);
        other.reset().await.unwrap();

        // owner-b never set anything, so its reset() is a no-op; owner-a's
        // override and backup are both still there, untouched.
        assert!(fs::read_to_string(&path)
            .unwrap()
            .starts_with(MARKER_PREFIX));
        assert!(backup_path_for(&path).exists());
    }

    #[tokio::test]
    async fn re_setting_with_the_same_owner_does_not_clobber_the_original_backup() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("resolv.conf");
        let original = "nameserver 9.9.9.9\n";
        fs::write(&path, original).unwrap();

        let mut b = StaticResolvConf::with_path("test-owner", &path);
        b.set("eth0", &config("1.2.3.4")).await.unwrap();
        // set() again, as if reapplying a changed config - must not back
        // up its own already-applied output over the real original.
        b.set("eth0", &config("5.6.7.8")).await.unwrap();

        b.reset().await.unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), original);
    }
}
