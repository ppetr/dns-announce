//! Last-resort fallback: directly read/write `/etc/resolv.conf` when no
//! smarter DNS manager (systemd-resolved, NetworkManager, resolvconf) is
//! usable.
//!
//! A plain `resolv.conf` has no concept of "route this domain elsewhere,
//! leave everything else as-is" - only a flat, global nameserver list. For
//! a non-empty `routing_domains` (the case this project actually needs;
//! see `docs/design-dns-host-config.md`, "Conditional forwarding without
//! native OS support"), [`set`](StaticResolvConf::set) gets there anyway,
//! by writing `config.servers` first and then, immediately after them, the
//! `nameserver` lines pulled out of whatever was in the file before us.
//! For anything outside our suffix `config.servers` answers `REFUSED`
//! (`dns-stack`'s `Reply::NotMine`), and glibc's stub resolver falls
//! through to the next nameserver on `REFUSED` - verified empirically, see
//! the design doc. `routing_domains` being empty (full override - a
//! non-goal for this project, but not rejected by the type) skips
//! appending the original servers, since the point there is to replace the
//! resolver entirely.
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
    Io(io::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
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
        let reusing_backup =
            current_owner(&self.path) == Some(self.owner.clone()) && self.backup_path.exists();
        // The *real* original content, for render() to pull fallback
        // nameservers out of - not whatever we ourselves last wrote, which
        // is what self.path would hold on a re-set() without this.
        let original: Vec<u8> = if reusing_backup {
            fs::read(&self.backup_path)?
        } else {
            // First takeover: preserve whatever was there before (or the
            // absence of a file at all) so reset() can restore it exactly.
            match fs::read(&self.path) {
                Ok(existing) => {
                    fs::write(&self.backup_path, &existing)?;
                    existing
                }
                Err(e) if e.kind() == io::ErrorKind::NotFound => {
                    fs::write(&self.backup_path, b"")?;
                    Vec::new()
                }
                Err(e) => return Err(e.into()),
            }
        };

        fs::write(&self.path, render(&self.owner, config, &original))?;
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

fn render(owner: &str, config: &DnsRouteConfig, original: &[u8]) -> String {
    let mut out = marker_line(owner);
    for server in &config.servers {
        out.push_str(&format!("nameserver {server}\n"));
    }
    if !config.routing_domains.is_empty() {
        // Conditional forwarding: fall through to the pre-existing
        // resolvers for anything outside routing_domains via
        // REFUSED-fallback (see the module docs and
        // docs/design-dns-host-config.md). Omitted for full override
        // (routing_domains empty), since the point there is to replace the
        // resolver entirely, not fall back to the one being replaced.
        for addr in parse_nameservers(original) {
            out.push_str(&format!("nameserver {addr}\n"));
        }
    }
    out
}

/// The address of every `nameserver` line in a resolv.conf's contents, in
/// order, duplicates included - resolv.conf(5) tolerates repeats and it's
/// not this function's job to second-guess what was already there.
fn parse_nameservers(content: &[u8]) -> Vec<String> {
    String::from_utf8_lossy(content)
        .lines()
        .filter_map(|line| {
            let addr = line
                .trim()
                .strip_prefix("nameserver")?
                .split_whitespace()
                .next()?;
            Some(addr.to_string())
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    fn config(server: &str) -> DnsRouteConfig {
        DnsRouteConfig::new(vec![server.parse::<IpAddr>().unwrap()], vec![]).unwrap()
    }

    fn backend(dir: &tempfile::TempDir) -> StaticResolvConf {
        StaticResolvConf::with_path("test-owner", dir.path().join("resolv.conf"))
    }

    fn config_with_routing_domains(server: &str, domains: &[&str]) -> DnsRouteConfig {
        DnsRouteConfig::new(
            vec![server.parse::<IpAddr>().unwrap()],
            domains.iter().map(|d| d.to_string()).collect(),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn set_with_routing_domains_appends_original_nameservers_after_ours() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("resolv.conf");
        fs::write(&path, "nameserver 9.9.9.9\nnameserver 8.8.8.8\n").unwrap();

        let mut b = StaticResolvConf::with_path("test-owner", &path);
        b.set(
            "eth0",
            &config_with_routing_domains("1.2.3.4", &["myvpn.example"]),
        )
        .await
        .unwrap();

        let written = fs::read_to_string(&path).unwrap();
        // Ours first (REFUSED-fallback relies on this exact order - see
        // docs/design-dns-host-config.md), then the pre-existing ones,
        // untouched.
        let servers: Vec<&str> = written
            .lines()
            .filter_map(|l| l.strip_prefix("nameserver "))
            .collect();
        assert_eq!(servers, ["1.2.3.4", "9.9.9.9", "8.8.8.8"]);
    }

    #[tokio::test]
    async fn set_with_empty_routing_domains_does_not_append_original_nameservers() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("resolv.conf");
        fs::write(&path, "nameserver 9.9.9.9\n").unwrap();

        let mut b = StaticResolvConf::with_path("test-owner", &path);
        // Empty routing_domains = full override (a non-goal for this
        // project, but the type still allows it) - the pre-existing
        // resolver must NOT reappear, since the whole point is to replace
        // it, not fall back to it.
        b.set("eth0", &config("1.2.3.4")).await.unwrap();

        let written = fs::read_to_string(&path).unwrap();
        assert!(!written.contains("9.9.9.9"));
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
    async fn re_setting_with_routing_domains_keeps_pulling_the_real_original_from_backup() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("resolv.conf");
        fs::write(&path, "nameserver 9.9.9.9\n").unwrap();

        let mut b = StaticResolvConf::with_path("test-owner", &path);
        b.set(
            "eth0",
            &config_with_routing_domains("1.2.3.4", &["myvpn.example"]),
        )
        .await
        .unwrap();
        // set() again, as if reapplying a changed config - the appended
        // fallback nameserver must still be the real original (9.9.9.9),
        // not our own previous output from the line above.
        b.set(
            "eth0",
            &config_with_routing_domains("5.6.7.8", &["myvpn.example"]),
        )
        .await
        .unwrap();

        let written = fs::read_to_string(&path).unwrap();
        let servers: Vec<&str> = written
            .lines()
            .filter_map(|l| l.strip_prefix("nameserver "))
            .collect();
        assert_eq!(servers, ["5.6.7.8", "9.9.9.9"]);
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
