//! Conditional forwarding via the `resolvconf(8)` helper (`openresolv` or
//! the original Debian `resolvconf` package): `resolvconf -a <name>` with
//! `nameserver` lines on stdin to add a record, `resolvconf -d <name> -f`
//! to remove it.
//!
//! `resolvconf(8)`'s whole job is merging every registered interface's
//! nameservers into one flat, global `/etc/resolv.conf` - which is exactly
//! what conditional forwarding via REFUSED-fallback needs (see
//! `docs/design-dns-host-config.md`, "Conditional forwarding without
//! native OS support"): our entry alongside whatever else is already
//! registered, in a specific order. The "alongside" part is free - the
//! host's original resolvers stay registered under their own names and
//! keep appearing in the merged file without this backend doing anything
//! about it. The **order** isn't free: `set()` registers under a synthetic
//! name, not the real `interface` it's given, specifically so it sorts
//! first - see `registration_name`.
//!
//! ## Detection
//!
//! Many systems ship a `resolvconf` binary that's actually a compatibility
//! shim symlinked to `resolvectl` (systemd-resolved provides one so
//! scripts written against the classic tool keep working). Driving that
//! through this backend would be redundant with, and less capable than,
//! the dedicated [`SystemdResolved`](crate::linux::SystemdResolved)
//! backend - so `probe()` resolves the binary's real target and refuses it
//! if it turns out to be `resolvectl` in disguise.
//!
//! ## Known gap
//!
//! Unlike `talpid-dns`, this doesn't check for a running `dnsmasq` in
//! `no-resolv` mode, which would silently ignore whatever `resolvconf`
//! writes. Detecting that reliably needs parsing a running dnsmasq's
//! effective config, which is out of scope for now.

use std::ffi::OsStr;
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Stdio;

use tokio::io::AsyncWriteExt;
use tokio::process::Command;

use crate::{DnsRoute, DnsRouteConfig};

#[derive(Debug)]
pub enum Error {
    NotAvailable(String),
    Io(io::Error),
    CommandFailed { args: Vec<String>, stderr: String },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::NotAvailable(msg) => write!(f, "resolvconf not usable: {msg}"),
            Error::Io(e) => write!(f, "resolvconf backend: {e}"),
            Error::CommandFailed { args, stderr } => {
                write!(f, "resolvconf {} failed: {stderr}", args.join(" "))
            }
        }
    }
}

impl std::error::Error for Error {}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::Io(e)
    }
}

pub struct Resolvconf {
    binary: PathBuf,
    registration_name: String,
    active: bool,
}

impl Resolvconf {
    /// Locates `resolvconf` on `PATH` and verifies it isn't a
    /// `resolvectl` compatibility shim. Fails otherwise - see the module
    /// docs. `owner` is folded into the name `set()`/`reset()` register
    /// under (see `registration_name`) so concurrent instances (e.g. two
    /// VPN tunnels on the same host) don't collide on the same entry -
    /// pick something stable and specific to your application.
    pub fn probe(owner: impl Into<String>) -> Result<Self, Error> {
        Self::probe_named("resolvconf", owner.into())
    }

    fn probe_named(name: &str, owner: String) -> Result<Self, Error> {
        let binary = find_in_path(name)
            .ok_or_else(|| Error::NotAvailable(format!("{name} not found on PATH")))?;
        if points_at_resolvectl(&binary) {
            return Err(Error::NotAvailable(
                "resolvconf is a systemd-resolved compatibility shim; \
                 use the systemd-resolved backend instead"
                    .into(),
            ));
        }
        Ok(Self {
            binary,
            registration_name: registration_name(&owner),
            active: false,
        })
    }
}

#[async_trait::async_trait]
impl DnsRoute for Resolvconf {
    type Error = Error;

    async fn set(&mut self, _interface: &str, config: &DnsRouteConfig) -> Result<(), Error> {
        let mut input = String::new();
        for server in &config.servers {
            input.push_str(&format!("nameserver {server}\n"));
        }
        self.run(&["-a", &self.registration_name], &input).await?;
        self.active = true;
        Ok(())
    }

    async fn reset(&mut self) -> Result<(), Error> {
        if !self.active {
            return Ok(());
        }
        self.active = false;
        self.run(&["-d", &self.registration_name, "-f"], "").await
    }
}

impl Resolvconf {
    async fn run(&self, args: &[&str], stdin_data: &str) -> Result<(), Error> {
        let mut child = Command::new(&self.binary)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()?;

        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(stdin_data.as_bytes()).await?;
        }

        let output = child.wait_with_output().await?;
        if !output.status.success() {
            return Err(Error::CommandFailed {
                args: args.iter().map(|s| s.to_string()).collect(),
                stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            });
        }
        Ok(())
    }
}

fn find_in_path(name: &str) -> Option<PathBuf> {
    let path_var = std::env::var_os("PATH")?;
    find_in_path_str(name, &path_var)
}

fn find_in_path_str(name: &str, path_var: &OsStr) -> Option<PathBuf> {
    std::env::split_paths(path_var)
        .map(|dir| dir.join(name))
        .find(|candidate| candidate.is_file())
}

/// Whether `path`, followed through any symlinks, resolves to a file named
/// `resolvectl`.
fn points_at_resolvectl(path: &Path) -> bool {
    std::fs::canonicalize(path)
        .ok()
        .and_then(|p| p.file_name().map(|n| n == "resolvectl"))
        .unwrap_or(false)
}

const REGISTRATION_PREFIX: &str = "vpn-";

/// The name `set()`/`reset()` register under with `resolvconf(8)` -
/// deliberately *not* the real interface name they're given.
/// `resolvconf(8)`'s default `/etc/resolvconf/interface-order` sorts a
/// `vpn*`-named entry near the very top (right after loopback, ahead of
/// `eth*`/`wlan*`/everything else, regardless of registration order -
/// verified empirically, see `docs/design-dns-host-config.md`), which the
/// real interface name can't guarantee: a WireGuard interface is commonly
/// named e.g. `wg0`, matching no high-priority pattern at all and sorting
/// wherever the catch-all `*` bucket happens to place it. `owner` is
/// folded in (sanitized to `[A-Za-z0-9_-]`, truncated) so two concurrent
/// instances don't register the same name and clobber each other.
fn registration_name(owner: &str) -> String {
    let sanitized: String = owner
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
        .take(32)
        .collect();
    format!("{REGISTRATION_PREFIX}{sanitized}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;
    use tokio::sync::Mutex;

    fn config(server: &str) -> DnsRouteConfig {
        DnsRouteConfig::new(vec![server.parse::<IpAddr>().unwrap()], vec![]).unwrap()
    }

    /// `#[tokio::test]` gives each test its own runtime, and `cargo test`
    /// runs tests in parallel by default; spawning a child process from
    /// several such runtimes at once has been observed to race (this
    /// module's tests spawn the fake `resolvconf` script below). Anything
    /// that calls `Resolvconf::run` takes this lock first, held across the
    /// `.await` for the duration of the `#[tokio::test]` body, to
    /// serialize them - a `tokio::sync::Mutex`, not `std::sync::Mutex`,
    /// specifically because it's safe to hold across an await point.
    static PROCESS_SPAWN_LOCK: Mutex<()> = Mutex::const_new(());

    #[test]
    fn find_in_path_locates_an_executable_file() {
        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join("resolvconf");
        std::fs::write(&bin, "#!/bin/sh\n").unwrap();
        let path_var = std::env::join_paths([dir.path()]).unwrap();
        assert_eq!(find_in_path_str("resolvconf", &path_var), Some(bin));
    }

    #[test]
    fn find_in_path_returns_none_when_absent() {
        let dir = tempfile::tempdir().unwrap();
        let path_var = std::env::join_paths([dir.path()]).unwrap();
        assert_eq!(find_in_path_str("resolvconf", &path_var), None);
    }

    #[test]
    fn points_at_resolvectl_follows_a_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("resolvectl");
        std::fs::write(&real, "#!/bin/sh\n").unwrap();
        let shim = dir.path().join("resolvconf");
        std::os::unix::fs::symlink(&real, &shim).unwrap();
        assert!(points_at_resolvectl(&shim));
    }

    #[test]
    fn points_at_resolvectl_is_false_for_a_standalone_binary() {
        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join("resolvconf");
        std::fs::write(&bin, "#!/bin/sh\n").unwrap();
        assert!(!points_at_resolvectl(&bin));
    }

    /// Writes a fake `resolvconf(8)` that records the arguments and stdin
    /// it was invoked with into `args`/`stdin` files under `record_dir`
    /// (its path baked directly into the generated script's text, not
    /// passed via a process-wide env var, so parallel tests never share
    /// mutable global state) and exits with `exit_code`.
    fn fake_resolvconf(bin_dir: &Path, record_dir: &Path, exit_code: i32) -> PathBuf {
        let bin = bin_dir.join("resolvconf");
        let record_dir = record_dir.display();
        std::fs::write(
            &bin,
            format!(
                "#!/bin/sh\n\
                 echo \"$@\" > \"{record_dir}/args\"\n\
                 cat > \"{record_dir}/stdin\"\n\
                 exit {exit_code}\n"
            ),
        )
        .unwrap();
        std::fs::set_permissions(&bin, std::os::unix::fs::PermissionsExt::from_mode(0o755))
            .unwrap();
        bin
    }

    fn backend(binary: PathBuf, owner: &str) -> Resolvconf {
        Resolvconf {
            binary,
            registration_name: registration_name(owner),
            active: false,
        }
    }

    #[test]
    fn registration_name_is_prefixed_and_sanitized() {
        assert_eq!(registration_name("my-vpn"), "vpn-my-vpn");
        assert_eq!(
            registration_name("weird chars!@# ok_1"),
            "vpn-weirdcharsok_1"
        );
    }

    #[test]
    fn registration_name_is_truncated() {
        let long = "a".repeat(100);
        assert_eq!(
            registration_name(&long).len(),
            REGISTRATION_PREFIX.len() + 32
        );
    }

    #[tokio::test]
    async fn set_registers_under_the_synthetic_name_not_the_real_interface() {
        let _guard = PROCESS_SPAWN_LOCK.lock().await;
        let bin_dir = tempfile::tempdir().unwrap();
        let record_dir = tempfile::tempdir().unwrap();
        let binary = fake_resolvconf(bin_dir.path(), record_dir.path(), 0);

        // set() is told "tun0", but must register as "vpn-<owner>" - see
        // the module docs on why the real interface name isn't used for
        // this.
        let mut b = backend(binary, "test-owner");
        b.set("tun0", &config("10.1.2.3")).await.unwrap();

        assert_eq!(
            std::fs::read_to_string(record_dir.path().join("args")).unwrap(),
            "-a vpn-test-owner\n"
        );
        assert_eq!(
            std::fs::read_to_string(record_dir.path().join("stdin")).unwrap(),
            "nameserver 10.1.2.3\n"
        );
        assert!(b.active);
    }

    #[tokio::test]
    async fn reset_invokes_resolvconf_dash_d_dash_f_on_the_synthetic_name() {
        let _guard = PROCESS_SPAWN_LOCK.lock().await;
        let bin_dir = tempfile::tempdir().unwrap();
        let record_dir = tempfile::tempdir().unwrap();
        let binary = fake_resolvconf(bin_dir.path(), record_dir.path(), 0);

        let mut b = backend(binary, "test-owner");
        b.active = true;
        b.reset().await.unwrap();

        assert_eq!(
            std::fs::read_to_string(record_dir.path().join("args")).unwrap(),
            "-d vpn-test-owner -f\n"
        );
        assert!(!b.active);
    }

    #[tokio::test]
    async fn reset_without_a_prior_set_is_a_no_op() {
        let bin_dir = tempfile::tempdir().unwrap();
        let record_dir = tempfile::tempdir().unwrap();
        // A binary that would fail if invoked, to prove reset() doesn't
        // call it when there's nothing to undo.
        let binary = fake_resolvconf(bin_dir.path(), record_dir.path(), 1);
        let mut b = backend(binary, "test-owner");
        b.reset().await.unwrap();
    }

    #[tokio::test]
    async fn a_nonzero_exit_status_is_reported_as_command_failed() {
        let _guard = PROCESS_SPAWN_LOCK.lock().await;
        let bin_dir = tempfile::tempdir().unwrap();
        let record_dir = tempfile::tempdir().unwrap();
        let binary = fake_resolvconf(bin_dir.path(), record_dir.path(), 1);

        let mut b = backend(binary, "test-owner");
        let err = b.set("tun0", &config("10.1.2.3")).await.unwrap_err();

        assert!(matches!(err, Error::CommandFailed { .. }));
    }
}
