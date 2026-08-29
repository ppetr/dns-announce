//! Global-override forwarding via the `resolvconf(8)` helper (`openresolv`
//! or the original Debian `resolvconf` package): `resolvconf -a
//! <interface>` with `nameserver` lines on stdin to add a record,
//! `resolvconf -d <interface> -f` to remove it.
//!
//! Like [`StaticResolvConf`](crate::linux::StaticResolvConf), this cannot
//! do conditional forwarding - `resolvconf(8)` merges every registered
//! interface's nameservers into one flat, global `/etc/resolv.conf`, with
//! no concept of routing one domain elsewhere while leaving the rest
//! alone. `set()` refuses a non-empty `routing_domains` for the same
//! reason the static-file backend does.
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
    active_interface: Option<String>,
}

impl Resolvconf {
    /// Locates `resolvconf` on `PATH` and verifies it isn't a
    /// `resolvectl` compatibility shim. Fails otherwise - see the module
    /// docs.
    pub fn probe() -> Result<Self, Error> {
        Self::probe_named("resolvconf")
    }

    fn probe_named(name: &str) -> Result<Self, Error> {
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
            active_interface: None,
        })
    }
}

#[async_trait::async_trait]
impl DnsRoute for Resolvconf {
    type Error = Error;

    async fn set(&mut self, interface: &str, config: &DnsRouteConfig) -> Result<(), Error> {
        if !config.routing_domains.is_empty() {
            return Err(Error::NotAvailable(
                "resolvconf(8) cannot do conditional forwarding; routing_domains must be empty"
                    .into(),
            ));
        }

        let mut input = String::new();
        for server in &config.servers {
            input.push_str(&format!("nameserver {server}\n"));
        }
        self.run(&["-a", interface], &input).await?;
        self.active_interface = Some(interface.to_string());
        Ok(())
    }

    async fn reset(&mut self) -> Result<(), Error> {
        let Some(interface) = self.active_interface.take() else {
            return Ok(());
        };
        self.run(&["-d", &interface, "-f"], "").await
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
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

    #[tokio::test]
    async fn set_invokes_resolvconf_dash_a_with_nameservers_on_stdin() {
        let _guard = PROCESS_SPAWN_LOCK.lock().await;
        let bin_dir = tempfile::tempdir().unwrap();
        let record_dir = tempfile::tempdir().unwrap();
        let binary = fake_resolvconf(bin_dir.path(), record_dir.path(), 0);

        let mut b = Resolvconf {
            binary,
            active_interface: None,
        };
        b.set("tun0", &config("10.1.2.3")).await.unwrap();

        assert_eq!(
            std::fs::read_to_string(record_dir.path().join("args")).unwrap(),
            "-a tun0\n"
        );
        assert_eq!(
            std::fs::read_to_string(record_dir.path().join("stdin")).unwrap(),
            "nameserver 10.1.2.3\n"
        );
        assert_eq!(b.active_interface.as_deref(), Some("tun0"));
    }

    #[tokio::test]
    async fn reset_invokes_resolvconf_dash_d_dash_f() {
        let _guard = PROCESS_SPAWN_LOCK.lock().await;
        let bin_dir = tempfile::tempdir().unwrap();
        let record_dir = tempfile::tempdir().unwrap();
        let binary = fake_resolvconf(bin_dir.path(), record_dir.path(), 0);

        let mut b = Resolvconf {
            binary,
            active_interface: Some("tun0".to_string()),
        };
        b.reset().await.unwrap();

        assert_eq!(
            std::fs::read_to_string(record_dir.path().join("args")).unwrap(),
            "-d tun0 -f\n"
        );
        assert!(b.active_interface.is_none());
    }

    #[tokio::test]
    async fn reset_without_a_prior_set_is_a_no_op() {
        let bin_dir = tempfile::tempdir().unwrap();
        let record_dir = tempfile::tempdir().unwrap();
        // A binary that would fail if invoked, to prove reset() doesn't
        // call it when there's nothing to undo.
        let binary = fake_resolvconf(bin_dir.path(), record_dir.path(), 1);
        let mut b = Resolvconf {
            binary,
            active_interface: None,
        };
        b.reset().await.unwrap();
    }

    #[tokio::test]
    async fn a_nonzero_exit_status_is_reported_as_command_failed() {
        let _guard = PROCESS_SPAWN_LOCK.lock().await;
        let bin_dir = tempfile::tempdir().unwrap();
        let record_dir = tempfile::tempdir().unwrap();
        let binary = fake_resolvconf(bin_dir.path(), record_dir.path(), 1);

        let mut b = Resolvconf {
            binary,
            active_interface: None,
        };
        let err = b.set("tun0", &config("10.1.2.3")).await.unwrap_err();

        assert!(matches!(err, Error::CommandFailed { .. }));
    }

    #[tokio::test]
    async fn set_refuses_routing_domains() {
        let bin_dir = tempfile::tempdir().unwrap();
        let record_dir = tempfile::tempdir().unwrap();
        let binary = fake_resolvconf(bin_dir.path(), record_dir.path(), 0);
        let mut b = Resolvconf {
            binary,
            active_interface: None,
        };
        let cfg = DnsRouteConfig::new(
            vec![IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))],
            vec!["myvpn.example".into()],
        )
        .unwrap();
        assert!(matches!(
            b.set("tun0", &cfg).await,
            Err(Error::NotAvailable(_))
        ));
    }
}
