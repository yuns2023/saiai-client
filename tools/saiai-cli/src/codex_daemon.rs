//! Codex caches authentication and network settings in its shared app-server.
//! Only the official lifecycle command may replace that process. Treat any
//! loaded thread (including an idle one) or failed probe as unsafe to restart.

use crate::{DoctorReport, codex_config_dir, codex_process_command};
use anyhow::{Result, anyhow, bail};
use serde_json::{Value, json};
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio_tungstenite::tungstenite::client::client_with_config;
use tokio_tungstenite::tungstenite::{Message, WebSocket};

#[cfg(unix)]
use std::os::unix::net::UnixStream as ControlStream;
#[cfg(windows)]
use uds_windows::UnixStream as ControlStream;

const PROBE_TIMEOUT: Duration = Duration::from_secs(5);
// Exceed the official default 60s shutdown grace so a slow drain is not cut
// off after the old daemon stops but before the new one starts.
const RESTART_TIMEOUT: Duration = Duration::from_secs(90);
const MAX_COMMAND_OUTPUT: u64 = 16 * 1024;
const MANUAL_RESTART: &str =
    "finish Codex tasks, then run `codex app-server daemon restart`; meanwhile use `saiai codex`";

pub(crate) fn after_initialization(home: &Path) {
    if crate::should_skip_initialization_proxy_start(
        std::env::var("SAIAI_SKIP_START").ok().as_deref(),
    ) {
        println!("Codex daemon refresh skipped (SAIAI_SKIP_START=1).");
        return;
    }
    match refresh(&OfficialDaemon { home }) {
        Ok(Refresh::Absent) => println!("Codex daemon is not running; no restart needed."),
        Ok(Refresh::Deferred) => println!(
            "WARNING: Codex daemon has loaded sessions; left running to preserve work. {MANUAL_RESTART}."
        ),
        Ok(Refresh::Restarted) => println!(
            "Codex daemon restarted and recognizes ChatGPT authentication; direct `codex` startup is ready."
        ),
        Err(error) => println!(
            "WARNING: Codex daemon refresh could not be verified: {error}. {MANUAL_RESTART}."
        ),
    }
}

pub(crate) fn check(report: &mut DoctorReport) {
    let Ok(home) = codex_config_dir() else { return };
    // A valid file alone does not prove that an already-running daemon loaded it.
    if crate::validate_codex_oauth_auth(&home.join("auth.json")).is_err() {
        return;
    }
    report_inspection(report, (OfficialDaemon { home: &home }).inspect());
}

fn report_inspection(report: &mut DoctorReport, inspection: Result<Option<RunningDaemon>>) {
    match inspection {
        Ok(None) => report.ok("Codex daemon", "not running; no cached authentication to check"),
        Ok(Some(running)) if running.snapshot.signed_in => report.ok(
            "Codex daemon auth",
            "account/read recognizes ChatGPT authentication; no model request was sent",
        ),
        Ok(Some(_)) => report.warn(
            "Codex daemon auth",
            format!("auth.json is valid but the running daemon is not signed in with ChatGPT; direct `codex` may show the login menu. {MANUAL_RESTART}"),
        ),
        Err(error) => report.warn(
            "Codex daemon",
            format!("could not verify cached authentication: {error}; no process was changed. {MANUAL_RESTART}"),
        ),
    }
}

#[derive(Debug, PartialEq)]
enum Refresh {
    Absent,
    Deferred,
    Restarted,
}

#[derive(Debug)]
struct RunningDaemon {
    managed: bool,
    snapshot: Snapshot,
}

#[derive(Debug, PartialEq)]
struct Snapshot {
    loaded_threads: usize,
    signed_in: bool,
}

trait DaemonControl {
    fn inspect(&self) -> Result<Option<RunningDaemon>>;
    fn restart(&self) -> Result<()>;
}

fn refresh(control: &impl DaemonControl) -> Result<Refresh> {
    let Some(running) = control.inspect()? else {
        return Ok(Refresh::Absent);
    };
    if running.snapshot.loaded_threads != 0 {
        return Ok(Refresh::Deferred);
    }
    if !running.managed {
        bail!("the app-server is not managed by the official daemon command");
    }
    control.restart()?;
    let verified = control
        .inspect()?
        .is_some_and(|running| running.snapshot.signed_in);
    if !verified {
        bail!("the restarted daemon did not report ChatGPT authentication");
    }
    Ok(Refresh::Restarted)
}

struct OfficialDaemon<'a> {
    home: &'a Path,
}

impl DaemonControl for OfficialDaemon<'_> {
    fn inspect(&self) -> Result<Option<RunningDaemon>> {
        let socket = self.home.join("app-server-control/app-server-control.sock");
        match fs::symlink_metadata(&socket) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => bail!("the current CODEX_HOME control socket is not readable"),
            Ok(_) => {}
        }
        // `version` only probes an existing daemon; unlike `start`, it cannot
        // bootstrap a daemon or start model work. Withhold all raw CLI output.
        let version = self.command("version", PROBE_TIMEOUT)?;
        if version.get("status").and_then(Value::as_str) != Some("running") {
            bail!("the official daemon command did not report a running app-server");
        }
        let reported_socket = version
            .get("socketPath")
            .and_then(Value::as_str)
            .map(PathBuf::from)
            .ok_or_else(|| anyhow!("the daemon command did not report its control socket"))?;
        if !same_path(&reported_socket, &socket) {
            bail!("the daemon command reported a socket outside the current CODEX_HOME");
        }
        let home = fs::canonicalize(self.home)
            .map_err(|_| anyhow!("could not resolve the current CODEX_HOME"))?;
        let snapshot = probe(&reported_socket, &home)?;
        Ok(Some(RunningDaemon {
            managed: version.get("backend").and_then(Value::as_str) == Some("pid"),
            snapshot,
        }))
    }

    fn restart(&self) -> Result<()> {
        let result = self.command("restart", RESTART_TIMEOUT)?;
        if result.get("status").and_then(Value::as_str) != Some("restarted") {
            bail!("the official daemon command did not confirm a restart");
        }
        Ok(())
    }
}

impl OfficialDaemon<'_> {
    fn command(&self, action: &str, deadline: Duration) -> Result<Value> {
        let mut command = codex_process_command()
            .map_err(|_| anyhow!("the official Codex executable was not found"))?;
        command
            .args(["app-server", "daemon", action])
            .env("CODEX_HOME", self.home);
        if action == "restart" {
            // Match the working launcher environment. A daemon started before
            // initialization also retains its old proxy/CA environment.
            let cfg = crate::read_saiai_config()
                .map_err(|_| anyhow!("SAIAI proxy configuration is unavailable"))?;
            let proxy = format!("http://{}", cfg.listen);
            for name in crate::CODEX_MANAGED_ENV {
                command.env_remove(name);
            }
            for name in [
                "HTTP_PROXY",
                "HTTPS_PROXY",
                "ALL_PROXY",
                "http_proxy",
                "https_proxy",
                "all_proxy",
            ] {
                command.env(name, &proxy);
            }
            for name in ["NO_PROXY", "no_proxy"] {
                command.env(name, crate::CODEX_LOCAL_PROXY_NO_PROXY);
            }
            command
                .env("SSL_CERT_FILE", &cfg.ca_cert_path)
                .env("CODEX_CA_CERTIFICATE", &cfg.ca_cert_path);
        }
        command_json(command, deadline)
    }
}

fn same_path(left: &Path, right: &Path) -> bool {
    fs::canonicalize(left)
        .ok()
        .zip(fs::canonicalize(right).ok())
        .is_some_and(|(left, right)| left == right)
}

fn command_json(mut command: Command, deadline: Duration) -> Result<Value> {
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| anyhow!("could not create the daemon command runtime"))?;
    runtime.block_on(async {
        let mut command = tokio::process::Command::from(command);
        command.kill_on_drop(true);
        let mut child = command
            .spawn()
            .map_err(|_| anyhow!("could not run the official daemon command"))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| anyhow!("daemon command output is unavailable"))?;
        let mut output = Vec::new();
        let result = tokio::time::timeout(deadline, async {
            stdout
                .take(MAX_COMMAND_OUTPUT + 1)
                .read_to_end(&mut output)
                .await
                .map_err(|_| anyhow!("could not read daemon command output"))?;
            if output.len() as u64 > MAX_COMMAND_OUTPUT {
                bail!("daemon command output exceeded the size limit");
            }
            let status = child
                .wait()
                .await
                .map_err(|_| anyhow!("could not wait for the daemon command"))?;
            if !status.success() {
                bail!("the official daemon command failed or is unsupported; raw output withheld");
            }
            serde_json::from_slice(&output).map_err(|_| {
                anyhow!("the daemon command returned invalid JSON; raw output withheld")
            })
        })
        .await;
        // Reap only the short-lived CLI helper. Never kill the daemon ourselves.
        if !matches!(result, Ok(Ok(_))) {
            let _ = child.kill().await;
            let _ = child.wait().await;
        }
        result.map_err(|_| {
            anyhow!("the official daemon command timed out; inspect its state before retrying")
        })?
    })
}

fn probe(socket: &Path, home: &Path) -> Result<Snapshot> {
    let socket = socket.to_path_buf();
    let home = home.to_path_buf();
    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    // Bound even the local socket connection/handshake. This worker performs
    // read-only control calls and cannot restart a process or start a turn.
    std::thread::spawn(move || {
        let _ = sender.send(probe_inner(&socket, &home));
    });
    receiver
        .recv_timeout(PROBE_TIMEOUT)
        .map_err(|_| anyhow!("the daemon control query timed out; state is unknown"))?
}

fn probe_inner(socket: &Path, home: &Path) -> Result<Snapshot> {
    #[cfg(unix)]
    let socket = fs::canonicalize(socket)
        .map_err(|_| anyhow!("could not resolve the daemon control socket"))?;
    let stream = ControlStream::connect(socket)
        .map_err(|_| anyhow!("could not connect to the daemon control socket"))?;
    stream
        .set_read_timeout(Some(PROBE_TIMEOUT))
        .and_then(|_| stream.set_write_timeout(Some(PROBE_TIMEOUT)))
        .map_err(|_| anyhow!("could not bound the daemon control query"))?;
    let config = tokio_tungstenite::tungstenite::protocol::WebSocketConfig::default()
        .max_message_size(Some(256 * 1024))
        .max_frame_size(Some(256 * 1024));
    let (mut websocket, _) = client_with_config("ws://localhost/", stream, Some(config))
        .map_err(|_| anyhow!("could not upgrade the daemon control socket"))?;
    let initialized = request(
        &mut websocket,
        1,
        "initialize",
        json!({
            "clientInfo": {"name": "saiai_daemon_check", "version": env!("CARGO_PKG_VERSION")},
            "capabilities": {"experimentalApi": true}
        }),
    )?;
    let reported_home = initialized
        .get("codexHome")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("the daemon did not report its CODEX_HOME"))?;
    if !same_path(Path::new(reported_home), home) {
        bail!("the connected daemon belongs to a different CODEX_HOME");
    }
    websocket
        .send(Message::Text(
            json!({"method":"initialized"}).to_string().into(),
        ))
        .map_err(|_| anyhow!("could not initialize the daemon control query"))?;
    let account = request(
        &mut websocket,
        2,
        "account/read",
        json!({"refreshToken":false}),
    )?;
    if account
        .get("requiresOpenaiAuth")
        .and_then(Value::as_bool)
        .is_none()
        || !account.get("account").is_some_and(|account| {
            account.is_null()
                || matches!(
                    account.get("type").and_then(Value::as_str),
                    Some("chatgpt" | "apiKey" | "amazonBedrock")
                )
        })
    {
        bail!("the daemon returned an unknown account shape");
    }
    let signed_in = account
        .get("account")
        .and_then(|account| account.get("type"))
        .and_then(Value::as_str)
        == Some("chatgpt");
    // Check activity last: account routing discovery can take time. There is
    // no atomic idle-only restart API, so retain even idle loaded sessions.
    let loaded = request(&mut websocket, 3, "thread/loaded/list", json!({}))?;
    let threads = loaded
        .get("data")
        .and_then(Value::as_array)
        .filter(|threads| threads.iter().all(Value::is_string))
        .ok_or_else(|| anyhow!("the daemon returned an unknown loaded-session shape"))?;
    let loaded_threads = threads.len();
    let _ = websocket.close(None);
    Ok(Snapshot {
        loaded_threads,
        signed_in,
    })
}

fn request<S: Read + Write>(
    websocket: &mut WebSocket<S>,
    id: u64,
    method: &str,
    params: Value,
) -> Result<Value> {
    websocket
        .send(Message::Text(
            json!({"id":id,"method":method,"params":params})
                .to_string()
                .into(),
        ))
        .map_err(|_| anyhow!("could not send a daemon control query"))?;
    for _ in 0..64 {
        match websocket
            .read()
            .map_err(|_| anyhow!("could not read a daemon control response"))?
        {
            Message::Text(text) => {
                let response: Value = serde_json::from_str(&text).map_err(|_| {
                    anyhow!("the daemon returned invalid control JSON; raw output withheld")
                })?;
                if response.get("id").and_then(Value::as_u64) != Some(id) {
                    continue;
                }
                if response.get("error").is_some() {
                    bail!("the daemon rejected a required control query; raw response withheld");
                }
                return response
                    .get("result")
                    .filter(|result| result.is_object())
                    .cloned()
                    .ok_or_else(|| anyhow!("the daemon omitted a required control result"));
            }
            Message::Ping(_) | Message::Pong(_) => {}
            _ => bail!("the daemon closed or changed its control protocol"),
        }
    }
    bail!("the daemon control response limit was exceeded")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};
    use std::collections::VecDeque;
    #[cfg(unix)]
    use std::os::unix::net::UnixListener as ControlListener;
    #[cfg(windows)]
    use uds_windows::UnixListener as ControlListener;

    struct FakeControl {
        inspections: RefCell<VecDeque<Result<Option<RunningDaemon>>>>,
        restarts: Cell<usize>,
        restart_fails: bool,
    }

    impl DaemonControl for FakeControl {
        fn inspect(&self) -> Result<Option<RunningDaemon>> {
            self.inspections
                .borrow_mut()
                .pop_front()
                .expect("unexpected inspection")
        }
        fn restart(&self) -> Result<()> {
            self.restarts.set(self.restarts.get() + 1);
            if self.restart_fails {
                bail!("restart failed")
            }
            Ok(())
        }
    }

    fn running(
        managed: bool,
        loaded_threads: usize,
        signed_in: bool,
    ) -> Result<Option<RunningDaemon>> {
        Ok(Some(RunningDaemon {
            managed,
            snapshot: Snapshot {
                loaded_threads,
                signed_in,
            },
        }))
    }

    fn fake(inspections: Vec<Result<Option<RunningDaemon>>>) -> FakeControl {
        FakeControl {
            inspections: RefCell::new(inspections.into()),
            restarts: Cell::new(0),
            restart_fails: false,
        }
    }

    #[test]
    fn stale_idle_daemon_is_restarted_and_auth_is_verified() {
        let control = fake(vec![running(true, 0, false), running(true, 0, true)]);
        assert_eq!(refresh(&control).unwrap(), Refresh::Restarted);
        assert_eq!(control.restarts.get(), 1);
    }

    #[test]
    fn absent_busy_unmanaged_and_unknown_daemons_are_never_restarted() {
        for (inspection, expected) in [
            (Ok(None), Some(Refresh::Absent)),
            (running(true, 1, false), Some(Refresh::Deferred)),
            (running(true, 2, true), Some(Refresh::Deferred)),
            (running(false, 0, false), None),
            (Err(anyhow!("query failed")), None),
        ] {
            let control = fake(vec![inspection]);
            let result = refresh(&control);
            match expected {
                Some(expected) => assert_eq!(result.unwrap(), expected),
                None => assert!(result.is_err()),
            }
            assert_eq!(control.restarts.get(), 0);
        }
    }

    #[test]
    fn failed_restart_or_postflight_never_reports_success() {
        for postflight in [
            Ok(None),
            running(true, 0, false),
            Err(anyhow!("query failed")),
        ] {
            let control = fake(vec![running(true, 0, false), postflight]);
            assert!(refresh(&control).is_err());
            assert_eq!(control.restarts.get(), 1);
        }
        let mut control = fake(vec![running(true, 0, false)]);
        control.restart_fails = true;
        assert!(refresh(&control).is_err());
        assert!(control.inspections.borrow().is_empty());
    }

    #[test]
    fn doctor_flags_valid_file_with_missing_daemon_account_without_restarting() {
        let control = fake(vec![running(true, 1, false)]);
        let mut report = DoctorReport::new();
        report_inspection(&mut report, control.inspect());
        assert_eq!(report.warnings, 1);
        assert_eq!(report.errors, 0);
        assert_eq!(control.restarts.get(), 0);
        report_inspection(&mut report, running(true, 1, true));
        assert_eq!(report.warnings, 1);
    }

    fn mock_probe(threads: Value, account: Value, wrong_home: bool) -> Result<Snapshot> {
        let home = tempfile::tempdir().unwrap();
        let socket = home.path().join("daemon.sock");
        let listener = ControlListener::bind(&socket).unwrap();
        let reported_home = if wrong_home {
            home.path().join("other-home")
        } else {
            home.path().to_path_buf()
        };
        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            stream.set_read_timeout(Some(PROBE_TIMEOUT)).unwrap();
            stream.set_write_timeout(Some(PROBE_TIMEOUT)).unwrap();
            let mut websocket = tokio_tungstenite::tungstenite::accept(stream).unwrap();
            let mut methods = Vec::new();
            while let Ok(message) = websocket.read() {
                let Message::Text(text) = message else { break };
                let request: Value = serde_json::from_str(&text).unwrap();
                let method = request["method"].as_str().unwrap();
                methods.push(method.to_string());
                let result = match method {
                    "initialize" => json!({"codexHome":reported_home}),
                    "initialized" => continue,
                    "thread/loaded/list" => threads.clone(),
                    "account/read" => {
                        assert_eq!(request["params"], json!({"refreshToken":false}));
                        account.clone()
                    }
                    _ => panic!("unexpected non-read-only control method"),
                };
                websocket
                    .send(Message::Text(
                        json!({"id":request["id"],"result":result})
                            .to_string()
                            .into(),
                    ))
                    .unwrap();
            }
            methods
        });
        let result = probe(&socket, home.path());
        let methods = server.join().unwrap();
        if result.is_ok() {
            assert_eq!(
                methods,
                [
                    "initialize",
                    "initialized",
                    "account/read",
                    "thread/loaded/list"
                ]
            );
        }
        result
    }

    #[test]
    fn native_control_socket_reads_actual_login_and_loaded_session_state() {
        let empty = json!({"data":[]});
        let missing = json!({"account":null,"requiresOpenaiAuth":true});
        assert_eq!(
            mock_probe(empty.clone(), missing.clone(), false).unwrap(),
            Snapshot {
                loaded_threads: 0,
                signed_in: false
            }
        );
        let signed_in = json!({"account":{"type":"chatgpt","email":"synthetic@example.invalid"},"requiresOpenaiAuth":true});
        assert_eq!(
            mock_probe(json!({"data":["busy-thread"]}), signed_in, false).unwrap(),
            Snapshot {
                loaded_threads: 1,
                signed_in: true
            }
        );
        assert!(mock_probe(json!({"data":null}), missing.clone(), false).is_err());
        assert!(mock_probe(json!({"data":[null]}), missing, false).is_err());
        assert!(mock_probe(empty.clone(), json!({}), false).is_err());
        assert!(
            mock_probe(
                empty.clone(),
                json!({"account":{},"requiresOpenaiAuth":true}),
                false
            )
            .is_err()
        );
        assert!(
            mock_probe(
                empty,
                json!({"account":null,"requiresOpenaiAuth":true}),
                true
            )
            .is_err()
        );
    }

    #[cfg(unix)]
    #[test]
    fn failed_cli_output_and_timeout_are_bounded_and_redacted() {
        let mut command = Command::new("sh");
        command.args(["-c", "printf 'SYNTHETIC_SECRET'; exit 1"]);
        let error = command_json(command, PROBE_TIMEOUT)
            .unwrap_err()
            .to_string();
        assert!(!error.contains("SYNTHETIC_SECRET"));
        let mut command = Command::new("sh");
        command.args(["-c", "printf 'SYNTHETIC_SECRET invalid-json'"]);
        assert!(
            !command_json(command, PROBE_TIMEOUT)
                .unwrap_err()
                .to_string()
                .contains("SYNTHETIC_SECRET")
        );
        let mut command = Command::new("sh");
        command.args(["-c", "printf '%17000s' ''"]);
        assert!(
            command_json(command, PROBE_TIMEOUT)
                .unwrap_err()
                .to_string()
                .contains("size limit")
        );
        let mut command = Command::new("sh");
        command.args(["-c", "exec sleep 10"]);
        let start = std::time::Instant::now();
        assert!(command_json(command, Duration::from_millis(100)).is_err());
        assert!(start.elapsed() < Duration::from_secs(2));
    }
}
