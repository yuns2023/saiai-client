use std::fs;
use std::io::{self, Read};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use saiai_core::{
    CONFIG_SCHEMA_VERSION, ClientProgramResolveError, GatewayUrl, PrivatePermissionIssueCode,
    Product, ProductSetupState, ProvisionRequest, RevokeTarget, SaiaiCore, SecretString,
    SetupIssue, SetupIssueCode, SetupState, SetupStatus, UnsupportedNpmShimReason,
    resolve_client_program,
};
use serde::{Deserialize, Serialize};

const VERSION_PROBE_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_VERSION_OUTPUT_BYTES: usize = 128;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct GatewayState {
    configured: bool,
    origin: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ClientStatus {
    kind: &'static str,
    name: &'static str,
    command: &'static str,
    setup_state: &'static str,
    runtime_state: &'static str,
    detail: String,
    version: Option<String>,
    home: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DesktopState {
    schema_version: u32,
    setup_state: &'static str,
    mode: &'static str,
    gateway: GatewayState,
    clients: Vec<ClientStatus>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SetupInput {
    product: String,
    base_url: String,
    api_key: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ActionResult {
    accepted: bool,
    message: String,
    removed_paths: Vec<String>,
    setup_state: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DoctorCheck {
    id: String,
    label: String,
    level: &'static str,
    summary: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DoctorReport {
    generated_at: String,
    checks: Vec<DoctorCheck>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum ProgramProbe {
    Found(String),
    Missing,
    Warning(&'static str),
}

#[tauri::command]
fn desktop_get_state() -> Result<DesktopState, String> {
    let core = discover_core()?;
    desktop_state_with(&core, probe_product_isolated)
}

#[tauri::command]
async fn desktop_setup(mut input: SetupInput) -> Result<ActionResult, String> {
    let (product, request) = take_provision_request(&mut input)?;
    let core = discover_core()?;
    let report = core
        .provision(product, request)
        .await
        .map_err(|error| error.to_string())?;

    Ok(ActionResult {
        accepted: true,
        message: setup_success_message(product, &report.bootstrap.gateway_version),
        removed_paths: Vec::new(),
        setup_state: setup_state_name(report.setup.state),
    })
}

fn setup_success_message(product: Product, gateway_version: &str) -> String {
    if gateway_version.trim().is_empty() {
        format!(
            "{} V2 初始化完成；Gateway 已通过无计费 bootstrap 验证。",
            product_display_name(product)
        )
    } else {
        format!(
            "{} V2 初始化完成；Gateway {} 已通过无计费 bootstrap 验证。",
            product_display_name(product),
            gateway_version
        )
    }
}

fn take_provision_request(input: &mut SetupInput) -> Result<(Product, ProvisionRequest), String> {
    // Take the IPC-owned allocation first. Every later early return drops a
    // SecretString, which zeroizes the allocation before freeing it.
    let secret =
        SecretString::new(std::mem::take(&mut input.api_key)).map_err(|error| error.to_string())?;
    let product = parse_product(&input.product)?;
    let base_url = GatewayUrl::parse(&input.base_url).map_err(|error| error.to_string())?;
    let request =
        ProvisionRequest::from_validated(base_url, secret).map_err(|error| error.to_string())?;
    Ok((product, request))
}

fn parse_product(product: &str) -> Result<Product, String> {
    match product {
        "claude" => Ok(Product::Claude),
        "codex" => Ok(Product::Codex),
        _ => Err("Unknown setup product".to_owned()),
    }
}

#[tauri::command]
fn desktop_doctor() -> Result<DoctorReport, String> {
    let core = discover_core()?;
    doctor_report_with(&core, probe_product_isolated)
}

#[tauri::command]
fn desktop_revoke(target: String) -> Result<ActionResult, String> {
    let core = discover_core()?;
    desktop_revoke_with_core(&core, &target)
}

fn discover_core() -> Result<SaiaiCore, String> {
    SaiaiCore::discover().map_err(|error| error.to_string())
}

fn desktop_state_with(
    core: &SaiaiCore,
    probe: impl FnMut(Product, Option<&Path>) -> ProgramProbe,
) -> Result<DesktopState, String> {
    let status = core.setup_status().map_err(|error| error.to_string())?;
    Ok(state_from_status(&status, probe))
}

fn state_from_status(
    status: &SetupStatus,
    mut probe: impl FnMut(Product, Option<&Path>) -> ProgramProbe,
) -> DesktopState {
    let gateway = status.config.as_ref().map(|config| GatewayState {
        configured: true,
        origin: Some(config.base_url().as_str().to_owned()),
    });

    DesktopState {
        schema_version: CONFIG_SCHEMA_VERSION,
        setup_state: setup_state_name(status.state),
        mode: "v2",
        gateway: gateway.unwrap_or(GatewayState {
            configured: false,
            origin: None,
        }),
        clients: Product::ALL
            .into_iter()
            .map(|product| {
                let product_status = status
                    .products
                    .iter()
                    .find(|candidate| candidate.product == product);
                let home_path = product_status.and_then(|candidate| candidate.home.as_ref());
                let configured = status
                    .config
                    .as_ref()
                    .is_some_and(|config| config.product(product).is_some());
                let program_probe =
                    configured.then(|| probe(product, home_path.map(|path| path.as_path())));
                let home = home_path.map(|path| path.to_string_lossy().into_owned());
                client_status(
                    product,
                    product_status.map_or(ProductSetupState::Unconfigured, |status| status.state),
                    home,
                    product_status.map_or(&[][..], |status| status.issues.as_slice()),
                    program_probe,
                )
            })
            .collect(),
    }
}

fn client_status(
    product: Product,
    setup_state: ProductSetupState,
    home: Option<String>,
    issues: &[SetupIssue],
    probe: Option<ProgramProbe>,
) -> ClientStatus {
    let (kind, name, command) = match product {
        Product::Claude => ("claude", "Claude Code", "saiai claude"),
        Product::Codex => ("codex", "Codex", "saiai codex"),
    };

    let (runtime_state, runtime_detail, version) = match probe {
        Some(ProgramProbe::Found(version)) => ("ready", None, Some(version)),
        Some(ProgramProbe::Missing) => {
            ("missing", Some(format!("未找到 {name} 可执行文件。")), None)
        }
        Some(ProgramProbe::Warning(reason)) => {
            ("warning", Some(format!("{name} {reason}。")), None)
        }
        None => ("not_checked", None, None),
    };

    let detail = match setup_state {
        ProductSetupState::Unconfigured => {
            format!("尚未初始化 {name}；未配置不会影响另一产品。")
        }
        ProductSetupState::Ready => runtime_detail
            .map(|detail| format!("V2 隔离环境已准备，但{detail}"))
            .unwrap_or_else(|| "客户端已安装，V2 隔离环境已准备。".to_owned()),
        ProductSetupState::Broken => {
            let summary = issues
                .iter()
                .map(|issue| issue.message.as_str())
                .collect::<Vec<_>>()
                .join("；");
            if summary.is_empty() {
                "该产品的 V2 状态未通过检查；可重新初始化或单独 revoke。".to_owned()
            } else {
                format!("该产品的 V2 状态未通过检查：{summary}")
            }
        }
    };

    ClientStatus {
        kind,
        name,
        command,
        setup_state: product_setup_state_name(setup_state),
        runtime_state,
        detail,
        version,
        home,
    }
}

fn doctor_report_with(
    core: &SaiaiCore,
    mut probe: impl FnMut(Product, Option<&Path>) -> ProgramProbe,
) -> Result<DoctorReport, String> {
    let status = core.setup_status().map_err(|error| error.to_string())?;
    let mut checks = Vec::new();

    checks.push(DoctorCheck {
        id: "setup".to_owned(),
        label: "V2 初始化".to_owned(),
        level: match status.state {
            SetupState::Ready => "ok",
            SetupState::Uninitialized => "pending",
            SetupState::Broken => "error",
        },
        summary: match status.state {
            SetupState::Ready => {
                let configured = status
                    .products
                    .iter()
                    .filter(|product| product.state == ProductSetupState::Ready)
                    .count();
                format!("{configured} 个产品已通过检查；未配置的产品不计为错误。")
            }
            SetupState::Uninitialized => "尚未创建 V2 本地状态。".to_owned(),
            SetupState::Broken => "检测到已配置产品的 V2 状态异常。".to_owned(),
        },
    });

    checks.push(DoctorCheck {
        id: "gateway".to_owned(),
        label: "Gateway 配置".to_owned(),
        level: if status.config.is_some() {
            "ok"
        } else if status.state == SetupState::Uninitialized {
            "pending"
        } else {
            "error"
        },
        summary: status
            .config
            .as_ref()
            .map(|config| format!("已验证 {}", config.base_url()))
            .unwrap_or_else(|| "V2 config.json 不存在或未通过验证。".to_owned()),
    });

    for product in Product::ALL {
        let (kind, label) = match product {
            Product::Claude => ("claude", "Claude 隔离环境"),
            Product::Codex => ("codex", "Codex 隔离环境"),
        };
        let product_status = status
            .products
            .iter()
            .find(|candidate| candidate.product == product);
        let product_state =
            product_status.map_or(ProductSetupState::Unconfigured, |status| status.state);
        checks.push(DoctorCheck {
            id: format!("{kind}-home"),
            label: label.to_owned(),
            level: match product_state {
                ProductSetupState::Unconfigured => "pending",
                ProductSetupState::Ready => "ok",
                ProductSetupState::Broken => "error",
            },
            summary: match product_state {
                ProductSetupState::Unconfigured => {
                    "未配置；按需启用即可，这不是 V2 状态错误。".to_owned()
                }
                ProductSetupState::Ready => {
                    let home = product_status
                        .and_then(|candidate| candidate.home.as_ref())
                        .map(|path| path.to_string_lossy().into_owned())
                        .unwrap_or_else(|| "V2 managed home".to_owned());
                    "凭据、必需文件和 managed marker 已验证：".to_owned() + &home
                }
                ProductSetupState::Broken => product_status
                    .map(|status| {
                        status
                            .issues
                            .iter()
                            .map(|issue| issue.message.as_str())
                            .collect::<Vec<_>>()
                            .join("；")
                    })
                    .filter(|summary| !summary.is_empty())
                    .unwrap_or_else(|| "该产品的凭据或隔离环境未通过检查。".to_owned()),
            },
        });

        let configured = status
            .config
            .as_ref()
            .is_some_and(|config| config.product(product).is_some());
        let client_probe = configured.then(|| {
            probe(
                product,
                product_status
                    .and_then(|candidate| candidate.home.as_ref())
                    .map(|path| path.as_path()),
            )
        });
        let (level, summary) = match client_probe {
            Some(ProgramProbe::Found(version)) => ("ok", format!("已检测到版本 {version}")),
            Some(ProgramProbe::Missing) => ("warning", "PATH 中未找到客户端命令。".to_owned()),
            Some(ProgramProbe::Warning(reason)) => ("warning", format!("版本{reason}。")),
            None => ("pending", "产品未配置；未运行版本探测。".to_owned()),
        };
        checks.push(DoctorCheck {
            id: format!("{kind}-program"),
            label: format!("{label}客户端"),
            level,
            summary,
        });
    }

    for (index, issue) in status.issues.iter().enumerate() {
        checks.push(DoctorCheck {
            id: format!("core-issue-{index}-{}", issue_code_id(issue.code)),
            label: "V2 状态问题".to_owned(),
            level: if status.state == SetupState::Broken {
                "error"
            } else {
                "pending"
            },
            summary: issue.message.clone(),
        });
    }

    let permissions = core.audit_private_permissions();
    checks.push(DoctorCheck {
        id: "managed-permissions".to_owned(),
        label: "V2 私有权限".to_owned(),
        level: if !permissions.supported {
            "warning"
        } else if permissions.is_secure() {
            "ok"
        } else {
            "error"
        },
        summary: if !permissions.supported {
            "当前平台不支持自动审计 V2 私有权限。".to_owned()
        } else if permissions.is_secure() {
            format!(
                "已检查 {} 个现有 V2 路径，未发现权限问题。",
                permissions.checked_paths
            )
        } else {
            format!(
                "已检查 {} 个现有 V2 路径，发现 {} 个权限问题。",
                permissions.checked_paths,
                permissions.issues.len()
            )
        },
    });
    for (index, issue) in permissions.issues.iter().enumerate() {
        checks.push(DoctorCheck {
            id: format!(
                "permission-issue-{index}-{}",
                permission_issue_code_id(issue.code)
            ),
            label: "V2 权限问题".to_owned(),
            level: "error",
            summary: format!("{}：{}", issue.path.to_string_lossy(), issue.message),
        });
    }

    checks.push(DoctorCheck {
        id: "permissions".to_owned(),
        label: "桌面权限".to_owned(),
        level: "ok",
        summary: "WebView 未启用 shell、opener、文件系统或 HTTP 插件能力。".to_owned(),
    });

    Ok(DoctorReport {
        generated_at: generated_at(),
        checks,
    })
}

fn desktop_revoke_with_core(core: &SaiaiCore, target: &str) -> Result<ActionResult, String> {
    let (target, label) = match target {
        "claude" => (RevokeTarget::Product(Product::Claude), "Claude"),
        "codex" => (RevokeTarget::Product(Product::Codex), "Codex"),
        "all" => (RevokeTarget::All, "全部 V2"),
        _ => return Err("Unknown revoke target".to_owned()),
    };
    let report = core.revoke(target).map_err(|error| error.to_string())?;
    let removed_paths = report
        .removed_paths
        .iter()
        .map(|path| path.to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    let count = removed_paths.len();

    Ok(ActionResult {
        accepted: true,
        message: format!("{label} 状态已清理（移除 {count} 个 V2 路径）。"),
        removed_paths,
        setup_state: setup_state_name(report.status.state),
    })
}

fn setup_state_name(state: SetupState) -> &'static str {
    match state {
        SetupState::Uninitialized => "uninitialized",
        SetupState::Ready => "ready",
        SetupState::Broken => "error",
    }
}

fn product_setup_state_name(state: ProductSetupState) -> &'static str {
    match state {
        ProductSetupState::Unconfigured => "unconfigured",
        ProductSetupState::Ready => "ready",
        ProductSetupState::Broken => "error",
    }
}

fn issue_code_id(code: SetupIssueCode) -> &'static str {
    match code {
        SetupIssueCode::ConfigMissing => "config-missing",
        SetupIssueCode::ConfigInvalid => "config-invalid",
        SetupIssueCode::CredentialMissing => "credential-missing",
        SetupIssueCode::CredentialInvalid => "credential-invalid",
        SetupIssueCode::GenerationMissing => "generation-missing",
        SetupIssueCode::UnsafeManagedPath => "unsafe-managed-path",
        SetupIssueCode::ProductInvalid => "product-invalid",
    }
}

fn permission_issue_code_id(code: PrivatePermissionIssueCode) -> &'static str {
    match code {
        PrivatePermissionIssueCode::InspectFailed => "inspect-failed",
        PrivatePermissionIssueCode::SymbolicLink => "symbolic-link",
        PrivatePermissionIssueCode::UnexpectedObjectType => "unexpected-object-type",
        PrivatePermissionIssueCode::InsecurePermissions => "insecure-permissions",
    }
}

fn product_display_name(product: Product) -> &'static str {
    match product {
        Product::Claude => "Claude",
        Product::Codex => "Codex",
    }
}

fn probe_product_isolated(product: Product, _home: Option<&Path>) -> ProgramProbe {
    // A client is allowed to create files even for `--version`. Keep an
    // offline status probe out of the normal product home and every persistent
    // V2 root so merely opening the UI cannot create or mutate client state.
    let temporary = match tempfile::Builder::new()
        .prefix("saiai-version-probe-")
        .tempdir()
    {
        Ok(temporary) => temporary,
        Err(_) => return ProgramProbe::Warning("版本探测隔离目录无法创建"),
    };
    let isolation_root = temporary.path();
    let isolated_home = isolation_root.join(product.directory_name());
    let isolation_directories = [
        isolated_home.clone(),
        isolation_root.join("home"),
        isolation_root.join("xdg-config"),
        isolation_root.join("xdg-data"),
        isolation_root.join("xdg-state"),
        isolation_root.join("xdg-cache"),
    ];
    for directory in isolation_directories {
        if fs::create_dir(&directory).is_err() {
            return ProgramProbe::Warning("版本探测隔离目录无法创建");
        }
    }
    probe_program(product, &isolated_home, isolation_root)
}

fn probe_program(product: Product, isolated_home: &Path, isolation_root: &Path) -> ProgramProbe {
    let program = match resolve_client_program(product) {
        Ok(program) => program,
        Err(error) => return program_resolve_error_probe(error),
    };
    let mut command = Command::new(program.executable());
    command
        .args(program.prefix_args())
        .arg("--version")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    configure_isolated_product_environment(&mut command, product, isolated_home, isolation_root);
    run_version_command(command, VERSION_PROBE_TIMEOUT)
}

fn program_resolve_error_probe(error: ClientProgramResolveError) -> ProgramProbe {
    match error {
        ClientProgramResolveError::NotFound { .. } => ProgramProbe::Missing,
        ClientProgramResolveError::UnsupportedNpmShim { reason, .. } => {
            ProgramProbe::Warning(match reason {
                UnsupportedNpmShimReason::PackageEntryMissing => {
                    "探测发现 npm 启动器不受支持（标准包入口缺失）"
                }
                UnsupportedNpmShimReason::NodeExecutableMissing => {
                    "探测发现 npm 启动器不受支持（未找到原生 node.exe）"
                }
            })
        }
    }
}

fn configure_isolated_product_environment(
    command: &mut Command,
    product: Product,
    isolated_home: &Path,
    isolation_root: &Path,
) {
    let inherited_path = std::env::var_os("PATH");
    #[cfg(windows)]
    let inherited_windows = ["SystemRoot", "WINDIR", "ComSpec", "PATHEXT", "SystemDrive"]
        .map(|name| (name, std::env::var_os(name)));
    command.env_clear();
    if let Some(path) = inherited_path {
        command.env("PATH", path);
    }
    #[cfg(windows)]
    for (name, value) in inherited_windows {
        if let Some(value) = value {
            command.env(name, value);
        }
    }
    command
        .env("HOME", isolation_root.join("home"))
        .env("USERPROFILE", isolation_root.join("home"))
        .env("APPDATA", isolation_root.join("xdg-config"))
        .env("LOCALAPPDATA", isolation_root.join("xdg-data"))
        .env("XDG_CONFIG_HOME", isolation_root.join("xdg-config"))
        .env("XDG_DATA_HOME", isolation_root.join("xdg-data"))
        .env("XDG_STATE_HOME", isolation_root.join("xdg-state"))
        .env("XDG_CACHE_HOME", isolation_root.join("xdg-cache"))
        .env("TEMP", isolation_root)
        .env("TMP", isolation_root)
        .env("TMPDIR", isolation_root)
        .env("LANG", "C")
        .env("LC_ALL", "C");
    match product {
        Product::Claude => {
            command.env("CLAUDE_CONFIG_DIR", isolated_home);
        }
        Product::Codex => {
            command.env("CODEX_HOME", isolated_home);
        }
    }
}

fn run_version_command(mut command: Command, timeout: Duration) -> ProgramProbe {
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return ProgramProbe::Missing,
        Err(_) => return ProgramProbe::Warning("版本探测无法启动"),
    };
    let Some(stdout) = child.stdout.take() else {
        let _ = child.kill();
        let _ = child.wait();
        return ProgramProbe::Warning("版本探测结果无法读取");
    };
    let Some(stderr) = child.stderr.take() else {
        let _ = child.kill();
        let _ = child.wait();
        return ProgramProbe::Warning("版本探测结果无法读取");
    };
    let stdout_reader = spawn_bounded_probe_reader(stdout);
    let stderr_reader = spawn_bounded_probe_reader(stderr);
    let deadline = Instant::now() + timeout;

    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                if !status.success() {
                    return ProgramProbe::Warning("版本命令返回异常状态");
                }
                let Some(stdout) = receive_probe_bytes(stdout_reader, deadline) else {
                    return ProgramProbe::Warning("版本输出读取超时");
                };
                let Some(stderr) = receive_probe_bytes(stderr_reader, deadline) else {
                    return ProgramProbe::Warning("版本输出读取超时");
                };
                return safe_version(&stdout, &stderr)
                    .map(ProgramProbe::Found)
                    .unwrap_or(ProgramProbe::Warning("版本输出无法安全展示"));
            }
            Ok(None) if Instant::now() < deadline => {
                thread::sleep(Duration::from_millis(20));
            }
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return ProgramProbe::Warning("版本探测超时");
            }
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                return ProgramProbe::Warning("版本探测状态不可用");
            }
        }
    }
}

fn spawn_bounded_probe_reader<R>(reader: R) -> mpsc::Receiver<io::Result<Vec<u8>>>
where
    R: Read + Send + 'static,
{
    let (sender, receiver) = mpsc::sync_channel(1);
    thread::spawn(move || {
        let mut bytes = Vec::new();
        let result = reader
            .take((MAX_VERSION_OUTPUT_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .map(|_| bytes);
        let _ = sender.send(result);
    });
    receiver
}

fn receive_probe_bytes(
    receiver: mpsc::Receiver<io::Result<Vec<u8>>>,
    deadline: Instant,
) -> Option<Vec<u8>> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    receiver.recv_timeout(remaining).ok()?.ok()
}

fn safe_version(stdout: &[u8], stderr: &[u8]) -> Option<String> {
    let candidate = [stdout, stderr]
        .into_iter()
        .filter_map(|bytes| std::str::from_utf8(bytes).ok())
        .flat_map(str::lines)
        .map(str::trim)
        .find(|line| !line.is_empty())?;
    let lowered = candidate.to_ascii_lowercase();
    if candidate.len() > MAX_VERSION_OUTPUT_BYTES
        || !candidate
            .chars()
            .any(|character| character.is_ascii_digit())
        || [
            "sk-", "token", "secret", "password", "api_key", "api-key", "bearer",
        ]
        .iter()
        .any(|marker| lowered.contains(marker))
        || !candidate.chars().all(|character| {
            character.is_ascii_alphanumeric()
                || matches!(
                    character,
                    ' ' | '.' | ',' | '-' | '_' | '/' | '(' | ')' | '+'
                )
        })
    {
        return None;
    }
    Some(candidate.to_owned())
}

fn generated_at() -> String {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs());
    format!("unix:{seconds}")
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            desktop_get_state,
            desktop_setup,
            desktop_doctor,
            desktop_revoke
        ])
        .run(tauri::generate_context!())
        .expect("error while running SAIAI Desktop Preview");
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::fs;
    use std::process::Command;

    use saiai_core::{
        AppPaths, CodexSetupArtifacts, ConfigV2, CredentialRef, GatewayUrl, GenerationRef,
        ProductConfig, ProductSetupArtifacts, ProductSetupStatus, SetupIssue, SetupRequest,
        SetupState,
    };

    use super::*;

    fn status(
        state: SetupState,
        claude: ProductSetupState,
        codex: ProductSetupState,
    ) -> SetupStatus {
        let configured_product = [(Product::Claude, claude), (Product::Codex, codex)]
            .into_iter()
            .find(|(_, state)| *state != ProductSetupState::Unconfigured);
        SetupStatus {
            state,
            config: configured_product.map(|(product, _)| {
                ConfigV2::new(
                    GatewayUrl::parse("https://api.example.test").unwrap(),
                    product,
                    ProductConfig::new(
                        CredentialRef::new(format!("desktop-test-{product}")).unwrap(),
                        GenerationRef::new(format!("gen-desktop-test-{product}")).unwrap(),
                    ),
                )
            }),
            products: [(Product::Claude, claude), (Product::Codex, codex)]
                .into_iter()
                .map(|(product, product_state)| ProductSetupStatus {
                    product,
                    state: product_state,
                    home: (product_state != ProductSetupState::Unconfigured).then(|| {
                        std::path::PathBuf::from(format!("/v2/{}", product.directory_name()))
                    }),
                    credential_present: product_state == ProductSetupState::Ready,
                    issues: (product_state == ProductSetupState::Broken)
                        .then(|| SetupIssue {
                            code: SetupIssueCode::CredentialMissing,
                            message: format!("{product} test credential is missing"),
                        })
                        .into_iter()
                        .collect(),
                })
                .collect(),
            issues: if state == SetupState::Broken {
                vec![SetupIssue {
                    code: SetupIssueCode::CredentialMissing,
                    message: "configured product state is broken".to_owned(),
                }]
            } else {
                Vec::new()
            },
        }
    }

    #[test]
    fn maps_one_ready_product_without_treating_the_other_as_an_error() {
        let probe_calls = Cell::new(0);
        let state = state_from_status(
            &status(
                SetupState::Ready,
                ProductSetupState::Ready,
                ProductSetupState::Unconfigured,
            ),
            |_, _| {
                probe_calls.set(probe_calls.get() + 1);
                ProgramProbe::Found("1.2.3".to_owned())
            },
        );
        assert_eq!(state.schema_version, 2);
        assert_eq!(state.setup_state, "ready");
        assert_eq!(
            state.gateway.origin.as_deref(),
            Some("https://api.example.test/")
        );
        assert_eq!(state.clients[0].setup_state, "ready");
        assert_eq!(state.clients[1].setup_state, "unconfigured");
        assert!(state.clients[0].home.is_some());
        assert!(state.clients[1].home.is_none());
        assert_eq!(state.clients[0].runtime_state, "ready");
        assert_eq!(state.clients[1].runtime_state, "not_checked");
        assert_eq!(
            probe_calls.get(),
            1,
            "unconfigured Codex must not be probed"
        );
    }

    #[test]
    fn invalid_setup_url_clears_the_owned_secret_without_echoing_it() {
        let secret = "TEST_ONLY_INVALID_URL_CREDENTIAL";
        for (base_url, credential_overlap) in [
            ("file:///unsafe".to_owned(), false),
            (format!("https://api.example.test/{secret}"), true),
        ] {
            let mut input = SetupInput {
                product: "claude".to_owned(),
                base_url,
                api_key: secret.to_owned(),
            };
            let error = take_provision_request(&mut input).unwrap_err();
            assert!(input.api_key.is_empty());
            assert!(!error.contains(secret));
            if credential_overlap {
                assert!(error.contains("host label or path segment"));
            }
        }
    }

    #[test]
    fn invalid_setup_product_clears_the_owned_secret_without_echoing_it() {
        let secret = "TEST_ONLY_INVALID_PRODUCT_CREDENTIAL";
        let mut input = SetupInput {
            product: "all".to_owned(),
            base_url: "https://api.example.test".to_owned(),
            api_key: secret.to_owned(),
        };
        let error = take_provision_request(&mut input).unwrap_err();
        assert!(input.api_key.is_empty());
        assert_eq!(error, "Unknown setup product");
        assert!(!error.contains(secret));
    }

    #[test]
    fn setup_success_message_handles_an_absent_gateway_version() {
        assert_eq!(
            setup_success_message(Product::Claude, ""),
            "Claude V2 初始化完成；Gateway 已通过无计费 bootstrap 验证。"
        );
        assert_eq!(
            setup_success_message(Product::Codex, "gateway-2.0"),
            "Codex V2 初始化完成；Gateway gateway-2.0 已通过无计费 bootstrap 验证。"
        );
    }

    #[test]
    fn missing_and_timed_out_programs_are_safe_states() {
        let mut probes = [ProgramProbe::Missing].into_iter();
        let state = state_from_status(
            &status(
                SetupState::Broken,
                ProductSetupState::Broken,
                ProductSetupState::Unconfigured,
            ),
            |_, _| probes.next().unwrap(),
        );
        assert_eq!(state.clients[0].setup_state, "error");
        assert_eq!(state.clients[1].setup_state, "unconfigured");
        assert_eq!(state.clients[0].runtime_state, "missing");
        assert_eq!(state.clients[1].runtime_state, "not_checked");
        assert!(
            probes.next().is_none(),
            "unconfigured Codex must not be probed"
        );
        assert!(state.clients.iter().all(|client| client.version.is_none()));
    }

    #[test]
    fn version_output_rejects_secret_shaped_or_unbounded_text() {
        assert_eq!(
            safe_version(b"codex-cli 0.144.1\n", b""),
            Some("codex-cli 0.144.1".to_owned())
        );
        assert_eq!(safe_version(b"token sk-example-123\n", b""), None);
        assert_eq!(safe_version(b"client api-key 1.2.3\n", b""), None);
        assert_eq!(safe_version(&[b'1'; 129], b""), None);
    }

    #[test]
    fn program_resolution_distinguishes_missing_and_unsupported_npm_layouts() {
        assert_eq!(
            program_resolve_error_probe(ClientProgramResolveError::NotFound {
                product: Product::Claude,
            }),
            ProgramProbe::Missing
        );
        assert_eq!(
            program_resolve_error_probe(ClientProgramResolveError::UnsupportedNpmShim {
                product: Product::Codex,
                shim: std::path::PathBuf::from(r"C:\npm\codex.cmd"),
                reason: UnsupportedNpmShimReason::PackageEntryMissing,
            }),
            ProgramProbe::Warning("探测发现 npm 启动器不受支持（标准包入口缺失）")
        );
        assert_eq!(
            program_resolve_error_probe(ClientProgramResolveError::UnsupportedNpmShim {
                product: Product::Codex,
                shim: std::path::PathBuf::from(r"C:\npm\codex.cmd"),
                reason: UnsupportedNpmShimReason::NodeExecutableMissing,
            }),
            ProgramProbe::Warning("探测发现 npm 启动器不受支持（未找到原生 node.exe）")
        );
    }

    #[test]
    fn version_probe_environment_uses_only_the_v2_product_home() {
        let home = std::path::PathBuf::from("/v2/claude");
        let mut command = Command::new("claude");
        let isolation_root = std::path::PathBuf::from("/isolated-probe");
        configure_isolated_product_environment(
            &mut command,
            Product::Claude,
            &home,
            &isolation_root,
        );
        let env = command
            .get_envs()
            .map(|(name, value)| {
                (
                    name.to_string_lossy().into_owned(),
                    value.map(|value| value.to_string_lossy().into_owned()),
                )
            })
            .collect::<std::collections::BTreeMap<_, _>>();
        assert_eq!(
            env.get("CLAUDE_CONFIG_DIR")
                .and_then(|value| value.as_deref()),
            Some("/v2/claude")
        );
        assert!(!env.contains_key("CODEX_HOME"));
        assert!(!env.contains_key("SAIAI_HOME"));
        assert!(!env.contains_key("ANTHROPIC_API_KEY"));
        assert!(!env.contains_key("OPENAI_API_KEY"));
        assert_eq!(
            env.get("HOME").and_then(|value| value.as_deref()),
            Some("/isolated-probe/home")
        );
        assert_eq!(
            env.get("XDG_CONFIG_HOME")
                .and_then(|value| value.as_deref()),
            Some("/isolated-probe/xdg-config")
        );
    }

    #[cfg(unix)]
    #[test]
    fn version_probe_timeout_does_not_return_process_output() {
        let mut command = Command::new("sh");
        command
            .arg("-c")
            .arg("sleep 1; printf 'secret sk-never-show-123'")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        assert_eq!(
            run_version_command(command, Duration::from_millis(20)),
            ProgramProbe::Warning("版本探测超时")
        );
    }

    #[cfg(unix)]
    #[test]
    fn version_probe_does_not_wait_forever_for_descendants_holding_pipes() {
        let mut command = Command::new("sh");
        command
            .arg("-c")
            .arg("(sleep 1) & printf 'client 1.2.3\\n'")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        assert_eq!(
            run_version_command(command, Duration::from_millis(40)),
            ProgramProbe::Warning("版本输出读取超时")
        );
    }

    #[test]
    fn all_revoke_only_removes_injected_v2_paths() {
        let temp = tempfile::tempdir().unwrap();
        let paths = AppPaths::from_app_dirs(
            temp.path().join("config/saiai"),
            temp.path().join("data/saiai"),
            temp.path().join("state/saiai"),
        )
        .unwrap();
        for root in [paths.config_dir(), paths.data_dir(), paths.state_dir()] {
            fs::create_dir_all(root).unwrap();
            fs::write(root.join("owned"), b"v2").unwrap();
        }
        let unmanaged = temp.path().join("unmanaged/sentinel");
        fs::create_dir_all(unmanaged.parent().unwrap()).unwrap();
        fs::write(&unmanaged, b"outside-v2").unwrap();

        let result = desktop_revoke_with_core(&SaiaiCore::new(paths.clone()), "all").unwrap();
        assert!(result.accepted);
        assert_eq!(result.removed_paths.len(), 3);
        assert!(!paths.config_dir().exists());
        assert!(!paths.data_dir().exists());
        assert!(!paths.state_dir().exists());
        assert_eq!(fs::read(&unmanaged).unwrap(), b"outside-v2");
    }

    #[test]
    fn product_revoke_keeps_an_independently_configured_other_product() {
        let temp = tempfile::tempdir().unwrap();
        let paths = AppPaths::from_app_dirs(
            temp.path().join("config/saiai"),
            temp.path().join("data/saiai"),
            temp.path().join("state/saiai"),
        )
        .unwrap();
        let core = SaiaiCore::new(paths);
        core.setup_product_with_artifacts(
            SetupRequest::new("https://api.example.test", "TEST_ONLY_CODEX_CREDENTIAL").unwrap(),
            ProductSetupArtifacts::Codex(
                CodexSetupArtifacts::new("model = \"gpt-test\"\nmodel_provider = \"saiai\"\n")
                    .unwrap(),
            ),
        )
        .unwrap();
        let codex_home = core.client_home(Product::Codex).unwrap();
        let codex_config = codex_home.join("config.toml");
        let codex_config_before = fs::read(&codex_config).unwrap();
        let shared_config = core.paths().config_file();
        let shared_config_before = fs::read(&shared_config).unwrap();

        let result = desktop_revoke_with_core(&core, "claude").unwrap();
        assert_eq!(result.setup_state, "ready");
        assert_eq!(fs::read(&codex_config).unwrap(), codex_config_before);
        assert_eq!(fs::read(&shared_config).unwrap(), shared_config_before);
        let status = core.setup_status().unwrap();
        assert_eq!(status.state, SetupState::Ready);
        assert_eq!(
            status
                .products
                .iter()
                .find(|product| product.product == Product::Claude)
                .unwrap()
                .state,
            ProductSetupState::Unconfigured
        );
        assert_eq!(
            status
                .products
                .iter()
                .find(|product| product.product == Product::Codex)
                .unwrap()
                .state,
            ProductSetupState::Ready
        );
    }

    #[test]
    fn doctor_uses_core_issues_without_secret_material() {
        let temp = tempfile::tempdir().unwrap();
        let core = SaiaiCore::new(
            AppPaths::from_app_dirs(
                temp.path().join("config/saiai"),
                temp.path().join("data/saiai"),
                temp.path().join("state/saiai"),
            )
            .unwrap(),
        );
        let report = doctor_report_with(&core, |_, _| ProgramProbe::Missing).unwrap();
        let serialized = serde_json::to_string(&report).unwrap();
        assert!(!serialized.contains("uninitialized"));
        assert!(!serialized.contains(".claude"));
        assert!(!serialized.contains(".codex"));
        assert!(!serialized.contains("sk-"));
        assert!(report.checks.iter().any(|check| {
            check.id == "claude-home"
                && check.level == "pending"
                && check.summary.contains("不是 V2 状态错误")
        }));
        assert!(report.checks.iter().any(|check| {
            check.id == "codex-home"
                && check.level == "pending"
                && check.summary.contains("不是 V2 状态错误")
        }));
        assert!(!report.checks.iter().any(|check| check.level == "error"));
    }

    #[cfg(unix)]
    #[test]
    fn doctor_reports_insecure_v2_permissions_as_an_error() {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir().unwrap();
        let paths = AppPaths::from_app_dirs(
            temp.path().join("config/saiai"),
            temp.path().join("data/saiai"),
            temp.path().join("state/saiai"),
        )
        .unwrap();
        fs::create_dir_all(paths.config_dir()).unwrap();
        fs::set_permissions(paths.config_dir(), fs::Permissions::from_mode(0o755)).unwrap();
        let report =
            doctor_report_with(&SaiaiCore::new(paths), |_, _| ProgramProbe::Missing).unwrap();
        assert!(
            report
                .checks
                .iter()
                .any(|check| check.id == "managed-permissions" && check.level == "error")
        );
        assert!(
            report.checks.iter().any(|check| {
                check.id.contains("insecure-permissions") && check.level == "error"
            })
        );
    }
}
