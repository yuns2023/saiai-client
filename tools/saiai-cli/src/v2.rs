use crate::claude_proxy;
use crate::{V2ClientCommand, V2SetupArgs};
use anyhow::{Context, Result, bail};
use saiai_core::{
    CLAUDE_CA_CERT_FILENAME, CLAUDE_CA_KEY_FILENAME, CLAUDE_SETTINGS_FILENAME,
    CLAUDE_STATE_FILENAME, CLAUDE_STREAM_IDLE_TIMEOUT_ENV, CLAUDE_STREAM_IDLE_TIMEOUT_VALUE,
    CODEX_CONFIG_FILENAME, GatewayUrl, GenerationLease, Product, ProductSetupState,
    ProvisionRequest, ResolvedClientProgram, RevokeTarget, SaiaiCore, SecretString, SetupState,
    resolve_client_program,
};
use std::env;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::{self, IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command as ProcessCommand, ExitStatus, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};
use tokio::sync::oneshot;
use zeroize::{Zeroize, Zeroizing};

const MAX_API_KEY_BYTES: usize = 16 * 1024;
const CLIENT_PROBE_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_VERSION_TEXT_BYTES: usize = 128;
const DEFAULT_NO_PROXY: &str = "localhost,127.0.0.1,::1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,169.254.0.0/16,fc00::/7,fe80::/10,.local";

struct ProductContext {
    base_url: GatewayUrl,
    credential: SecretString,
    home: PathBuf,
    _lease: GenerationLease,
}

pub(super) fn run_setup(args: V2SetupArgs) -> Result<()> {
    let core = SaiaiCore::discover().context("failed to resolve V2 application directories")?;
    let product = match args.product {
        Some(product) => product,
        None if interactive_terminal() => prompt_product()?,
        None => bail!(
            "a non-interactive setup must select a product; run `saiai setup claude` or `saiai setup codex`"
        ),
    };
    provision_product(&core, product, args.base_url, args.api_key_stdin)
}

fn provision_product(
    core: &SaiaiCore,
    product: Product,
    requested_base_url: Option<String>,
    api_key_stdin: bool,
) -> Result<()> {
    let status = core
        .setup_status()
        .context("failed to inspect existing V2 setup state")?;
    if status.state == SetupState::Broken && status.config.is_none() {
        bail!(
            "existing V2 state is invalid and is not migrated; run `saiai revoke --all`, then configure {} again",
            product_name(product)
        );
    }
    if !api_key_stdin && !interactive_terminal() {
        bail!(
            "non-interactive {} setup cannot prompt for an API key; pass `--api-key-stdin` (and `--base-url` for the first product setup)",
            product_name(product)
        );
    }
    let base_url = match requested_base_url {
        Some(base_url) => GatewayUrl::parse(&base_url).context("invalid SAIAI gateway URL")?,
        None => match status.config.as_ref() {
            Some(config) => config.base_url().clone(),
            None if api_key_stdin => {
                bail!("`--base-url` is required for the first non-interactive product setup")
            }
            None if !interactive_terminal() => bail!(
                "the first {} setup needs an interactive terminal for the Gateway URL, or pass `--base-url`",
                product_name(product)
            ),
            None => GatewayUrl::parse(&prompt_line("SAIAI Gateway URL: ")?)
                .context("invalid SAIAI gateway URL")?,
        },
    };
    reject_shared_gateway_mismatch(&status, product, &base_url)?;
    let api_key = read_api_key(product, api_key_stdin)?;
    let request =
        ProvisionRequest::from_validated(base_url, api_key).context("invalid SAIAI gateway URL")?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("failed to start the V2 setup runtime")?;
    let report = runtime
        .block_on(core.provision(product, request))
        .context("failed to provision SAIAI V2")?;
    let status = report.setup;
    let product_status = status
        .products
        .iter()
        .find(|candidate| candidate.product == product)
        .context("the provision report omitted the selected product")?;
    if product_status.state != ProductSetupState::Ready {
        bail!(
            "{} setup did not reach the ready state",
            product_name(product)
        );
    }
    let product_home = product_status
        .home
        .as_deref()
        .context("the provision report omitted the selected product home")?;

    println!("{} V2 setup is ready.", product_name(product));
    println!(
        "Gateway: {} (server {})",
        status
            .config
            .as_ref()
            .expect("ready setup has config")
            .base_url(),
        display_gateway_version(&report.bootstrap.gateway_version)
    );
    println!("Config: {}", core.paths().config_file().display());
    println!("{} home: {}", product_name(product), product_home.display());
    print_client_probe(product);
    println!();
    println!("Launch with `saiai {}`.", product.directory_name());
    Ok(())
}

pub(super) fn run_codex(command: V2ClientCommand) -> Result<()> {
    if command == V2ClientCommand::Revoke {
        return revoke_product(Product::Codex);
    }
    let V2ClientCommand::Launch(arguments) = command else {
        unreachable!();
    };

    // Demand-driven setup must commit before client discovery so a missing
    // optional executable is reported only after this product is initialized.
    let context = load_product_with_initialization(Product::Codex, &[CODEX_CONFIG_FILENAME])?;
    let program = resolve_product_client(Product::Codex)?;
    let mut child = ProcessCommand::new(program.executable());
    child.args(program.prefix_args()).args(arguments);
    remove_env_keys(&mut child, codex_conflicting_env());
    child.env("CODEX_HOME", &context.home);
    child.env("SAIAI_CODEX_API_KEY", context.credential.expose_secret());
    let mut child = child.spawn().with_context(|| {
        format!(
            "failed to start Codex through {}",
            program.executable().display()
        )
    })?;
    let status = match child.wait() {
        Ok(status) => status,
        Err(error) => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(error).context("failed while waiting for Codex");
        }
    };
    drop(context);
    finish_with_child_status("Codex", status)
}

pub(super) fn run_claude(command: V2ClientCommand) -> Result<()> {
    if command == V2ClientCommand::Revoke {
        return revoke_product(Product::Claude);
    }
    let V2ClientCommand::Launch(arguments) = command else {
        unreachable!();
    };

    // Keep the same initialization-before-discovery contract as Codex.
    let context = load_product_with_initialization(
        Product::Claude,
        &[
            CLAUDE_SETTINGS_FILENAME,
            CLAUDE_STATE_FILENAME,
            CLAUDE_CA_CERT_FILENAME,
            CLAUDE_CA_KEY_FILENAME,
        ],
    )?;
    let program = resolve_product_client(Product::Claude)?;
    let cert_path = context.home.join(CLAUDE_CA_CERT_FILENAME);
    let key_path = context.home.join(CLAUDE_CA_KEY_FILENAME);
    let cert_pem = fs::read_to_string(&cert_path)
        .with_context(|| format!("failed to read {}", cert_path.display()))?;
    let key_pem = Zeroizing::new(
        fs::read_to_string(&key_path)
            .with_context(|| format!("failed to read {}", key_path.display()))?,
    );
    claude_proxy::validate_runtime_tls_config(&cert_pem, key_pem.as_str())
        .context("the V2 Claude installation CA is invalid; run `saiai setup claude` again")?;

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("failed to start the V2 Claude runtime")?;
    let status = runtime.block_on(run_claude_session(
        program, context, arguments, cert_path, cert_pem, key_pem,
    ))?;
    finish_with_child_status("Claude", status)
}

pub(super) fn run_revoke_all() -> Result<()> {
    let core = SaiaiCore::discover().context("failed to resolve V2 application directories")?;
    let report = core
        .revoke(RevokeTarget::All)
        .context("failed to remove V2 state")?;
    if report.removed_paths.is_empty() {
        println!("SAIAI V2 was already revoked.");
    } else {
        println!("Removed all SAIAI V2 state:");
        for path in report.removed_paths {
            println!("  {}", path.display());
        }
    }
    println!("Legacy SAIAI, Claude, and Codex homes were not inspected or changed.");
    Ok(())
}

pub(super) fn run_doctor() -> Result<()> {
    let core = SaiaiCore::discover().context("failed to resolve V2 application directories")?;
    let status = core
        .setup_status()
        .context("failed to inspect V2 setup state")?;
    let mut errors = Vec::new();
    let mut warnings = Vec::new();

    println!("SAIAI V2 doctor (offline)");
    println!("config: {}", core.paths().config_file().display());
    println!("state: {:?}", status.state);
    if let Some(config) = status.config.as_ref() {
        println!("Gateway: {}", config.base_url());
    }

    match status.state {
        SetupState::Uninitialized => errors
            .push("V2 has no configured product; run `saiai claude` or `saiai codex`".to_string()),
        SetupState::Broken => errors.push("V2 setup contains invalid managed state".to_string()),
        SetupState::Ready => println!("[ok] schema-2 config"),
    }
    for issue in &status.issues {
        errors.push(issue.message.clone());
    }

    for product in Product::ALL {
        let Some(product_status) = status
            .products
            .iter()
            .find(|entry| entry.product == product)
        else {
            errors.push(format!("{} status is missing", product_name(product)));
            continue;
        };
        match product_status.state {
            ProductSetupState::Unconfigured => {
                println!(
                    "[info] {}: unconfigured (run `saiai {}` when needed)",
                    product_name(product),
                    product.directory_name()
                );
                continue;
            }
            ProductSetupState::Broken => {
                if product_status.issues.is_empty() {
                    errors.push(format!(
                        "{} V2 state is invalid; run `saiai setup {}` to replace it",
                        product_name(product),
                        product.directory_name()
                    ));
                }
                continue;
            }
            ProductSetupState::Ready => {}
        }
        if !product_status.credential_present {
            errors.push(format!(
                "{} credential is missing or invalid",
                product_name(product)
            ));
            continue;
        }
        let Some(home) = product_status.home.as_ref() else {
            errors.push(format!("{} V2 home is missing", product_name(product)));
            continue;
        };
        let required: &[&str] = match product {
            Product::Claude => &[
                CLAUDE_SETTINGS_FILENAME,
                CLAUDE_STATE_FILENAME,
                CLAUDE_CA_CERT_FILENAME,
                CLAUDE_CA_KEY_FILENAME,
            ],
            Product::Codex => &[CODEX_CONFIG_FILENAME],
        };
        for name in required {
            let path = home.join(name);
            if !path.is_file() {
                errors.push(format!("required V2 file is missing: {}", path.display()));
            }
        }
        if required.iter().all(|name| home.join(name).is_file()) {
            println!("[ok] {} home: {}", product_name(product), home.display());
        }
        match probe_client(product) {
            Ok(version) => println!("[ok] {}: {version}", product.directory_name()),
            Err(error) => warnings.push(error.to_string()),
        }
    }

    check_private_permissions(&core, &mut errors, &mut warnings);

    for warning in &warnings {
        println!("[warning] {warning}");
    }
    for error in &errors {
        println!("[error] {error}");
    }
    println!(
        "doctor summary: {} error(s), {} warning(s)",
        errors.len(),
        warnings.len()
    );
    if !errors.is_empty() {
        bail!("SAIAI V2 doctor found {} error(s)", errors.len());
    }
    Ok(())
}

pub(super) fn run_ui() -> Result<()> {
    let current = env::current_exe().context("failed to locate the SAIAI executable")?;
    for candidate in desktop_binary_candidates(&current) {
        if candidate.is_file() {
            ProcessCommand::new(&candidate)
                .spawn()
                .with_context(|| format!("failed to start {}", candidate.display()))?;
            return Ok(());
        }
    }

    #[cfg(target_os = "macos")]
    {
        if ProcessCommand::new("open")
            .args(["-a", "SAIAI"])
            .status()
            .is_ok_and(|status| status.success())
        {
            return Ok(());
        }
    }

    ProcessCommand::new(desktop_binary_name())
        .spawn()
        .context(
            "failed to start `saiai-desktop`; install the Preview desktop app or place it next to `saiai`",
        )?;
    Ok(())
}

fn desktop_binary_candidates(current_exe: &Path) -> Vec<PathBuf> {
    let mut candidates = vec![current_exe.with_file_name(desktop_binary_name())];

    #[cfg(target_os = "linux")]
    {
        candidates.push(PathBuf::from("/usr/local/bin/saiai-desktop"));
        candidates.push(PathBuf::from("/usr/bin/saiai-desktop"));
    }

    #[cfg(target_os = "macos")]
    {
        candidates.push(PathBuf::from(
            "/Applications/SAIAI.app/Contents/MacOS/saiai-desktop",
        ));
        if let Some(home) = env::var_os("HOME") {
            candidates.push(
                PathBuf::from(home).join("Applications/SAIAI.app/Contents/MacOS/saiai-desktop"),
            );
        }
    }

    #[cfg(target_os = "windows")]
    {
        if let Some(local) = env::var_os("LOCALAPPDATA") {
            let local = PathBuf::from(local);
            candidates.push(local.join("Programs/SAIAI/saiai-desktop.exe"));
            candidates.push(local.join("SAIAI/saiai-desktop.exe"));
        }
        if let Some(program_files) = env::var_os("ProgramFiles") {
            candidates.push(PathBuf::from(program_files).join("SAIAI/saiai-desktop.exe"));
        }
    }

    candidates
}

async fn run_claude_session(
    program: ResolvedClientProgram,
    context: ProductContext,
    arguments: Vec<String>,
    cert_path: PathBuf,
    cert_pem: String,
    key_pem: Zeroizing<String>,
) -> Result<ExitStatus> {
    let runtime_config = claude_proxy::Config {
        listen: "127.0.0.1:0".to_string(),
        base_url: context.base_url.as_str().to_string(),
        api_key: context.credential.expose_secret().to_string(),
        verbose: false,
    }
    .with_runtime_ca(cert_pem, key_pem.as_str().to_owned())
    .quiet(true);
    drop(key_pem);
    let proxy = claude_proxy::bind(runtime_config)
        .await
        .context("failed to bind the ephemeral Claude proxy")?;
    let proxy_address = proxy.local_addr();
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let mut proxy_task = tokio::spawn(proxy.run_until(async move {
        let _ = shutdown_rx.await;
    }));

    let proxy_url = format!("http://{proxy_address}");
    let mut child = tokio::process::Command::new(program.executable());
    child.args(program.prefix_args()).args(arguments);
    remove_tokio_env_keys(&mut child, claude_conflicting_env());
    child.env("CLAUDE_CONFIG_DIR", &context.home);
    child.env(
        "CLAUDE_CODE_OAUTH_TOKEN",
        context.credential.expose_secret(),
    );
    child.env("HTTP_PROXY", &proxy_url);
    child.env("HTTPS_PROXY", &proxy_url);
    child.env("ALL_PROXY", &proxy_url);
    child.env("NO_PROXY", DEFAULT_NO_PROXY);
    child.env("NODE_EXTRA_CA_CERTS", cert_path);
    child.env("CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC", "1");
    child.env(
        CLAUDE_STREAM_IDLE_TIMEOUT_ENV,
        CLAUDE_STREAM_IDLE_TIMEOUT_VALUE,
    );
    child.env("ENABLE_PROMPT_CACHING_1H", "1");
    child.env("ENABLE_TOOL_SEARCH", "true");
    child.kill_on_drop(true);

    let mut child = match child.spawn() {
        Ok(child) => child,
        Err(error) => {
            let _ = shutdown_tx.send(());
            let _ = proxy_task.await;
            return Err(error).with_context(|| {
                format!(
                    "failed to start Claude through {}",
                    program.executable().display()
                )
            });
        }
    };
    let status = tokio::select! {
        result = child.wait() => match result {
            Ok(status) => status,
            Err(error) => {
                let _ = child.kill().await;
                let _ = child.wait().await;
                let _ = shutdown_tx.send(());
                let _ = proxy_task.await;
                return Err(error).context("failed while waiting for Claude");
            }
        },
        result = &mut proxy_task => {
            let _ = child.kill().await;
            let _ = child.wait().await;
            match result {
                Ok(Ok(())) => bail!("the ephemeral Claude proxy stopped unexpectedly"),
                Ok(Err(error)) => return Err(error).context("the ephemeral Claude proxy failed"),
                Err(error) => return Err(error).context("the ephemeral Claude proxy task failed"),
            }
        }
    };

    let _ = shutdown_tx.send(());
    proxy_task
        .await
        .context("the ephemeral Claude proxy task failed")??;
    Ok(status)
}

fn load_product_with_initialization(
    product: Product,
    required_files: &[&str],
) -> Result<ProductContext> {
    let core = SaiaiCore::discover().context("failed to resolve V2 application directories")?;
    let status = core.setup_status().context("failed to inspect V2 setup")?;
    let product_status = status
        .products
        .iter()
        .find(|entry| entry.product == product)
        .context("V2 product status is missing")?;
    match product_status.state {
        ProductSetupState::Unconfigured if interactive_terminal() => {
            eprintln!(
                "{} is not configured yet; starting its one-time V2 setup.",
                product_name(product)
            );
            provision_product(&core, product, None, false)?;
        }
        ProductSetupState::Unconfigured => bail!(
            "{} V2 is not configured and first launch cannot prompt without terminal standard input and standard error; run `saiai setup {} --base-url <url> --api-key-stdin`",
            product_name(product),
            product.directory_name()
        ),
        ProductSetupState::Broken if status.config.is_none() => bail!(
            "existing V2 state is invalid and is not migrated; run `saiai revoke --all`, then `saiai setup {}`",
            product.directory_name()
        ),
        ProductSetupState::Broken => bail!(
            "{} V2 state is invalid; run `saiai setup {}` to replace only that product, or inspect it with `saiai doctor`",
            product_name(product),
            product.directory_name()
        ),
        ProductSetupState::Ready => {}
    }

    load_product(&core, product, required_files)
}

fn load_product(
    core: &SaiaiCore,
    product: Product,
    required_files: &[&str],
) -> Result<ProductContext> {
    let committed = core.load_committed_product(product).with_context(|| {
        format!(
            "failed to load one committed {} V2 snapshot; run `saiai doctor`",
            product_name(product)
        )
    })?;
    let (_, base_url, home, credential, lease) = committed.into_parts();
    for filename in required_files {
        let path = home.join(filename);
        if !path.is_file() {
            bail!(
                "{} V2 state is incomplete (missing {}); run `saiai setup {}` again",
                product_name(product),
                path.display(),
                product.directory_name()
            );
        }
    }
    Ok(ProductContext {
        base_url,
        credential,
        home,
        _lease: lease,
    })
}

fn revoke_product(product: Product) -> Result<()> {
    let core = SaiaiCore::discover().context("failed to resolve V2 application directories")?;
    let report = core
        .revoke(RevokeTarget::Product(product))
        .with_context(|| format!("failed to revoke {} V2 state", product_name(product)))?;
    if report.removed_paths.is_empty() {
        println!("{} V2 state was already revoked.", product_name(product));
    } else {
        println!("Removed {} V2 state:", product_name(product));
        for path in report.removed_paths {
            println!("  {}", path.display());
        }
    }
    println!(
        "The normal {} configuration was not inspected or changed.",
        product_name(product)
    );
    Ok(())
}

fn check_private_permissions(
    core: &SaiaiCore,
    errors: &mut Vec<String>,
    warnings: &mut Vec<String>,
) {
    let audit = core.audit_private_permissions();
    if !audit.supported {
        warnings.push("private-permission verification is not available on this platform".into());
        return;
    }
    if audit.issues.is_empty() {
        println!(
            "[ok] private permissions: {} V2-owned path(s)",
            audit.checked_paths
        );
        return;
    }
    errors.extend(audit.issues.into_iter().map(|issue| {
        format!(
            "private permissions for {} are invalid: {}",
            issue.path.display(),
            issue.message
        )
    }));
}

fn read_api_key(product: Product, from_stdin: bool) -> Result<SecretString> {
    let mut value = if from_stdin {
        let mut bytes = Vec::new();
        if let Err(error) = io::stdin()
            .take((MAX_API_KEY_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
        {
            bytes.zeroize();
            return Err(error).context("failed to read the API key from standard input");
        }
        if bytes.len() > MAX_API_KEY_BYTES {
            bytes.zeroize();
            bail!("API key input is too large");
        }
        let mut value = match String::from_utf8(bytes) {
            Ok(value) => value,
            Err(error) => {
                let mut bytes = error.into_bytes();
                bytes.zeroize();
                bail!("API key input is not UTF-8");
            }
        };
        while value
            .as_bytes()
            .last()
            .is_some_and(|byte| matches!(byte, b'\r' | b'\n'))
        {
            value.truncate(value.len() - 1);
        }
        value
    } else {
        let config = rpassword::ConfigBuilder::new()
            .output_writer(io::stderr())
            .build();
        rpassword::prompt_password_with_config(
            format!("{} SAIAI API key: ", product_name(product)),
            config,
        )
        .context("failed to read the API key without terminal echo")?
    };
    if value.len() > MAX_API_KEY_BYTES {
        value.zeroize();
        bail!("API key input is too large");
    }
    SecretString::new(value).context("invalid SAIAI API key")
}

fn prompt_product() -> Result<Product> {
    let value = prompt_line("Product to configure (claude/codex): ")?;
    match value.trim().to_ascii_lowercase().as_str() {
        "claude" => Ok(Product::Claude),
        "codex" => Ok(Product::Codex),
        _ => bail!("product must be `claude` or `codex`"),
    }
}

fn interactive_terminal() -> bool {
    io::stdin().is_terminal() && io::stderr().is_terminal()
}

fn prompt_line(prompt: &str) -> Result<String> {
    eprint!("{prompt}");
    io::stderr().flush().context("failed to write prompt")?;
    let mut value = String::new();
    io::stdin()
        .read_line(&mut value)
        .context("failed to read interactive input")?;
    Ok(value.trim_end_matches(['\r', '\n']).to_string())
}

fn reject_shared_gateway_mismatch(
    status: &saiai_core::SetupStatus,
    product: Product,
    requested_base_url: &GatewayUrl,
) -> Result<()> {
    let Some(config) = status.config.as_ref() else {
        return Ok(());
    };
    let Some(other) = Product::ALL.into_iter().find(|candidate| {
        *candidate != product
            && config.product(*candidate).is_some()
            && config.base_url() != requested_base_url
    }) else {
        return Ok(());
    };
    bail!(
        "cannot configure {} because {} already uses a different shared Gateway; use the existing Gateway or revoke {} first",
        product_name(product),
        product_name(other),
        product_name(other)
    )
}

fn resolve_product_client(product: Product) -> Result<ResolvedClientProgram> {
    resolve_client_program(product).with_context(|| {
        format!(
            "could not resolve the {} client; install the official `{}` client on PATH (for npm installs, repair the standard package layout and native Node.js executable)",
            product_name(product),
            product.directory_name()
        )
    })
}

fn probe_client(product: Product) -> Result<String> {
    let program = resolve_product_client(product)?;
    probe_program_with_timeout(
        program.executable(),
        program.prefix_args(),
        CLIENT_PROBE_TIMEOUT,
    )
}

fn probe_program_with_timeout(
    executable: &Path,
    prefix_args: &[OsString],
    timeout: Duration,
) -> Result<String> {
    let isolated = tempfile::Builder::new()
        .prefix("saiai-version-probe-")
        .tempdir()
        .context("failed to create an isolated version-probe home")?;
    let home = isolated.path().join("home");
    let xdg_config = isolated.path().join("xdg-config");
    let xdg_data = isolated.path().join("xdg-data");
    let xdg_state = isolated.path().join("xdg-state");
    let xdg_cache = isolated.path().join("xdg-cache");
    for path in [&home, &xdg_config, &xdg_data, &xdg_state, &xdg_cache] {
        fs::create_dir(path).context("failed to prepare an isolated version-probe home")?;
    }

    let mut command = ProcessCommand::new(executable);
    command
        .args(prefix_args)
        .arg("--version")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    configure_isolated_probe_environment(
        &mut command,
        &home,
        &xdg_config,
        &xdg_data,
        &xdg_state,
        &xdg_cache,
        isolated.path(),
    );
    let mut child = command
        .spawn()
        .with_context(|| format!("failed to start {}", executable.display()))?;
    let stdout = child
        .stdout
        .take()
        .context("version probe stdout is unavailable")?;
    let stderr = child
        .stderr
        .take()
        .context("version probe stderr is unavailable")?;
    let stdout_reader = spawn_bounded_probe_reader(stdout);
    let stderr_reader = spawn_bounded_probe_reader(stderr);

    let deadline = Instant::now() + timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(10)),
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                bail!("{} --version timed out", executable.display());
            }
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(error).context("failed to wait for version probe");
            }
        }
    };
    let stdout = Zeroizing::new(receive_probe_bytes(stdout_reader, deadline)?);
    let stderr = Zeroizing::new(receive_probe_bytes(stderr_reader, deadline)?);
    if !status.success() {
        bail!("{} --version exited with {status}", executable.display());
    }
    safe_version_text(&stdout, &stderr)
}

fn spawn_bounded_probe_reader<R>(reader: R) -> mpsc::Receiver<io::Result<Vec<u8>>>
where
    R: Read + Send + 'static,
{
    let (sender, receiver) = mpsc::sync_channel(1);
    thread::spawn(move || {
        let mut bytes = Vec::new();
        let result = reader
            .take((MAX_VERSION_TEXT_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .map(|_| bytes);
        let _ = sender.send(result);
    });
    receiver
}

fn receive_probe_bytes(
    receiver: mpsc::Receiver<io::Result<Vec<u8>>>,
    deadline: Instant,
) -> Result<Vec<u8>> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    match receiver.recv_timeout(remaining) {
        Ok(result) => result.context("failed to read version output"),
        Err(mpsc::RecvTimeoutError::Timeout) => bail!("version output timed out"),
        Err(mpsc::RecvTimeoutError::Disconnected) => bail!("version output reader failed"),
    }
}

fn configure_isolated_probe_environment(
    command: &mut ProcessCommand,
    home: &Path,
    xdg_config: &Path,
    xdg_data: &Path,
    xdg_state: &Path,
    xdg_cache: &Path,
    temporary: &Path,
) {
    let inherited_path = env::var_os("PATH");
    #[cfg(windows)]
    let inherited_windows = ["SystemRoot", "WINDIR", "ComSpec", "PATHEXT", "SystemDrive"]
        .map(|name| (name, env::var_os(name)));

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
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env("APPDATA", xdg_config)
        .env("LOCALAPPDATA", xdg_data)
        .env("XDG_CONFIG_HOME", xdg_config)
        .env("XDG_DATA_HOME", xdg_data)
        .env("XDG_STATE_HOME", xdg_state)
        .env("XDG_CACHE_HOME", xdg_cache)
        .env("CLAUDE_CONFIG_DIR", home.join("claude"))
        .env("CODEX_HOME", home.join("codex"))
        .env("TEMP", temporary)
        .env("TMP", temporary)
        .env("TMPDIR", temporary)
        .env("LANG", "C")
        .env("LC_ALL", "C");
}

fn safe_version_text(stdout: &[u8], stderr: &[u8]) -> Result<String> {
    let candidate = [stdout, stderr]
        .into_iter()
        .flat_map(|bytes| bytes.split(|byte| *byte == b'\n'))
        .map(trim_ascii)
        .find(|line| !line.is_empty())
        .context("version output was empty")?;
    let lower = Zeroizing::new(candidate.to_ascii_lowercase());
    let forbidden = [
        b"sk-".as_slice(),
        b"token".as_slice(),
        b"secret".as_slice(),
        b"password".as_slice(),
        b"api_key".as_slice(),
        b"api-key".as_slice(),
        b"bearer".as_slice(),
    ];
    if candidate.len() > MAX_VERSION_TEXT_BYTES
        || !candidate.iter().all(|byte| (b' '..=b'~').contains(byte))
        || !candidate.iter().any(u8::is_ascii_digit)
        || forbidden
            .iter()
            .any(|needle| lower.windows(needle.len()).any(|window| window == *needle))
    {
        bail!("version output was rejected by the safe-output policy");
    }
    String::from_utf8(candidate.to_vec()).context("version output is not UTF-8")
}

fn trim_ascii(mut bytes: &[u8]) -> &[u8] {
    while bytes.first().is_some_and(u8::is_ascii_whitespace) {
        bytes = &bytes[1..];
    }
    while bytes.last().is_some_and(u8::is_ascii_whitespace) {
        bytes = &bytes[..bytes.len() - 1];
    }
    bytes
}

fn print_client_probe(product: Product) {
    let program = product.directory_name();
    match probe_client(product) {
        Ok(version) => println!("Detected {program}: {version}"),
        Err(error) => println!("[warning] Could not safely identify {program}: {error}"),
    }
}

fn remove_env_keys(command: &mut ProcessCommand, keys: &[&str]) {
    for key in keys {
        command.env_remove(key);
    }
}

fn remove_tokio_env_keys(command: &mut tokio::process::Command, keys: &[&str]) {
    for key in keys {
        command.env_remove(key);
    }
}

fn claude_conflicting_env() -> &'static [&'static str] {
    &[
        "CLAUDE_CONFIG_DIR",
        "CLAUDE_CODE_OAUTH_TOKEN",
        "ANTHROPIC_BASE_URL",
        "ANTHROPIC_AUTH_TOKEN",
        "ANTHROPIC_API_KEY",
        "CLAUDE_CODE_USE_BEDROCK",
        "CLAUDE_CODE_SKIP_BEDROCK_AUTH",
        "ANTHROPIC_BEDROCK_BASE_URL",
        "CLAUDE_CODE_USE_VERTEX",
        "CLAUDE_CODE_SKIP_VERTEX_AUTH",
        "ANTHROPIC_VERTEX_BASE_URL",
        "ANTHROPIC_VERTEX_PROJECT_ID",
        "CLOUD_ML_REGION",
        "CLAUDE_CODE_USE_FOUNDRY",
        "CLAUDE_CODE_SKIP_FOUNDRY_AUTH",
        "ANTHROPIC_FOUNDRY_BASE_URL",
        "ANTHROPIC_FOUNDRY_RESOURCE",
        "ANTHROPIC_FOUNDRY_API_KEY",
        "ANTHROPIC_MODEL",
        "ANTHROPIC_DEFAULT_OPUS_MODEL",
        "ANTHROPIC_DEFAULT_SONNET_MODEL",
        "ANTHROPIC_DEFAULT_HAIKU_MODEL",
        "ANTHROPIC_SMALL_FAST_MODEL",
        "CLAUDE_CODE_SUBAGENT_MODEL",
        "CLAUDE_CODE_EFFORT_LEVEL",
        "CLAUDE_CODE_ENTRYPOINT",
        "CLAUDE_CODE_ATTRIBUTION_HEADER",
        CLAUDE_STREAM_IDLE_TIMEOUT_ENV,
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "NO_PROXY",
        "NODE_EXTRA_CA_CERTS",
        "http_proxy",
        "https_proxy",
        "all_proxy",
        "no_proxy",
    ]
}

fn codex_conflicting_env() -> &'static [&'static str] {
    &[
        "CODEX_HOME",
        "SAIAI_CODEX_API_KEY",
        "OPENAI_API_KEY",
        "OPENAI_BASE_URL",
        "OPENAI_ORG_ID",
        "OPENAI_PROJECT_ID",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "NO_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
        "no_proxy",
    ]
}

fn finish_with_child_status(name: &str, status: ExitStatus) -> Result<()> {
    if status.success() {
        return Ok(());
    }
    let code = child_exit_code(&status);
    eprintln!("{name} exited with status {status}");
    std::process::exit(code);
}

fn child_exit_code(status: &ExitStatus) -> i32 {
    if let Some(code) = status.code() {
        return code.clamp(1, 255);
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(signal) = status.signal() {
            return (128 + signal).clamp(1, 255);
        }
    }
    1
}

fn product_name(product: Product) -> &'static str {
    match product {
        Product::Claude => "Claude",
        Product::Codex => "Codex",
    }
}

fn display_gateway_version(version: &str) -> &str {
    if version.trim().is_empty() {
        "unknown"
    } else {
        version
    }
}

fn desktop_binary_name() -> &'static OsStr {
    #[cfg(target_os = "windows")]
    {
        OsStr::new("saiai-desktop.exe")
    }
    #[cfg(not(target_os = "windows"))]
    {
        OsStr::new("saiai-desktop")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ui_search_includes_a_desktop_binary_next_to_the_cli() {
        let current = Path::new("/opt/saiai/bin/saiai");
        assert_eq!(
            desktop_binary_candidates(current).first(),
            Some(&current.with_file_name(desktop_binary_name()))
        );
    }

    #[test]
    fn child_environment_conflict_lists_cover_provider_and_proxy_routing() {
        for name in [
            "CLAUDE_CODE_USE_BEDROCK",
            "CLAUDE_CODE_SKIP_BEDROCK_AUTH",
            "ANTHROPIC_BEDROCK_BASE_URL",
            "CLAUDE_CODE_USE_VERTEX",
            "CLAUDE_CODE_SKIP_VERTEX_AUTH",
            "ANTHROPIC_VERTEX_BASE_URL",
            "ANTHROPIC_VERTEX_PROJECT_ID",
            "CLOUD_ML_REGION",
            "CLAUDE_CODE_USE_FOUNDRY",
            "CLAUDE_CODE_SKIP_FOUNDRY_AUTH",
            "ANTHROPIC_FOUNDRY_BASE_URL",
            "ANTHROPIC_FOUNDRY_RESOURCE",
            "ANTHROPIC_MODEL",
            "ANTHROPIC_DEFAULT_OPUS_MODEL",
            "ANTHROPIC_DEFAULT_SONNET_MODEL",
            "ANTHROPIC_DEFAULT_HAIKU_MODEL",
            "ANTHROPIC_SMALL_FAST_MODEL",
            "CLAUDE_CODE_SUBAGENT_MODEL",
            "CLAUDE_CODE_EFFORT_LEVEL",
            "CLAUDE_CODE_ENTRYPOINT",
            "CLAUDE_CODE_ATTRIBUTION_HEADER",
            CLAUDE_STREAM_IDLE_TIMEOUT_ENV,
        ] {
            assert!(
                claude_conflicting_env().contains(&name),
                "missing Claude conflict: {name}"
            );
        }
        for name in [
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "ALL_PROXY",
            "NO_PROXY",
            "http_proxy",
            "https_proxy",
            "all_proxy",
            "no_proxy",
        ] {
            assert!(
                codex_conflicting_env().contains(&name),
                "missing Codex conflict: {name}"
            );
        }
    }

    #[test]
    fn version_text_policy_only_accepts_short_printable_version_shapes() {
        assert_eq!(
            safe_version_text(b"claude-code 2.1.181\n", b"").unwrap(),
            "claude-code 2.1.181"
        );
        for unsafe_output in [
            b"sk-secret-123\n".as_slice(),
            b"Bearer abc123\n".as_slice(),
            b"tool without version\n".as_slice(),
            b"tool 1.2.3\x1b[31m\n".as_slice(),
        ] {
            assert!(safe_version_text(unsafe_output, b"").is_err());
        }
        assert!(safe_version_text(&[b'x'; MAX_VERSION_TEXT_BYTES + 1], b"").is_err());
    }

    #[test]
    fn version_probe_environment_is_allowlist_based_and_isolated() {
        let home = PathBuf::from("isolated-probe-home");
        let mut command = ProcessCommand::new("client");
        command.env("SAIAI_TEST_SECRET", "sk-never-inherit");
        configure_isolated_probe_environment(
            &mut command,
            &home,
            Path::new("isolated-probe-config"),
            Path::new("isolated-probe-data"),
            Path::new("isolated-probe-state"),
            Path::new("isolated-probe-cache"),
            Path::new("isolated-probe-tmp"),
        );
        let configured = command
            .get_envs()
            .map(|(name, value)| {
                (
                    name.to_string_lossy().into_owned(),
                    value.map(|value| value.to_string_lossy().into_owned()),
                )
            })
            .collect::<std::collections::BTreeMap<_, _>>();
        assert!(!configured.contains_key("SAIAI_TEST_SECRET"));
        let expected_home = home.to_string_lossy().into_owned();
        let expected_codex_home = home.join("codex").to_string_lossy().into_owned();
        let expected_claude_home = home.join("claude").to_string_lossy().into_owned();
        assert_eq!(
            configured.get("HOME").and_then(|value| value.as_deref()),
            Some(expected_home.as_str())
        );
        assert_eq!(
            configured
                .get("CODEX_HOME")
                .and_then(|value| value.as_deref()),
            Some(expected_codex_home.as_str())
        );
        assert_eq!(
            configured
                .get("CLAUDE_CONFIG_DIR")
                .and_then(|value| value.as_deref()),
            Some(expected_claude_home.as_str())
        );
    }

    #[cfg(unix)]
    #[test]
    fn version_probe_places_fixed_package_entry_before_version_argument() {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir().unwrap();
        let client = temp.path().join("node with spaces");
        fs::write(
            &client,
            "#!/bin/sh\n[ \"$#\" = 2 ] || exit 70\n[ \"$1\" = '/fixed/package entry.js' ] || exit 71\n[ \"$2\" = '--version' ] || exit 72\nprintf 'client 1.2.3\\n'\n",
        )
        .unwrap();
        fs::set_permissions(&client, fs::Permissions::from_mode(0o700)).unwrap();

        let version = probe_program_with_timeout(
            &client,
            &[OsString::from("/fixed/package entry.js")],
            Duration::from_secs(1),
        )
        .unwrap();
        assert_eq!(version, "client 1.2.3");
    }

    #[cfg(unix)]
    #[test]
    fn version_probe_kills_a_hung_client_within_its_deadline() {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir().unwrap();
        let client = temp.path().join("hung-client");
        fs::write(&client, "#!/bin/sh\nwhile :; do :; done\n").unwrap();
        fs::set_permissions(&client, fs::Permissions::from_mode(0o700)).unwrap();
        let started = Instant::now();
        assert!(probe_program_with_timeout(&client, &[], Duration::from_millis(40)).is_err());
        assert!(started.elapsed() < Duration::from_secs(1));
    }
}
