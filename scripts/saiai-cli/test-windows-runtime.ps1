[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$BinaryPath
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Assert-Saiai {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw $Message }
}

function Invoke-SaiaiProcess {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [bool]$CaptureOutput = $true,
        [int]$TimeoutMilliseconds = 10000
    )

    $startInfo = [Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $Path
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $CaptureOutput
    $startInfo.RedirectStandardError = $CaptureOutput
    foreach ($argument in $Arguments) {
        $null = $startInfo.ArgumentList.Add($argument)
    }
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    try {
        $null = $process.Start()
        if ($CaptureOutput) {
            $stdout = $process.StandardOutput.ReadToEndAsync()
            $stderr = $process.StandardError.ReadToEndAsync()
        }
        if (-not $process.WaitForExit($TimeoutMilliseconds)) {
            $process.Kill($true)
            throw "SAIAI $($Arguments -join ' ') did not return within $TimeoutMilliseconds ms"
        }
        $output = if ($CaptureOutput) {
            $stdout.GetAwaiter().GetResult() + $stderr.GetAwaiter().GetResult()
        }
        else {
            ""
        }
        return [pscustomobject]@{
            ExitCode = $process.ExitCode
            Output = $output
        }
    }
    finally {
        $process.Dispose()
    }
}

$binary = (Resolve-Path -LiteralPath $BinaryPath).Path
$temporary = Join-Path ([IO.Path]::GetTempPath()) ("saiai-config-windows-runtime-" + [guid]::NewGuid().ToString("N"))
$claudeDir = Join-Path $temporary ".claude"
$settingsPath = Join-Path $claudeDir "settings.json"
$statePath = Join-Path $claudeDir ".claude.json"
$credentialsPath = Join-Path $claudeDir ".credentials.json"
$caPath = Join-Path $claudeDir "saiai-ca.crt"
$caKeyPath = Join-Path $claudeDir "saiai-ca.key"
$testKey = "TEST_ONLY_WINDOWS_RUNTIME_KEY"
$replacementKey = "TEST_ONLY_WINDOWS_REPLACEMENT_KEY"
$codexKey = "TEST_ONLY_WINDOWS_CODEX_PROXY_KEY"
$savedConfigDir = $env:CLAUDE_CONFIG_DIR
$savedSaiaiHome = $env:SAIAI_HOME
$savedCodexHome = $env:CODEX_HOME
$savedPath = $env:PATH
$savedDesktopBin = $env:SAIAI_DESKTOP_BIN
$savedChatgptTimezone = $env:SAIAI_CHATGPT_TIMEZONE
$savedDesktopCapture = $env:SAIAI_DESKTOP_CAPTURE

try {
    $null = New-Item -ItemType Directory -Path $claudeDir -Force
    [IO.File]::WriteAllText(
        $settingsPath,
        '{"permissions":{"allow":["Read"]},"env":{"KEEP_ME":"yes","ANTHROPIC_AUTH_TOKEN":"old","HTTP_PROXY":"http://127.0.0.1:19908"}}'
    )
    [IO.File]::WriteAllText($statePath, '{"oauthAccount":{"email":"old"},"userID":"kept"}')
    [IO.File]::WriteAllText($credentialsPath, '{"oauth":"old"}')
    [IO.File]::WriteAllText($caPath, 'old ca')
    $env:CLAUDE_CONFIG_DIR = $claudeDir
    $env:SAIAI_HOME = Join-Path $temporary ".saiai"

    # Initialization starts the detached proxy itself. Do not attach that
    # worker to a PowerShell output-capture pipeline.
    $initialization = Invoke-SaiaiProcess -Path $binary -Arguments @("init", "https://gateway.example.test", $testKey) -CaptureOutput $false -TimeoutMilliseconds 30000
    Assert-Saiai ($initialization.ExitCode -eq 0) "SAIAI config command failed"

    $saiaiConfig = Get-Content -LiteralPath (Join-Path $env:SAIAI_HOME "config.json") -Raw | ConvertFrom-Json
    $proxyUrl = "http://$([string]$saiaiConfig.listen)"

    $settings = Get-Content -LiteralPath $settingsPath -Raw | ConvertFrom-Json
    Assert-Saiai ($null -eq $settings.env.PSObject.Properties["ANTHROPIC_BASE_URL"]) "Direct gateway override remains"
    Assert-Saiai ([string]$settings.env.CLAUDE_CODE_OAUTH_TOKEN -ceq $testKey) "API key differs"
    Assert-Saiai ([string]$settings.env.CLAUDE_STREAM_IDLE_TIMEOUT_MS -ceq "600000") "Timeout differs"
    Assert-Saiai ([string]$settings.env.KEEP_ME -ceq "yes") "Unrelated env was lost"
    Assert-Saiai ($null -eq $settings.env.PSObject.Properties["ANTHROPIC_AUTH_TOKEN"]) "Conflicting auth token remains"
    Assert-Saiai ([string]$settings.env.http_proxy -ceq $proxyUrl) "Local proxy differs"
    Assert-Saiai ([string]$settings.env.NODE_EXTRA_CA_CERTS -ceq $caPath) "CA path differs"
    Assert-Saiai (@($settings.permissions.allow) -contains "Read") "Unrelated settings were lost"

    $state = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
    Assert-Saiai ($null -eq $state.PSObject.Properties["oauthAccount"]) "oauthAccount remains"
    Assert-Saiai ([string]$state.userID -ceq "kept") "Machine identity was lost"
    Assert-Saiai (-not (Test-Path -LiteralPath $credentialsPath)) "OAuth credentials remain"
    Assert-Saiai (Test-Path -LiteralPath $caPath -PathType Leaf) "Installation CA was not generated"
    Assert-Saiai (Test-Path -LiteralPath $caKeyPath -PathType Leaf) "Installation CA key was not generated"
    $initialStatus = Invoke-SaiaiProcess -Path $binary -Arguments @("status")
    Assert-Saiai ($initialStatus.ExitCode -eq 0) "SAIAI status failed after initialization: $($initialStatus.Output)"
    Assert-Saiai ($initialStatus.Output.Contains("service active: yes")) "Claude initialization did not start the managed proxy: $($initialStatus.Output)"

    $caHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $caPath).Hash
    $caKeyHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $caKeyPath).Hash
    $repeatInitialization = Invoke-SaiaiProcess -Path $binary -Arguments @("init", "https://replacement.example.test", $replacementKey) -CaptureOutput $false -TimeoutMilliseconds 30000
    Assert-Saiai ($repeatInitialization.ExitCode -eq 0) "Repeated SAIAI config failed"
    Assert-Saiai ((Get-FileHash -Algorithm SHA256 -LiteralPath $caPath).Hash -ceq $caHash) "Repeated setup replaced a valid CA"
    Assert-Saiai ((Get-FileHash -Algorithm SHA256 -LiteralPath $caKeyPath).Hash -ceq $caKeyHash) "Repeated setup replaced a valid CA key"
    $repeatedSettings = Get-Content -LiteralPath $settingsPath -Raw | ConvertFrom-Json
    Assert-Saiai ([string]$repeatedSettings.env.CLAUDE_CODE_OAUTH_TOKEN -ceq $replacementKey) "Repeated setup did not replace the API key"
    $saiaiConfig = Get-Content -LiteralPath (Join-Path $env:SAIAI_HOME "config.json") -Raw | ConvertFrom-Json
    Assert-Saiai ([string]$saiaiConfig.base_url -ceq "https://replacement.example.test") "Repeated setup did not replace the Gateway"
    Assert-Saiai ([string]$saiaiConfig.api_key -ceq $replacementKey) "Repeated setup config Key differs"

    $env:CODEX_HOME = Join-Path $temporary ".codex"
    $null = New-Item -ItemType Directory -Path $env:CODEX_HOME -Force
    [IO.File]::WriteAllText(
        (Join-Path $env:CODEX_HOME ".env"),
        "USER_SETTING=keep`nHTTP_PROXY=http://127.0.0.1:19908`n"
    )
    $codexInitialization = Invoke-SaiaiProcess -Path $binary -Arguments @("init-codex", "https://codex.example.test/v1", $codexKey) -CaptureOutput $false -TimeoutMilliseconds 30000
    Assert-Saiai ($codexInitialization.ExitCode -eq 0) "SAIAI Codex initialization failed"
    $codexProxyConfig = Get-Content -LiteralPath (Join-Path $env:SAIAI_HOME "config.json") -Raw | ConvertFrom-Json
    Assert-Saiai ([string]$codexProxyConfig.base_url -ceq "https://codex.example.test") "Codex initialization did not normalize the local-proxy Gateway root"
    Assert-Saiai ([string]$codexProxyConfig.api_key -ceq $codexKey) "Codex initialization did not update the local-proxy Key"
    Assert-Saiai ((Get-FileHash -Algorithm SHA256 -LiteralPath $caPath).Hash -ceq $caHash) "Codex initialization replaced the existing CA"
    Assert-Saiai ((Get-FileHash -Algorithm SHA256 -LiteralPath $caKeyPath).Hash -ceq $caKeyHash) "Codex initialization replaced the existing CA key"
    Assert-Saiai (Test-Path -LiteralPath (Join-Path $env:CODEX_HOME "config.toml") -PathType Leaf) "Codex config was not created"
    Assert-Saiai (Test-Path -LiteralPath (Join-Path $env:CODEX_HOME "auth.json") -PathType Leaf) "Codex auth was not created"
    Assert-Saiai (Test-Path -LiteralPath (Join-Path $env:CODEX_HOME ".env") -PathType Leaf) "Codex environment was not created"
    $codexAuth = Get-Content -LiteralPath (Join-Path $env:CODEX_HOME "auth.json") -Raw | ConvertFrom-Json
    $codexConfig = Get-Content -LiteralPath (Join-Path $env:CODEX_HOME "config.toml") -Raw
    $codexEnv = Get-Content -LiteralPath (Join-Path $env:CODEX_HOME ".env") -Raw
    Assert-Saiai ([string]$codexAuth.auth_mode -ceq "chatgptAuthTokens") "Codex initialization did not create local-proxy OAuth auth"
    Assert-Saiai ($null -eq $codexAuth.OPENAI_API_KEY) "Codex API-key auth remains after OAuth initialization"
    Assert-Saiai ($codexConfig.Contains('model_provider = "openai"')) "Codex initialization did not select the built-in provider"
    Assert-Saiai (-not $codexConfig.Contains("[model_providers")) "Codex initialization retained a direct-provider compatibility route"
    Assert-Saiai ($codexEnv.Contains("USER_SETTING=keep")) "Codex initialization removed unrelated environment configuration"
    Assert-Saiai ($codexEnv.Contains("HTTP_PROXY=`"$proxyUrl`"")) "Codex initialization did not synchronize the local proxy port"
    $codexInitialStatus = Invoke-SaiaiProcess -Path $binary -Arguments @("status")
    Assert-Saiai ($codexInitialStatus.ExitCode -eq 0) "SAIAI status failed after Codex initialization: $($codexInitialStatus.Output)"
    Assert-Saiai ($codexInitialStatus.Output.Contains("service active: yes")) "Codex initialization did not refresh the managed proxy: $($codexInitialStatus.Output)"
    # `vscode` may start the detached proxy. Do not attach it to a PowerShell
    # output pipeline: the child can inherit the pipeline handle and keep
    # Out-String waiting for EOF after the command itself exits.
    $vscode = Invoke-SaiaiProcess -Path $binary -Arguments @("vscode") -CaptureOutput $false
    Assert-Saiai ($vscode.ExitCode -eq 0) "SAIAI Codex OAuth configuration refresh failed"
    $codexAuth = Get-Content -LiteralPath (Join-Path $env:CODEX_HOME "auth.json") -Raw | ConvertFrom-Json
    $codexConfig = Get-Content -LiteralPath (Join-Path $env:CODEX_HOME "config.toml") -Raw
    Assert-Saiai ([string]$codexAuth.auth_mode -ceq "chatgptAuthTokens") "Codex OAuth configuration is not retained after refresh"
    Assert-Saiai ($null -eq $codexAuth.OPENAI_API_KEY) "Codex API-key auth remains after OAuth refresh"
    Assert-Saiai (-not [string]::IsNullOrWhiteSpace([string]$codexAuth.tokens.access_token)) "Codex OAuth placeholder access token is missing"
    Assert-Saiai ([string]$codexAuth.tokens.refresh_token -ceq "") "Synthetic Codex auth must not contain a provider refresh token"

    $fakeDesktop = Join-Path $temporary "FakeOpenAIDesktop.exe"
    $fakeDesktopSourcePath = Join-Path $temporary "fake_openai_desktop.rs"
    $desktopCapture = Join-Path $temporary "desktop-capture.txt"
    $fakeDesktopSource = @'
use std::env;
use std::fs;

fn main() {
    let mut lines = env::args().skip(1).map(|arg| format!("ARG={arg}")).collect::<Vec<_>>();
    for key in [
        "HOME", "USERPROFILE", "CODEX_HOME", "CODEX_ELECTRON_USER_DATA_PATH",
        "CODEX_CA_CERTIFICATE", "SSL_CERT_FILE", "NODE_EXTRA_CA_CERTS",
        "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "TZ",
    ] {
        lines.push(format!("ENV={key}={}", env::var(key).unwrap_or_default()));
    }
    let capture = env::var("SAIAI_DESKTOP_CAPTURE").expect("capture path");
    fs::write(capture, lines.join("\n") + "\n").expect("write capture");
}
'@
    [IO.File]::WriteAllText($fakeDesktopSourcePath, $fakeDesktopSource)
    & rustc $fakeDesktopSourcePath -o $fakeDesktop
    Assert-Saiai ($LASTEXITCODE -eq 0) "Failed to build the Windows Desktop smoke fixture"
    $env:SAIAI_DESKTOP_BIN = $fakeDesktop
    $env:SAIAI_CHATGPT_TIMEZONE = "America/Los_Angeles"
    $env:SAIAI_DESKTOP_CAPTURE = $desktopCapture
    $desktop = Invoke-SaiaiProcess -Path $binary -Arguments @("desktop", "--", "--smoke-argument")
    Assert-Saiai ($desktop.ExitCode -eq 0) "SAIAI Windows Desktop launch failed: $($desktop.Output)"
    Assert-Saiai ($desktop.Output.Contains("Starting OpenAI Desktop through the SAIAI local proxy.")) "Windows Desktop launcher did not start the configured executable"
    $desktopRoot = Join-Path $env:SAIAI_HOME "desktop"
    $desktopCodex = Join-Path $desktopRoot "codex"
    $desktopUserData = Join-Path $desktopRoot "user-data"
    $desktopHome = Join-Path $desktopRoot "home"
    $desktopLines = @(Get-Content -LiteralPath $desktopCapture)
    Assert-Saiai ($desktopLines -contains "ARG=--user-data-dir=$desktopUserData") "Windows Desktop user-data argument differs"
    Assert-Saiai ($desktopLines -contains "ARG=--proxy-server=$proxyUrl") "Windows Desktop proxy argument differs"
    Assert-Saiai ($desktopLines -contains "ARG=--smoke-argument") "Windows Desktop argument was not preserved"
    Assert-Saiai ($desktopLines -contains "ENV=HOME=$desktopHome") "Windows Desktop HOME is not isolated"
    Assert-Saiai ($desktopLines -contains "ENV=USERPROFILE=$desktopHome") "Windows Desktop USERPROFILE is not isolated"
    Assert-Saiai ($desktopLines -contains "ENV=CODEX_HOME=$desktopCodex") "Windows Desktop CODEX_HOME is not isolated"
    Assert-Saiai ($desktopLines -contains "ENV=CODEX_ELECTRON_USER_DATA_PATH=$desktopUserData") "Windows Desktop Electron user data is not isolated"
    Assert-Saiai ($desktopLines -contains "ENV=CODEX_CA_CERTIFICATE=$caPath") "Windows Desktop Codex CA differs"
    Assert-Saiai ($desktopLines -contains "ENV=SSL_CERT_FILE=$caPath") "Windows Desktop SSL CA differs"
    Assert-Saiai ($desktopLines -contains "ENV=NODE_EXTRA_CA_CERTS=$caPath") "Windows Desktop Node CA differs"
    Assert-Saiai ($desktopLines -contains "ENV=HTTP_PROXY=$proxyUrl") "Windows Desktop HTTP proxy differs"
    Assert-Saiai ($desktopLines -contains "ENV=TZ=America/Los_Angeles") "Windows Desktop timezone differs"
    $desktopConfig = Get-Content -LiteralPath (Join-Path $desktopCodex "config.toml") -Raw
    Assert-Saiai ($desktopConfig.Contains("respect_system_proxy = false")) "Windows Desktop config can bypass the child proxy through WinHTTP DIRECT"

    # Rust's std::process::Command does not execute .cmd files directly. A
    # normal Windows npm installation exposes codex.cmd plus the JavaScript
    # launcher, so verify SAIAI resolves it through node.exe without cmd.exe.
    $codexShimDir = Join-Path $temporary "npm-bin"
    $codexEntrypointDir = Join-Path $codexShimDir "node_modules\@openai\codex\bin"
    $null = New-Item -ItemType Directory -Path $codexEntrypointDir -Force
    [IO.File]::WriteAllText((Join-Path $codexShimDir "codex.cmd"), "@echo off`r`nexit /b 99`r`n")
    [IO.File]::WriteAllText(
        (Join-Path $codexEntrypointDir "codex.js"),
        'console.log("SAIAI_WINDOWS_NPM_CODEX " + process.argv.slice(2).join(" "));'
    )
    $env:PATH = $codexShimDir + [IO.Path]::PathSeparator + $savedPath
    $npmCodex = Invoke-SaiaiProcess -Path $binary -Arguments @("codex", "--", "--version") -TimeoutMilliseconds 30000
    Assert-Saiai ($npmCodex.ExitCode -eq 0) "SAIAI failed to launch a Windows npm Codex install: $($npmCodex.Output)"
    Assert-Saiai ($npmCodex.Output.Contains("SAIAI_WINDOWS_NPM_CODEX")) "SAIAI did not execute the npm Codex JavaScript launcher"
    Assert-Saiai ($codexConfig.Contains("respect_system_proxy = false")) "Windows Codex IDE config can bypass the child proxy through WinHTTP DIRECT"
    Assert-Saiai ($npmCodex.Output.Contains("features.respect_system_proxy=false")) "SAIAI did not force Windows Codex to use the child proxy environment"
    Assert-Saiai ($npmCodex.Output.Contains("otel.metrics_exporter=")) "SAIAI did not disable the unreachable Statsig OTEL endpoint"
    Assert-Saiai ($npmCodex.Output.Contains("features.apps=false")) "SAIAI did not disable the unsupported hosted Apps MCP control plane"
    Assert-Saiai ($npmCodex.Output.Contains("--version")) "SAIAI did not preserve Codex arguments"
    $env:PATH = $savedPath
    $preStartStop = Invoke-SaiaiProcess -Path $binary -Arguments @("stop")
    Assert-Saiai ($preStartStop.ExitCode -eq 0) "SAIAI stop after Codex OAuth upgrade failed: $($preStartStop.Output)"

    $help = & $binary --help 2>&1 | Out-String
    Assert-Saiai ($LASTEXITCODE -eq 0) "SAIAI help failed: $help"
    Assert-Saiai ($help.Contains("saiai start")) "Local-proxy commands are missing"
    Assert-Saiai ($help.Contains("saiai codex")) "Codex local-proxy launcher is missing"
    Assert-Saiai (-not $help.Contains($testKey)) "Help exposed the key"

    $start = Invoke-SaiaiProcess -Path $binary -Arguments @("start") -CaptureOutput $false
    Assert-Saiai ($start.ExitCode -eq 0) "SAIAI start failed: $($start.Output)"
    $status = Invoke-SaiaiProcess -Path $binary -Arguments @("status")
    Assert-Saiai ($status.ExitCode -eq 0) "SAIAI status failed: $($status.Output)"
    Assert-Saiai ($status.Output.Contains("service active: yes")) "SAIAI background proxy is not active: $($status.Output)"
    $stop = Invoke-SaiaiProcess -Path $binary -Arguments @("stop")
    Assert-Saiai ($stop.ExitCode -eq 0) "SAIAI stop failed: $($stop.Output)"
}
finally {
    if ((Test-Path -LiteralPath $binary -PathType Leaf) -and (Test-Path -LiteralPath $env:SAIAI_HOME -PathType Container)) {
        & $binary stop *> $null
    }
    $env:CLAUDE_CONFIG_DIR = $savedConfigDir
    $env:SAIAI_HOME = $savedSaiaiHome
    $env:CODEX_HOME = $savedCodexHome
    $env:PATH = $savedPath
    $env:SAIAI_DESKTOP_BIN = $savedDesktopBin
    $env:SAIAI_CHATGPT_TIMEZONE = $savedChatgptTimezone
    $env:SAIAI_DESKTOP_CAPTURE = $savedDesktopCapture
    Remove-Item -LiteralPath $temporary -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host "SAIAI local-proxy Windows runtime smoke passed"
$global:LASTEXITCODE = 0
