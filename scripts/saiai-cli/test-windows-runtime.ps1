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

    $output = & $binary init "https://gateway.example.test" $testKey 2>&1 | Out-String
    Assert-Saiai ($LASTEXITCODE -eq 0) "SAIAI config command failed: $output"
    Assert-Saiai (-not $output.Contains($testKey)) "SAIAI output exposed the API key"

    $settings = Get-Content -LiteralPath $settingsPath -Raw | ConvertFrom-Json
    Assert-Saiai ($null -eq $settings.env.PSObject.Properties["ANTHROPIC_BASE_URL"]) "Direct gateway override remains"
    Assert-Saiai ([string]$settings.env.CLAUDE_CODE_OAUTH_TOKEN -ceq $testKey) "API key differs"
    Assert-Saiai ([string]$settings.env.CLAUDE_STREAM_IDLE_TIMEOUT_MS -ceq "600000") "Timeout differs"
    Assert-Saiai ([string]$settings.env.KEEP_ME -ceq "yes") "Unrelated env was lost"
    Assert-Saiai ($null -eq $settings.env.PSObject.Properties["ANTHROPIC_AUTH_TOKEN"]) "Conflicting auth token remains"
    Assert-Saiai ([string]$settings.env.http_proxy -ceq "http://127.0.0.1:19908") "Local proxy differs"
    Assert-Saiai ([string]$settings.env.NODE_EXTRA_CA_CERTS -ceq $caPath) "CA path differs"
    Assert-Saiai (@($settings.permissions.allow) -contains "Read") "Unrelated settings were lost"

    $state = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
    Assert-Saiai ($null -eq $state.PSObject.Properties["oauthAccount"]) "oauthAccount remains"
    Assert-Saiai ([string]$state.userID -ceq "kept") "Machine identity was lost"
    Assert-Saiai (-not (Test-Path -LiteralPath $credentialsPath)) "OAuth credentials remain"
    Assert-Saiai (Test-Path -LiteralPath $caPath -PathType Leaf) "Installation CA was not generated"
    Assert-Saiai (Test-Path -LiteralPath $caKeyPath -PathType Leaf) "Installation CA key was not generated"

    $caHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $caPath).Hash
    $caKeyHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $caKeyPath).Hash
    $repeatOutput = & $binary init "https://replacement.example.test" $replacementKey 2>&1 | Out-String
    Assert-Saiai ($LASTEXITCODE -eq 0) "Repeated SAIAI config failed: $repeatOutput"
    Assert-Saiai (-not $repeatOutput.Contains($replacementKey)) "Repeated config output exposed the API key"
    Assert-Saiai ((Get-FileHash -Algorithm SHA256 -LiteralPath $caPath).Hash -ceq $caHash) "Repeated setup replaced a valid CA"
    Assert-Saiai ((Get-FileHash -Algorithm SHA256 -LiteralPath $caKeyPath).Hash -ceq $caKeyHash) "Repeated setup replaced a valid CA key"
    $repeatedSettings = Get-Content -LiteralPath $settingsPath -Raw | ConvertFrom-Json
    Assert-Saiai ([string]$repeatedSettings.env.CLAUDE_CODE_OAUTH_TOKEN -ceq $replacementKey) "Repeated setup did not replace the API key"
    $saiaiConfig = Get-Content -LiteralPath (Join-Path $env:SAIAI_HOME "config.json") -Raw | ConvertFrom-Json
    Assert-Saiai ([string]$saiaiConfig.base_url -ceq "https://replacement.example.test") "Repeated setup did not replace the Gateway"
    Assert-Saiai ([string]$saiaiConfig.api_key -ceq $replacementKey) "Repeated setup config Key differs"

    $env:CODEX_HOME = Join-Path $temporary ".codex"
    $codexOutput = & $binary init-codex "https://codex.example.test/v1" $codexKey 2>&1 | Out-String
    Assert-Saiai ($LASTEXITCODE -eq 0) "SAIAI Codex initialization failed: $codexOutput"
    Assert-Saiai (-not $codexOutput.Contains($codexKey)) "Codex initialization output exposed the API key"
    $codexProxyConfig = Get-Content -LiteralPath (Join-Path $env:SAIAI_HOME "config.json") -Raw | ConvertFrom-Json
    Assert-Saiai ([string]$codexProxyConfig.base_url -ceq "https://codex.example.test") "Codex initialization did not normalize the local-proxy Gateway root"
    Assert-Saiai ([string]$codexProxyConfig.api_key -ceq $codexKey) "Codex initialization did not update the local-proxy Key"
    Assert-Saiai ((Get-FileHash -Algorithm SHA256 -LiteralPath $caPath).Hash -ceq $caHash) "Codex initialization replaced the existing CA"
    Assert-Saiai ((Get-FileHash -Algorithm SHA256 -LiteralPath $caKeyPath).Hash -ceq $caKeyHash) "Codex initialization replaced the existing CA key"
    Assert-Saiai (Test-Path -LiteralPath (Join-Path $env:CODEX_HOME "config.toml") -PathType Leaf) "Codex config was not created"
    Assert-Saiai (Test-Path -LiteralPath (Join-Path $env:CODEX_HOME "auth.json") -PathType Leaf) "Codex auth was not created"
    # `vscode` may start the detached proxy. Do not attach it to a PowerShell
    # output pipeline: the child can inherit the pipeline handle and keep
    # Out-String waiting for EOF after the command itself exits.
    $vscode = Invoke-SaiaiProcess -Path $binary -Arguments @("vscode") -CaptureOutput $false
    Assert-Saiai ($vscode.ExitCode -eq 0) "SAIAI Codex OAuth upgrade failed"
    $codexAuth = Get-Content -LiteralPath (Join-Path $env:CODEX_HOME "auth.json") -Raw | ConvertFrom-Json
    $codexConfig = Get-Content -LiteralPath (Join-Path $env:CODEX_HOME "config.toml") -Raw
    Assert-Saiai ([string]$codexAuth.auth_mode -ceq "chatgptAuthTokens") "Managed legacy Codex auth was not upgraded to externally supplied token mode"
    Assert-Saiai ($null -eq $codexAuth.OPENAI_API_KEY) "Managed legacy Codex API key remains after upgrade"
    Assert-Saiai (-not [string]::IsNullOrWhiteSpace([string]$codexAuth.tokens.access_token)) "Codex OAuth placeholder access token is missing"
    Assert-Saiai ([string]$codexAuth.tokens.refresh_token -ceq "") "Synthetic Codex auth must not contain a provider refresh token"

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
    $npmCodex = Invoke-SaiaiProcess -Path $binary -Arguments @("codex", "--", "--version")
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
    Remove-Item -LiteralPath $temporary -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host "SAIAI local-proxy Windows runtime smoke passed"
$global:LASTEXITCODE = 0
