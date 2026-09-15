[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$BundleDir,
    [Parameter(Mandatory = $true)][string]$SetupPs1,
    [Parameter(Mandatory = $true)][string]$SetupCmd,
    [Parameter(Mandatory = $true)][string]$AssetName
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Assert-Saiai {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw $Message }
}

function Get-Sha256 {
    param([string]$Path)
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Invoke-SaiaiProcess {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [bool]$CaptureOutput = $true,
        [int]$TimeoutMilliseconds = 15000
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
            throw "$Path $($Arguments -join ' ') did not return within $TimeoutMilliseconds ms"
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

$bundle = (Resolve-Path -LiteralPath $BundleDir).Path
$setupPowerShell = (Resolve-Path -LiteralPath $SetupPs1).Path
$setupCommand = (Resolve-Path -LiteralPath $SetupCmd).Path
$binary = Join-Path $bundle $AssetName
$manifest = Get-Content -LiteralPath (Join-Path $bundle "manifest.json") -Raw | ConvertFrom-Json
Assert-Saiai ([int]$manifest.manifest_schema -eq 1) "Windows manifest schema differs"
Assert-Saiai ([string]$manifest.client_mode -ceq "local-proxy") "Windows manifest mode differs"
Assert-Saiai ([int]$manifest.configuration_schema_version -eq 1) "Windows configuration schema differs"
Assert-Saiai ($null -eq $manifest.PSObject.Properties["bootstrap_schema_version"]) "Windows manifest still claims V2 bootstrap"
$entry = $manifest.assets.PSObject.Properties[$AssetName]
Assert-Saiai ($null -ne $entry) "Windows asset is absent from manifest"
Assert-Saiai ((Get-Sha256 $binary) -ceq [string]$entry.Value.sha256) "Windows asset hash differs"
Assert-Saiai ((Get-Item -LiteralPath $binary).Length -eq [long]$entry.Value.size) "Windows asset size differs"
Assert-Saiai ((Get-Content -LiteralPath $setupCommand -Raw).Contains("local-proxy")) "CMD wrapper contract differs"

$temporary = Join-Path ([IO.Path]::GetTempPath()) ("saiai-config-windows-release-" + [guid]::NewGuid().ToString("N"))
$testHome = Join-Path $temporary "home"
$install = Join-Path $temporary "install"
$null = New-Item -ItemType Directory -Path $testHome, $install -Force
$downloadBase = ([Uri](Resolve-Path -LiteralPath $bundle).Path).AbsoluteUri.TrimEnd('/')
$testKey = "TEST_ONLY_WINDOWS_RELEASE_KEY"

$saved = @{}
foreach ($name in @("HOME", "USERPROFILE", "LOCALAPPDATA", "APPDATA", "CLAUDE_CONFIG_DIR", "SAIAI_HOME", "SAIAI_INSTALL_DIR", "SAIAI_DOWNLOAD_BASE", "SAIAI_SKIP_START")) {
    $saved[$name] = [Environment]::GetEnvironmentVariable($name, "Process")
}
$savedUserPath = [Environment]::GetEnvironmentVariable("Path", "User")

try {
    $env:HOME = $testHome
    $env:USERPROFILE = $testHome
    $env:LOCALAPPDATA = Join-Path $temporary "local-app-data"
    $env:APPDATA = Join-Path $temporary "roaming-app-data"
    $env:CLAUDE_CONFIG_DIR = Join-Path $testHome ".claude"
    $env:SAIAI_HOME = Join-Path $testHome ".saiai"
    $env:SAIAI_INSTALL_DIR = $install
    $env:SAIAI_DOWNLOAD_BASE = $downloadBase
    $env:SAIAI_SKIP_START = "1"

    . $setupPowerShell
    $result = Invoke-Saiai "https://gateway.example.test" $testKey
    Assert-Saiai ($result -is [int]) "PowerShell wrapper returned a non-scalar exit code"
    Assert-Saiai ($result -eq 0) "PowerShell wrapper failed"
    $installed = Join-Path $install "saiai.exe"
    Assert-Saiai (Test-Path -LiteralPath $installed -PathType Leaf) "PowerShell wrapper did not install saiai.exe"
    Assert-Saiai ((Get-Sha256 $installed) -ceq (Get-Sha256 $binary)) "PowerShell wrapper changed the binary"

    $settingsPath = Join-Path $env:CLAUDE_CONFIG_DIR "settings.json"
    $settings = Get-Content -LiteralPath $settingsPath -Raw | ConvertFrom-Json
    $proxyConfig = Get-Content -LiteralPath (Join-Path $env:SAIAI_HOME "config.json") -Raw | ConvertFrom-Json
    $proxyUrl = "http://$([string]$proxyConfig.listen)"
    Assert-Saiai ([string]$settings.env.CLAUDE_CODE_OAUTH_TOKEN -ceq $testKey) "PowerShell wrapper did not apply the key"
    Assert-Saiai ($null -eq $settings.env.PSObject.Properties["ANTHROPIC_BASE_URL"]) "PowerShell wrapper left a direct gateway override"
    Assert-Saiai ([string]$settings.env.http_proxy -ceq $proxyUrl) "PowerShell wrapper did not apply the local proxy"

    $second = Invoke-Saiai "https://new-gateway.example.test" "TEST_ONLY_WINDOWS_REPLACEMENT_KEY"
    Assert-Saiai ($second -is [int]) "Repeat PowerShell wrapper returned a non-scalar exit code"
    Assert-Saiai ($second -eq 0) "Repeat PowerShell wrapper failed"
    $proxyConfig = Get-Content -LiteralPath (Join-Path $env:SAIAI_HOME "config.json") -Raw | ConvertFrom-Json
    Assert-Saiai ([string]$proxyConfig.base_url -ceq "https://new-gateway.example.test") "Repeat setup did not replace the gateway"

    # Appended PE overlay data keeps the executable runnable while making its
    # hash differ from the release manifest. This models upgrading an older
    # installed binary while its background worker has the executable locked.
    [IO.File]::AppendAllText($installed, "OLDER_TEST_BUILD")
    Assert-Saiai ((Get-Sha256 $installed) -cne (Get-Sha256 $binary)) "Upgrade fixture still matches the release binary"
    $oldStart = Invoke-SaiaiProcess -Path $installed -Arguments @("start") -CaptureOutput $false
    Assert-Saiai ($oldStart.ExitCode -eq 0) "Upgrade fixture could not start: $($oldStart.Output)"

    # Keep a second process from the same installed image alive. The updater
    # must terminate exact-path stragglers as well as the managed background
    # PID before replacing the executable.
    $stragglerInfo = [Diagnostics.ProcessStartInfo]::new()
    $stragglerInfo.FileName = $installed
    $stragglerInfo.UseShellExecute = $false
    $stragglerInfo.CreateNoWindow = $true
    $null = $stragglerInfo.ArgumentList.Add("logs")
    $stragglerInfo.RedirectStandardOutput = $true
    $stragglerInfo.RedirectStandardError = $true
    $straggler = [Diagnostics.Process]::new()
    $straggler.StartInfo = $stragglerInfo
    $null = $straggler.Start()
    Start-Sleep -Milliseconds 500
    Assert-Saiai (-not $straggler.HasExited) "Upgrade straggler fixture exited before replacement"

    Remove-Item Env:SAIAI_SKIP_START
    $escapedSetup = $setupPowerShell.Replace("'", "''")
    $childScript = @"
. '$escapedSetup'
`$result = Invoke-Saiai 'https://upgrade.example.test' 'TEST_ONLY_WINDOWS_UPGRADE_KEY'
if (`$result -ne 0) { exit `$result }
exit 0
"@
    $powerShellPath = [Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
    $upgrade = Invoke-SaiaiProcess -Path $powerShellPath -Arguments @("-NoProfile", "-NonInteractive", "-Command", $childScript) -CaptureOutput $false -TimeoutMilliseconds 45000
    Assert-Saiai ($upgrade.ExitCode -eq 0) "Running-client upgrade failed: $($upgrade.Output)"
    $straggler.WaitForExit(5000) | Out-Null
    Assert-Saiai ($straggler.HasExited) "Running-client upgrade left an exact-path SAIAI process alive"
    $straggler.Dispose()
    Assert-Saiai ((Get-Sha256 $installed) -ceq (Get-Sha256 $binary)) "Running-client upgrade did not install the release binary"
    $upgradedStatus = Invoke-SaiaiProcess -Path $installed -Arguments @("status")
    Assert-Saiai ($upgradedStatus.ExitCode -eq 0) "Upgraded client status failed: $($upgradedStatus.Output)"
    Assert-Saiai ($upgradedStatus.Output.Contains("service active: yes")) "Upgraded background proxy is not active: $($upgradedStatus.Output)"

    # Both initialization paths own one native start/refresh. Stopping first
    # makes this prove that legacy Codex initialization starts a new managed
    # proxy even when there was no active process to refresh.
    & $installed stop *> $null
    Assert-Saiai ($LASTEXITCODE -eq 0) "Could not stop the proxy before Codex initialization"
    $codexInit = Invoke-Saiai init-codex "https://codex-gateway.example.test/v1" "TEST_ONLY_WINDOWS_CODEX_KEY"
    Assert-Saiai ($codexInit -is [int]) "Codex PowerShell initialization returned a non-scalar exit code"
    Assert-Saiai ($codexInit -eq 0) "Codex PowerShell initialization failed"
    $codexStatus = Invoke-SaiaiProcess -Path $installed -Arguments @("status")
    Assert-Saiai ($codexStatus.ExitCode -eq 0) "Codex-initialized client status failed: $($codexStatus.Output)"
    Assert-Saiai ($codexStatus.Output.Contains("service active: yes")) "Codex initialization did not start the background proxy: $($codexStatus.Output)"

    # GitHub's default pwsh shell is PowerShell 7, while many installed
    # Windows systems still use inbox Windows PowerShell 5.1. Run the public
    # wrapper in that exact host so a modern-.NET-only ProcessStartInfo API
    # cannot regress either initialization entrypoint unnoticed.
    $legacyPowerShell = Join-Path $env:WINDIR "System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    Assert-Saiai (Test-Path -LiteralPath $legacyPowerShell -PathType Leaf) "Windows PowerShell 5.1 is unavailable on this runner"
    $legacySetup = $setupPowerShell.Replace("'", "''")
    $legacyScript = @"
`$ErrorActionPreference = 'Stop'
. '$legacySetup'
`$claudeResult = Invoke-Saiai 'https://powershell51-claude.example.test' 'TEST_ONLY_WINDOWS_PS51_CLAUDE_KEY WITH SPACE'
if (`$claudeResult -ne 0) { exit `$claudeResult }
`$codexResult = Invoke-Saiai init-codex 'https://powershell51-codex.example.test/v1' 'TEST_ONLY_WINDOWS_PS51_CODEX_KEY WITH SPACE'
if (`$codexResult -ne 0) { exit `$codexResult }
exit 0
"@
    $legacy = Invoke-SaiaiProcess -Path $legacyPowerShell -Arguments @("-NoProfile", "-NonInteractive", "-Command", $legacyScript) -CaptureOutput $false -TimeoutMilliseconds 60000
    Assert-Saiai ($legacy.ExitCode -eq 0) "Windows PowerShell 5.1 setup wrapper smoke failed"
    $legacyConfig = Get-Content -LiteralPath (Join-Path $env:SAIAI_HOME "config.json") -Raw | ConvertFrom-Json
    Assert-Saiai ([string]$legacyConfig.api_key -ceq "TEST_ONLY_WINDOWS_PS51_CODEX_KEY WITH SPACE") "Windows PowerShell 5.1 wrapper did not preserve the Codex Key argument"
    $legacyStatus = Invoke-SaiaiProcess -Path $installed -Arguments @("status")
    Assert-Saiai ($legacyStatus.ExitCode -eq 0) "Windows PowerShell 5.1 initialized client status failed: $($legacyStatus.Output)"
    Assert-Saiai ($legacyStatus.Output.Contains("service active: yes")) "Windows PowerShell 5.1 initialization did not start the background proxy: $($legacyStatus.Output)"
}
finally {
    $installedForCleanup = Join-Path $install "saiai.exe"
    if ((Test-Path -LiteralPath $installedForCleanup -PathType Leaf) -and (Test-Path -LiteralPath $env:SAIAI_HOME -PathType Container)) {
        & $installedForCleanup stop *> $null
    }
    foreach ($name in $saved.Keys) {
        [Environment]::SetEnvironmentVariable($name, $saved[$name], "Process")
    }
    [Environment]::SetEnvironmentVariable("Path", $savedUserPath, "User")
    Remove-Item -LiteralPath $temporary -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host "SAIAI local-proxy Windows release wrapper smoke passed"
$global:LASTEXITCODE = 0
