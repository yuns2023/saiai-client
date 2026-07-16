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

$bundle = (Resolve-Path -LiteralPath $BundleDir).Path
$setupPowerShell = (Resolve-Path -LiteralPath $SetupPs1).Path
$setupCommand = (Resolve-Path -LiteralPath $SetupCmd).Path
$binary = Join-Path $bundle $AssetName
$manifest = Get-Content -LiteralPath (Join-Path $bundle "manifest.json") -Raw | ConvertFrom-Json
Assert-Saiai ([int]$manifest.manifest_schema -eq 1) "Windows manifest schema differs"
Assert-Saiai ([string]$manifest.client_mode -ceq "global-config") "Windows manifest mode differs"
Assert-Saiai ([int]$manifest.configuration_schema_version -eq 1) "Windows configuration schema differs"
Assert-Saiai ($null -eq $manifest.PSObject.Properties["bootstrap_schema_version"]) "Windows manifest still claims V2 bootstrap"
$entry = $manifest.assets.PSObject.Properties[$AssetName]
Assert-Saiai ($null -ne $entry) "Windows asset is absent from manifest"
Assert-Saiai ((Get-Sha256 $binary) -ceq [string]$entry.Value.sha256) "Windows asset hash differs"
Assert-Saiai ((Get-Item -LiteralPath $binary).Length -eq [long]$entry.Value.size) "Windows asset size differs"
Assert-Saiai ((Get-Content -LiteralPath $setupCommand -Raw).Contains("global-config")) "CMD wrapper contract differs"

$temporary = Join-Path ([IO.Path]::GetTempPath()) ("saiai-config-windows-release-" + [guid]::NewGuid().ToString("N"))
$testHome = Join-Path $temporary "home"
$install = Join-Path $temporary "install"
$null = New-Item -ItemType Directory -Path $testHome, $install -Force
$downloadBase = ([Uri](Resolve-Path -LiteralPath $bundle).Path).AbsoluteUri.TrimEnd('/')
$testKey = "TEST_ONLY_WINDOWS_RELEASE_KEY"

$saved = @{}
foreach ($name in @("HOME", "USERPROFILE", "LOCALAPPDATA", "APPDATA", "CLAUDE_CONFIG_DIR", "SAIAI_INSTALL_DIR", "SAIAI_DOWNLOAD_BASE")) {
    $saved[$name] = [Environment]::GetEnvironmentVariable($name, "Process")
}
$savedUserPath = [Environment]::GetEnvironmentVariable("Path", "User")

try {
    $env:HOME = $testHome
    $env:USERPROFILE = $testHome
    $env:LOCALAPPDATA = Join-Path $temporary "local-app-data"
    $env:APPDATA = Join-Path $temporary "roaming-app-data"
    $env:CLAUDE_CONFIG_DIR = Join-Path $testHome ".claude"
    $env:SAIAI_INSTALL_DIR = $install
    $env:SAIAI_DOWNLOAD_BASE = $downloadBase

    . $setupPowerShell
    $result = Invoke-Saiai "https://gateway.example.test" $testKey
    Assert-Saiai ($result -eq 0) "PowerShell wrapper failed"
    $installed = Join-Path $install "saiai.exe"
    Assert-Saiai (Test-Path -LiteralPath $installed -PathType Leaf) "PowerShell wrapper did not install saiai.exe"
    Assert-Saiai ((Get-Sha256 $installed) -ceq (Get-Sha256 $binary)) "PowerShell wrapper changed the binary"

    $settingsPath = Join-Path $env:CLAUDE_CONFIG_DIR "settings.json"
    $settings = Get-Content -LiteralPath $settingsPath -Raw | ConvertFrom-Json
    Assert-Saiai ([string]$settings.env.CLAUDE_CODE_OAUTH_TOKEN -ceq $testKey) "PowerShell wrapper did not apply the key"
    Assert-Saiai ([string]$settings.env.ANTHROPIC_BASE_URL -ceq "https://gateway.example.test") "PowerShell wrapper did not apply the gateway"

    $second = Invoke-Saiai "https://new-gateway.example.test" "TEST_ONLY_WINDOWS_REPLACEMENT_KEY"
    Assert-Saiai ($second -eq 0) "Repeat PowerShell wrapper failed"
    $settings = Get-Content -LiteralPath $settingsPath -Raw | ConvertFrom-Json
    Assert-Saiai ([string]$settings.env.ANTHROPIC_BASE_URL -ceq "https://new-gateway.example.test") "Repeat setup did not replace the gateway"
}
finally {
    foreach ($name in $saved.Keys) {
        [Environment]::SetEnvironmentVariable($name, $saved[$name], "Process")
    }
    [Environment]::SetEnvironmentVariable("Path", $savedUserPath, "User")
    Remove-Item -LiteralPath $temporary -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host "SAIAI global-config Windows release wrapper smoke passed"
$global:LASTEXITCODE = 0
