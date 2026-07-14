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

function Invoke-Child {
    param([string]$FileName, [string[]]$Arguments)
    $output = & $FileName @Arguments 2>&1 | Out-String
    $exitCode = $LASTEXITCODE
    if ($exitCode -ne 0) {
        throw "$FileName failed with exit code $exitCode`n$output"
    }
    return $output
}

$bundle = (Resolve-Path -LiteralPath $BundleDir).Path
$setupPowerShell = (Resolve-Path -LiteralPath $SetupPs1).Path
$setupCommand = (Resolve-Path -LiteralPath $SetupCmd).Path
$binary = Join-Path $bundle $AssetName
$manifestPath = Join-Path $bundle "manifest.json"
Assert-Saiai (Test-Path -LiteralPath $binary -PathType Leaf) "Windows release binary is missing"
Assert-Saiai (Test-Path -LiteralPath $manifestPath -PathType Leaf) "Windows release manifest is missing"

$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
Assert-Saiai ([int]$manifest.manifest_schema -eq 1) "Windows manifest schema is not 1"
Assert-Saiai ([int]$manifest.bootstrap_schema_version -eq 2) "Windows manifest bootstrap schema is not 2"
$entry = $manifest.assets.PSObject.Properties[$AssetName]
Assert-Saiai ($null -ne $entry) "Windows asset is absent from manifest"
Assert-Saiai ((Get-Sha256 $binary) -ceq [string]$entry.Value.sha256) "Windows asset hash differs from manifest"
Assert-Saiai ((Get-Item -LiteralPath $binary).Length -eq [long]$entry.Value.size) "Windows asset size differs from manifest"

$temporary = Join-Path ([IO.Path]::GetTempPath()) ("saiai-v2-windows-release-" + [guid]::NewGuid().ToString("N"))
$testHome = Join-Path $temporary "home"
$localAppData = Join-Path $temporary "local-app-data"
$appData = Join-Path $temporary "roaming-app-data"
$install = Join-Path $temporary "install"
$null = New-Item -ItemType Directory -Path $testHome, $localAppData, $appData, $install -Force
$downloadBase = ([Uri](Resolve-Path -LiteralPath $bundle).Path).AbsoluteUri.TrimEnd('/')

$saved = @{}
foreach ($name in @("HOME", "USERPROFILE", "LOCALAPPDATA", "APPDATA", "SAIAI_INSTALL_DIR", "SAIAI_DOWNLOAD_BASE")) {
    $saved[$name] = [Environment]::GetEnvironmentVariable($name, "Process")
}
$savedUserPath = [Environment]::GetEnvironmentVariable("Path", "User")

try {
    $env:HOME = $testHome
    $env:USERPROFILE = $testHome
    $env:LOCALAPPDATA = $localAppData
    $env:APPDATA = $appData
    $env:SAIAI_INSTALL_DIR = $install
    $env:SAIAI_DOWNLOAD_BASE = $downloadBase

    $sentinels = [ordered]@{
        (Join-Path $testHome ".saiai\sentinel") = "legacy-saiai`n"
        (Join-Path $testHome ".claude\sentinel") = "legacy-claude`n"
        (Join-Path $testHome ".codex\sentinel") = "legacy-codex`n"
    }
    $utf8 = [Text.UTF8Encoding]::new($false)
    foreach ($pair in $sentinels.GetEnumerator()) {
        $null = New-Item -ItemType Directory -Path (Split-Path -Parent $pair.Key) -Force
        [IO.File]::WriteAllText([string]$pair.Key, [string]$pair.Value, $utf8)
    }

    $installed = Join-Path $install "saiai.exe"
    $previous = Join-Path $install "saiai-previous.exe"
    $previousContents = "previous preview client`n"
    [IO.File]::WriteAllText($installed, $previousContents, $utf8)

    $quotedSetup = $setupPowerShell.Replace("'", "''")
    $expression = ". '$quotedSetup'; `$result = Invoke-Saiai install; exit `$result"
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($expression))
    $powerShellOutput = Invoke-Child "powershell.exe" @(
        "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
        "-EncodedCommand", $encoded
    )
    Assert-Saiai ($powerShellOutput.Contains("Next: & `"$installed`" claude or & `"$installed`" codex")) "PowerShell wrapper omitted V2 guidance"

    Assert-Saiai (Test-Path -LiteralPath $installed -PathType Leaf) "PowerShell wrapper did not install saiai.exe"
    Assert-Saiai ((Get-Sha256 $installed) -ceq (Get-Sha256 $binary)) "PowerShell wrapper changed the binary"
    Assert-Saiai (Test-Path -LiteralPath $previous -PathType Leaf) "PowerShell wrapper did not preserve the previous client"
    Assert-Saiai ([IO.File]::ReadAllText($previous, $utf8) -ceq $previousContents) "PowerShell wrapper changed the preserved client"
    $versionOutput = Invoke-Child $installed @("--version")
    Assert-Saiai ($versionOutput.Contains("saiai $($manifest.version)")) "Windows binary version differs from manifest"
    $helpOutput = Invoke-Child $installed @("--help")
    foreach ($required in @("saiai setup [claude|codex]", "saiai claude", "saiai codex", "saiai revoke --all")) {
        Assert-Saiai ($helpOutput.Contains($required)) "Windows V2 help omitted $required"
    }

    Remove-Item -LiteralPath $installed, $previous -Force
    $cmdPreviousContents = "previous cmd preview client`n"
    [IO.File]::WriteAllText($installed, $cmdPreviousContents, $utf8)
    $cmdOutput = Invoke-Child "cmd.exe" @("/d", "/s", "/c", "`"$setupCommand`" install")
    Assert-Saiai ($cmdOutput.Contains("Next:")) "CMD wrapper omitted V2 guidance"
    Assert-Saiai (Test-Path -LiteralPath $installed -PathType Leaf) "CMD wrapper did not install saiai.exe"
    Assert-Saiai ((Get-Sha256 $installed) -ceq (Get-Sha256 $binary)) "CMD wrapper changed the binary"
    Assert-Saiai (Test-Path -LiteralPath $previous -PathType Leaf) "CMD wrapper did not preserve the previous client"
    Assert-Saiai ([IO.File]::ReadAllText($previous, $utf8) -ceq $cmdPreviousContents) "CMD wrapper changed the preserved client"

    foreach ($root in @(
        (Join-Path $localAppData "SAIAI\config"),
        (Join-Path $localAppData "SAIAI\data"),
        (Join-Path $localAppData "SAIAI\state")
    )) {
        Assert-Saiai (-not (Test-Path -LiteralPath $root)) "Install-only wrapper initialized V2 state"
    }
    foreach ($pair in $sentinels.GetEnumerator()) {
        $actual = [IO.File]::ReadAllText([string]$pair.Key, $utf8)
        Assert-Saiai ($actual -ceq [string]$pair.Value) "Install-only wrapper changed legacy state"
    }
}
finally {
    foreach ($name in $saved.Keys) {
        [Environment]::SetEnvironmentVariable($name, $saved[$name], "Process")
    }
    [Environment]::SetEnvironmentVariable("Path", $savedUserPath, "User")
    Remove-Item -LiteralPath $temporary -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host "SAIAI V2 Windows release wrapper smoke passed"
$global:LASTEXITCODE = 0
