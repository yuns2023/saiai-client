# Install the SAIAI V2 client binary. Product setup is performed by `saiai`.

$ErrorActionPreference = "Stop"

function Get-SaiaiAssetName {
    $architecture = [string]$env:PROCESSOR_ARCHITECTURE
    if ($architecture -ieq "X86" -and -not [string]::IsNullOrWhiteSpace($env:PROCESSOR_ARCHITEW6432)) {
        $architecture = [string]$env:PROCESSOR_ARCHITEW6432
    }
    switch ($architecture.Trim().ToUpperInvariant()) {
        "AMD64" { return "saiai-windows-x86_64.exe" }
        "X64" { return "saiai-windows-x86_64.exe" }
        "ARM64" { return "saiai-windows-aarch64.exe" }
        "AARCH64" { return "saiai-windows-aarch64.exe" }
        default { throw "Unsupported Windows architecture: $architecture" }
    }
}

function Get-SaiaiSha256 {
    param([Parameter(Mandatory = $true)][string]$Path)

    if (Get-Command Get-FileHash -ErrorAction SilentlyContinue) {
        return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
    }
    $algorithm = [System.Security.Cryptography.SHA256]::Create()
    $stream = [System.IO.File]::OpenRead($Path)
    try {
        return ([BitConverter]::ToString($algorithm.ComputeHash($stream))).Replace("-", "").ToLowerInvariant()
    }
    finally {
        $stream.Dispose()
        $algorithm.Dispose()
    }
}

function Get-SaiaiInstallPath {
    if (-not [string]::IsNullOrWhiteSpace($env:SAIAI_INSTALL_DIR)) {
        $directory = $env:SAIAI_INSTALL_DIR
    }
    elseif (-not [string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)) {
        $directory = Join-Path $env:LOCALAPPDATA "SAIAI\bin"
    }
    elseif (-not [string]::IsNullOrWhiteSpace($env:USERPROFILE)) {
        $directory = Join-Path $env:USERPROFILE "AppData\Local\SAIAI\bin"
    }
    else {
        throw "Cannot resolve the per-user install directory. Set SAIAI_INSTALL_DIR."
    }
    return [System.IO.Path]::GetFullPath((Join-Path $directory "saiai.exe"))
}

function Add-SaiaiPath {
    param([Parameter(Mandatory = $true)][string]$Directory)

    $comparison = [System.StringComparison]::OrdinalIgnoreCase
    $userPath = [string][Environment]::GetEnvironmentVariable("Path", "User")
    $userParts = @($userPath.Split(';') | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    $present = $false
    foreach ($part in $userParts) {
        if ([string]::Equals($part.TrimEnd('\'), $Directory.TrimEnd('\'), $comparison)) {
            $present = $true
            break
        }
    }
    if (-not $present) {
        $newPath = if ([string]::IsNullOrWhiteSpace($userPath)) { $Directory } else { "$userPath;$Directory" }
        [Environment]::SetEnvironmentVariable("Path", $newPath, "User")
    }

    $processParts = @(([string]$env:Path).Split(';'))
    $processPresent = $false
    foreach ($part in $processParts) {
        if (-not [string]::IsNullOrWhiteSpace($part) -and
            [string]::Equals($part.TrimEnd('\'), $Directory.TrimEnd('\'), $comparison)) {
            $processPresent = $true
            break
        }
    }
    if (-not $processPresent) {
        $env:Path = "$Directory;$env:Path"
    }
}

function Invoke-Saiai {
    param(
        [Parameter(ValueFromRemainingArguments = $true)]
        [string[]]$Arguments
    )

    $provided = @($Arguments)
    if ($provided.Count -gt 1 -or ($provided.Count -eq 1 -and $provided[0] -ne "install")) {
        Write-Error "Usage: Invoke-Saiai [install]. This wrapper installs only; run 'saiai setup claude' or 'saiai setup codex' afterward."
        return 2
    }

    $asset = Get-SaiaiAssetName
    $downloadBase = if ([string]::IsNullOrWhiteSpace($env:SAIAI_DOWNLOAD_BASE)) {
        "https://api.saiai.top/saiai-cli"
    }
    else {
        $env:SAIAI_DOWNLOAD_BASE.TrimEnd('/')
    }
    $manifestUrl = "$downloadBase/manifest.json"
    $assetUrl = "$downloadBase/$asset"
    $installPath = Get-SaiaiInstallPath
    $installDirectory = Split-Path -Parent $installPath
    $backupPath = Join-Path $installDirectory "saiai-previous.exe"
    $temporary = Join-Path ([System.IO.Path]::GetTempPath()) ("saiai-install-" + [guid]::NewGuid().ToString("N"))
    $null = New-Item -ItemType Directory -Path $temporary -Force
    $manifestPath = Join-Path $temporary "manifest.json"
    $candidatePath = Join-Path $temporary "saiai.exe"

    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $progressBefore = $ProgressPreference
        $ProgressPreference = "SilentlyContinue"
        $client = New-Object Net.WebClient
        try {
            Write-Host "Checking $manifestUrl" -ForegroundColor Cyan
            $client.DownloadFile($manifestUrl, $manifestPath)
            $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
            if ([int]$manifest.manifest_schema -ne 1) {
                throw "Unsupported SAIAI manifest schema."
            }
            if ([int]$manifest.bootstrap_schema_version -ne 2) {
                throw "Release is not compatible with SAIAI bootstrap schema 2."
            }
            $entry = $manifest.assets.PSObject.Properties[$asset]
            if ($null -eq $entry) {
                throw "Manifest does not contain $asset."
            }
            $expectedSha256 = [string]$entry.Value.sha256
            $expectedSize = [long]$entry.Value.size
            if ($expectedSha256 -notmatch '^[0-9a-f]{64}$' -or $expectedSize -le 0) {
                throw "Manifest metadata is invalid for $asset."
            }

            Write-Host "Downloading $assetUrl" -ForegroundColor Cyan
            $client.DownloadFile($assetUrl, $candidatePath)
        }
        finally {
            $client.Dispose()
            $ProgressPreference = $progressBefore
        }

        $actualSize = (Get-Item -LiteralPath $candidatePath).Length
        if ($actualSize -ne $expectedSize) {
            throw "Size mismatch for $asset."
        }
        $actualSha256 = Get-SaiaiSha256 -Path $candidatePath
        if ($actualSha256 -cne $expectedSha256) {
            throw "SHA-256 mismatch for $asset."
        }

        $null = New-Item -ItemType Directory -Path $installDirectory -Force
        if (Test-Path -LiteralPath $installPath -PathType Container) {
            throw "Install path is a directory: $installPath"
        }
        if (Test-Path -LiteralPath $installPath -PathType Leaf) {
            $installedItem = Get-Item -LiteralPath $installPath -Force
            if (($installedItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "Refusing to replace reparse-point install path: $installPath"
            }
        }
        if ((Test-Path -LiteralPath $installPath -PathType Leaf) -and
            (Get-SaiaiSha256 -Path $installPath) -cne $actualSha256 -and
            -not (Test-Path -LiteralPath $backupPath)) {
            [System.IO.File]::Copy($installPath, $backupPath, $false)
            Write-Host "Preserved the previous client at $backupPath" -ForegroundColor DarkGray
        }
        $stagedPath = Join-Path $installDirectory (".saiai.install." + [guid]::NewGuid().ToString("N") + ".exe")
        try {
            [System.IO.File]::Copy($candidatePath, $stagedPath, $false)
            Move-Item -LiteralPath $stagedPath -Destination $installPath -Force
        }
        finally {
            Remove-Item -LiteralPath $stagedPath -Force -ErrorAction SilentlyContinue
        }
        Add-SaiaiPath -Directory $installDirectory

        Write-Host "SAIAI V2 installed at $installPath" -ForegroundColor Green
        Write-Host "Next: & `"$installPath`" claude or & `"$installPath`" codex" -ForegroundColor Green
        Write-Host "Explicit setup: & `"$installPath`" setup claude or & `"$installPath`" setup codex" -ForegroundColor Green
        return 0
    }
    finally {
        Remove-Item -LiteralPath $temporary -Recurse -Force -ErrorAction SilentlyContinue
    }
}

if ($args.Count -gt 0) {
    $exitCode = Invoke-Saiai @args
    if ($exitCode -ne 0) {
        exit $exitCode
    }
}
