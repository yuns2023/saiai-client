# Install or reuse SAIAI, apply the requested config, and start the Claude
# per-user local proxy service for the Claude setup path.

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
    if (-not ($processParts | Where-Object {
        -not [string]::IsNullOrWhiteSpace($_) -and
        [string]::Equals($_.TrimEnd('\'), $Directory.TrimEnd('\'), $comparison)
    })) {
        $env:Path = "$Directory;$env:Path"
    }
}

function Stop-SaiaiForReplacement {
    param([Parameter(Mandatory = $true)][string]$Path)

    Write-Host "Stopping the running SAIAI background proxy before updating..." -ForegroundColor DarkGray
    & $Path stop | Out-Host
    $stopExitCode = [int]$LASTEXITCODE
    if ($stopExitCode -ne 0) {
        throw "Existing SAIAI client could not be stopped before update (exit $stopExitCode)."
    }
}

function Move-SaiaiCandidate {
    param(
        [Parameter(Mandatory = $true)][string]$Source,
        [Parameter(Mandatory = $true)][string]$Destination
    )

    $lastError = $null
    foreach ($attempt in 1..20) {
        try {
            Move-Item -LiteralPath $Source -Destination $Destination -Force -ErrorAction Stop
            return
        }
        catch {
            $lastError = $_
            if ($attempt -lt 20) {
                Start-Sleep -Milliseconds 100
            }
        }
    }
    throw $lastError
}

function Invoke-Saiai {
    param(
        [Parameter(ValueFromRemainingArguments = $true)]
        [string[]]$Arguments
    )

    $provided = @($Arguments)
    if ($provided.Count -lt 2) {
        Write-Error "Usage: Invoke-Saiai <base_url> <api_key> OR Invoke-Saiai init-codex <base_url> <api_key> [--websockets]"
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
            Write-Host "Checking SAIAI client release metadata..." -ForegroundColor Cyan
            $client.DownloadFile($manifestUrl, $manifestPath)
            $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
            if ([int]$manifest.manifest_schema -ne 1) {
                throw "Unsupported SAIAI manifest schema."
            }
            if ([string]$manifest.client_mode -cne "local-proxy") {
                throw "Release is not a SAIAI local-proxy client."
            }
            if ([int]$manifest.configuration_schema_version -ne 1) {
                throw "Unsupported SAIAI configuration schema."
            }
            $entry = $manifest.assets.PSObject.Properties[$asset]
            if ($null -eq $entry) {
                throw "Manifest does not contain $asset."
            }
            $expectedSha256 = [string]$entry.Value.sha256
            $expectedSize = [long]$entry.Value.size
            $releaseVersion = [string]$manifest.version
            if ($expectedSha256 -notmatch '^[0-9a-f]{64}$' -or $expectedSize -le 0) {
                throw "Manifest metadata is invalid for $asset."
            }

            $null = New-Item -ItemType Directory -Path $installDirectory -Force
            if (Test-Path -LiteralPath $installPath -PathType Container) {
                throw "Install path is a directory: $installPath"
            }
            if (Test-Path -LiteralPath $installPath -PathType Leaf) {
                $installedItem = Get-Item -LiteralPath $installPath -Force
                if (($installedItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                    throw "Refusing to use reparse-point install path: $installPath"
                }
            }

            $installedMatches = (Test-Path -LiteralPath $installPath -PathType Leaf) -and
                ((Get-SaiaiSha256 -Path $installPath) -ceq $expectedSha256)
            if ($installedMatches) {
                Write-Host "SAIAI $releaseVersion is already installed; binary download skipped." -ForegroundColor DarkGray
            }
            else {
                Write-Host "Downloading $asset..." -ForegroundColor Cyan
                $client.DownloadFile($assetUrl, $candidatePath)
                if ((Get-Item -LiteralPath $candidatePath).Length -ne $expectedSize) {
                    throw "Size mismatch for $asset."
                }
                if ((Get-SaiaiSha256 -Path $candidatePath) -cne $expectedSha256) {
                    throw "SHA-256 mismatch for $asset."
                }

                $installedExists = Test-Path -LiteralPath $installPath -PathType Leaf
                if ($installedExists) {
                    Stop-SaiaiForReplacement -Path $installPath
                }
                if ($installedExists -and
                    -not (Test-Path -LiteralPath $backupPath)) {
                    [System.IO.File]::Copy($installPath, $backupPath, $false)
                    Write-Host "Preserved the previous client at $backupPath." -ForegroundColor DarkGray
                }
                $stagedPath = Join-Path $installDirectory (".saiai.install." + [guid]::NewGuid().ToString("N") + ".exe")
                try {
                    [System.IO.File]::Copy($candidatePath, $stagedPath, $false)
                    Move-SaiaiCandidate -Source $stagedPath -Destination $installPath
                }
                finally {
                    Remove-Item -LiteralPath $stagedPath -Force -ErrorAction SilentlyContinue
                }
                Write-Host "Installed SAIAI $releaseVersion at $installPath." -ForegroundColor Green
            }
        }
        finally {
            $client.Dispose()
            $ProgressPreference = $progressBefore
        }

        Add-SaiaiPath -Directory $installDirectory
        # Keep the native client's human-readable stdout visible without
        # mixing it into this function's scalar exit-code result. PowerShell
        # otherwise captures both values when callers assign Invoke-Saiai.
        if ($provided[0] -eq "init-codex") {
            & $installPath @provided | Out-Host
            return [int]$LASTEXITCODE
        }

        $claudeArguments = @("init") + $provided
        & $installPath @claudeArguments | Out-Host
        $nativeExitCode = [int]$LASTEXITCODE
        if ($nativeExitCode -ne 0) {
            return $nativeExitCode
        }
        if ([string]$env:SAIAI_SKIP_START -eq "1") {
            return 0
        }
        & $installPath start | Out-Host
        return [int]$LASTEXITCODE
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
