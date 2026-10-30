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

function Test-SaiaiDirectoryOverride {
    param([string]$Name, [string]$Default)
    $raw = [Environment]::GetEnvironmentVariable($Name, "Process")
    if ($null -eq $raw) { return $false }
    if ([string]::IsNullOrWhiteSpace($raw)) { throw "$Name is empty; unset it to use the default environment." }
    return -not [string]::Equals([IO.Path]::GetFullPath($raw).TrimEnd('\'),
        [IO.Path]::GetFullPath($Default).TrimEnd('\'), [StringComparison]::OrdinalIgnoreCase)
}

function Stop-SaiaiForReplacement {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [ValidateSet("claude", "codex")][string]$Product = "claude"
    )

    $helpText = (& $Path --help | Out-String)
    if ($LASTEXITCODE -ne 0) { throw "Could not inspect the installed SAIAI client's environment support." }
    if ($helpText.Contains("--environment")) {
        Write-Host "Stopping only the selected SAIAI environment before updating..." -ForegroundColor DarkGray
        & $Path --environment $Product stop | Out-Host
    }
    else {
        $variable = if ($Product -eq "codex") { "CODEX_HOME" } else { "CLAUDE_CONFIG_DIR" }
        $defaultDirectory = Join-Path $env:USERPROFILE ("." + $Product)
        if ((Test-SaiaiDirectoryOverride -Name $variable -Default $defaultDirectory) -or
            (Test-SaiaiDirectoryOverride -Name "SAIAI_HOME" -Default (Join-Path $env:USERPROFILE ".saiai"))) {
            Write-Host "Preserving the old shared proxy while installing for a separate environment. If Windows prevents replacement, close the existing client explicitly and retry." -ForegroundColor DarkGray
            return
        }
        Write-Host "Stopping the legacy default SAIAI proxy before updating..." -ForegroundColor DarkGray
        & $Path stop | Out-Host
    }
    $stopExitCode = [int]$LASTEXITCODE
    if ($stopExitCode -ne 0) {
        throw "Selected SAIAI environment could not be stopped before update (exit $stopExitCode)."
    }
}

function Move-SaiaiCandidate {
    param(
        [Parameter(Mandatory = $true)][string]$Source,
        [Parameter(Mandatory = $true)][string]$Destination
    )

    # taskkill can return before Windows releases every executable handle held
    # by the detached proxy worker. Retry long enough for that normal teardown
    # race, but return as soon as the replacement succeeds.
    $maximumAttempts = 120
    $lastError = $null
    foreach ($attempt in 1..$maximumAttempts) {
        try {
            if (Test-Path -LiteralPath $Destination -PathType Leaf) {
                # The staged candidate lives in the installation directory, so
                # it is on the same volume as the installed executable.
                # File.Replace is the explicit Windows PowerShell 5.1 API for
                # replacing an existing file; it avoids relying on the
                # FileSystem provider's Move-Item error mapping.
                # PowerShell binds a null backup path as an empty path, so use
                # a unique same-volume temporary backup and remove it after
                # replacement. The user-visible rollback backup is managed
                # separately as saiai-previous.exe.
                $replacementBackup = Join-Path (Split-Path -Parent $Destination) (".saiai.replace." + [guid]::NewGuid().ToString("N") + ".bak")
                try {
                    [System.IO.File]::Replace($Source, $Destination, $replacementBackup, $true)
                }
                finally {
                    Remove-Item -LiteralPath $replacementBackup -Force -ErrorAction SilentlyContinue
                }
            }
            else {
                [System.IO.File]::Move($Source, $Destination)
            }
            return
        }
        catch {
            $lastError = $_
            if ($attempt -lt $maximumAttempts) {
                Start-Sleep -Milliseconds 250
            }
        }
    }
    throw "Could not replace existing SAIAI binary at $Destination after $maximumAttempts attempts: $($lastError.Exception.Message)"
}

function ConvertTo-WindowsCommandLineArgument {
    param([AllowNull()][AllowEmptyString()][string]$Value)

    # The per-argument ProcessStartInfo collection is only available on modern
    # .NET. The public wrapper must also run from inbox Windows PowerShell 5.1,
    # whose .NET Framework ProcessStartInfo exposes only the string Arguments API.
    # Quote with the CommandLineToArgvW/MSVC rules so the native CLI receives
    # precisely the original URL, Key, and optional flags.
    if ($null -eq $Value -or $Value.Length -eq 0) {
        return '""'
    }
    if ($Value -notmatch '[\s"]') {
        return $Value
    }

    $builder = [System.Text.StringBuilder]::new()
    $null = $builder.Append('"')
    $backslashCount = 0
    foreach ($character in $Value.ToCharArray()) {
        if ($character -eq [char]'\') {
            $backslashCount++
            continue
        }
        if ($character -eq [char]'"') {
            $null = $builder.Append((('\' * (($backslashCount * 2) + 1)) -join ''))
            $null = $builder.Append('"')
            $backslashCount = 0
            continue
        }
        if ($backslashCount -gt 0) {
            $null = $builder.Append((('\' * $backslashCount) -join ''))
            $backslashCount = 0
        }
        $null = $builder.Append($character)
    }
    if ($backslashCount -gt 0) {
        $null = $builder.Append((('\' * ($backslashCount * 2)) -join ''))
    }
    $null = $builder.Append('"')
    return $builder.ToString()
}

function Invoke-SaiaiNative {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string[]]$Arguments
    )

    # Native initialization may launch the detached local-proxy worker. Keep
    # its stdout attached to the invoking console rather than a PowerShell
    # output pipeline, whose inherited write handle could keep callers waiting
    # after the initializer has exited.
    $startInfo = [Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $Path
    $startInfo.UseShellExecute = $false
    $encodedArguments = @()
    foreach ($argument in $Arguments) {
        $encodedArguments += ConvertTo-WindowsCommandLineArgument -Value $argument
    }
    $startInfo.Arguments = [string]::Join(" ", [string[]]$encodedArguments)
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    try {
        $null = $process.Start()
        $process.WaitForExit()
        return [int]$process.ExitCode
    }
    finally {
        $process.Dispose()
    }
}

function Get-SaiaiRelease {
    param(
        [Parameter(Mandatory = $true)][Net.WebClient]$Client,
        [Parameter(Mandatory = $true)][string]$DownloadBase,
        [Parameter(Mandatory = $true)][string]$Asset,
        [Parameter(Mandatory = $true)][string]$ManifestPath
    )

    Write-Host "Checking SAIAI client release metadata..." -ForegroundColor Cyan
    $Client.DownloadFile("$DownloadBase/manifest.json", $ManifestPath)
    $manifest = Get-Content -LiteralPath $ManifestPath -Raw | ConvertFrom-Json
    if ([int]$manifest.manifest_schema -ne 1) {
        throw "Unsupported SAIAI manifest schema."
    }
    if ([string]$manifest.client_mode -cne "local-proxy") {
        throw "Release is not a SAIAI local-proxy client."
    }
    if ([int]$manifest.configuration_schema_version -ne 1) {
        throw "Unsupported SAIAI configuration schema."
    }
    $entry = $manifest.assets.PSObject.Properties[$Asset]
    if ($null -eq $entry) {
        throw "Manifest does not contain $Asset."
    }
    $release = [pscustomobject]@{
        Sha256 = [string]$entry.Value.sha256
        Size = [long]$entry.Value.size
        Version = [string]$manifest.version
    }
    if ($release.Sha256 -notmatch '^[0-9a-f]{64}$' -or $release.Size -le 0) {
        throw "Manifest metadata is invalid for $Asset."
    }
    return $release
}

function Save-SaiaiReleaseAsset {
    param(
        [Parameter(Mandatory = $true)][Net.WebClient]$Client,
        [Parameter(Mandatory = $true)][string]$DownloadBase,
        [Parameter(Mandatory = $true)][string]$Asset,
        [Parameter(Mandatory = $true)]$Release,
        [Parameter(Mandatory = $true)][string]$Destination
    )

    Write-Host "Downloading $Asset..." -ForegroundColor Cyan
    $Client.DownloadFile("$DownloadBase/$Asset", $Destination)
    if ((Get-Item -LiteralPath $Destination).Length -ne $Release.Size) {
        throw "Size mismatch for $Asset."
    }
    if ((Get-SaiaiSha256 -Path $Destination) -cne $Release.Sha256) {
        throw "SHA-256 mismatch for $Asset."
    }
}

function Get-SaiaiDownloadBase {
    if ([string]::IsNullOrWhiteSpace($env:SAIAI_DOWNLOAD_BASE)) {
        return "https://api.saiai.top/saiai-cli"
    }
    return $env:SAIAI_DOWNLOAD_BASE.TrimEnd('/')
}

function Test-SaiaiUninstallSupport {
    param([string]$Path, [string[]]$Arguments = @())

    if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return $false
    }
    $ErrorActionPreference = "Continue"
    try {
        $probe = @(& $Path uninstall --dry-run --yes @Arguments 2>$null)
        return ($LASTEXITCODE -eq 0) -and ($probe -ccontains "SAIAI uninstall plan")
    }
    catch {
        return $false
    }
}

# The native client is the only uninstall executor: find or download a capable
# client; this wrapper never deletes files itself.
function Invoke-SaiaiUninstall {
    param([string[]]$Arguments)

    foreach ($argument in $Arguments) {
        if (@("--yes", "--dry-run", "--forget-unknown-environments") -cnotcontains $argument) {
            [Console]::Error.WriteLine("Usage: Invoke-Saiai uninstall [--yes] [--dry-run] [--forget-unknown-environments]")
            return 2
        }
    }
    $candidates = @()
    try { $candidates += Get-SaiaiInstallPath } catch {}
    $command = Get-Command saiai -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($null -ne $command) { $candidates += $command.Source }
    $executor = $null
    foreach ($candidate in $candidates) {
        if (Test-SaiaiUninstallSupport -Path $candidate -Arguments $Arguments) {
            $executor = $candidate
            break
        }
    }
    $temporary = Join-Path ([System.IO.Path]::GetTempPath()) ("saiai-uninstall-" + [guid]::NewGuid().ToString("N"))
    try {
        if ($null -eq $executor) {
            Write-Host "No installed SAIAI client supports uninstall; downloading the current release to a temporary directory." -ForegroundColor DarkGray
            try {
                $null = New-Item -ItemType Directory -Path $temporary -Force
                [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
                $progressBefore = $ProgressPreference
                $ProgressPreference = "SilentlyContinue"
                $client = New-Object Net.WebClient
                try {
                    $asset = Get-SaiaiAssetName
                    $downloadBase = Get-SaiaiDownloadBase
                    $release = Get-SaiaiRelease -Client $client -DownloadBase $downloadBase -Asset $asset -ManifestPath (Join-Path $temporary "manifest.json")
                    $executor = Join-Path $temporary "saiai-uninstall.exe"
                    Save-SaiaiReleaseAsset -Client $client -DownloadBase $downloadBase -Asset $asset -Release $release -Destination $executor
                }
                finally {
                    $client.Dispose()
                    $ProgressPreference = $progressBefore
                }
            }
            catch {
                [Console]::Error.WriteLine("Could not download a SAIAI client that supports uninstall ($($_.Exception.Message)). Nothing was changed.")
                [Console]::Error.WriteLine("Retry when the network is available, or remove SAIAI manually: run ``saiai stop``, delete %USERPROFILE%\.saiai and %LOCALAPPDATA%\SAIAI, remove the SAIAI env entries from %USERPROFILE%\.claude\settings.json and the `"# BEGIN SAIAI CODEX IDE (managed)`" block from %USERPROFILE%\.codex\.env, then run ``codex login``.")
                return 1
            }
        }
        return Invoke-SaiaiNative -Path $executor -Arguments (@("uninstall") + $Arguments)
    }
    finally {
        Remove-Item -LiteralPath $temporary -Recurse -Force -ErrorAction SilentlyContinue
    }
}

function Invoke-Saiai {
    param(
        [Parameter(ValueFromRemainingArguments = $true)]
        [string[]]$Arguments
    )

    $provided = @($Arguments)
    if ($provided.Count -ge 1 -and $provided[0] -ceq "uninstall") {
        return Invoke-SaiaiUninstall -Arguments @($provided | Select-Object -Skip 1)
    }
    if ($provided.Count -lt 2) {
        Write-Error "Usage: Invoke-Saiai <base_url> <api_key> OR Invoke-Saiai init-codex <base_url> <api_key> [--websockets] OR Invoke-Saiai uninstall [--yes] [--dry-run] [--forget-unknown-environments]"
        return 2
    }

    $asset = Get-SaiaiAssetName
    $downloadBase = Get-SaiaiDownloadBase
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
            $release = Get-SaiaiRelease -Client $client -DownloadBase $downloadBase -Asset $asset -ManifestPath $manifestPath
            $expectedSha256 = $release.Sha256
            $releaseVersion = $release.Version

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
            $binaryUpdated = $false
            if ($installedMatches) {
                Write-Host "SAIAI $releaseVersion is already installed; binary download skipped." -ForegroundColor DarkGray
            }
            else {
                $binaryUpdated = $true
                Save-SaiaiReleaseAsset -Client $client -DownloadBase $downloadBase -Asset $asset -Release $release -Destination $candidatePath

                $installedExists = Test-Path -LiteralPath $installPath -PathType Leaf
                if ($installedExists) {
                    Stop-SaiaiForReplacement -Path $installPath -Product $(if ($provided[0] -eq "init-codex") { "codex" } else { "claude" })
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
        $previousBinaryUpdated = $env:SAIAI_BINARY_UPDATED
        $env:SAIAI_BINARY_UPDATED = if ($binaryUpdated) { "1" } else { "0" }
        # Keep the native client's human-readable stdout visible without
        # mixing it into this function's scalar exit-code result. PowerShell
        # otherwise captures both values when callers assign Invoke-Saiai.
        try {
            if ($provided[0] -eq "init-codex") {
                return Invoke-SaiaiNative -Path $installPath -Arguments $provided
            }

            $claudeArguments = @("init") + $provided
            return Invoke-SaiaiNative -Path $installPath -Arguments $claudeArguments
        }
        finally {
            $env:SAIAI_BINARY_UPDATED = $previousBinaryUpdated
        }
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
