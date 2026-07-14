@echo off
setlocal EnableExtensions DisableDelayedExpansion

rem Install the SAIAI V2 client binary. Product setup is performed by saiai.exe.
if not "%~2"=="" goto usage
if not "%~1"=="" if /I not "%~1"=="install" goto usage

set "ARCH=%PROCESSOR_ARCHITECTURE%"
if /I "%ARCH%"=="X86" if not "%PROCESSOR_ARCHITEW6432%"=="" set "ARCH=%PROCESSOR_ARCHITEW6432%"
if /I "%ARCH%"=="AMD64" set "ASSET=saiai-windows-x86_64.exe"
if /I "%ARCH%"=="X64" set "ASSET=saiai-windows-x86_64.exe"
if /I "%ARCH%"=="ARM64" set "ASSET=saiai-windows-aarch64.exe"
if /I "%ARCH%"=="AARCH64" set "ASSET=saiai-windows-aarch64.exe"
if not defined ASSET (
  echo Unsupported Windows architecture: %ARCH% 1>&2
  exit /b 1
)

if not "%SAIAI_DOWNLOAD_BASE%"=="" (
  set "DOWNLOAD_BASE=%SAIAI_DOWNLOAD_BASE%"
) else (
  set "DOWNLOAD_BASE=https://api.saiai.top/saiai-cli"
)
if "%DOWNLOAD_BASE:~-1%"=="/" set "DOWNLOAD_BASE=%DOWNLOAD_BASE:~0,-1%"

if not "%SAIAI_INSTALL_DIR%"=="" (
  set "INSTALL_DIR=%SAIAI_INSTALL_DIR%"
) else if not "%LOCALAPPDATA%"=="" (
  set "INSTALL_DIR=%LOCALAPPDATA%\SAIAI\bin"
) else if not "%USERPROFILE%"=="" (
  set "INSTALL_DIR=%USERPROFILE%\AppData\Local\SAIAI\bin"
) else (
  echo Cannot resolve the per-user install directory. Set SAIAI_INSTALL_DIR. 1>&2
  exit /b 1
)

set "TEMP_ROOT=%TEMP%\saiai-install-%RANDOM%%RANDOM%"
set "MANIFEST=%TEMP_ROOT%\manifest.json"
set "CANDIDATE=%TEMP_ROOT%\saiai.exe"
set "EXPECTED=%TEMP_ROOT%\expected.txt"
set "ACTUAL=%TEMP_ROOT%\actual.txt"
set "INSTALL_PATH=%INSTALL_DIR%\saiai.exe"
set "BACKUP_PATH=%INSTALL_DIR%\saiai-previous.exe"
set "STAGED_PATH=%INSTALL_DIR%\.saiai.install.%RANDOM%%RANDOM%.exe"
for %%I in ("%INSTALL_PATH%") do set "INSTALL_PATH=%%~fI"
for %%I in ("%BACKUP_PATH%") do set "BACKUP_PATH=%%~fI"
for %%I in ("%STAGED_PATH%") do set "STAGED_PATH=%%~fI"

mkdir "%TEMP_ROOT%" >nul 2>nul
mkdir "%INSTALL_DIR%" >nul 2>nul

echo Checking %DOWNLOAD_BASE%/manifest.json
powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command ^
  "$ErrorActionPreference='Stop'; $ProgressPreference='SilentlyContinue'; [Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12; $url=$env:DOWNLOAD_BASE.TrimEnd('/')+'/manifest.json'; (New-Object Net.WebClient).DownloadFile($url,$env:MANIFEST)"
if errorlevel 1 goto failed

powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command ^
  "$ErrorActionPreference='Stop'; $m=Get-Content -LiteralPath $env:MANIFEST -Raw | ConvertFrom-Json; if ([int]$m.manifest_schema -ne 1) { throw 'Unsupported manifest schema' }; if ([int]$m.bootstrap_schema_version -ne 2) { throw 'Incompatible bootstrap schema' }; $p=$m.assets.PSObject.Properties[$env:ASSET]; if ($null -eq $p) { throw 'Asset missing from manifest' }; $sha=[string]$p.Value.sha256; $size=[long]$p.Value.size; if ($sha -notmatch '^[0-9a-f]{64}$' -or $size -le 0) { throw 'Invalid asset metadata' }; [IO.File]::WriteAllLines($env:EXPECTED,@($sha,$size.ToString([Globalization.CultureInfo]::InvariantCulture)))"
if errorlevel 1 goto failed
set "EXPECTED_SIZE="
set /p EXPECTED_SHA256=<"%EXPECTED%"
for /f "skip=1 usebackq delims=" %%S in ("%EXPECTED%") do if not defined EXPECTED_SIZE set "EXPECTED_SIZE=%%S"

echo Downloading %DOWNLOAD_BASE%/%ASSET%
powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command ^
  "$ErrorActionPreference='Stop'; $ProgressPreference='SilentlyContinue'; [Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12; $url=$env:DOWNLOAD_BASE.TrimEnd('/')+'/'+$env:ASSET; (New-Object Net.WebClient).DownloadFile($url,$env:CANDIDATE)"
if errorlevel 1 goto failed

powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command ^
  "$ErrorActionPreference='Stop'; $sha=[Security.Cryptography.SHA256]::Create(); $stream=[IO.File]::OpenRead($env:CANDIDATE); try { $hash=([BitConverter]::ToString($sha.ComputeHash($stream))).Replace('-','').ToLowerInvariant(); [IO.File]::WriteAllLines($env:ACTUAL,@($hash,$stream.Length.ToString([Globalization.CultureInfo]::InvariantCulture))) } finally { $stream.Dispose(); $sha.Dispose() }"
if errorlevel 1 goto failed
set /p ACTUAL_SHA256=<"%ACTUAL%"
set "ACTUAL_SIZE="
for /f "skip=1 usebackq delims=" %%S in ("%ACTUAL%") do if not defined ACTUAL_SIZE set "ACTUAL_SIZE=%%S"
if /I not "%ACTUAL_SHA256%"=="%EXPECTED_SHA256%" (
  echo SHA-256 mismatch for %ASSET%. 1>&2
  goto failed
)
if not "%ACTUAL_SIZE%"=="%EXPECTED_SIZE%" (
  echo Size mismatch for %ASSET%. 1>&2
  goto failed
)

powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command ^
  "$ErrorActionPreference='Stop'; $path=$env:INSTALL_PATH; if (Test-Path -LiteralPath $path) { $item=Get-Item -LiteralPath $path -Force; if ($item.PSIsContainer) { throw 'Install path is a directory' }; if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Refusing to replace a reparse-point install path' }; $sha=[Security.Cryptography.SHA256]::Create(); $stream=[IO.File]::OpenRead($path); try { $hash=([BitConverter]::ToString($sha.ComputeHash($stream))).Replace('-','').ToLowerInvariant() } finally { $stream.Dispose(); $sha.Dispose() }; if ($hash -cne $env:ACTUAL_SHA256 -and -not (Test-Path -LiteralPath $env:BACKUP_PATH)) { [IO.File]::Copy($path,$env:BACKUP_PATH,$false); Write-Host ('Preserved the previous client at '+$env:BACKUP_PATH) } }"
if errorlevel 1 goto failed

copy /B /Y "%CANDIDATE%" "%STAGED_PATH%" >nul
if errorlevel 1 (
  echo Could not stage SAIAI in %INSTALL_DIR%. 1>&2
  goto failed
)
move /Y "%STAGED_PATH%" "%INSTALL_PATH%" >nul
if errorlevel 1 (
  echo Could not replace %INSTALL_PATH%. Stop any running SAIAI process and try again. 1>&2
  goto failed
)

rd /s /q "%TEMP_ROOT%" >nul 2>nul
echo SAIAI V2 installed at %INSTALL_PATH%
echo Next: "%INSTALL_PATH%" claude or "%INSTALL_PATH%" codex
echo Explicit setup: "%INSTALL_PATH%" setup claude or "%INSTALL_PATH%" setup codex
exit /b 0

:usage
echo Usage: setup.cmd [install] 1>&2
echo This wrapper installs only. Product setup is performed by saiai.exe. 1>&2
exit /b 2

:failed
del /F /Q "%STAGED_PATH%" >nul 2>nul
rd /s /q "%TEMP_ROOT%" >nul 2>nul
echo SAIAI V2 installation failed. 1>&2
exit /b 1
