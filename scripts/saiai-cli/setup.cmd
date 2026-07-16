@echo off
setlocal EnableExtensions DisableDelayedExpansion

rem Install or reuse SAIAI, apply config, and start the Claude local proxy.
if "%~2"=="" goto usage

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
set "INSTALLED_HASH=%TEMP_ROOT%\installed-hash.txt"
set "INSTALL_PATH=%INSTALL_DIR%\saiai.exe"
set "BACKUP_PATH=%INSTALL_DIR%\saiai-previous.exe"
set "STAGED_PATH=%INSTALL_DIR%\.saiai.install.%RANDOM%%RANDOM%.exe"
for %%I in ("%INSTALL_PATH%") do set "INSTALL_PATH=%%~fI"
for %%I in ("%BACKUP_PATH%") do set "BACKUP_PATH=%%~fI"
for %%I in ("%STAGED_PATH%") do set "STAGED_PATH=%%~fI"

mkdir "%TEMP_ROOT%" >nul 2>nul
mkdir "%INSTALL_DIR%" >nul 2>nul

echo Checking SAIAI client release metadata...
powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command ^
  "$ErrorActionPreference='Stop'; $ProgressPreference='SilentlyContinue'; [Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12; $url=$env:DOWNLOAD_BASE.TrimEnd('/')+'/manifest.json'; (New-Object Net.WebClient).DownloadFile($url,$env:MANIFEST)"
if errorlevel 1 goto failed

powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command ^
  "$ErrorActionPreference='Stop'; $m=Get-Content -LiteralPath $env:MANIFEST -Raw ^| ConvertFrom-Json; if ([int]$m.manifest_schema -ne 1) { throw 'Unsupported manifest schema' }; if ([string]$m.client_mode -cne 'local-proxy') { throw 'Release is not a local-proxy client' }; if ([int]$m.configuration_schema_version -ne 1) { throw 'Unsupported configuration schema' }; $p=$m.assets.PSObject.Properties[$env:ASSET]; if ($null -eq $p) { throw 'Asset missing from manifest' }; $sha=[string]$p.Value.sha256; $size=[long]$p.Value.size; $version=[string]$m.version; if ($sha -notmatch '^[0-9a-f]{64}$' -or $size -le 0) { throw 'Invalid asset metadata' }; [IO.File]::WriteAllLines($env:EXPECTED,@($sha,$size.ToString([Globalization.CultureInfo]::InvariantCulture),$version))"
if errorlevel 1 goto failed
set /p EXPECTED_SHA256=<"%EXPECTED%"
set "EXPECTED_SIZE="
set "RELEASE_VERSION="
for /f "skip=1 usebackq tokens=1,* delims=:" %%A in (`findstr /n "^" "%EXPECTED%"`) do (
  if "%%A"=="2" set "EXPECTED_SIZE=%%B"
  if "%%A"=="3" set "RELEASE_VERSION=%%B"
)

if exist "%INSTALL_PATH%\" (
  echo Install path is a directory: %INSTALL_PATH% 1>&2
  goto failed
)

set "INSTALLED_MATCHES=0"
if exist "%INSTALL_PATH%" (
  powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command ^
    "$ErrorActionPreference='Stop'; $item=Get-Item -LiteralPath $env:INSTALL_PATH -Force; if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Refusing to use a reparse-point install path' }; $hash=(Get-FileHash -LiteralPath $env:INSTALL_PATH -Algorithm SHA256).Hash.ToLowerInvariant(); [IO.File]::WriteAllText($env:INSTALLED_HASH,$hash)"
  if errorlevel 1 goto failed
  set /p ACTUAL_INSTALLED_SHA256=<"%INSTALLED_HASH%"
  if /I "%ACTUAL_INSTALLED_SHA256%"=="%EXPECTED_SHA256%" set "INSTALLED_MATCHES=1"
)

if "%INSTALLED_MATCHES%"=="1" (
  echo SAIAI %RELEASE_VERSION% is already installed; binary download skipped.
  goto configure
)

echo Downloading %ASSET%...
powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command ^
  "$ErrorActionPreference='Stop'; $ProgressPreference='SilentlyContinue'; [Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12; $url=$env:DOWNLOAD_BASE.TrimEnd('/')+'/'+$env:ASSET; (New-Object Net.WebClient).DownloadFile($url,$env:CANDIDATE); $item=Get-Item -LiteralPath $env:CANDIDATE; if ($item.Length -ne [long]$env:EXPECTED_SIZE) { throw 'Size mismatch' }; $hash=(Get-FileHash -LiteralPath $env:CANDIDATE -Algorithm SHA256).Hash.ToLowerInvariant(); if ($hash -cne $env:EXPECTED_SHA256) { throw 'SHA-256 mismatch' }"
if errorlevel 1 goto failed

if exist "%INSTALL_PATH%" if not exist "%BACKUP_PATH%" copy /B /Y "%INSTALL_PATH%" "%BACKUP_PATH%" >nul
copy /B /Y "%CANDIDATE%" "%STAGED_PATH%" >nul
if errorlevel 1 goto failed
move /Y "%STAGED_PATH%" "%INSTALL_PATH%" >nul
if errorlevel 1 goto failed
echo Installed SAIAI %RELEASE_VERSION% at %INSTALL_PATH%.

:configure
if /I "%~1"=="init-codex" goto configure_codex
"%INSTALL_PATH%" init %*
set "SAIAI_EXIT=%ERRORLEVEL%"
if not "%SAIAI_EXIT%"=="0" goto configured
if "%SAIAI_SKIP_START%"=="1" goto configured
"%INSTALL_PATH%" start
set "SAIAI_EXIT=%ERRORLEVEL%"
goto configured

:configure_codex
"%INSTALL_PATH%" %*
set "SAIAI_EXIT=%ERRORLEVEL%"

:configured
rd /s /q "%TEMP_ROOT%" >nul 2>nul
exit /b %SAIAI_EXIT%

:usage
echo Usage: setup.cmd ^<base_url^> ^<api_key^> 1>&2
echo    or: setup.cmd init-codex ^<base_url^> ^<api_key^> [--websockets] 1>&2
exit /b 2

:failed
del /F /Q "%STAGED_PATH%" >nul 2>nul
rd /s /q "%TEMP_ROOT%" >nul 2>nul
echo SAIAI setup failed. 1>&2
exit /b 1
