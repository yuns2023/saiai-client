param([Parameter(Mandatory = $true)][string]$WrapperPath)
$ErrorActionPreference = 'Stop'
. $WrapperPath
$temporary = Join-Path ([IO.Path]::GetTempPath()) ('saiai-wrapper-scope-' + [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $temporary
$names = @('CODEX_HOME', 'CLAUDE_CONFIG_DIR', 'SAIAI_HOME', 'SAIAI_WRAPPER_CALLS', 'USERPROFILE')
$saved = @{}
foreach ($name in $names) { $saved[$name] = [Environment]::GetEnvironmentVariable($name, 'Process') }
try {
    $env:USERPROFILE = Join-Path $temporary 'home'
    $env:SAIAI_HOME = Join-Path $env:USERPROFILE '.saiai'
    $env:CODEX_HOME = Join-Path $temporary 'codex-project'
    $env:CLAUDE_CONFIG_DIR = Join-Path $temporary 'claude-project'
    $env:SAIAI_WRAPPER_CALLS = Join-Path $temporary 'calls.txt'
    $legacy = Join-Path $temporary 'legacy.cmd'
    $modern = Join-Path $temporary 'modern.cmd'
    $template = @'
@echo off
if "%~1"=="--help" (
  echo HELP_TEXT
  exit /b 0
)
echo %*>>"%SAIAI_WRAPPER_CALLS%"
exit /b 0
'@
    [IO.File]::WriteAllText($legacy, $template.Replace('HELP_TEXT', 'legacy client'), [Text.Encoding]::ASCII)
    [IO.File]::WriteAllText($modern, $template.Replace('HELP_TEXT', '--environment claude codex default'), [Text.Encoding]::ASCII)
    Stop-SaiaiForReplacement -Path $legacy -Product codex
    if (Test-Path $env:SAIAI_WRAPPER_CALLS) { throw 'project setup called the legacy shared stop' }
    Stop-SaiaiForReplacement -Path $modern -Product codex
    $calls = [IO.File]::ReadAllText($env:SAIAI_WRAPPER_CALLS).Trim()
    if ($calls -cne '--environment codex stop') { throw 'modern wrapper did not select the product environment' }
    Remove-Item $env:SAIAI_WRAPPER_CALLS
    $env:CODEX_HOME = $null
    Stop-SaiaiForReplacement -Path $legacy -Product codex
    if ([IO.File]::ReadAllText($env:SAIAI_WRAPPER_CALLS).Trim() -cne 'stop') { throw 'legacy default update was not preserved' }
    Remove-Item $env:SAIAI_WRAPPER_CALLS
    $env:SAIAI_HOME = Join-Path $temporary 'separate-root'
    Stop-SaiaiForReplacement -Path $legacy -Product codex
    if (Test-Path $env:SAIAI_WRAPPER_CALLS) { throw 'custom root setup stopped the legacy shared proxy' }
    Write-Host 'Windows wrapper environment routing passed; no real service or network operations'
}
finally {
    foreach ($name in $names) { [Environment]::SetEnvironmentVariable($name, $saved[$name], 'Process') }
    Remove-Item $temporary -Recurse -Force
}
