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

$binary = (Resolve-Path -LiteralPath $BinaryPath).Path
$temporary = Join-Path ([IO.Path]::GetTempPath()) ("saiai-config-windows-runtime-" + [guid]::NewGuid().ToString("N"))
$claudeDir = Join-Path $temporary ".claude"
$settingsPath = Join-Path $claudeDir "settings.json"
$statePath = Join-Path $claudeDir ".claude.json"
$credentialsPath = Join-Path $claudeDir ".credentials.json"
$caPath = Join-Path $claudeDir "saiai-ca.crt"
$testKey = "TEST_ONLY_WINDOWS_RUNTIME_KEY"
$savedConfigDir = $env:CLAUDE_CONFIG_DIR

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

    $output = & $binary "https://gateway.example.test" $testKey 2>&1 | Out-String
    Assert-Saiai ($LASTEXITCODE -eq 0) "SAIAI config command failed: $output"
    Assert-Saiai (-not $output.Contains($testKey)) "SAIAI output exposed the API key"

    $settings = Get-Content -LiteralPath $settingsPath -Raw | ConvertFrom-Json
    Assert-Saiai ([string]$settings.env.ANTHROPIC_BASE_URL -ceq "https://gateway.example.test") "Gateway differs"
    Assert-Saiai ([string]$settings.env.CLAUDE_CODE_OAUTH_TOKEN -ceq $testKey) "API key differs"
    Assert-Saiai ([string]$settings.env.CLAUDE_STREAM_IDLE_TIMEOUT_MS -ceq "600000") "Timeout differs"
    Assert-Saiai ([string]$settings.env.KEEP_ME -ceq "yes") "Unrelated env was lost"
    Assert-Saiai ($null -eq $settings.env.PSObject.Properties["ANTHROPIC_AUTH_TOKEN"]) "Conflicting auth token remains"
    Assert-Saiai ($null -eq $settings.env.PSObject.Properties["HTTP_PROXY"]) "Conflicting proxy remains"
    Assert-Saiai (@($settings.permissions.allow) -contains "Read") "Unrelated settings were lost"

    $state = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
    Assert-Saiai ($null -eq $state.PSObject.Properties["oauthAccount"]) "oauthAccount remains"
    Assert-Saiai ([string]$state.userID -ceq "kept") "Machine identity was lost"
    Assert-Saiai (-not (Test-Path -LiteralPath $credentialsPath)) "OAuth credentials remain"
    Assert-Saiai (-not (Test-Path -LiteralPath $caPath)) "Old SAIAI CA remains"

    $doctor = & $binary doctor 2>&1 | Out-String
    Assert-Saiai ($LASTEXITCODE -eq 0) "SAIAI doctor failed: $doctor"
    Assert-Saiai ($doctor.Contains("value hidden")) "Doctor did not hide the key"
    Assert-Saiai (-not $doctor.Contains($testKey)) "Doctor exposed the key"
}
finally {
    $env:CLAUDE_CONFIG_DIR = $savedConfigDir
    Remove-Item -LiteralPath $temporary -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host "SAIAI global-config Windows runtime smoke passed"
$global:LASTEXITCODE = 0
