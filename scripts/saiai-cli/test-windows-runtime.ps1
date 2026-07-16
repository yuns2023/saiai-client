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
$caKeyPath = Join-Path $claudeDir "saiai-ca.key"
$testKey = "TEST_ONLY_WINDOWS_RUNTIME_KEY"
$replacementKey = "TEST_ONLY_WINDOWS_REPLACEMENT_KEY"
$savedConfigDir = $env:CLAUDE_CONFIG_DIR
$savedSaiaiHome = $env:SAIAI_HOME

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
    $env:SAIAI_HOME = Join-Path $temporary ".saiai"

    $output = & $binary init "https://gateway.example.test" $testKey 2>&1 | Out-String
    Assert-Saiai ($LASTEXITCODE -eq 0) "SAIAI config command failed: $output"
    Assert-Saiai (-not $output.Contains($testKey)) "SAIAI output exposed the API key"

    $settings = Get-Content -LiteralPath $settingsPath -Raw | ConvertFrom-Json
    Assert-Saiai ($null -eq $settings.env.PSObject.Properties["ANTHROPIC_BASE_URL"]) "Direct gateway override remains"
    Assert-Saiai ([string]$settings.env.CLAUDE_CODE_OAUTH_TOKEN -ceq $testKey) "API key differs"
    Assert-Saiai ([string]$settings.env.CLAUDE_STREAM_IDLE_TIMEOUT_MS -ceq "600000") "Timeout differs"
    Assert-Saiai ([string]$settings.env.KEEP_ME -ceq "yes") "Unrelated env was lost"
    Assert-Saiai ($null -eq $settings.env.PSObject.Properties["ANTHROPIC_AUTH_TOKEN"]) "Conflicting auth token remains"
    Assert-Saiai ([string]$settings.env.HTTP_PROXY -ceq "http://127.0.0.1:19908") "Local proxy differs"
    Assert-Saiai ([string]$settings.env.NODE_EXTRA_CA_CERTS -ceq $caPath) "CA path differs"
    Assert-Saiai (@($settings.permissions.allow) -contains "Read") "Unrelated settings were lost"

    $state = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
    Assert-Saiai ($null -eq $state.PSObject.Properties["oauthAccount"]) "oauthAccount remains"
    Assert-Saiai ([string]$state.userID -ceq "kept") "Machine identity was lost"
    Assert-Saiai (-not (Test-Path -LiteralPath $credentialsPath)) "OAuth credentials remain"
    Assert-Saiai (Test-Path -LiteralPath $caPath -PathType Leaf) "Installation CA was not generated"
    Assert-Saiai (Test-Path -LiteralPath $caKeyPath -PathType Leaf) "Installation CA key was not generated"

    $caHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $caPath).Hash
    $caKeyHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $caKeyPath).Hash
    $repeatOutput = & $binary init "https://replacement.example.test" $replacementKey 2>&1 | Out-String
    Assert-Saiai ($LASTEXITCODE -eq 0) "Repeated SAIAI config failed: $repeatOutput"
    Assert-Saiai (-not $repeatOutput.Contains($replacementKey)) "Repeated config output exposed the API key"
    Assert-Saiai ((Get-FileHash -Algorithm SHA256 -LiteralPath $caPath).Hash -ceq $caHash) "Repeated setup replaced a valid CA"
    Assert-Saiai ((Get-FileHash -Algorithm SHA256 -LiteralPath $caKeyPath).Hash -ceq $caKeyHash) "Repeated setup replaced a valid CA key"
    $repeatedSettings = Get-Content -LiteralPath $settingsPath -Raw | ConvertFrom-Json
    Assert-Saiai ([string]$repeatedSettings.env.CLAUDE_CODE_OAUTH_TOKEN -ceq $replacementKey) "Repeated setup did not replace the API key"
    $saiaiConfig = Get-Content -LiteralPath (Join-Path $env:SAIAI_HOME "config.json") -Raw | ConvertFrom-Json
    Assert-Saiai ([string]$saiaiConfig.base_url -ceq "https://replacement.example.test") "Repeated setup did not replace the Gateway"
    Assert-Saiai ([string]$saiaiConfig.api_key -ceq $replacementKey) "Repeated setup config Key differs"

    $help = & $binary --help 2>&1 | Out-String
    Assert-Saiai ($LASTEXITCODE -eq 0) "SAIAI help failed: $help"
    Assert-Saiai ($help.Contains("saiai start")) "Local-proxy commands are missing"
    Assert-Saiai (-not $help.Contains($testKey)) "Help exposed the key"
}
finally {
    $env:CLAUDE_CONFIG_DIR = $savedConfigDir
    $env:SAIAI_HOME = $savedSaiaiHome
    Remove-Item -LiteralPath $temporary -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host "SAIAI local-proxy Windows runtime smoke passed"
$global:LASTEXITCODE = 0
