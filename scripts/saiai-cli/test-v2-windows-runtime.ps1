[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$BinaryPath,

    [ValidateRange(5, 120)]
    [int]$CommandTimeoutSeconds = 30
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
Set-StrictMode -Version Latest

$claudeKey = "TEST_ONLY_WINDOWS_RUNTIME_CLAUDE_KEY"
$codexKey = "TEST_ONLY_WINDOWS_RUNTIME_CODEX_KEY"
$testKeys = @($claudeKey, $codexKey)
$utf8NoBom = [System.Text.UTF8Encoding]::new($false)
$commandResults = [System.Collections.Generic.List[object]]::new()

function Assert-Saiai {
    param(
        [bool]$Condition,
        [string]$Message
    )
    if (-not $Condition) {
        throw $Message
    }
}

function Assert-NoSaiaiSecret {
    param([AllowEmptyString()][string]$Text)
    foreach ($key in $testKeys) {
        if ($Text.Contains($key, [System.StringComparison]::Ordinal)) {
            throw "SAIAI V2 Windows runtime output exposed a test API key"
        }
    }
}

function Test-SamePath {
    param(
        [string]$Left,
        [string]$Right
    )
    $separators = [char[]]@(
        [System.IO.Path]::DirectorySeparatorChar,
        [System.IO.Path]::AltDirectorySeparatorChar
    )
    return [string]::Equals(
        [System.IO.Path]::GetFullPath($Left).TrimEnd($separators),
        [System.IO.Path]::GetFullPath($Right).TrimEnd($separators),
        [System.StringComparison]::OrdinalIgnoreCase
    )
}

function Invoke-SaiaiRuntimeCommand {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$CommandArguments,

        [AllowNull()]
        [string]$StandardInput,

        [Parameter(Mandatory = $true)]
        [System.Collections.IDictionary]$EnvironmentOverrides
    )

    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $script:binary
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardInput = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    foreach ($argument in $CommandArguments) {
        $null = $startInfo.ArgumentList.Add([string]$argument)
    }
    foreach ($entry in $EnvironmentOverrides.GetEnumerator()) {
        $name = [string]$entry.Key
        if ($null -eq $entry.Value) {
            $null = $startInfo.Environment.Remove($name)
        }
        else {
            $startInfo.Environment[$name] = [string]$entry.Value
        }
    }

    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    $stdout = ""
    $stderr = ""
    $timedOut = $false
    try {
        Assert-Saiai ($process.Start()) "Could not start the built saiai.exe"
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        if ($null -ne $StandardInput) {
            $process.StandardInput.Write($StandardInput)
        }
        $process.StandardInput.Close()

        if (-not $process.WaitForExit($CommandTimeoutSeconds * 1000)) {
            $timedOut = $true
            try {
                $process.Kill($true)
            }
            catch {
                $process.Kill()
            }
            Assert-Saiai ($process.WaitForExit(5000)) "Timed-out saiai.exe could not be terminated"
        }
        $stdout = $stdoutTask.GetAwaiter().GetResult()
        $stderr = $stderrTask.GetAwaiter().GetResult()
        $exitCode = $process.ExitCode
    }
    finally {
        $process.Dispose()
    }

    Assert-NoSaiaiSecret ($stdout + $stderr)
    $displayCommand = "saiai " + ($CommandArguments -join " ")
    Assert-Saiai (-not $timedOut) "$displayCommand exceeded the bounded command timeout"
    Assert-Saiai ($exitCode -eq 0) "$displayCommand failed with exit code $exitCode`nstdout:`n$stdout`nstderr:`n$stderr"

    $result = [pscustomobject]@{
        Arguments = @($CommandArguments)
        Stdout = $stdout
        Stderr = $stderr
        ExitCode = $exitCode
    }
    $commandResults.Add($result)
    return $result
}

function Read-SaiaiConfigState {
    param(
        [string]$ConfigPath,
        [string]$DataRoot
    )
    Assert-Saiai (Test-Path -LiteralPath $ConfigPath -PathType Leaf) "V2 config.json is missing"
    $configText = [System.IO.File]::ReadAllText($ConfigPath, $utf8NoBom)
    Assert-NoSaiaiSecret $configText
    $config = $configText | ConvertFrom-Json
    Assert-Saiai ([int]$config.schema_version -eq 2) "V2 config is not schema 2"

    $productNames = @($config.products.PSObject.Properties.Name)
    Assert-Saiai ($productNames.Count -gt 0) "V2 config has no configured product"
    $homes = @{}
    $credentialRefs = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase
    )
    foreach ($productName in $productNames) {
        Assert-Saiai ($productName -in @("claude", "codex")) "V2 config contains an unexpected product"
        $entry = $config.products.$productName
        $generation = [string]$entry.active_generation
        $credentialRef = [string]$entry.credential_ref
        Assert-Saiai (-not [string]::IsNullOrWhiteSpace($generation)) "$productName has no active generation"
        Assert-Saiai (-not [string]::IsNullOrWhiteSpace($credentialRef)) "$productName has no credential reference"
        Assert-Saiai ($credentialRefs.Add($credentialRef)) "Configured products share a credential reference"
        $homes[$productName] = Join-Path $DataRoot "generations\$generation\clients\$productName"
    }
    return [pscustomobject]@{
        Config = $config
        ProductNames = $productNames
        Homes = $homes
    }
}

function Assert-NoProductHome {
    param(
        [string]$DataRoot,
        [string]$Product
    )
    $generations = Join-Path $DataRoot "generations"
    if (-not (Test-Path -LiteralPath $generations -PathType Container)) {
        return
    }
    foreach ($generation in Get-ChildItem -LiteralPath $generations -Directory -Force) {
        $candidate = Join-Path $generation.FullName "clients\$Product"
        Assert-Saiai (-not (Test-Path -LiteralPath $candidate)) "Setup unexpectedly generated a $Product home"
    }
}

function Assert-LegacySentinels {
    param([System.Collections.IDictionary]$Sentinels)
    foreach ($entry in $Sentinels.GetEnumerator()) {
        Assert-Saiai (Test-Path -LiteralPath $entry.Key -PathType Leaf) "V2 changed a legacy sentinel"
        $actual = [System.IO.File]::ReadAllText([string]$entry.Key, $utf8NoBom)
        Assert-Saiai ($actual -eq [string]$entry.Value) "V2 changed a legacy sentinel"
    }
}

function Read-Capture {
    param([string]$Path)
    Assert-Saiai (Test-Path -LiteralPath $Path -PathType Leaf) "Fake client did not write its launch capture"
    $text = [System.IO.File]::ReadAllText($Path, $utf8NoBom)
    Assert-NoSaiaiSecret $text
    return $text | ConvertFrom-Json
}

function Assert-ExactArguments {
    param(
        [object]$Capture,
        [string[]]$Expected
    )
    $actual = @($Capture.arguments)
    Assert-Saiai ($actual.Count -eq $Expected.Count) "Client launch changed the argument count"
    for ($index = 0; $index -lt $Expected.Count; $index++) {
        Assert-Saiai ([string]$actual[$index] -ceq $Expected[$index]) "Client launch changed an argument"
    }
}

$binary = (Resolve-Path -LiteralPath $BinaryPath).Path
Assert-Saiai ([System.IO.Path]::GetExtension($binary) -ieq ".exe") "Windows runtime smoke requires the built saiai.exe"
$nodeCommand = Get-Command node.exe -CommandType Application -ErrorAction Stop |
    Select-Object -First 1
$node = $nodeCommand.Source
Assert-Saiai ([System.IO.Path]::IsPathFullyQualified($node)) "Runner node.exe did not resolve to an absolute path"
$nodeDirectory = Split-Path -Parent $node
$pythonCommand = Get-Command python.exe -CommandType Application -ErrorAction SilentlyContinue |
    Select-Object -First 1
if ($null -eq $pythonCommand) {
    $pythonCommand = Get-Command python -CommandType Application -ErrorAction Stop |
        Select-Object -First 1
}
$python = $pythonCommand.Source
Assert-Saiai ([System.IO.Path]::IsPathFullyQualified($python)) "Runner Python did not resolve to an absolute path"

$temporary = Join-Path ([System.IO.Path]::GetTempPath()) ("saiai-v2-windows-runtime-" + [guid]::NewGuid().ToString("N"))
$isolatedHome = Join-Path $temporary "home"
$localAppData = Join-Path $temporary "local-app-data"
$roamingAppData = Join-Path $temporary "roaming-app-data"
$temporaryFiles = Join-Path $temporary "tmp"
$fakeBin = Join-Path $temporary "npm-bin"
$output = Join-Path $temporary "capture"
$configRoot = Join-Path $localAppData "SAIAI\config"
$dataRoot = Join-Path $localAppData "SAIAI\data"
$stateRoot = Join-Path $localAppData "SAIAI\state"
$configPath = Join-Path $configRoot "config.json"
$fixtureScript = Join-Path $temporary "bootstrap-fixture.py"
$fixturePortFile = Join-Path $temporary "bootstrap-port.txt"
$fixtureCallsFile = Join-Path $temporary "bootstrap-calls.json"
$fixtureProcess = $null
$fixtureStdoutTask = $null
$fixtureStderrTask = $null

try {
    foreach ($directory in @(
        $isolatedHome,
        $localAppData,
        $roamingAppData,
        $temporaryFiles,
        $fakeBin,
        $output
    )) {
        $null = New-Item -ItemType Directory -Path $directory -Force
    }

    $legacySentinels = [ordered]@{
        (Join-Path $isolatedHome ".saiai\sentinel") = "legacy-saiai`n"
        (Join-Path $isolatedHome ".claude\sentinel") = "legacy-claude`n"
        (Join-Path $isolatedHome ".claude\.credentials.json") = "legacy-credentials`n"
        (Join-Path $isolatedHome ".claude.json") = "legacy-claude-state`n"
        (Join-Path $isolatedHome ".codex\sentinel") = "legacy-codex`n"
    }
    foreach ($entry in $legacySentinels.GetEnumerator()) {
        $null = New-Item -ItemType Directory -Path (Split-Path -Parent $entry.Key) -Force
        [System.IO.File]::WriteAllText([string]$entry.Key, [string]$entry.Value, $utf8NoBom)
    }

    # Deliberately invalid marker bodies prove the launcher never executes or parses .cmd.
    foreach ($markerName in @("claude.cmd", "codex.cmd")) {
        [System.IO.File]::WriteAllText(
            (Join-Path $fakeBin $markerName),
            "@echo off`r`nexit /b 97`r`n",
            $utf8NoBom
        )
    }
    $claudeEntry = Join-Path $fakeBin "node_modules\@anthropic-ai\claude-code\cli.js"
    $codexEntry = Join-Path $fakeBin "node_modules\@openai\codex\bin\codex.js"
    $null = New-Item -ItemType Directory -Path (Split-Path -Parent $claudeEntry) -Force
    $null = New-Item -ItemType Directory -Path (Split-Path -Parent $codexEntry) -Force

    $claudeSource = @'
"use strict";
const fs = require("fs");
const path = require("path");
const args = process.argv.slice(2);
if (args.length === 1 && args[0] === "--version") {
  process.stdout.write("claude 1.2.3 windows-runtime-test\n");
  process.exit(0);
}
function requireTest(condition) {
  if (!condition) process.exit(64);
}
const env = process.env;
requireTest(env.CLAUDE_CODE_OAUTH_TOKEN === env.SAIAI_TEST_EXPECTED_CLAUDE_KEY);
requireTest(env.CLAUDE_STREAM_IDLE_TIMEOUT_MS === "600000");
requireTest(Boolean(env.CLAUDE_CONFIG_DIR));
requireTest(Boolean(env.HTTP_PROXY));
requireTest(env.HTTP_PROXY === env.HTTPS_PROXY && env.HTTP_PROXY === env.ALL_PROXY);
const proxy = new URL(env.HTTP_PROXY);
requireTest(proxy.protocol === "http:" && proxy.hostname === "127.0.0.1" && Boolean(proxy.port));
requireTest(Boolean(env.NODE_EXTRA_CA_CERTS) && fs.existsSync(env.NODE_EXTRA_CA_CERTS));
for (const name of [
  "ANTHROPIC_BASE_URL", "ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_API_KEY",
  "CLAUDE_CODE_USE_BEDROCK", "CLAUDE_CODE_USE_VERTEX", "CLAUDE_CODE_USE_FOUNDRY"
]) requireTest(env[name] === undefined);
const capture = {
  arguments: args,
  runtime: { executable: process.execPath, entry: process.argv[1] },
  environment: {
    home: env.CLAUDE_CONFIG_DIR,
    proxy: env.HTTP_PROXY,
    noProxy: env.NO_PROXY,
    ca: env.NODE_EXTRA_CA_CERTS,
    streamIdleTimeout: env.CLAUDE_STREAM_IDLE_TIMEOUT_MS,
    disableNonessentialTraffic: env.CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC,
    promptCaching: env.ENABLE_PROMPT_CACHING_1H,
    toolSearch: env.ENABLE_TOOL_SEARCH
  }
};
fs.writeFileSync(path.join(env.SAIAI_TEST_OUTPUT, "claude-capture.json"), JSON.stringify(capture));
'@
    $codexSource = @'
"use strict";
const fs = require("fs");
const path = require("path");
const args = process.argv.slice(2);
if (args.length === 1 && args[0] === "--version") {
  process.stdout.write("codex-cli 1.2.3 windows-runtime-test\n");
  process.exit(0);
}
function requireTest(condition) {
  if (!condition) process.exit(64);
}
const env = process.env;
requireTest(env.SAIAI_CODEX_API_KEY === env.SAIAI_TEST_EXPECTED_CODEX_KEY);
requireTest(Boolean(env.CODEX_HOME));
for (const name of [
  "OPENAI_API_KEY", "OPENAI_BASE_URL", "OPENAI_ORG_ID", "OPENAI_PROJECT_ID",
  "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
  "http_proxy", "https_proxy", "all_proxy", "no_proxy"
]) requireTest(env[name] === undefined);
const capture = {
  arguments: args,
  runtime: { executable: process.execPath, entry: process.argv[1] },
  environment: { home: env.CODEX_HOME }
};
fs.writeFileSync(path.join(env.SAIAI_TEST_OUTPUT, "codex-capture.json"), JSON.stringify(capture));
'@
    [System.IO.File]::WriteAllText($claudeEntry, $claudeSource, $utf8NoBom)
    [System.IO.File]::WriteAllText($codexEntry, $codexSource, $utf8NoBom)

    $fixtureSource = @'
import http.server
import json
import os
from pathlib import Path
import sys
import time


EXPECTED = ("claude", "codex")


class Handler(http.server.BaseHTTPRequestHandler):
    calls = []
    failed = False

    def log_message(self, _format, *_args):
        return

    def do_GET(self):
        if self.path != "/api/v1/client/bootstrap":
            type(self).failed = True
            self.send_error(404)
            return
        authorization = self.headers.get("Authorization")
        if authorization == "Bearer " + os.environ["SAIAI_SMOKE_CLAUDE_KEY"]:
            product = "claude"
            capabilities = {
                "claude": True,
                "codex": False,
                "codex_responses": False,
                "codex_websockets": False,
                "openai_messages_dispatch": False,
            }
        elif authorization == "Bearer " + os.environ["SAIAI_SMOKE_CODEX_KEY"]:
            product = "codex"
            capabilities = {
                "claude": False,
                "codex": True,
                "codex_responses": True,
                "codex_websockets": False,
                "openai_messages_dispatch": False,
            }
        else:
            type(self).failed = True
            self.send_error(401)
            return
        type(self).calls.append(product)
        body = json.dumps(
            {
                "code": 0,
                "message": "success",
                "data": {
                    "schema_version": 2,
                    "gateway_version": "windows-runtime-test",
                    "capabilities": capabilities,
                },
            },
            separators=(",", ":"),
        ).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)


server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
server.timeout = 0.25
Path(os.environ["SAIAI_SMOKE_PORT_FILE"]).write_text(str(server.server_port), encoding="ascii")
deadline = time.monotonic() + 90
while len(Handler.calls) < len(EXPECTED) and not Handler.failed and time.monotonic() < deadline:
    server.handle_request()
server.server_close()
Path(os.environ["SAIAI_SMOKE_CALLS_FILE"]).write_text(json.dumps(Handler.calls), encoding="ascii")
sys.exit(0 if tuple(Handler.calls) == EXPECTED and not Handler.failed else 2)
'@
    [System.IO.File]::WriteAllText($fixtureScript, $fixtureSource, $utf8NoBom)

    $fixtureInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $fixtureInfo.FileName = $python
    $null = $fixtureInfo.ArgumentList.Add($fixtureScript)
    $fixtureInfo.UseShellExecute = $false
    $fixtureInfo.CreateNoWindow = $true
    $fixtureInfo.RedirectStandardOutput = $true
    $fixtureInfo.RedirectStandardError = $true
    $fixtureInfo.Environment["SAIAI_SMOKE_CLAUDE_KEY"] = $claudeKey
    $fixtureInfo.Environment["SAIAI_SMOKE_CODEX_KEY"] = $codexKey
    $fixtureInfo.Environment["SAIAI_SMOKE_PORT_FILE"] = $fixturePortFile
    $fixtureInfo.Environment["SAIAI_SMOKE_CALLS_FILE"] = $fixtureCallsFile
    $fixtureProcess = [System.Diagnostics.Process]::new()
    $fixtureProcess.StartInfo = $fixtureInfo
    Assert-Saiai ($fixtureProcess.Start()) "Could not start the bounded bootstrap fixture"
    $fixtureStdoutTask = $fixtureProcess.StandardOutput.ReadToEndAsync()
    $fixtureStderrTask = $fixtureProcess.StandardError.ReadToEndAsync()

    $port = 0
    for ($attempt = 0; $attempt -lt 100; $attempt++) {
        Assert-Saiai (-not $fixtureProcess.HasExited) "Bootstrap fixture exited before publishing its port"
        if (Test-Path -LiteralPath $fixturePortFile -PathType Leaf) {
            try {
                $candidate = [int]([System.IO.File]::ReadAllText($fixturePortFile, $utf8NoBom))
                if ($candidate -gt 0 -and $candidate -le 65535) {
                    $port = $candidate
                    break
                }
            }
            catch {
                # The fixture may still be completing its short port-file write.
            }
        }
        Start-Sleep -Milliseconds 100
    }
    Assert-Saiai ($port -gt 0) "Bootstrap fixture did not publish a port within 10 seconds"
    $gateway = "http://127.0.0.1:$port"

    $pathParts = @($fakeBin, $nodeDirectory)
    if (-not [string]::IsNullOrWhiteSpace($env:PATH)) {
        $pathParts += $env:PATH
    }
    $baseEnvironment = [ordered]@{
        "HOME" = $isolatedHome
        "USERPROFILE" = $isolatedHome
        "LOCALAPPDATA" = $localAppData
        "APPDATA" = $roamingAppData
        "TEMP" = $temporaryFiles
        "TMP" = $temporaryFiles
        "PATH" = ($pathParts -join [System.IO.Path]::PathSeparator)
        "SAIAI_TEST_OUTPUT" = $output
        "SAIAI_TEST_EXPECTED_CLAUDE_KEY" = $claudeKey
        "SAIAI_TEST_EXPECTED_CODEX_KEY" = $codexKey
        "SAIAI_HOME" = (Join-Path $isolatedHome ".saiai")
        "CLAUDE_CONFIG_DIR" = (Join-Path $isolatedHome ".claude")
        "CODEX_HOME" = (Join-Path $isolatedHome ".codex")
        "ANTHROPIC_BASE_URL" = "https://legacy-anthropic.invalid"
        "ANTHROPIC_AUTH_TOKEN" = "legacy-anthropic-token"
        "ANTHROPIC_API_KEY" = "legacy-anthropic-key"
        "CLAUDE_CODE_USE_BEDROCK" = "1"
        "CLAUDE_CODE_USE_VERTEX" = "1"
        "CLAUDE_CODE_USE_FOUNDRY" = "1"
        "CLAUDE_STREAM_IDLE_TIMEOUT_MS" = "12345"
        "OPENAI_API_KEY" = "legacy-openai-key"
        "OPENAI_BASE_URL" = "https://legacy-openai.invalid"
        "OPENAI_ORG_ID" = "legacy-org"
        "OPENAI_PROJECT_ID" = "legacy-project"
        # Windows environment names are case-insensitive. Use the lowercase
        # spellings to prove the launcher clears inherited proxy conflicts
        # without creating duplicate keys in PowerShell's ordered dictionary.
        "http_proxy" = $null
        "https_proxy" = $null
        "all_proxy" = $null
        "no_proxy" = "127.0.0.1,localhost"
    }
    $launchEnvironment = [ordered]@{}
    foreach ($entry in $baseEnvironment.GetEnumerator()) {
        $launchEnvironment[$entry.Key] = $entry.Value
    }
    foreach ($name in @("http_proxy", "https_proxy", "all_proxy")) {
        $launchEnvironment[$name] = "http://legacy-proxy.invalid:8080"
    }
    $launchEnvironment["no_proxy"] = "legacy.invalid"

    $null = Invoke-SaiaiRuntimeCommand `
        -CommandArguments @("setup", "claude", "--base-url", $gateway, "--api-key-stdin") `
        -StandardInput ($claudeKey + "`n") `
        -EnvironmentOverrides $baseEnvironment

    $claudeOnly = Read-SaiaiConfigState -ConfigPath $configPath -DataRoot $dataRoot
    Assert-Saiai ($claudeOnly.ProductNames.Count -eq 1 -and $claudeOnly.ProductNames[0] -eq "claude") "Claude setup configured another product"
    $claudeHome = [string]$claudeOnly.Homes["claude"]
    Assert-Saiai (Test-Path -LiteralPath $claudeHome -PathType Container) "Claude setup did not create its generation home"
    foreach ($name in @("settings.json", ".claude.json", "saiai-ca.crt", "saiai-ca.key")) {
        Assert-Saiai (Test-Path -LiteralPath (Join-Path $claudeHome $name) -PathType Leaf) "Claude setup omitted a managed artifact"
    }
    Assert-NoProductHome -DataRoot $dataRoot -Product "codex"
    $claudeSettings = Get-Content -LiteralPath (Join-Path $claudeHome "settings.json") -Raw | ConvertFrom-Json
    Assert-Saiai ([string]$claudeSettings.env.CLAUDE_STREAM_IDLE_TIMEOUT_MS -eq "600000") "Claude setup omitted the 10-minute stream idle timeout"
    $claudeGeneration = [string]$claudeOnly.Config.products.claude.active_generation
    $claudeCredential = [string]$claudeOnly.Config.products.claude.credential_ref
    Assert-LegacySentinels $legacySentinels

    $doctorClaudeOnly = Invoke-SaiaiRuntimeCommand `
        -CommandArguments @("doctor") `
        -StandardInput $null `
        -EnvironmentOverrides $baseEnvironment
    $doctorClaudeText = ($doctorClaudeOnly.Stdout + $doctorClaudeOnly.Stderr).ToLowerInvariant()
    Assert-Saiai ($doctorClaudeText.Contains("codex") -and $doctorClaudeText.Contains("unconfigured")) "Doctor did not report Codex as unconfigured"

    $claudeArguments = @("--print", "two words", "--permission-mode=plan")
    $null = Invoke-SaiaiRuntimeCommand `
        -CommandArguments (@("claude", "--") + $claudeArguments) `
        -StandardInput $null `
        -EnvironmentOverrides $launchEnvironment
    $claudeCapture = Read-Capture (Join-Path $output "claude-capture.json")
    Assert-ExactArguments -Capture $claudeCapture -Expected $claudeArguments
    Assert-Saiai (Test-SamePath ([string]$claudeCapture.runtime.executable) $node) "Claude did not launch through the runner's native node.exe"
    Assert-Saiai (Test-SamePath ([string]$claudeCapture.runtime.entry) $claudeEntry) "Claude did not use the fixed package entry"
    Assert-Saiai (Test-SamePath ([string]$claudeCapture.environment.home) $claudeHome) "Claude received the wrong V2 home"
    Assert-Saiai ([string]$claudeCapture.environment.streamIdleTimeout -eq "600000") "Claude received the wrong stream idle timeout"
    Assert-Saiai ([string]$claudeCapture.environment.disableNonessentialTraffic -eq "1") "Claude did not receive the quiet-traffic flag"
    Assert-Saiai ([string]$claudeCapture.environment.promptCaching -eq "1") "Claude did not receive prompt-cache configuration"
    Assert-Saiai ([string]$claudeCapture.environment.toolSearch -eq "true") "Claude did not receive tool-search configuration"
    $expectedNoProxy = "localhost,127.0.0.1,::1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,169.254.0.0/16,fc00::/7,fe80::/10,.local"
    Assert-Saiai ([string]$claudeCapture.environment.noProxy -eq $expectedNoProxy) "Claude inherited a conflicting NO_PROXY value"

    $null = Invoke-SaiaiRuntimeCommand `
        -CommandArguments @("setup", "codex", "--api-key-stdin") `
        -StandardInput ($codexKey + "`n") `
        -EnvironmentOverrides $baseEnvironment

    Assert-Saiai ($fixtureProcess.WaitForExit(10000)) "Bootstrap fixture did not stop after its two expected calls"
    $fixtureStdout = $fixtureStdoutTask.GetAwaiter().GetResult()
    $fixtureStderr = $fixtureStderrTask.GetAwaiter().GetResult()
    Assert-NoSaiaiSecret ($fixtureStdout + $fixtureStderr)
    Assert-Saiai ($fixtureProcess.ExitCode -eq 0) "Bounded bootstrap fixture rejected the setup sequence"
    Assert-Saiai (Test-Path -LiteralPath $fixtureCallsFile -PathType Leaf) "Bootstrap fixture did not write its call receipt"
    $fixtureCalls = @(([System.IO.File]::ReadAllText($fixtureCallsFile, $utf8NoBom) | ConvertFrom-Json))
    Assert-Saiai ($fixtureCalls.Count -eq 2 -and $fixtureCalls[0] -eq "claude" -and $fixtureCalls[1] -eq "codex") "Bootstrap calls were not product-scoped"

    $both = Read-SaiaiConfigState -ConfigPath $configPath -DataRoot $dataRoot
    Assert-Saiai ($both.ProductNames.Count -eq 2 -and $both.ProductNames -contains "claude" -and $both.ProductNames -contains "codex") "Codex setup did not retain Claude"
    Assert-Saiai ([string]$both.Config.base_url -eq [string]$claudeOnly.Config.base_url) "Codex setup changed the shared Gateway"
    Assert-Saiai ([string]$both.Config.products.claude.active_generation -eq $claudeGeneration) "Codex setup replaced Claude's generation"
    Assert-Saiai ([string]$both.Config.products.claude.credential_ref -eq $claudeCredential) "Codex setup replaced Claude's credential reference"
    Assert-Saiai ([string]$both.Config.products.codex.active_generation -ne $claudeGeneration) "Claude and Codex share a generation"
    $codexHome = [string]$both.Homes["codex"]
    Assert-Saiai (Test-Path -LiteralPath (Join-Path $codexHome "config.toml") -PathType Leaf) "Codex setup omitted config.toml"
    Assert-Saiai (-not (Test-Path -LiteralPath (Join-Path $codexHome "auth.json"))) "Codex setup created auth.json"
    $codexGeneration = [string]$both.Config.products.codex.active_generation
    $codexCredential = [string]$both.Config.products.codex.credential_ref

    $codexArguments = @("exec", "two words", "--sandbox=read-only")
    $null = Invoke-SaiaiRuntimeCommand `
        -CommandArguments (@("codex", "--") + $codexArguments) `
        -StandardInput $null `
        -EnvironmentOverrides $launchEnvironment
    $codexCapture = Read-Capture (Join-Path $output "codex-capture.json")
    Assert-ExactArguments -Capture $codexCapture -Expected $codexArguments
    Assert-Saiai (Test-SamePath ([string]$codexCapture.runtime.executable) $node) "Codex did not launch through the runner's native node.exe"
    Assert-Saiai (Test-SamePath ([string]$codexCapture.runtime.entry) $codexEntry) "Codex did not use the fixed package entry"
    Assert-Saiai (Test-SamePath ([string]$codexCapture.environment.home) $codexHome) "Codex received the wrong V2 home"

    $null = Invoke-SaiaiRuntimeCommand `
        -CommandArguments @("doctor") `
        -StandardInput $null `
        -EnvironmentOverrides $baseEnvironment

    $null = Invoke-SaiaiRuntimeCommand `
        -CommandArguments @("claude", "revoke") `
        -StandardInput $null `
        -EnvironmentOverrides $baseEnvironment
    $codexOnly = Read-SaiaiConfigState -ConfigPath $configPath -DataRoot $dataRoot
    Assert-Saiai ($codexOnly.ProductNames.Count -eq 1 -and $codexOnly.ProductNames[0] -eq "codex") "Claude revoke crossed the product boundary"
    Assert-Saiai ([string]$codexOnly.Config.products.codex.active_generation -eq $codexGeneration) "Claude revoke changed Codex's generation"
    Assert-Saiai ([string]$codexOnly.Config.products.codex.credential_ref -eq $codexCredential) "Claude revoke changed Codex's credential reference"
    Assert-Saiai (-not (Test-Path -LiteralPath $claudeHome)) "Claude revoke retained its active home"
    Assert-Saiai (Test-Path -LiteralPath $codexHome -PathType Container) "Claude revoke removed the Codex home"
    $doctorCodexOnly = Invoke-SaiaiRuntimeCommand `
        -CommandArguments @("doctor") `
        -StandardInput $null `
        -EnvironmentOverrides $baseEnvironment
    $doctorCodexText = ($doctorCodexOnly.Stdout + $doctorCodexOnly.Stderr).ToLowerInvariant()
    Assert-Saiai ($doctorCodexText.Contains("claude") -and $doctorCodexText.Contains("unconfigured")) "Doctor did not report Claude as unconfigured after revoke"
    Assert-LegacySentinels $legacySentinels

    $null = Invoke-SaiaiRuntimeCommand `
        -CommandArguments @("revoke", "--all") `
        -StandardInput $null `
        -EnvironmentOverrides $baseEnvironment
    $null = Invoke-SaiaiRuntimeCommand `
        -CommandArguments @("revoke", "--all") `
        -StandardInput $null `
        -EnvironmentOverrides $baseEnvironment
    foreach ($root in @($configRoot, $dataRoot, $stateRoot)) {
        Assert-Saiai (-not (Test-Path -LiteralPath $root)) "Repeated full revoke retained a V2 application root"
    }
    Assert-LegacySentinels $legacySentinels

    foreach ($result in $commandResults) {
        Assert-NoSaiaiSecret ($result.Stdout + $result.Stderr)
    }
}
finally {
    if ($null -ne $fixtureProcess) {
        try {
            if (-not $fixtureProcess.HasExited) {
                try {
                    $fixtureProcess.Kill($true)
                }
                catch {
                    $fixtureProcess.Kill()
                }
                $null = $fixtureProcess.WaitForExit(5000)
            }
        }
        catch {
            Write-Warning "Could not stop the bounded bootstrap fixture"
        }
        $fixtureProcess.Dispose()
    }
    try {
        Remove-Item -LiteralPath $temporary -Recurse -Force -ErrorAction Stop
    }
    catch {
        Write-Warning "Could not remove Windows runtime smoke-test files"
    }
}

Write-Host "SAIAI V2 native Windows runtime smoke passed"
$global:LASTEXITCODE = 0
