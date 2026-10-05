$ErrorActionPreference = 'Stop'
$observer = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__OBSERVER_SOURCE__'))
$root = 'C:\SAIAI-TEST-ONLY'
$env:SAIAI_RUNTIME_APP_ID = 'OpenAI.Codex_TEST_ONLY!App'
$env:SAIAI_RUNTIME_PACKAGE_ROOT = $root
$cases = @(
    'gone_then_valid', 'gone_then_empty', 'gone_then_foreign_owner',
    'gone_early_path_then_valid', 'gone_early_session_then_valid',
    'gone_early_throw_then_valid', 'gone_before_metadata_then_valid',
    'gone_early_path_then_empty', 'gone_early_path_then_foreign_path',
    'gone_early_path_then_foreign_session', 'gone_early_path_then_pid_reused',
    'live_path_unavailable', 'live_path_read_failed', 'early_exit_proof_denied',
    'never_early_settles', 'unrelated_codex',
    'live_missing', 'exit_proof_denied', 'long_command', 'foreign_owner',
    'owner_query_failed', 'foreign_session', 'foreign_path', 'pid_reused',
    'inventory_limit', 'cim_query_failed', 'never_settles',
    'package_root_changed', 'package_app_id_changed', 'package_publisher_changed',
    'package_not_store_signed', 'package_not_ready', 'entrypoint_not_signed',
    'changed_root_not_signed', 'changed_root_foreign_publisher', 'multiple_packages',
    'refresh_empty', 'refresh_live_actor', 'refresh_unrelated_codex'
)
$options = [Diagnostics.ProcessStartInfo]::new()
$options.FileName = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$options.Arguments = '-NoProfile -NonInteractive -Command "[Console]::ReadLine() | Out-Null"'
$options.UseShellExecute = $false
$options.CreateNoWindow = $true
$options.RedirectStandardInput = $true
$child = [Diagnostics.Process]::new()
$child.StartInfo = $options
$childStarted = $false
$live = $null
try {
    $child.Start() | Out-Null
    $childStarted = $true
    $live = [Diagnostics.Process]::GetProcessById($child.Id)
    if ($live.HasExited) { throw 'fixture_live_exit_proof_failed' }
    $child.StandardInput.Close()
    if (-not $child.WaitForExit(10000) -or -not $live.HasExited) { throw 'fixture_native_exit_proof_failed' }
} finally {
    if ($childStarted -and -not $child.HasExited) { $child.Kill(); $child.WaitForExit(5000) | Out-Null }
    if ($null -ne $live) { $live.Dispose() }
    $child.Dispose()
}
$reports = @(@{name='native_exit_proof';passed=$true})
foreach ($case in $cases) {
    $reports += & {
        $state = @{name=$case;reads=0;pauses=0;metadata_reads=0;actors=@{}}
        $env:SAIAI_RUNTIME_REQUIRE_NO_ACTORS = if ($case -like 'refresh_*') { '1' } else { '0' }
        $entrypoint = Join-Path $root 'app\ChatGPT.exe'
        $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        $started = [DateTime]::Parse('2026-01-01T00:00:00Z').ToUniversalTime()
        function New-FixtureActor([int]$identifier, [bool]$exited) {
            $actor = [pscustomobject]@{
                Id=$identifier;ProcessName='ChatGPT';Path=$entrypoint;SessionId=1
                StartTime=$started.AddSeconds($identifier);MainWindowHandle=[IntPtr]1;HasExited=$exited
            }
            if ($state.name -in @('exit_proof_denied','early_exit_proof_denied')) {
                $actor.PSObject.Properties.Remove('HasExited')
                $actor | Add-Member ScriptProperty HasExited { throw 'TEST_ONLY_PRIVATE_EXIT_PROOF' }
            }
            $state.actors[$identifier] = $actor
            return $actor
        }
        function New-EarlyExitActor {
            $actor = New-FixtureActor 102 ($state.name -eq 'gone_before_metadata_then_valid')
            if ($state.name -eq 'gone_early_session_then_valid') {
                $actor.PSObject.Properties.Remove('SessionId')
                $actor | Add-Member ScriptProperty SessionId {
                    $state.metadata_reads++
                    $this.HasExited = $true
                    return 0
                }
            } else {
                $actor.PSObject.Properties.Remove('Path')
                $actor | Add-Member ScriptProperty Path {
                    $state.metadata_reads++
                    $this.HasExited = $true
                    if ($state.name -in @('gone_early_throw_then_valid','gone_before_metadata_then_valid')) { throw 'TEST_ONLY_PRIVATE_EXIT_PATH' }
                    return $null
                }
            }
            return $actor
        }
        function Get-Process {
            [CmdletBinding()]
            param([string[]]$Name, [int]$Id)
            if ($Id -eq $PID) { return [pscustomobject]@{SessionId=1} }
            if ($Name) {
                $state.reads++
                if ($state.name -eq 'refresh_empty') { return @() }
                if ($state.name -in @('refresh_unrelated_codex','unrelated_codex')) {
                    $actor = New-FixtureActor 201 $false
                    $actor.ProcessName = 'Codex'
                    $actor.Path = 'C:\SAIAI-TEST-ONLY-CLI\codex.exe'
                    return $actor
                }
                if ($state.name -eq 'inventory_limit') {
                    return @(1..65 | ForEach-Object { New-FixtureActor (100 + $_) $false })
                }
                if ($state.name -eq 'never_early_settles') { return New-EarlyExitActor }
                if ($state.name -eq 'never_settles') { return New-FixtureActor 102 $false }
                if ($state.name -like 'gone_then_*' -and $state.reads -eq 1) {
                    return @((New-FixtureActor 101 $false), (New-FixtureActor 102 $false))
                }
                if (($state.name -like 'gone_early_*' -or $state.name -eq 'gone_before_metadata_then_valid') -and $state.reads -eq 1) {
                    return @((New-FixtureActor 101 $false), (New-EarlyExitActor))
                }
                if ($state.name -in @('gone_then_empty','gone_early_path_then_empty')) { return @() }
                $actor = New-FixtureActor 201 $false
                if ($state.name -in @('foreign_session','gone_early_path_then_foreign_session')) { $actor.SessionId=0 }
                if ($state.name -in @('foreign_path','gone_early_path_then_foreign_path')) { $actor.Path='C:\SAIAI-FOREIGN-TEST-ONLY\ChatGPT.exe' }
                if ($state.name -in @('live_path_unavailable','early_exit_proof_denied')) { $actor.Path=$null }
                if ($state.name -eq 'live_path_read_failed') {
                    $actor.PSObject.Properties.Remove('Path')
                    $actor | Add-Member ScriptProperty Path { throw 'TEST_ONLY_PRIVATE_LIVE_PATH' }
                }
                return $actor
            }
            $actor = New-FixtureActor $Id $false
            if ($state.name -in @('pid_reused','gone_early_path_then_pid_reused')) { $actor.StartTime=$actor.StartTime.AddSeconds(1) }
            return $actor
        }
        function Get-AppxPackage {
            [CmdletBinding()]
            param([string]$Name)
            $package = [pscustomobject]@{
                PackageFamilyName='OpenAI.Codex_TEST_ONLY';InstallLocation=$root
                Publisher='CN=50BDFD77-8903-4850-9FFE-6E8522F64D5B';SignatureKind='Store';Status='Ok';Version='1.0.0.0'
            }
            if ($state.name -in @('package_root_changed','changed_root_not_signed','changed_root_foreign_publisher')) { $package.InstallLocation='C:\SAIAI-TEST-ONLY-UPDATED' }
            if ($state.name -eq 'package_app_id_changed') { $package.PackageFamilyName='OpenAI.Codex_FOREIGN_TEST_ONLY' }
            if ($state.name -in @('package_publisher_changed','changed_root_foreign_publisher')) { $package.Publisher='TEST_ONLY_FOREIGN_PUBLISHER' }
            if ($state.name -eq 'package_not_store_signed') { $package.SignatureKind='Developer' }
            if ($state.name -eq 'package_not_ready') { $package.Status='Modified' }
            if ($state.name -eq 'multiple_packages') { return @($package,$package) }
            return $package
        }
        function Get-AuthenticodeSignature {
            [CmdletBinding()]
            param([string]$LiteralPath)
            $status = if ($state.name -in @('entrypoint_not_signed','changed_root_not_signed')) { 'NotSigned' } else { 'Valid' }
            return [pscustomobject]@{Status=$status}
        }
        function Get-FileHash {
            [CmdletBinding()]
            param([string]$LiteralPath, [string]$Algorithm)
            return [pscustomobject]@{Hash=('a' * 64)}
        }
        function Get-CimInstance {
            [CmdletBinding()]
            param([string]$ClassName, [string]$Filter, [int]$OperationTimeoutSec)
            if ($state.name -eq 'cim_query_failed') { throw 'TEST_ONLY_PRIVATE_CIM_FAILURE' }
            $identifier = [int]$Filter.Substring('ProcessId='.Length)
            if ($identifier -eq 102) { $state.actors[$identifier].HasExited=$true; return $null }
            if ($state.name -in @('live_missing','exit_proof_denied')) { return $null }
            $pins = [Convert]::ToBase64String([byte[]]::new(32))
            $command = '"'+$entrypoint+'" --proxy-server=http://127.0.0.1:19908 --ignore-certificate-errors-spki-list='+$pins
            if ($state.name -eq 'long_command') { $command='x' * 8193 }
            return [pscustomobject]@{ProcessId=$identifier;CommandLine=$command}
        }
        function Invoke-CimMethod {
            [CmdletBinding()]
            param($InputObject, [string]$MethodName, [int]$OperationTimeoutSec)
            $owner = $sid
            $result = 0
            if ($state.name -eq 'foreign_owner' -or ($state.name -eq 'gone_then_foreign_owner' -and $InputObject.ProcessId -eq 201)) { $owner='S-1-5-9999' }
            if ($state.name -eq 'owner_query_failed') { $result=1 }
            return [pscustomobject]@{Sid=$owner;ReturnValue=$result}
        }
        function Start-Sleep {
            [CmdletBinding()]
            param([int]$Milliseconds)
            if ($Milliseconds -ne 100) { throw 'fixture_sleep_bound_failed' }
            $state.pauses++
        }
        $expected = switch ($state.name) {
            'gone_then_foreign_owner' { 'same_user_actor_required' }
            'live_missing' { 'live_actor_inspection_required' }
            'exit_proof_denied' { 'TEST_ONLY_PRIVATE_EXIT_PROOF' }
            'long_command' { 'bounded_actor_command_line_required' }
            'foreign_owner' { 'same_user_actor_required' }
            'owner_query_failed' { 'same_user_actor_required' }
            'foreign_session' { 'unknown_or_foreign_actor' }
            'foreign_path' { 'unknown_or_foreign_actor' }
            'gone_early_path_then_foreign_path' { 'unknown_or_foreign_actor' }
            'gone_early_path_then_foreign_session' { 'unknown_or_foreign_actor' }
            'live_path_unavailable' { 'unknown_or_foreign_actor' }
            'pid_reused' { 'actor_changed_during_inspection' }
            'gone_early_path_then_pid_reused' { 'actor_changed_during_inspection' }
            'inventory_limit' { 'bounded_actor_inventory_required' }
            'cim_query_failed' { 'TEST_ONLY_PRIVATE_CIM_FAILURE' }
            'never_settles' { 'actor_inventory_did_not_settle' }
            'never_early_settles' { 'actor_inventory_did_not_settle' }
            'package_root_changed' { 'official_package_root_changed' }
            'package_app_id_changed' { 'official_package_app_id_required' }
            'package_publisher_changed' { 'official_package_publisher_required' }
            'package_not_store_signed' { 'official_package_store_signature_required' }
            'package_not_ready' { 'official_package_not_ready' }
            'entrypoint_not_signed' { 'signed_entrypoint_required' }
            'changed_root_not_signed' { 'signed_entrypoint_required' }
            'changed_root_foreign_publisher' { 'official_package_publisher_required' }
            'multiple_packages' { 'single_official_package_required' }
            'refresh_live_actor' { 'package_refresh_requires_no_actors' }
            'refresh_unrelated_codex' { 'package_refresh_requires_no_actors' }
            default { $null }
        }
        $failure = $null
        $snapshot = $null
        try { $snapshot = (& ([ScriptBlock]::Create($observer))) | ConvertFrom-Json }
        catch { $failure=$_.Exception.Message }
        if ($state.name -in @('exit_proof_denied','early_exit_proof_denied','live_path_read_failed')) {
            if ($null -eq $failure) { throw 'observer_fixture_exit_proof_accepted' }
        } elseif ($failure -cne $expected) { throw 'observer_fixture_outcome_failed' }
        $reads = if ($state.name -in @('never_settles','never_early_settles')) { 3 } elseif ($state.name -like 'gone_*') { 2 } elseif ($state.name -like 'package_*' -or $state.name -like 'changed_root_*' -or $state.name -in @('entrypoint_not_signed','multiple_packages')) { 0 } else { 1 }
        if ($state.reads -ne $reads -or $state.pauses -ne [Math]::Max(0,($reads - 1))) { throw 'observer_fixture_retry_bound_failed' }
        if ($state.name -eq 'gone_then_valid' -or $state.name -like 'gone_*_then_valid') {
            if ($snapshot.actor_count -ne 1 -or @($snapshot.windows).Count -ne 1 -or $snapshot.windows[0].process_id -ne 201) { throw 'observer_fixture_partial_snapshot_reused' }
            if ($snapshot.windows[0].proxy -ne 'http://127.0.0.1:19908' -or -not $snapshot.windows[0].spki) { throw 'observer_fixture_binding_lost' }
        }
        if ($state.name -in @('gone_then_empty','gone_early_path_then_empty','unrelated_codex') -and ($snapshot.actor_count -ne 0 -or @($snapshot.windows).Count -ne 0)) { throw 'observer_fixture_stale_actor_count' }
        if ($state.name -eq 'gone_before_metadata_then_valid' -and $state.metadata_reads -ne 0) { throw 'observer_fixture_exited_metadata_read' }
        if ($state.name -like 'gone_early_*' -and $state.metadata_reads -ne 1) { throw 'observer_fixture_metadata_race_missing' }
        if ($state.name -eq 'never_early_settles' -and $state.metadata_reads -ne 3) { throw 'observer_fixture_metadata_retry_bound_failed' }
        if ($state.name -eq 'refresh_empty' -and ($snapshot.actor_count -ne 0 -or @($snapshot.windows).Count -ne 0)) { throw 'observer_fixture_refresh_actor_count' }
        return @{name=$state.name;passed=$true;inventory_reads=$state.reads;pauses=$state.pauses}
    }
}
ConvertTo-Json -InputObject @($reports) -Depth 4 -Compress
