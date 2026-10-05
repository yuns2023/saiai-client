$ErrorActionPreference = 'Stop'
$resolver = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__RESOLVER_SOURCE__'))
$root = 'C:\SAIAI-TEST-ONLY'
$reports = @()
foreach ($case in @('absent','valid','multiple','foreign_publisher','not_store','not_ready','unsigned')) {
    $reports += & {
        $state = @{name=$case;reads=0;signatures=0}
        function Get-AppxPackage {
            [CmdletBinding()]
            param([string]$Name)
            if ($Name -cne 'OpenAI.Codex') { throw 'resolver_fixture_wrong_package' }
            $state.reads++
            if ($state.name -eq 'absent') { return @() }
            $package = [pscustomobject]@{
                PackageFamilyName='OpenAI.Codex_TEST_ONLY';InstallLocation=$root
                Publisher='CN=50BDFD77-8903-4850-9FFE-6E8522F64D5B';SignatureKind='Store';Status='Ok';Version='26.930.4958.0'
            }
            if ($state.name -eq 'multiple') { return @($package,$package) }
            if ($state.name -eq 'foreign_publisher') { $package.Publisher='TEST_ONLY_FOREIGN_PUBLISHER' }
            if ($state.name -eq 'not_store') { $package.SignatureKind='Developer' }
            if ($state.name -eq 'not_ready') { $package.Status='Modified' }
            return $package
        }
        function Get-AuthenticodeSignature {
            [CmdletBinding()]
            param([string]$LiteralPath)
            if ($LiteralPath -ine (Join-Path $root 'app\ChatGPT.exe')) { throw 'resolver_fixture_wrong_entrypoint' }
            $state.signatures++
            return [pscustomobject]@{Status=$(if ($state.name -eq 'unsigned') { 'NotSigned' } else { 'Valid' })}
        }
        function Get-StartApps { throw 'resolver_fixture_separate_identity_lookup' }
        function Start-Process { throw 'resolver_fixture_activation_forbidden' }
        function Stop-Process { throw 'resolver_fixture_stop_forbidden' }
        $failure = $null
        $package = $null
        try { $package = (& ([ScriptBlock]::Create($resolver))) | ConvertFrom-Json }
        catch { $failure = $_.Exception.Message }
        $expected = switch ($state.name) {
            'multiple' { 'single_official_package_required' }
            'foreign_publisher' { 'official_package_publisher_required' }
            'not_store' { 'official_package_store_signature_required' }
            'not_ready' { 'official_package_not_ready' }
            'unsigned' { 'signed_entrypoint_required' }
            default { $null }
        }
        if ($failure -cne $expected -or $state.reads -ne 1) { throw 'resolver_fixture_outcome_failed' }
        $signatures = if ($state.name -in @('valid','unsigned')) { 1 } else { 0 }
        if ($state.signatures -ne $signatures) { throw 'resolver_fixture_signature_check_failed' }
        if ($state.name -eq 'valid' -and ($package.app_id -cne 'OpenAI.Codex_TEST_ONLY!App' -or $package.install_location -ine $root -or $package.package_version -cne '26.930.4958.0')) { throw 'resolver_fixture_identity_not_coherent' }
        if ($state.name -eq 'absent' -and $null -ne $package) { throw 'resolver_fixture_absent_package' }
        return @{name=$state.name;passed=$true;package_reads=$state.reads;signature_checks=$state.signatures}
    }
}
ConvertTo-Json -InputObject @($reports) -Depth 4 -Compress
