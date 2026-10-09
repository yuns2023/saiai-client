$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
$store = $null
$certificate = $null
$failure = 'trust_not_established'
try {
    $pem = [IO.File]::ReadAllText($env:SAIAI_VSCODE_CA_PATH)
    $match = [regex]::Match($pem, '\A\s*-----BEGIN CERTIFICATE-----\s*(?<der>[A-Za-z0-9+/=\s]+)-----END CERTIFICATE-----\s*\z')
    if (-not $match.Success) { throw 'Expected one public installation CA' }
    $der = [Convert]::FromBase64String($match.Groups['der'].Value)
    $algorithm = [Security.Cryptography.SHA256]::Create()
    try { $hash = ([BitConverter]::ToString($algorithm.ComputeHash($der))).Replace('-', '').ToLowerInvariant() }
    finally { $algorithm.Dispose() }
    if ($hash -cne $env:SAIAI_VSCODE_CA_SHA256) { throw 'Installation CA changed during trust setup' }
    $certificate = [Security.Cryptography.X509Certificates.X509Certificate2]::new($der)
    $constraint = @($certificate.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.19' })
    if ($constraint.Count -ne 1) { throw 'Installation CA constraints are missing' }
    $basic = [Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new($constraint[0], $constraint[0].Critical)
    if (-not $basic.CertificateAuthority -or $certificate.HasPrivateKey -or
        $certificate.NotBefore.ToUniversalTime() -gt [DateTime]::UtcNow -or
        $certificate.NotAfter.ToUniversalTime() -le [DateTime]::UtcNow) {
        throw 'Installation CA is not a valid public authority certificate'
    }
    # This exact store is deliberately fixed. Never use LocalMachine or infer
    # a different target from the caller's elevation or environment.
    $store = [Security.Cryptography.X509Certificates.X509Store]::new('Root', 'CurrentUser')
    $store.Open([Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
    $prior = @($store.Certificates.Find('FindByThumbprint', $certificate.Thumbprint, $false))
    foreach ($item in $prior) {
        if ([Convert]::ToBase64String($item.RawData) -cne [Convert]::ToBase64String($der)) {
            throw 'An existing certificate has a conflicting identity'
        }
    }
    $imported = $prior.Count -eq 0
    if ($imported) {
        # Protected CurrentUser roots require Windows' own confirmation UI.
        # Session zero (for example SSH) cannot present it. Never bypass that
        # confirmation by changing protected-root policy or the store provider.
        if ([Diagnostics.Process]::GetCurrentProcess().SessionId -eq 0) {
            $failure = 'interactive_session_required'
            throw 'An interactive Windows desktop is required'
        }
        $store.Add($certificate)
    }
    $installed = @($store.Certificates.Find('FindByThumbprint', $certificate.Thumbprint, $false))
    if ($installed.Count -eq 0) { throw 'Installation CA trust was not established' }
    [pscustomobject]@{ imported = $imported; current_user_only = $true } | ConvertTo-Json -Compress
} catch {
    # Certificate bytes, file content and native exceptions never reach logs.
    [pscustomobject]@{ imported = $null; current_user_only = $true; error = $failure } | ConvertTo-Json -Compress
    exit 1
} finally {
    if ($null -ne $store) { $store.Close(); $store.Dispose() }
    if ($null -ne $certificate) { $certificate.Dispose() }
}
