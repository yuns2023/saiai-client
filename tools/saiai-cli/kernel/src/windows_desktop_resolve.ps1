$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
$packages = @(Get-AppxPackage -Name OpenAI.Codex)
if ($packages.Count -eq 0) { 'null'; return }
if ($packages.Count -ne 1) { throw 'single_official_package_required' }
$package = $packages[0]
if ($package.Publisher -ne 'CN=50BDFD77-8903-4850-9FFE-6E8522F64D5B') { throw 'official_package_publisher_required' }
if ([string]$package.SignatureKind -ne 'Store') { throw 'official_package_store_signature_required' }
if ([string]$package.Status -ne 'Ok') { throw 'official_package_not_ready' }
$root = [IO.Path]::GetFullPath($package.InstallLocation)
$entrypoint = Join-Path $root 'app\ChatGPT.exe'
if ([string](Get-AuthenticodeSignature -LiteralPath $entrypoint).Status -ne 'Valid') { throw 'signed_entrypoint_required' }
@{
    app_id=$package.PackageFamilyName+'!App'
    install_location=$root
    package_version=[string]$package.Version
} | ConvertTo-Json -Compress
