$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
$session = (Get-Process -Id $PID).SessionId
if ($session -eq 0) { throw 'interactive_session_required' }
$sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$packages = @(Get-AppxPackage -Name OpenAI.Codex)
if ($packages.Count -ne 1) { throw 'single_official_package_required' }
$package = $packages[0]
$root = [IO.Path]::GetFullPath($env:SAIAI_RUNTIME_PACKAGE_ROOT)
$appId = $package.PackageFamilyName+'!App'
if ($appId -cne $env:SAIAI_RUNTIME_APP_ID -or [IO.Path]::GetFullPath($package.InstallLocation) -ine $root -or $package.Publisher -ne 'CN=50BDFD77-8903-4850-9FFE-6E8522F64D5B' -or [string]$package.SignatureKind -ne 'Store' -or [string]$package.Status -ne 'Ok') { throw 'official_package_identity_required' }
$entrypoint = Join-Path $root 'app\ChatGPT.exe'
if ([string](Get-AuthenticodeSignature -LiteralPath $entrypoint).Status -ne 'Valid') { throw 'signed_entrypoint_required' }
$hash = (Get-FileHash -LiteralPath $entrypoint -Algorithm SHA256).Hash.ToLowerInvariant()
$processes = @(Get-Process -Name ChatGPT,Codex -ErrorAction SilentlyContinue)
if ($processes.Count -gt 64) { throw 'bounded_actor_inventory_required' }
$relevant = @()
foreach ($process in $processes) {
    if ($process.ProcessName -eq 'ChatGPT' -or $process.Path -ieq (Join-Path $root 'app\Codex.exe')) {
        if ($process.SessionId -ne $session -or $process.Path -notin @($entrypoint,(Join-Path $root 'app\Codex.exe'))) { throw 'unknown_or_foreign_actor' }
        $relevant += $process
    }
}
$windows = @()
if ($relevant.Count) {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class SaiaiRuntimeArguments {
    [DllImport("shell32.dll", SetLastError=true)]
    static extern IntPtr CommandLineToArgvW([MarshalAs(UnmanagedType.LPWStr)] string commandLine, out int count);
    [DllImport("kernel32.dll")]
    static extern IntPtr LocalFree(IntPtr memory);
    public static string[] Split(string commandLine) {
        int count;
        IntPtr memory = CommandLineToArgvW(commandLine, out count);
        if (memory == IntPtr.Zero || count < 1 || count > 256) {
            if (memory != IntPtr.Zero) LocalFree(memory);
            throw new InvalidOperationException("bounded_command_arguments_required");
        }
        try {
            var result = new string[count];
            for (int index=0; index<count; index++) result[index] = Marshal.PtrToStringUni(Marshal.ReadIntPtr(memory,index*IntPtr.Size));
            return result;
        } finally { LocalFree(memory); }
    }
}
'@
    foreach ($process in $relevant) {
        $native = Get-CimInstance Win32_Process -Filter ('ProcessId='+$process.Id) -OperationTimeoutSec 3
        if (-not $native -or $native.CommandLine.Length -gt 8192) { throw 'live_actor_inspection_required' }
        $owner = Invoke-CimMethod -InputObject $native -MethodName GetOwnerSid -OperationTimeoutSec 3
        if ($owner.ReturnValue -ne 0 -or $owner.Sid -ne $sid) { throw 'same_user_actor_required' }
        $arguments = @([SaiaiRuntimeArguments]::Split([string]$native.CommandLine))
        if ($process.Path -ine $entrypoint -or @($arguments | Where-Object {$_ -like '--type=*'}).Count) { continue }
        $proxy = @($arguments | Where-Object {$_.StartsWith('--proxy-server=',[StringComparison]::Ordinal)})
        $pins = @($arguments | Where-Object {$_.StartsWith('--ignore-certificate-errors-spki-list=',[StringComparison]::Ordinal)})
        $unsafe = @($arguments | Where-Object {
            ($_ -like '--proxy-*' -and $_ -notlike '--proxy-server=*') -or
            ($_ -like '--ignore-certificate-errors*' -and $_ -notlike '--ignore-certificate-errors-spki-list=*') -or
            $_ -like '--user-data-dir*' -or $_ -like '--no-proxy-server*' -or $_ -like '--disable-web-security*'
        }).Count -gt 0
        $proxyValue = $null
        if ($proxy.Count -eq 1 -and $proxy[0].Length -le 256) {
            $value = $proxy[0].Substring('--proxy-server='.Length)
            if ($value -match '^http://(127(\.[0-9]{1,3}){3}|\[::1\]):[0-9]{1,5}$') { $proxyValue = $value }
        }
        $pinValue = $null
        if ($pins.Count -eq 1 -and $pins[0].Length -le 2100) {
            $value = $pins[0].Substring('--ignore-certificate-errors-spki-list='.Length)
            $valid = $value.Length -gt 0
            foreach ($pin in $value.Split(',')) {
                try { if ([Convert]::FromBase64String($pin).Length -ne 32) { $valid = $false } }
                catch { $valid = $false }
            }
            if ($valid) { $pinValue = $value }
        }
        $live = Get-Process -Id $process.Id
        if ($live.Path -ine $entrypoint -or $live.SessionId -ne $session -or $live.StartTime.ToUniversalTime().ToFileTimeUtc() -ne $process.StartTime.ToUniversalTime().ToFileTimeUtc()) { throw 'actor_changed_during_inspection' }
        $windows += @{
            process_id=$process.Id
            started_filetime=$live.StartTime.ToUniversalTime().ToFileTimeUtc().ToString([Globalization.CultureInfo]::InvariantCulture)
            native_window=($live.MainWindowHandle -ne 0)
            proxy=$proxyValue
            spki=$pinValue
            unsafe_overrides=[bool]$unsafe
        }
    }
}
@{
    identity=@{app_id=$appId;package_version=[string]$package.Version;entrypoint_sha256=$hash;session_id=$session;owner_sid=$sid}
    codex_home=Join-Path ([Environment]::GetFolderPath('UserProfile')) '.codex'
    runtime_directory=Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'SAIAI\desktop-runtime'
    actor_count=$relevant.Count
    windows=@($windows)
} | ConvertTo-Json -Depth 6 -Compress
