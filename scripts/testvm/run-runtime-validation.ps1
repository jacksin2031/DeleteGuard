param(
    [switch]$IncludeDriverReload,
    [int]$StressAttempts = 100
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'TestVm.Common.ps1')

Assert-DeleteGuardAdministrator
Assert-DeleteGuardDisposableVm
Assert-DeleteGuardSafeTestPath -Path $script:DeleteGuardTestRoot

if (-not (Test-DeleteGuardFilterLoaded)) {
    throw 'DeleteGuardFilter is not loaded. Run install-test-stack.ps1 first.'
}

$relay = Get-Service -Name 'DeleteGuardEventRelay' -ErrorAction SilentlyContinue
if (-not $relay -or $relay.Status -ne 'Running') {
    throw 'DeleteGuardEventRelay service is not running.'
}

$results = [System.Collections.Generic.List[object]]::new()
$startedUtc = [DateTimeOffset]::UtcNow
$reportDirectory = Join-Path $env:ProgramData 'DeleteGuard'
$reportPath = Join-Path $reportDirectory ("runtime-validation-{0}.json" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
$sentinelName = '.deleteguard-runtime-test-root'
$sentinelPath = Join-Path $script:DeleteGuardTestRoot $sentinelName
$protected = $false

function Add-Result {
    param([string]$Name, [bool]$Passed, [string]$Detail)
    $results.Add([pscustomobject]@{
        name = $Name
        passed = $Passed
        detail = $Detail
        utc = [DateTimeOffset]::UtcNow.ToString('O')
    })
    Write-Host ("[{0}] {1} - {2}" -f ($(if ($Passed) { 'PASS' } else { 'FAIL' })), $Name, $Detail)
}

function Assert-StillExists {
    param([string]$Name, [string]$Path, [string]$Detail)
    $exists = Test-Path -LiteralPath $Path
    Add-Result -Name $Name -Passed $exists -Detail $Detail
    if (-not $exists) { throw "Safety validation failed: '$Name' unexpectedly deleted $Path" }
}

function Remove-PreviousSafeRoot {
    if (-not (Test-Path -LiteralPath $script:DeleteGuardTestRoot)) { return }
    if (-not (Test-Path -LiteralPath $sentinelPath)) {
        throw "Refusing to reuse existing $script:DeleteGuardTestRoot because the DeleteGuard test sentinel is absent."
    }

    try { Invoke-DeleteGuardBroker -Command unprotect -Path $script:DeleteGuardTestRoot } catch { }
    Remove-Item -LiteralPath $script:DeleteGuardTestRoot -Recurse -Force
}

$interopSource = @'
using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

public static class DeleteGuardRuntimeNativeProbe
{
    const uint DELETE = 0x00010000;
    const uint FILE_SHARE_READ = 0x1;
    const uint FILE_SHARE_WRITE = 0x2;
    const uint FILE_SHARE_DELETE = 0x4;
    const uint OPEN_EXISTING = 3;
    const uint FILE_ATTRIBUTE_NORMAL = 0x80;
    const uint FILE_FLAG_DELETE_ON_CLOSE = 0x04000000;
    const int FileDispositionInfo = 4;

    [StructLayout(LayoutKind.Sequential)]
    struct FILE_DISPOSITION_INFO
    {
        [MarshalAs(UnmanagedType.Bool)] public bool DeleteFile;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern SafeFileHandle CreateFileW(
        string lpFileName, uint dwDesiredAccess, uint dwShareMode, IntPtr lpSecurityAttributes,
        uint dwCreationDisposition, uint dwFlagsAndAttributes, IntPtr hTemplateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool SetFileInformationByHandle(
        SafeFileHandle hFile, int FileInformationClass,
        ref FILE_DISPOSITION_INFO lpFileInformation, uint dwBufferSize);

    public static int TryDispositionDelete(string path)
    {
        using (var handle = CreateFileW(path, DELETE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            IntPtr.Zero, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, IntPtr.Zero))
        {
            if (handle.IsInvalid) return Marshal.GetLastWin32Error();
            var info = new FILE_DISPOSITION_INFO { DeleteFile = true };
            if (!SetFileInformationByHandle(handle, FileDispositionInfo, ref info, (uint)Marshal.SizeOf<FILE_DISPOSITION_INFO>()))
                return Marshal.GetLastWin32Error();
            return 0;
        }
    }

    public static int TryDeleteOnClose(string path)
    {
        using (var handle = CreateFileW(path, DELETE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            IntPtr.Zero, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_DELETE_ON_CLOSE, IntPtr.Zero))
        {
            if (handle.IsInvalid) return Marshal.GetLastWin32Error();
            return 0;
        }
    }
}
'@

try {
    Remove-PreviousSafeRoot
    New-Item -ItemType Directory -Path $script:DeleteGuardTestRoot -Force | Out-Null
    Set-Content -LiteralPath $sentinelPath -Value 'DeleteGuard disposable VM runtime test root' -Encoding UTF8

    $paths = @{
        PowerShell = Join-Path $script:DeleteGuardTestRoot 'powershell-delete.txt'
        Cmd = Join-Path $script:DeleteGuardTestRoot 'cmd-delete.txt'
        DotNet = Join-Path $script:DeleteGuardTestRoot 'dotnet-delete.txt'
        Win32Disposition = Join-Path $script:DeleteGuardTestRoot 'win32-disposition.txt'
        DeleteOnClose = Join-Path $script:DeleteGuardTestRoot 'delete-on-close.txt'
        RelayDown = Join-Path $script:DeleteGuardTestRoot 'relay-down.txt'
        Stress = Join-Path $script:DeleteGuardTestRoot 'stress.txt'
        RaceSentinel = Join-Path $script:DeleteGuardTestRoot 'race-sentinel.txt'
        ApprovedFile = Join-Path $script:DeleteGuardTestRoot 'approved-file.txt'
        ReloadFallback = Join-Path $script:DeleteGuardTestRoot 'reload-fallback.txt'
    }

    foreach ($path in $paths.Values) { Set-Content -LiteralPath $path -Value 'DeleteGuard runtime test' -Encoding UTF8 }
    $directoryCase = Join-Path $script:DeleteGuardTestRoot 'recursive-directory'
    New-Item -ItemType Directory -Path $directoryCase -Force | Out-Null
    1..20 | ForEach-Object { Set-Content -LiteralPath (Join-Path $directoryCase "file-$_.txt") -Value $_ }

    $approvedTree = Join-Path $script:DeleteGuardTestRoot 'approved-race-tree'
    New-Item -ItemType Directory -Path $approvedTree -Force | Out-Null
    1..500 | ForEach-Object { Set-Content -LiteralPath (Join-Path $approvedTree ("file-{0:D4}.txt" -f $_)) -Value $_ }

    Invoke-DeleteGuardBroker -Command protect -Path $script:DeleteGuardTestRoot
    $protected = $true

    $eventFile = Join-Path $reportDirectory 'denied-events.jsonl'
    $eventBefore = if (Test-Path -LiteralPath $eventFile) { (Get-Item -LiteralPath $eventFile).LastWriteTimeUtc } else { [DateTime]::MinValue }

    try { Remove-Item -LiteralPath $paths.PowerShell -Force -ErrorAction Stop } catch { $psError = $_.Exception.Message }
    Assert-StillExists 'PowerShell Remove-Item denied' $paths.PowerShell ($psError ?? 'file remained protected')

    & cmd.exe /d /c "del /f /q `"$($paths.Cmd)`"" 2>&1 | Out-Null
    Assert-StillExists 'cmd del denied' $paths.Cmd "cmd exit=$LASTEXITCODE"

    try { [IO.File]::Delete($paths.DotNet) } catch { $dotnetError = $_.Exception.Message }
    Assert-StillExists '.NET File.Delete denied' $paths.DotNet ($dotnetError ?? 'file remained protected')

    if (-not ('DeleteGuardRuntimeNativeProbe' -as [type])) {
        Add-Type -TypeDefinition $interopSource -Language CSharp
    }
    $win32Error = [DeleteGuardRuntimeNativeProbe]::TryDispositionDelete($paths.Win32Disposition)
    Assert-StillExists 'Win32 FileDispositionInfo denied' $paths.Win32Disposition "Win32 result=$win32Error"

    $deleteOnCloseError = [DeleteGuardRuntimeNativeProbe]::TryDeleteOnClose($paths.DeleteOnClose)
    Assert-StillExists 'Win32 FILE_FLAG_DELETE_ON_CLOSE denied' $paths.DeleteOnClose "Win32 result=$deleteOnCloseError"

    & cmd.exe /d /c "rmdir /s /q `"$directoryCase`"" 2>&1 | Out-Null
    Assert-StillExists 'recursive directory deletion denied' $directoryCase "cmd exit=$LASTEXITCODE"

    Stop-Service -Name 'DeleteGuardEventRelay' -Force
    (Get-Service -Name 'DeleteGuardEventRelay').WaitForStatus('Stopped', [TimeSpan]::FromSeconds(15))
    try { [IO.File]::Delete($paths.RelayDown) } catch { $relayDownError = $_.Exception.Message }
    Assert-StillExists 'enforcement survives Relay outage' $paths.RelayDown ($relayDownError ?? 'file remained protected')
    Start-Service -Name 'DeleteGuardEventRelay'
    (Get-Service -Name 'DeleteGuardEventRelay').WaitForStatus('Running', [TimeSpan]::FromSeconds(15))
    Start-Sleep -Seconds 2

    for ($i = 0; $i -lt $StressAttempts; $i++) {
        try { [IO.File]::Delete($paths.Stress) } catch { }
    }
    Assert-StillExists 'repeated denied-delete stress' $paths.Stress "attempts=$StressAttempts"

    $raceJob = Start-Job -ScriptBlock {
        param($Path)
        for ($i = 0; $i -lt 600; $i++) {
            try { [IO.File]::Delete($Path) } catch { }
            Start-Sleep -Milliseconds 3
        }
    } -ArgumentList $paths.RaceSentinel

    try {
        Invoke-DeleteGuardBroker -Command delete -Path $approvedTree
    }
    finally {
        Wait-Job -Job $raceJob -Timeout 15 | Out-Null
        Stop-Job -Job $raceJob -ErrorAction SilentlyContinue
        Remove-Job -Job $raceJob -Force -ErrorAction SilentlyContinue
    }
    Add-Result 'approved broker recursive delete' (-not (Test-Path -LiteralPath $approvedTree)) '500-file approved tree'
    Assert-StillExists 'scoped grant blocks competing process' $paths.RaceSentinel 'competing process attempted deletion during broker grant window'

    if ($IncludeDriverReload) {
        & fltmc.exe unload DeleteGuardFilter | Out-Host
        if ($LASTEXITCODE -ne 0) { throw 'Failed to unload DeleteGuardFilter for fallback validation.' }
        try { [IO.File]::Delete($paths.ReloadFallback) } catch { $reloadError = $_.Exception.Message }
        Assert-StillExists 'ACL fallback survives driver unload' $paths.ReloadFallback ($reloadError ?? 'file remained protected')
        & fltmc.exe load DeleteGuardFilter | Out-Host
        if ($LASTEXITCODE -ne 0) { throw 'Failed to reload DeleteGuardFilter.' }
        Wait-DeleteGuardFilterLoaded
        Start-Sleep -Seconds 3
        Add-Result 'driver reload' $true 'filter reloaded; Relay given time to reconnect and synchronize policy'
    }

    Invoke-DeleteGuardBroker -Command delete -Path $paths.ApprovedFile
    Add-Result 'explicit approved file delete' (-not (Test-Path -LiteralPath $paths.ApprovedFile)) 'broker grant path'

    Start-Sleep -Seconds 2
    $eventAfter = if (Test-Path -LiteralPath $eventFile) { (Get-Item -LiteralPath $eventFile).LastWriteTimeUtc } else { [DateTime]::MinValue }
    Add-Result 'kernel denial events reached Event Relay' ($eventAfter -gt $eventBefore) "event stream lastWrite=$eventAfter"
}
catch {
    Add-Result 'runtime harness' $false $_.Exception.ToString()
}
finally {
    try {
        if ($protected -and (Test-Path -LiteralPath $script:DeleteGuardTestRoot)) {
            Invoke-DeleteGuardBroker -Command unprotect -Path $script:DeleteGuardTestRoot
            $protected = $false
        }
    }
    catch {
        Add-Result 'cleanup unprotect' $false $_.Exception.Message
    }

    try {
        if (Test-Path -LiteralPath $script:DeleteGuardTestRoot) {
            if (-not (Test-Path -LiteralPath $sentinelPath)) {
                throw 'Cleanup refused because the runtime-test sentinel is missing.'
            }
            Remove-Item -LiteralPath $script:DeleteGuardTestRoot -Recurse -Force
        }
    }
    catch {
        Add-Result 'cleanup test root' $false $_.Exception.Message
    }

    New-Item -ItemType Directory -Path $reportDirectory -Force | Out-Null
    $report = [ordered]@{
        startedUtc = $startedUtc.ToString('O')
        completedUtc = [DateTimeOffset]::UtcNow.ToString('O')
        machineName = $env:COMPUTERNAME
        includeDriverReload = [bool]$IncludeDriverReload
        stressAttempts = $StressAttempts
        passed = -not ($results | Where-Object { -not $_.passed })
        results = $results
    }
    $report | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $reportPath -Encoding UTF8
    Write-Host "Runtime validation report: $reportPath"
}

if ($results | Where-Object { -not $_.passed }) {
    exit 1
}

Write-Host 'DeleteGuard runtime validation passed. Interactive Explorer/Agent/UAC acceptance remains a manual test.'
exit 0
