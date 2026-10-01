[CmdletBinding()]
param(
    [ValidateSet('Preflight', 'Run', 'SelfTest')]
    [string]$Mode = 'Preflight',
    [switch]$DisposableVm,
    [string]$PackageDirectory,
    [string]$DriverPackageDirectory,
    [string]$ExpectedLoadedDriverSha256,
    [string]$OutputDirectory
)

$ErrorActionPreference = 'Stop'
$script:Cases = [System.Collections.Generic.List[object]]::new()
$script:PackageRoot = $null
$script:BrokerPath = $null
$script:CliPath = $null
$script:CorePath = $null
$script:RunRoot = $null
$script:GuardRoot = $null
$script:Protected = $false
$script:OwnedPaths = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
$script:ChildMayBeRunning = $false

function Get-UtcNow { [DateTimeOffset]::UtcNow.ToString('O') }

function Normalize-Path([string]$Path) {
    $full = [IO.Path]::GetFullPath($Path)
    $root = [IO.Path]::GetPathRoot($full)
    if ($root -and $full.Equals($root, [StringComparison]::OrdinalIgnoreCase)) { return $full }
    return $full.TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar)
}

function Test-UnderPath([string]$Candidate, [string]$Root) {
    $candidateFull = Normalize-Path $Candidate
    $rootFull = Normalize-Path $Root
    return $candidateFull.Equals($rootFull, [StringComparison]::OrdinalIgnoreCase) -or
        $candidateFull.StartsWith($rootFull.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase)
}

function Test-CanonicalFixtureRoot([string]$Candidate, [string]$TempRoot, [string]$RunId) {
    try {
        $fixedParent = Normalize-Path (Join-Path $TempRoot 'DeleteGuard.VmAcceptance')
        $expected = Normalize-Path (Join-Path $fixedParent $RunId)
        $candidateFull = Normalize-Path $Candidate
        return $RunId -match '^[0-9a-f]{32}$' -and
            $candidateFull.Equals($expected, [StringComparison]::OrdinalIgnoreCase) -and
            (Test-UnderPath $candidateFull $fixedParent)
    }
    catch { return $false }
}

function Test-NoReparsePoints([string]$Path) {
    $full = Normalize-Path $Path
    $segments = [System.Collections.Generic.List[string]]::new()
    $cursor = $full
    while ($cursor) {
        $segments.Add($cursor)
        $parent = [IO.Directory]::GetParent($cursor)
        if ($null -eq $parent) { break }
        $cursor = $parent.FullName
    }
    foreach ($segment in $segments) {
        if (Test-Path -LiteralPath $segment) {
            $item = Get-Item -LiteralPath $segment -Force
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { return $false }
        }
    }
    return $true
}

function Test-SafeFixtureTree([string]$Path, [string]$RunRoot, [string]$TempRoot, [string]$RunId) {
    if (-not (Test-CanonicalFixtureRoot $RunRoot $TempRoot $RunId)) { return $false }
    if (-not (Test-UnderPath $Path $RunRoot)) { return $false }
    if (-not (Test-NoReparsePoints $RunRoot)) { return $false }
    if (Test-Path -LiteralPath $RunRoot) {
        foreach ($item in Get-ChildItem -LiteralPath $RunRoot -Force -Recurse) {
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { return $false }
        }
    }
    return $true
}

function Register-OwnedPath([string]$Path) {
    [void]$script:OwnedPaths.Add((Normalize-Path $Path))
}

function Ensure-TestDirectory([string]$Path) {
    $full = Normalize-Path $Path
    if (Test-Path -LiteralPath $full) {
        if (-not $script:OwnedPaths.Contains($full) -or -not (Test-Path -LiteralPath $full -PathType Container)) {
            throw "Fixture path already exists but is not owned by this run: $full"
        }
        return
    }
    if (-not (Test-UnderPath $full $script:RunRoot)) { throw "Fixture directory escaped the owned root: $full" }
    $parent = [IO.Directory]::GetParent($full)
    if ($null -eq $parent) { throw "Cannot resolve fixture directory parent: $full" }
    Ensure-TestDirectory $parent.FullName
    [void](New-Item -ItemType Directory -Path $full -ErrorAction Stop)
    Register-OwnedPath $full
}

function Test-OnlyOwnedPaths([string]$RunRoot) {
    $unexpected = [System.Collections.Generic.List[string]]::new()
    if (-not $script:OwnedPaths.Contains((Normalize-Path $RunRoot))) { $unexpected.Add($RunRoot) }
    foreach ($item in Get-ChildItem -LiteralPath $RunRoot -Force -Recurse -ErrorAction Stop) {
        if (-not $script:OwnedPaths.Contains((Normalize-Path $item.FullName))) { $unexpected.Add($item.FullName) }
    }
    return $unexpected.ToArray()
}

function Get-OverallStatus([object[]]$Items) {
    $statuses = @($Items | ForEach-Object { [string]$_.status })
    if ($statuses -contains 'FAIL') { return 'FAIL' }
    if ($statuses -contains 'BLOCKED') { return 'BLOCKED' }
    if ($statuses -contains 'NOT_RUN') { return 'NOT_RUN' }
    if ($statuses.Count -gt 0 -and @($statuses | Where-Object { $_ -ne 'PASS' }).Count -eq 0) { return 'PASS' }
    return 'NOT_RUN'
}

function Test-RunPrerequisites([pscustomobject]$Facts) {
    $blockers = [System.Collections.Generic.List[string]]::new()
    if (-not $Facts.isWindows) { $blockers.Add('Windows is required.') }
    if (-not $Facts.powershell7) { $blockers.Add('PowerShell 7 or later is required.') }
    if (-not $Facts.disposableVm) { $blockers.Add('Explicit -DisposableVm assertion is required.') }
    if (-not $Facts.virtualMachine) { $blockers.Add('CIM must positively identify virtual hardware.') }
    if (-not $Facts.elevated) { $blockers.Add('Elevated Administrator session is required.') }
    if (-not $Facts.outputWritable) { $blockers.Add('Caller-supplied OutputDirectory must be writable.') }
    if (-not $Facts.coreLoaded) { $blockers.Add('DeleteGuard.Core must load from the expected package.') }
    if (-not $Facts.ntfs) { $blockers.Add('Fixture volume must be NTFS.') }
    if (-not $Facts.driverPackagePresent) { $blockers.Add('Driver package files required for hash evidence are missing.') }
    if (-not $Facts.loadedDriverMatches) { $blockers.Add('Running driver image hash does not match ExpectedLoadedDriverSha256.') }
    if (-not $Facts.driverActive) { $blockers.Add('Active driver Ping and doctor proof with zero roots are required.') }
    if (-not $Facts.emptyPolicyStore) { $blockers.Add('DeleteGuard policy store must be empty before this run.') }
    if (-not $Facts.safeFixturePath) { $blockers.Add('Fixture path must be free of reparse points and CMD metacharacters.') }
    return [pscustomobject]@{ ready = ($blockers.Count -eq 0); blockers = $blockers.ToArray() }
}

function Add-Case([string]$Id, [string]$Status, [string]$Expected, [string]$Observed,
    [string]$Path = '', [Nullable[int]]$ExitCode = $null, [Nullable[int]]$NativeError = $null,
    [object[]]$Evidence = @()) {
    $script:Cases.Add([ordered]@{
        id = $Id
        status = $Status
        observedUtc = Get-UtcNow
        expected = $Expected
        observed = $Observed
        path = $Path
        exitCode = $ExitCode
        nativeError = $NativeError
        evidence = @($Evidence)
    })
}

function Add-TypeAssembly {
    if (-not ('DeleteGuard.Core.Security.AclProtector' -as [type])) {
        Add-Type -Path $script:CorePath
    }
    $loadedCore = ('DeleteGuard.Core.Security.AclProtector' -as [type]).Assembly.Location
    if (-not (Normalize-Path $loadedCore).Equals((Normalize-Path $script:CorePath), [StringComparison]::OrdinalIgnoreCase)) {
        throw 'A different DeleteGuard.Core assembly is already loaded. Start a fresh pwsh -File process with the requested package.'
    }
    if (-not ('DeleteGuard.VmAcceptance.Native' -as [type])) {
        $nativeSource = @'
using System;
using System.Runtime.InteropServices;
namespace DeleteGuard.VmAcceptance {
    public static class Native {
        private const uint DeleteAccess = 0x00010000;
        private const uint ShareAll = 0x00000007;
        private const uint OpenExisting = 3;
        private const uint DeleteOnClose = 0x04000000;
        private static readonly IntPtr InvalidHandle = new IntPtr(-1);

        [DllImport("kernel32.dll", EntryPoint="DeleteFileW", CharSet=CharSet.Unicode, SetLastError=true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool DeleteFileNative(string path);

        public static bool DeleteFile(string path, out int error) {
            bool result = DeleteFileNative(path);
            error = result ? 0 : Marshal.GetLastWin32Error();
            return result;
        }

        [DllImport("kernel32.dll", EntryPoint="RemoveDirectoryW", CharSet=CharSet.Unicode, SetLastError=true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool RemoveDirectoryNative(string path);

        public static bool RemoveDirectory(string path, out int error) {
            bool result = RemoveDirectoryNative(path);
            error = result ? 0 : Marshal.GetLastWin32Error();
            return result;
        }

        [DllImport("kernel32.dll", EntryPoint="CreateFileW", CharSet=CharSet.Unicode, SetLastError=true)]
        private static extern IntPtr CreateFile(string path, uint access, uint share, IntPtr security,
            uint creation, uint flags, IntPtr template);

        [DllImport("kernel32.dll", SetLastError=true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CloseHandle(IntPtr handle);

        public static bool OpenDeleteOnClose(string path, out int error) {
            IntPtr handle = CreateFile(path, DeleteAccess, ShareAll, IntPtr.Zero,
                OpenExisting, DeleteOnClose, IntPtr.Zero);
            if (handle == InvalidHandle) { error = Marshal.GetLastWin32Error(); return false; }
            CloseHandle(handle);
            error = 0;
            return true;
        }
    }
}
'@
        Add-Type -TypeDefinition $nativeSource -Language CSharp
    }
}

function Get-NativeErrorCode([Exception]$Exception) {
    $current = $Exception
    while ($null -ne $current) {
        if ($current -is [ComponentModel.Win32Exception]) { return $current.NativeErrorCode }
        if ($current.HResult -eq [int]0x80070005) { return 5 }
        if ($current.Data -and $current.Data.Contains('NativeErrorCode')) {
            try { return [int]$current.Data['NativeErrorCode'] } catch { }
        }
        $current = $current.InnerException
    }
    return $null
}

function Invoke-BoundedProcess([string]$FilePath, [string[]]$Arguments, [int]$TimeoutSeconds,
    [hashtable]$Environment = @{}) {
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $FilePath
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    foreach ($argument in $Arguments) { [void]$start.ArgumentList.Add([string]$argument) }
    foreach ($key in $Environment.Keys) { $start.Environment[[string]$key] = [string]$Environment[$key] }
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $start
    try {
        if (-not $process.Start()) { throw "Could not start $FilePath" }
        $timer = [Diagnostics.Stopwatch]::StartNew()
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
            try { $process.Kill($true) } catch { }
            [void]$process.WaitForExit(5000)
            $childExited = $false
            try { $childExited = $process.HasExited } catch { }
            if (-not $childExited) { $script:ChildMayBeRunning = $true }
            $stdout = if ($stdoutTask.Wait(1000)) { $stdoutTask.GetAwaiter().GetResult() } else { '[stdout capture timed out]' }
            $stderr = if ($stderrTask.Wait(1000)) { $stderrTask.GetAwaiter().GetResult() } else { '[stderr capture timed out]' }
            return [pscustomobject]@{
                timedOut = $true; exitCode = $null; stdout = $stdout
                stderr = $stderr; durationMs = [int]$timer.ElapsedMilliseconds; childExited = $childExited
            }
        }
        # A descendant can retain the redirected handles even after the direct
        # child exits. Bound stream capture as well as process lifetime.
        if (-not $stdoutTask.Wait(1000) -or -not $stderrTask.Wait(1000)) {
            $script:ChildMayBeRunning = $true
            return [pscustomobject]@{
                timedOut = $true; exitCode = $process.ExitCode
                stdout = '[redirected output capture timed out]'
                stderr = '[a descendant may retain output handles]'
                durationMs = [int]$timer.ElapsedMilliseconds; childExited = $false
            }
        }
        return [pscustomobject]@{
            timedOut = $false; exitCode = $process.ExitCode
            stdout = $stdoutTask.GetAwaiter().GetResult(); stderr = $stderrTask.GetAwaiter().GetResult()
            durationMs = [int]$timer.ElapsedMilliseconds; childExited = $true
        }
    }
    finally { $process.Dispose() }
}

function Get-PackageFiles([string]$Directory) {
    $required = @(
        'deleteguard.exe', 'deleteguard.dll', 'deleteguard.runtimeconfig.json',
        'deleteguard.deps.json', 'DeleteGuard.Broker.exe', 'DeleteGuard.Broker.dll',
        'DeleteGuard.Broker.runtimeconfig.json', 'DeleteGuard.Broker.deps.json', 'DeleteGuard.Core.dll'
    )
    return @($required | ForEach-Object { Join-Path $Directory $_ })
}

function Get-ArtifactHashes([string[]]$Paths) {
    $hashes = [System.Collections.Generic.List[object]]::new()
    foreach ($path in $Paths) {
        if (Test-Path -LiteralPath $path -PathType Leaf) {
            $item = Get-Item -LiteralPath $path
            $hashes.Add([ordered]@{
                path = $item.FullName
                length = $item.Length
                sha256 = (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash
            })
        }
    }
    return $hashes.ToArray()
}

function Test-OutputWritable([string]$Path) {
    if ([string]::IsNullOrWhiteSpace($Path)) { return [pscustomobject]@{ writable = $false; path = ''; error = 'OutputDirectory was not supplied.' } }
    $full = $Path
    $probe = $null
    try {
        $full = [IO.Path]::GetFullPath($Path)
        $probe = Join-Path $full ('.deleteguard-writecheck-' + [Guid]::NewGuid().ToString('N') + '.tmp')
        [void](New-Item -ItemType Directory -Path $full -Force)
        [IO.File]::WriteAllText($probe, 'DeleteGuard evidence write check')
        $ok = [IO.File]::ReadAllText($probe) -eq 'DeleteGuard evidence write check'
        Remove-Item -LiteralPath $probe -Force -ErrorAction Stop
        return [pscustomobject]@{ writable = $ok; path = $full; error = $null }
    }
    catch {
        if ($probe -and (Test-Path -LiteralPath $probe)) { try { Remove-Item -LiteralPath $probe -Force -ErrorAction Stop } catch { } }
        return [pscustomobject]@{ writable = $false; path = $full; error = $_.Exception.ToString() }
    }
}

function Test-AccessDeniedEvidence([Nullable[int]]$NativeError, [bool]$ExplicitDeniedEvidence) {
    if ($null -ne $NativeError) { return $NativeError -eq 5 }
    return $ExplicitDeniedEvidence
}

function Get-AdminState {
    if (-not $IsWindows) { return $false }
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-VmState {
    if (-not $IsWindows) { return [pscustomobject]@{ recognized = $false; manufacturer = ''; model = ''; error = 'Windows required' } }
    try {
        $system = Get-CimInstance -ClassName Win32_ComputerSystem
        $manufacturer = [string]$system.Manufacturer
        $model = [string]$system.Model
        $recognized = ($manufacturer + ' ' + $model) -match '(?i)(VMware|VirtualBox|KVM|QEMU|Virtual Machine|HVM domU|Xen|Parallels|Amazon EC2|Google Compute Engine|OpenStack|bhyve)'
        return [pscustomobject]@{ recognized = [bool]$recognized; manufacturer = $manufacturer; model = $model; error = $null }
    }
    catch { return [pscustomobject]@{ recognized = $false; manufacturer = ''; model = ''; error = $_.Exception.Message } }
}

function Resolve-DriverImagePath([string]$PathName) {
    $path = $PathName.Trim().Trim('"')
    if ($path.StartsWith('\SystemRoot\', [StringComparison]::OrdinalIgnoreCase)) {
        $path = Join-Path $env:SystemRoot $path.Substring('\SystemRoot\'.Length)
    }
    elseif ($path.StartsWith('\??\', [StringComparison]::OrdinalIgnoreCase)) {
        $path = $path.Substring('\??\'.Length)
    }
    elseif ($path.StartsWith('\\?\', [StringComparison]::OrdinalIgnoreCase)) {
        $path = $path.Substring('\\?\'.Length)
    }
    $path = [Environment]::ExpandEnvironmentVariables($path)
    return [IO.Path]::GetFullPath($path)
}

function Get-LoadedDriverEvidence([string]$ExpectedHash) {
    $evidence = [ordered]@{
        serviceName = 'DeleteGuardFilter'
        state = $null
        imagePath = $null
        imageSha256 = $null
        expectedSha256 = $ExpectedHash
        imageHashMatches = $false
        fltmcFiltersExitCode = $null
        fltmcFiltersOutput = ''
        fltmcInstancesExitCode = $null
        fltmcInstancesOutput = ''
        loadedEvidence = $false
        hashProvenance = 'Hash is for the on-disk image referenced by the running service; loaded memory bytes are not hashed.'
        error = $null
    }
    if (-not $IsWindows) { $evidence.error = 'Windows required.'; return [pscustomobject]$evidence }
    try {
        $service = Get-CimInstance -ClassName Win32_SystemDriver -Filter "Name='DeleteGuardFilter'"
        if ($null -eq $service) { $evidence.error = 'Win32_SystemDriver entry not found.'; return [pscustomobject]$evidence }
        $evidence.state = [string]$service.State
        $imagePath = Resolve-DriverImagePath ([string]$service.PathName)
        $evidence.imagePath = $imagePath
        if (Test-Path -LiteralPath $imagePath -PathType Leaf) {
            $evidence.imageSha256 = (Get-FileHash -LiteralPath $imagePath -Algorithm SHA256).Hash
            $evidence.imageHashMatches = $ExpectedHash -match '^[0-9a-fA-F]{64}$' -and
                $evidence.imageSha256.Equals($ExpectedHash, [StringComparison]::OrdinalIgnoreCase)
        }
        $fltmc = Join-Path $env:SystemRoot 'System32\fltmc.exe'
        if (Test-Path -LiteralPath $fltmc -PathType Leaf) {
            $filters = Invoke-BoundedProcess $fltmc @('filters') 10
            $instances = Invoke-BoundedProcess $fltmc @('instances', '-f', 'DeleteGuardFilter') 10
            $evidence.fltmcFiltersExitCode = $filters.exitCode
            $evidence.fltmcFiltersOutput = ($filters.stdout + $filters.stderr).Trim()
            $evidence.fltmcInstancesExitCode = $instances.exitCode
            $evidence.fltmcInstancesOutput = ($instances.stdout + $instances.stderr).Trim()
            $fltmcProof = -not $filters.timedOut -and -not $instances.timedOut -and
                $filters.exitCode -eq 0 -and $instances.exitCode -eq 0 -and
                $filters.stdout -match '(?i)DeleteGuardFilter' -and $instances.stdout -match '(?i)DeleteGuardFilter'
            $evidence.loadedEvidence = $service.State -eq 'Running' -and $fltmcProof -and $evidence.imageHashMatches
        }
        else { $evidence.error = 'fltmc.exe was not found.' }
        if ($ExpectedHash -notmatch '^[0-9a-fA-F]{64}$') { $evidence.error = 'ExpectedLoadedDriverSha256 must be a 64-character SHA-256 value.' }
    }
    catch { $evidence.error = $_.Exception.ToString() }
    return [pscustomobject]$evidence
}

function Get-FixtureVolumeState([string]$Path) {
    try {
        $root = [IO.Path]::GetPathRoot((Normalize-Path $Path))
        $drive = [IO.DriveInfo]::new($root)
        return [pscustomobject]@{ ntfs = $drive.DriveFormat.Equals('NTFS', [StringComparison]::OrdinalIgnoreCase); root = $root; format = $drive.DriveFormat; error = $null }
    }
    catch { return [pscustomobject]@{ ntfs = $false; root = ''; format = ''; error = $_.Exception.Message } }
}

function Get-DriverPing {
    if (-not $IsWindows -or -not (Get-AdminState)) {
        return [pscustomobject]@{ active = $false; protocol = $null; roots = $null; error = 'Elevated Windows session required for the command port.' }
    }
    try {
        $driver = $null
        if (-not [DeleteGuard.Core.Driver.FilterPortClient]::TryConnect([ref]$driver) -or $null -eq $driver) {
            return [pscustomobject]@{ active = $false; protocol = $null; roots = $null; error = 'Filter Manager command port connection failed.' }
        }
        try {
            $reply = $driver.Ping()
            return [pscustomobject]@{ active = $true; protocol = [DeleteGuard.Core.Driver.DriverProtocol]::Version; roots = $reply.RootCount; error = $null }
        }
        finally { $driver.Dispose() }
    }
    catch { return [pscustomobject]@{ active = $false; protocol = $null; roots = $null; error = $_.Exception.ToString() } }
}

function Get-PolicyCount {
    try {
        $store = [DeleteGuard.Core.Services.PolicyStore]::new()
        return [int]$store.Load().Count
    }
    catch { return -1 }
}

function Test-AccessDeniedResult([string]$Id, [string]$Path, [scriptblock]$Action, [string]$Expected) {
    $nativeError = $null
    $exitCode = $null
    $detail = ''
    $denied = $false
    try {
        $result = & $Action $Path
        if ($result -is [System.Collections.IDictionary]) {
            $detail = [string]$result.detail
            $exitCode = $result.exitCode
            $nativeError = $result.nativeError
            $denied = [bool]$result.denied -and (Test-AccessDeniedEvidence $nativeError ([bool]$result.denied))
        }
        elseif ($null -ne $result) {
            $detail = [string]$result
        }
        else { $detail = 'Operation returned without an access-denied result.' }
    }
    catch {
        $detail = $_.Exception.ToString()
        $nativeError = Get-NativeErrorCode $_.Exception
        $denied = Test-AccessDeniedEvidence $nativeError $false
    }
    $exists = Test-Path -LiteralPath $Path
    $status = if ($denied -and $exists) { 'PASS' } else { 'FAIL' }
    Add-Case $Id $status $Expected "$detail; targetExists=$exists" $Path $exitCode $nativeError
}

function Get-TreeSnapshot([string]$Path) {
    $entries = [System.Collections.Generic.List[object]]::new()
    foreach ($item in Get-ChildItem -LiteralPath $Path -Force -Recurse -ErrorAction Stop) {
        $relative = [IO.Path]::GetRelativePath($Path, $item.FullName)
        if ($item.PSIsContainer) {
            $entries.Add([ordered]@{ path = $relative; type = 'directory'; length = $null; sha256 = $null })
        }
        else {
            $entries.Add([ordered]@{ path = $relative; type = 'file'; length = $item.Length; sha256 = (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash })
        }
    }
    return @($entries.ToArray() | Sort-Object path)
}

function Test-AccessDeniedDirectoryResult([string]$Id, [string]$Path, [scriptblock]$Action, [string]$Expected) {
    $before = Get-TreeSnapshot $Path
    $nativeError = $null
    $exitCode = $null
    $detail = ''
    $denied = $false
    try {
        $result = & $Action $Path
        if ($result -is [System.Collections.IDictionary]) {
            $detail = [string]$result.detail
            $exitCode = $result.exitCode
            $nativeError = $result.nativeError
            $denied = [bool]$result.denied -and (Test-AccessDeniedEvidence $nativeError ([bool]$result.denied))
        }
        else { $detail = 'Operation returned without explicit access-denied evidence.' }
    }
    catch {
        $detail = $_.Exception.ToString()
        $nativeError = Get-NativeErrorCode $_.Exception
        $denied = Test-AccessDeniedEvidence $nativeError $false
    }
    $exists = Test-Path -LiteralPath $Path -PathType Container
    $after = if ($exists) { Get-TreeSnapshot $Path } else { @() }
    $same = $exists -and ((ConvertTo-Json -InputObject $before -Compress -Depth 6) -ceq (ConvertTo-Json -InputObject $after -Compress -Depth 6))
    $status = if ($denied -and $same) { 'PASS' } else { 'FAIL' }
    $evidence = @([ordered]@{ before = $before; after = $after })
    Add-Case $Id $status $Expected "$detail; targetExists=$exists; treeUnchanged=$same" $Path $exitCode $nativeError $evidence
}

function Assert-Case([string]$Id, [string]$Expected, [string]$Observed, [bool]$Passed,
    [string]$Path = '', [Nullable[int]]$ExitCode = $null, [Nullable[int]]$NativeError = $null,
    [object[]]$Evidence = @()) {
    Add-Case $Id $(if ($Passed) { 'PASS' } else { 'FAIL' }) $Expected $Observed $Path $ExitCode $NativeError $Evidence
}

function New-TestFile([string]$Path) {
    $parent = [IO.Path]::GetDirectoryName($Path)
    Ensure-TestDirectory $parent
    if (Test-Path -LiteralPath $Path) { throw "Fixture file path already exists: $Path" }
    [IO.File]::WriteAllText($Path, 'DeleteGuard disposable VM acceptance fixture')
    Register-OwnedPath $Path
}

function New-TestDirectory([string]$Path, [int]$FileCount = 0) {
    Ensure-TestDirectory $Path
    for ($index = 0; $index -lt $FileCount; $index++) {
        New-TestFile (Join-Path $Path ("item-{0}.txt" -f $index))
    }
}

function Invoke-CmdDelete([string]$Path, [bool]$Directory) {
    if ($Path -match '[%\^!&|<>"()]') {
        return @{ denied = $false; exitCode = $null; nativeError = $null; detail = 'Path contains CMD metacharacters; probe safely skipped.' }
    }
    $command = if ($Directory) { "rmdir /s /q `"$Path`"" } else { "del /f /q `"$Path`"" }
    $result = Invoke-BoundedProcess "$env:SystemRoot\System32\cmd.exe" @('/d', '/c', $command) 12
    $text = ($result.stdout + "`n" + $result.stderr).Trim()
    $deniedText = $text -match '(?i)(access is denied|access denied|\[winerror 5\]|拒絕存取|拒绝访问|アクセスが拒否|拒否されました|zugriff verweigert|accès refusé)'
    return @{ denied = (-not $result.timedOut -and $deniedText); exitCode = $result.exitCode; nativeError = $null; detail = "denialSource=CMD message (no measured native error code); timedOut=$($result.timedOut); output=$text" }
}

function Invoke-PythonDelete([string]$Path, [string]$PythonPath, [string]$ScriptPath) {
    $result = Invoke-BoundedProcess $PythonPath @($ScriptPath, $Path) 12
    $text = $result.stdout.Trim()
    $json = $null
    try { $json = $text | ConvertFrom-Json -ErrorAction Stop } catch { }
    $denied = -not $result.timedOut -and $result.exitCode -ne 0 -and $null -ne $json -and $json.winerror -eq 5
    return @{ denied = $denied; exitCode = $result.exitCode; nativeError = $(if ($null -ne $json) { $json.winerror } else { $null }); detail = "timedOut=$($result.timedOut); stdout=$text; stderr=$($result.stderr.Trim())" }
}

function Invoke-ProtectFixture {
    $result = Invoke-BoundedProcess $script:BrokerPath @('protect', $script:GuardRoot) 45
    $script:Protected = [DeleteGuard.Core.Security.AclProtector]::HasGuardRule($script:GuardRoot)
    $active = $result.stdout -match '(?im)^Kernel enforcement:\s*active\s*$'
    $passed = -not $result.timedOut -and $result.exitCode -eq 0 -and $active -and $script:Protected
    Assert-Case 'broker-protect' 'Broker registers the fixture root, inserts the guard ACL, and reports kernel enforcement active.' `
        "timedOut=$($result.timedOut); exit=$($result.exitCode); guardPresent=$($script:Protected); output=$($result.stdout.Trim()) $($result.stderr.Trim())" `
        $passed $script:GuardRoot $result.exitCode $null
    return $passed
}

function Get-DeleteDenyRules([string]$Path) {
    $needed = [int]([Security.AccessControl.FileSystemRights]::Delete -bor [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles)
    $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
    $rules = $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])
    $matches = [System.Collections.Generic.List[object]]::new()
    foreach ($rule in $rules) {
        if ($rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Deny) { continue }
        if (([int]$rule.FileSystemRights -band $needed) -eq 0) { continue }
        $matches.Add([ordered]@{ path = $Path; sid = $rule.IdentityReference.Value; rights = [string]$rule.FileSystemRights; inherited = $rule.IsInherited })
    }
    return $matches.ToArray()
}

function Invoke-BrokerDelete([string]$Id, [string]$Target, [bool]$Directory, [string]$Sentinel) {
    $sentinelHash = if ([IO.File]::Exists($Sentinel)) { (Get-FileHash -LiteralPath $Sentinel).Hash } else { $null }
    $result = Invoke-BoundedProcess $script:BrokerPath @('delete', $Target) 45
    $gone = -not (Test-Path -LiteralPath $Target)
    $grantClaim = $result.stdout -match '(?im)^Kernel grant:\s*used and revoked\s*$'
    $guardRestored = [DeleteGuard.Core.Security.AclProtector]::HasGuardRule($script:GuardRoot)
    $sentinelIntact = $null -ne $sentinelHash -and [IO.File]::Exists($Sentinel) -and (Get-FileHash -LiteralPath $Sentinel).Hash -eq $sentinelHash
    $passed = -not $result.timedOut -and $result.exitCode -eq 0 -and $grantClaim -and $gone -and $guardRestored -and $sentinelIntact
    Assert-Case $Id 'Broker reports its kernel grant was used and revoked; approved target is gone, an unrelated sentinel remains unchanged, and fixture guard ACL is restored.' `
        "timedOut=$($result.timedOut); exit=$($result.exitCode); grantClaim=$grantClaim; targetGone=$gone; guardRestored=$guardRestored; sentinel=$Sentinel; sentinelIntact=$sentinelIntact; output=$($result.stdout.Trim()) $($result.stderr.Trim())" `
        $passed $Target $result.exitCode $null
}

function Invoke-KernelOnlyProbe([string]$Target) {
    $mutex = [Threading.Mutex]::new($false, 'Global\DeleteGuard.Broker.Mutation')
    $acquired = $false
    $mutexReleased = $false
    $removed = $false
    $restored = $false
    $nativeError = $null
    $deleteSucceeded = $null
    $probeBlocked = $false
    $detail = ''
    try {
        try { $acquired = $mutex.WaitOne([TimeSpan]::FromSeconds(30)) }
        catch [Threading.AbandonedMutexException] { $acquired = $true }
        if (-not $acquired) { $probeBlocked = $true; throw 'Mutation mutex was not acquired within 30 seconds.' }
        $removed = [DeleteGuard.Core.Security.AclProtector]::Remove($script:GuardRoot)
        if (-not $removed -or [DeleteGuard.Core.Security.AclProtector]::HasGuardRule($script:GuardRoot)) {
            throw 'The exact fixture guard ACL could not be removed for the kernel-only probe.'
        }
        $parentPath = [IO.Directory]::GetParent($Target).FullName
        $residualDenies = @((Get-DeleteDenyRules $Target) + (Get-DeleteDenyRules $parentPath))
        if ($residualDenies.Count -gt 0) {
            $probeBlocked = $true
            $detail = "Residual delete-deny ACL may mask kernel enforcement: $($residualDenies | ConvertTo-Json -Compress)"
        }
        else {
            $deleteSucceeded = [DeleteGuard.VmAcceptance.Native]::DeleteFile($Target, [ref]$nativeError)
            $detail = "mutexAcquired=$acquired; aclRemoved=$removed; DeleteFileW=$deleteSucceeded; targetExists=$(Test-Path -LiteralPath $Target)"
        }
    }
    catch { $detail = $_.Exception.ToString() }
    finally {
        if ($acquired) {
            try {
                if ((Test-Path -LiteralPath $script:GuardRoot) -and -not [DeleteGuard.Core.Security.AclProtector]::HasGuardRule($script:GuardRoot)) {
                    [void][DeleteGuard.Core.Security.AclProtector]::Apply($script:GuardRoot)
                }
                $restored = [DeleteGuard.Core.Security.AclProtector]::HasGuardRule($script:GuardRoot)
            }
            catch { $detail += "; ACL restore error=$($_.Exception.ToString())" }
            try { $mutex.ReleaseMutex(); $mutexReleased = $true }
            catch { $detail += "; mutex release error=$($_.Exception.Message)" }
        }
        elseif (Test-Path -LiteralPath $script:GuardRoot) {
            try { $restored = [DeleteGuard.Core.Security.AclProtector]::HasGuardRule($script:GuardRoot) } catch { }
        }
        $mutex.Dispose()
    }
    $exists = Test-Path -LiteralPath $Target
    $passed = $acquired -and $removed -and -not $deleteSucceeded -and $nativeError -eq 5 -and $exists -and $restored -and $mutexReleased
    $status = if ($acquired -and (-not $restored -or -not $mutexReleased)) { 'FAIL' } elseif ($probeBlocked) { 'BLOCKED' } elseif ($passed) { 'PASS' } else { 'FAIL' }
    Add-Case 'kernel-only-win32-delete' $status 'With only the registered minifilter policy enforcing this fixture, DeleteFileW returns native error 5 and leaves the file; guard ACL is restored.' `
        "$detail; nativeError=$nativeError; guardRestored=$restored" $Target $null $nativeError
}

function Invoke-RunCleanup([string]$TempRoot, [string]$RunId) {
    $cleanupNotes = [System.Collections.Generic.List[string]]::new()
    $cleanupPassed = $true
    if ($script:ChildMayBeRunning) {
        Add-Case 'cleanup-owned-fixture' 'FAIL' 'Do not unprotect or delete fixture while a timed-out child may still be running.' "Fixture retained for recovery because a child process did not exit after termination request: $script:RunRoot" $script:RunRoot
        return
    }
    $safeToTouch = $false
    if ($script:RunRoot -and (Test-Path -LiteralPath $script:RunRoot)) {
        $safeToTouch = (Test-SafeFixtureTree $script:RunRoot $script:RunRoot $TempRoot $RunId) -and
            $script:OwnedPaths.Contains((Normalize-Path $script:RunRoot))
    }
    if (-not $safeToTouch) {
        $cleanupPassed = $false
        $cleanupNotes.Add("Policy/ACL left untouched because the owned GUID subtree failed path or reparse validation: $script:RunRoot")
    }
    elseif ($script:Protected -and (Test-Path -LiteralPath $script:GuardRoot)) {
        try {
            $policies = [DeleteGuard.Core.Services.PolicyStore]::new().Load()
            $policy = @($policies | Where-Object { $_.RootPath.Equals($script:GuardRoot, [StringComparison]::OrdinalIgnoreCase) })
            if ($policy.Count -gt 0) {
                $result = Invoke-BoundedProcess $script:BrokerPath @('unprotect', $script:GuardRoot) 45
                $cleanupNotes.Add("broker-unprotect exit=$($result.exitCode); timedOut=$($result.timedOut); output=$($result.stdout.Trim()) $($result.stderr.Trim())")
                if ($result.timedOut -or $result.exitCode -ne 0) { $cleanupPassed = $false }
            }
            elseif ([DeleteGuard.Core.Security.AclProtector]::HasGuardRule($script:GuardRoot)) {
                [void][DeleteGuard.Core.Security.AclProtector]::Remove($script:GuardRoot)
                $cleanupNotes.Add('Removed leftover exact fixture guard ACL; no fixture policy remained.')
            }
            $policiesAfter = [DeleteGuard.Core.Services.PolicyStore]::new().Load()
            $stillRegistered = @($policiesAfter | Where-Object { $_.RootPath.Equals($script:GuardRoot, [StringComparison]::OrdinalIgnoreCase) }).Count -gt 0
            $guardRemains = [IO.Directory]::Exists($script:GuardRoot) -and [DeleteGuard.Core.Security.AclProtector]::HasGuardRule($script:GuardRoot)
            if ($stillRegistered -or $guardRemains) { $cleanupPassed = $false; $cleanupNotes.Add("policyRemains=$stillRegistered; guardRemains=$guardRemains") }
        }
        catch { $cleanupPassed = $false; $cleanupNotes.Add("Unprotect failed: $($_.Exception.ToString())") }
    }
    elseif (-not $script:Protected -and $safeToTouch -and $script:GuardRoot -and [IO.Directory]::Exists($script:GuardRoot)) {
        try {
            $policies = [DeleteGuard.Core.Services.PolicyStore]::new().Load()
            $policyCount = @($policies | Where-Object { $_.RootPath.Equals($script:GuardRoot, [StringComparison]::OrdinalIgnoreCase) }).Count
            if ($policyCount -gt 0) {
                $result = Invoke-BoundedProcess $script:BrokerPath @('unprotect', $script:GuardRoot) 45
                $cleanupNotes.Add("partial-protect broker-unprotect exit=$($result.exitCode); timedOut=$($result.timedOut)")
                if ($result.timedOut -or $result.exitCode -ne 0) { $cleanupPassed = $false }
            }
            elseif ([DeleteGuard.Core.Security.AclProtector]::HasGuardRule($script:GuardRoot)) {
                [void][DeleteGuard.Core.Security.AclProtector]::Remove($script:GuardRoot)
                $cleanupNotes.Add('Removed leftover exact fixture guard ACL; no fixture policy remained.')
            }
            $policiesAfter = [DeleteGuard.Core.Services.PolicyStore]::new().Load()
            $stillRegistered = @($policiesAfter | Where-Object { $_.RootPath.Equals($script:GuardRoot, [StringComparison]::OrdinalIgnoreCase) }).Count -gt 0
            $guardRemains = [IO.Directory]::Exists($script:GuardRoot) -and [DeleteGuard.Core.Security.AclProtector]::HasGuardRule($script:GuardRoot)
            if ($stillRegistered -or $guardRemains) { $cleanupPassed = $false; $cleanupNotes.Add("partial-protect cleanup remains: policy=$stillRegistered; guard=$guardRemains") }
        }
        catch { $cleanupPassed = $false; $cleanupNotes.Add("Partial-protect cleanup failed: $($_.Exception.ToString())") }
    }

    if ($safeToTouch) {
        try {
            $unexpected = @(Test-OnlyOwnedPaths $script:RunRoot)
            if ($unexpected.Count -gt 0) {
                $cleanupPassed = $false
                $cleanupNotes.Add("Unexpected unowned paths found; fixture retained: $($unexpected -join ', ')")
            }
        }
        catch { $cleanupPassed = $false; $cleanupNotes.Add("Owned-path inventory failed: $($_.Exception.ToString())") }
    }

    if ($script:RunRoot -and (Test-Path -LiteralPath $script:RunRoot)) {
        if ($cleanupPassed -and $safeToTouch -and (Test-SafeFixtureTree $script:RunRoot $script:RunRoot $TempRoot $RunId)) {
            try {
                Remove-Item -LiteralPath $script:RunRoot -Recurse -Force -ErrorAction Stop
                $cleanupNotes.Add('Deleted only the verified GUID fixture subtree with PowerShell LiteralPath.')
            }
            catch { $cleanupPassed = $false; $cleanupNotes.Add("Fixture removal failed: $($_.Exception.ToString())") }
        }
        else { $cleanupPassed = $false; $cleanupNotes.Add("Fixture retained; cleanup preconditions failed. Recovery path: $script:RunRoot") }
    }
    $script:Protected = $false
    Add-Case 'cleanup-owned-fixture' $(if ($cleanupPassed) { 'PASS' } else { 'FAIL' }) `
        'Unprotect the owned policy first, then remove only the verified literal GUID fixture subtree.' `
        ($cleanupNotes -join ' | ') $script:RunRoot
}

function Invoke-Preflight([bool]$ForRun) {
    $tempRoot = [IO.Path]::GetTempPath()
    $vm = Get-VmState
    $admin = Get-AdminState
    $volume = Get-FixtureVolumeState $tempRoot
    $output = Test-OutputWritable $OutputDirectory
    $powershell7 = $PSVersionTable.PSVersion.Major -ge 7

    Add-Case 'windows-powershell' $(if ($IsWindows -and $powershell7) { 'PASS' } else { 'BLOCKED' }) 'Windows PowerShell 7 or later.' "OS=$([Environment]::OSVersion.Platform); PowerShell=$($PSVersionTable.PSVersion)"
    Add-Case 'virtual-machine' $(if ($vm.recognized) { 'PASS' } else { 'BLOCKED' }) 'CIM manufacturer/model identifies recognized virtual hardware.' "recognized=$($vm.recognized); manufacturer=$($vm.manufacturer); model=$($vm.model); error=$($vm.error)"
    Add-Case 'elevated-session' $(if ($admin) { 'PASS' } else { 'BLOCKED' }) 'Current process token is elevated as Administrator.' "elevated=$admin"
    Add-Case 'fixture-volume-ntfs' $(if ($volume.ntfs) { 'PASS' } else { 'BLOCKED' }) 'The %TEMP% fixture volume is NTFS.' "root=$($volume.root); format=$($volume.format); error=$($volume.error)"
    Add-Case 'output-directory' $(if ($output.writable) { 'PASS' } else { 'BLOCKED' }) 'Caller-supplied evidence OutputDirectory can be created and written before fixture mutations.' "path=$($output.path); error=$($output.error)" $output.path

    $packageAvailable = -not [string]::IsNullOrWhiteSpace($PackageDirectory) -and (Test-Path -LiteralPath $PackageDirectory -PathType Container)
    $packageOk = $false
    $packageFiles = @()
    $missing = @()
    if ($packageAvailable) {
        $script:PackageRoot = (Resolve-Path -LiteralPath $PackageDirectory).Path
        $script:CliPath = Join-Path $script:PackageRoot 'deleteguard.exe'
        $script:BrokerPath = Join-Path $script:PackageRoot 'DeleteGuard.Broker.exe'
        $script:CorePath = Join-Path $script:PackageRoot 'DeleteGuard.Core.dll'
        $packageFiles = Get-PackageFiles $script:PackageRoot
        $missing = @($packageFiles | Where-Object { -not (Test-Path -LiteralPath $_ -PathType Leaf) })
        $packageOk = $missing.Count -eq 0
    }
    Add-Case 'package-files' $(if ($packageOk) { 'PASS' } else { 'BLOCKED' }) 'Published CLI, Broker, Core, and required runtime/dependency files exist.' "package=$script:PackageRoot; missing=$($missing -join ', '); supplied=$packageAvailable" $script:PackageRoot $null $null (Get-ArtifactHashes $packageFiles)

    $coreLoaded = $false
    $coreError = $null
    if ($packageOk) {
        try { Add-TypeAssembly; $coreLoaded = $true }
        catch { $coreError = $_.Exception.ToString() }
    }
    Add-Case 'core-assembly-load' $(if ($coreLoaded) { 'PASS' } else { 'BLOCKED' }) 'DeleteGuard.Core loads for its public ACL, policy, and driver contracts.' "loaded=$coreLoaded; error=$coreError" $script:CorePath

    $driverDirectory = $DriverPackageDirectory
    if ([string]::IsNullOrWhiteSpace($driverDirectory) -and $script:PackageRoot) {
        $driverDirectory = Join-Path (Split-Path -Parent $script:PackageRoot) 'driver-x64'
    }
    $driverFiles = @()
    $driverMissing = @()
    $driverPackageOk = $false
    if (-not [string]::IsNullOrWhiteSpace($driverDirectory)) {
        foreach ($name in @('DeleteGuardFilter.sys', 'DeleteGuardFilter.inf', 'deleteguardfilter.cat')) { $driverFiles += Join-Path $driverDirectory $name }
        $driverMissing = @($driverFiles | Where-Object { -not (Test-Path -LiteralPath $_ -PathType Leaf) })
        $driverPackageOk = $driverMissing.Count -eq 0
    }
    Add-Case 'driver-package-files' $(if ($driverPackageOk) { 'PASS' } else { 'BLOCKED' }) 'Unsigned CI driver package files are present for hash evidence.' "driverPackage=$driverDirectory; missing=$($driverMissing -join ', ')" $driverDirectory $null $null (Get-ArtifactHashes $driverFiles)

    $ping = if ($coreLoaded -and $admin -and $IsWindows) { Get-DriverPing } else { [pscustomobject]@{ active = $false; protocol = $null; roots = $null; error = 'Core package or elevated Windows session unavailable.' } }
    $doctor = $null
    if ($packageOk -and $admin -and $IsWindows) {
        try { $doctor = Invoke-BoundedProcess $script:CliPath @('doctor') 10 }
        catch { $doctor = [pscustomobject]@{ timedOut = $false; exitCode = $null; stdout = ''; stderr = $_.Exception.ToString() } }
    }
    $doctorText = if ($null -ne $doctor) { [string]$doctor.stdout } else { '' }
    $doctorMatch = [regex]::Match($doctorText, '(?im)^Minifilter:\s*active\s*\(protocol=(\d+), roots=(\d+)\)')
    $doctorProof = $null -ne $doctor -and -not $doctor.timedOut -and $doctorMatch.Success
    $doctorRoots = if ($doctorProof) { [int]$doctorMatch.Groups[2].Value } else { $null }
    $driverActive = $ping.active -and $ping.roots -eq 0 -and $doctorProof -and $doctorRoots -eq 0
    $doctorExit = if ($null -ne $doctor) { $doctor.exitCode } else { $null }
    $doctorOutput = if ($null -ne $doctor) { "$($doctor.stdout.Trim()) $($doctor.stderr.Trim())" } else { '[doctor not run]' }
    $driverObservation = "ping=$($ping | ConvertTo-Json -Compress); pingRoots=$($ping.roots); doctorExit=$doctorExit; doctorProof=$doctorProof; doctorRoots=$doctorRoots; doctorOutput=$doctorOutput"
    Add-Case 'loaded-driver-proof' $(if ($driverActive) { 'PASS' } else { 'BLOCKED' }) 'FilterPortClient Ping succeeds, Ping/doctor root count is zero, and elevated doctor explicitly reports Minifilter active.' $driverObservation $script:CliPath $doctorExit
    $loadedDriver = if ($admin -and $IsWindows) { Get-LoadedDriverEvidence $ExpectedLoadedDriverSha256 } else { [pscustomobject]@{ loadedEvidence = $false; error = 'Elevated Windows session required.'; imagePath = $null; imageSha256 = $null; expectedSha256 = $ExpectedLoadedDriverSha256 } }
    Add-Case 'loaded-driver-image' $(if ($loadedDriver.loadedEvidence) { 'PASS' } else { 'BLOCKED' }) 'Running Win32_SystemDriver image path, fltmc filter/instance output, and on-disk SHA-256 match the caller expected hash.' ($loadedDriver | ConvertTo-Json -Compress -Depth 6) $loadedDriver.imagePath

    $policyCount = if ($coreLoaded) { Get-PolicyCount } else { -1 }
    $emptyPolicies = $policyCount -eq 0
    Add-Case 'empty-policy-store' $(if ($emptyPolicies) { 'PASS' } else { 'BLOCKED' }) 'Disposable acceptance VM starts with no existing DeleteGuard policies.' "policyCount=$policyCount"

    $safeFixturePath = (Test-NoReparsePoints $tempRoot) -and (Get-SafeCmdPath $tempRoot)
    Add-Case 'fixture-path-safety' $(if ($safeFixturePath) { 'PASS' } else { 'BLOCKED' }) 'Temp ancestors have no reparse points and path is safe for bounded CMD probes.' "path=$tempRoot; safe=$safeFixturePath"
    if (-not $ForRun) { Add-Case 'automated-fixture-suite' 'NOT_RUN' 'Run mode has not been requested; no fixture or policy mutation occurred.' 'Read-only preflight.' }

    $facts = [pscustomobject]@{
        isWindows = [bool]$IsWindows
        powershell7 = [bool]$powershell7
        disposableVm = [bool]$DisposableVm
        virtualMachine = [bool]$vm.recognized
        elevated = [bool]$admin
        outputWritable = [bool]$output.writable
        coreLoaded = [bool]$coreLoaded
        ntfs = [bool]$volume.ntfs
        driverPackagePresent = [bool]$driverPackageOk
        driverActive = [bool]$driverActive
        loadedDriverMatches = [bool]$loadedDriver.loadedEvidence
        emptyPolicyStore = [bool]$emptyPolicies
        safeFixturePath = [bool]$safeFixturePath
    }
    $gate = Test-RunPrerequisites $facts
    Add-Case 'run-readiness' $(if ($gate.ready) { 'PASS' } else { 'BLOCKED' }) 'Every disposable VM run prerequisite passes before any fixture or policy mutation.' ($gate.blockers -join ' | ')
    return [pscustomobject]@{ ready = $gate.ready; blockers = $gate.blockers; tempRoot = $tempRoot; vm = $vm; volume = $volume; admin = $admin; ping = $ping; output = $output; loadedDriver = $loadedDriver; facts = $facts }
}

function Get-SafeCmdPath([string]$Path) { return $Path -notmatch '[%\^!&|<>"()]' }

function Invoke-RunSuite([pscustomobject]$Preflight) {
    $tempRoot = $Preflight.tempRoot
    $runId = [Guid]::NewGuid().ToString('N')
    $fixtureParent = Join-Path $tempRoot 'DeleteGuard.VmAcceptance'
    $script:RunRoot = Join-Path $fixtureParent $runId
    $script:GuardRoot = Join-Path $script:RunRoot 'protected'
    if (-not (Test-CanonicalFixtureRoot $script:RunRoot $tempRoot $runId) -or -not (Test-NoReparsePoints $fixtureParent)) {
        Add-Case 'fixture-create' 'BLOCKED' 'Fresh GUID path is a direct child of the fixed temp parent with no reparse points.' "path=$script:RunRoot" $script:RunRoot
        return
    }
    if (Test-Path -LiteralPath $script:RunRoot) {
        Add-Case 'fixture-create' 'BLOCKED' 'The generated GUID fixture root must not already exist.' 'Existing directory retained without mutation or cleanup.' $script:RunRoot
        return
    }
    try {
        [void](New-Item -ItemType Directory -Path $script:RunRoot -ErrorAction Stop)
        Register-OwnedPath $script:RunRoot
        New-TestDirectory $script:GuardRoot
        $siblingRoot = Join-Path $script:RunRoot 'protected-sibling'
        New-TestDirectory $siblingRoot
        Assert-Case 'fixture-create' 'Fresh isolated root and prefix sibling are created under %TEMP%\DeleteGuard.VmAcceptance\<guid>.' "runRoot=$script:RunRoot; guardRoot=$script:GuardRoot; prefixSibling=$siblingRoot" $true $script:RunRoot

        $plainFile = Join-Path $siblingRoot 'unprotected-delete.txt'
        New-TestFile $plainFile
        [IO.File]::Delete($plainFile)
        Assert-Case 'unprotected-delete' 'An ordinary unprotected file can be deleted.' "exists=$(Test-Path -LiteralPath $plainFile)" (-not (Test-Path -LiteralPath $plainFile)) $plainFile

        if (-not (Invoke-ProtectFixture)) {
            foreach ($id in @('prefix-sibling-delete','deny-dotnet-file-delete','deny-dotnet-directory-delete','deny-powershell-remove-item','deny-cmd-del','deny-cmd-rmdir','deny-python-file-delete','deny-win32-deletefile','deny-win32-removedirectory','deny-file-delete-on-close','kernel-only-win32-delete','broker-approved-file-delete','post-approved-file-ordinary-delete-denied','broker-approved-recursive-delete','post-approved-tree-ordinary-delete-denied')) {
                Add-Case $id 'NOT_RUN' 'Broker protect must report active kernel enforcement before mutation probes proceed.' 'Skipped because fixture registration or active enforcement failed.' $script:GuardRoot
            }
            return
        }

        $boundaryFile = Join-Path $siblingRoot 'boundary-prefix.txt'
        New-TestFile $boundaryFile
        [IO.File]::Delete($boundaryFile)
        Assert-Case 'prefix-sibling-delete' 'A sibling whose name shares the protected-root prefix remains outside the policy boundary and can be deleted.' "sibling=$siblingRoot; exists=$(Test-Path -LiteralPath $boundaryFile)" (-not (Test-Path -LiteralPath $boundaryFile)) $boundaryFile

        $probes = Join-Path $script:GuardRoot 'probes'
        New-TestDirectory $probes
        $dotnetFile = Join-Path $probes 'dotnet.txt'; New-TestFile $dotnetFile
        Test-AccessDeniedResult 'deny-dotnet-file-delete' $dotnetFile { param($p) [IO.File]::Delete($p) } 'System.IO.File.Delete throws an access-denied error (Win32 5) and the file remains.'
        $dotnetTree = Join-Path $probes 'dotnet-tree'; New-TestDirectory $dotnetTree 1
        Test-AccessDeniedDirectoryResult 'deny-dotnet-directory-delete' $dotnetTree { param($p) [IO.Directory]::Delete($p, $true) } 'System.IO.Directory.Delete(recursive) is denied and every original path/content hash remains unchanged.'
        $psFile = Join-Path $probes 'powershell.txt'; New-TestFile $psFile
        Test-AccessDeniedResult 'deny-powershell-remove-item' $psFile { param($p) Remove-Item -LiteralPath $p -Force -ErrorAction Stop } 'PowerShell Remove-Item reports access denied (Win32 5) and the file remains.'

        $cmdFile = Join-Path $probes 'cmd-del.txt'; New-TestFile $cmdFile
        Test-AccessDeniedResult 'deny-cmd-del' $cmdFile { param($p) Invoke-CmdDelete $p $false } 'cmd del emits an explicit access-denied message and the file remains.'
        $cmdTree = Join-Path $probes 'cmd-tree'; New-TestDirectory $cmdTree 1
        Test-AccessDeniedDirectoryResult 'deny-cmd-rmdir' $cmdTree { param($p) Invoke-CmdDelete $p $true } 'cmd rmdir /s emits an explicit access-denied message and every original path/content hash remains unchanged.'

        $pythonCommand = Get-Command python, python3 -ErrorAction SilentlyContinue | Select-Object -First 1
        $pythonFile = Join-Path $probes 'python.txt'; New-TestFile $pythonFile
        if ($null -eq $pythonCommand) {
            Add-Case 'deny-python-file-delete' 'NOT_RUN' 'Python deletion reports access denied (WinError 5) and file remains.' 'Python 3 executable not found.' $pythonFile
        }
        else {
            $pythonScript = Join-Path $script:RunRoot 'python-delete-probe.py'
            if (Test-Path -LiteralPath $pythonScript) { throw "Python probe script path already exists: $pythonScript" }
            @'
import json, os, sys
try:
    os.remove(sys.argv[1])
    result = {"deleted": True}
except OSError as e:
    result = {"deleted": False, "errno": e.errno, "winerror": getattr(e, "winerror", None)}
print(json.dumps(result))
sys.exit(0 if result["deleted"] else 1)
'@ | Set-Content -LiteralPath $pythonScript -Encoding utf8
            Register-OwnedPath $pythonScript
            Test-AccessDeniedResult 'deny-python-file-delete' $pythonFile { param($p) Invoke-PythonDelete $p $pythonCommand.Source $pythonScript } 'Python os.remove reports WinError 5 and the file remains.'
        }

        $nativeFile = Join-Path $probes 'win32-deletefile.txt'; New-TestFile $nativeFile
        Test-AccessDeniedResult 'deny-win32-deletefile' $nativeFile {
            param($p)
            $nativeCode = 0
            $ok = [DeleteGuard.VmAcceptance.Native]::DeleteFile($p, [ref]$nativeCode)
            return @{ denied = (-not $ok -and $nativeCode -eq 5); nativeError = $nativeCode; detail = "DeleteFileW=$ok; error=$nativeCode" }
        } 'DeleteFileW returns FALSE with GetLastError=5 and file remains.'
        $nativeDirectory = Join-Path $probes 'win32-removedirectory'; New-TestDirectory $nativeDirectory
        Test-AccessDeniedResult 'deny-win32-removedirectory' $nativeDirectory {
            param($p)
            $nativeCode = 0
            $ok = [DeleteGuard.VmAcceptance.Native]::RemoveDirectory($p, [ref]$nativeCode)
            return @{ denied = (-not $ok -and $nativeCode -eq 5); nativeError = $nativeCode; detail = "RemoveDirectoryW=$ok; error=$nativeCode" }
        } 'RemoveDirectoryW returns FALSE with GetLastError=5 and directory remains.'
        $onCloseFile = Join-Path $probes 'delete-on-close.txt'; New-TestFile $onCloseFile
        Test-AccessDeniedResult 'deny-file-delete-on-close' $onCloseFile {
            param($p)
            $nativeCode = 0
            $opened = [DeleteGuard.VmAcceptance.Native]::OpenDeleteOnClose($p, [ref]$nativeCode)
            return @{ denied = (-not $opened -and $nativeCode -eq 5); nativeError = $nativeCode; detail = "FILE_DELETE_ON_CLOSE open=$opened; error=$nativeCode" }
        } 'CreateFileW with FILE_DELETE_ON_CLOSE returns INVALID_HANDLE_VALUE and GetLastError=5; file remains.'

        $kernelFile = Join-Path $probes 'kernel-only.txt'; New-TestFile $kernelFile
        Invoke-KernelOnlyProbe $kernelFile

        $approvedFile = Join-Path $script:GuardRoot 'approved-file.txt'; New-TestFile $approvedFile
        Invoke-BrokerDelete 'broker-approved-file-delete' $approvedFile $false $kernelFile
        $afterFile = Join-Path $script:GuardRoot 'after-approved-file.txt'; New-TestFile $afterFile
        Test-AccessDeniedResult 'post-approved-file-ordinary-delete-denied' $afterFile { param($p) [IO.File]::Delete($p) } 'After approved delete, the restored guard denies a subsequent ordinary delete with Win32 5.'

        $approvedTree = Join-Path $script:GuardRoot 'approved-tree'; New-TestDirectory $approvedTree 2
        Invoke-BrokerDelete 'broker-approved-recursive-delete' $approvedTree $true $afterFile
        $afterTree = Join-Path $script:GuardRoot 'after-approved-tree.txt'; New-TestFile $afterTree
        Test-AccessDeniedResult 'post-approved-tree-ordinary-delete-denied' $afterTree { param($p) [IO.File]::Delete($p) } 'After approved recursive delete, the restored guard denies a subsequent ordinary delete with Win32 5.'
    }
    catch {
        Add-Case 'automated-suite-unhandled-error' 'FAIL' 'All independent core acceptance cases execute or are recorded.' $_.Exception.ToString() $script:RunRoot
    }
    finally { Invoke-RunCleanup $tempRoot $runId }
}

function Invoke-SelfTest {
    $assertions = [System.Collections.Generic.List[string]]::new()
    $runId = [Guid]::NewGuid().ToString('N')
    $temp = [IO.Path]::GetTempPath()
    $valid = Join-Path (Join-Path $temp 'DeleteGuard.VmAcceptance') $runId
    if (-not (Test-CanonicalFixtureRoot $valid $temp $runId)) { throw 'SelfTest: a valid GUID fixture path was rejected.' }
    $assertions.Add('canonical fixture path accepted')
    if (Test-CanonicalFixtureRoot (Join-Path $valid '..\escape') $temp $runId) { throw 'SelfTest: traversal path was accepted.' }
    $assertions.Add('traversal path rejected')
    if (Test-UnderPath ($valid + '-sibling') $valid) { throw 'SelfTest: prefix sibling was accepted as a descendant.' }
    $assertions.Add('prefix sibling rejected')
    if ((Get-OverallStatus @([pscustomobject]@{ status = 'PASS' }, [pscustomobject]@{ status = 'FAIL' })) -ne 'FAIL') { throw 'SelfTest: FAIL aggregation mismatch.' }
    if ((Get-OverallStatus @([pscustomobject]@{ status = 'PASS' }, [pscustomobject]@{ status = 'BLOCKED' })) -ne 'BLOCKED') { throw 'SelfTest: BLOCKED aggregation mismatch.' }
    if ((Get-OverallStatus @([pscustomobject]@{ status = 'PASS' }, [pscustomobject]@{ status = 'NOT_RUN' })) -ne 'NOT_RUN') { throw 'SelfTest: NOT_RUN aggregation mismatch.' }
    $assertions.Add('status aggregation precedence verified')
    $baseFacts = [pscustomobject]@{
        isWindows = $true; powershell7 = $true; disposableVm = $true; virtualMachine = $true
        elevated = $true; outputWritable = $true; coreLoaded = $true; ntfs = $true
        driverPackagePresent = $true; driverActive = $true; loadedDriverMatches = $true
        emptyPolicyStore = $true; safeFixturePath = $true
    }
    if (-not (Test-RunPrerequisites $baseFacts).ready) { throw 'SelfTest: valid run facts were rejected.' }
    $withoutVm = $baseFacts.PSObject.Copy(); $withoutVm.virtualMachine = $false
    if ((Test-RunPrerequisites $withoutVm).ready) { throw 'SelfTest: missing VM did not block Run.' }
    $withoutOutput = $baseFacts.PSObject.Copy(); $withoutOutput.outputWritable = $false
    if ((Test-RunPrerequisites $withoutOutput).ready) { throw 'SelfTest: missing output directory did not block Run.' }
    $withoutAssertion = $baseFacts.PSObject.Copy(); $withoutAssertion.disposableVm = $false
    if ((Test-RunPrerequisites $withoutAssertion).ready) { throw 'SelfTest: missing disposable-VM assertion did not block Run.' }
    $assertions.Add('VM, writable output, and disposable assertion are hard Run gates')
    if (-not (Test-AccessDeniedEvidence 5 $true) -or (Test-AccessDeniedEvidence 13 $true)) { throw 'SelfTest: only native error 5 may establish access denied.' }
    $assertions.Add('access-denied classification rejects non-5 native errors')
    $sample = [ordered]@{ schemaVersion = 1; overallStatus = 'NOT_RUN'; cases = @([ordered]@{ id = 'sample'; status = 'NOT_RUN'; path = $valid; exitCode = $null; nativeError = $null }) }
    $roundTrip = ConvertFrom-Json -InputObject (ConvertTo-Json -InputObject $sample -Depth 5)
    if ($roundTrip.cases[0].path -ne $valid -or $roundTrip.overallStatus -ne 'NOT_RUN') { throw 'SelfTest: report JSON round-trip mismatch.' }
    $assertions.Add('report JSON round-trip verified')
    [pscustomobject]@{ mode = 'SelfTest'; status = 'PASS'; filesystemMutations = $false; policyMutations = $false; assertions = @($assertions); observedUtc = Get-UtcNow } | ConvertTo-Json -Depth 4
}

if ($Mode -eq 'SelfTest') {
    try { Invoke-SelfTest; exit 0 }
    catch { [Console]::Error.WriteLine($_.Exception.Message); exit 1 }
}

if (-not $IsWindows) {
    Add-Case 'host-platform' 'BLOCKED' 'Windows 10/11 is required.' "platform=$([Environment]::OSVersion.Platform)"
}
if ($Mode -eq 'Run' -and -not $DisposableVm) {
    Add-Case 'disposable-vm-assertion' 'BLOCKED' 'Run mode requires explicit -DisposableVm.' 'Switch absent.'
}
if ($Mode -eq 'Run' -and [string]::IsNullOrWhiteSpace($OutputDirectory)) {
    Add-Case 'evidence-output' 'BLOCKED' 'Run mode requires caller-supplied OutputDirectory.' 'OutputDirectory absent.'
}

$preflight = Invoke-Preflight ($Mode -eq 'Run')
if ($Mode -eq 'Run' -and -not $preflight.ready) {
    foreach ($blocker in $preflight.blockers) { Add-Case 'run-precondition' 'BLOCKED' 'All run gates must pass before fixture or policy mutation.' $blocker }
}
elseif ($Mode -eq 'Run') {
    Invoke-RunSuite $preflight
}

$automatedCases = @($script:Cases.ToArray() | Where-Object { $_.id -ne 'deny-python-file-delete' -or $_.status -ne 'NOT_RUN' })
$automatedStatus = Get-OverallStatus $automatedCases
$manualStatus = 'NOT_RUN'
$combinedOverall = if ($automatedStatus -in @('FAIL', 'BLOCKED', 'NOT_RUN')) { $automatedStatus } else { 'PARTIAL' }
$driverFiles = @()
if (-not [string]::IsNullOrWhiteSpace($DriverPackageDirectory)) {
    $driverFiles = @()
    foreach ($name in @('DeleteGuardFilter.sys', 'DeleteGuardFilter.inf', 'deleteguardfilter.cat')) { $driverFiles += Join-Path $DriverPackageDirectory $name }
}
elseif ($script:PackageRoot) {
    $driverDirectory = Join-Path (Split-Path -Parent $script:PackageRoot) 'driver-x64'
    foreach ($name in @('DeleteGuardFilter.sys', 'DeleteGuardFilter.inf', 'deleteguardfilter.cat')) { $driverFiles += Join-Path $driverDirectory $name }
}
$packageFiles = if ($script:PackageRoot) { Get-PackageFiles $script:PackageRoot } else { @() }
$report = [ordered]@{
    schemaVersion = 1
    mode = $Mode
    overallStatus = $combinedOverall
    automatedStatus = $automatedStatus
    manualStatus = $manualStatus
    observedUtc = Get-UtcNow
    environment = [ordered]@{
        computerName = $env:COMPUTERNAME
        osVersion = [Environment]::OSVersion.VersionString
        powershellVersion = $PSVersionTable.PSVersion.ToString()
        elevated = Get-AdminState
        vm = Get-VmState | Select-Object recognized, manufacturer, model, error
        fixtureVolume = if ($preflight) { $preflight.volume } else { $null }
        loadedDriver = if ($preflight) { $preflight.loadedDriver } else { $null }
    }
    packageDirectory = $script:PackageRoot
    packageHashes = Get-ArtifactHashes $packageFiles
    driverPackageHashes = Get-ArtifactHashes $driverFiles
    blockers = @($preflight.blockers)
    cases = $script:Cases.ToArray()
    manualCases = @(
        [ordered]@{ id = 'explorer-agent-uac-ordinary-user'; status = 'NOT_RUN'; reason = 'GUI, ordinary-user, and UAC acceptance is a manual VM gate.' },
        [ordered]@{ id = 'grant-pid-path-expiry-revoke'; status = 'NOT_RUN'; reason = 'Cross-process PID/path/expiry grant matrix is reserved for the manual release gate.' },
        [ordered]@{ id = 'disposition-ex'; status = 'NOT_RUN'; reason = 'FileDispositionInformationEx is outside this bounded harness.' },
        [ordered]@{ id = 'relay-driver-restart-stress-verifier'; status = 'NOT_RUN'; reason = 'Restart, burst, stress, and Driver Verifier are not automated.' }
    )
}

$reportJson = ConvertTo-Json -InputObject $report -Depth 14
if (-not [string]::IsNullOrWhiteSpace($OutputDirectory)) {
    try {
        $resolvedOutput = [IO.Path]::GetFullPath($OutputDirectory)
        [void](New-Item -ItemType Directory -Path $resolvedOutput -Force)
        $reportPath = Join-Path $resolvedOutput ("vm-acceptance-{0}-{1}.json" -f (Get-Date -Format 'yyyyMMddTHHmmss'), [Guid]::NewGuid().ToString('N').Substring(0, 8))
        Set-Content -LiteralPath $reportPath -Value $reportJson -Encoding utf8
        Write-Output "Evidence: $reportPath"
    }
    catch {
        [Console]::Error.WriteLine("Could not write requested evidence output: $($_.Exception.ToString())")
        exit 2
    }
}
Write-Output $reportJson
if ($combinedOverall -eq 'FAIL') { exit 1 }
if ($combinedOverall -eq 'BLOCKED') { exit 2 }
if ($Mode -eq 'Run' -and $combinedOverall -ne 'PARTIAL') { exit 3 }
exit 0
