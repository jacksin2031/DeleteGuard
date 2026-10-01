param(
    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Release'
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$packages = Join-Path $root 'packages'
$project = Join-Path $root 'drivers\DeleteGuard.Filter\DeleteGuardFilter.vcxproj'
$out = Join-Path $root 'artifacts\driver-x64'

$nuget = Get-Command nuget.exe -ErrorAction SilentlyContinue
if (-not $nuget) {
    $nuget = Get-Command nuget -ErrorAction SilentlyContinue
}
if (-not $nuget) {
    throw 'nuget.exe is required to restore the pinned WDK packages.'
}

& $nuget.Source restore (Join-Path $root 'packages.config') -PackagesDirectory $packages -NonInteractive
if ($LASTEXITCODE -ne 0) { throw "NuGet restore failed with exit code $LASTEXITCODE." }

# The WDK NuGet package brings the driver build targets and tools, but hosted
# runners do not automatically add tools such as stampinf.exe/inf2cat.exe to PATH.
# Discover their actual package locations so this script remains independent of
# the internal NuGet package layout.
$requiredTools = @('stampinf.exe')
$optionalTools = @('inf2cat.exe', 'signtool.exe')
$toolDirectories = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

foreach ($toolName in ($requiredTools + $optionalTools)) {
    $matches = @(Get-ChildItem -Path $packages -Filter $toolName -File -Recurse -ErrorAction SilentlyContinue |
        Sort-Object { if ($_.FullName -match '[\\/]x64[\\/]') { 0 } else { 1 } }, FullName)

    if ($matches.Count -eq 0) {
        if ($requiredTools -contains $toolName) {
            throw "$toolName was not found in the restored WDK/SDK packages."
        }
        continue
    }

    $selected = $matches[0]
    [void]$toolDirectories.Add($selected.DirectoryName)
    Write-Host "WDK tool: $toolName -> $($selected.FullName)"
}

if ($toolDirectories.Count -gt 0) {
    $env:PATH = (($toolDirectories | Sort-Object) -join [IO.Path]::PathSeparator) + [IO.Path]::PathSeparator + $env:PATH
}

$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
if (-not (Test-Path $vswhere)) {
    throw 'vswhere.exe was not found. Install Visual Studio 2022 Build Tools with Desktop development with C++.'
}

# Use 64-bit MSBuild. The x64 WDK NuGet package contains the x64 InfVerif and
# ApiValidator host tools; 32-bit MSBuild selects the x86 validator path and the
# validation phase fails even after the driver itself compiles and links.
$msbuild = & $vswhere -latest -products * -requires Microsoft.Component.MSBuild -find 'MSBuild\**\Bin\amd64\MSBuild.exe' |
    Select-Object -First 1
if (-not $msbuild) {
    throw '64-bit MSBuild.exe was not found. Install a current Visual Studio 2022 Build Tools/Enterprise C++ workload.'
}
Write-Host "MSBuild x64: $msbuild"

& $msbuild $project /m /restore /p:Configuration=$Configuration /p:Platform=x64 /p:SignMode=Off /p:Inf2CatUseLocalTime=true
if ($LASTEXITCODE -ne 0) { throw "Driver build failed with exit code $LASTEXITCODE." }

Remove-Item $out -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Path $out -Force | Out-Null

$driverBin = Join-Path $root "drivers\DeleteGuard.Filter\bin\$Configuration"
$sys = Join-Path $driverBin 'DeleteGuardFilter.sys'
if (-not (Test-Path $sys)) {
    $sys = Get-ChildItem -Path (Join-Path $root 'drivers\DeleteGuard.Filter') -Filter DeleteGuardFilter.sys -File -Recurse |
        Select-Object -First 1 -ExpandProperty FullName
}
if (-not $sys -or -not (Test-Path $sys)) {
    throw 'Driver build completed but DeleteGuardFilter.sys could not be located.'
}

Copy-Item $sys $out -Force
Copy-Item (Join-Path $root 'drivers\DeleteGuard.Filter\DeleteGuardFilter.inf') $out -Force
$cat = Get-ChildItem -Path (Join-Path $root 'drivers\DeleteGuard.Filter') -Filter DeleteGuardFilter.cat -File -Recurse -ErrorAction SilentlyContinue |
    Select-Object -First 1 -ExpandProperty FullName
if ($cat) { Copy-Item $cat $out -Force }

Write-Host "DeleteGuard minifilter package: $out"
Write-Warning 'The CI artifact is unsigned. Load it only in a disposable driver-test VM using an appropriate test-signing workflow.'
