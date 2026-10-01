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

$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
if (-not (Test-Path $vswhere)) {
    throw 'vswhere.exe was not found. Install Visual Studio 2022 Build Tools with Desktop development with C++.'
}

$msbuild = & $vswhere -latest -products * -requires Microsoft.Component.MSBuild -find 'MSBuild\**\Bin\MSBuild.exe' | Select-Object -First 1
if (-not $msbuild) {
    throw 'MSBuild.exe was not found.'
}

& $msbuild $project /m /restore /p:Configuration=$Configuration /p:Platform=x64 /p:SignMode=Off /p:Inf2CatUseLocalTime=true
if ($LASTEXITCODE -ne 0) { throw "Driver build failed with exit code $LASTEXITCODE." }

Remove-Item $out -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Path $out -Force | Out-Null

$driverBin = Join-Path $root "drivers\DeleteGuard.Filter\bin\$Configuration"
Copy-Item (Join-Path $driverBin 'DeleteGuardFilter.sys') $out -Force
Copy-Item (Join-Path $root 'drivers\DeleteGuard.Filter\DeleteGuardFilter.inf') $out -Force
$cat = Join-Path $driverBin 'DeleteGuardFilter.cat'
if (Test-Path $cat) { Copy-Item $cat $out -Force }

Write-Host "DeleteGuard minifilter package: $out"
Write-Warning 'The CI artifact is unsigned. Load it only in a disposable driver-test VM using an appropriate test-signing workflow.'
