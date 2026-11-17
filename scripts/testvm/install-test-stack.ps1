param(
    [switch]$SkipUserModeBuild,
    [switch]$EnableAgentForCurrentUser
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'TestVm.Common.ps1')

Assert-DeleteGuardAdministrator
Assert-DeleteGuardDisposableVm

$repo = Get-DeleteGuardRepoRoot
$package = Join-Path $repo 'artifacts\driver-x64'
$sys = Join-Path $package 'DeleteGuardFilter.sys'
$inf = Join-Path $package 'DeleteGuardFilter.inf'
$cat = Join-Path $package 'DeleteGuardFilter.cat'

foreach ($path in @($sys, $inf, $cat)) {
    if (-not (Test-Path -LiteralPath $path)) {
        throw "Missing test-signed driver package file: $path. Run sign-test-driver.ps1 first."
    }
}

foreach ($path in @($sys, $cat)) {
    $signature = Get-AuthenticodeSignature -FilePath $path
    if ($signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid) {
        throw "Signature is not valid for $path : $($signature.Status)"
    }
}

Write-Host 'Installing the minifilter INF into this disposable VM...'
$process = Start-Process -FilePath 'rundll32.exe' `
    -ArgumentList @('setupapi.dll,InstallHinfSection', 'DefaultInstall', '132', $inf) `
    -Wait -PassThru -NoNewWindow
if ($process.ExitCode -ne 0) {
    throw "INF installation failed with exit code $($process.ExitCode)."
}

$service = Get-Service -Name 'DeleteGuardFilter' -ErrorAction SilentlyContinue
if (-not $service) {
    throw 'DeleteGuardFilter service was not registered by the INF installation.'
}

if (-not (Test-DeleteGuardFilterLoaded)) {
    & fltmc.exe load DeleteGuardFilter | Out-Host
    if ($LASTEXITCODE -ne 0) {
        throw "fltmc load DeleteGuardFilter failed with exit code $LASTEXITCODE. Confirm TESTSIGNING is enabled and the VM has been rebooted."
    }
}
Wait-DeleteGuardFilterLoaded
Write-Host 'DeleteGuardFilter is loaded.'

if (-not $SkipUserModeBuild) {
    & (Join-Path $repo 'scripts\build.ps1') -Configuration Release -Runtime win-x64
    if ($LASTEXITCODE -ne 0) { throw 'DeleteGuard user-mode build failed.' }
}

& (Join-Path $repo 'scripts\install.ps1') -Runtime win-x64 -SkipPath
if ($LASTEXITCODE -ne 0) { throw 'DeleteGuard user-mode installation failed.' }

& (Join-Path $repo 'scripts\install-approval.ps1')
if ($LASTEXITCODE -ne 0) { throw 'DeleteGuard Event Relay installation failed.' }

if ($EnableAgentForCurrentUser) {
    & (Join-Path $repo 'scripts\enable-agent.ps1')
    if ($LASTEXITCODE -ne 0) { throw 'DeleteGuard Agent enablement failed.' }
}

Write-Host 'DeleteGuard disposable-VM test stack is installed.'
Write-Host 'Run enable-verifier.ps1 before stress testing, then reboot the VM.'
