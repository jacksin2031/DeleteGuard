param(
    [switch]$RestartNow
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'TestVm.Common.ps1')

Assert-DeleteGuardAdministrator
Assert-DeleteGuardDisposableVm

& verifier.exe /reset | Out-Host
if ($LASTEXITCODE -ne 0) { throw "verifier /reset failed with exit code $LASTEXITCODE." }

& verifier.exe /standard /driver DeleteGuardFilter.sys | Out-Host
if ($LASTEXITCODE -ne 0) { throw "verifier /standard failed with exit code $LASTEXITCODE." }

& verifier.exe /bootmode resetonbootfail | Out-Host
if ($LASTEXITCODE -ne 0) { throw "verifier /bootmode resetonbootfail failed with exit code $LASTEXITCODE." }

Write-Host 'Driver Verifier standard checks are configured for DeleteGuardFilter.sys.'
Write-Host 'On Windows 11, /standard includes File System Filter Verification; the target is limited to DeleteGuardFilter.sys only.'
& verifier.exe /querysettings | Out-Host

Write-Warning 'A reboot is required before the configured non-volatile verification settings take effect.'
if ($RestartNow) {
    Restart-Computer -Force
}
