$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'TestVm.Common.ps1')

Assert-DeleteGuardAdministrator
Assert-DeleteGuardDisposableVm

$failed = $false

if (Test-DeleteGuardFilterLoaded) {
    Write-Host '[PASS] DeleteGuardFilter is present in fltmc filters.'
}
else {
    Write-Error '[FAIL] DeleteGuardFilter is not loaded.'
    $failed = $true
}

$relay = Get-Service -Name 'DeleteGuardEventRelay' -ErrorAction SilentlyContinue
if ($relay -and $relay.Status -eq 'Running') {
    Write-Host '[PASS] DeleteGuardEventRelay is running.'
}
else {
    Write-Error '[FAIL] DeleteGuardEventRelay is not running.'
    $failed = $true
}

$verifier = (& verifier.exe /querysettings 2>&1 | Out-String)
if ($verifier -match '(?i)DeleteGuardFilter\.sys') {
    Write-Host '[PASS] Driver Verifier configuration references DeleteGuardFilter.sys.'
}
else {
    Write-Warning 'Driver Verifier querysettings does not show DeleteGuardFilter.sys. Re-run enable-verifier.ps1 and reboot before stress validation.'
}

$doctor = Join-Path (Get-DeleteGuardInstalledDirectory) 'deleteguard.exe'
if (Test-Path -LiteralPath $doctor) {
    & $doctor doctor | Out-Host
}
else {
    Write-Warning "deleteguard.exe was not found at $doctor"
}

if ($failed) { exit 1 }
exit 0
