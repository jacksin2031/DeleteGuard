param(
    [switch]$IUnderstandThisIsADisposableVm,
    [switch]$EnableTestSigning,
    [switch]$RestartNow
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'TestVm.Common.ps1')

Assert-DeleteGuardAdministrator

if (-not $IUnderstandThisIsADisposableVm) {
    throw 'Refusing to prepare this computer. Re-run with -IUnderstandThisIsADisposableVm only inside a disposable Windows test VM.'
}

$marker = [ordered]@{
    acknowledged = $true
    machineName = $env:COMPUTERNAME
    createdUtc = [DateTimeOffset]::UtcNow.ToString('O')
    testRoot = $script:DeleteGuardTestRoot
}
$marker | ConvertTo-Json | Set-Content -LiteralPath $script:DeleteGuardTestVmMarker -Encoding UTF8
Write-Host "Disposable-VM marker created: $script:DeleteGuardTestVmMarker"

$secureBoot = $null
try {
    $secureBoot = Confirm-SecureBootUEFI
}
catch {
    Write-Host 'Secure Boot status could not be queried (legacy BIOS or unsupported environment).'
}

$hvciPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity'
$hvciEnabled = $false
if (Test-Path $hvciPath) {
    $hvciEnabled = ((Get-ItemProperty -Path $hvciPath -Name Enabled -ErrorAction SilentlyContinue).Enabled -eq 1)
}

Write-Host "Secure Boot: $secureBoot"
Write-Host "Memory Integrity / HVCI: $hvciEnabled"
Write-Host 'DeleteGuard test signing always signs the driver image and catalog with a self-created test certificate.'

if (Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue) {
    try {
        $bitLocker = Get-BitLockerVolume -MountPoint $env:SystemDrive
        Write-Host "BitLocker protection on $($env:SystemDrive): $($bitLocker.ProtectionStatus)"
    }
    catch {
        Write-Warning "BitLocker status could not be queried: $($_.Exception.Message)"
    }
}

if ($EnableTestSigning) {
    if ($secureBoot -eq $true) {
        throw 'Secure Boot is enabled. DeleteGuard will not change firmware settings. Disable Secure Boot manually in this disposable VM, then re-run this script.'
    }

    & bcdedit.exe /set testsigning on | Out-Host
    if ($LASTEXITCODE -ne 0) {
        throw "BCDEdit failed with exit code $LASTEXITCODE."
    }

    Write-Host 'TESTSIGNING has been enabled in BCD. A reboot is required before loading a test-signed kernel driver.'
    if ($RestartNow) {
        Restart-Computer -Force
    }
}
else {
    Write-Host 'TESTSIGNING was not changed. Use -EnableTestSigning in the disposable VM when you are ready.'
}
