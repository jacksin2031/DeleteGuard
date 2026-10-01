param(
    [switch]$DisableTestSigning,
    [switch]$RestartNow
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'TestVm.Common.ps1')

Assert-DeleteGuardAdministrator
Assert-DeleteGuardDisposableVm

$repo = Get-DeleteGuardRepoRoot
$marker = Get-Content -LiteralPath $script:DeleteGuardTestVmMarker -Raw | ConvertFrom-Json

try { & (Join-Path $repo 'scripts\disable-agent.ps1') | Out-Host } catch { Write-Warning $_.Exception.Message }
try { & (Join-Path $repo 'scripts\uninstall-approval.ps1') | Out-Host } catch { Write-Warning $_.Exception.Message }

if (Test-Path -LiteralPath $script:DeleteGuardTestRoot) {
    Assert-DeleteGuardSafeTestPath -Path $script:DeleteGuardTestRoot
    $sentinel = Join-Path $script:DeleteGuardTestRoot '.deleteguard-runtime-test-root'
    if (-not (Test-Path -LiteralPath $sentinel)) {
        throw "Refusing cleanup of $script:DeleteGuardTestRoot because the runtime-test sentinel is missing."
    }

    try { Invoke-DeleteGuardBroker -Command unprotect -Path $script:DeleteGuardTestRoot } catch { Write-Warning $_.Exception.Message }
    Remove-Item -LiteralPath $script:DeleteGuardTestRoot -Recurse -Force
}

& verifier.exe /reset | Out-Host
if ($LASTEXITCODE -ne 0) { Write-Warning "verifier /reset returned exit code $LASTEXITCODE." }

if (Test-DeleteGuardFilterLoaded) {
    & fltmc.exe unload DeleteGuardFilter | Out-Host
    if ($LASTEXITCODE -ne 0) { Write-Warning "fltmc unload returned exit code $LASTEXITCODE." }
}

$service = Get-Service -Name 'DeleteGuardFilter' -ErrorAction SilentlyContinue
if ($service) {
    & sc.exe delete DeleteGuardFilter | Out-Host
    if ($LASTEXITCODE -ne 0) { Write-Warning "sc delete DeleteGuardFilter returned exit code $LASTEXITCODE." }
}

$thumbprint = $null
if ($marker.PSObject.Properties.Name -contains 'testCertificateThumbprint') {
    $thumbprint = [string]$marker.testCertificateThumbprint
}

if ($thumbprint) {
    foreach ($store in @('My', 'Root', 'TrustedPublisher')) {
        $certificatePath = "Cert:\LocalMachine\$store\$thumbprint"
        if (Test-Path -LiteralPath $certificatePath) {
            Remove-Item -LiteralPath $certificatePath -Force
        }
    }
    Write-Host "Removed marker-bound DeleteGuard test certificate: $thumbprint"
}
else {
    Write-Warning 'The disposable-VM marker does not contain a test certificate thumbprint; no certificate was removed by subject/name guessing.'
}

if ($DisableTestSigning) {
    & bcdedit.exe /set testsigning off | Out-Host
    if ($LASTEXITCODE -ne 0) { throw "BCDEdit failed with exit code $LASTEXITCODE." }
    Write-Host 'TESTSIGNING disabled. A reboot is required.'
}

Remove-Item -LiteralPath $script:DeleteGuardTestVmMarker -Force
Write-Host 'DeleteGuard test-VM marker removed. This computer can no longer run the guarded test scripts without re-acknowledgment.'

if ($RestartNow) {
    Restart-Computer -Force
}
