$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'TestVm.Common.ps1')

Assert-DeleteGuardAdministrator
Assert-DeleteGuardDisposableVm

$checks = [System.Collections.Generic.List[object]]::new()
function Add-Check {
    param([string]$Name, [bool]$Passed, [string]$Detail)
    $checks.Add([pscustomobject]@{ name = $Name; passed = $Passed; detail = $Detail })
    Write-Host ("[{0}] {1} - {2}" -f ($(if ($Passed) { 'PASS' } else { 'FAIL' })), $Name, $Detail)
}

$os = Get-CimInstance Win32_OperatingSystem
Add-Check 'Windows 11/10 x64' ($env:PROCESSOR_ARCHITECTURE -eq 'AMD64' -and $os.Version -like '10.*') "$($os.Caption) $($os.Version)"

$repo = Get-DeleteGuardRepoRoot
Add-Check '.NET SDK' ([bool](Get-Command dotnet.exe -ErrorAction SilentlyContinue)) ((& dotnet.exe --version 2>$null) | Out-String).Trim()
Add-Check 'NuGet' ([bool](Get-Command nuget.exe -ErrorAction SilentlyContinue) -or (Test-Path (Join-Path $repo 'packages'))) 'NuGet command or restored package directory'

$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
$hasVs = Test-Path -LiteralPath $vswhere
Add-Check 'Visual Studio 2022 tooling' $hasVs $vswhere

$testSigningOutput = (& bcdedit.exe /enum '{current}' 2>&1 | Out-String)
$testSigningEnabled = $testSigningOutput -match '(?im)testsigning\s+Yes'
Add-Check 'TESTSIGNING enabled' $testSigningEnabled (($testSigningOutput -split "`r?`n" | Where-Object { $_ -match 'testsigning' }) -join '; ')

$secureBoot = $null
try { $secureBoot = Confirm-SecureBootUEFI } catch { }
Add-Check 'Secure Boot not blocking test mode' ($secureBoot -ne $true) "SecureBoot=$secureBoot"

$hvciPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity'
$hvciEnabled = $false
if (Test-Path $hvciPath) {
    $hvciEnabled = ((Get-ItemProperty -Path $hvciPath -Name Enabled -ErrorAction SilentlyContinue).Enabled -eq 1)
}
Add-Check 'HVCI state recorded' $true "MemoryIntegrity/HVCI=$hvciEnabled; DeleteGuard still requires a signed test image"

$passed = -not ($checks | Where-Object { -not $_.passed })
if (-not $passed) {
    throw 'One or more disposable-VM prerequisites are not ready. Resolve failed checks before installing the driver.'
}

Write-Host 'DeleteGuard disposable-VM prerequisites are ready.'
