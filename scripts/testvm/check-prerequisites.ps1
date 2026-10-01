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
$dotnet = Get-Command dotnet.exe -ErrorAction SilentlyContinue
$dotnetDetail = if ($dotnet) { ((& $dotnet.Source --version 2>$null) | Out-String).Trim() } else { 'dotnet.exe not found' }
Add-Check '.NET SDK' ([bool]$dotnet) $dotnetDetail

$nuget = Get-Command nuget.exe -ErrorAction SilentlyContinue
$hasRestoredPackages = Test-Path (Join-Path $repo 'packages')
Add-Check 'NuGet/restored packages' ([bool]$nuget -or $hasRestoredPackages) "nuget=$([bool]$nuget); packages=$hasRestoredPackages"

$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
$hasVs = Test-Path -LiteralPath $vswhere
Add-Check 'Visual Studio 2022 tooling' $hasVs $vswhere

$testSigningOutput = (& bcdedit.exe /enum '{current}' 2>&1 | Out-String)
$testSigningLines = @($testSigningOutput -split "`r?`n" | Where-Object { $_ -match '(?i)testsigning' })
# BCDEdit's value text can be localized. Presence is informational here; the
# hard gate is the subsequent signed-driver load in install-test-stack.ps1.
Add-Check 'TESTSIGNING configuration visible' ($testSigningLines.Count -gt 0) (($testSigningLines -join '; ').Trim())

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

Write-Host 'DeleteGuard disposable-VM prerequisites are ready for the next stage.'
Write-Host 'The definitive TESTSIGNING check is whether the locally test-signed DeleteGuardFilter can be loaded successfully.'
