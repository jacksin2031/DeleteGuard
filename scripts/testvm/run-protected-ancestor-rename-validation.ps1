$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'TestVm.Common.ps1')

Assert-DeleteGuardAdministrator
Assert-DeleteGuardDisposableVm
Assert-DeleteGuardSafeTestPath -Path $script:DeleteGuardTestRoot

if (-not (Test-DeleteGuardFilterLoaded)) {
    throw 'DeleteGuardFilter is not loaded. Run install-test-stack.ps1 first.'
}

$relay = Get-Service -Name 'DeleteGuardEventRelay' -ErrorAction SilentlyContinue
if (-not $relay -or $relay.Status -ne 'Running') {
    throw 'DeleteGuardEventRelay service is not running.'
}

$root = $script:DeleteGuardTestRoot
$rootSentinel = Join-Path $root '.deleteguard-runtime-test-root'
$caseRoot = Join-Path $root 'ancestor-rename-case'
$caseSentinel = Join-Path $caseRoot '.deleteguard-ancestor-test'
$container = Join-Path $caseRoot 'container'
$protectedRoot = Join-Path $container 'protected'
$renamedContainer = Join-Path $caseRoot 'container-renamed'
$reportDirectory = Join-Path $env:ProgramData 'DeleteGuard'
$reportPath = Join-Path $reportDirectory ("ancestor-rename-validation-{0}.json" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
$createdRoot = $false
$protected = $false
$results = [System.Collections.Generic.List[object]]::new()

function Add-AncestorResult {
    param([string]$Name, [bool]$Passed, [string]$Detail)
    $results.Add([pscustomobject]@{
        name = $Name
        passed = $Passed
        detail = $Detail
        utc = [DateTimeOffset]::UtcNow.ToString('O')
    })
    Write-Host ("[{0}] {1} - {2}" -f ($(if ($Passed) { 'PASS' } else { 'FAIL' })), $Name, $Detail)
}

function Find-AncestorDeniedEvent {
    param([DateTimeOffset]$NotBefore)

    foreach ($file in @(
        (Join-Path $reportDirectory 'denied-events.1.jsonl'),
        (Join-Path $reportDirectory 'denied-events.jsonl'))) {
        if (-not (Test-Path -LiteralPath $file)) { continue }
        foreach ($line in (Get-Content -LiteralPath $file -Tail 300 -ErrorAction SilentlyContinue)) {
            if ([string]::IsNullOrWhiteSpace($line)) { continue }
            try { $record = $line | ConvertFrom-Json } catch { continue }
            if ([int]$record.operation -ne 5) { continue }
            if (-not [string]::Equals([string]$record.targetPath, $container, [StringComparison]::OrdinalIgnoreCase)) { continue }
            try { $observed = [DateTimeOffset]::Parse([string]$record.observedUtc) } catch { continue }
            if ($observed -ge $NotBefore) { return $record }
        }
    }

    return $null
}

try {
    if (-not (Test-Path -LiteralPath $root)) {
        New-Item -ItemType Directory -Path $root -Force | Out-Null
        Set-Content -LiteralPath $rootSentinel -Value 'DeleteGuard disposable VM runtime test root' -Encoding UTF8
        $createdRoot = $true
    }
    elseif (-not (Test-Path -LiteralPath $rootSentinel)) {
        throw "Refusing to use existing $root because the DeleteGuard runtime-test sentinel is absent."
    }

    Assert-DeleteGuardSafeTestPath -Path $caseRoot

    if (Test-Path -LiteralPath $caseRoot) {
        if (-not (Test-Path -LiteralPath $caseSentinel)) {
            throw "Refusing to reuse existing $caseRoot because its test sentinel is absent."
        }
        if (Test-Path -LiteralPath $protectedRoot) {
            try { Invoke-DeleteGuardBroker -Command unprotect -Path $protectedRoot } catch { }
        }
        Remove-Item -LiteralPath $caseRoot -Recurse -Force
    }

    New-Item -ItemType Directory -Path $protectedRoot -Force | Out-Null
    Set-Content -LiteralPath $caseSentinel -Value 'DeleteGuard protected-ancestor rename test' -Encoding UTF8
    Set-Content -LiteralPath (Join-Path $protectedRoot 'sentinel.txt') -Value 'must remain under the protected path' -Encoding UTF8

    Invoke-DeleteGuardBroker -Command protect -Path $protectedRoot
    $protected = $true

    $attemptUtc = [DateTimeOffset]::UtcNow
    $renameError = $null
    try {
        Move-Item -LiteralPath $container -Destination $renamedContainer -ErrorAction Stop
    }
    catch {
        $renameError = $_.Exception.Message
    }

    $containerExists = Test-Path -LiteralPath $container
    Add-AncestorResult 'protected-root ancestor rename denied' $containerExists $(if ($renameError) { $renameError } else { 'ancestor remained in place' })
    Add-AncestorResult 'protected root remains at configured path' (Test-Path -LiteralPath $protectedRoot) $protectedRoot
    Add-AncestorResult 'ancestor rename destination not created' (-not (Test-Path -LiteralPath $renamedContainer)) $renamedContainer

    if (-not $containerExists -or -not (Test-Path -LiteralPath $protectedRoot) -or (Test-Path -LiteralPath $renamedContainer)) {
        throw 'Protected-root ancestor rename escaped the configured protection path.'
    }

    Start-Sleep -Seconds 2
    $event = Find-AncestorDeniedEvent -NotBefore $attemptUtc
    Add-AncestorResult 'kernel protected-ancestor event observed' ($null -ne $event) 'operation=RenameProtectedAncestor'
    if ($event) {
        Add-AncestorResult 'protected-ancestor event is non-approvable' (-not [bool]$event.canApprove) 'rename must never invoke the delete broker'
    }
}
catch {
    Add-AncestorResult 'protected-ancestor runtime harness' $false $_.Exception.ToString()
}
finally {
    try {
        if ($protected -and (Test-Path -LiteralPath $protectedRoot)) {
            Invoke-DeleteGuardBroker -Command unprotect -Path $protectedRoot
            $protected = $false
        }
    }
    catch {
        Add-AncestorResult 'cleanup unprotect' $false $_.Exception.Message
    }

    try {
        if (Test-Path -LiteralPath $caseRoot) {
            if (-not (Test-Path -LiteralPath $caseSentinel)) {
                throw 'Cleanup refused because the protected-ancestor test sentinel is missing.'
            }
            Remove-Item -LiteralPath $caseRoot -Recurse -Force
        }
        elseif (Test-Path -LiteralPath $renamedContainer) {
            throw 'Cleanup refused because the ancestor unexpectedly moved; preserve the VM for investigation.'
        }

        if ($createdRoot -and (Test-Path -LiteralPath $root)) {
            if (-not (Test-Path -LiteralPath $rootSentinel)) {
                throw 'Cleanup refused because the runtime-test root sentinel is missing.'
            }
            Remove-Item -LiteralPath $root -Recurse -Force
        }
    }
    catch {
        Add-AncestorResult 'cleanup test case' $false $_.Exception.Message
    }

    New-Item -ItemType Directory -Path $reportDirectory -Force | Out-Null
    [ordered]@{
        completedUtc = [DateTimeOffset]::UtcNow.ToString('O')
        machineName = $env:COMPUTERNAME
        protectedRoot = $protectedRoot
        ancestorPath = $container
        passed = -not ($results | Where-Object { -not $_.passed })
        results = $results
    } | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $reportPath -Encoding UTF8
    Write-Host "Protected-ancestor validation report: $reportPath"
}

if ($results | Where-Object { -not $_.passed }) {
    exit 1
}

Write-Host 'Protected-root ancestor rename validation passed.'
exit 0
