param(
    [int]$Threshold = 20,
    [int]$WindowSeconds = 10,
    [int]$TotalFiles = 400
)

# Loaded-driver validation of the bulk-delete guard, inside the disposable VM only.
# The rate-limiter logic itself is unit-tested in user mode (tests\native); this proves the
# driver wiring: modes, counting, lockout, grants, namespace behaviour and the event.

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

$caseRoot = Join-Path $script:DeleteGuardTestRoot 'BulkGuardCase'
$caseSentinel = Join-Path $caseRoot '.deleteguard-bulkguard-test-case'
$guarded = Join-Path $caseRoot 'Guarded'
$eventFile = Join-Path $env:ProgramData 'DeleteGuard\denied-events.jsonl'
$protected = $false
$results = [System.Collections.Generic.List[object]]::new()

Assert-DeleteGuardSafeTestPath -Path $caseRoot
Assert-DeleteGuardSafeTestPath -Path $guarded

function Add-Result {
    param([string]$Name, [bool]$Passed, [string]$Detail)
    $results.Add([pscustomobject]@{ name = $Name; passed = $Passed; detail = $Detail })
    Write-Host ("[{0}] {1} - {2}" -f ($(if ($Passed) { 'PASS' } else { 'FAIL' })), $Name, $Detail)
}

function New-TestFiles {
    param([string]$Directory, [int]$Count, [string]$Prefix)
    New-Item -ItemType Directory -Path $Directory -Force | Out-Null
    1..$Count | ForEach-Object { Set-Content -LiteralPath (Join-Path $Directory ("{0}-{1:D4}.txt" -f $Prefix, $_)) -Value $_ }
}

try {
    if (Test-Path -LiteralPath $caseRoot) {
        if (-not (Test-Path -LiteralPath $caseSentinel)) {
            throw "Refusing to reuse $caseRoot because its bulk-guard-test sentinel is missing."
        }
        try { Invoke-DeleteGuardBroker -Command unprotect -Path $guarded } catch { }
        Remove-Item -LiteralPath $caseRoot -Recurse -Force
    }

    New-Item -ItemType Directory -Path $guarded -Force | Out-Null
    Set-Content -LiteralPath $caseSentinel -Value 'DeleteGuard disposable VM bulk-guard test case root'

    Invoke-DeleteGuardBroker -Command protect -Path $guarded -ExtraArguments @('--bulk-guard', "--threshold=$Threshold", "--window=$WindowSeconds")
    $protected = $true

    # 1. Everyday work is unaffected: edit, rename, create and delete a few files.
    $a = Join-Path $guarded 'a.txt'
    Set-Content -LiteralPath $a -Value 'one'
    Add-Content -LiteralPath $a -Value 'two'
    Rename-Item -LiteralPath $a -NewName 'b.txt'
    Move-Item -LiteralPath (Join-Path $guarded 'b.txt') -Destination (Join-Path $caseRoot 'moved-out.txt')
    Move-Item -LiteralPath (Join-Path $caseRoot 'moved-out.txt') -Destination (Join-Path $guarded 'back.txt')
    Remove-Item -LiteralPath (Join-Path $guarded 'back.txt')
    Add-Result 'normal edit, rename, move and single delete are allowed' `
        (-not (Test-Path -LiteralPath (Join-Path $guarded 'back.txt'))) `
        'renames and moves are not gated for a bulk-guard folder'

    # 2. A runaway recursive delete is stopped near the threshold.
    New-TestFiles -Directory (Join-Path $guarded 'wipe') -Count $TotalFiles -Prefix 'w'
    $start = [DateTimeOffset]::UtcNow
    Remove-Item -LiteralPath (Join-Path $guarded 'wipe') -Recurse -Force -ErrorAction SilentlyContinue
    $remaining = @(Get-ChildItem -LiteralPath (Join-Path $guarded 'wipe') -File -ErrorAction SilentlyContinue).Count
    $deleted = $TotalFiles - $remaining
    Add-Result 'runaway recursive delete is blocked after the threshold' `
        ($remaining -gt 0 -and $deleted -le ($Threshold + 5)) `
        "deleted $deleted of $TotalFiles (threshold $Threshold); $remaining survived"

    # 3. Retrying inside the lock window cannot sneak more deletions through.
    $retryDeleted = 0
    1..30 | ForEach-Object {
        Get-ChildItem -LiteralPath (Join-Path $guarded 'wipe') -File -ErrorAction SilentlyContinue | Select-Object -First 5 | ForEach-Object {
            try { Remove-Item -LiteralPath $_.FullName -ErrorAction Stop; $retryDeleted++ } catch { }
        }
        Start-Sleep -Milliseconds 300
    }
    Add-Result 'persistent retries during the lock delete nothing' ($retryDeleted -eq 0) "retries that succeeded: $retryDeleted"

    # 4. A bulk event reached the Relay, names the folder, and is NOT approvable.
    Start-Sleep -Seconds 2
    $events = @(Get-Content -LiteralPath $eventFile -ErrorAction SilentlyContinue | Select-Object -Last 200 |
        ForEach-Object { $_ | ConvertFrom-Json } | Where-Object { $_.operation -eq 8 })
    $bulkEvent = $events | Select-Object -Last 1
    Add-Result 'bulk event recorded for the protected folder' `
        ($null -ne $bulkEvent -and ($bulkEvent.targetPath -ieq $guarded)) `
        $(if ($bulkEvent) { "targetPath=$($bulkEvent.targetPath)" } else { 'no operation-8 event found' })
    Add-Result 'bulk event is non-approvable' `
        ($null -ne $bulkEvent -and -not [bool]$bulkEvent.canApprove) `
        'approving it would delete the whole protected folder'

    # 5. After a quiet period the lock clears and normal deletes work again.
    Start-Sleep -Seconds ([Math]::Max(40, ($WindowSeconds * 3) + 10))
    $probe = Join-Path $guarded 'probe.txt'
    Set-Content -LiteralPath $probe -Value 'probe'
    Remove-Item -LiteralPath $probe -ErrorAction SilentlyContinue
    Add-Result 'lock clears after a quiet period' (-not (Test-Path -LiteralPath $probe)) 'a single delete works again'

    # 6. A deliberate large deletion through the Broker is not counted against the limit.
    New-TestFiles -Directory (Join-Path $guarded 'approved') -Count $TotalFiles -Prefix 'x'
    Invoke-DeleteGuardBroker -Command delete -Path (Join-Path $guarded 'approved')
    Add-Result 'Broker-approved bulk deletion succeeds' `
        (-not (Test-Path -LiteralPath (Join-Path $guarded 'approved'))) `
        "Broker deleted $TotalFiles files via its kernel grant"
}
finally {
    if ($protected -and (Test-Path -LiteralPath $guarded)) {
        try { Invoke-DeleteGuardBroker -Command unprotect -Path $guarded } catch { Write-Warning $_.Exception.Message }
    }

    if (Test-Path -LiteralPath $caseRoot) {
        Assert-DeleteGuardSafeTestPath -Path $caseRoot
        if (-not (Test-Path -LiteralPath $caseSentinel)) {
            throw "Refusing cleanup of $caseRoot because its bulk-guard-test sentinel is missing."
        }
        Remove-Item -LiteralPath $caseRoot -Recurse -Force
    }
}

if ($results | Where-Object { -not $_.passed }) {
    exit 1
}

Write-Host 'DeleteGuard bulk-delete guard validation passed.'
exit 0
