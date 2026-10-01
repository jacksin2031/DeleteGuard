param(
    [int]$RaceAttempts = 800
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'TestVm.Common.ps1')

Assert-DeleteGuardAdministrator
Assert-DeleteGuardDisposableVm
Assert-DeleteGuardSafeTestPath -Path $script:DeleteGuardTestRoot

if (-not (Test-DeleteGuardFilterLoaded)) {
    throw 'DeleteGuardFilter is not loaded. Run install-test-stack.ps1 first.'
}

$protectedRoot = Join-Path $script:DeleteGuardTestRoot 'Protected'
$escapeRoot = Join-Path $script:DeleteGuardTestRoot 'Escape'
$sentinelPath = Join-Path $protectedRoot 'race-sentinel.txt'
$escapeSentinelPath = Join-Path $escapeRoot 'race-sentinel.txt'
$ordinaryMoveSource = Join-Path $protectedRoot 'ordinary-move.txt'
$ordinaryMoveDestination = Join-Path $escapeRoot 'ordinary-move.txt'
$replaceSource = Join-Path $script:DeleteGuardTestRoot 'replacement-source.txt'
$replaceTarget = Join-Path $protectedRoot 'replacement-target.txt'
$approvedTree = Join-Path $protectedRoot 'approved-tree'
$protected = $false
$results = [System.Collections.Generic.List[object]]::new()

function Add-Result {
    param([string]$Name, [bool]$Passed, [string]$Detail)
    $results.Add([pscustomobject]@{ name = $Name; passed = $Passed; detail = $Detail })
    Write-Host ("[{0}] {1} - {2}" -f ($(if ($Passed) { 'PASS' } else { 'FAIL' })), $Name, $Detail)
}

try {
    if (Test-Path -LiteralPath $script:DeleteGuardTestRoot) {
        $rootItem = Get-Item -LiteralPath $script:DeleteGuardTestRoot -Force
        if (($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'Refusing namespace validation because the test root is a reparse point.'
        }
    }
    else {
        New-Item -ItemType Directory -Path $script:DeleteGuardTestRoot | Out-Null
    }

    New-Item -ItemType Directory -Path $protectedRoot -Force | Out-Null
    New-Item -ItemType Directory -Path $escapeRoot -Force | Out-Null
    Set-Content -LiteralPath $ordinaryMoveSource -Value 'ordinary protected source'
    Set-Content -LiteralPath $sentinelPath -Value 'must remain protected'
    Set-Content -LiteralPath $replaceSource -Value 'attacker replacement payload'
    Set-Content -LiteralPath $replaceTarget -Value 'protected original payload'
    New-Item -ItemType Directory -Path $approvedTree -Force | Out-Null
    1..1500 | ForEach-Object {
        Set-Content -LiteralPath (Join-Path $approvedTree ("file-{0:D4}.txt" -f $_)) -Value $_
    }

    Invoke-DeleteGuardBroker -Command protect -Path $protectedRoot
    $protected = $true

    $moveError = $null
    try {
        Move-Item -LiteralPath $ordinaryMoveSource -Destination $ordinaryMoveDestination -ErrorAction Stop
    }
    catch { $moveError = $_.Exception.Message }
    Add-Result 'protected move-out denied' `
        ((Test-Path -LiteralPath $ordinaryMoveSource) -and -not (Test-Path -LiteralPath $ordinaryMoveDestination)) `
        ($(if ($moveError) { $moveError } else { 'source/destination state checked' }))

    $moveRace = Start-Job -ScriptBlock {
        param($Source, $Destination, $Attempts)
        for ($i = 0; $i -lt $Attempts; $i++) {
            try { Move-Item -LiteralPath $Source -Destination $Destination -Force -ErrorAction Stop } catch { }
            if (-not (Test-Path -LiteralPath $Source)) { break }
            Start-Sleep -Milliseconds 2
        }
    } -ArgumentList $sentinelPath, $escapeSentinelPath, $RaceAttempts

    $replaceRace = Start-Job -ScriptBlock {
        param($Source, $Destination, $Attempts)
        Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class DeleteGuardMoveProbe {
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern bool MoveFileEx(string existingName, string newName, int flags);
}
'@
        for ($i = 0; $i -lt $Attempts; $i++) {
            [void][DeleteGuardMoveProbe]::MoveFileEx($Source, $Destination, 1)
            if (-not (Test-Path -LiteralPath $Source)) { break }
            Start-Sleep -Milliseconds 2
        }
    } -ArgumentList $replaceSource, $replaceTarget, $RaceAttempts

    try {
        Invoke-DeleteGuardBroker -Command delete -Path $approvedTree
    }
    finally {
        foreach ($job in @($moveRace, $replaceRace)) {
            Wait-Job -Job $job -Timeout 20 | Out-Null
            Stop-Job -Job $job -ErrorAction SilentlyContinue
            Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
        }
    }

    Add-Result 'approved delete completed' (-not (Test-Path -LiteralPath $approvedTree)) '1500-file Broker delete'
    Add-Result 'move-out blocked during ACL-relax window' `
        ((Test-Path -LiteralPath $sentinelPath) -and -not (Test-Path -LiteralPath $escapeSentinelPath)) `
        'competing process repeatedly attempted protected namespace escape'

    $replacementValue = if (Test-Path -LiteralPath $replaceTarget) {
        Get-Content -LiteralPath $replaceTarget -Raw
    } else { '' }
    Add-Result 'replace-into-protected blocked during ACL-relax window' `
        ((Test-Path -LiteralPath $replaceSource) -and
         (Test-Path -LiteralPath $replaceTarget) -and
         $replacementValue.Trim() -eq 'protected original payload') `
        'MoveFileEx(REPLACE_EXISTING) could not replace protected destination'
}
finally {
    if ($protected -and (Test-Path -LiteralPath $protectedRoot)) {
        try { Invoke-DeleteGuardBroker -Command unprotect -Path $protectedRoot } catch { Write-Warning $_.Exception.Message }
    }

    if (Test-Path -LiteralPath $script:DeleteGuardTestRoot) {
        Assert-DeleteGuardSafeTestPath -Path $script:DeleteGuardTestRoot
        Remove-Item -LiteralPath $script:DeleteGuardTestRoot -Recurse -Force
    }
}

if ($results | Where-Object { -not $_.passed }) {
    exit 1
}

Write-Host 'DeleteGuard namespace validation passed.'
exit 0
