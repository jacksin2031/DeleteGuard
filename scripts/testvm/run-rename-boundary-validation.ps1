param(
    [int]$Attempts = 600
)

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

$protectedRoot = Join-Path $script:DeleteGuardTestRoot 'RenameProtected'
$outsideRoot = Join-Path $script:DeleteGuardTestRoot 'RenameOutside'
$sentinel = Join-Path $script:DeleteGuardTestRoot '.deleteguard-rename-test-root'
$eventFile = Join-Path $env:ProgramData 'DeleteGuard\denied-events.jsonl'
$protected = $false

Assert-DeleteGuardSafeTestPath -Path $protectedRoot
Assert-DeleteGuardSafeTestPath -Path $outsideRoot

function Assert-True {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw $Message }
    Write-Host "[PASS] $Message"
}

try {
    if (Test-Path -LiteralPath $script:DeleteGuardTestRoot) {
        if (-not (Test-Path -LiteralPath $sentinel)) {
            throw "Refusing to reuse $script:DeleteGuardTestRoot because the rename-test sentinel is absent."
        }
        try { Invoke-DeleteGuardBroker -Command unprotect -Path $protectedRoot } catch { }
        Remove-Item -LiteralPath $script:DeleteGuardTestRoot -Recurse -Force
    }

    New-Item -ItemType Directory -Path $protectedRoot -Force | Out-Null
    New-Item -ItemType Directory -Path $outsideRoot -Force | Out-Null
    Set-Content -LiteralPath $sentinel -Value 'DeleteGuard disposable VM rename boundary test root' -Encoding UTF8

    $moveSource = Join-Path $protectedRoot 'move-out-source.txt'
    $moveDestination = Join-Path $outsideRoot 'move-out-destination.txt'
    $replaceSource = Join-Path $outsideRoot 'replace-source.txt'
    $replaceTarget = Join-Path $protectedRoot 'replace-target.txt'
    $approvedTree = Join-Path $protectedRoot 'approved-tree'

    Set-Content -LiteralPath $moveSource -Value 'protected move source' -Encoding UTF8
    Set-Content -LiteralPath $replaceSource -Value 'outside replacement payload' -Encoding UTF8
    Set-Content -LiteralPath $replaceTarget -Value 'protected original payload' -Encoding UTF8
    New-Item -ItemType Directory -Path $approvedTree -Force | Out-Null
    1..500 | ForEach-Object {
        Set-Content -LiteralPath (Join-Path $approvedTree ("file-{0:D4}.txt" -f $_)) -Value $_
    }

    Invoke-DeleteGuardBroker -Command protect -Path $protectedRoot
    $protected = $true

    $attackJob = Start-Job -ScriptBlock {
        param($MoveSource, $MoveDestination, $ReplaceSource, $ReplaceTarget, $Attempts)

        Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

public static class DeleteGuardRenameProbe
{
    const uint MOVEFILE_REPLACE_EXISTING = 0x00000001;

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern bool MoveFileExW(string existingFileName, string newFileName, uint flags);

    public static int TryReplace(string source, string destination)
    {
        if (MoveFileExW(source, destination, MOVEFILE_REPLACE_EXISTING)) return 0;
        return Marshal.GetLastWin32Error();
    }
}
'@

        for ($i = 0; $i -lt $Attempts; $i++) {
            try {
                if ([IO.File]::Exists($MoveSource) -and -not [IO.File]::Exists($MoveDestination)) {
                    [IO.File]::Move($MoveSource, $MoveDestination)
                }
            }
            catch { }

            try {
                if ([IO.File]::Exists($ReplaceSource)) {
                    [void][DeleteGuardRenameProbe]::TryReplace($ReplaceSource, $ReplaceTarget)
                }
            }
            catch { }

            Start-Sleep -Milliseconds 3
        }
    } -ArgumentList $moveSource, $moveDestination, $replaceSource, $replaceTarget, $Attempts

    try {
        Invoke-DeleteGuardBroker -Command delete -Path $approvedTree
    }
    finally {
        Wait-Job -Job $attackJob -Timeout 20 | Out-Null
        Stop-Job -Job $attackJob -ErrorAction SilentlyContinue
        Remove-Job -Job $attackJob -Force -ErrorAction SilentlyContinue
    }

    Assert-True (-not (Test-Path -LiteralPath $approvedTree)) 'approved Broker delete completed'
    Assert-True (Test-Path -LiteralPath $moveSource) 'protected move-out source remained in protected root'
    Assert-True (-not (Test-Path -LiteralPath $moveDestination)) 'move-out destination was never created'
    Assert-True (Test-Path -LiteralPath $replaceSource) 'outside replacement source remained outside protected root'
    Assert-True (Test-Path -LiteralPath $replaceTarget) 'protected replacement target still exists'
    Assert-True ((Get-Content -LiteralPath $replaceTarget -Raw).Trim() -eq 'protected original payload') 'protected replacement target content was not overwritten'

    Start-Sleep -Seconds 2
    $events = @()
    if (Test-Path -LiteralPath $eventFile) {
        $events = @(Get-Content -LiteralPath $eventFile | ForEach-Object {
            try { $_ | ConvertFrom-Json } catch { $null }
        } | Where-Object { $_ })
    }

    $moveEvents = @($events | Where-Object {
        $_.operation -eq 3 -and $_.targetPath -eq $moveSource
    })
    $replaceEvents = @($events | Where-Object {
        $_.operation -eq 4 -and $_.targetPath -eq $replaceTarget
    })

    Assert-True ($moveEvents.Count -gt 0) 'RenameOut denial reached Event Relay'
    Assert-True (-not [bool]$moveEvents[-1].canApprove) 'RenameOut denial is non-approvable'
    Assert-True ($replaceEvents.Count -gt 0) 'RenameReplace denial reached Event Relay'
    Assert-True (-not [bool]$replaceEvents[-1].canApprove) 'RenameReplace denial is non-approvable'

    Write-Host 'DeleteGuard rename-boundary runtime validation passed.'
}
finally {
    if ($protected -and (Test-Path -LiteralPath $protectedRoot)) {
        try { Invoke-DeleteGuardBroker -Command unprotect -Path $protectedRoot } catch { Write-Warning $_.Exception.Message }
    }

    if (Test-Path -LiteralPath $script:DeleteGuardTestRoot) {
        if (-not (Test-Path -LiteralPath $sentinel)) {
            throw 'Cleanup refused because the rename-test sentinel is missing.'
        }
        Remove-Item -LiteralPath $script:DeleteGuardTestRoot -Recurse -Force
    }
}
