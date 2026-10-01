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

$probeSource = Join-Path $PSScriptRoot 'HardLinkProbe.cs'
if (-not (Test-Path -LiteralPath $probeSource)) {
    throw "Hard-link probe source was not found: $probeSource"
}
Add-Type -Path $probeSource

$caseRoot = Join-Path $script:DeleteGuardTestRoot 'HardLinkCase'
$caseSentinel = Join-Path $caseRoot '.deleteguard-hardlink-test-case'
$protectedRoot = Join-Path $caseRoot 'Protected'
$escapeRoot = Join-Path $caseRoot 'Escape'
$protectedSource = Join-Path $protectedRoot 'source.txt'
$internalAlias = Join-Path $protectedRoot 'internal-link.txt'
$externalAlias = Join-Path $escapeRoot 'external-link.txt'
$raceSource = Join-Path $protectedRoot 'race-source.txt'
$raceAlias = Join-Path $escapeRoot 'race-link.txt'
$replacementSource = Join-Path $caseRoot 'replacement-source.txt'
$replacementTarget = Join-Path $protectedRoot 'replacement-target.txt'
$approvedTree = Join-Path $protectedRoot 'approved-tree'
$protected = $false
$results = [System.Collections.Generic.List[object]]::new()
$StatusAccessDenied = -1073741790 # 0xC0000022

Assert-DeleteGuardSafeTestPath -Path $caseRoot

function Add-Result {
    param([string]$Name, [bool]$Passed, [string]$Detail)
    $results.Add([pscustomobject]@{ name = $Name; passed = $Passed; detail = $Detail })
    Write-Host ("[{0}] {1} - {2}" -f ($(if ($Passed) { 'PASS' } else { 'FAIL' })), $Name, $Detail)
}

try {
    if (Test-Path -LiteralPath $caseRoot) {
        if (-not (Test-Path -LiteralPath $caseSentinel)) {
            throw "Refusing to reuse $caseRoot because its hard-link-test sentinel is missing."
        }
        Remove-Item -LiteralPath $caseRoot -Recurse -Force
    }

    New-Item -ItemType Directory -Path $protectedRoot -Force | Out-Null
    New-Item -ItemType Directory -Path $escapeRoot -Force | Out-Null
    Set-Content -LiteralPath $caseSentinel -Value 'DeleteGuard hard-link validation case root'
    Set-Content -LiteralPath $protectedSource -Value 'protected source'
    Set-Content -LiteralPath $raceSource -Value 'race source'
    Set-Content -LiteralPath $replacementSource -Value 'replacement source'
    Set-Content -LiteralPath $replacementTarget -Value 'protected original'
    New-Item -ItemType Directory -Path $approvedTree -Force | Out-Null
    1..1500 | ForEach-Object {
        Set-Content -LiteralPath (Join-Path $approvedTree ("file-{0:D4}.txt" -f $_)) -Value $_
    }

    Invoke-DeleteGuardBroker -Command protect -Path $protectedRoot
    $protected = $true

    $externalError = [DeleteGuardHardLinkProbe]::CreateHardLinkError($externalAlias, $protectedSource)
    Add-Result 'protected source external hard link denied' `
        ($externalError -eq 5 -and -not (Test-Path -LiteralPath $externalAlias)) `
        "CreateHardLinkW error=$externalError (expected ERROR_ACCESS_DENIED=5)"

    $internalError = [DeleteGuardHardLinkProbe]::CreateHardLinkError($internalAlias, $protectedSource)
    Add-Result 'same-root hard link remains allowed' `
        ($internalError -eq 0 -and (Test-Path -LiteralPath $internalAlias)) `
        "CreateHardLinkW error=$internalError"

    $replaceStatus = [DeleteGuardHardLinkProbe]::ReplaceWithHardLinkStatus($replacementSource, $replacementTarget)
    Add-Result 'replace protected destination with hard link denied' `
        ($replaceStatus -eq $StatusAccessDenied) `
        ("NtSetInformationFile status=0x{0:X8}" -f ([uint32]$replaceStatus))

    $raceJob = Start-Job -ScriptBlock {
        param($Alias, $Source, $Attempts, $ProbeSource)
        Add-Type -Path $ProbeSource
        $unexpected = @()
        for ($i = 0; $i -lt $Attempts; $i++) {
            $errorCode = [DeleteGuardHardLinkProbe]::CreateHardLinkError($Alias, $Source)
            if ($errorCode -eq 0) {
                $unexpected += 0
                break
            }
            if ($errorCode -ne 5 -and $unexpected.Count -lt 10) {
                $unexpected += $errorCode
            }
            Start-Sleep -Milliseconds 2
        }
        [pscustomobject]@{
            unexpected = $unexpected
            aliasExists = (Test-Path -LiteralPath $Alias)
        }
    } -ArgumentList $raceAlias, $raceSource, $RaceAttempts, $probeSource

    try {
        Invoke-DeleteGuardBroker -Command delete -Path $approvedTree
    }
    finally {
        Wait-Job -Job $raceJob -Timeout 20 | Out-Null
    }

    $raceResult = Receive-Job -Job $raceJob -ErrorAction SilentlyContinue
    Stop-Job -Job $raceJob -ErrorAction SilentlyContinue
    Remove-Job -Job $raceJob -Force -ErrorAction SilentlyContinue

    Add-Result 'approved recursive delete completed' `
        (-not (Test-Path -LiteralPath $approvedTree)) `
        'Broker deleted the approved 1500-file tree'

    $racePassed = $raceResult -and
        -not $raceResult.aliasExists -and
        @($raceResult.unexpected).Count -eq 0 -and
        (Test-Path -LiteralPath $raceSource)
    Add-Result 'hard-link escape blocked during ACL-relax window' `
        $racePassed `
        'competing process never created an external alias and observed only access-denied failures'

    $replacementValue = Get-Content -LiteralPath $replacementTarget -Raw
    Add-Result 'protected replacement target unchanged' `
        ((Test-Path -LiteralPath $replacementSource) -and $replacementValue.Trim() -eq 'protected original') `
        'replacement source remains separate and protected target content is intact'
}
finally {
    if ($protected -and (Test-Path -LiteralPath $protectedRoot)) {
        try {
            Invoke-DeleteGuardBroker -Command unprotect -Path $protectedRoot
        }
        catch {
            Write-Warning $_.Exception.Message
        }
    }

    if (Test-Path -LiteralPath $caseRoot) {
        Assert-DeleteGuardSafeTestPath -Path $caseRoot
        if (-not (Test-Path -LiteralPath $caseSentinel)) {
            throw "Refusing cleanup of $caseRoot because its hard-link-test sentinel is missing."
        }
        Remove-Item -LiteralPath $caseRoot -Recurse -Force
    }
}

if ($results | Where-Object { -not $_.passed }) {
    exit 1
}

Write-Host 'DeleteGuard hard-link validation passed.'
exit 0
