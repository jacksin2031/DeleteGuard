$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$source = Join-Path $repo 'scripts\Test-VmAcceptance.ps1'
$tokens = $null; $parseErrors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($source,[ref]$tokens,[ref]$parseErrors)
if ($parseErrors.Count) { throw 'Harness syntax errors.' }
$allowed = @('Normalize-Path','Test-UnderPath','Test-CanonicalFixtureRoot','Test-NoReparsePoints','Test-SafeFixtureTree','Register-OwnedPath','Ensure-TestDirectory','Test-OnlyOwnedPaths','New-TestFile','New-TestDirectory','Get-TreeSnapshot','Add-NativeType','Add-TypeAssembly','Invoke-RunCleanup','Add-Case','Get-UtcNow')
foreach ($node in $ast.FindAll({param($candidate) $candidate -is [Management.Automation.Language.FunctionDefinitionAst]},$true)) {
    if ($allowed -contains $node.Name) { . ([scriptblock]::Create($node.Extent.Text)) }
}
$script:CorePath = Join-Path $repo 'artifacts\win-x64\DeleteGuard.Core.dll'
$script:OwnedPaths = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
$tempRoot = Join-Path $repo 'artifacts\harness-helper-fixtures'
$runId = [guid]::NewGuid().ToString('N')
$script:RunRoot = Join-Path (Join-Path $tempRoot 'DeleteGuard.VmAcceptance') $runId
$ownedMainRoot = $script:RunRoot
$collisionRoot = $null
$results = [Collections.Generic.List[string]]::new()
$nativeDispositionResults = [Collections.Generic.List[object]]::new()
$dispositionStatuses = [Collections.Generic.List[string]]::new()
$cleanupErrors = [Collections.Generic.List[string]]::new()
$failureMessage = $null
try {
    New-Item -ItemType Directory -Path $script:RunRoot | Out-Null
    Register-OwnedPath $script:RunRoot
    $tree = Join-Path $script:RunRoot 'tree'
    New-TestDirectory $tree 2
    if (@(Test-OnlyOwnedPaths $script:RunRoot).Count) { throw 'Created fixtures are absent from ownership inventory.' }
    $results.Add('owned fixture inventory accepts only created paths')
    $before = @(Get-TreeSnapshot $tree)
    $after = @(Get-TreeSnapshot $tree)
    if (($before | ConvertTo-Json -Compress) -ne ($after | ConvertTo-Json -Compress)) { throw 'Unchanged fixture snapshot mismatched.' }
    [IO.File]::WriteAllText((Join-Path $tree 'item-0.txt'),'changed fixture content')
    if (($before | ConvertTo-Json -Compress) -eq ((@(Get-TreeSnapshot $tree)) | ConvertTo-Json -Compress)) { throw 'Modified file content went undetected.' }
    $results.Add('recursive snapshot detects changed file contents')
    $extra = Join-Path $script:RunRoot 'unexpected-fixture.txt'
    [IO.File]::WriteAllText($extra,'synthetic unexpected data')
    $unexpected = @(Test-OnlyOwnedPaths $script:RunRoot)
    if ($unexpected.Count -ne 1 -or $unexpected[0] -ne $extra -or -not [IO.File]::Exists($extra)) { throw 'Unexpected path was not detected and retained.' }
    $results.Add('unexpected ordinary file is detected and retained')
    # The test has observed the unowned path. It was created by this helper;
    # register it only now so later cleanup may remove this known fixture.
    Register-OwnedPath $extra

    Add-TypeAssembly
    $nativeError = 0
    $missing = Join-Path $script:RunRoot 'missing-native.txt'
    if ([DeleteGuard.VmAcceptance.Native]::DeleteFile($missing,[ref]$nativeError) -or $nativeError -ne 2) { throw "Native error capture mismatch: $nativeError" }
    $results.Add('native wrapper captures actual ERROR_FILE_NOT_FOUND=2')
    $ordinary = Join-Path $script:RunRoot 'ordinary-native.txt'
    New-TestFile $ordinary
    if (-not [DeleteGuard.VmAcceptance.Native]::DeleteFile($ordinary,[ref]$nativeError) -or [IO.File]::Exists($ordinary) -or $nativeError -ne 0) { throw 'Unprotected native DeleteFile control failed.' }
    $onClose = Join-Path $script:RunRoot 'ordinary-delete-on-close.txt'
    New-TestFile $onClose
    if (-not [DeleteGuard.VmAcceptance.Native]::OpenDeleteOnClose($onClose,[ref]$nativeError) -or [IO.File]::Exists($onClose)) { throw 'Unprotected delete-on-close control failed.' }
    $results.Add('unprotected native delete and delete-on-close controls execute')

    foreach ($dispositionCase in @(
        [pscustomobject]@{ name = 'delete'; flags = [uint32]1; readOnly = $false },
        [pscustomobject]@{ name = 'posix'; flags = [uint32]3; readOnly = $false },
        [pscustomobject]@{ name = 'ignore-readonly'; flags = [uint32]17; readOnly = $true }
    )) {
        $path = Join-Path $script:RunRoot ("disposition-ex-{0}.txt" -f $dispositionCase.name)
        New-TestFile $path
        if ($dispositionCase.readOnly) {
            $attributes = [IO.File]::GetAttributes($path)
            [IO.File]::SetAttributes($path, $attributes -bor [IO.FileAttributes]::ReadOnly)
        }
        $readOnlyBefore = (([IO.File]::GetAttributes($path) -band [IO.FileAttributes]::ReadOnly) -ne 0)
        $hashBefore = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
        $native = [DeleteGuard.VmAcceptance.Native]::SetDispositionInfoEx($path, $dispositionCase.flags)
        $targetExists = [IO.File]::Exists($path)
        $hashAfter = if ($targetExists) { (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash } else { $null }
        $readOnlyAfter = if ($targetExists) { (([IO.File]::GetAttributes($path) -band [IO.FileAttributes]::ReadOnly) -ne 0) } else { $false }
        $succeeded = $native.OpenAttempted -and $native.OpenSucceeded -and $native.SetAttempted -and
            $native.SetReturned -and $native.SetSucceeded -and $native.CloseAttempted -and
            $native.CloseSucceeded -and -not $targetExists -and
            (-not $dispositionCase.readOnly -or $readOnlyBefore)
        $unsupported = ($native.OpenError -in @(1, 50, 87)) -or ($native.SetError -in @(1, 50, 87))
        $status = if ($succeeded) { 'PASS' } elseif ($unsupported) { 'BLOCKED' } else { 'FAIL' }
        $dispositionStatuses.Add($status)
        $nativeDispositionResults.Add([ordered]@{
            scenario = $dispositionCase.name
            status = $status
            path = $path
            informationClass = $native.InformationClass
            flags = $native.Flags
            openAttempted = $native.OpenAttempted
            openSucceeded = $native.OpenSucceeded
            openError = $native.OpenError
            openException = $native.OpenException
            openHResult = $native.OpenHResult
            setAttempted = $native.SetAttempted
            setReturned = $native.SetReturned
            setSucceeded = $native.SetSucceeded
            setError = $native.SetError
            setException = $native.SetException
            setHResult = $native.SetHResult
            closeAttempted = $native.CloseAttempted
            closeSucceeded = $native.CloseSucceeded
            closeError = $native.CloseError
            closeException = $native.CloseException
            closeHResult = $native.CloseHResult
            readOnlyBefore = $readOnlyBefore
            readOnlyAfter = $readOnlyAfter
            targetExists = $targetExists
            hashBefore = $hashBefore
            hashAfter = $hashAfter
        })
        if ($status -eq 'FAIL') { throw "Unprotected FileDispositionInformationEx $($dispositionCase.name) control failed; see native stage results." }
    }
    $results.Add('unprotected FileDispositionInformationEx DELETE, POSIX, and IGNORE_READONLY controls recorded with native stages')

    $readonlyBaseline = Join-Path $script:RunRoot 'disposition-ex-readonly-baseline.txt'
    New-TestFile $readonlyBaseline
    [IO.File]::SetAttributes($readonlyBaseline, [IO.File]::GetAttributes($readonlyBaseline) -bor [IO.FileAttributes]::ReadOnly)
    $readonlyHashBefore = (Get-FileHash -LiteralPath $readonlyBaseline -Algorithm SHA256).Hash
    $readonlyResult = [DeleteGuard.VmAcceptance.Native]::SetDispositionInfoEx($readonlyBaseline, [uint32]1)
    $readonlyExists = [IO.File]::Exists($readonlyBaseline)
    $readonlyHashAfter = if ($readonlyExists) { (Get-FileHash -LiteralPath $readonlyBaseline -Algorithm SHA256).Hash } else { $null }
    $readonlyStayed = $readonlyExists -and $readonlyHashBefore -ceq $readonlyHashAfter -and
        (([IO.File]::GetAttributes($readonlyBaseline) -band [IO.FileAttributes]::ReadOnly) -ne 0)
    $readonlyDenied = ($readonlyResult.OpenSucceeded -and $readonlyResult.SetAttempted -and $readonlyResult.SetReturned -and
        -not $readonlyResult.SetSucceeded -and $readonlyResult.SetError -eq 5 -and $readonlyResult.CloseSucceeded) -or
        (-not $readonlyResult.OpenSucceeded -and $readonlyResult.OpenError -eq 5 -and -not $readonlyResult.SetAttempted)
    $readonlyUnsupported = ($readonlyResult.OpenError -in @(1, 50, 87)) -or ($readonlyResult.SetError -in @(1, 50, 87))
    $readonlyStatus = if ($readonlyDenied -and $readonlyStayed) { 'PASS' } elseif ($readonlyUnsupported) { 'BLOCKED' } else { 'FAIL' }
    $dispositionStatuses.Add($readonlyStatus)
    $nativeDispositionResults.Add([ordered]@{
        scenario = 'readonly-baseline-delete'
        status = $readonlyStatus
        path = $readonlyBaseline
        informationClass = $readonlyResult.InformationClass
        flags = $readonlyResult.Flags
        openAttempted = $readonlyResult.OpenAttempted
        openSucceeded = $readonlyResult.OpenSucceeded
        openError = $readonlyResult.OpenError
        openException = $readonlyResult.OpenException
        openHResult = $readonlyResult.OpenHResult
        setAttempted = $readonlyResult.SetAttempted
        setReturned = $readonlyResult.SetReturned
        setSucceeded = $readonlyResult.SetSucceeded
        setError = $readonlyResult.SetError
        setException = $readonlyResult.SetException
        setHResult = $readonlyResult.SetHResult
        closeAttempted = $readonlyResult.CloseAttempted
        closeSucceeded = $readonlyResult.CloseSucceeded
        closeError = $readonlyResult.CloseError
        closeException = $readonlyResult.CloseException
        closeHResult = $readonlyResult.CloseHResult
        readOnlyBefore = $true
        readOnlyAfter = if ($readonlyExists) { (([IO.File]::GetAttributes($readonlyBaseline) -band [IO.FileAttributes]::ReadOnly) -ne 0) } else { $false }
        targetExists = $readonlyExists
        hashBefore = $readonlyHashBefore
        hashAfter = $readonlyHashAfter
    })
    if ($readonlyStatus -eq 'FAIL') { throw 'Read-only FileDispositionInformationEx DELETE baseline did not fail with access denied while preserving the fixture.' }
    $results.Add('read-only DELETE baseline is denied and the readonly fixture hash survives')

    $missingDisposition = Join-Path $script:RunRoot 'missing-disposition-ex.txt'
    $missingResult = [DeleteGuard.VmAcceptance.Native]::SetDispositionInfoEx($missingDisposition, [uint32]1)
    $missingStatus = if ($missingResult.OpenAttempted -and -not $missingResult.OpenSucceeded -and $missingResult.OpenError -eq 2 -and
        -not $missingResult.SetAttempted -and -not $missingResult.CloseAttempted -and -not [IO.File]::Exists($missingDisposition)) { 'PASS' }
        elseif (($missingResult.OpenError -in @(1, 50, 87)) -or ($missingResult.SetError -in @(1, 50, 87))) { 'BLOCKED' } else { 'FAIL' }
    $dispositionStatuses.Add($missingStatus)
    $nativeDispositionResults.Add([ordered]@{
        scenario = 'missing-path-open-stage'
        status = $missingStatus
        path = $missingDisposition
        informationClass = $missingResult.InformationClass
        flags = $missingResult.Flags
        openAttempted = $missingResult.OpenAttempted
        openSucceeded = $missingResult.OpenSucceeded
        openError = $missingResult.OpenError
        openException = $missingResult.OpenException
        openHResult = $missingResult.OpenHResult
        setAttempted = $missingResult.SetAttempted
        setReturned = $missingResult.SetReturned
        setSucceeded = $missingResult.SetSucceeded
        setError = $missingResult.SetError
        setException = $missingResult.SetException
        setHResult = $missingResult.SetHResult
        closeAttempted = $missingResult.CloseAttempted
        closeSucceeded = $missingResult.CloseSucceeded
        closeError = $missingResult.CloseError
        closeException = $missingResult.CloseException
        closeHResult = $missingResult.CloseHResult
        targetExists = [IO.File]::Exists($missingDisposition)
    })
    if ($missingStatus -eq 'FAIL') { throw 'Missing-path probe did not capture ERROR_FILE_NOT_FOUND=2 at CreateFileW.' }
    $results.Add('missing path reports open-stage ERROR_FILE_NOT_FOUND=2 without attempting set or close')

    $collisionId = [guid]::NewGuid().ToString('N')
    $collisionRoot = Join-Path (Join-Path $tempRoot 'DeleteGuard.VmAcceptance') $collisionId
    New-Item -ItemType Directory -Path $collisionRoot | Out-Null
    $marker = Join-Path $collisionRoot 'pre-existing-synthetic-data.txt'
    [IO.File]::WriteAllText($marker,'must survive harness cleanup')
    $script:RunRoot = $collisionRoot
    $script:GuardRoot = Join-Path $collisionRoot 'protected'
    $script:Protected = $false
    $script:ChildMayBeRunning = $false
    $script:Cases = [Collections.Generic.List[object]]::new()
    Invoke-RunCleanup $tempRoot $collisionId
    if (-not [IO.File]::Exists($marker) -or $script:Cases[0].status -ne 'FAIL') { throw 'Cleanup deleted or accepted a canonical but unowned pre-existing root.' }
    $results.Add('cleanup refuses and preserves a canonical pre-existing unowned GUID subtree')
    # Ownership must remain absent during the negative cleanup assertion.
    # Both paths were created by this helper and can be registered afterwards.
    Register-OwnedPath $collisionRoot
    Register-OwnedPath $marker
}
catch { $failureMessage = $_.Exception.ToString() }
finally {
    $workspaceFence = [IO.Path]::GetFullPath($tempRoot).TrimEnd('\') + '\'
    $scratchTargets = @([pscustomobject]@{path=$ownedMainRoot;id=$runId})
    if ($collisionRoot) { $scratchTargets += [pscustomobject]@{path=$collisionRoot;id=$collisionId} }
    foreach ($target in $scratchTargets) {
        try {
            $resolvedTarget = [IO.Path]::GetFullPath($target.path)
            $safe = $resolvedTarget.StartsWith($workspaceFence,[StringComparison]::OrdinalIgnoreCase) -and
                (Test-SafeFixtureTree $resolvedTarget $resolvedTarget $tempRoot $target.id) -and
                $script:OwnedPaths.Contains((Normalize-Path $resolvedTarget))
            if (-not $safe) { $cleanupErrors.Add("Unsafe scratch cleanup target retained: $resolvedTarget") }
            elseif (Test-Path -LiteralPath $resolvedTarget) {
                $unexpectedPaths = @(Test-OnlyOwnedPaths $resolvedTarget)
                if ($unexpectedPaths.Count) { $cleanupErrors.Add("Unowned scratch paths retained: $($unexpectedPaths -join ', ')") }
                else { Remove-Item -LiteralPath $resolvedTarget -Recurse -Force -ErrorAction Stop }
            }
        }
        catch { $cleanupErrors.Add("Scratch cleanup failed for $($target.path): $($_.Exception.ToString())") }
    }
}
$helperStatus = if ($failureMessage -or $cleanupErrors.Count -gt 0 -or $dispositionStatuses -contains 'FAIL') { 'FAIL' } elseif ($dispositionStatuses -contains 'BLOCKED') { 'BLOCKED' } else { 'PASS' }
$result = [ordered]@{status=$helperStatus;failureMessage=$failureMessage;cleanupErrors=$cleanupErrors.ToArray();checks=$results.ToArray();nativeDispositionResults=$nativeDispositionResults.ToArray();scope='Tool helpers and generated unprotected scratch files only; no policy, driver loading, or protected-delete testing';observedUtc=[DateTimeOffset]::UtcNow.ToString('o')}
try {
    New-Item -ItemType Directory -Path (Join-Path $repo 'artifacts\acceptance-validation') -Force -ErrorAction Stop | Out-Null
    $resultJson = ConvertTo-Json -InputObject $result -Depth 6
    Set-Content -LiteralPath (Join-Path $repo 'artifacts\acceptance-validation\helper-smoke.json') -Value $resultJson -Encoding utf8 -ErrorAction Stop
}
catch {
    $result.status = 'FAIL'
    $result.cleanupErrors = @($result.cleanupErrors) + @("Could not save helper-smoke.json: $($_.Exception.ToString())")
    $resultJson = ConvertTo-Json -InputObject $result -Depth 6
}
Write-Output $resultJson
if ($result.status -eq 'FAIL') { exit 1 }
if ($result.status -eq 'BLOCKED') { exit 2 }
