$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$source = Join-Path $repo 'scripts\Test-VmAcceptance.ps1'
$tokens = $null; $parseErrors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($source,[ref]$tokens,[ref]$parseErrors)
if ($parseErrors.Count) { throw 'Harness syntax errors.' }
$allowed = @('Normalize-Path','Test-UnderPath','Test-CanonicalFixtureRoot','Test-NoReparsePoints','Test-SafeFixtureTree','Register-OwnedPath','Ensure-TestDirectory','Test-OnlyOwnedPaths','New-TestFile','New-TestDirectory','Get-TreeSnapshot','Add-TypeAssembly','Invoke-RunCleanup','Add-Case','Get-UtcNow')
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
}
finally {
    $workspaceFence = [IO.Path]::GetFullPath($tempRoot).TrimEnd('\') + '\'
    $scratchTargets = @([pscustomobject]@{path=$ownedMainRoot;id=$runId})
    if ($collisionRoot) { $scratchTargets += [pscustomobject]@{path=$collisionRoot;id=$collisionId} }
    foreach ($target in $scratchTargets) {
        $resolvedTarget = [IO.Path]::GetFullPath($target.path)
        if (-not $resolvedTarget.StartsWith($workspaceFence,[StringComparison]::OrdinalIgnoreCase) -or -not (Test-SafeFixtureTree $resolvedTarget $resolvedTarget $tempRoot $target.id)) { throw 'Smoke fixture cleanup target was unsafe.' }
        if (Test-Path -LiteralPath $resolvedTarget) { Remove-Item -LiteralPath $resolvedTarget -Recurse -Force }
    }
}
$result = [ordered]@{status='PASS';checks=$results.ToArray();scope='Tool helpers and generated unprotected scratch files only; no policy, driver loading, or protected-delete testing';observedUtc=[DateTimeOffset]::UtcNow.ToString('o')}
New-Item -ItemType Directory -Path (Join-Path $repo 'artifacts\acceptance-validation') -Force | Out-Null
$result | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $repo 'artifacts\acceptance-validation\helper-smoke.json') -Encoding utf8
$result | ConvertTo-Json -Depth 4
