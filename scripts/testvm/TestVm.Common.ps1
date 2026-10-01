Set-StrictMode -Version Latest

$script:DeleteGuardTestVmMarker = Join-Path $env:ProgramData 'DeleteGuard-TestVM.marker.json'
$script:DeleteGuardTestRoot = 'C:\DeleteGuard-VMTest'

function Get-DeleteGuardRepoRoot {
    return Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
}

function Assert-DeleteGuardAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'This DeleteGuard test-VM step must run from an elevated PowerShell.'
    }
}

function Assert-DeleteGuardDisposableVm {
    if (-not (Test-Path -LiteralPath $script:DeleteGuardTestVmMarker)) {
        throw "DeleteGuard disposable-VM marker is missing: $script:DeleteGuardTestVmMarker. Run prepare-test-vm.ps1 first."
    }

    try {
        $marker = Get-Content -LiteralPath $script:DeleteGuardTestVmMarker -Raw | ConvertFrom-Json
    }
    catch {
        throw "DeleteGuard disposable-VM marker is invalid: $($_.Exception.Message)"
    }

    if ($marker.machineName -ne $env:COMPUTERNAME -or $marker.acknowledged -ne $true) {
        throw 'DeleteGuard disposable-VM marker does not match this computer.'
    }
}

function Assert-DeleteGuardNoReparseComponents {
    param(
        [Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)][string]$Candidate
    )

    $current = $Root
    if (Test-Path -LiteralPath $current) {
        $rootItem = Get-Item -LiteralPath $current -Force
        if (-not $rootItem.PSIsContainer) {
            throw "DeleteGuard test root exists but is not a directory: $current"
        }
        if (($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Refusing destructive test because the test root is a reparse point: $current"
        }
    }

    if ($Candidate.Equals($Root, [StringComparison]::OrdinalIgnoreCase)) {
        return
    }

    $relative = $Candidate.Substring($Root.Length).TrimStart('\')
    foreach ($segment in @($relative -split '\\' | Where-Object { $_ })) {
        $current = Join-Path $current $segment
        if (-not (Test-Path -LiteralPath $current)) {
            continue
        }

        $item = Get-Item -LiteralPath $current -Force
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Refusing destructive test through a reparse point: $current"
        }
    }
}

function Assert-DeleteGuardSafeTestPath {
    param([Parameter(Mandatory)][string]$Path)

    $root = [IO.Path]::GetFullPath($script:DeleteGuardTestRoot).TrimEnd('\')
    $candidate = [IO.Path]::GetFullPath($Path).TrimEnd('\')

    if (-not $candidate.Equals($root, [StringComparison]::OrdinalIgnoreCase) -and
        -not $candidate.StartsWith($root + '\', [StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing destructive test outside $root : $candidate"
    }

    Assert-DeleteGuardNoReparseComponents -Root $root -Candidate $candidate
}

function Get-DeleteGuardInstalledDirectory {
    return Join-Path $env:ProgramFiles 'DeleteGuard'
}

function Get-DeleteGuardBrokerPath {
    $path = Join-Path (Get-DeleteGuardInstalledDirectory) 'DeleteGuard.Broker.exe'
    if (-not (Test-Path -LiteralPath $path)) {
        throw "DeleteGuard broker not found at $path. Install the user-mode package first."
    }
    return $path
}

function Invoke-DeleteGuardBroker {
    param(
        [Parameter(Mandatory)][ValidateSet('protect','unprotect','delete')][string]$Command,
        [Parameter(Mandatory)][string]$Path,
        [string[]]$ExtraArguments = @()
    )

    Assert-DeleteGuardSafeTestPath -Path $Path
    $broker = Get-DeleteGuardBrokerPath
    $arguments = @($Command, $Path) + $ExtraArguments
    $process = Start-Process -FilePath $broker -ArgumentList $arguments -Wait -PassThru -NoNewWindow
    if ($process.ExitCode -ne 0) {
        throw "DeleteGuard broker command '$Command' failed with exit code $($process.ExitCode)."
    }
}

function Test-DeleteGuardFilterLoaded {
    $output = & fltmc.exe filters 2>&1 | Out-String
    return $output -match '(?im)^DeleteGuardFilter\s'
}

function Wait-DeleteGuardFilterLoaded {
    param([int]$TimeoutSeconds = 15)

    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        if (Test-DeleteGuardFilterLoaded) { return }
        Start-Sleep -Milliseconds 500
    } while ([DateTime]::UtcNow -lt $deadline)

    throw 'DeleteGuardFilter did not appear in fltmc filters before timeout.'
}
