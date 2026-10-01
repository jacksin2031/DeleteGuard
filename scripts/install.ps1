param(
    [ValidateSet('win-x64', 'win-arm64')]
    [string]$Runtime = 'win-x64',
    [switch]$SkipPath
)

$ErrorActionPreference = 'Stop'
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run install.ps1 from an elevated PowerShell.'
}

$repo = Split-Path -Parent $PSScriptRoot
$source = Join-Path $repo "artifacts\$Runtime"
$destination = Join-Path $env:ProgramFiles 'DeleteGuard'
if (-not (Test-Path (Join-Path $source 'deleteguard.exe'))) {
    throw "Build artifacts not found. Run .\scripts\build.ps1 first."
}

New-Item -ItemType Directory -Path $destination -Force | Out-Null
Copy-Item (Join-Path $source '*') $destination -Recurse -Force

if (-not $SkipPath) {
    $machinePath = [Environment]::GetEnvironmentVariable('Path', 'Machine')
    $parts = @($machinePath -split ';' | Where-Object { $_ })
    if ($parts -notcontains $destination) {
        [Environment]::SetEnvironmentVariable('Path', (($parts + $destination) -join ';'), 'Machine')
    }
}

Write-Host "Installed DeleteGuard to $destination"
Write-Host 'Open a new terminal and run: deleteguard doctor'
