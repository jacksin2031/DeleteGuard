param([switch]$PurgeData)

$ErrorActionPreference = 'Stop'
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run uninstall.ps1 from an elevated PowerShell.'
}

$destination = Join-Path $env:ProgramFiles 'DeleteGuard'
$machinePath = [Environment]::GetEnvironmentVariable('Path', 'Machine')
$parts = @($machinePath -split ';' | Where-Object { $_ -and $_ -ne $destination })
[Environment]::SetEnvironmentVariable('Path', ($parts -join ';'), 'Machine')

if (Test-Path $destination) {
    Remove-Item $destination -Recurse -Force
}

if ($PurgeData) {
    $data = Join-Path $env:ProgramData 'DeleteGuard'
    if (Test-Path $data) { Remove-Item $data -Recurse -Force }
}

Write-Host 'DeleteGuard binaries removed.'
Write-Warning 'Uninstalling does not automatically remove protection ACLs. Run deleteguard unprotect on protected roots first.'
