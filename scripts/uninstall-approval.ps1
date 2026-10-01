param(
    [switch]$KeepAgentStartup
)

$ErrorActionPreference = 'Stop'
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run uninstall-approval.ps1 from an elevated PowerShell.'
}

$serviceName = 'DeleteGuardEventRelay'
$service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if ($service) {
    if ($service.Status -ne 'Stopped') {
        Stop-Service -Name $serviceName -Force
        $service.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(15))
    }

    & sc.exe delete $serviceName | Out-Host
    if ($LASTEXITCODE -ne 0) { throw "sc.exe delete failed with exit code $LASTEXITCODE." }
}

if (-not $KeepAgentStartup) {
    Write-Warning 'Agent auto-start is per-user. Run scripts\disable-agent.ps1 in each Windows account where it was enabled.'
}

Write-Host 'DeleteGuard Event Relay service removed.'
