param(
    [string]$InstallDirectory = (Join-Path $env:ProgramFiles 'DeleteGuard')
)

$ErrorActionPreference = 'Stop'
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run install-approval.ps1 from an elevated PowerShell.'
}

$relay = Join-Path $InstallDirectory 'DeleteGuard.EventRelay.exe'
if (-not (Test-Path $relay)) {
    throw "DeleteGuard.EventRelay.exe was not found at $relay. Install the v0.2.1 user-mode package first."
}

$serviceName = 'DeleteGuardEventRelay'
$existing = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if ($existing) {
    if ($existing.Status -ne 'Stopped') {
        Stop-Service -Name $serviceName -Force
        $existing.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(15))
    }

    & sc.exe config $serviceName "binPath= `"$relay`"" 'start= auto' 'obj= LocalSystem' | Out-Host
    if ($LASTEXITCODE -ne 0) { throw "sc.exe config failed with exit code $LASTEXITCODE." }
}
else {
    & sc.exe create $serviceName "binPath= `"$relay`"" 'start= auto' 'obj= LocalSystem' 'DisplayName= DeleteGuard Event Relay' | Out-Host
    if ($LASTEXITCODE -ne 0) { throw "sc.exe create failed with exit code $LASTEXITCODE." }
}

& sc.exe description $serviceName 'Relays DeleteGuard minifilter denial events to the read-only user approval channel.' | Out-Host
if ($LASTEXITCODE -ne 0) { throw "sc.exe description failed with exit code $LASTEXITCODE." }

& sc.exe failure $serviceName 'reset= 86400' 'actions= restart/5000/restart/15000/restart/60000' | Out-Host
if ($LASTEXITCODE -ne 0) { throw "sc.exe failure failed with exit code $LASTEXITCODE." }

Start-Service -Name $serviceName
(Get-Service -Name $serviceName).WaitForStatus('Running', [TimeSpan]::FromSeconds(15))

Write-Host 'DeleteGuard Event Relay is installed and running as LocalSystem.'
Write-Host 'Next, run scripts\enable-agent.ps1 once as the desktop user who should receive approval prompts.'
Write-Warning 'This does not install or test-sign the development minifilter driver.'
