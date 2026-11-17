param(
    [string]$InstallDirectory = (Join-Path $env:ProgramFiles 'DeleteGuard'),
    [switch]$NoStart
)

$ErrorActionPreference = 'Stop'
$agent = Join-Path $InstallDirectory 'DeleteGuard.Agent.exe'
if (-not (Test-Path $agent)) {
    throw "DeleteGuard.Agent.exe was not found at $agent. Install the v0.2.1 user-mode package first."
}

$runKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
New-Item -Path $runKey -Force | Out-Null
New-ItemProperty -Path $runKey -Name 'DeleteGuardAgent' -PropertyType String -Value "`"$agent`" --background" -Force | Out-Null

if (-not $NoStart) {
    $alreadyRunning = Get-Process -Name 'DeleteGuard.Agent' -ErrorAction SilentlyContinue
    if (-not $alreadyRunning) {
        Start-Process -FilePath $agent -ArgumentList '--background'
    }
}

Write-Host 'DeleteGuard Agent is enabled for the current Windows user.'
Write-Host 'It will start automatically at sign-in and show approval prompts for fresh denial events.'
