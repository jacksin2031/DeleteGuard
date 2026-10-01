$ErrorActionPreference = 'Stop'

$runKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
Remove-ItemProperty -Path $runKey -Name 'DeleteGuardAgent' -ErrorAction SilentlyContinue

Get-Process -Name 'DeleteGuard.Agent' -ErrorAction SilentlyContinue | Stop-Process -Force

Write-Host 'DeleteGuard Agent auto-start is disabled for the current Windows user.'
