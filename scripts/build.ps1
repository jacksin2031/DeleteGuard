param(
    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Release',
    [ValidateSet('win-x64', 'win-arm64')]
    [string]$Runtime = 'win-x64'
)

$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
$out = Join-Path $repo "artifacts\$Runtime"

if (Test-Path $out) { Remove-Item $out -Recurse -Force }
New-Item -ItemType Directory -Path $out -Force | Out-Null

dotnet restore (Join-Path $repo 'DeleteGuard.sln')
dotnet build (Join-Path $repo 'DeleteGuard.sln') -c $Configuration --no-restore

dotnet publish (Join-Path $repo 'src\DeleteGuard.Cli\DeleteGuard.Cli.csproj') `
    -c $Configuration -r $Runtime --self-contained false -o $out

dotnet publish (Join-Path $repo 'src\DeleteGuard.Broker\DeleteGuard.Broker.csproj') `
    -c $Configuration -r $Runtime --self-contained false -o $out

Write-Host "DeleteGuard package: $out"
