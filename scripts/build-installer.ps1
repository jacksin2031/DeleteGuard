<#
.SYNOPSIS
  Builds the DeleteGuard MSI installers (one per installer-UI language).

.DESCRIPTION
  1. Publishes the CLI, Broker, Agent and Event Relay self-contained (win-x64) into one payload folder.
  2. Builds installer\DeleteGuard.Installer.wixproj once per culture and collects the MSIs in
     artifacts\installer as DeleteGuard-<version>-x64-<culture>.msi.

  The MSI installs the user-mode package only. It does not install the development minifilter
  driver and does not register the Event Relay service (see scripts\install-approval.ps1).
  The MSIs are unsigned.

.PARAMETER Cultures
  Installer UI languages to build. Defaults to all supported ones.
#>
param(
    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Release',
    [string[]]$Cultures = @('en-US', 'zh-TW', 'zh-CN', 'ja-JP', 'ko-KR', 'es-ES', 'fr-FR', 'de-DE', 'pt-BR', 'ru-RU')
)

$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
$runtime = 'win-x64'
$payload = Join-Path $repo 'artifacts\installer\payload'
$out = Join-Path $repo 'artifacts\installer'

[xml]$props = Get-Content (Join-Path $repo 'Directory.Build.props')
$version = $props.Project.PropertyGroup.Version | Where-Object { $_ } | Select-Object -First 1
if (-not $version) { throw 'Could not read <Version> from Directory.Build.props.' }
Write-Host "DeleteGuard $version installer, cultures: $($Cultures -join ', ')"

if (Test-Path $out) { Remove-Item $out -Recurse -Force }
New-Item -ItemType Directory -Path $payload -Force | Out-Null

foreach ($project in 'DeleteGuard.Cli', 'DeleteGuard.Broker', 'DeleteGuard.Agent', 'DeleteGuard.EventRelay') {
    dotnet publish (Join-Path $repo "src\$project\$project.csproj") `
        -c $Configuration -r $runtime --self-contained true -o $payload
    if ($LASTEXITCODE -ne 0) { throw "Publishing $project failed with exit code $LASTEXITCODE." }
}

$wixBin = Join-Path $repo 'artifacts\installer\wix'
# MSBuild treats ';' on the command line as a property separator, so the culture list must use %3B.
$cultureList = $Cultures -join '%3B'
dotnet build (Join-Path $repo 'installer\DeleteGuard.Installer.wixproj') `
    -c $Configuration `
    -p:PayloadDir=$payload `
    -p:Cultures=$cultureList `
    -p:OutputPath="$wixBin\"
if ($LASTEXITCODE -ne 0) { throw "WiX build failed with exit code $LASTEXITCODE." }

foreach ($culture in $Cultures) {
    $msi = Get-ChildItem -Path $wixBin -Recurse -Filter 'DeleteGuard.msi' |
        Where-Object { $_.Directory.Name -eq $culture } |
        Select-Object -First 1
    if (-not $msi -and $Cultures.Count -eq 1) {
        $msi = Get-ChildItem -Path $wixBin -Recurse -Filter 'DeleteGuard.msi' | Select-Object -First 1
    }
    if (-not $msi) { throw "No MSI was produced for culture $culture." }

    $target = Join-Path $out "DeleteGuard-$version-x64-$culture.msi"
    Copy-Item $msi.FullName $target -Force
    Write-Host ("  {0}  ({1:N1} MB)" -f (Split-Path $target -Leaf), ((Get-Item $target).Length / 1MB))
}

Write-Host "Installers written to $out"
Write-Warning 'The installers are unsigned (Windows SmartScreen will warn) and do not include the minifilter driver.'
