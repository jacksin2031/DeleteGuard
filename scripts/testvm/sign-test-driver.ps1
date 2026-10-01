param(
    [string]$CertificateSubject = 'CN=DeleteGuard Test VM',
    [switch]$SkipBuild
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'TestVm.Common.ps1')

Assert-DeleteGuardAdministrator
Assert-DeleteGuardDisposableVm

$repo = Get-DeleteGuardRepoRoot
if (-not $SkipBuild) {
    & (Join-Path $repo 'scripts\build-driver.ps1') -Configuration Release
    if ($LASTEXITCODE -ne 0) { throw 'DeleteGuard driver build failed.' }
}

$package = Join-Path $repo 'artifacts\driver-x64'
$sys = Join-Path $package 'DeleteGuardFilter.sys'
$inf = Join-Path $package 'DeleteGuardFilter.inf'
$cat = Join-Path $package 'DeleteGuardFilter.cat'
foreach ($path in @($sys, $inf)) {
    if (-not (Test-Path -LiteralPath $path)) { throw "Missing driver package file: $path" }
}

$cert = Get-ChildItem Cert:\LocalMachine\My |
    Where-Object { $_.Subject -eq $CertificateSubject -and $_.NotAfter -gt (Get-Date).AddDays(1) } |
    Sort-Object NotAfter -Descending |
    Select-Object -First 1

if (-not $cert) {
    $cert = New-SelfSignedCertificate `
        -Type CodeSigningCert `
        -Subject $CertificateSubject `
        -CertStoreLocation 'Cert:\LocalMachine\My' `
        -KeyAlgorithm RSA `
        -KeyLength 3072 `
        -HashAlgorithm SHA256 `
        -NotAfter (Get-Date).AddDays(30)
}

$cer = Join-Path $package 'DeleteGuard-TestVM.cer'
Export-Certificate -Cert $cert -FilePath $cer -Force | Out-Null
Import-Certificate -FilePath $cer -CertStoreLocation 'Cert:\LocalMachine\Root' | Out-Null
Import-Certificate -FilePath $cer -CertStoreLocation 'Cert:\LocalMachine\TrustedPublisher' | Out-Null

$signtool = Get-ChildItem -Path (Join-Path $repo 'packages') -Filter signtool.exe -Recurse -File -ErrorAction Stop |
    Where-Object { $_.FullName -match '\\x64\\signtool\.exe$' } |
    Select-Object -First 1 -ExpandProperty FullName
$inf2cat = Get-ChildItem -Path (Join-Path $repo 'packages') -Filter Inf2Cat.exe -Recurse -File -ErrorAction Stop |
    Select-Object -First 1 -ExpandProperty FullName

if (-not $signtool) { throw 'signtool.exe was not found in the restored WDK/SDK packages.' }
if (-not $inf2cat) { throw 'Inf2Cat.exe was not found in the restored WDK packages.' }

Write-Host "Signing driver image with test certificate $($cert.Thumbprint)..."
& $signtool sign /v /fd SHA256 /sm /s My /sha1 $cert.Thumbprint $sys | Out-Host
if ($LASTEXITCODE -ne 0) { throw "SignTool failed to sign $sys." }

if (Test-Path -LiteralPath $cat) { Remove-Item -LiteralPath $cat -Force }
& $inf2cat "/driver:$package" '/os:10_X64' '/uselocaltime' | Out-Host
if ($LASTEXITCODE -ne 0) { throw 'Inf2Cat failed after the driver image was signed.' }

& $signtool sign /v /fd SHA256 /sm /s My /sha1 $cert.Thumbprint $cat | Out-Host
if ($LASTEXITCODE -ne 0) { throw "SignTool failed to sign $cat." }

& $signtool verify /v /kp $sys | Out-Host
if ($LASTEXITCODE -ne 0) { throw 'Kernel-policy signature verification failed for DeleteGuardFilter.sys.' }
& $signtool verify /v /kp /c $cat $inf | Out-Host
if ($LASTEXITCODE -ne 0) { throw 'Catalog/INF verification failed.' }

Write-Host 'DeleteGuard test-signed driver package is ready:'
Write-Host "  $package"
Write-Host 'The private key remains in this disposable VM LocalMachine certificate store and is not exported.'
