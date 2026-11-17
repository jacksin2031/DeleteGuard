<#
.SYNOPSIS
  Compiles and runs the user-mode C tests for the pieces of the minifilter that have no kernel
  dependencies (currently the bulk-delete rate limiter). Needs Visual Studio's C++ tools.
#>
$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot
$out = Join-Path $here 'bin'
New-Item -ItemType Directory -Path $out -Force | Out-Null

$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
if (-not (Test-Path $vswhere)) { throw 'vswhere.exe was not found; install Visual Studio Build Tools with the C++ workload.' }
$install = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath | Select-Object -First 1
if (-not $install) { throw 'No Visual Studio installation with the C++ x64 tools was found.' }
$devCmd = Join-Path $install 'VC\Auxiliary\Build\vcvars64.bat'
if (-not (Test-Path $devCmd)) { throw "vcvars64.bat was not found under $install." }

$source = Join-Path $here 'bulkguard_test.c'
$exe = Join-Path $out 'bulkguard_test.exe'

# /W4 /WX: the header is shared with kernel code, so keep it warning-free.
$compile = "`"$devCmd`" >nul && cl /nologo /W4 /WX /Fe:`"$exe`" /Fo:`"$out\\`" `"$source`""
# Newer Visual Studio setups call vswhere.exe from vcvars64.bat but do not put it on PATH.
$env:PATH = (Split-Path $vswhere) + ';' + $env:PATH
cmd.exe /c $compile
if ($LASTEXITCODE -ne 0) { throw "Compiling the native tests failed ($LASTEXITCODE)." }

& $exe
if ($LASTEXITCODE -ne 0) { throw "Native tests failed ($LASTEXITCODE)." }
