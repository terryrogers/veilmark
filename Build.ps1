param([string]$OutputPath = (Join-Path $PSScriptRoot 'Veilmark.exe'))
$ErrorActionPreference = 'Stop'
$compiler = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
if (-not (Test-Path -LiteralPath $compiler)) { throw '.NET Framework 4.x compiler was not found.' }
$compilerArguments = @(
    '/nologo', '/target:winexe', '/optimize+', '/platform:anycpu',
    "/out:$OutputPath",
    "/win32icon:$PSScriptRoot\Veilmark.ico",
    "/resource:$PSScriptRoot\Veilmark.ico,Veilmark.ico",
    "/resource:$PSScriptRoot\Veilmark.png,Veilmark.png",
    '/reference:System.dll', '/reference:System.Core.dll', '/reference:System.Security.dll', '/reference:System.Drawing.dll', '/reference:System.Windows.Forms.dll',
    "$PSScriptRoot\Veilmark.cs"
)
& $compiler @compilerArguments
if ($LASTEXITCODE -ne 0) { throw 'Build failed.' }
Write-Host 'Built Veilmark.exe'
