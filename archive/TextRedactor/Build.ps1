$ErrorActionPreference = 'Stop'
$compiler = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
if (-not (Test-Path -LiteralPath $compiler)) { throw '.NET Framework 4.x compiler was not found.' }
& $compiler /nologo /target:winexe /optimize+ /platform:anycpu /out:"$PSScriptRoot\TextRedactor.exe" /reference:System.dll /reference:System.Core.dll /reference:System.Drawing.dll /reference:System.Windows.Forms.dll "$PSScriptRoot\TextRedactor.cs"
if ($LASTEXITCODE -ne 0) { throw 'Build failed.' }
Write-Host 'Built TextRedactor.exe'
