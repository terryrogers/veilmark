param([string]$ReportFolder = (Join-Path $PSScriptRoot 'validation'))
$ErrorActionPreference = 'Stop'
$app = Join-Path $PSScriptRoot 'TextRedactor.exe'
if (-not (Test-Path -LiteralPath $app)) { & (Join-Path $PSScriptRoot 'Build.ps1') }
$ReportFolder = [System.IO.Path]::GetFullPath($ReportFolder)
New-Item -ItemType Directory -Force -Path $ReportFolder | Out-Null
$testProcess = Start-Process -FilePath $app -ArgumentList @('--self-test', ('"' + $ReportFolder + '"')) -WindowStyle Hidden -PassThru -Wait
Get-Content -LiteralPath (Join-Path $ReportFolder 'test-results.txt')
if ($testProcess.ExitCode -ne 0) { throw 'Self-test failed. See test-results.txt.' }
