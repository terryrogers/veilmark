param([string]$ReportFolder = (Join-Path $PSScriptRoot 'validation'), [string]$AppPath = (Join-Path $PSScriptRoot 'Veilmark.exe'))
$ErrorActionPreference = 'Stop'
$app = $AppPath
if (-not (Test-Path -LiteralPath $app)) { throw 'Executable not found. Build first, or run scripts\Test-CI.ps1 for a clean build and test.' }
$ReportFolder = [System.IO.Path]::GetFullPath($ReportFolder)
New-Item -ItemType Directory -Force -Path $ReportFolder | Out-Null
$report = Join-Path $ReportFolder 'test-results.txt'
if (Test-Path -LiteralPath $report) { Remove-Item -LiteralPath $report -Force }
$testProcess = Start-Process -FilePath $app -ArgumentList @('--self-test', ('"' + $ReportFolder + '"')) -WindowStyle Hidden -PassThru -Wait
if ($testProcess.ExitCode -ne 0) { throw 'Self-test failed. See test-results.txt.' }
if (-not (Test-Path -LiteralPath $report)) { throw 'Self-test did not create a fresh report.' }
$result = Get-Content -LiteralPath $report -Raw
Write-Host $result
if ($result -notmatch 'PASS: \d+ synthetic checks\.') { throw 'Self-test report did not confirm success.' }
