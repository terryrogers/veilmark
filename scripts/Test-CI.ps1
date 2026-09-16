$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
# A unique, previously nonexistent directory avoids stale executables and reports
# without deleting developer output. No build cache or release packaging is used.
$run = Join-Path $root ('validation\ci-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $run | Out-Null
$app = Join-Path $run 'Veilmark.exe'
& (Join-Path $root 'Build.ps1') -OutputPath $app
if (-not (Test-Path -LiteralPath $app)) { throw 'Build did not create the expected executable.' }
$hash = (Get-FileHash -LiteralPath $app -Algorithm SHA256).Hash
& (Join-Path $root 'Test.ps1') -AppPath $app -ReportFolder (Join-Path $run 'reports')
if ((Get-FileHash -LiteralPath $app -Algorithm SHA256).Hash -ne $hash) { throw 'Executable changed during testing.' }
Write-Host "Tested fresh executable SHA256: $hash"
