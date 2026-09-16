$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$scratch = Join-Path ([IO.Path]::GetTempPath()) ('veilmark-hook-tests-' + [guid]::NewGuid().ToString('N'))
$checks = 0
function Check-Hook([string]$Name, [bool]$ShouldPass) {
    $ErrorActionPreference = 'Continue' # Windows PowerShell wraps native stderr as ErrorRecord.
    $output = & git -C $scratch hook run $Name 2>&1
    $passed = $LASTEXITCODE -eq 0
    $ErrorActionPreference = 'Stop'
    if ($passed -ne $ShouldPass) { throw "Unexpected result from $Name at check $($script:checks + 1); expected success=$ShouldPass." }
    $script:checks++
}
function Stage-Text([string]$Path, [string]$Text) {
    $target = Join-Path $scratch $Path
    New-Item -ItemType Directory -Path (Split-Path -Parent $target) -Force | Out-Null
    [IO.File]::WriteAllText($target, $Text)
    & git -C $scratch add -- $Path
    if ($LASTEXITCODE -ne 0) { throw 'Failed to stage synthetic fixture.' }
}
function Check-PushInput([string]$Path, [bool]$ShouldPass) {
    $ErrorActionPreference = 'Continue'
    $output = & powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File (Join-Path $scratch 'scripts\Test-Secrets.ps1') -Mode Push -Repository $scratch -PushUpdatesPath $Path 2>&1
    $passed = $LASTEXITCODE -eq 0
    $ErrorActionPreference = 'Stop'
    if ($passed -ne $ShouldPass) { throw "Unexpected outgoing-object scan result at check $($script:checks + 1); expected success=$ShouldPass." }
    $script:checks++
}
New-Item -ItemType Directory -Path $scratch | Out-Null
try {
    Copy-Item -LiteralPath (Join-Path $root 'scripts') -Destination $scratch -Recurse
    Copy-Item -LiteralPath (Join-Path $root '.githooks') -Destination $scratch -Recurse
    Copy-Item -LiteralPath (Join-Path $root '.gitleaks.toml') -Destination $scratch
    Copy-Item -LiteralPath (Join-Path $root 'security') -Destination $scratch -Recurse
    $toolDirectory = Join-Path $scratch '.tools\gitleaks'
    New-Item -ItemType Directory -Path $toolDirectory -Force | Out-Null
    $tool = Join-Path $toolDirectory 'gitleaks.exe'
    Copy-Item -LiteralPath (Join-Path $root '.tools\gitleaks\gitleaks.exe') -Destination $tool
    & git -C $scratch init --quiet
    if ($LASTEXITCODE -ne 0) { throw 'Failed to create isolated test repository.' }
    & git -C $scratch config core.hooksPath .githooks
    & git -C $scratch config user.name 'Synthetic Baseline Test'
    & git -C $scratch config user.email 'synthetic@example.invalid'
    Stage-Text 'Veilmark.cs' 'public class Example {}'
    Check-Hook 'pre-commit' $true
    & git -C $scratch commit --quiet -m 'Synthetic benign baseline'
    if ($LASTEXITCODE -ne 0) { throw 'Failed to create isolated benign history fixture.' }
    $benignCommit = (& git -C $scratch rev-parse HEAD).Trim()
    $pushUpdates = Join-Path $scratch 'push-updates.txt'
    [IO.File]::WriteAllText($pushUpdates, "refs/heads/synthetic $benignCommit refs/heads/synthetic $('0' * 40)`n")
    Check-PushInput $pushUpdates $true
    # Construct a nonfunctional token-shaped canary at runtime. Never use a real token.
    $canary = 'ghp_' + ([guid]::NewGuid().ToString('N') + [guid]::NewGuid().ToString('N')).Substring(0, 36)
    Stage-Text 'Veilmark.cs' ('token = "' + $canary + '"')
    Check-Hook 'pre-commit' $false
    # Unstaged removal must not hide a secret still present in the index.
    [IO.File]::WriteAllText((Join-Path $scratch 'Veilmark.cs'), 'public class Example {}')
    Check-Hook 'pre-commit' $false
    $fixture = 'password=' + 'synthetic_' + 'Secret91'
    Stage-Text 'Veilmark.cs' $fixture
    Check-Hook 'pre-commit' $true
    Stage-Text 'Veilmark.cs' ($fixture + '; token="' + $canary + '"')
    Check-Hook 'pre-commit' $false
    Stage-Text 'Veilmark.cs' 'public class Example {}'
    Stage-Text 'archive/Veilmark-1.2.1/Veilmark.cs' ('token="' + $canary + '"')
    Check-Hook 'pre-commit' $false
    Stage-Text 'archive/Veilmark-1.2.1/Veilmark.cs' 'public class Example {}'
    Stage-Text 'unexpected.txt' $fixture
    Check-Hook 'pre-commit' $false
    Stage-Text 'unexpected.txt' 'benign'
    Move-Item -LiteralPath $tool -Destination ($tool + '.saved')
    Check-Hook 'pre-commit' $false
    Check-Hook 'pre-push' $false
    [IO.File]::WriteAllText($tool, 'tampered scanner')
    Check-Hook 'pre-commit' $false
    Check-Hook 'pre-push' $false
    Remove-Item -LiteralPath $tool
    Move-Item -LiteralPath ($tool + '.saved') -Destination $tool
    Check-Hook 'pre-commit' $true
    Stage-Text 'Veilmark.cs' ('token = "' + $canary + '"')
    & git -C $scratch commit --quiet --no-verify -m 'Synthetic secret history fixture'
    if ($LASTEXITCODE -ne 0) { throw 'Failed to create isolated secret history fixture.' }
    $secretCommit = (& git -C $scratch rev-parse HEAD).Trim()
    [IO.File]::WriteAllText($pushUpdates, "refs/heads/synthetic $secretCommit refs/heads/synthetic $benignCommit`n")
    Check-PushInput $pushUpdates $false
    $missing = Join-Path $scratch 'missing.exe'
    $ErrorActionPreference = 'Continue'
    $output = & powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File (Join-Path $root 'Test.ps1') -AppPath $missing -ReportFolder (Join-Path $scratch 'reports') 2>&1
    $ErrorActionPreference = 'Stop'
    if ($LASTEXITCODE -eq 0 -or (Test-Path -LiteralPath $missing)) { throw 'Missing executable did not fail closed.' }
    $checks++
    Write-Host "PASS: $checks baseline checks. No Veilmark commits or pushes performed."
} finally {
    if ([IO.Path]::GetFullPath($scratch).StartsWith([IO.Path]::GetFullPath([IO.Path]::GetTempPath()), [StringComparison]::OrdinalIgnoreCase)) {
        Remove-Item -LiteralPath $scratch -Recurse -Force
    }
}
