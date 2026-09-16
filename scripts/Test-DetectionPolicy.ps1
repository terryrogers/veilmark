$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$scanner = Join-Path $root '.tools\gitleaks\gitleaks.exe'
$portableConfig = Join-Path $root 'security\gitleaks-portable.toml'
$projectConfig = Join-Path $root '.gitleaks.toml'
$scratch = Join-Path ([IO.Path]::GetTempPath()) ('veilmark-policy-tests-' + [guid]::NewGuid().ToString('N'))
$checks = 0

function Invoke-Case {
    param(
        [string]$Name,
        [string]$RuleId,
        [string]$RelativePath,
        [string]$Content,
        [bool]$ShouldFind,
        [string]$Config = $portableConfig
    )
    $caseRoot = Join-Path $scratch $Name
    $target = Join-Path $caseRoot $RelativePath
    New-Item -ItemType Directory -Path (Split-Path -Parent $target) -Force | Out-Null
    [IO.File]::WriteAllText($target, $Content, [Text.UTF8Encoding]::new($false))
    $report = Join-Path $scratch ($Name + '.json')
    $ErrorActionPreference = 'Continue'
    & $scanner '--config' $Config '--enable-rule' $RuleId '--redact=100' '--no-banner' '--no-color' '--report-format' 'json' '--report-path' $report 'dir' $caseRoot 2>&1 | Out-Null
    $exitCode = $LASTEXITCODE
    $ErrorActionPreference = 'Stop'
    $findings = if (Test-Path -LiteralPath $report) { @(Get-Content -LiteralPath $report -Raw | ConvertFrom-Json) } else { @() }
    $matching = @($findings | Where-Object RuleID -eq $RuleId)
    $found = $matching.Count -gt 0
    if ($found -ne $ShouldFind) { throw "Unexpected detection result for $Name ($RuleId); expected finding=$ShouldFind." }
    if ($ShouldFind -and $exitCode -ne 1) { throw "Expected Gitleaks finding exit code for $Name." }
    if (-not $ShouldFind -and $exitCode -ne 0) { throw "Unexpected Gitleaks error for negative case $Name." }
    $script:checks++
}

function Invoke-ProjectExceptionSet {
    param([bool]$ShouldPass, [string]$Name, [hashtable]$Files)
    $caseRoot = Join-Path $scratch $Name
    foreach ($entry in $Files.GetEnumerator()) {
        $target = Join-Path $caseRoot $entry.Key
        New-Item -ItemType Directory -Path (Split-Path -Parent $target) -Force | Out-Null
        [IO.File]::WriteAllText($target, $entry.Value, [Text.UTF8Encoding]::new($false))
    }
    Copy-Item -LiteralPath $projectConfig -Destination (Join-Path $caseRoot '.gitleaks.toml')
    New-Item -ItemType Directory -Path (Join-Path $caseRoot 'security') -Force | Out-Null
    Copy-Item -LiteralPath $portableConfig -Destination (Join-Path $caseRoot 'security\gitleaks-portable.toml')
    $report = Join-Path $scratch ($Name + '.json')
    Push-Location $caseRoot
    try {
        $ErrorActionPreference = 'Continue'
        & $scanner '--config' '.gitleaks.toml' '--redact=100' '--no-banner' '--no-color' '--report-format' 'json' '--report-path' $report 'dir' '.' 2>&1 | Out-Null
        $passed = $LASTEXITCODE -eq 0
        $ErrorActionPreference = 'Stop'
    } finally { Pop-Location }
    $findings = if (Test-Path -LiteralPath $report) { @(Get-Content -LiteralPath $report -Raw | ConvertFrom-Json) } else { @() }
    if ($passed -ne $ShouldPass) {
        $ruleIds = @($findings | ForEach-Object RuleID | Sort-Object -Unique) -join ', '
        throw "Unexpected project-exception result for $Name; expected success=$ShouldPass; rules=$ruleIds."
    }
    $script:checks++
}

if (-not (Test-Path -LiteralPath $scanner -PathType Leaf)) { throw 'Install the pinned Gitleaks binary first.' }
New-Item -ItemType Directory -Path $scratch | Out-Null
try {
    # Construct all canaries at runtime so the repository never contains a
    # complete token-shaped value outside the exact application fixtures.
    $canary = ('Q7m~2Lp+' + '9Vx=4Ka.' + 'R8t_6Nz-' + '3Hs5Df0')
    $placeholders = @('<TOKEN>', '${ACCESS_TOKEN}', '{{ secrets.ACCESS_TOKEN }}', 'YOUR_ACCESS_TOKEN', 'REDACTED', 'EXAMPLE_ONLY')

    Invoke-Case 'connection-positive' 'portable-connection-string-password' 'app.config' ('Server=db.example.invalid;Database=app;User Id=svc;Password=' + $canary) $true
    Invoke-Case 'connection-negative' 'portable-connection-string-password' 'docs/example.txt' (($placeholders | ForEach-Object { 'Server=db.example.invalid;Password=' + $_ }) -join "`n") $false

    Invoke-Case 'uri-positive' 'portable-credentialed-uri' 'settings.txt' ('postgresql://service:' + $canary + '@db.example.invalid/app') $true
    Invoke-Case 'uri-negative' 'portable-credentialed-uri' 'docs/example.txt' (($placeholders | ForEach-Object { 'postgresql://service:' + $_ + '@db.example.invalid/app' }) -join "`n") $false

    Invoke-Case 'authorization-positive' 'portable-authorization-header' 'request.http' ('Authorization: Bearer ' + $canary) $true
    Invoke-Case 'authorization-basic-positive' 'portable-authorization-header' 'basic.http' ('Authorization: Basic ' + $canary) $true
    Invoke-Case 'authorization-negative' 'portable-authorization-header' 'docs/example.http' (($placeholders | ForEach-Object { 'Authorization: Bearer ' + $_ }) -join "`n") $false

    Invoke-Case 'client-positive' 'portable-client-secret' 'oauth.env' ('client_secret=' + $canary) $true
    Invoke-Case 'client-negative' 'portable-client-secret' 'docs/example.env' (($placeholders | ForEach-Object { 'client_secret=' + $_ }) -join "`n") $false

    Invoke-Case 'refresh-positive' 'portable-refresh-token' 'oauth.env' ('refresh_token=' + $canary) $true
    Invoke-Case 'refresh-negative' 'portable-refresh-token' 'docs/example.env' (($placeholders | ForEach-Object { 'refresh_token=' + $_ }) -join "`n") $false

    Invoke-Case 'session-positive' 'portable-session-secret' 'headers.txt' ('Cookie: sessionid=' + $canary) $true
    Invoke-Case 'session-token-positive' 'portable-session-secret' 'session.env' ('session_token=' + $canary) $true
    Invoke-Case 'session-negative' 'portable-session-secret' 'docs/example.txt' (($placeholders | ForEach-Object { 'session_token=' + $_ }) -join "`n") $false

    Invoke-Case 'key-file-positive' 'portable-sensitive-key-file' 'keys/application.jks' 'synthetic binary placeholder' $true
    Invoke-Case 'key-name-positive' 'portable-sensitive-key-file' 'keys/server.key' 'synthetic key placeholder' $true
    Invoke-Case 'key-file-negative' 'portable-sensitive-key-file' 'certificates/public.crt' 'public certificate documentation' $false
    Invoke-Case 'public-key-negative' 'portable-sensitive-key-file' 'keys/server-public.key' 'public key documentation' $false

    # Confirm the relevant upstream rules remain enabled rather than duplicating them.
    $privateKeyFixture = "-----BEGIN PRIVATE KEY-----`n" + ('QUJD' * 20) + "`n-----END PRIVATE KEY-----"
    Invoke-Case 'builtin-private-key-positive' 'private-key' 'keys/material.txt' $privateKeyFixture $true
    Invoke-Case 'builtin-pkcs12-positive' 'pkcs12-file' 'keys/application.pfx' 'synthetic binary placeholder' $true

    # Each exception is one exact synthetic value in one exact reviewed file.
    $syntheticCredential = 'password=' + 'synthetic_' + 'Secret91'
    $reviewed = @{
        'Veilmark.cs' = $syntheticCredential
        'archive/TextRedactor/TextRedactor.cs' = $syntheticCredential
        'archive/Veilmark/Veilmark.cs' = $syntheticCredential
        'archive/Veilmark-1.1.1/Veilmark.cs' = $syntheticCredential
        'archive/Veilmark-1.2.0/Veilmark.cs' = $syntheticCredential
        'archive/Veilmark-1.2.1/Veilmark.cs' = $syntheticCredential
    }
    Invoke-ProjectExceptionSet $true 'project-exact-exceptions' $reviewed
    Invoke-ProjectExceptionSet $false 'project-wrong-file' @{ 'docs/example.txt' = $syntheticCredential }
    Invoke-ProjectExceptionSet $false 'project-neighbor-value' @{ 'Veilmark.cs' = ($syntheticCredential + 'X') }

    Write-Host "PASS: $checks detection-policy checks across seven portable rules, two retained upstream rules, placeholders, and exact project exceptions."
} finally {
    $scratchFull = [IO.Path]::GetFullPath($scratch)
    $tempFull = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
    if ($scratchFull.StartsWith($tempFull, [StringComparison]::OrdinalIgnoreCase)) {
        Remove-Item -LiteralPath $scratchFull -Recurse -Force
    }
}

# Expected positive fixtures make Gitleaks return 1 during this test suite.
# Prevent that handled native exit code from becoming the script's process exit
# code after every assertion has passed.
exit 0
