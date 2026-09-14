# Development And Verification

## Environment

- Windows with .NET Framework 4.8 and its 64-bit framework compiler.
- PowerShell capable of running the provided scripts.
- No package restore, network access or external dependency download is required.

## Build

From the repository root:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Build.ps1
```

The script compiles `Veilmark.cs`, embeds `Veilmark.ico` and `Veilmark.png`, and writes `Veilmark.exe` unless an alternate output path is supplied.

## Synthetic Tests

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Test.ps1
```

The test runner launches the executable with its self-test argument, uses synthetic fixtures and isolated settings, and writes generated reports and previews. Clipboard paths use an in-memory substitute; this does not prove integration with the real Windows clipboard.

## Manual Acceptance Boundary

Before a future release is treated as fully accepted, manually verify at minimum:

- real clipboard copying and failure feedback;
- tray minimise, restore, maximised restore and Quit;
- configuration and window-layout persistence under the intended Windows account;
- representative redaction cases and deliberate misses;
- explicit save content and file encoding;
- operation on each Windows edition and architecture claimed as supported.

## Packaging

Local ZIP packages currently contain the executable, source, build scripts, documentation, branding assets, preview and synthetic test result. Existing packages are historical evidence and are intentionally excluded from the first Git commit. A future release workflow should generate a fresh package, manifest and checksum from an approved immutable revision.
