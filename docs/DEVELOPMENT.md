# Development And Verification

## Environment

- Windows with .NET Framework 4.8 and its 64-bit framework compiler.
- PowerShell capable of running the provided scripts.
- No package restore, network access or external dependency download is required.

The application build remains offline. Security tooling setup downloads a pinned,
checksum-verified Gitleaks executable from its official GitHub release.

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

`Test.ps1` requires an existing executable and rejects missing executables or
missing success reports. For the same fresh build and test used in CI, run:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\Test-CI.ps1
```

Each invocation creates a unique directory beneath `validation`, builds there,
passes that exact executable to the tests, and reports its SHA-256. It does not
reuse the root executable, restore build caches, package artifacts, or publish a
release. Generated evidence stays local and is not uploaded by CI.

## Local Secret Checks

Run these commands from the repository root on 64-bit Windows with Git for Windows:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\Install-Gitleaks.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\Install-GitHooks.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\Test-Secrets.ps1 -Mode WorkingTree
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\Test-Secrets.ps1 -Mode History
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\Test-DetectionPolicy.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\Test-Baseline.ps1
```

The installer changes only this clone's `core.hooksPath` to `.githooks`; it refuses
to replace another hook configuration or active hook files. Each clone requires
setup. The hooks require Windows PowerShell and the verified local scanner; they
do not download software during commits or pushes. Missing or modified tooling,
scan errors, and detected secrets block the operation.

The pre-commit hook scans the Git index, including partially staged files. The
pre-push hook reads Git's outgoing-ref list and scans each exact outgoing commit;
new refs include the commit's full ancestry, while updates scan the range after the
known remote commit. Non-commit objects and malformed hook input fail closed.
The separate history check scans every local ref and requires a complete clone.
Working-tree scanning includes tracked and non-ignored new files, but excludes
generated untracked data. History scanning still checks tracked files regardless
of `.gitignore`.

Findings are redacted. Inspect affected source locally; do not paste credentials
into issues or CI logs. Secret policy is layered:

- `security/gitleaks-portable.toml` extends Gitleaks defaults with reusable rules
  for credential-bearing connection strings, non-curl authorization headers,
  client and refresh secrets, session credentials, and sensitive key filenames.
- `.gitleaks.toml` adds only Veilmark's exact synthetic fixture exceptions. Each
  exception combines an anchored complete value with one anchored reviewed file.
- An optional private publication-safety configuration is resolved only through
  this clone's `veilmark.publicationSafetyConfig` Git setting. It must be outside
  the repository. The hooks fail closed if a configured private file disappears,
  and GitHub Actions neither contains nor receives that path or its protected
  values.

`Test-DetectionPolicy.ps1` supplies synthetic positive and negative cases for
every portable rule, confirms retained upstream private-key and PKCS#12 coverage,
checks common documentation placeholders, and proves that an allowed value in a
different file or a neighboring value is still blocked. There are no whole-file,
whole-directory, whole-rule, or whole-commit exceptions.

See `docs/SECRET-DETECTION-POLICY.md` for the public-safe rule catalogue,
false-positive controls, regression scope, and remaining detection boundaries.

To undo hook activation after review, remove only the setting installed here:

```powershell
git config --local --unset core.hooksPath
```

Hooks are a developer safeguard and can be bypassed; server-side checks and
required status checks provide separate protection. Secret detection remains
heuristic and does not replace internal-information or publication review.

## CI And Dependency Review

`.github/workflows/ci.yml` runs on pushes, pull requests, manual dispatch, and a
weekly schedule. Every run includes full-history secret scanning and an isolated
Windows build with the existing self-tests. Pull requests also run dependency
review, failing on reported vulnerabilities of any severity. The workflow has
only `contents: read`, does not retain checkout credentials or comment on pull
requests, and pins every external Action to a full commit SHA.

`.github/dependabot.yml` requests weekly GitHub Actions update proposals once
published. Review those proposals; they are not automatically merged. Updating
Gitleaks requires reviewing its release and updating both hashes and the version
in `scripts/gitleaks-lock.json`, then reinstalling and rerunning baseline tests.

There are currently no NuGet, npm, Python, or other application package manifests
to audit. Framework and operating-system security updates belong to Windows
servicing. Dependency review covers supported dependency-graph changes; it does
not audit arbitrary executables, the bundled compiler, or all transitive code
inside pinned Actions. Reassess package auditing when dependencies are added.

Remote Actions execution and dependency-graph availability require validation
after an explicitly approved publication. Making `Secret Scan`, `Clean Build And
Tests`, and `Dependency Review` required for pull requests is a separate remote
branch/ruleset change. CI detects a pushed secret after upload; local hooks and
GitHub push protection are the earlier barriers. No workflow here deploys,
publishes, uploads release assets, or creates releases.

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
