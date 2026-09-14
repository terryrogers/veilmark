# Roadmap

Roadmap items are deliberately separated by evidence state. No dates are assigned because none are supported.

## Current Work

- **Confirmed:** The initial reviewed source publication is complete.
- **Confirmed:** Keep reconstructed project records and release evidence synchronized.
- **Confirmed:** Prepare, but do not publish, historical tag and GitHub Release mappings where an exact source revision can be established.

## Proposed Next Release Scope

- **Proposed:** Complete manual user acceptance testing of real clipboard interaction, tray behaviour and saved settings on a supported Windows 10 or Windows 11 system.
- **Proposed:** Separate the synthetic test harness from the production source file while preserving the dependency-free build.
- **Proposed:** Add deterministic package generation with a manifest and SHA-256 checksum output.
- **Proposed:** Add automated source scanning and repeatable build verification before each release candidate.

## Proposed Longer-Term Work

- **Proposed:** Assess migration from .NET Framework 4.8 to a currently supported Windows desktop runtime without weakening portability or DPAPI behaviour.
- **Proposed:** Review accessibility, high-DPI rendering and keyboard-only operation.
- **Proposed:** Decide whether code signing is warranted and how signing credentials would be protected.
- **Proposed:** Expand detection tests for uncommon credentials, international addresses and structured-text edge cases without claiming guaranteed redaction.

## Open Decisions

- Licence and copyright ownership are not established in the available evidence.
- Formal support and vulnerability-reporting channels are not established.
- Supported Windows editions and architectures have not been independently compatibility-tested.
- Historical Git tags and GitHub Releases require an exact revision mapping and explicit publication approval.
