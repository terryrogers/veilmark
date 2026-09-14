# Project History And Current Position

## Classification

- **Confirmed:** Project name and product name: Veilmark.
- **Confirmed:** Former product name: Text Redactor.
- **Confirmed:** Primary category: Software Development.
- **Confirmed:** Principal deliverable: a portable Windows desktop executable for local text redaction and configurable pseudonymisation.
- **Inferred:** The intended primary user is the project owner or another Windows user preparing text for safer sharing or troubleshooting.

## Evidence-Supported Timeline

All preserved artifacts are dated 2 September 2026. These timestamps prove local file state, not external publication.

1. **Confirmed:** Text Redactor prototype — version metadata `0.0.0.0`; 68 synthetic checks.
2. **Confirmed:** Veilmark 1.1.0 — renamed product and added branding; 68 synthetic checks.
3. **Confirmed:** Veilmark 1.1.1 — corrected layout and added the On-header toggle; 78 synthetic checks.
4. **Confirmed:** Veilmark 1.2.0 — added DPAPI-protected settings and dialog fixes; 100 synthetic checks.
5. **Confirmed:** Veilmark 1.2.1 — expanded configuration and layout persistence; 110 synthetic checks.
6. **Confirmed:** Veilmark 1.3.0 — added tray controls, status feedback and full-output click-to-copy; 125 synthetic checks.
7. **Confirmed:** On 14 September 2026 the project history and documentation were reconstructed from retained local evidence and committed to source control.

## Current Functionality

The current source supports eight detection categories, per-category enablement and modes, custom replacement templates, randomised aliases, exact-match lists, repeated-value matching, bounded asynchronous processing, plain-text file input, drag and drop, explicit save, clipboard copy, encrypted preferences, retained layout, tray behaviour and status feedback.

## Known Limitations And Risks

- Heuristic detection cannot guarantee complete removal of sensitive data.
- The executable is unsigned.
- Real clipboard behaviour was not covered by the synthetic test substitute.
- Compatibility beyond the stated Windows/.NET Framework environment is not independently evidenced.
- Historical packages predate Git history, so arbitrary tags must not be attached to the reconstruction commit.
- Licence, copyright ownership, formal support and vulnerability-reporting decisions are unresolved.

## Evidence Classification Rules

- **Confirmed** statements are directly supported by retained source, documentation, binary metadata, package contents, hashes or validation records.
- **Inferred** statements are strongly suggested by evidence but not directly recorded.
- **Proposed** statements are future recommendations and are recorded in the roadmap rather than rewritten as history.
