# Security And Privacy

## Supported Security Boundary

Veilmark is a local text-transformation utility. It does not claim to guarantee removal of every sensitive value or to provide a secure-memory vault.

## Confirmed Controls

- Text processing occurs locally and the application contains no network integration or telemetry.
- Source and transformed output are not saved automatically.
- User rules, templates, exact-match lists and layout settings are encrypted with Windows DPAPI for the current user.
- Processing failures clear the generated output rather than falling back to the unredacted source.
- Input length is limited to 1,000,000 characters.
- Synthetic tests use synthetic values and an in-memory clipboard substitute.

## Confirmed Limitations

- Detection is heuristic; unfamiliar, unlabelled, encoded or obfuscated values may be missed.
- Clipboard history or synchronisation can retain copied output according to Windows settings.
- Process memory, paging and crash dumps are outside the application's protection boundary.
- Saved output can still contain disabled categories or missed detections and must be reviewed.
- The current executable is unsigned.
- DPAPI protects saved settings from other Windows accounts, not from software already running as the same user.

## Secret Management

- Never add real credentials, tokens, private keys, personal data, encrypted settings files or diagnostic text containing sensitive input to this repository.
- Use synthetic fixtures and reserved domains such as `example.invalid` in tests and documentation.
- Keep `%LOCALAPPDATA%\Veilmark\settings.dat` outside the source tree and outside release packages.
- Treat a detected secret in Git history as an incident: do not push it, disclose only its type and location, and rotate or revoke it where exposure is possible.

## Reporting

No formal public vulnerability-reporting or support channel is established in the available project evidence. Do not infer a response-time or support commitment from this document.
