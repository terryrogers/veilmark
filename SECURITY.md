# Security Policy

## Supported Versions

| Release | Security Maintenance |
| --- | --- |
| Latest Published Release | Eligible for security fixes where a safe and maintainable correction is available. |
| Earlier Releases | Not routinely supported; upgrade to the latest published release before requesting a fix. |
| Unreleased Code | Accepted for early reporting but is not a supported release. |

## Reporting A Vulnerability

Use the repository's **Security** tab to submit a private vulnerability report when that option is available. If it is unavailable, contact a repository maintainer through an existing authorized private channel and ask for a private reporting route.

Do not open a public issue, discussion, or pull request containing vulnerability details, credentials, personal data, internal infrastructure, sensitive reproduction data, or exploit material.

Include:

- the affected product and version or commit;
- the affected component and environment;
- a concise impact assessment;
- reproducible steps or a minimal proof of concept;
- relevant logs or screenshots with secrets and personal data removed; and
- any known workaround or suggested remediation.

## Response Process

Maintainers will acknowledge and triage reports as soon as reasonably practicable. They may request more evidence, attempt to reproduce the issue, assess affected versions, prepare and validate a correction, and coordinate publication of an advisory or fixed release. No response or remediation deadline is promised unless a project-specific agreement states one.

## Coordinated Disclosure

Keep the report and supporting material private until maintainers confirm that disclosure is safe. Allow reasonable time for triage, correction, validation, and affected-user communication. Maintainers will credit reporters when requested and appropriate, subject to confidentiality and safety constraints.

## Security Updates

Security corrections are published through the repository's normal release or advisory channels. Release notes will describe user action where disclosure is safe. Users should run the latest supported release and apply security updates promptly.

## Scope

Reports are in scope when they demonstrate a security impact in source, packaged artifacts, supported integrations, authentication or authorization, data handling, update or installation behavior, or documented deployment defaults maintained by this repository.

Reports are normally out of scope when they concern unsupported versions, social engineering, denial-of-service testing against systems without authorization, automated findings without a reproducible impact, third-party services outside this project's control, or configuration that contradicts the documented security requirements.

## Safe Harbour

Good-faith research should avoid privacy violations, data loss, service disruption, persistence, lateral movement, and access beyond what is necessary to demonstrate the issue. Follow applicable law and test only systems you own or are explicitly authorized to assess.

## Confidentiality

Never include credentials, tokens, private keys, personal data, internal addresses, private paths, or confidential infrastructure details in a public report or artifact. Share only the minimum necessary evidence through the approved private route.

## Project-Specific Security Guidance

### Supported Security Boundary

Veilmark is a local text-transformation utility. It does not claim to guarantee removal of every sensitive value or to provide a secure-memory vault.

### Confirmed Controls

- Text processing occurs locally and the application contains no network integration or telemetry.
- Source and transformed output are not saved automatically.
- User rules, templates, exact-match lists and layout settings are encrypted with Windows DPAPI for the current user.
- Processing failures clear the generated output rather than falling back to the unredacted source.
- Input length is limited to 1,000,000 characters.
- Synthetic tests use synthetic values and an in-memory clipboard substitute.

### Confirmed Limitations

- Detection is heuristic; unfamiliar, unlabelled, encoded or obfuscated values may be missed.
- Clipboard history or synchronisation can retain copied output according to Windows settings.
- Process memory, paging and crash dumps are outside the application's protection boundary.
- Saved output can still contain disabled categories or missed detections and must be reviewed.
- The current executable is unsigned.
- DPAPI protects saved settings from other Windows accounts, not from software already running as the same user.

### Secret Management

- Never add real credentials, tokens, private keys, personal data, encrypted settings files or diagnostic text containing sensitive input to this repository.
- Use synthetic fixtures and reserved domains such as `example.invalid` in tests and documentation.
- Keep `%LOCALAPPDATA%\Veilmark\settings.dat` outside the source tree and outside release packages.
- Treat a detected secret in Git history as an incident: do not push it, disclose only its type and location, and rotate or revoke it where exposure is possible.
