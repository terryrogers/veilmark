# Secret Detection Policy

## Policy Layers

1. `security/gitleaks-portable.toml` extends Gitleaks defaults with reusable,
   repository-safe credential rules. It contains no organization, person,
   account, host, path, or project-specific values.
2. A private local configuration contains protected publication identifiers.
   Its location is stored only in local Git configuration under
   `veilmark.publicationSafetyConfig`. It must remain outside the repository and
   is never referenced by GitHub Actions.
3. `.gitleaks.toml` contains Veilmark exceptions. Every exception requires both
   a complete anchored synthetic value and one complete anchored reviewed path.

## Portable Custom Rules

| Rule ID | Coverage Added |
| --- | --- |
| `portable-connection-string-password` | Password or `pwd` fields in key/value connection strings. |
| `portable-credentialed-uri` | Credentials embedded in database and messaging URIs. |
| `portable-authorization-header` | Basic, Bearer, or Token authorization headers outside curl commands. |
| `portable-client-secret` | Generic OAuth and application client secrets, including punctuation-bearing values. |
| `portable-refresh-token` | Generic OAuth refresh tokens. |
| `portable-session-secret` | Session tokens, keys, secrets, IDs, and common session cookies. |
| `portable-sensitive-key-file` | Java keystores and high-risk private-key filenames. |

Gitleaks 8.30.1 already detects provider-specific credentials, generic labelled
high-entropy secrets, private-key blocks, curl credentials, and PKCS#12 `.p12`
and `.pfx` files. Those upstream rules remain enabled. The portable policy does
not duplicate public certificate files such as `.crt` or `.cer`, because those
normally contain public material.

## False-Positive Controls

Portable rules accept only anchored documentation placeholders such as angle-
bracket values, environment-variable references, template expressions, explicit
`YOUR_...`, `REDACTED`, and reserved example markers. Connection-string checks
also recognize a reserved example-domain value and bracketed redaction markers.
These controls do not exempt a file, directory, rule, commit, or arbitrary value.

Project exceptions are finite synthetic test fixtures. Moving an allowed value
to another path, changing one character, or adding a neighboring credential must
still produce a finding.

## Regression Tests

`scripts/Test-DetectionPolicy.ps1` creates disposable fixtures and verifies:

- at least one positive and one negative case for every portable rule;
- common placeholder and documentation examples;
- retained upstream private-key and PKCS#12 coverage;
- exact project exceptions, wrong-file rejection, and neighboring-value
  rejection.

The private policy has a separate test script outside the repository. It tests
every private rule and verifies that local working-tree scanning runs both the
public and private layers. It also proves that missing private configuration and
a private configuration placed inside the repository fail closed.

## Boundaries

Detection is heuristic. It may miss encrypted, encoded, split, generated, novel,
low-entropy, or unlabeled credentials. File-name rules cannot inspect every
binary key-store format. Local hooks can be bypassed, and the private publication
layer is intentionally absent from public CI. Publication still requires review
of exact outgoing content and a separate history check.
