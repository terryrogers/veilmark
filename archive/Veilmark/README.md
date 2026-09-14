# Veilmark

A small portable Windows app that transforms text locally. Requires Windows with .NET Framework 4.8 (normally included on Windows 10/11). No installer, Python, PowerShell launch script or network connection is needed to run the executable. Formerly named Text Redactor, it now includes the Veilmark logo in its window, taskbar and executable icon.

## Start

1. Extract the ZIP to a folder, if using the ZIP download.
2. Double-click **Veilmark.exe**.
3. Paste or drag text into the left box. You can also use **Open text file…** or drop one text file onto the left box.
4. Tick the categories to replace. The right box updates automatically.
5. Review the right box, then use **Copy output** or **Save output…**.

The executable is locally built and unsigned.

## Choose what to replace

All eight categories start enabled:

| Category | Automatic detection examples |
| --- | --- |
| Passwords | `password`, `passwd`, `pwd`, `passphrase`, prefixed environment variables, quoted values, long CLI password options, passwords in connection URLs |
| Encryption / private keys | Labelled encryption/private/secret/AES/SSH keys; PEM and PGP private-key blocks |
| API keys | Labelled API/access/subscription keys and API tokens; common AWS, GitHub, OpenAI-style and Slack token patterns |
| Bearer tokens | `Bearer …`, labelled access/refresh/ID/bearer tokens, JWT-shaped strings |
| Other credentials | Labelled usernames, user IDs, client secrets, session IDs/tokens, account keys and recovery codes; Basic authorization; complete Cookie/Set-Cookie header values; usernames in connection URLs |
| Names | Labelled name, full/first/last/given/display/customer/contact name and surname fields |
| Addresses | Labelled address/postcode fields, common English street patterns and UK postcodes |
| Email addresses | Common email address patterns |

Untick **On** to disable a category. A value may still be detected by another enabled category or an exact-match list; for example an email inside a password field is still an email.

**Exact matches…** lets you add literal values for any category, one per line. Use it for names in prose, full addresses, unfamiliar credential formats or anything automatic detection misses. Matching ignores case and respects word boundaries. For a multi-line address, enter each line separately. Double-click a category's **Exact** count to open its list directly.

**Match repeated values** also replaces literal, case-sensitive repetitions of detected values of at least four characters. These repetitions must have word boundaries. This can hide a word used elsewhere innocently; turn it off if needed.

## Replacement text and randomisation

Each row has independent **Mode**, **Replacement text (Redact)** and **Template (Randomise)** fields. Click a cell to edit it. Use **Redact all** or **Randomise all** to set every row's mode without changing category tick boxes.

- **Redact:** use your exact replacement text, such as `[PASSWORD REMOVED]`, `***` or an empty cell to delete the matched value.
- **Randomise:** generate an opaque random alias using your template. These aliases are synthetic identifiers, not usable passwords, keys, real names or real addresses.
- **New random values:** regenerate the session's random aliases.

Available template fields, supported in both columns:

| Field | Meaning |
| --- | --- |
| `{type}` | Category identifier, such as `password` or `email` |
| `{n}` | Number assigned to each distinct category/value pair in this output |
| `{random}` | A 16-character hexadecimal alias derived with a random session key |

Examples: `[hidden-{type}]`, `Person-{random}`, `contact-{random}@example.invalid`, `[ADDRESS-{n}]`.

Keep `{random}` in the Randomise template if you want its value to change when regenerating. A template without it is fixed text or numbering. Repeated identical values in the same category share an alias during the session. `{n}` can change when earlier matches are inserted. Overlapping detections are combined so partially matched sensitive values are not exposed.

## Local data handling and limits

- No network calls, telemetry, input logs, autosaves or saved settings. Source text, exact-match lists, templates and randomisation state stay in the running process and reset when it closes.
- **Clear all text** clears both boxes, their undo histories and all exact-match lists, and regenerates the randomisation key. It keeps your category and template settings for the current session.
- Copying is explicit and uses the Windows clipboard, which can be retained by Windows clipboard history or synchronised by your Windows settings. Clearing the app does not clear that clipboard.
- Saving is explicit and writes only the currently generated output to the path you choose. Review it first: disabled categories and missed detections remain in the output.
- Ordinary managed process memory is used. This is not a secure-memory vault; OS paging or crash dumps are outside the app's control.
- Input is limited to 1,000,000 characters. Files must be UTF-8 or BOM-marked Unicode plain text. Word/PDF/binary documents are not parsed.
- Detection is heuristic, not a guarantee. Unlabelled names and arbitrary passwords or keys cannot reliably be inferred; use exact matches. Street patterns are limited, and comma-separated/multi-line address components may need explicit matching. Encoded/obfuscated data and uncommon credential formats may be missed. This is a text transformation tool, not a format-aware JSON/YAML/XML editor; replacement templates can affect syntax.
- Private-key blocks without an end marker are redacted through the end of the input. A processing error or timeout clears the output and disables Copy/Save. Source text is never used as fallback output.

## Quick acceptance check

1. Click **Load demo**. Expect labelled values on the right to become `[REDACTED_…]`, including both copies of the demo password.
2. Untick **Passwords**. Expect the demo password to appear on the right; tick it again to hide it.
3. Change the password replacement to `***`. Expect `DB_PASSWORD=***`.
4. Click **Randomise all**. Expect aliases; the repeated demo password should have the same alias. Click **New random values** and expect different aliases.
5. Click **Exact matches…**, select **Names**, enter `Morgan Sample`, then **Apply**. Add `Hello Morgan Sample` on the left and expect the name to be replaced.
6. Click **Clear all text**. Expect empty text boxes and zero exact-match counts.

## Source, build and automated checks

`Veilmark.cs` contains the full application and synthetic self-tests. `Build.ps1` compiles with the Windows .NET Framework compiler, with no package downloads. The included `Veilmark.ico` and `Veilmark.png` are embedded in the executable. `Build-Icon.ps1` can regenerate the icon from the logo. See `BRAND.md` for branding assets and the generation prompt.

Open PowerShell in this folder. Run separately:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Build.ps1
```

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Test.ps1
```

The test command uses only built-in synthetic fixtures. It writes `validation\test-results.txt`, `validation\preview.png` and `validation\preview-minimum.png`. Tests cover category detection/toggles, private keys, literal lists, replacement templates, repeat matching, randomisation, overlap protection, unchanged ordinary text, Unicode, limits, cancellation and live UI updates. Self-tests may briefly display their synthetic window.

`preview.png` is a rendering of the supplied app using synthetic demonstration text. It contains no real credentials.
