# Veilmark

A small portable Windows app that transforms text locally. Requires Windows with .NET Framework 4.8 (normally included on Windows 10/11). No installer, Python, PowerShell launch script or network connection is needed to run the executable. Formerly named Text Redactor, it now includes the Veilmark logo in its window, taskbar and executable icon.

Current version: **1.3.0**.

The source tree was reconstructed as its first Git history from retained local evidence. Historical packages remain local and are not GitHub Releases unless a later, explicitly approved tag and release mapping is published.

This version adds minimise-to-tray, a tray menu with Open/Quit, a bottom status bar, and full-output copying when you click the right-hand text box. Existing configuration retention and saved settings remain supported. Earlier builds are preserved under `archive`; intermediate files are under `work`. Current validation evidence is under `validation\1.3.0`, and the portable ZIP is under `releases`.

## Start

1. Extract the ZIP to a folder, if using the ZIP download.
2. Double-click **Veilmark.exe**.
3. Paste or drag text into the left box. You can also use **Open text file…** or drop one text file onto the left box.
4. Tick the categories to replace. The right box updates automatically.
5. Review the right box, then click inside it to copy its full contents. The status bar confirms the copied character count. **Copy output** and **Save output…** are also available.

The executable is locally built and unsigned.

## Tray and status bar

- Click the window's **Minimise** button to hide it in the Windows system tray. Text stays in memory and your settings are saved. If the icon is hidden by Windows, click the up-arrow beside the clock to find it.
- Double-click the Veilmark tray icon, or right-click it and choose **Open Veilmark**, to restore the window. A maximized window restores maximized.
- Right-click the tray icon and choose **Quit** to save settings and exit. The window's **X** button also exits; only Minimise sends it to the tray.
- The bottom status bar reports processing, copying and save outcomes. The right side shows the replacement count and source character count; hover over it for counts by category.
- A left click in the output text area copies the entire generated output, even if only part is selected. Right-clicking does not automatically copy. The copy button follows the same full-output behavior.
- Empty or unfinished output is not copied, so those clicks leave the clipboard unchanged. Clipboard failures appear in the status bar and can be retried by clicking the output again.

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

Untick **On** to disable a category. Click the **On** column header to turn all categories off when every row is selected, or to turn all categories on if any row is off. This leaves modes, replacement templates and exact-match lists unchanged. A value may still be detected by another enabled category or an exact-match list; for example an email inside a password field is still an email.

**Exact matches…** lets you add literal values for any category, one per line. Use it for names in prose, full addresses, unfamiliar credential formats or anything automatic detection misses. Matching ignores case and respects word boundaries. For a multi-line address, enter each line separately. Double-click a category's **Exact** count to open its list directly. **Apply** saves all edited lists encrypted for your Windows account; **Cancel** discards edits in that dialog.

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

- No network calls, telemetry or input logs. Source and output text are never saved automatically. Randomisation keys remain in memory and change on each launch.
- Category tick boxes, Redact/Randomise modes, both template columns, exact-match lists and the repeated-value option are saved automatically and restored on launch. The file is encrypted using Windows DPAPI for the current account; no plaintext settings or exact-match files are written. This protects stored data from other accounts, not from software already running as you.
- The main window's size, position and maximized state, the text-panel divider, all rules-column widths, and the exact-match window's size, position and last selected category are also retained. Off-screen window positions are brought back onto an available display. Minimizing before closing does not make the next launch start minimized.
- Configuration edits are saved after a short pause and flushed on normal close, including the cell currently being edited. Exact-match edits are saved by **Apply**; **Cancel** discards list edits while remembering the dialog's layout and category selection. Source/output text and generated random aliases are not restored.
- Settings are stored at `%LOCALAPPDATA%\Veilmark\settings.dat` (normally `C:\Users\<user>\AppData\Local\Veilmark\settings.dat`). They are separate from the portable application and its ZIP. Other Windows accounts have independent settings; copying the encrypted file to a different account is not a supported migration method.
- **Clear all text** clears both boxes and their undo histories and regenerates the randomisation key. It retains saved rules, templates and exact-match lists. To remove exact matches, open **Exact matches…**, choose the category, select/delete the contents and click **Apply**.
- Clicking the output text area or **Copy output** writes to the Windows clipboard, which can be retained by Windows clipboard history or synchronised by your Windows settings. Clearing the app does not clear that clipboard.
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
6. Click **Clear all text**. Expect empty source/output boxes; the exact-match counts stay unchanged.
7. Resize the main and exact-match windows, drag the text-panel divider, and resize a rules column. Close and reopen Veilmark. Expect all configuration choices and the layout to be restored, with empty source/output boxes. An edit in a replacement cell should also survive closing immediately.
8. Load the demo, then click inside the output. Expect **Copied … characters to the clipboard** in the status bar. Paste into a blank text document to confirm that the full generated output was copied.
9. Minimise Veilmark. Expect its taskbar window to disappear and its tray icon to appear. Double-click the tray icon to restore it, then minimise again and choose **Quit** from its right-click menu. Expect Veilmark to exit and the tray icon to disappear.

## Settings recovery or reset

If saved settings cannot be decrypted or parsed, Veilmark leaves the file untouched, starts with defaults, and warns that saving is disabled for that launch. If a save fails, it warns you and retries on close; the existing saved file is preserved.

To intentionally reset settings or recover from an unreadable file:

1. Close all Veilmark windows.
2. In File Explorer, enter `%LOCALAPPDATA%\Veilmark` in the address bar.
3. Rename `settings.dat` to `settings.dat.backup` (choose a different backup filename if that one exists).
4. Reopen Veilmark. Defaults will be active; new changes create a new encrypted settings file.

## Source, build and automated checks

`Veilmark.cs` contains the full application and synthetic self-tests. `Build.ps1` compiles with the Windows .NET Framework compiler, with no package downloads. The included `Veilmark.ico` and `Veilmark.png` are embedded in the executable. `Build-Icon.ps1` can regenerate the icon from the logo. See `BRAND.md` for branding assets and the generation prompt.

Open PowerShell in this folder. Run separately:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Build.ps1
```

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Test.ps1
```

The test command uses only built-in synthetic fixtures and isolated settings files; it does not read or modify your saved preferences. Clipboard-copy tests use an in-memory substitute and do not alter your Windows clipboard. It writes its report and main/dialog previews under `validation` by default. The supplied 1.3.0 validation run passed 125 checks, including tray minimise/Open/double-click/Quit, normal/maximized restoration, full-output click copying, copy confirmations and failures, stale/empty output guards, status-bar visibility, and all prior persistence and redaction checks. Self-tests may briefly display synthetic windows and their tray icon.

`preview.png` is a rendering of the supplied app using synthetic demonstration text. It contains no real credentials.

## Project documentation

- [CHANGELOG.md](CHANGELOG.md) reconstructs the evidence-supported release history.
- [ROADMAP.md](ROADMAP.md) separates current work from proposed future improvements.
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) describes the application structure and data flow.
- [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) covers building, testing and packaging boundaries.
- [docs/PROJECT_HISTORY.md](docs/PROJECT_HISTORY.md) records confirmed history, inferences and proposals.
- [docs/RELEASE_EVIDENCE.md](docs/RELEASE_EVIDENCE.md) inventories locally retained packages and hashes.
- [SECURITY.md](SECURITY.md) records security, privacy and secret-management guidance without claiming a support commitment.

No licence, copyright owner, compatibility guarantee or formal support policy has been established in the available evidence.
