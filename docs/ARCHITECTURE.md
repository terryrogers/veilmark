# Architecture

## Overview

**Confirmed:** Veilmark is a dependency-free C# Windows Forms application targeting .NET Framework 4.8. The production application and synthetic self-tests currently share `Veilmark.cs`.

## Main Components

- `Rule` defines the eight configurable detection categories and their replacement modes.
- `Preferences` and `WindowPreferences` hold rule and layout state.
- `SettingsStore` serialises settings and protects them with Windows DPAPI for the current user.
- `Engine` detects candidate values, resolves overlaps, performs replacement or pseudonymisation and enforces cancellation and size limits.
- `MainForm` owns the application workflow, asynchronous processing, file input, output review, clipboard/save actions, settings persistence, tray icon and status feedback.
- The self-test path exercises engine, persistence and UI behaviours with synthetic data and isolated settings.

## Data Flow

1. The user pastes, drops or opens supported plain text.
2. `MainForm` captures the active rules and starts cancellable processing.
3. `Engine` detects values, combines overlapping matches and applies redaction or session-scoped random aliases.
4. `MainForm` displays the generated output and replacement counts.
5. The user reviews the output, then explicitly copies or saves it.
6. Configuration and layout changes are separately encrypted and persisted; source and generated output are not persisted automatically.

## Trust Boundaries

- Untrusted input is bounded to 1,000,000 characters and parsed only as supported text encodings.
- DPAPI-protected settings cross the process/disk boundary under the current Windows account.
- Explicit save crosses into a user-selected file location.
- Explicit copy crosses into the Windows clipboard, which may have history or synchronisation enabled.
- Build output is unsigned and therefore has no publisher identity assurance.

## Dependencies

**Confirmed:** The build uses the Windows .NET Framework compiler and only framework assemblies: `System`, `System.Core`, `System.Security`, `System.Drawing` and `System.Windows.Forms`. No package download or external runtime service is required.
