# Changelog

All notable changes to Nitro Boost Linker will be documented in this file.

---

## 1.5.5 — 2026-02-21

### Security Fixes
- **[HIGH] SSRF via DiscordApiBase**: `DiscordApiBase` is a user-configurable field in the
  Oxide config file. A poisoned or tampered config could redirect all HTTP calls to an
  internal network address. `NormalizeConfig()` now validates that the value starts with
  `https://discord.com` and resets it to the default if it does not.
- **[HIGH] PII leakage in debug logs**: When `DebugLogging` was true, full HTTP response
  bodies were written to `oxide/logs/NitroBoostLinker.txt`. Discord API responses for
  guild member and user endpoints can contain email addresses, phone-number verification
  status, and other user PII. Only the HTTP status code is now logged regardless of
  `DebugLogging`.
- **[MEDIUM] Corrupt data file causes NullReferenceException**: Link records loaded from
  `NitroBoostLinker_Links.json` were not validated before being stored in `_linked`.
  A corrupt or manually-edited data file with null `SteamId` or zero `DiscordUserId`
  could cause null-dereference crashes during revalidation or `/nitrostatus`. Records
  are now validated by `LinkRecord.IsValid()` and `PendingRecord.IsValid()` at load time;
  invalid entries are skipped with a log warning.
- **[MEDIUM] Config integer abuse**: `VerificationCodeLength`, `VerificationCodeTTLSeconds`,
  `RevalidationIntervalMinutes`, `RateLimitPerPlayerPerMinute`, and `HttpTimeoutSeconds`
  had no bounds checks. Extreme values could cause allocation spikes, near-zero rate
  limits, or DoS via very long HTTP timeouts. `NormalizeConfig()` clamps all of these
  to sane ranges on load.
- **[LOW] `VerificationCodeLength` clamping missing in `GenerateCode`**: Even though the
  config is now clamped, `GenerateCode` itself also clamps to `[4, MaxCodeLength]` as a
  defense-in-depth measure in case the method is called directly with an unchecked value.

### New Features
- **Localization**: All player-facing strings are now managed through Oxide's `lang`
  system via `lang.RegisterMessages` and `lang.GetMessage`. Four locale files are
  provided: English (`en`), Russian (`ru`), Spanish (`es`), and Latin (`la`).
  Translators can add additional locales by creating
  `oxide/lang/{locale}/NitroBoostLinker.json` with the message keys defined in `Msg`.

### Code Quality
- `NormalizeConfig()` extracted from `LoadConfigTyped()` to centralize all config
  validation and normalization logic.
- `Msg` nested static class introduced to hold all lang message key constants,
  eliminating magic strings throughout command handlers.
- `GetMsg()` helper wraps `lang.GetMessage` with safe `string.Format` fallback.
- `BarkIfHardDisabled` updated to use the localized `HardDisabledNotice` message.
- `CmdNitroDiag` now prints `DiscordApiBase` in the output to aid debugging
  SSRF-related config issues.


---

## 1.5.3 — 2025-02-21

### Security Fixes
- **[CRITICAL] Timer accumulation**: `RepeatConsoleBark()` (now `StartBarkTimer()`) created a new
  permanent 300-second timer every time `ReevaluateHardFailPrereqs()` ran. Because
  `OnPluginLoaded` and `OnPluginUnloaded` both call that method, rapid plugin reloads caused
  unbounded timer growth leading to memory leaks and escalating log spam. All bark timers are
  now tracked in `_barkTimers` and destroyed before new ones are created.
- **[HIGH] Bot token logging warning**: When using `/nitrodiscordbotlink`, the bot token appears
  in Oxide's server console log (all RCON/console commands are logged verbatim). An explicit
  console warning now informs the admin to rotate the token if log access is not restricted.
- **[HIGH] Invalid config JSON**: `oxide/config/NitroBoostLinker.json` contained a comment block
  (`###...###`) at the top, making it invalid JSON. Oxide would fail to parse and auto-regenerate
  this file, silently discarding any manual edits. The sample config is now valid JSON.
- **[MEDIUM] Unbounded `_rate` dictionary**: The rate-limit dictionary retained entries for every
  player who ever connected. Added an hourly cleanup timer (`ScheduleRateCleanup()`) that removes
  entries whose entire timestamp window has expired.
- **[MEDIUM] Code collision in pending lookup**: `GenerateUniqueCode()` now retries up to 10 times
  to find a code not already in `_pendingByCode`, preventing the edge case where a second concurrent
  link attempt would overwrite the first in the code-keyed dictionary while leaving
  `_pendingBySteam` intact, causing inconsistent cleanup.
- **[MEDIUM] Incomplete rich-text stripping**: `StripRichText()` now uses a regex to handle
  parameterized tags like `<color=#FF0000>` and `<size=14>`. The previous `string.Replace()` approach
  silently passed those tags through into log output.
- **[LOW] File case mismatch**: Renamed `Install.md` to `INSTALL.md` and `changelog.md` to
  `CHANGELOG.md` to match `manifest.json` references and avoid broken paths on case-sensitive
  Linux filesystems.
- **[LOW] Version inconsistency**: `.umod.yaml` was at `1.5.0` while the plugin and manifest were
  at `1.5.2`. All three now agree on `1.5.3`.

### Code Quality
- Simplified double-negative admin guard in `CmdNitroDiscordBotLink` for readability.
- Added `DestroyBarkTimers()` call in `Unload()` to clean up on server shutdown.
- Verified `CodeAlphabet` length (32) divides 256 evenly — zero modulo bias in code generation.
- Removed hard-fail messages from `PluginConfig` (they were baked-in strings, not user-configurable
  in practice) and inlined them in `ReevaluateHardFailPrereqs()` to keep the config surface minimal.

---

## 1.5.2 — 2025-12-05

Bumped version and author metadata. Consolidated 1.5.1 improvements:
added `OnServerInitialized`, `OnPluginLoaded`, `OnPluginUnloaded` hooks to handle dependency
load order; improved dependency checking; hardened rate limiting, DM sending, and Discord API
error handling; added `DisplayVersion`/`DisplayAuthor` constants.

---

## 1.5.1 — 2025

Robust load-order handling; refactored config loading/saving; improved help output,
diagnostics formatting, and logging; dynamic booster role resolution by name;
strengthened rate limiting, pending code storage, and data persistence.

---

## 1.5.0 — 2025

Initial public release. Discord↔Steam verification flow via one-time codes.
Grants `NitroBoost` permission and optional Oxide group. Commands: `nitrolink`,
`nitroverify`, `nitrostatus`, `nitroresync`, `nitrodiscordbotlink`, `nitrodiag`.

---

## 1.5.4 — 2025-02-21

### Build Fix
- **[CRITICAL] CS8179: Predefined type 'System.ValueTuple' is not defined or imported.**
  The callback signature `Action<(bool, DateTime?, bool)?>` and the tuple destructuring
  `var (a, b, c) = result.Value` use C# 7.0 value-tuple syntax. On Oxide's uMod build system,
  plugins are compiled against a .NET target below 4.7 without a NuGet package reference, so
  `System.ValueTuple` is not available at compile time. This caused a silent build failure on
  uMod with no displayed error message.
  Fix: replaced the `(bool, DateTime?, bool)?` tuple with a private `BoostCheckResult` class.
  All callback sites updated to use named properties (`IsPremiumBoosting`, `PremiumSince`,
  `HasBoosterRole`) instead of positional tuple elements.
  This was a pre-existing bug in 1.5.2 and carried into 1.5.3.

