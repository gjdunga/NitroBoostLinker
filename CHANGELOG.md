# Changelog

All notable changes to Nitro Boost Linker will be documented in this file.

Maintainer: Gabriel Dungan, DunganSoft Technologies.

---

## 5.4.1 -- 2026-06-06

### Changed (uMod submission prep)
- `[Info]` author set to the uMod username `gjdunga` (uMod approval requires the
  author attribute to be the submitting account's username). Display credit
  (Gabriel Dungan, DunganSoft Technologies) is retained in the source header,
  README, manifest, and the in-game diagnostics output.

### Build / tooling
- Added an out-of-server compile-validation chain (`build/NitroBoostLinker.csproj`,
  `tools/fetch-references.{sh,ps1}`, `.github/workflows/compile.yml`, `Makefile`,
  `BUILD.md`) that type-checks the plugin against the real Oxide/Rust/Unity
  assemblies on every push / PR. The csproj excludes the bundled `Oxide.References`
  facade to avoid a `Newtonsoft.Json` `JsonProperty` collision (CS0433).

No gameplay, configuration, hook, or data-format changes. Drop-in compatible with 5.4.0.

## 5.4.0 -- 2026-05-17

> **Versioning note.** This release jumps from 1.5.6 to 5.4.0. The earlier
> 1.x sequence was a mis-versioning by the author; the project now adopts
> 5.4.0 as the corrected version line going forward. No code or data
> migration is required — the bump is purely a numbering correction.


### Project metadata

- Author attribution updated to **Gabriel Dungan of DunganSoft Technologies** across
  the plugin `[Info]` attribute, `DisplayAuthor` constant, header copyright line,
  `manifest.json`, `.umod.yaml`, and `LICENSE`.
- `manifest.json` now lists `CONTRIBUTING.md` and an `oxide_verified_through` field
  noting the most recently verified Oxide.Rust build (2.0.7245).

### Security fixes

- **[MEDIUM] Unsaved bad credentials after a typo in /nitrodiscordbotlink.** The
  previous flow mutated `_config.DiscordBotToken`, `DiscordGuildId`,
  `BoosterRoleId`, and `BoosterRoleName` in-memory *before* validating against
  Discord. On validation failure the disk file was correctly left alone, but the
  running plugin was left using the unsaved bad credentials until the next reload.
  The command now snapshots all four fields, reapplies the snapshot on validation
  failure, and logs that the rollback occurred. An admin typo can no longer leave
  the live plugin in a divergent state from disk.

### Hardening / modernization

- Replaced the obsolete `RNGCryptoServiceProvider` constructor with
  `RandomNumberGenerator.Create()` in `GenerateCode()`. The factory method is
  available on every Oxide-supported .NET target and avoids `SYSLIB0023` warnings
  when the plugin is built against .NET 6+ tooling. Cryptographic behaviour is
  identical (system CSPRNG, 32-character alphabet, zero modulo bias).
- `CmdNitroResync` now snapshots `_linked` with `.ToArray()` before iterating, in
  line with `ScheduleRevalidation`. This makes the iteration safe if any future
  revision mutates the dictionary from inside the resync callback.

### Compatibility

- Re-verified against current Facepunch Rust and Oxide.Rust 2.0.7245. No hook
  signature changes affecting this plugin. Covalence-only design continues to
  insulate the plugin from monthly force-wipe updates.

### Documentation

- `README.md` rewritten as a product-oriented landing page (what it is, why use it,
  feature highlights, requirements table, commands table, configuration table,
  security & privacy summary).
- `INSTALL.md` rewritten as a step-by-step walkthrough covering prerequisites,
  Discord application setup with intents, credential configuration, VIP-kit
  wiring, player flow, admin tooling, config tuning, updating, troubleshooting,
  and uninstalling.
- `CONTRIBUTING.md` added: ground rules, versioning policy, local development
  loop, full test checklist, locale-add procedure, config-key procedure,
  command-add procedure, and security-disclosure process.
- `CHANGELOG.md` (this file) reorganized with a maintainer line and dated 5.4.0
  entry.

---

## 1.5.6 -- 2026-03-30

### Compatibility

- Verified compatible with Oxide 2.0.7182 (Rust Community Update 268). No hook
  signature changes affecting this plugin were introduced between Oxide 2.0.7022
  and 2.0.7182. The plugin uses only Covalence (IPlayer) types and makes no
  direct references to Assembly-CSharp game types.

### Documentation

- Copyright year updated to 2026 in plugin header.
- INSTALL.md corrected to reflect current version (was stale at v1.5.3).
- manifest.json: added oxide_minimum field (2.0.7022) to compatibility block.

---

## 1.5.5 -- 2026-02-21

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

## 1.5.4 -- 2026-02-21

### Build Fix
- **[CRITICAL] CS8179: Predefined type 'System.ValueTuple' is not defined or imported.**
  The callback signature `Action<(bool, DateTime?, bool)?>` and the tuple destructuring
  `var (a, b, c) = result.Value` use C# 7.0 value-tuple syntax. On Oxide's uMod build
  system, plugins are compiled against a .NET target below 4.7 without a NuGet package
  reference, so `System.ValueTuple` is not available at compile time. This caused a
  silent build failure on uMod with no displayed error message.
  Fix: replaced the `(bool, DateTime?, bool)?` tuple with a private `BoostCheckResult`
  class. All callback sites updated to use named properties (`IsPremiumBoosting`,
  `PremiumSince`, `HasBoosterRole`) instead of positional tuple elements.
  This was a pre-existing bug in 1.5.2 and carried into 1.5.3.

---

## 1.5.3 -- 2025-02-21

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
- Verified `CodeAlphabet` length (32) divides 256 evenly -- zero modulo bias in code generation.
- Removed hard-fail messages from `PluginConfig` (they were baked-in strings, not user-configurable
  in practice) and inlined them in `ReevaluateHardFailPrereqs()` to keep the config surface minimal.

---

## 1.5.2 -- 2025-12-05

Bumped version and author metadata. Consolidated 1.5.1 improvements:
added `OnServerInitialized`, `OnPluginLoaded`, `OnPluginUnloaded` hooks to handle dependency
load order; improved dependency checking; hardened rate limiting, DM sending, and Discord API
error handling; added `DisplayVersion`/`DisplayAuthor` constants.

---

## 1.5.1 -- 2025

Robust load-order handling; refactored config loading/saving; improved help output,
diagnostics formatting, and logging; dynamic booster role resolution by name;
strengthened rate limiting, pending code storage, and data persistence.

---

## 1.5.0 -- 2025

Initial public release. Discord/Steam verification flow via one-time codes.
Grants `NitroBoost` permission and optional Oxide group. Commands: `nitrolink`,
`nitroverify`, `nitrostatus`, `nitroresync`, `nitrodiscordbotlink`, `nitrodiag`.
