# Changelog

All notable changes to Nitro Boost Linker will be documented in this file.

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
