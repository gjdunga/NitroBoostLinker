# Nitro Boost Linker

**Reward your Discord Nitro boosters with in-game VIP on your Rust server, automatically.**

Nitro Boost Linker is an Oxide (uMod) plugin for Rust servers. It links a player's Steam
account to their Discord account through a one-time verification code, then continuously
verifies whether that Discord account is actively boosting your guild (`premium_since`)
or holds a configured Booster role. While the player qualifies, the plugin grants the
`NitroBoost` Oxide permission so any other plugin — most commonly **Custom Auto Kits** —
can unlock VIP kits, perks, or commands for them.

- **Maintainer:** Gabriel Dungan, DunganSoft Technologies
- **License:** GPL-3.0
- **Repository:** <https://github.com/gjdunga/NitroBoostLinker>
- **Current release:** **v5.4.4** — see [CHANGELOG.md](CHANGELOG.md)

---

## Why use it

Most "give boosters a kit" workflows on Rust servers rely on someone manually granting
a permission whenever a player boosts the Discord. That breaks the moment a player
stops boosting, joins from a new Steam account, or the admin forgets. Nitro Boost
Linker automates the entire loop:

1. The player runs `/nitrolink <DiscordUserID>` in chat. The bot DMs them a one-time code.
2. The player runs `/nitroverify <CODE>`. The plugin records the Steam ↔ Discord pairing.
3. The plugin polls Discord (default: every 60 minutes) and revokes the `NitroBoost`
   permission the moment the player stops boosting or loses the role.

No web portal to host, no OAuth callback, no extra dependencies beyond standard
Rust-server plugins.

---

## Feature highlights

- **Hard-fail safety.** If Image Library, Rust Kits, Custom Auto Kits, or your Discord
  credentials are missing or invalid, the plugin disables itself, logs a clear error
  every 5 minutes, and tells any admin who pokes it what to fix. No half-working state.
- **Runtime configuration.** `/nitrodiscordbotlink` lets an admin paste a bot token,
  guild ID, and optional booster-role ID/name from console or RCON. Credentials are
  validated against Discord before being written to disk; on validation failure the
  live plugin rolls back to the previous credentials so a typo never leaves the
  running plugin in an unsaved bad state.
- **Built-in diagnostics.** `/nitrodiag` prints a full health report (dependency
  status, configured Discord IDs, link counts, rate-limit settings) and tees it to
  `oxide/logs/NitroBoostLinker.txt`.
- **Localized.** Player-facing strings ship in English, Spanish, Russian, and Latin.
  Add `oxide/lang/<locale>/NitroBoostLinker.json` for any additional locale.
- **Security-reviewed.** SSRF-hardened API base, modulo-bias-free cryptographic code
  generation, ownership-checked verification codes, PII-free debug logging, rate
  limiting with periodic cleanup, and on-disk data validation. See
  [CHANGELOG.md](CHANGELOG.md) for the full audit trail.

---

## Requirements

| Requirement | Where to get it |
|---|---|
| Rust dedicated server | Facepunch (latest release) |
| Oxide.Rust 2.0.7022 or newer (verified through 2.0.7245) | <https://umod.org> |
| [Image Library](https://umod.org/plugins/image-library) | uMod |
| [Rust Kits](https://umod.org/plugins/rust-kits) | uMod |
| [Custom Auto Kits](https://umod.org/plugins/custom-auto-kits) | uMod |
| A Discord application + bot in your guild | <https://discord.com/developers/applications> |

The Discord bot needs the **Server Members Intent** (to read `premium_since` and the
member's role list) and the **Send Messages** permission (to DM verification codes).
No message-content intent is required.

---

## Install in 60 seconds

```text
1. Drop NitroBoostLinker.cs into oxide/plugins/
2. Make sure Image Library, Rust Kits, and Custom Auto Kits are also in oxide/plugins/
3. From server console or RCON:
     nitrodiscordbotlink <BotToken> <GuildId> [BoosterRoleId|RoleName]
4. In Custom Auto Kits, mark your VIP kit as requiring permission "NitroBoost".
```

Full step-by-step walkthrough with screenshots, Discord-side configuration, and
troubleshooting is in [INSTALL.md](INSTALL.md).

---

## Commands

| Command | Audience | Purpose |
|---|---|---|
| `/nitrolink help` | All players | Show the linking walkthrough; works even while hard-disabled |
| `/nitrolink <DiscordUserID>` | All players | Start linking — bot DMs the player a one-time code |
| `/nitroverify <CODE>` | All players | Complete linking with the DM code |
| `/nitrostatus` | All players | Show the caller's current link / boost / last-checked status |
| `/nitroresync [player]` | Admin / console / RCON | Force a re-check for one player or every linked player |
| `/nitrodiscordbotlink <BotToken> <GuildId> [BoosterRoleId\|RoleName]` | Admin / console / RCON | Configure / rotate Discord credentials at runtime |
| `/nitrodiag` | Admin / console / RCON | Full health report; also written to `oxide/logs/NitroBoostLinker.txt` |

All commands are exposed through Oxide's Covalence layer, so they work identically in
in-game chat, on the server console, and over RCON.

---

## Configuration

The first load creates `oxide/config/NitroBoostLinker.json` with sensible defaults.
You typically only edit it to tune behaviour — credentials should go through
`/nitrodiscordbotlink` so they get validated before being saved. Notable keys:

| Key | Default | What it does |
|---|---|---|
| `OxidePermissionName` | `NitroBoost` | The permission granted to qualifying boosters |
| `OxideGroupName` / `AlsoCreateOxideGroup` / `GrantGroupIfExistsOnly` | `NitroBoost` / `true` / `true` | Optional Oxide group membership |
| `TreatPremiumSinceAsBoost` | `true` | Accept a non-null `premium_since` as a qualifying boost |
| `UseBoosterRoleCheck` | `true` | Also accept the configured Booster role |
| `BoosterRoleId` / `BoosterRoleName` | `0` / `""` | The role to honor (ID wins if both are set) |
| `VerificationCodeLength` | `6` | Code length, clamped to `[4, 32]` |
| `VerificationCodeTTLSeconds` | `600` | How long a `/nitroverify` code stays valid |
| `RevalidationIntervalMinutes` | `60` | How often linked players are re-checked |
| `RateLimitPerPlayerPerMinute` | `6` | Sliding-window rate limit per Steam ID |
| `HttpTimeoutSeconds` | `15` | Per-request timeout for Discord API calls (clamped to `[5, 60]`) |
| `DiscordApiBase` | `https://discord.com/api/v10` | Discord REST base; **must** start with `https://discord.com` |
| `DebugLogging` | `false` | Logs HTTP status codes only — response bodies are never logged |

All numeric values are clamped at load time so a hand-edited config can't trigger
allocation spikes, ultra-low rate limits, or runaway HTTP timeouts.

---

## Compatibility notes

- Covalence-only. The plugin makes no direct references to Assembly-CSharp game types,
  so monthly Facepunch Rust force-wipe updates do not require a rebuild.
- Verified against Oxide.Rust 2.0.7245.
- C# language features used compile cleanly on every Oxide-supported .NET target
  (no value tuples, no `record` types, no nullable reference types).

---

## Security & privacy

- The Discord bot token is stored in `oxide/config/NitroBoostLinker.json` in plaintext.
  Restrict file-system access on the host.
- `/nitrodiscordbotlink` accepts the token as a command argument and Oxide logs all
  console / RCON commands verbatim. The plugin prints a warning the first time you
  use it. Rotate the token if console access is not restricted to trusted admins.
- HTTP response bodies are **never** written to logs, even with `DebugLogging` on,
  to avoid leaking Discord user PII (email, MFA status, etc.).
- `DiscordApiBase` is prefix-validated at load to prevent SSRF via a poisoned config.
- See [CHANGELOG.md](CHANGELOG.md) for the dated security-fix log.

To report a security issue privately, see the **Reporting security issues** section in
[CONTRIBUTING.md](CONTRIBUTING.md).

---

## Contributing

Bug reports, pull requests, and translations are welcome. Start with
[CONTRIBUTING.md](CONTRIBUTING.md) — it covers the local build loop, the test
checklist, the locale-file format, and the security-disclosure process.
