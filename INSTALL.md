# Installation Guide

This guide walks you through installing **Nitro Boost Linker v5.4.2** on a Rust
dedicated server running Oxide (uMod). Plan on ~10 minutes if you already have a
Discord application; ~20 minutes if you need to create one from scratch.

> Author: Gabriel Dungan, DunganSoft Technologies — MIT licensed.

---

## What you'll end up with

By the end of this guide:

- Players type `/nitrolink <DiscordUserID>` in chat and get a DM from your bot with a
  code.
- They type `/nitroverify <CODE>` and the plugin grants them the Oxide permission
  `NitroBoost` while they are boosting your guild or hold the Booster role.
- A separate plugin (typically **Custom Auto Kits**) hands out a VIP kit to anyone
  who holds `NitroBoost`.
- The plugin polls Discord automatically and revokes `NitroBoost` the moment the
  player stops qualifying.

---

## 1. Prerequisites

| Requirement | Minimum | Recommended |
|---|---|---|
| Rust dedicated server | Current Facepunch release | Current Facepunch release |
| Oxide.Rust | 2.0.7022 | 2.0.7245 or newer |
| [Image Library](https://umod.org/plugins/image-library) | Latest | Latest |
| [Rust Kits](https://umod.org/plugins/rust-kits) | Latest | Latest |
| [Custom Auto Kits](https://umod.org/plugins/custom-auto-kits) | Latest | Latest |
| Discord application + bot | — | Bot must be a member of your guild |

If any of the three plugin dependencies is missing, Nitro Boost Linker hard-disables
itself, logs the missing dependency every 5 minutes, and tells admins exactly what
is wrong. There is no half-loaded state.

---

## 2. Copy the plugin into your server

Drop these files into the matching paths under your server's Oxide installation:

```text
oxide/plugins/NitroBoostLinker.cs
oxide/lang/en/NitroBoostLinker.json
oxide/lang/ru/NitroBoostLinker.json
oxide/lang/es/NitroBoostLinker.json
oxide/lang/la/NitroBoostLinker.json
```

The `oxide/config/NitroBoostLinker.json` file in this repository is a **sample only**
— Oxide generates the live config on first load. Use it as a reference when you want
to hand-tune values that have no command-line equivalent.

Reload, or restart, the server. The plugin will appear as hard-disabled until you
complete the next two steps.

---

## 3. Create the Discord bot

1. Open the [Discord Developer Portal](https://discord.com/developers/applications)
   and click **New Application**. Name it whatever you like.
2. Under **Bot**, click **Reset Token** to reveal the bot token. Copy it now — you
   cannot view it again later.
3. On the same **Bot** page, enable **Server Members Intent**. The plugin needs this
   to read `premium_since` and the member's role list.
4. Under **OAuth2 → URL Generator**, tick:
   - Scopes: `bot`
   - Bot permissions: `Send Messages`
5. Open the generated URL in a browser and add the bot to your guild.
6. With Developer Mode on in Discord (Settings → Advanced), right-click your guild
   icon and choose **Copy Server ID**. Save this number — you'll need it next.

If you want to honor a specific Booster role in addition to `premium_since`, also
right-click that role under **Server Settings → Roles** and **Copy ID**. Otherwise
skip this — the plugin will treat any active Nitro booster as qualifying.

---

## 4. Configure credentials at runtime

In the server console, over RCON, or in-game as an admin, run:

```text
nitrodiscordbotlink <BotToken> <GuildId> [BoosterRoleId|RoleName]
```

Examples:

```text
nitrodiscordbotlink MTAxOTAwOTM3Mzg1NzYyMzQ1NDE2 123456789012345678
nitrodiscordbotlink MTAxOTAwOTM3Mzg1NzYyMzQ1NDE2 123456789012345678 987654321098765432
nitrodiscordbotlink MTAxOTAwOTM3Mzg1NzYyMzQ1NDE2 123456789012345678 "Server Booster"
```

What happens:

1. The plugin prints a warning that the token will appear in Oxide's console log.
2. It performs two read-only Discord API calls (`GET /users/@me` and
   `GET /guilds/{id}`) to validate the token and confirm the bot is actually in
   the guild.
3. **On success**, the credentials are written to `oxide/config/NitroBoostLinker.json`
   and the plugin enables itself.
4. **On failure**, the previous credentials are restored in-memory and nothing is
   written to disk. A typo can never leave the live plugin running with bad,
   unsaved credentials.

> **Security note.** Oxide logs every console / RCON command verbatim, including
> the token argument. Use a trusted console or a secured RCON session, and rotate
> the token if logs may have been viewed by anyone untrusted.

---

## 5. Wire up your VIP kit

In **Custom Auto Kits**, edit (or create) the kit you want boosters to receive and
set its required permission to:

```text
NitroBoost
```

The permission name is configurable in `oxide/config/NitroBoostLinker.json`
(`OxidePermissionName`), but the default is what the rest of this guide assumes.

If you also enable `AlsoCreateOxideGroup`, the plugin adds qualifying players to an
Oxide group of the same name. You can use that group instead of the raw permission
in any other plugin that prefers groups.

---

## 6. The player flow

Tell your players:

1. Enable Developer Mode in Discord (Settings → Advanced).
2. Right-click their avatar in Discord → **Copy User ID**.
3. In Rust chat, type:
   ```text
   /nitrolink <DiscordUserID>
   ```
4. Open Discord and read the DM from the bot. Copy the code.
5. In Rust chat, type:
   ```text
   /nitroverify <CODE>
   ```
6. If they're actively boosting (or hold the configured Booster role) they get the
   `NitroBoost` permission immediately. If they aren't currently qualifying, the
   plugin still saves the link and grants the permission automatically the next
   time the periodic re-check sees them qualify.

Players can check their own status any time:

```text
/nitrostatus
```

---

## 7. Admin tools

| Command | What it does |
|---|---|
| `/nitroresync <player>` | Re-check one named or ID-specified player right now |
| `/nitroresync` | Queue a re-check for every linked player |
| `/nitrodiag` | Print full health report to chat + console + `oxide/logs/NitroBoostLinker.txt` |
| `/nitrodiscordbotlink ...` | Rotate Discord credentials without editing files |

`/nitrodiag` is the first thing to run when something looks wrong. It will tell you
which dependency is missing, whether the Discord credentials are configured, the
current API base URL, the active booster role configuration, link / pending counts,
and the rate-limit settings.

---

## 8. Tuning the config file

Most servers never need to edit `oxide/config/NitroBoostLinker.json` directly.
When you do, here are the values that are most useful to change:

| Key | Why you'd change it |
|---|---|
| `RevalidationIntervalMinutes` | Shorter = boosters lose access faster after they stop boosting. Default 60. Minimum 5. |
| `VerificationCodeTTLSeconds` | Longer = more time to copy the code from Discord. Default 600. Minimum 60. |
| `RateLimitPerPlayerPerMinute` | Raise on busy servers; lower if abuse is observed. Default 6, minimum 1. |
| `HttpTimeoutSeconds` | Raise on flaky networks; clamped to `[5, 60]`. |
| `SendDMTemplate` | Change the wording players see in the DM. `{CODE}` is substituted. |
| `DebugLogging` | Turn on to log Discord HTTP status codes (response bodies are never logged). |

All numeric fields are clamped on load — extreme values can't take down the plugin.

---

## 9. Updating

To install a new release:

1. Replace `oxide/plugins/NitroBoostLinker.cs` with the new file.
2. From the server console run:
   ```text
   oxide.reload NitroBoostLinker
   ```
3. The plugin reloads, re-validates prerequisites, and resumes with your existing
   config and link data. No data loss.

Config and persisted link data live under `oxide/data/NitroBoostLinker_Links.json`
and `oxide/data/NitroBoostLinker_Pending.json`. Back these up if you do a host
migration.

---

## 10. Troubleshooting cheat sheet

| Symptom | Likely cause | Fix |
|---|---|---|
| "[DISABLED] Image Library not loaded" | Dependency missing | Install Image Library and reload |
| "Discord validation failed" on `/nitrodiscordbotlink` | Wrong token, bot not in guild, or wrong guild ID | Recheck each, then re-run the command. Previous live credentials are restored automatically. |
| "Could not DM that Discord user" | The Discord user blocks DMs from server members, or the user ID is wrong | Enable DMs from server members or fix the ID |
| Boosting but not qualifying | Bot is missing the **Server Members Intent**, or the bot was added without the intent enabled | Enable the intent in the Developer Portal, then `oxide.reload NitroBoostLinker` |
| Linked but `NitroBoost` not granted | Player started boosting after `/nitroverify` — wait for the next re-check or run `/nitroresync <player>` | — |

For anything else, `/nitrodiag` is your friend. The same output is appended to
`oxide/logs/NitroBoostLinker.txt` so you can paste it into a support thread.

---

## 11. Uninstalling

1. Unload the plugin: `oxide.unload NitroBoostLinker`.
2. Optionally delete:
   - `oxide/plugins/NitroBoostLinker.cs`
   - `oxide/config/NitroBoostLinker.json`
   - `oxide/data/NitroBoostLinker_Links.json`
   - `oxide/data/NitroBoostLinker_Pending.json`
   - `oxide/lang/*/NitroBoostLinker.json`
   - `oxide/logs/NitroBoostLinker.txt`
3. Remove the Oxide permission everywhere it was referenced (e.g. in your Custom
   Auto Kits kit definitions). The plugin does not auto-clean these.

---

Need to report a problem or contribute a translation? See
[CONTRIBUTING.md](CONTRIBUTING.md).
