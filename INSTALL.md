# Installation Guide

Follow these steps to install **Nitro Boost Linker v1.5.3** on your Rust server with uMod (Oxide).

---

## 1. Download the plugin

Copy `NitroBoostLinker.cs` from this repository into your server's `oxide/plugins/` directory.

## 2. Install required dependencies

The following plugins must be installed and loaded **before** Nitro Boost Linker will activate:

| Plugin | Oxide ID | Required by |
|---|---|---|
| [Image Library](https://umod.org/plugins/image-library) | `image-library` | Rust Kits |
| [Rust Kits](https://umod.org/plugins/rust-kits) | `rust-kits` | kit granting |
| [Custom Auto Kits](https://umod.org/plugins/custom-auto-kits) | `custom-auto-kits` | permission-based auto-kits |

Install each by copying their `.cs` files into `oxide/plugins/` or via the uMod website.

If any of these are missing, the plugin hard-disables itself and logs a clear error every 5 minutes
until the dependency is added.

## 3. Create a Discord bot and add it to your guild

1. Go to the [Discord Developer Portal](https://discord.com/developers/applications) and create an application.
2. Under **Bot**, enable the **Server Members Intent** (required to fetch member records).
3. Copy the bot **Token** — you will need this in step 4.
4. Under **OAuth2 > URL Generator**, select scopes `bot` and permissions **Send Messages** and
   **Read Message History**. Use the generated URL to invite the bot to your guild.

## 4. Configure the plugin via command

In console, RCON, or in-game as an admin, run:

```
/nitrodiscordbotlink <BotToken> <GuildId> [BoosterRoleId|RoleName]
```

- `<BotToken>` — your bot token from the Developer Portal.
- `<GuildId>` — the numerical ID of your Discord server (right-click server icon with Developer Mode
  enabled > **Copy Server ID**).
- `[BoosterRoleId|RoleName]` — optional. If omitted, only players with an active Nitro boost
  (`premium_since`) qualify. Supply a role ID or exact role name to also accept that role.

**Security note:** The bot token will appear in Oxide's server console log because all commands are
logged verbatim. Use physical console access or a secured RCON connection. Rotate the token if
console logs may have been viewed by unauthorized parties.

Example:
```
/nitrodiscordbotlink MTAxOTAwOTM3Mzg1NzYyMzQ1NDE2 123456789012345678 987654321098765432
```

The plugin validates the token and guild ID before saving. If validation fails, credentials are
**not** written to disk.

## 5. Set up your VIP kit

In **Custom Auto Kits**, create or edit the kit you want to grant to Nitro boosters.
Set its required permission to `NitroBoost` (exact casing).

## 6. Player linking process

Players must link their Discord account once:

1. In Discord, enable **Developer Mode** (Settings > Advanced) and copy their User ID
   (right-click avatar > **Copy User ID**).
2. In game chat: `/nitrolink <DiscordUserID>`
3. Check Discord DM from the bot for a verification code.
4. In game chat: `/nitroverify <CODE>`

Once linked, boost/role status is re-checked automatically every 60 minutes (configurable).

## 7. Verify and troubleshoot

| Command | Purpose |
|---|---|
| `/nitrostatus` | Check a player's link and boost status |
| `/nitroresync [player]` | Force re-validation for one or all players (admin) |
| `/nitrodiag` | Full health report — dependency status, config summary, counts (admin) |

The diag command also writes to `oxide/logs/NitroBoostLinker.txt`.

## Updating

Replace `NitroBoostLinker.cs` with the new version and run:
```
oxide.reload NitroBoostLinker
```
Configuration and link data are preserved across updates.
