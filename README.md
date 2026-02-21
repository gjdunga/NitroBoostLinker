# Nitro Boost Linker

Grants the `NitroBoost` Oxide permission when a linked Discord user is actively boosting your
guild (`premium_since`) or has a configured Booster role. Designed to pair with **Custom Auto Kits**
and **Rust Kits** so VIP kits unlock automatically.

- Hard-fails without prerequisites (Image Library, Rust Kits, Custom Auto Kits, Discord config) and logs a clear error every 5 minutes
- `/nitrodiscordbotlink` lets admins configure the bot at runtime without editing files
- `/nitrodiag` prints a full health report and logs it to `oxide/logs/NitroBoostLinker.txt`
- `/nitrolink help` is always available, even while hard-disabled
- Boost/role status is re-checked automatically on a configurable interval

## Requirements

- [Image Library](https://umod.org/plugins/image-library) (`ImageLibrary`)
- [Rust Kits](https://umod.org/plugins/rust-kits) (`Kits`)
- [Custom Auto Kits](https://umod.org/plugins/custom-auto-kits) (`CustomAutoKits`)
- A Discord bot in your guild (token + guild ID)

## Quick Install

See [INSTALL.md](INSTALL.md) for full steps.

**TL;DR:**

1. Copy `NitroBoostLinker.cs` to `oxide/plugins/`.
2. Install Image Library, Rust Kits, and Custom Auto Kits.
3. In console/RCON: `/nitrodiscordbotlink YOUR_BOT_TOKEN 123456789012345678`
   Optionally include a Booster role ID or name:
   `/nitrodiscordbotlink YOUR_BOT_TOKEN 123456789012345678 987654321098765432`
4. In Custom Auto Kits, set your VIP kit to require permission `NitroBoost` (exact casing).

## Commands

| Command | Who | Description |
|---|---|---|
| `/nitrolink help` | Players | Show linking steps and required plugin links |
| `/nitrolink <DiscordUserID>` | Players | Start link flow |
| `/nitroverify <CODE>` | Players | Complete link with DM code |
| `/nitrostatus` | Players | Show link/boost status |
| `/nitroresync [player]` | Admin | Re-check one or all players |
| `/nitrodiscordbotlink <BotToken> <GuildId> [RoleId|Name]` | Admin/console | Configure Discord credentials |
| `/nitrodiag` | Admin/console | Full health report |

## Version

See [CHANGELOG.md](CHANGELOG.md).

Current version: **1.5.4**
