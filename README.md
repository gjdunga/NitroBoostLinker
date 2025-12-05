Nitro Boost Linker

Grants the NitroBoost permission when a linked Discord user is actively boosting your guild (premium_since) or has a configured Booster role. Designed for use with Custom Auto Kits + Rust Kits so VIP kits unlock automatically.

Hard‑fails without prerequisites (Image Library, Rust Kits, Custom Auto Kits, Discord config)

/nitrodiscordbotlink lets admins configure the bot without editing files

/nitrodiag prints a clear health report and logs it to Oxide

Help stays open (/nitrolink help) even while hard‑disabled

Requirements

Image Library
 (ImageLibrary)

Rust Kits
 (Kits)

Custom Auto Kits
 (CustomAutoKits)

A Discord bot in your guild (token + guild ID)

Quick Install

See INSTALL.md
 for detailed steps.

TL;DR

Copy NitroBoostLinker.cs to oxide/plugins/.

Install Image Library, Rust Kits, and Custom Auto Kits.

In console/RCON: /nitrodiscordbotlink YOUR_BOT_TOKEN 123456789012345678
Optionally include Booster role ID or name:
/nitrodiscordbotlink YOUR_BOT_TOKEN 123456789012345678 987654321098765432
OR /nitrodiscordbotlink YOUR_BOT_TOKEN 123456789012345678 BoosterRoleName

In Custom Auto Kits, set your VIP kit to require permission NitroBoost (exact casing).

Commands

nitrolink help – show linking steps + required plugin links (available even while disabled)

nitrolink <DiscordUserID> – start link

nitroverify <CODE> – complete link

nitrostatus – show your link/boost status

nitroresync [player] – admin re‑check one or all players

nitrodiscordbotlink <BotToken> <GuildId> [BoosterRoleId|RoleName] – admin/console setup

nitrodiag – admin/console diagnostics (also writes to oxide/logs/NitroBoostLinker.txt)

Sample Config

A sample oxide/config/NitroBoostLinker.json is included in this repo for screenshots and easy bootstrapping.

Version

See CHANGELOG.md
.
