Installation Guide

Follow these steps to install Nitro Boost Linker on your Rust server with uMod (Oxide):

Download the plugin

Copy the NitroBoostLinker.cs file from this repository into your server's oxide/plugins/ directory.

Install required dependencies

Ensure the following plugins are installed and loaded on your server:

Image Library
 (ImageLibrary)

Rust Kits
 (Kits)

Custom Auto Kits
 (CustomAutoKits)

These plugins can be installed via the uMod website or by copying their .cs files into oxide/plugins/.

Add your Discord bot to the guild

Create a Discord bot via the Discord Developer Portal
.

Add the bot to your Discord guild and grant it permissions to view members, manage roles (if using booster roles), and send DMs.

Configure the plugin via command

In console, RCON, or in‑game as an admin, run the following command to link your bot:

/nitrodiscordbotlink <BotToken> <GuildId> [BoosterRoleId|RoleName]


<BotToken> is your bot's token from the Discord Developer Portal.

<GuildId> is the numerical ID of your Discord server. You can copy it by enabling Developer Mode and right‑clicking your server.

[BoosterRoleId|RoleName] is optional. Specify either the ID or the name of a role that counts as a booster. If omitted, only Nitro boosters (premium_since) qualify.

Example:

/nitrodiscordbotlink MTAxOTAwOTM3Mzg1NzYyMzQ1NDE2 123456789012345678 987654321098765432


Set up your VIP kit

In Custom Auto Kits, create or edit the kit you want to grant to Nitro boosters. Set its required permission to NitroBoost (exact casing).

Player linking process

Players must link their Discord accounts to receive the permission:

In Discord, enable Developer Mode and copy their User ID (right‑click their avatar → Copy User ID).

In game chat, run /nitrolink <DiscordUserID>.

They will receive a DM from your bot with a verification code. Run /nitroverify <CODE> in game to complete the link.

Verify and troubleshoot

Use /nitrostatus to check a player's link and boost status.

Use /nitroresync [player] to force re‑validation for one or all players.

Use /nitrodiag to print diagnostics (dependency status, configuration, etc.) to chat and log file.

Updating

To update, replace the old NitroBoostLinker.cs with the latest version and run oxide.reload NitroBoostLinker in console/RCON. Configuration and link data are preserved across updates.
