# Installation Guide — Nitro Boost Linker

This plugin grants the `NitroBoost` permission to players who are verified Discord Nitro boosters of your guild (via `premium_since`) **or** who hold a configured Booster role. It integrates with **Custom Auto Kits** and **Rust Kits**.

## Prerequisites (Install these first)
- **Image Library** — https://umod.org/plugins/image-library
- **Rust Kits** — https://umod.org/plugins/rust-kits
- **Custom Auto Kits** — https://umod.org/plugins/custom-auto-kits
- A Discord **bot** added to your guild, with a **bot token** and the bot able to DM users.

> The plugin will **hard-fail** and clearly bark in logs if any of these are missing.

## Steps
1. Place `NitroBoostLinker.cs` into `oxide/plugins/`.
2. Make sure the three prerequisite plugins are installed and loaded.
3. Set up Discord via console or RCON:
   nitrodiscordbotlink YOUR_BOT_TOKEN 123456789012345678
   # Optional: include Booster role by ID OR name:
   nitrodiscordbotlink YOUR_BOT_TOKEN 123456789012345678 987654321098765432
   # or
   nitrodiscordbotlink YOUR_BOT_TOKEN 123456789012345678 BoosterRoleName
4. Create/adjust your Custom Auto Kits VIP kit to require permission NitroBoost.
5. Players link via: /nitrolink <DiscordUserID>   /nitroverify <CODE>
6.Use /nitrostatus, /nitroresync, and /nitrodiag for visibility and maintenance.

Troubleshooting

Run /nitrodiag (console/RCON or in-game as admin) to see current dependency status.

Check logs at oxide/logs/NitroBoostLinker.txt plus your server console log for bark messages.

Ensure the bot can DM users (user privacy settings, mutual server, etc.).

