# Nitro Boost Linker

Grants the `NitroBoost` permission when a linked Discord user is actively boosting your guild (`premium_since`) **or** has a configured Booster role. Designed for use with **Custom Auto Kits** + **Rust Kits** so VIP kits unlock automatically.

- **Hard-fails** without prerequisites (Image Library, Rust Kits, Custom Auto Kits, Discord config)
- **`/nitrodiscordbotlink`** lets admins configure the bot without editing files
- **`/nitrodiag`** prints a clear health report and logs it to Oxide
- **Help stays open** (`/nitrolink help`) even while hard-disabled

## Requirements
- [Image Library](https://umod.org/plugins/image-library) (`ImageLibrary`)
- [Rust Kits](https://umod.org/plugins/rust-kits) (`Kits`)
- [Custom Auto Kits](https://umod.org/plugins/custom-auto-kits) (`CustomAutoKits`)
- A Discord bot in your guild (token + guild ID)

## Quick Install
See **[INSTALL.md](./INSTALL.md)** for detailed steps.

### TL;DR
1. Copy `NitroBoostLinker.cs` to `oxide/plugins/`.
2. Install **Image Library**, **Rust Kits**, and **Custom Auto Kits**.
3. In console/RCON:
