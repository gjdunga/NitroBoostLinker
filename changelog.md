# Changelog — Nitro Boost Linker

## 1.5.0 — Required links in help + Install guide (2025-11-09)
- **Added** clickable **required plugin URLs** in `/nitrolink help`.
- **Added** `INSTALL.md` with detailed, link-rich setup flow.
- **Polish**: tightened help text, kept help available even when hard-disabled.
- **Docs**: updated README to point to INSTALL and CHANGELOG.

## 1.4.0 — Image Library hard requirement
- **Added** hard-fail check for **Image Library** (required by Rust Kits).
- **Diagnostics**: `/nitrodiag` now shows Image Library status.
- **Logging**: failures bark to server console, Oxide global log, and plugin log file.

## 1.3.0 — Diagnostics + RCON setup + approval-friendly refactor
- **New** admin commands:
  - `/nitrodiag` prints dependency health and configuration.
  - `/nitrodiscordbotlink <BotToken> <GuildId> [BoosterRoleId|RoleName]` for live Discord setup.
- **Hard-fail** if **Rust Kits**, **Custom Auto Kits**, or **Discord config** are missing.
- **Help stays open**: `/nitrolink help` works even while disabled.
- **Logging**: consistent error messages to all logging surfaces.
- **Config**: typed JSON config with safe defaults and future-proof fields.

## 1.2.x and earlier — Internal drafts
- Initial MVP: link/verify flow, Nitro boost (premium_since) + Booster role checks, and permission grant/revoke for `NitroBoost`.
