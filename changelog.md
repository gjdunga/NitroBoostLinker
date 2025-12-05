Changelog

All notable changes to Nitro Boost Linker will be documented in this file.

1.5.2 — 2025‑12‑05

Bumped version and author metadata to 1.5.2 (Gabriel).

Consolidated improvements introduced in 1.5.1:

Added OnServerInitialized, OnPluginLoaded and OnPluginUnloaded hooks to better handle dependency load order.

Improved dependency checking and automatic re‑evaluation when required plugins load or unload.

Hardened rate limiting, DM sending and Discord API error handling.

Added display metadata (DisplayVersion and DisplayAuthor) for cleaner help output.

No functional changes from 1.5.1 beyond the version and author update.

1.5.1 — 2025‑MM‑DD

Introduced robust load‑order handling to re‑evaluate prerequisites after server initialization and when plugins load/unload.

Refactored configuration loading, saving, and default values.

Improved help output, diagnostics formatting, and logging.

Added support for dynamic booster role resolution by name if an ID is not provided.

Strengthened rate limiting, pending code storage, and data persistence.

1.5.0 — 2025‑MM‑DD

Initial public release of Nitro Boost Linker.

Links Discord users to Steam players via verification codes.

Grants NitroBoost permission and optional Oxide group when a linked user boosts your guild or has the Booster role.

Provides commands for linking, verifying, checking status, resyncing, configuring the bot, and diagnostics.
