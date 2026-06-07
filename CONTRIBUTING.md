# Contributing to Nitro Boost Linker

Thanks for taking the time to help out. This file covers the conventions used in the
project, how to test changes locally against a real Rust + Oxide server, the
locale-file format, and how to disclose security issues responsibly.

> Maintainer: Gabriel Dungan, DunganSoft Technologies — GPL-3.0 licensed.

---

## Ground rules

- One logical change per pull request. Small focused PRs ship faster than large ones.
- Keep the plugin Covalence-only. No direct references to Assembly-CSharp game types.
  This is what lets the plugin survive Facepunch's monthly force-wipe updates.
- Keep player-facing strings in `oxide/lang/<locale>/NitroBoostLinker.json` and the
  English defaults in `LoadDefaultMessages()` — never hard-code English in command
  handlers.
- Maintain the security model documented at the top of `NitroBoostLinker.cs`. If you
  weaken a check, call it out explicitly in the PR description.
- Update `CHANGELOG.md` and bump the version in **all three** places:
  `oxide/plugins/NitroBoostLinker.cs` (the `[Info]` attribute and `DisplayVersion`),
  `manifest.json`, and `.umod.yaml`. The release CI rejects mismatches.

---

## Versioning

The project follows semantic versioning:

- **Patch** (`5.4.x`) — bug or security fixes, documentation, locale changes.
- **Minor** (`1.x.0`) — new behaviour or config keys with backward-compatible defaults.
- **Major** (`x.0.0`) — breaking changes to config, command syntax, or persisted data.

When you bump the version, add a dated section to `CHANGELOG.md` in the same PR.

---

## Local development loop

The plugin is a single `.cs` file that Oxide compiles in-process. There is no project
file or build step — just edit and reload.

1. Stand up a test Rust dedicated server with Oxide.Rust 2.0.7022 or newer.
2. Install **Image Library**, **Rust Kits**, and **Custom Auto Kits**.
3. Symlink (or copy) your working copy of `oxide/plugins/NitroBoostLinker.cs` into
   the server's `oxide/plugins/` folder.
4. After each change run, in the server console:
   ```text
   oxide.reload NitroBoostLinker
   ```
5. Watch the console for compile errors. Oxide prints them inline with file +
   line + column.
6. Iterate.

Tip: keep `DebugLogging` on while developing. It logs Discord HTTP status codes
(never response bodies) so you can see exactly which API call failed.

---

## Test checklist before opening a PR

Run through this list against a live test server. Tick everything that applies to
your change.

**Lifecycle**

- [ ] `oxide.reload NitroBoostLinker` succeeds with no compile errors.
- [ ] `oxide.unload NitroBoostLinker` followed by `oxide.load NitroBoostLinker`
  succeeds and re-loads link data.
- [ ] Unloading the plugin while a verification is mid-flight does not throw.

**Hard-fail behaviour**

- [ ] With Image Library missing: plugin logs hard-fail and `/nitrolink help` still
  responds; all other player commands print the disabled notice.
- [ ] Same with Rust Kits missing.
- [ ] Same with Custom Auto Kits missing.
- [ ] With Discord credentials cleared: same behaviour.
- [ ] After fixing the issue and reloading the dependency, the plugin re-enables
  itself with no manual intervention.

**Linking flow**

- [ ] `/nitrolink <id>` DMs the player a code.
- [ ] `/nitroverify <CODE>` grants `NitroBoost` if the player is boosting.
- [ ] `/nitroverify` from a different Steam account using someone else's code is
  rejected with the ownership-mismatch message.
- [ ] An expired code is rejected and removed from the pending set.
- [ ] Spamming `/nitrolink` triggers the rate-limit message after the configured
  threshold.

**Admin tooling**

- [ ] `/nitroresync <player>` re-checks one player.
- [ ] `/nitroresync` queues every linked player.
- [ ] `/nitrodiscordbotlink` with a *valid* token writes to disk and enables the
  plugin.
- [ ] `/nitrodiscordbotlink` with an *invalid* token leaves the on-disk config
  untouched **and** restores the previous in-memory credentials so the plugin
  continues to work.
- [ ] `/nitrodiag` prints to chat + console + `oxide/logs/NitroBoostLinker.txt`.

**Localization**

- [ ] If you added a new player-facing string, the key exists in `LoadDefaultMessages`
  and in every locale file under `oxide/lang/`.

---

## Adding a new locale

1. Copy `oxide/lang/en/NitroBoostLinker.json` to
   `oxide/lang/<your-locale>/NitroBoostLinker.json`.
2. Translate the values — do **not** translate the keys, and keep all `{token}`
   placeholders intact in the same positions.
3. Add your locale code to `manifest.json` under `localization.supported`.
4. Test by running `o.lang <your-locale> <yourSteamId>` and verifying the in-game
   messages match.

The locale codes already shipped are `en`, `ru`, `es`, and `la`.

---

## Adding a new config key

1. Add the field to `PluginConfig` in `NitroBoostLinker.cs` with a `[JsonProperty]`
   attribute and a sensible default.
2. If it's numeric, add bounds enforcement to `NormalizeConfig()`. The plugin assumes
   anything that survives `NormalizeConfig` is safe to use without further checks.
3. Add the field (with its default) to the sample
   `oxide/config/NitroBoostLinker.json` in the repo root.
4. Document the field in `README.md` (Configuration section) and in `INSTALL.md`
   (Tuning section) only if it's something a typical server operator would change.
5. Add a changelog entry under "New Features" or "Config".

---

## Adding a new command

1. Register it inside `Init()` with `AddCovalenceCommand`.
2. Implement the handler with the standard signature
   `void Cmd<Name>(IPlayer player, string command, string[] args)`.
3. If the command is for admins only, replicate the existing guard:
   ```csharp
   if (player != null && !player.IsServer && !player.IsAdmin)
   {
       player.Reply(lang.GetMessage(Msg.AdminOnly, this, player.Id));
       return;
   }
   ```
4. Player-facing commands must call `CheckRate(player)` before doing any work.
5. Every command must call `BarkIfHardDisabled(player)` (or check `_hardDisabled`
   explicitly) before touching Discord or permissions, unless the command is
   intended to be usable while the plugin is hard-disabled (e.g. `/nitrolink help`,
   `/nitrostatus`, `/nitrodiag`).
6. Add the command to:
   - `manifest.json` under `commands`
   - `README.md` (Commands table)
   - `INSTALL.md` (Admin tools section, if applicable)

---

## Reporting security issues

Please do **not** open public GitHub issues for security problems. Report privately:

- Email: open a private security advisory via GitHub at
  <https://github.com/gjdunga/NitroBoostLinker/security/advisories/new>.
- Include reproduction steps, affected version(s), and the impact you observed.

You should expect an initial reply within 72 hours and a coordinated patch + public
disclosure within 14 days for confirmed issues. If you don't hear back inside 72
hours, ping the repository owner on GitHub.

Items we treat as in-scope security issues:

- Anything that lets a non-admin player elevate to `NitroBoost` without legitimately
  boosting or holding the configured Booster role.
- Bot-token leakage via logs, errors, or command output.
- SSRF, request smuggling, or any way to redirect plugin HTTP traffic away from
  `https://discord.com`.
- Crashes triggered by malformed config or data files that aren't already caught by
  `NormalizeConfig` / `IsValid` / `LoadData`.
- PII (Discord email, MFA status, etc.) appearing in any log file regardless of
  `DebugLogging`.

Out of scope:

- Issues that require an attacker to already have file-system or RCON access on the
  host. Treat those as host-hardening problems, not plugin bugs.
- Issues in Image Library, Rust Kits, or Custom Auto Kits themselves — report those
  upstream.

---

## Pull request checklist

Before requesting review:

- [ ] One logical change.
- [ ] Test checklist above ticked for the areas you touched.
- [ ] Version bumped consistently across plugin / manifest / .umod.yaml if you're
  cutting a release.
- [ ] `CHANGELOG.md` updated with a dated entry.
- [ ] Documentation updated (`README.md`, `INSTALL.md`, locale files) for any
  user-visible change.
- [ ] No new compiler warnings on Oxide's build.

Thanks again for contributing.
