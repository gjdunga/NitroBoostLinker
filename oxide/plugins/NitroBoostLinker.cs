/*
MIT License

Copyright (c) 2025 Gabriel Dungan, Github: gjdunga

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to do so, subject to the
following conditions:
The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
IN THE SOFTWARE.
*/

using System;
using System.Collections.Generic;
using System.Text;
using Newtonsoft.Json;
using Oxide.Core;
using Oxide.Core.Configuration;
using Oxide.Core.Libraries.Covalence;

namespace Oxide.Plugins
{
    [Info("Nitro Boost Linker", "gjdunga", "1.5.0")]
    [Description("Grants NitroBoost permission when a linked Discord user is boosting (premium_since) or has a Booster role. Hard-fails if prerequisites are missing (Image Library + Rust Kits + Custom Auto Kits + Discord config). Includes /nitrodiag and verbose logging.")]
    public class NitroBoostLinker : CovalencePlugin
    {
        // Keep the older script tag visible per earlier request while showing the live build.
        private const string DisplayVersion = "1.5.0 (build), Script ID: 1.0.Beta";
        private const string DisplayAuthor  = "Gabriel Dungan, gjdunga, MIT License";

        // Docs/links used in help output
        private const string UrlImageLibrary = "https://umod.org/plugins/image-library";
        private const string UrlRustKits     = "https://umod.org/plugins/rust-kits";
        private const string UrlCustomKits   = "https://umod.org/plugins/custom-auto-kits";

        // Soft references (null if not loaded)
        [PluginReference] private Plugin ImageLibrary;   // Image Library (dependency of Rust Kits)
        [PluginReference] private Plugin Kits;           // Rust Kits ("Kits")
        [PluginReference] private Plugin CustomAutoKits; // Custom Auto Kits

        // Hard-disable state
        private bool _hardDisabled = false;
        private string _hardDisabledReason = "Not initialized";

        // Log file name (oxide/logs/NitroBoostLinker.txt)
        private const string LogFile = "NitroBoostLinker";

        #region Configuration

        private PluginConfig _config;

        private class PluginConfig
        {
            [JsonProperty("DiscordBotToken")] public string DiscordBotToken = "";
            [JsonProperty("DiscordGuildId")]  public ulong DiscordGuildId = 0;

            [JsonProperty("OxidePermissionName")] public string OxidePermissionName = "NitroBoost";

            [JsonProperty("AlsoCreateOxideGroup")] public bool AlsoCreateOxideGroup = true;
            [JsonProperty("OxideGroupName")]      public string OxideGroupName = "NitroBoost";
            [JsonProperty("GrantGroupIfExistsOnly")] public bool GrantGroupIfExistsOnly = true;

            // Booster OR premium_since logic
            [JsonProperty("TreatPremiumSinceAsBoost")] public bool TreatPremiumSinceAsBoost = true;
            [JsonProperty("UseBoosterRoleCheck")]     public bool UseBoosterRoleCheck = true;
            [JsonProperty("BoosterRoleId")]           public ulong BoosterRoleId = 0;     // ID preferred
            [JsonProperty("BoosterRoleName")]         public string BoosterRoleName = "";  // optional name

            [JsonProperty("VerificationCodeLength")]     public int VerificationCodeLength = 6;
            [JsonProperty("VerificationCodeTTLSeconds")] public int VerificationCodeTTLSeconds = 600;

            [JsonProperty("RevalidationIntervalMinutes")] public int RevalidationIntervalMinutes = 60;
            [JsonProperty("RateLimitPerPlayerPerMinute")] public int RateLimitPerPlayerPerMinute = 6;

            [JsonProperty("DiscordApiBase")]     public string DiscordApiBase = "https://discord.com/api/v10";
            [JsonProperty("HttpTimeoutSeconds")] public int HttpTimeoutSeconds = 15;

            [JsonProperty("SendDMTemplate")]
            public string SendDMTemplate =
                "Your Rust verification code is: **{CODE}**\nReturn to the server and run: `/nitroverify {CODE}`";

            [JsonProperty("DebugLogging")] public bool DebugLogging = false;

            // Dependency resolution lists
            [JsonProperty("ImageLibraryPluginNames")]
            public string[] ImageLibraryPluginNames = new[] { "ImageLibrary", "Image Library", "image-library" };

            [JsonProperty("RustKitsPluginNames")]
            public string[] RustKitsPluginNames = new[] { "Kits", "Rust Kits", "rust-kits" };

            [JsonProperty("CustomAutoKitsPluginNames")]
            public string[] CustomAutoKitsPluginNames = new[] { "Custom Auto Kits", "CustomAutoKits", "custom-auto-kits" };

            // Hard-fail messages
            [JsonProperty("HardFailMessage_ImageLibraryMissing")]
            public string HardFailMessageImageLibraryMissing =
                "[NitroBoostLinker] HARD-FAIL: Image Library is not installed/loaded. Rust Kits depends on it. Install " + UrlImageLibrary + ".";

            [JsonProperty("HardFailMessage_RustKitsMissing")]
            public string HardFailMessageRustKitsMissing =
                "[NitroBoostLinker] HARD-FAIL: Rust Kits is not installed/loaded. Install " + UrlRustKits + ".";

            [JsonProperty("HardFailMessage_CAKMissing")]
            public string HardFailMessageCakMissing =
                "[NitroBoostLinker] HARD-FAIL: Custom Auto Kits is not installed/loaded. Install " + UrlCustomKits + " and configure a kit with permission 'NitroBoost'.";

            [JsonProperty("HardFailMessage_DiscordNotConfigured")]
            public string HardFailMessageDiscordNotConfigured =
                "[NitroBoostLinker] HARD-FAIL: Discord bot token and/or guild ID are not configured. Use /nitrodiscordbotlink <BotToken> <GuildId> [BoosterRoleId|RoleName] from console/RCON/in-game (admin).";
        }

        protected override void LoadDefaultConfig()
        {
            LogWarning("Generating default configuration...");
            _config = new PluginConfig();
            Config.WriteObject(_config, true);
        }

        private void LoadConfigTyped()
        {
            try
            {
                _config = Config.ReadObject<PluginConfig>();
                if (_config == null) throw new Exception("Config null");
            }
            catch
            {
                LogWarning("Config invalid; regenerating defaults.");
                LoadDefaultConfig();
            }
        }

        private void SaveConfigTyped() => Config.WriteObject(_config, true);

        #endregion

        #region Data

        private class LinkRecord
        {
            [JsonProperty("SteamId")] public string SteamId;
            [JsonProperty("DiscordUserId")] public ulong DiscordUserId;
            [JsonProperty("LinkedAtUtc")] public DateTime LinkedAtUtc;
            [JsonProperty("LastVerifiedUtc")] public DateTime LastVerifiedUtc;
            [JsonProperty("IsBoosting")] public bool IsBoosting;
            [JsonProperty("LastKnownPremiumSince")] public DateTime? LastKnownPremiumSince;
        }

        private class PendingRecord
        {
            [JsonProperty("SteamId")] public string SteamId;
            [JsonProperty("DiscordUserId")] public ulong DiscordUserId;
            [JsonProperty("Code")] public string Code;
            [JsonProperty("ExpiresUtc")] public DateTime ExpiresUtc;
            [JsonProperty("CreatedUtc")] public DateTime CreatedUtc;
        }

        private const string LinksFile   = "NitroBoostLinker_Links";
        private const string PendingFile = "NitroBoostLinker_Pending";

        private Dictionary<string, LinkRecord> _linked;            // steamId -> record
        private Dictionary<string, PendingRecord> _pendingBySteam; // steamId -> pending
        private Dictionary<string, PendingRecord> _pendingByCode;  // code -> pending

        private readonly Dictionary<string, List<DateTime>> _rate = new Dictionary<string, List<DateTime>>();

        private ulong _boosterRoleIdResolved;
        private DateTime _roleCacheTimeUtc = DateTime.MinValue;

        #endregion

        #region Hooks

        private void Init()
        {
            LoadConfigTyped();

            permission.RegisterPermission(_config.OxidePermissionName, this);

            if (_config.AlsoCreateOxideGroup && !_config.GrantGroupIfExistsOnly && !permission.GroupExists(_config.OxideGroupName))
                permission.CreateGroup(_config.OxideGroupName, _config.OxideGroupName, 0);

            LoadData();

            AddCovalenceCommand("nitrolink", nameof(CmdNitroLink));
            AddCovalenceCommand("nitroverify", nameof(CmdNitroVerify));
            AddCovalenceCommand("nitrostatus", nameof(CmdNitroStatus));
            AddCovalenceCommand("nitroresync", nameof(CmdNitroResync));
            AddCovalenceCommand("nitrodiscordbotlink", nameof(CmdNitroDiscordBotLink)); // setup from console/RCON/in-game (admin)
            AddCovalenceCommand("nitrodiag", nameof(CmdNitroDiag)); // health/diagnostics

            ReevaluateHardFailPrereqs();
            ScheduleRevalidation();
        }

        private void Unload() => SaveData();

        #endregion

        #region Hard-fail logic & Logging

        private void ReevaluateHardFailPrereqs()
        {
            bool imageLibPresent   = IsImageLibraryPresent();
            bool rustKitsPresent   = IsRustKitsPresent();
            bool cakPresent        = IsCustomAutoKitsPresent();
            bool discordConfigured = !string.IsNullOrWhiteSpace(_config.DiscordBotToken) && _config.DiscordGuildId != 0;

            if (!imageLibPresent)
            {
                HardDisable(_config.HardFailMessageImageLibraryMissing);
                RepeatConsoleBark(() => !IsImageLibraryPresent(), _config.HardFailMessageImageLibraryMissing);
                return;
            }

            if (!rustKitsPresent)
            {
                HardDisable(_config.HardFailMessageRustKitsMissing);
                RepeatConsoleBark(() => !IsRustKitsPresent(), _config.HardFailMessageRustKitsMissing);
                return;
            }

            if (!cakPresent)
            {
                HardDisable(_config.HardFailMessageCakMissing);
                RepeatConsoleBark(() => !IsCustomAutoKitsPresent(), _config.HardFailMessageCakMissing);
                return;
            }

            if (!discordConfigured)
            {
                HardDisable(_config.HardFailMessageDiscordNotConfigured);
                RepeatConsoleBark(() => string.IsNullOrWhiteSpace(_config.DiscordBotToken) || _config.DiscordGuildId == 0, _config.HardFailMessageDiscordNotConfigured);
                return;
            }

            if (_hardDisabled)
                Puts("[NitroBoostLinker] Prerequisites satisfied; re-enabling features.");

            _hardDisabled = false;
            _hardDisabledReason = "";
        }

        // Write errors to console AND oxide log file (oxide/logs/NitroBoostLinker.txt)
        private void LogFailure(string message)
        {
            PrintError(message);                      // Console (also goes to Rust log)
            Interface.Oxide.LogError(message);        // Oxide global error log
            LogToFile(LogFile, $"[{DateTime.UtcNow:u}] {message}", this); // Plugin log file
        }

        private void HardDisable(string reason)
        {
            _hardDisabled = true;
            _hardDisabledReason = reason;
            LogFailure(reason);
        }

        private void RepeatConsoleBark(Func<bool> stillFailing, string message)
        {
            timer.Every(300f, () =>
            {
                if (_hardDisabled && stillFailing())
                    LogFailure(message);
            });
        }

        // Returns true if it interrupted and barked
        private bool BarkIfHardDisabled(IPlayer player)
        {
            if (!_hardDisabled) return false;

            if (player == null || player.IsServer || player.IsAdmin)
                player?.Reply(_hardDisabledReason);

            LogFailure(_hardDisabledReason);
            return true;
        }

        #endregion

        #region Commands

        private void CmdNitroLink(IPlayer player, string command, string[] args)
        {
            // Help remains available even while disabled
            if (args.Length == 1 && args[0].Equals("help", StringComparison.OrdinalIgnoreCase))
            {
                player?.Reply(
$@"<color=#9be7ff>— Nitro Link Help —</color>
Version: {DisplayVersion}
Author: {DisplayAuthor}

Required plugins (must be installed & loaded):
 • Image Library — <color=#ffff99>{UrlImageLibrary}</color>
 • Rust Kits — <color=#ffff99>{UrlRustKits}</color>
 • Custom Auto Kits — <color=#ffff99>{UrlCustomKits}</color>

Steps:
 1) In Discord, enable Developer Mode → right-click yourself → Copy User ID.
 2) In chat: <color=#ffff99>/nitrolink &lt;DiscordUserID&gt;</color>
 3) Check the DM from the bot for your code.
 4) In chat: <color=#ffff99>/nitroverify &lt;CODE&gt;</color>

VIP unlocks when:
 • You’re actively boosting the guild (premium_since), OR
 • You have the configured Booster role.

See status with <color=#ffff99>/nitrostatus</color>.");
                if (_hardDisabled) BarkIfHardDisabled(player);
                return;
            }

            if (BarkIfHardDisabled(player)) return;
            if (!CheckRate(player)) return;

            if (args.Length != 1)
            {
                player.Reply("Usage: /nitrolink <DiscordUserID>  — or —  /nitrolink help");
                return;
            }

            if (!ulong.TryParse(args[0], out var discordUserId))
            {
                player.Reply("That does not look like a valid Discord User ID.");
                return;
            }

            var steamId = player.Id;
            if (_linked != null && _linked.TryGetValue(steamId, out var existing))
            {
                player.Reply($"Already linked to Discord ID `{existing.DiscordUserId}`. Use /nitrostatus or ask an admin for /nitroresync.");
                return;
            }

            var code = GenerateCode(_config.VerificationCodeLength);
            var pending = new PendingRecord
            {
                SteamId = steamId,
                DiscordUserId = discordUserId,
                Code = code,
                CreatedUtc = DateTime.UtcNow,
                ExpiresUtc = DateTime.UtcNow.AddSeconds(_config.VerificationCodeTTLSeconds)
            };

            if (_pendingBySteam.TryGetValue(steamId, out var old))
                _pendingByCode.Remove(old.Code);

            _pendingBySteam[steamId] = pending;
            _pendingByCode[code] = pending;
            SaveData();

            SendVerificationDM(discordUserId, code, ok =>
            {
                if (!ok)
                {
                    player.Reply("I couldn't DM that Discord user. Check the ID and whether the user allows DMs from the bot.");
                    _pendingBySteam.Remove(steamId);
                    _pendingByCode.Remove(code);
                    SaveData();
                    return;
                }

                player.Reply($"I DM’d a verification code to `{discordUserId}`. Run `/nitroverify {code}` within {_config.VerificationCodeTTLSeconds / 60} minutes.");
            });
        }

        private void CmdNitroVerify(IPlayer player, string command, string[] args)
        {
            if (BarkIfHardDisabled(player)) return;
            if (!CheckRate(player)) return;

            if (args.Length != 1) { player.Reply("Usage: /nitroverify <code>"); return; }

            var code = args[0].Trim();
            if (!_pendingByCode.TryGetValue(code, out var pending))
            {
                player.Reply("Invalid or expired code. Run `/nitrolink <DiscordUserID>` again.");
                return;
            }

            if (!string.Equals(pending.SteamId, player.Id, StringComparison.Ordinal))
            {
                player.Reply("This code does not belong to your account.");
                return;
            }

            if (DateTime.UtcNow > pending.ExpiresUtc)
            {
                CleanupPending(pending);
                player.Reply("That code has expired. Run `/nitrolink <DiscordUserID>` again.");
                return;
            }

            CheckMemberBoostOrRole(pending.DiscordUserId, result =>
            {
                if (result == null) { player.Reply("I couldn't verify your guild status right now. Try again shortly."); return; }

                var (isBoostingByPremium, premiumSince, hasBoosterRole) = result.Value;
                var qualifies = isBoostingByPremium || hasBoosterRole;
                var now = DateTime.UtcNow;

                var record = new LinkRecord
                {
                    SteamId = player.Id,
                    DiscordUserId = pending.DiscordUserId,
                    LinkedAtUtc = now,
                    LastVerifiedUtc = now,
                    IsBoosting = qualifies,
                    LastKnownPremiumSince = premiumSince
                };

                _linked[player.Id] = record;
                CleanupPending(pending);
                SaveData();

                if (qualifies)
                {
                    GrantVip(player.Id);
                    var reason = isBoostingByPremium ? "Nitro boost detected" : "Booster role detected";
                    player.Reply($"Linked ✅ — {reason}! You now have the `{_config.OxidePermissionName}` permission.");
                }
                else
                {
                    player.Reply("Linked ✅ but neither Nitro boost nor Booster role were found. Once that changes, the permission will be granted on re-check.");
                }
            });
        }

        private void CmdNitroStatus(IPlayer player, string command, string[] args)
        {
            if (_hardDisabled)
            {
                if (_linked != null && _linked.TryGetValue(player.Id, out var link))
                    player.Reply($"[DISABLED] Reason: {_hardDisabledReason}\nDiscord ID: `{link.DiscordUserId}`\nBoost/Role OK: {(link.IsBoosting ? "Yes" : "No")}\nPremium Since: {link.LastKnownPremiumSince?.ToString("u") ?? "n/a"}\nLast Verified: {link.LastVerifiedUtc:u}");
                else
                    player.Reply($"[DISABLED] Reason: {_hardDisabledReason}\nNot linked. Use: /nitrolink help");
                return;
            }

            if (_linked != null && _linked.TryGetValue(player.Id, out var l))
                player.Reply($"Discord ID: `{l.DiscordUserId}`\nBoost/Role OK: {(l.IsBoosting ? "Yes" : "No")}\nPremium Since: {l.LastKnownPremiumSince?.ToString("u") ?? "n/a"}\nLast Verified: {l.LastVerifiedUtc:u}");
            else
                player.Reply("Not linked. Use: /nitrolink <DiscordUserID>  (or /nitrolink help).");
        }

        private void CmdNitroResync(IPlayer player, string command, string[] args)
        {
            if (!player.IsServer && !player.IsAdmin) { player.Reply("You must be an admin to use this."); return; }
            if (BarkIfHardDisabled(player)) return;

            if (args.Length == 1)
            {
                var target = FindPlayer(args[0]);
                if (target == null) { player.Reply("Player not found."); return; }

                ResyncPlayer(target.Id, ok => player.Reply(ok ? $"Resynced {target.Name}." : $"Failed to resync {target.Name}."));
                return;
            }

            var total = 0;
            foreach (var kv in _linked) { total++; ResyncPlayer(kv.Key, null); }
            player.Reply($"Queued revalidation for {total} linked accounts.");
        }

        /// Admin/console/RCON runtime setup for Discord. Optional Booster role (ID or Name).
        /// Usage: /nitrodiscordbotlink <BotToken> <GuildId> [BoosterRoleId|RoleName]
        private void CmdNitroDiscordBotLink(IPlayer player, string command, string[] args)
        {
            if (!(player == null || player.IsServer || player.IsAdmin))
            {
                player?.Reply("You must be an admin (or console/RCON) to use this.");
                return;
            }

            if (args.Length < 2)
            {
                player?.Reply("Usage: /nitrodiscordbotlink <BotToken> <GuildId> [BoosterRoleId|RoleName]");
                LogFailure("Usage: nitrodiscordbotlink <BotToken> <GuildId> [BoosterRoleId|RoleName]");
                return;
            }

            var newToken = args[0];
            if (!ulong.TryParse(args[1], out var newGuildId) || newGuildId == 0)
            {
                player?.Reply("GuildId must be a non-zero unsigned integer.");
                return;
            }

            if (args.Length >= 3)
            {
                if (ulong.TryParse(args[2], out var roleId))
                {
                    _config.BoosterRoleId = roleId;
                    _config.BoosterRoleName = "";
                }
                else
                {
                    _config.BoosterRoleName = args[2];
                    _config.BoosterRoleId = 0;
                }
            }

            _config.DiscordBotToken = newToken;
            _config.DiscordGuildId  = newGuildId;

            ValidateDiscordCredentials(ok =>
            {
                if (!ok)
                {
                    player?.Reply("Discord validation failed. Check the bot token, ensure the bot is in the guild, and the GuildId is correct.");
                    LogFailure("Discord validation failed. Token or GuildId incorrect, or bot not in guild.");
                    return;
                }

                SaveConfigTyped();
                player?.Reply($"Discord link saved and validated. GuildId={_config.DiscordGuildId}. Rechecking prerequisites...");
                Puts("[NitroBoostLinker] Discord credentials validated and saved.");

                ReevaluateHardFailPrereqs();
                if (_hardDisabled)
                {
                    if (player != null) player.Reply($"Still disabled: {_hardDisabledReason}");
                    LogFailure($"Still disabled: {_hardDisabledReason}");
                }
                else
                {
                    if (player != null) player.Reply("Plugin is now ENABLED.");
                    Puts("[NitroBoostLinker] Plugin is now ENABLED.");
                }
            });
        }

        /// Health/diagnostics: shows dependency + config status; allowed anytime.
        /// Usage: /nitrodiag
        private void CmdNitroDiag(IPlayer player, string command, string[] args)
        {
            if (!(player == null || player.IsServer || player.IsAdmin))
            {
                player?.Reply("You must be an admin (or console/RCON) to use this.");
                return;
            }

            var imageLib = IsImageLibraryPresent();
            var rustKits = IsRustKitsPresent();
            var cak      = IsCustomAutoKitsPresent();
            var discord  = !string.IsNullOrWhiteSpace(_config.DiscordBotToken) && _config.DiscordGuildId != 0;

            var sb = new StringBuilder();
            sb.AppendLine("<color=#9be7ff>— NitroBoostLinker Diagnostics —</color>");
            sb.AppendLine($"Version: {DisplayVersion}");
            sb.AppendLine($"Status: {(_hardDisabled ? $"<color=#ff7777>DISABLED</color> — {_hardDisabledReason}" : "<color=#77ff77>ENABLED</color>")}");
            sb.AppendLine($"Image Library loaded: {(imageLib ? "<color=#77ff77>Yes</color>" : "<color=#ff7777>No</color>")}");
            sb.AppendLine($"Rust Kits loaded: {(rustKits ? "<color=#77ff77>Yes</color>" : "<color=#ff7777>No</color>")}");
            sb.AppendLine($"Custom Auto Kits loaded: {(cak ? "<color=#77ff77>Yes</color>" : "<color=#ff7777>No</color>")}");
            sb.AppendLine($"Discord configured: {(discord ? "<color=#77ff77>Yes</color>" : "<color=#ff7777>No</color>")}");
            sb.AppendLine($"Booster role (ID): {(_config.BoosterRoleId != 0 ? _config.BoosterRoleId.ToString() : "n/a")}   Name: {(_config.BoosterRoleName ?? "n/a")}");
            sb.AppendLine($"Permission name: '{_config.OxidePermissionName}'   Group: '{_config.OxideGroupName}' (create={_config.AlsoCreateOxideGroup}, existing-only={_config.GrantGroupIfExistsOnly})");
            sb.AppendLine($"Revalidation interval (min): {_config.RevalidationIntervalMinutes}");
            sb.AppendLine($"Rate limit (per-player/min): {_config.RateLimitPerPlayerPerMinute}");

            var msg = sb.ToString();
            if (player != null) player.Reply(msg);
            Puts(StripRichText(msg)); // console & rust log
            LogToFile(LogFile, $"[{DateTime.UtcNow:u}] DIAG: {StripRichText(msg)}", this);
        }

        private string StripRichText(string s)
        {
            return s.Replace("<color=#9be7ff>", "").Replace("<color=#77ff77>", "")
                    .Replace("<color=#ff7777>", "").Replace("</color>", "");
        }

        #endregion

        #region Verification / Scheduling

        private void ResyncPlayer(string steamId, Action<bool> done)
        {
            if (_hardDisabled) { done?.Invoke(false); return; }
            if (!_linked.TryGetValue(steamId, out var link)) { done?.Invoke(false); return; }

            CheckMemberBoostOrRole(link.DiscordUserId, result =>
            {
                if (result == null) { done?.Invoke(false); return; }

                var (isBoostingByPremium, premiumSince, hasBoosterRole) = result.Value;
                link.LastVerifiedUtc = DateTime.UtcNow;
                link.IsBoosting = (isBoostingByPremium || hasBoosterRole);
                link.LastKnownPremiumSince = premiumSince;
                SaveData();

                if (link.IsBoosting) GrantVip(steamId);
                else RevokeVip(steamId);

                done?.Invoke(true);
            });
        }

        private void ScheduleRevalidation()
        {
            var seconds = Math.Max(60, _config.RevalidationIntervalMinutes * 60);
            timer.Every(seconds, () =>
            {
                if (_hardDisabled) return;
                foreach (var kv in _linked)
                    ResyncPlayer(kv.Key, null);
            });
        }

        #endregion

        #region Discord REST

        private class CreateDMResponse { [JsonProperty("id")] public string Id; }

        private class GuildMember
        {
            [JsonProperty("user")]          public DiscordUser User;
            [JsonProperty("premium_since")] public DateTime? PremiumSince;
            [JsonProperty("roles")]         public List<string> Roles;
        }

        private class DiscordUser
        {
            [JsonProperty("id")]          public string Id;
            [JsonProperty("username")]    public string Username;
            [JsonProperty("global_name")] public string GlobalName;
        }

        private class GuildRole
        {
            [JsonProperty("id")]   public string Id;
            [JsonProperty("name")] public string Name;
        }

        private bool HttpOK(int code) => code >= 200 && code < 300;

        private Dictionary<string, string> AuthHeaders() =>
            new Dictionary<string, string> { ["Authorization"] = $"Bot {_config.DiscordBotToken}" };

        private void ValidateDiscordCredentials(Action<bool> cb)
        {
            var meUrl = $"{_config.DiscordApiBase}/users/@me";
            webrequest.Enqueue(meUrl, null, (s1, r1) =>
            {
                if (!HttpOK(s1)) { cb?.Invoke(false); return; }

                var guildUrl = $"{_config.DiscordApiBase}/guilds/{_config.DiscordGuildId}";
                webrequest.Enqueue(guildUrl, null, (s2, r2) =>
                {
                    cb?.Invoke(HttpOK(s2));
                }, this, RequestMethod.GET, AuthHeaders(), _config.HttpTimeoutSeconds);

            }, this, RequestMethod.GET, AuthHeaders(), _config.HttpTimeoutSeconds);
        }

        private void SendVerificationDM(ulong discordUserId, string code, Action<bool> cb)
        {
            if (_hardDisabled) { cb?.Invoke(false); return; }

            var dmUrl = $"{_config.DiscordApiBase}/users/@me/channels";
            var headers = AuthHeaders();
            headers["Content-Type"] = "application/json";
            var body = JsonConvert.SerializeObject(new Dictionary<string, object> { ["recipient_id"] = discordUserId.ToString() });

            webrequest.Enqueue(dmUrl, body, (status, resp) =>
            {
                if (!HttpOK(status))
                {
                    if (_config.DebugLogging) LogFailure($"CreateDM failed ({status}): {resp}");
                    cb?.Invoke(false);
                    return;
                }

                CreateDMResponse dm = null;
                try { dm = JsonConvert.DeserializeObject<CreateDMResponse>(resp); }
                catch (Exception e) { if (_config.DebugLogging) LogFailure($"CreateDM parse error: {e.Message}"); }

                if (dm == null || string.IsNullOrEmpty(dm.Id)) { cb?.Invoke(false); return; }

                var msgUrl = $"{_config.DiscordApiBase}/channels/{dm.Id}/messages";
                var msg = _config.SendDMTemplate.Replace("{CODE}", code);
                var msgBody = JsonConvert.SerializeObject(new Dictionary<string, object> { ["content"] = msg });

                webrequest.Enqueue(msgUrl, msgBody, (s2, r2) =>
                {
                    if (!HttpOK(s2))
                    {
                        if (_config.DebugLogging) LogFailure($"Send DM failed ({s2}): {r2}");
                        cb?.Invoke(false); return;
                    }
                    cb?.Invoke(true);
                }, this, RequestMethod.POST, headers, _config.HttpTimeoutSeconds);

            }, this, RequestMethod.POST, headers, _config.HttpTimeoutSeconds);
        }

        private void CheckMemberBoostOrRole(ulong discordUserId, Action<(bool, DateTime?, bool)?> cb)
        {
            if (_hardDisabled) { cb?.Invoke(null); return; }

            ResolveBoosterRoleIdIfNeeded(() =>
            {
                var url = $"{_config.DiscordApiBase}/guilds/{_config.DiscordGuildId}/members/{discordUserId}";
                webrequest.Enqueue(url, null, (status, resp) =>
                {
                    if (!HttpOK(status)) { if (_config.DebugLogging) LogFailure($"GET member failed ({status}): {resp}"); cb?.Invoke(null); return; }

                    try
                    {
                        var member = JsonConvert.DeserializeObject<GuildMember>(resp);
                        var premium = _config.TreatPremiumSinceAsBoost && (member?.PremiumSince != null);
                        var roleOk = false;

                        if (_config.UseBoosterRoleCheck)
                        {
                            var targetRole = _config.BoosterRoleId != 0 ? _config.BoosterRoleId : _boosterRoleIdResolved;
                            if (targetRole != 0 && member?.Roles != null)
                            {
                                foreach (var rid in member.Roles)
                                {
                                    if (ulong.TryParse(rid, out var id) && id == targetRole) { roleOk = true; break; }
                                }
                            }
                        }

                        cb?.Invoke((premium, member?.PremiumSince, roleOk));
                    }
                    catch (Exception e)
                    {
                        if (_config.DebugLogging) LogFailure($"Member parse error: {e.Message}");
                        cb?.Invoke(null);
                    }
                }, this, RequestMethod.GET, AuthHeaders(), _config.HttpTimeoutSeconds);
            });
        }

        private void ResolveBoosterRoleIdIfNeeded(Action done)
        {
            if (!_config.UseBoosterRoleCheck) { done?.Invoke(); return; }
            if (_config.BoosterRoleId != 0 || string.IsNullOrWhiteSpace(_config.BoosterRoleName)) { done?.Invoke(); return; }

            if (_boosterRoleIdResolved != 0 && (DateTime.UtcNow - _roleCacheTimeUtc).TotalMinutes < 30) { done?.Invoke(); return; }

            var url = $"{_config.DiscordApiBase}/guilds/{_config.DiscordGuildId}/roles";
            webrequest.Enqueue(url, null, (status, resp) =>
            {
                if (!HttpOK(status)) { if (_config.DebugLogging) LogFailure($"GET roles failed ({status}): {resp}"); done?.Invoke(); return; }

                try
                {
                    var roles = JsonConvert.DeserializeObject<List<GuildRole>>(resp) ?? new List<GuildRole>();
                    foreach (var role in roles)
                    {
                        if (string.Equals(role.Name, _config.BoosterRoleName, StringComparison.OrdinalIgnoreCase) &&
                            ulong.TryParse(role.Id, out var id))
                        {
                            _boosterRoleIdResolved = id;
                            _roleCacheTimeUtc = DateTime.UtcNow;
                            break;
                        }
                    }
                }
                catch (Exception e) { if (_config.DebugLogging) LogFailure($"Roles parse error: {e.Message}"); }

                done?.Invoke();
            }, this, RequestMethod.GET, AuthHeaders(), _config.HttpTimeoutSeconds);
        }

        #endregion

        #region Persistence / Permissions

        private void LoadData()
        {
            _linked = Interface.Oxide.DataFileSystem.ReadObject<Dictionary<string, LinkRecord>>(LinksFile) ?? new Dictionary<string, LinkRecord>();
            var pendingList = Interface.Oxide.DataFileSystem.ReadObject<List<PendingRecord>>(PendingFile) ?? new List<PendingRecord>();

            _pendingBySteam = new Dictionary<string, PendingRecord>();
            _pendingByCode  = new Dictionary<string, PendingRecord>();
            var now = DateTime.UtcNow;
            foreach (var p in pendingList)
            {
                if (p != null && p.ExpiresUtc > now)
                {
                    _pendingBySteam[p.SteamId] = p;
                    _pendingByCode[p.Code] = p;
                }
            }
        }

        private void SaveData()
        {
            Interface.Oxide.DataFileSystem.WriteObject(LinksFile, _linked);
            Interface.Oxide.DataFileSystem.WriteObject(PendingFile, new List<PendingRecord>(_pendingBySteam.Values));
        }

        private void GrantVip(string steamId)
        {
            if (!permission.UserHasPermission(steamId, _config.OxidePermissionName))
                permission.GrantUserPermission(steamId, _config.OxidePermissionName, this);

            if (_config.AlsoCreateOxideGroup)
            {
                var groupExists = permission.GroupExists(_config.OxideGroupName);
                if (groupExists || !_config.GrantGroupIfExistsOnly)
                {
                    if (!groupExists) permission.CreateGroup(_config.OxideGroupName, _config.OxideGroupName, 0);
                    permission.AddUserGroup(steamId, _config.OxideGroupName);
                }
            }
        }

        private void RevokeVip(string steamId)
        {
            if (permission.UserHasPermission(steamId, _config.OxidePermissionName))
                permission.RevokeUserPermission(steamId, _config.OxidePermissionName);

            if (_config.AlsoCreateOxideGroup && permission.GroupExists(_config.OxideGroupName))
                permission.RemoveUserGroup(steamId, _config.OxideGroupName);
        }

        #endregion

        #region Utilities

        private string GenerateCode(int length)
        {
            const string alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
            var bytes = new byte[length];
            new System.Security.Cryptography.RNGCryptoServiceProvider().GetBytes(bytes);
            var sb = new StringBuilder(length);
            foreach (var b in bytes) sb.Append(alphabet[b % alphabet.Length]);
            return sb.ToString();
        }

        private void CleanupPending(PendingRecord pending)
        {
            if (pending == null) return;
            _pendingBySteam.Remove(pending.SteamId);
            _pendingByCode.Remove(pending.Code);
            SaveData();
        }

        private bool CheckRate(IPlayer player)
        {
            if (player == null) return true; // console/RCON not rate-limited

            if (!_rate.TryGetValue(player.Id, out var list))
            {
                list = new List<DateTime>();
                _rate[player.Id] = list;
            }

            var now = DateTime.UtcNow;
            list.RemoveAll(t => (now - t).TotalSeconds > 60);
            if (list.Count >= _config.RateLimitPerPlayerPerMinute)
            {
                player.Reply("You’re doing that too often; try again in a minute.");
                return false;
            }
            list.Add(now);
            return true;
        }

        private IPlayer FindPlayer(string nameOrId)
        {
            foreach (var p in players.Connected)
            {
                if (p == null) continue;
                if (p.Id == nameOrId) return p;
                if (!string.IsNullOrEmpty(p.Name) &&
                    p.Name.IndexOf(nameOrId, StringComparison.OrdinalIgnoreCase) >= 0) return p;
            }
            return players.FindPlayer(nameOrId);
        }

        private bool IsImageLibraryPresent()
        {
            if (ImageLibrary != null) return true;
            foreach (var name in _config.ImageLibraryPluginNames)
            {
                var found = plugins.Find(name);
                if (found != null) return true;
            }
            return false;
        }

        private bool IsRustKitsPresent()
        {
            if (Kits != null) return true;
            foreach (var name in _config.RustKitsPluginNames)
            {
                var found = plugins.Find(name);
                if (found != null) return true;
            }
            return false;
        }

        private bool IsCustomAutoKitsPresent()
        {
            if (CustomAutoKits != null) return true;
            foreach (var name in _config.CustomAutoKitsPluginNames)
            {
                var found = plugins.Find(name);
                if (found != null) return true;
            }
            return false;
        }

        #endregion
    }
}
