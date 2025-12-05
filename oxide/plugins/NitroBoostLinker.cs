// NitroBoostLinker.cs
// MIT License
// (c) 2025 Gabriel Dungan (github.com/gjdunga)

using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Newtonsoft.Json;
using Oxide.Core;
using Oxide.Core.Libraries;
using Oxide.Core.Libraries.Covalence;
using Oxide.Core.Plugins;

namespace Oxide.Plugins
{
    [Info("Nitro Boost Linker", "Gabriel", "1.5.2")]
    [Description("Grants a NitroBoost permission when a linked Discord user is boosting your guild or has a Booster role. Hard-fails if prerequisites are missing (Image Library + Rust Kits + Custom Auto Kits + Discord config). Includes /nitrodiag and verbose logging.")]
    public class NitroBoostLinker : CovalencePlugin
    {
        // Display metadata for help and diagnostics
        private const string DisplayVersion = "1.5.2 (build)";
        private const string DisplayAuthor  = "Gabriel — MIT License";

        // Helpful URLs for required plugins
        private const string UrlImageLibrary = "https://umod.org/plugins/image-library";
        private const string UrlRustKits     = "https://umod.org/plugins/rust-kits";
        private const string UrlCustomKits   = "https://umod.org/plugins/custom-auto-kits";

        // Soft references to required plugins (null when not loaded)
        [PluginReference] private Plugin ImageLibrary;   // Image Library (dependency of Rust Kits)
        [PluginReference] private Plugin Kits;           // Rust Kits
        [PluginReference] private Plugin CustomAutoKits; // Custom Auto Kits

        // Hard-disable state
        private bool _hardDisabled       = true;
        private string _hardDisabledReason = "Not initialized";

        // Log file name for plugin-specific log
        private const string LogFile = "NitroBoostLinker";

        #region Configuration

        private PluginConfig _config;

        private class PluginConfig
        {
            // Discord / guild configuration
            [JsonProperty("DiscordBotToken")] public string DiscordBotToken = string.Empty;
            [JsonProperty("DiscordGuildId")]  public ulong DiscordGuildId = 0;

            // Oxide permission + group
            [JsonProperty("OxidePermissionName")] public string OxidePermissionName = "NitroBoost";
            [JsonProperty("AlsoCreateOxideGroup")] public bool AlsoCreateOxideGroup = true;
            [JsonProperty("OxideGroupName")]      public string OxideGroupName = "NitroBoost";
            [JsonProperty("GrantGroupIfExistsOnly")] public bool GrantGroupIfExistsOnly = true;

            // Booster or premium logic
            [JsonProperty("TreatPremiumSinceAsBoost")] public bool TreatPremiumSinceAsBoost = true;
            [JsonProperty("UseBoosterRoleCheck")]     public bool UseBoosterRoleCheck = true;
            [JsonProperty("BoosterRoleId")]           public ulong BoosterRoleId = 0;
            [JsonProperty("BoosterRoleName")]         public string BoosterRoleName = string.Empty;

            // Verification flow
            [JsonProperty("VerificationCodeLength")]     public int VerificationCodeLength = 6;
            [JsonProperty("VerificationCodeTTLSeconds")] public int VerificationCodeTTLSeconds = 600;

            // Periodic revalidation
            [JsonProperty("RevalidationIntervalMinutes")] public int RevalidationIntervalMinutes = 60;
            // Rate limiting
            [JsonProperty("RateLimitPerPlayerPerMinute")] public int RateLimitPerPlayerPerMinute = 6;

            // Discord API details
            [JsonProperty("DiscordApiBase")]     public string DiscordApiBase = "https://discord.com/api/v10";
            [JsonProperty("HttpTimeoutSeconds")] public int HttpTimeoutSeconds = 15;

            // DM template for verification
            [JsonProperty("SendDMTemplate")]
            public string SendDMTemplate =
                "Your Rust verification code is: **{CODE}**\n" +
                "Return to the server and run: `/nitroverify {CODE}`";

            [JsonProperty("DebugLogging")] public bool DebugLogging = false;

            // Dependency resolution lists (names to probe)
            [JsonProperty("ImageLibraryPluginNames")]
            public string[] ImageLibraryPluginNames = { "ImageLibrary", "Image Library", "image-library" };
            [JsonProperty("RustKitsPluginNames")]
            public string[] RustKitsPluginNames = { "Kits", "Rust Kits", "rust-kits" };
            [JsonProperty("CustomAutoKitsPluginNames")]
            public string[] CustomAutoKitsPluginNames = { "Custom Auto Kits", "CustomAutoKits", "custom-auto-kits" };

            // Hard-fail messages for missing prerequisites
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
                "[NitroBoostLinker] HARD-FAIL: Discord bot token and/or guild ID are not configured. " +
                "Use /nitrodiscordbotlink <BotToken> <GuildId> [BoosterRoleId|RoleName] from console/RCON/in-game (admin).";
        }

        protected override void LoadDefaultConfig()
        {
            LogWarning("Generating default configuration...");
            _config = new PluginConfig();
            SaveConfigTyped();
        }

        private void LoadConfigTyped()
        {
            try
            {
                _config = Config.ReadObject<PluginConfig>();
                if (_config == null) throw new Exception("Config deserialized as null");
            }
            catch
            {
                LogWarning("Config invalid; regenerating defaults.");
                LoadDefaultConfig();
            }
        }

        private void SaveConfigTyped() => Config.WriteObject(_config, true);

        #endregion

        #region Data & State

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

        private Dictionary<string, LinkRecord>   _linked = new Dictionary<string, LinkRecord>();
        private Dictionary<string, PendingRecord> _pendingBySteam = new Dictionary<string, PendingRecord>();
        private Dictionary<string, PendingRecord> _pendingByCode = new Dictionary<string, PendingRecord>();

        // Rate limiting: steamId -> list of timestamps
        private readonly Dictionary<string, List<DateTime>> _rate = new Dictionary<string, List<DateTime>>();

        // Booster role ID resolution cache
        private ulong   _boosterRoleIdResolved;
        private DateTime _roleCacheTimeUtc = DateTime.MinValue;

        #endregion

        #region Hooks / Lifecycle

        private void Init()
        {
            LoadConfigTyped();
            RegisterPermissions();
            LoadData();

            // Register commands
            AddCovalenceCommand("nitrolink", nameof(CmdNitroLink));
            AddCovalenceCommand("nitroverify", nameof(CmdNitroVerify));
            AddCovalenceCommand("nitrostatus", nameof(CmdNitroStatus));
            AddCovalenceCommand("nitroresync", nameof(CmdNitroResync));
            AddCovalenceCommand("nitrodiscordbotlink", nameof(CmdNitroDiscordBotLink));
            AddCovalenceCommand("nitrodiag", nameof(CmdNitroDiag));

            ScheduleRevalidation();
        }

        private void OnServerInitialized()
        {
            // Delay evaluation until Rust & dependent plugins fully load
            ReevaluateHardFailPrereqs();
        }

        private void OnPluginLoaded(Plugin plugin)
        {
            if (plugin == null) return;
            // Re-evaluate prerequisites if a dependency loads late
            if (MatchesDependency(plugin.Name))
                ReevaluateHardFailPrereqs();
        }

        private void OnPluginUnloaded(Plugin plugin)
        {
            if (plugin == null) return;
            // Re-evaluate when dependency unloads
            if (MatchesDependency(plugin.Name))
                ReevaluateHardFailPrereqs();
        }

        private void Unload()
        {
            SaveData();
        }

        private void RegisterPermissions()
        {
            if (string.IsNullOrWhiteSpace(_config.OxidePermissionName))
                _config.OxidePermissionName = "NitroBoost";

            permission.RegisterPermission(_config.OxidePermissionName, this);

            if (_config.AlsoCreateOxideGroup && !_config.GrantGroupIfExistsOnly)
            {
                if (!permission.GroupExists(_config.OxideGroupName))
                    permission.CreateGroup(_config.OxideGroupName, _config.OxideGroupName, 0);
            }
        }

        #endregion

        #region Hard-fail logic & logging

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

            _hardDisabled       = false;
            _hardDisabledReason = string.Empty;
        }

        private void LogFailure(string message)
        {
            PrintError(message);                      // Console + Rust log
            Interface.Oxide.LogError(message);        // Oxide global error log
            LogToFile(LogFile, $"[{DateTime.UtcNow:u}] {message}", this); // Plugin-specific log
        }

        private void HardDisable(string reason)
        {
            _hardDisabled       = true;
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

        /// <summary>
        /// Returns true if command execution is blocked due to hard-disabled state and notifies player
        /// </summary>
        private bool BarkIfHardDisabled(IPlayer player)
        {
            if (!_hardDisabled) return false;

            if (player != null)
            {
                player.Reply(_hardDisabledReason);
            }
            LogFailure(_hardDisabledReason);
            return true;
        }

        #endregion

        #region Commands

        private void CmdNitroLink(IPlayer player, string command, string[] args)
        {
            if (player == null || !player.IsConnected) return;

            // Show help any time
            if (args.Length == 1 && args[0].Equals("help", StringComparison.OrdinalIgnoreCase))
            {
                player.Reply(
                    $"— Nitro Link Help —\n" +
                    $"Version: {DisplayVersion}\n" +
                    $"Author: {DisplayAuthor}\n\n" +
                    "Required plugins (must be installed & loaded):\n" +
                    $" • Image Library — {UrlImageLibrary}\n" +
                    $" • Rust Kits — {UrlRustKits}\n" +
                    $" • Custom Auto Kits — {UrlCustomKits}\n\n" +
                    "Steps:\n" +
                    " 1) In Discord, enable Developer Mode → right-click yourself → Copy User ID.\n" +
                    " 2) In chat: /nitrolink <DiscordUserID>\n" +
                    " 3) Check the DM from the bot for your code.\n" +
                    " 4) In chat: /nitroverify <CODE>\n\n" +
                    "VIP unlocks when:\n" +
                    " • You’re actively boosting the guild (premium_since), OR\n" +
                    " • You have the configured Booster role.\n\n" +
                    "See status with: /nitrostatus"
                );

                if (_hardDisabled)
                    BarkIfHardDisabled(player);

                return;
            }

            if (BarkIfHardDisabled(player)) return;
            if (!CheckRate(player)) return;

            if (args.Length != 1)
            {
                player.Reply("Usage: /nitrolink <DiscordUserID>  — or —  /nitrolink help");
                return;
            }

            if (!ulong.TryParse(args[0], out ulong discordUserId))
            {
                player.Reply("That does not look like a valid Discord User ID.");
                return;
            }

            string steamId = player.Id;

            if (_linked.TryGetValue(steamId, out LinkRecord existing))
            {
                player.Reply(
                    $"Already linked to Discord ID `{existing.DiscordUserId}`.\n" +
                    "Use /nitrostatus or ask an admin for /nitroresync."
                );
                return;
            }

            string code = GenerateCode(_config.VerificationCodeLength);
            DateTime now = DateTime.UtcNow;

            var pending = new PendingRecord
            {
                SteamId      = steamId,
                DiscordUserId = discordUserId,
                Code         = code,
                CreatedUtc   = now,
                ExpiresUtc   = now.AddSeconds(_config.VerificationCodeTTLSeconds)
            };

            if (_pendingBySteam.TryGetValue(steamId, out PendingRecord oldPending))
            {
                _pendingByCode.Remove(oldPending.Code);
            }

            _pendingBySteam[steamId] = pending;
            _pendingByCode[code]     = pending;
            SaveData();

            SendVerificationDM(discordUserId, code, ok =>
            {
                if (!ok)
                {
                    player.Reply(
                        "I couldn't DM that Discord user.\n" +
                        "Check the ID and whether the user allows DMs from the bot."
                    );

                    _pendingBySteam.Remove(steamId);
                    _pendingByCode.Remove(code);
                    SaveData();
                    return;
                }

                int minutes = Math.Max(1, _config.VerificationCodeTTLSeconds / 60);

                player.Reply(
                    $"I DM’d a verification code to `{discordUserId}`.\n" +
                    $"Run `/nitroverify {code}` within {minutes} minute(s)."
                );
            });
        }

        private void CmdNitroVerify(IPlayer player, string command, string[] args)
        {
            if (player == null || !player.IsConnected) return;

            if (BarkIfHardDisabled(player)) return;
            if (!CheckRate(player)) return;

            if (args.Length != 1)
            {
                player.Reply("Usage: /nitroverify <CODE>");
                return;
            }

            string code = args[0].Trim();

            if (!_pendingByCode.TryGetValue(code, out PendingRecord pending))
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
                if (result == null)
                {
                    player.Reply("I couldn't verify your guild status right now. Try again shortly.");
                    return;
                }

                var (isBoostingByPremium, premiumSince, hasBoosterRole) = result.Value;
                bool qualifies = isBoostingByPremium || hasBoosterRole;

                var now = DateTime.UtcNow;

                var record = new LinkRecord
                {
                    SteamId               = player.Id,
                    DiscordUserId         = pending.DiscordUserId,
                    LinkedAtUtc           = now,
                    LastVerifiedUtc       = now,
                    IsBoosting            = qualifies,
                    LastKnownPremiumSince = premiumSince
                };

                _linked[player.Id] = record;

                CleanupPending(pending);
                SaveData();

                if (qualifies)
                {
                    GrantVip(player.Id);

                    string reason = isBoostingByPremium
                        ? "Nitro boost detected"
                        : "Booster role detected";

                    player.Reply(
                        $"Linked ✅ — {reason}! You now have the `{_config.OxidePermissionName}` permission."
                    );
                }
                else
                {
                    player.Reply(
                        "Linked ✅ but neither Nitro boost nor Booster role were found.\n" +
                        "Once that changes, the permission will be granted on re-check."
                    );
                }
            });
        }

        private void CmdNitroStatus(IPlayer player, string command, string[] args)
        {
            if (player == null || !player.IsConnected) return;

            if (_linked.TryGetValue(player.Id, out LinkRecord link))
            {
                string premiumSince = link.LastKnownPremiumSince?.ToString("u") ?? "n/a";

                if (_hardDisabled)
                {
                    player.Reply(
                        $"[DISABLED] Reason: {_hardDisabledReason}\n" +
                        $"Discord ID: `{link.DiscordUserId}`\n" +
                        $"Boost/Role OK: {(link.IsBoosting ? "Yes" : "No")}\n" +
                        $"Premium Since: {premiumSince}\n" +
                        $"Last Verified: {link.LastVerifiedUtc:u}"
                    );
                }
                else
                {
                    player.Reply(
                        $"Discord ID: `{link.DiscordUserId}`\n" +
                        $"Boost/Role OK: {(link.IsBoosting ? "Yes" : "No")}\n" +
                        $"Premium Since: {premiumSince}\n" +
                        $"Last Verified: {link.LastVerifiedUtc:u}"
                    );
                }
            }
            else
            {
                if (_hardDisabled)
                {
                    player.Reply(
                        $"[DISABLED] Reason: {_hardDisabledReason}\n" +
                        "Not linked. Use: /nitrolink help"
                    );
                }
                else
                {
                    player.Reply("Not linked. Use: /nitrolink <DiscordUserID> (or /nitrolink help).");
                }
            }
        }

        private void CmdNitroResync(IPlayer player, string command, string[] args)
        {
            // Admin/console only
            if (player != null && !player.IsServer && !player.IsAdmin)
            {
                player.Reply("You must be an admin to use this.");
                return;
            }

            if (BarkIfHardDisabled(player)) return;

            // /nitroresync <player>
            if (args.Length == 1)
            {
                IPlayer target = FindPlayer(args[0]);

                if (target == null)
                {
                    player?.Reply("Player not found.");
                    return;
                }

                ResyncPlayer(target.Id, ok =>
                {
                    player?.Reply(ok
                        ? $"Resynced {target.Name}."
                        : $"Failed to resync {target.Name}.");
                });

                return;
            }

            // /nitroresync  (all)
            int total = 0;

            foreach (KeyValuePair<string, LinkRecord> kv in _linked)
            {
                total++;
                ResyncPlayer(kv.Key, null);
            }

            player?.Reply($"Queued revalidation for {total} linked accounts.");
        }

        /// <summary>
        /// Discord runtime setup from console / RCON / admin.
        /// Usage: /nitrodiscordbotlink <BotToken> <GuildId> [BoosterRoleId|RoleName]
        /// </summary>
        private void CmdNitroDiscordBotLink(IPlayer player, string command, string[] args)
        {
            if (!(player == null || player.IsServer || player.IsAdmin))
            {
                player?.Reply("You must be an admin (or console/RCON) to use this.");
                return;
            }

            if (args.Length < 2)
            {
                string usage = "Usage: /nitrodiscordbotlink <BotToken> <GuildId> [BoosterRoleId|RoleName]";
                player?.Reply(usage);
                LogFailure(usage);
                return;
            }

            string newToken = args[0];

            if (!ulong.TryParse(args[1], out ulong newGuildId) || newGuildId == 0)
            {
                player?.Reply("GuildId must be a non-zero unsigned integer.");
                return;
            }

            if (args.Length >= 3)
            {
                if (ulong.TryParse(args[2], out ulong roleId))
                {
                    _config.BoosterRoleId   = roleId;
                    _config.BoosterRoleName = string.Empty;
                }
                else
                {
                    _config.BoosterRoleName = args[2];
                    _config.BoosterRoleId   = 0;
                }
            }

            _config.DiscordBotToken = newToken;
            _config.DiscordGuildId  = newGuildId;

            ValidateDiscordCredentials(ok =>
            {
                if (!ok)
                {
                    player?.Reply(
                        "Discord validation failed.\n" +
                        "Check the bot token, ensure the bot is in the guild, and the GuildId is correct."
                    );

                    LogFailure("Discord validation failed. Token or GuildId incorrect, or bot not in guild.");
                    return;
                }

                SaveConfigTyped();

                player?.Reply(
                    $"Discord link saved and validated. GuildId={_config.DiscordGuildId}.\n" +
                    "Rechecking prerequisites..."
                );

                Puts("[NitroBoostLinker] Discord credentials validated and saved.");

                ReevaluateHardFailPrereqs();

                if (_hardDisabled)
                {
                    player?.Reply($"Still disabled: {_hardDisabledReason}");
                    LogFailure($"Still disabled: {_hardDisabledReason}");
                }
                else
                {
                    player?.Reply("Plugin is now ENABLED.");
                    Puts("[NitroBoostLinker] Plugin is now ENABLED.");
                }
            });
        }

        /// <summary>
        /// Health/diagnostics: dependency + config status.
        /// Usage: /nitrodiag
        /// </summary>
        private void CmdNitroDiag(IPlayer player, string command, string[] args)
        {
            if (!(player == null || player.IsServer || player.IsAdmin))
            {
                player?.Reply("You must be an admin (or console/RCON) to use this.");
                return;
            }

            bool imageLib = IsImageLibraryPresent();
            bool rustKits = IsRustKitsPresent();
            bool cak      = IsCustomAutoKitsPresent();

            bool discordConfigured = !string.IsNullOrWhiteSpace(_config.DiscordBotToken) && _config.DiscordGuildId != 0;

            var sb = new StringBuilder();
            sb.AppendLine("— NitroBoostLinker Diagnostics —");
            sb.AppendLine($"Version: {DisplayVersion}");
            sb.AppendLine($"Status: {(_hardDisabled ? $"DISABLED — {_hardDisabledReason}" : "ENABLED")}");
            sb.AppendLine($"Image Library loaded: {(imageLib ? "Yes" : "No")}");
            sb.AppendLine($"Rust Kits loaded: {(rustKits ? "Yes" : "No")}");
            sb.AppendLine($"Custom Auto Kits loaded: {(cak ? "Yes" : "No")}");
            sb.AppendLine($"Discord configured: {(discordConfigured ? "Yes" : "No")}");
            sb.AppendLine(
                $"Booster role (ID): {(_config.BoosterRoleId != 0 ? _config.BoosterRoleId.ToString() : "n/a")} " +
                $"Name: {(_config.BoosterRoleName ?? "n/a")}"
            );
            sb.AppendLine(
                $"Permission name: '{_config.OxidePermissionName}' " +
                $"Group: '{_config.OxideGroupName}' " +
                $"(create={_config.AlsoCreateOxideGroup}, existing-only={_config.GrantGroupIfExistsOnly})"
            );
            sb.AppendLine($"Revalidation interval (min): {_config.RevalidationIntervalMinutes}");
            sb.AppendLine($"Rate limit (per-player/min): {_config.RateLimitPerPlayerPerMinute}");

            string msg = sb.ToString();
            player?.Reply(msg);
            Puts(StripRichText(msg));
            LogToFile(LogFile, $"[{DateTime.UtcNow:u}] DIAG: {StripRichText(msg)}", this);
        }

        #endregion

        #region Verification / Scheduling

        private void ResyncPlayer(string steamId, Action<bool> done)
        {
            if (_hardDisabled)
            {
                done?.Invoke(false);
                return;
            }

            if (!_linked.TryGetValue(steamId, out LinkRecord link))
            {
                done?.Invoke(false);
                return;
            }

            CheckMemberBoostOrRole(link.DiscordUserId, result =>
            {
                if (result == null)
                {
                    done?.Invoke(false);
                    return;
                }

                var (isBoostingByPremium, premiumSince, hasBoosterRole) = result.Value;

                link.LastVerifiedUtc       = DateTime.UtcNow;
                link.IsBoosting            = isBoostingByPremium || hasBoosterRole;
                link.LastKnownPremiumSince = premiumSince;

                SaveData();

                if (link.IsBoosting)
                    GrantVip(steamId);
                else
                    RevokeVip(steamId);

                done?.Invoke(true);
            });
        }

        private void ScheduleRevalidation()
        {
            int seconds = Math.Max(60, _config.RevalidationIntervalMinutes * 60);

            timer.Every(seconds, () =>
            {
                if (_hardDisabled) return;

                foreach (KeyValuePair<string, LinkRecord> kv in _linked.ToArray())
                {
                    ResyncPlayer(kv.Key, null);
                }
            });
        }

        #endregion

        #region Discord REST

        private class CreateDMResponse
        {
            [JsonProperty("id")] public string Id;
        }

        private class DiscordUser
        {
            [JsonProperty("id")]          public string Id;
            [JsonProperty("username")]    public string Username;
            [JsonProperty("global_name")] public string GlobalName;
        }

        private class GuildMember
        {
            [JsonProperty("user")]          public DiscordUser User;
            [JsonProperty("premium_since")] public DateTime? PremiumSince;
            [JsonProperty("roles")]         public List<string> Roles;
        }

        private class GuildRole
        {
            [JsonProperty("id")]   public string Id;
            [JsonProperty("name")] public string Name;
        }

        private bool HttpOK(int code)
        {
            return code >= 200 && code < 300;
        }

        private Dictionary<string, string> AuthHeaders()
        {
            return new Dictionary<string, string>
            {
                ["Authorization"] = $"Bot {_config.DiscordBotToken}"
            };
        }

        private void ValidateDiscordCredentials(Action<bool> cb)
        {
            string meUrl = $"{_config.DiscordApiBase}/users/@me";

            webrequest.Enqueue(
                meUrl,
                null,
                (status1, resp1) =>
                {
                    if (!HttpOK(status1))
                    {
                        cb?.Invoke(false);
                        return;
                    }

                    string guildUrl = $"{_config.DiscordApiBase}/guilds/{_config.DiscordGuildId}";

                    webrequest.Enqueue(
                        guildUrl,
                        null,
                        (status2, resp2) =>
                        {
                            cb?.Invoke(HttpOK(status2));
                        },
                        this,
                        RequestMethod.GET,
                        AuthHeaders(),
                        _config.HttpTimeoutSeconds
                    );
                },
                this,
                RequestMethod.GET,
                AuthHeaders(),
                _config.HttpTimeoutSeconds
            );
        }

        private void SendVerificationDM(ulong discordUserId, string code, Action<bool> cb)
        {
            if (_hardDisabled)
            {
                cb?.Invoke(false);
                return;
            }

            string dmUrl = $"{_config.DiscordApiBase}/users/@me/channels";
            var headers  = AuthHeaders();
            headers["Content-Type"] = "application/json";

            var dmBody = new Dictionary<string, string>
            {
                ["recipient_id"] = discordUserId.ToString()
            };

            string bodyJson = JsonConvert.SerializeObject(dmBody);

            webrequest.Enqueue(
                dmUrl,
                bodyJson,
                (status, resp) =>
                {
                    if (!HttpOK(status))
                    {
                        if (_config.DebugLogging)
                            LogFailure($"CreateDM failed ({status}): {resp}");

                        cb?.Invoke(false);
                        return;
                    }

                    CreateDMResponse dm = null;

                    try
                    {
                        dm = JsonConvert.DeserializeObject<CreateDMResponse>(resp);
                    }
                    catch (Exception e)
                    {
                        if (_config.DebugLogging)
                            LogFailure($"CreateDM parse error: {e.Message}");
                    }

                    if (dm == null || string.IsNullOrEmpty(dm.Id))
                    {
                        cb?.Invoke(false);
                        return;
                    }

                    string msgUrl = $"{_config.DiscordApiBase}/channels/{dm.Id}/messages";
                    string msg    = _config.SendDMTemplate.Replace("{CODE}", code);

                    var msgBody = new Dictionary<string, string>
                    {
                        ["content"] = msg
                    };

                    string msgJson = JsonConvert.SerializeObject(msgBody);

                    webrequest.Enqueue(
                        msgUrl,
                        msgJson,
                        (status2, resp2) =>
                        {
                            if (!HttpOK(status2))
                            {
                                if (_config.DebugLogging)
                                    LogFailure($"Send DM failed ({status2}): {resp2}");

                                cb?.Invoke(false);
                                return;
                            }

                            cb?.Invoke(true);
                        },
                        this,
                        RequestMethod.POST,
                        headers,
                        _config.HttpTimeoutSeconds
                    );
                },
                this,
                RequestMethod.POST,
                headers,
                _config.HttpTimeoutSeconds
            );
        }

        /// <summary>
        /// Returns (premium_since-present, premium_since-value, hasBoosterRole).
        /// </summary>
        private void CheckMemberBoostOrRole(ulong discordUserId, Action<(bool, DateTime?, bool)?> cb)
        {
            if (_hardDisabled)
            {
                cb?.Invoke(null);
                return;
            }

            ResolveBoosterRoleIdIfNeeded(() =>
            {
                string url = $"{_config.DiscordApiBase}/guilds/{_config.DiscordGuildId}/members/{discordUserId}";

                webrequest.Enqueue(
                    url,
                    null,
                    (status, resp) =>
                    {
                        if (!HttpOK(status))
                        {
                            if (_config.DebugLogging)
                                LogFailure($"GET member failed ({status}): {resp}");

                            cb?.Invoke(null);
                            return;
                        }

                        try
                        {
                            GuildMember member = JsonConvert.DeserializeObject<GuildMember>(resp);
                            bool premium = _config.TreatPremiumSinceAsBoost && member?.PremiumSince != null;

                            bool roleOk = false;

                            if (_config.UseBoosterRoleCheck)
                            {
                                ulong targetRole = _config.BoosterRoleId != 0
                                    ? _config.BoosterRoleId
                                    : _boosterRoleIdResolved;

                                if (targetRole != 0 && member?.Roles != null)
                                {
                                    foreach (string rid in member.Roles)
                                    {
                                        if (ulong.TryParse(rid, out ulong id) && id == targetRole)
                                        {
                                            roleOk = true;
                                            break;
                                        }
                                    }
                                }
                            }

                            cb?.Invoke((premium, member?.PremiumSince, roleOk));
                        }
                        catch (Exception e)
                        {
                            if (_config.DebugLogging)
                                LogFailure($"Member parse error: {e.Message}");

                            cb?.Invoke(null);
                        }
                    },
                    this,
                    RequestMethod.GET,
                    AuthHeaders(),
                    _config.HttpTimeoutSeconds
                );
            });
        }

        private void ResolveBoosterRoleIdIfNeeded(Action done)
        {
            if (!_config.UseBoosterRoleCheck)
            {
                done?.Invoke();
                return;
            }

            if (_config.BoosterRoleId != 0 || string.IsNullOrWhiteSpace(_config.BoosterRoleName))
            {
                done?.Invoke();
                return;
            }

            if (_boosterRoleIdResolved != 0 && (DateTime.UtcNow - _roleCacheTimeUtc).TotalMinutes < 30)
            {
                done?.Invoke();
                return;
            }

            string url = $"{_config.DiscordApiBase}/guilds/{_config.DiscordGuildId}/roles";

            webrequest.Enqueue(
                url,
                null,
                (status, resp) =>
                {
                    if (!HttpOK(status))
                    {
                        if (_config.DebugLogging)
                            LogFailure($"GET roles failed ({status}): {resp}");

                        done?.Invoke();
                        return;
                    }

                    try
                    {
                        List<GuildRole> roles =
                            JsonConvert.DeserializeObject<List<GuildRole>>(resp) ?? new List<GuildRole>();

                        foreach (GuildRole role in roles)
                        {
                            if (string.Equals(role.Name, _config.BoosterRoleName, StringComparison.OrdinalIgnoreCase) &&
                                ulong.TryParse(role.Id, out ulong id))
                            {
                                _boosterRoleIdResolved = id;
                                _roleCacheTimeUtc      = DateTime.UtcNow;
                                break;
                            }
                        }
                    }
                    catch (Exception e)
                    {
                        if (_config.DebugLogging)
                            LogFailure($"Roles parse error: {e.Message}");
                    }

                    done?.Invoke();
                },
                this,
                RequestMethod.GET,
                AuthHeaders(),
                _config.HttpTimeoutSeconds
            );
        }

        #endregion

        #region Persistence / Permissions

        private void LoadData()
        {
            _linked = Interface.Oxide.DataFileSystem.ReadObject<Dictionary<string, LinkRecord>>(LinksFile)
                      ?? new Dictionary<string, LinkRecord>();

            List<PendingRecord> pendingList =
                Interface.Oxide.DataFileSystem.ReadObject<List<PendingRecord>>(PendingFile)
                ?? new List<PendingRecord>();

            _pendingBySteam = new Dictionary<string, PendingRecord>();
            _pendingByCode  = new Dictionary<string, PendingRecord>();

            DateTime now = DateTime.UtcNow;

            foreach (PendingRecord p in pendingList)
            {
                if (p != null && p.ExpiresUtc > now)
                {
                    _pendingBySteam[p.SteamId] = p;
                    _pendingByCode[p.Code]     = p;
                }
            }
        }

        private void SaveData()
        {
            Interface.Oxide.DataFileSystem.WriteObject(LinksFile, _linked);
            Interface.Oxide.DataFileSystem.WriteObject(PendingFile, _pendingBySteam.Values.ToList());
        }

        private void GrantVip(string steamId)
        {
            if (!permission.UserHasPermission(steamId, _config.OxidePermissionName))
            {
                permission.GrantUserPermission(steamId, _config.OxidePermissionName, this);
            }

            if (_config.AlsoCreateOxideGroup)
            {
                bool groupExists = permission.GroupExists(_config.OxideGroupName);

                if (groupExists || !_config.GrantGroupIfExistsOnly)
                {
                    if (!groupExists)
                        permission.CreateGroup(_config.OxideGroupName, _config.OxideGroupName, 0);

                    permission.AddUserGroup(steamId, _config.OxideGroupName);
                }
            }
        }

        private void RevokeVip(string steamId)
        {
            if (permission.UserHasPermission(steamId, _config.OxidePermissionName))
            {
                permission.RevokeUserPermission(steamId, _config.OxidePermissionName);
            }

            if (_config.AlsoCreateOxideGroup && permission.GroupExists(_config.OxideGroupName))
            {
                permission.RemoveUserGroup(steamId, _config.OxideGroupName);
            }
        }

        #endregion

        #region Utilities

        private string GenerateCode(int length)
        {
            const string alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

            if (length <= 0)
                length = 6;

            var bytes = new byte[length];

            using (var rng = new RNGCryptoServiceProvider())
            {
                rng.GetBytes(bytes);
            }

            var sb = new StringBuilder(length);

            foreach (byte b in bytes)
                sb.Append(alphabet[b % alphabet.Length]);

            return sb.ToString();
        }

        private void CleanupPending(PendingRecord pending)
        {
            if (pending == null)
                return;

            _pendingBySteam.Remove(pending.SteamId);
            _pendingByCode.Remove(pending.Code);
            SaveData();
        }

        private bool CheckRate(IPlayer player)
        {
            // Console / RCON not rate-limited
            if (player == null || player.IsServer)
                return true;

            if (!_rate.TryGetValue(player.Id, out List<DateTime> list))
            {
                list = new List<DateTime>();
                _rate[player.Id] = list;
            }

            DateTime now = DateTime.UtcNow;

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
            if (string.IsNullOrWhiteSpace(nameOrId))
                return null;

            // Prefer exact ID or connected players
            foreach (IPlayer p in players.Connected)
            {
                if (p == null) continue;

                if (p.Id == nameOrId)
                    return p;

                if (!string.IsNullOrEmpty(p.Name) &&
                    p.Name.IndexOf(nameOrId, StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    return p;
                }
            }

            // Fallback to covalence lookup
            return players.FindPlayer(nameOrId);
        }

        private bool IsImageLibraryPresent()
        {
            if (ImageLibrary != null)
                return true;

            foreach (string name in _config.ImageLibraryPluginNames)
            {
                Plugin found = plugins.Find(name);
                if (found != null) return true;
            }

            return false;
        }

        private bool IsRustKitsPresent()
        {
            if (Kits != null)
                return true;

            foreach (string name in _config.RustKitsPluginNames)
            {
                Plugin found = plugins.Find(name);
                if (found != null) return true;
            }

            return false;
        }

        private bool IsCustomAutoKitsPresent()
        {
            if (CustomAutoKits != null)
                return true;

            foreach (string name in _config.CustomAutoKitsPluginNames)
            {
                Plugin found = plugins.Find(name);
                if (found != null) return true;
            }

            return false;
        }

        private bool MatchesDependency(string pluginName)
        {
            if (string.IsNullOrEmpty(pluginName)) return false;

            return _config.ImageLibraryPluginNames.Contains(pluginName) ||
                   _config.RustKitsPluginNames.Contains(pluginName) ||
                   _config.CustomAutoKitsPluginNames.Contains(pluginName);
        }

        private string StripRichText(string s)
        {
            if (string.IsNullOrEmpty(s))
                return string.Empty;

            // No rich text used currently, but keep this as a future-safety shim.
            return s
                .Replace("<b>", string.Empty).Replace("</b>", string.Empty)
                .Replace("<i>", string.Empty).Replace("</i>", string.Empty)
                .Replace("<color=", string.Empty).Replace("</color>", string.Empty);
        }

        #endregion
    }
}
